"""Dashboard assistant: the chat runs the app's own API as the caller, and changes wait for Confirm.

The model is a scripted fake (no network); everything else is real: the
catalog comes from app.openapi(), calls go through main.app in-process with
the caller's token, and the staff / role guards decide what is allowed.
"""
from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.config import settings
from app.db.models import (
    AssistantAction, AssistantConversation, Plan, ResellerInboxMessage, ResellerStaff, StaffActivityLog,
)
from app.services import staff_access
from app.services.assistant import agent as agent_mod
from app.services.assistant import shaping
from app.services.assistant.caller import Caller
from app.services.assistant.catalog import Catalog, build_path, reset_catalog
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_admin, make_plan, make_reseller


# ---------------------------------------------------------------------------
# A scripted model
# ---------------------------------------------------------------------------

class _Block:
    def __init__(self, data: dict):
        self.data = data
        self.type = data["type"]

    def to_dict(self, mode="python"):
        return dict(self.data)


class _Usage:
    input_tokens = 100
    output_tokens = 20
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0


class _Message:
    def __init__(self, blocks: list[dict], stop_reason: str):
        self.content = [_Block(b) for b in blocks]
        self.stop_reason = stop_reason
        self.usage = _Usage()


class _TextEvent:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Stream:
    def __init__(self, message: _Message):
        self.message = message

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def __aiter__(self):
        async def gen():
            for block in self.message.content:
                if block.type == "text":
                    yield _TextEvent(block.data["text"])
        return gen()

    async def get_final_message(self):
        return self.message


class FakeModel:
    """Each call to stream() pops the next scripted reply; requests are kept."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests: list[dict] = []
        self.uploads: list[tuple] = []
        outer = self

        class _Messages:
            def stream(self, **kwargs):
                outer.requests.append(json.loads(json.dumps(kwargs, default=str)))
                reply = outer.replies.pop(0)
                if callable(reply):
                    reply = reply(kwargs)
                return _Stream(reply)

        class _Beta:
            messages = _Messages()

        class _Files:
            async def upload(self, *, file, **kwargs):
                outer.uploads.append(file)

                class Meta:
                    id = "file_test_1"
                return Meta()

        self.beta = _Beta()
        self.files = _Files()


def text_reply(text: str) -> _Message:
    return _Message([{"type": "text", "text": text}], "end_turn")


def tool_reply(name: str, args: dict, tool_id: str = "tu_1", text: str = "") -> _Message:
    blocks = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    if text:
        blocks.append({"type": "text", "text": text})
    blocks.append({"type": "tool_use", "id": tool_id, "name": name, "input": args})
    return _Message(blocks, "tool_use")


def sse_events(body: str) -> list[dict]:
    events = []
    for chunk in body.split("\n\n"):
        data = [line[6:] for line in chunk.splitlines() if line.startswith("data: ")]
        if data:
            events.append(json.loads("\n".join(data)))
    return events


def tool_results(request: dict) -> list[dict]:
    last = request["messages"][-1]
    return [json.loads(b["content"]) | {"_is_error": b.get("is_error", False)}
            for b in last["content"] if b.get("type") == "tool_result"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(engine, monkeypatch):
    import main

    staff_access.reset_cache()
    reset_catalog()
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(settings, "ASSISTANT_ENABLED", True)

    async def no_alert(*args, **kwargs):
        pass

    monkeypatch.setattr(staff_access, "alert_owner", no_alert)
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c
    agent_mod.set_client(None)
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def owner(db):
    reseller = await make_reseller(db, email="owner@example.com", organization_name="Kwetu WiFi")
    token = create_access_token(login_token_claims(reseller), timedelta(hours=1))
    return reseller, token


def use_model(replies) -> FakeModel:
    model = FakeModel(replies)
    agent_mod.set_client(model)
    return model


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def _caller(**kw) -> Caller:
    base = dict(user_id=1, role="reseller", authorization="Bearer x", organization="Org")
    base.update(kw)
    return Caller(**base)


def test_catalog_covers_the_dashboard_api_and_nothing_public():
    import main

    catalog = Catalog.from_openapi(main.app.openapi())
    keys = {a.key for a in catalog.actions}
    assert "GET /api/customers" in keys
    assert "PUT /api/customers/{customer_id}" in keys
    assert "POST /api/plans/create" in keys
    assert not any(a.template.startswith("/api/assistant") for a in catalog.actions)
    assert not any(a.template.startswith("/api/public/") for a in catalog.actions)
    assert not any(a.template.startswith("/api/auth/") for a in catalog.actions)
    assert "POST /api/mpesa/callback" not in keys
    assert len(catalog.actions) > 250

    assert catalog.get("GET", "/api/customers").always_reads
    assert not catalog.get("PUT", "/api/customers/{customer_id}").always_reads
    assert catalog.get("POST", "/api/compensation/outage/preview").always_reads


def test_catalog_follows_roles_and_staff_permissions():
    import main

    catalog = Catalog.from_openapi(main.app.openapi())
    admin = {a.key for a in catalog.for_caller(_caller(role="admin"))}
    owner = {a.key for a in catalog.for_caller(_caller())}
    cashier = {a.key for a in catalog.for_caller(_caller(staff_id=5, staff_permissions=frozenset(
        {"customers.view", "vouchers.generate", "transactions.view"})))}
    viewer = {a.key for a in catalog.for_caller(_caller(viewer_sid=9))}

    assert any(k.startswith("GET /api/admin/") for k in admin)
    assert not any(k.split(" ", 1)[1].startswith("/api/admin/") and "routers" not in k for k in owner)
    assert "GET /api/customers" in cashier
    assert "PUT /api/customers/{customer_id}" not in cashier
    assert "POST /api/plans/create" not in cashier
    assert not any("/api/staff" in k and not k.endswith("/api/staff/me") for k in cashier)
    assert "PUT /api/customers/{customer_id}" not in viewer
    assert "GET /api/customers" in viewer


def test_paths_are_rebuilt_safely():
    import main

    catalog = Catalog.from_openapi(main.app.openapi())
    action, params = catalog.match("PUT", "/api/customers/42")
    assert action.template == "/api/customers/{customer_id}"
    assert build_path(action, params) == "/api/customers/42"
    action, params = catalog.match("GET", "/api/customers/..")
    assert action is None or build_path(action, params) is None


def test_secrets_are_masked_and_refused():
    data = {"name": "Jane", "pppoe_password": "hunter2", "nested": [{"consumer_secret": "abc", "ok": 1}]}
    masked = shaping.mask(data)
    assert masked["name"] == "Jane"
    assert "hunter2" not in json.dumps(masked) and "abc" not in json.dumps(masked)
    assert shaping.secret_fields({"password": "x", "phone": "07"}) == ["password"]
    assert shaping.secret_fields({"password": ""}) == []
    big = {"items": [{"i": i, "note": "x" * 1000} for i in range(500)]}
    assert len(json.dumps(shaping.for_model(big))) < 16000


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_not_configured_without_a_key(client, owner, monkeypatch):
    _, token = owner
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    status = await client.get("/api/assistant/status", headers=auth(token))
    assert status.status_code == 200 and status.json()["enabled"] is False
    r = await client.post("/api/assistant/chat", json={"message": "hi"}, headers=auth(token))
    assert r.status_code == 503
    assert (await client.post("/api/assistant/chat", json={"message": "hi"})).status_code == 401


@pytest.mark.asyncio
async def test_a_read_runs_as_the_caller_and_is_shown(client, owner, db):
    reseller, token = owner
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    other = await make_reseller(db, email="other@example.com")
    await make_plan(db, other, name="Someone else's plan")

    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "table"}),
        text_reply("You have one plan: Daily 50 at 50."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "What plans do I have?"},
                          headers=auth(token))
    assert r.status_code == 200
    events = sse_events(r.text)
    kinds = [e["type"] for e in events]
    assert kinds[0] == "conversation" and kinds[-1] == "done"
    data = next(e for e in events if e["type"] == "data")
    assert "Daily 50" in json.dumps(data["payload"])
    assert "Someone else" not in json.dumps(data["payload"])  # scoped by the caller's own token
    assert "".join(e["delta"] for e in events if e["type"] == "text") == "You have one plan: Daily 50 at 50."

    # The model saw the result; the system prompt carries the index; history is stored.
    result = tool_results(model.requests[1])[0]
    assert result["status"] == 200 and "Daily 50" in json.dumps(result["data"])
    assert "POST /api/plans/create" in model.requests[0]["system"][0]["text"]
    conv_id = events[0]["id"]
    stored = await client.get(f"/api/assistant/conversations/{conv_id}", headers=auth(token))
    kinds = [t["type"] for t in stored.json()["transcript"]]
    assert kinds == ["user", "data", "assistant"]
    listed = await client.get("/api/assistant/conversations", headers=auth(token))
    assert listed.json()["conversations"][0]["title"] == "What plans do I have?"

    # Another account cannot open it.
    other_token = create_access_token(login_token_claims(other), timedelta(hours=1))
    assert (await client.get(f"/api/assistant/conversations/{conv_id}",
                             headers=auth(other_token))).status_code == 404


@pytest.mark.asyncio
async def test_a_change_waits_for_confirm_then_runs_once(client, owner, db):
    reseller, token = owner
    reseller_id = reseller.id
    body = {"name": "Weekly 300", "speed": "5M/5M", "price": 300, "duration_value": 7,
            "duration_unit": "DAYS", "connection_type": "hotspot"}
    use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": body,
                                "summary": "Create Weekly 300 (KES 300, 7 days)"}),
        text_reply("I will create Weekly 300. Tap Confirm."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Add a weekly plan for 300"},
                          headers=auth(token))
    events = sse_events(r.text)
    card = next(e for e in events if e["type"] == "action")
    assert card["method"] == "POST" and card["path"] == "/api/plans/create" and card["body"] == body
    assert card["summary"] == "Create Weekly 300 (KES 300, 7 days)"
    conv_id = events[0]["id"]
    plans = (await db.execute(select(Plan).where(Plan.user_id == reseller_id))).scalars().all()
    assert plans == []  # nothing ran yet

    model = use_model([text_reply("Done: Weekly 300 is live.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide",
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]},
                          headers=auth(token))
    events = sse_events(r.text)
    result = next(e for e in events if e["type"] == "action_result")
    assert result["status"] == "done" and result["ok"] is True
    db.expire_all()
    plans = (await db.execute(select(Plan).where(Plan.user_id == reseller_id))).scalars().all()
    assert [p.name for p in plans] == ["Weekly 300"]
    confirmation = model.requests[0]["messages"][-1]["content"][0]["text"]
    assert confirmation.startswith("[Confirmation results]") and '"outcome":"done"' in confirmation

    # A second confirm of the same card does nothing.
    use_model([text_reply("Already handled.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide",
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]},
                          headers=auth(token))
    again = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert again["status"] == "expired"
    db.expire_all()
    assert len((await db.execute(select(Plan).where(Plan.user_id == reseller_id))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_only_the_proposer_can_confirm(client, owner, db):
    _, token = owner
    use_model([
        tool_reply("call_api", {"method": "DELETE", "path": "/api/plans/1"}),
        text_reply("Confirm to delete."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "delete plan 1"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    other = await make_reseller(db, email="intruder@example.com")
    other_token = create_access_token(login_token_claims(other), timedelta(hours=1))
    r = await client.post(f"/api/assistant/conversations/{events[0]['id']}/decide",
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]},
                          headers=auth(other_token))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_staff_cannot_do_through_chat_what_they_cannot_do_on_the_dashboard(client, owner, db):
    reseller, _ = owner
    member = ResellerStaff(parent_reseller_id=reseller.id, name="Cashier Jo", email="jo@example.com",
                           password_hash=pwd_context.hash("pw-123456"),
                           permissions=["customers.view", "vouchers.generate"])
    db.add(member)
    await db.commit()
    token = create_access_token(staff_access.staff_token_claims(member, reseller), timedelta(hours=1))

    model = use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create",
                                "body": {"name": "x", "speed": "1M/1M", "price": 1, "duration_value": 1,
                                         "duration_unit": "DAYS", "connection_type": "hotspot"}}),
        text_reply("You do not have permission to manage plans."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "make a plan"}, headers=auth(token))
    assert r.status_code == 200
    events = sse_events(r.text)
    assert not any(e["type"] == "action" for e in events)
    refused = tool_results(model.requests[1])[0]
    assert refused["_is_error"] and "plans.manage" in refused["error"]
    assert "POST /api/plans/create" not in model.requests[0]["system"][0]["text"]  # not in a cashier's index
    assert (await db.execute(select(AssistantAction))).scalars().all() == []
    # The chat message itself is not an activity-log entry.
    logs = (await db.execute(select(StaffActivityLog))).scalars().all()
    assert not any("/api/assistant/chat" in (l.path or "") for l in logs)


@pytest.mark.asyncio
async def test_secrets_never_go_through_the_chat(client, owner):
    _, token = owner
    model = use_model([
        tool_reply("call_api", {"method": "PUT", "path": "/api/customers/5",
                                "body": {"pppoe_password": "hunter2"}}),
        text_reply("Please set the password on the customer page."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "set password"},
                                           headers=auth(token))).text)
    assert not any(e["type"] == "action" for e in events)
    refused = tool_results(model.requests[1])[0]
    assert refused["_is_error"] and "pppoe_password" in refused["error"]


@pytest.mark.asyncio
async def test_photos_reach_the_model_by_file_id(client, owner, db):
    _, token = owner
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 64
    model = use_model([text_reply("I can see a Winbox terminal error.")])
    r = await client.post("/api/assistant/chat", json={
        "message": "my router says this",
        "images": [{"media_type": "image/png", "data": base64.b64encode(png).decode(),
                    "thumbnail": "data:image/jpeg;base64,AAAA"}],
    }, headers=auth(token))
    assert r.status_code == 200
    assert model.uploads and model.uploads[0][2] == "image/png"
    content = model.requests[0]["messages"][-1]["content"]
    assert content[0] == {"type": "image", "source": {"type": "file", "file_id": "file_test_1"}}
    conv = (await db.execute(select(AssistantConversation))).scalar_one()
    assert conv.transcript[0]["images"] == ["data:image/jpeg;base64,AAAA"]

    fake = base64.b64encode(b"not an image").decode()
    bad = await client.post("/api/assistant/chat", json={
        "message": "x", "images": [{"media_type": "image/png", "data": fake}]}, headers=auth(token))
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_support_can_read_a_chat_and_leave_a_note(client, owner, db):
    reseller, token = owner
    admin = await make_admin(db, email="support@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    use_model([text_reply("Let's connect your router.")])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "help me set up"},
                                           headers=auth(token))).text)
    conv_id = events[0]["id"]

    assert (await client.get("/api/admin/assistant/conversations", headers=auth(token))).status_code == 403
    listed = await client.get("/api/admin/assistant/conversations", headers=auth(admin_token))
    assert listed.json()["conversations"][0]["id"] == conv_id
    note = await client.post(f"/api/admin/assistant/conversations/{conv_id}/notes",
                             json={"text": "Your port 1 cable looks loose in the photo."},
                             headers=auth(admin_token))
    assert note.status_code == 200
    seen = await client.get(f"/api/assistant/conversations/{conv_id}", headers=auth(token))
    assert seen.json()["transcript"][-1]["type"] == "support"
    inbox = (await db.execute(select(ResellerInboxMessage).where(
        ResellerInboxMessage.recipient_user_id == reseller.id))).scalars().all()
    assert inbox and conv_id in inbox[-1].body

    model = use_model([text_reply("Support says to check the cable in port 1.")])
    await client.post("/api/assistant/chat", json={"message": "what did they say?",
                                                    "conversation_id": conv_id}, headers=auth(token))
    texts = [b.get("text", "") for m in model.requests[0]["messages"] for b in m["content"]
             if isinstance(b, dict)]
    assert any(t.startswith("[Bitwave support note from") for t in texts)

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
from app.services.assistant import briefing as briefing_mod
from app.services.assistant import home as home_mod
from app.services.assistant import shaping
from app.services.assistant.caller import Caller
from app.services.assistant.catalog import Catalog, build_path, reset_catalog
from app.services.auth import create_access_token, pwd_context
from tests.factories import (
    make_admin, make_customer, make_plan, make_reseller, make_router, make_sms_account,
)


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
            def __init__(self, path):
                self.path = path

            def stream(self, **kwargs):
                outer.requests.append(json.loads(json.dumps(kwargs, default=str)) | {"_path": self.path})
                reply = outer.replies.pop(0)
                if callable(reply):
                    reply = reply(kwargs)
                return _Stream(reply)

        class _Beta:
            messages = _Messages("beta")

        self.messages = _Messages("messages")

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


def visible_text(events: list[dict]) -> str:
    """The words left on screen: text, minus what was taken back as working notes."""
    out = ""
    for e in events:
        if e["type"] == "text":
            out += e.get("delta", "")
        elif e["type"] == "retract":
            out = out[: max(0, len(out) - e["chars"])]
    return out.strip()


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

    from app.services.plan_cache import invalidate_plan_cache

    staff_access.reset_cache()
    reset_catalog()
    briefing_mod.reset_cache()   # the home figures are kept per person for a minute
    home_mod.reset_cache()       # ...and the rollout percentage for half a minute
    await invalidate_plan_cache()  # GET /api/plans is cached per user id; every test's DB reuses id 1
    monkeypatch.setattr(settings, "ASSISTANT_PROVIDER", "deepseek")
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "test-key")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
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
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "")
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
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": body,
                                "summary": "Create Weekly 300 (KES 300, 7 days)"}),
        text_reply("Ready to create Weekly 300. Tap Confirm."),
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
        tool_reply("describe_action", {"method": "DELETE", "path": "/api/plans/{plan_id}"}, "tu_d"),
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


PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 64


@pytest.mark.asyncio
async def test_photos_reach_deepseek_inline(client, owner, db):
    _, token = owner
    model = use_model([text_reply("I can see a Winbox terminal error.")])
    data = base64.b64encode(PNG).decode()
    r = await client.post("/api/assistant/chat", json={
        "message": "my router says this",
        "images": [{"media_type": "image/png", "data": data, "thumbnail": "data:image/jpeg;base64,AAAA"}],
    }, headers=auth(token))
    assert r.status_code == 200
    assert model.uploads == []  # DeepSeek keeps files 30 days at most: the photo stays in the history
    content = model.requests[0]["messages"][-1]["content"]
    assert content[0] == {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
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


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deepseek_gets_a_plain_anthropic_format_request(client, owner):
    _, token = owner
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "none"}),
        text_reply("No plans yet."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "plans?"}, headers=auth(token))
    assert r.status_code == 200
    first = model.requests[0]
    assert first["_path"] == "messages"            # not the beta path
    assert first["model"] == "deepseek-flash"
    assert "fallbacks" not in first and "betas" not in first
    assert "cache_control" not in first            # DeepSeek caches prefixes by itself
    assert "output_config" not in first            # provider default effort
    assert first["metadata"]["user_id"].startswith("bitwave-")
    status = (await client.get("/api/assistant/status", headers=auth(token))).json()
    assert status["provider"] == "deepseek" and status["model"] == "deepseek-flash"


def test_deepseek_client_uses_its_anthropic_endpoint(monkeypatch):
    agent_mod.set_client(None)
    monkeypatch.setattr(settings, "ASSISTANT_PROVIDER", "deepseek")
    monkeypatch.setattr(settings, "ASSISTANT_BASE_URL", "")
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "sk-test")
    try:
        client = agent_mod.get_client()
        assert str(client.base_url).rstrip("/") == "https://api.deepseek.com/anthropic"
        assert agent_mod.assistant_ready() == (True, "")
        monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "")
        assert agent_mod.assistant_ready()[0] is False
    finally:
        agent_mod.set_client(None)


def test_consecutive_turns_are_merged_only_in_the_request():
    history = [
        {"role": "user", "content": [{"type": "text", "text": "hi"}]},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "x", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "{}"}]},
        {"role": "user", "content": [{"type": "text", "text": "[Bitwave support note from S] check port 1"}]},
    ]
    sent = agent_mod.request_messages(history)
    assert len(sent) == 3 and len(history) == 4
    assert [b["type"] for b in sent[-1]["content"]] == ["tool_result", "text"]  # tool results first


@pytest.mark.asyncio
async def test_claude_path_keeps_its_own_features(client, owner, monkeypatch):
    _, token = owner
    monkeypatch.setattr(settings, "ASSISTANT_PROVIDER", "anthropic")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test-key")
    model = use_model([text_reply("Seen.")])
    r = await client.post("/api/assistant/chat", json={
        "message": "photo", "images": [{"media_type": "image/png", "data": base64.b64encode(PNG).decode()}],
    }, headers=auth(token))
    assert r.status_code == 200
    first = model.requests[0]
    assert first["_path"] == "beta" and first["model"] == "claude-opus-5-5"
    assert first["fallbacks"] == "default" and first["cache_control"] == {"type": "ephemeral"}
    assert model.uploads and first["messages"][-1]["content"][0]["source"]["type"] == "file"


def _sse(chunks: list[dict]) -> bytes:
    return ("".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + ": keep-alive\n\ndata: [DONE]\n\n").encode()


@pytest.mark.asyncio
async def test_openai_compatible_provider_like_the_assets_assistant(client, owner, db, monkeypatch):
    import httpx

    reseller, token = owner
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    monkeypatch.setattr(settings, "ASSISTANT_PROVIDER", "openai_compatible")
    monkeypatch.setattr(settings, "ASSISTANT_BASE_URL", "https://tokenhub.example/v1")
    monkeypatch.setattr(settings, "ASSISTANT_MODEL", "deepseek-v4.1-flash-1017")
    bodies: list[dict] = []
    replies = [
        _sse([  # a tool call whose arguments arrive in pieces
            {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                                 "function": {"name": "call_api", "arguments": ""}}]}}]},
            {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"method":"GET",'}}]}}]},
            {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"path":"/api/plans","show":"table"}'}}]},
                          "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 9000, "completion_tokens": 20, "prompt_cache_hit_tokens": 8000}},
        ]),
        _sse([
            {"choices": [{"index": 0, "delta": {"content": "You have one plan: "}}]},
            {"choices": [{"index": 0, "delta": {"content": "Daily 50."}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 9500, "completion_tokens": 8, "prompt_cache_hit_tokens": 9000}},
        ]),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://tokenhub.example/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-key"
        bodies.append(json.loads(request.content))
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=replies.pop(0))

    agent_mod.set_openai_transport(httpx.MockTransport(handler))
    try:
        r = await client.post("/api/assistant/chat", json={"message": "plans?"}, headers=auth(token))
    finally:
        agent_mod.set_openai_transport(None)
    events = sse_events(r.text)
    assert "Daily 50" in json.dumps(next(e for e in events if e["type"] == "data")["payload"])
    assert "".join(e["delta"] for e in events if e["type"] == "text") == "You have one plan: Daily 50."

    first, second = bodies
    assert first["model"] == "deepseek-v4.1-flash-1017" and first["tool_choice"] == "auto"
    assert first["thinking"] == {"type": "disabled"} and "temperature" not in first
    assert first["tools"][1]["function"]["name"] == "call_api"
    assert first["messages"][0]["role"] == "system" and "API index" in first["messages"][0]["content"]
    assert second["messages"][-2]["tool_calls"][0]["function"]["name"] == "call_api"
    assert second["messages"][-1]["role"] == "tool" and second["messages"][-1]["tool_call_id"] == "call_1"
    conv = (await db.execute(select(AssistantConversation))).scalar_one()
    assert conv.input_tokens == (1000 + 8000) + (500 + 9000) and conv.output_tokens == 28


def test_openai_messages_carry_photos_and_tool_results_in_order():
    from app.services.assistant.openai_compat import to_openai_messages

    msgs = to_openai_messages([{"type": "text", "text": "SYS"}], [
        {"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "QUJD"}},
            {"type": "text", "text": "what is this?"}]},
        {"role": "assistant", "content": [{"type": "thinking", "thinking": "hmm", "signature": ""},
                                          {"type": "tool_use", "id": "c1", "name": "call_api", "input": {"a": 1}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "{}"},
                                     {"type": "text", "text": "[Bitwave support note from S] hi"}]},
    ])
    assert [m["role"] for m in msgs] == ["system", "user", "assistant", "tool", "user"]
    assert msgs[1]["content"][0] == {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,QUJD"}}
    assert msgs[2]["reasoning_content"] == "hmm" and msgs[2]["content"] is None
    assert json.loads(msgs[2]["tool_calls"][0]["function"]["arguments"]) == {"a": 1}



@pytest.mark.asyncio
async def test_a_change_must_be_looked_up_and_valid_before_a_card(client, owner, db):
    _, token = owner
    good = {"name": "Hourly", "speed": "1M/1M", "price": 1, "duration_value": 1,
            "duration_unit": "HOURS", "connection_type": "hotspot"}
    model = use_model([
        # 1. no describe_action yet -> refused
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": good}, "tu_1"),
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_2"),
        # 2. a value the handler would reject after Confirm -> refused before the card
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create",
                                "body": {**good, "duration_unit": "hour", "speedd": "x"}}, "tu_3"),
        # 3. missing required field
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create",
                                "body": {k: v for k, v in good.items() if k != "price"}}, "tu_4"),
        # 4. correct -> card
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": good,
                                "summary": "Create Hourly"}, "tu_5"),
        text_reply("Ready to create Hourly. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "hourly plan"},
                                           headers=auth(token))).text)
    cards = [e for e in events if e["type"] == "action"]
    assert len(cards) == 1 and cards[0]["body"]["duration_unit"] == "HOURS"

    no_lookup = tool_results(model.requests[1])[0]
    assert no_lookup["_is_error"] and "describe_action" in no_lookup["error"]
    described = json.loads(model.requests[2]["messages"][-1]["content"][0]["content"])
    assert described["body"]["properties"]["duration_unit"]["allowed_values"] == ["MINUTES", "HOURS", "DAYS"]
    bad_value = tool_results(model.requests[3])[0]
    assert "'duration_unit' must be one of MINUTES, HOURS, DAYS (got 'hour')" in bad_value["error"]
    assert "unknown field(s): speedd" in bad_value["error"]
    missing = tool_results(model.requests[4])[0]
    assert "'price' is required" in missing["error"]
    assert len((await db.execute(select(AssistantAction))).scalars().all()) == 1


def _long_chat(turns: int, result_chars: int = 2000) -> list:
    msgs = []
    for i in range(turns):
        msgs.append({"role": "user", "content": [{"type": "text", "text": f"question {i}"}]})
        msgs.append({"role": "assistant", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": "call_api", "input": {"method": "GET", "path": "/api/plans"}}]})
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": "x" * result_chars}]})
        msgs.append({"role": "assistant", "content": [{"type": "text", "text": f"answer {i}"}]})
    return msgs


def _pairs_intact(msgs: list) -> bool:
    uses = {b["id"] for m in msgs if m["role"] == "assistant" for b in m["content"] if b.get("type") == "tool_use"}
    results = {b["tool_use_id"] for m in msgs if m["role"] == "user" for b in m["content"]
               if b.get("type") == "tool_result"}
    return uses == results


def test_long_chats_are_trimmed_for_the_model_only():
    history = _long_chat(30)
    before = json.dumps(history)
    sent = agent_mod.fit_context(history, budget_tokens=1_000_000)
    assert json.dumps(history) == before                       # stored chat untouched
    results = [b["content"] for m in sent for b in m["content"] if b.get("type") == "tool_result"]
    assert all(r.startswith("[Earlier result") for r in results[:-3])
    assert all(r == "x" * 2000 for r in results[-3:])          # the last 3 questions keep theirs
    assert _pairs_intact(sent)

    tight = agent_mod.fit_context(history, budget_tokens=1500)
    assert tight[0]["role"] == "user" and tight[0]["content"][0]["text"].startswith("[The earlier part")
    assert tight[-1] == sent[-1] and _pairs_intact(tight)
    assert len(tight) < len(sent)


def test_trimming_keeps_the_cached_prefix_stable_as_the_chat_grows():
    history = _long_chat(25)
    first = agent_mod.fit_context(history, budget_tokens=1_000_000)
    second = agent_mod.fit_context(history + _long_chat(1)[:1], budget_tokens=1_000_000)
    # everything that was already shortened is byte-identical on the next call
    cut = len(history) - 3 * 4
    assert json.dumps(first[:cut]) == json.dumps(second[:cut])


@pytest.mark.asyncio
async def test_a_note_before_a_lookup_gives_way_to_the_answer(client, owner):
    _, token = owner
    use_model([
        _Message([{"type": "text", "text": "Checking."},
                  {"type": "tool_use", "id": "tu_1", "name": "call_api",
                   "input": {"method": "GET", "path": "/api/plans", "show": "none"}}], "tool_use"),
        text_reply("No plans yet."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "plans?"},
                                           headers=auth(token))).text)
    assert visible_text(events) == "No plans yet."
    # the answer starts its own text, with no stray paragraph break in front
    assert not any(e["type"] == "text" and e["delta"] == chr(10) * 2 for e in events)


def test_deepseek_peak_hours_cost_double():
    from datetime import datetime as dt

    from app.services.assistant.usage import call_cost_micros, deepseek_peak

    tuesday_peak, tuesday_quiet, saturday = dt(2026, 11, 17, 7), dt(2026, 11, 17, 12), dt(2026, 11, 21, 7)
    assert deepseek_peak(tuesday_peak) and not deepseek_peak(tuesday_quiet) and not deepseek_peak(saturday)
    args = dict(input_tokens=1_000_000, cache_read_tokens=1_000_000, output_tokens=1_000_000)
    assert call_cost_micros("deepseek-flash", "deepseek", at=tuesday_quiet, **args) == 753_000   # $0.15+0.003+0.60
    assert call_cost_micros("deepseek-flash", "deepseek", at=tuesday_peak, **args) == 1_506_000
    assert call_cost_micros("claude-opus-5-5", "anthropic", at=tuesday_peak, **args) == 24_200_000


@pytest.mark.asyncio
async def test_usage_is_counted_per_account_and_reported_to_admins(client, owner, db):
    from app.db.models import AssistantUsageDaily

    _, token = owner
    use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "none"}),
        text_reply("None yet."),
    ])
    await client.post("/api/assistant/chat", json={"message": "plans?"}, headers=auth(token))
    use_model([text_reply("Still none.")])
    await client.post("/api/assistant/chat", json={"message": "and now?"}, headers=auth(token))
    row = (await db.execute(select(AssistantUsageDaily))).scalar_one()
    assert (row.questions, row.model_calls, row.input_tokens, row.output_tokens) == (2, 3, 300, 60)
    assert row.staff_id == 0 and row.cost_usd_micros > 0

    assert (await client.get("/api/admin/assistant/usage", headers=auth(token))).status_code == 403
    admin = await make_admin(db, email="usage-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    report = (await client.get("/api/admin/assistant/usage?days=7", headers=auth(admin_token))).json()
    assert report["summary"]["today"]["questions"] == 2 and report["summary"]["today"]["accounts"] == 1
    assert report["top_accounts"][0]["questions"] == 2 and report["days"][-1]["model_calls"] == 3


def test_index_spells_out_fixed_query_values():
    import main

    catalog = Catalog.from_openapi(main.app.openapi())
    index = catalog.index_text(_caller())
    stats = next(l for l in index.splitlines() if l.startswith("GET /api/dashboard/stats "))
    assert "period:int" in stats                     # a number of days, not "today"
    fixed = [a for a in catalog.actions for p in a.query_params if (p.get("schema") or {}).get("pattern", "").startswith("^(")]
    assert fixed, "expected at least one query param with fixed values"
    admin_index = catalog.index_text(_caller(role="admin"))
    line = next(l for l in admin_index.splitlines() if l.startswith(f"{fixed[0].method} {fixed[0].template} "))
    assert "=" in line and "|" in line


def test_view_as_usage_is_the_admins_not_the_resellers():
    viewer = _caller(user_id=487, viewer_sid=12, viewer_admin_id=1)
    assert viewer.usage_owner == (1, None)
    staff = _caller(user_id=487, staff_id=5)
    assert staff.usage_owner == (487, 5)


@pytest.mark.asyncio
async def test_the_assistant_knows_bitwave_product_answers(client, owner):
    _, token = owner
    model = use_model([text_reply("Use Access Credentials.")])
    await client.post("/api/assistant/chat", json={"message": "staff internet?"}, headers=auth(token))
    system = model.requests[0]["system"][0]["text"]
    assert "Access Credentials (/access-credentials" in system
    # what support has learnt about faults: every entry listed, the full entry on request
    assert "- wifi-drops-sessions:" in system and "- paid-not-delivered:" in system


# ---------------------------------------------------------------------------
# The home screen: live figures, richer drawings, and who starts there
# ---------------------------------------------------------------------------

async def _pay(db, reseller, amount, when, *, plan=None, customer=None, revenue=True):
    from app.db.models import CustomerPayment

    db.add(CustomerPayment(reseller_id=reseller.id, amount=amount, days_paid_for=1, created_at=when,
                           plan_id=plan.id if plan else None,
                           customer_id=customer.id if customer else None, counts_as_revenue=revenue))
    await db.commit()


async def _staff_token(db, reseller, permissions, email="jo@example.com"):
    member = ResellerStaff(parent_reseller_id=reseller.id, name="Cashier Jo", email=email,
                           password_hash="not-a-real-hash", permissions=permissions)
    db.add(member)
    await db.commit()
    return member, create_access_token(staff_access.staff_token_claims(member, reseller), timedelta(hours=1))


@pytest.mark.asyncio
async def test_briefing_gives_the_home_screen_its_figures(client, owner, db):
    from datetime import datetime

    from app.db.models import CustomerStatus

    reseller, token = owner
    now = datetime.utcnow()
    # days are the account's own (Kenyan) calendar days, as naive UTC bounds
    clock = briefing_mod.make_clock(reseller, now)
    today = clock.today_start
    daily = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    monthly = await make_plan(db, reseller, name="Monthly 1500", price=1500)
    soon = now + timedelta(minutes=2)
    jane = await make_customer(db, reseller, daily, status=CustomerStatus.ACTIVE, expiry=soon, name="Jane")
    await make_customer(db, reseller, monthly, status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=2),
                        name="Otieno", phone="254700000002")
    await make_customer(db, reseller, monthly, status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=20),
                        name="Far away", phone="254700000003")
    await make_customer(db, reseller, daily, status=CustomerStatus.INACTIVE, expiry=now - timedelta(days=2),
                        name="Ran out", phone="254700000004")
    await make_customer(db, reseller, daily, status=CustomerStatus.INACTIVE, expiry=now - timedelta(days=2),
                        name="Paused", phone="254700000005", paused_at=now - timedelta(days=2))
    await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=now)
    await make_router(db, reseller, name="Estate", last_status=False, last_checked_at=now,
                      last_online_at=now - timedelta(hours=2))
    await make_router(db, reseller, name="New box")
    await make_sms_account(db, reseller, balance=120)

    await _pay(db, reseller, 50, now, plan=daily, customer=jane)
    await _pay(db, reseller, 1500, now, plan=monthly)
    await _pay(db, reseller, 70, now, plan=daily, revenue=False)        # a comp: a payment, not revenue
    await _pay(db, reseller, 200, today - timedelta(hours=1), plan=daily)  # yesterday
    await _pay(db, reseller, 300, today - timedelta(days=9), plan=daily)   # the week before
    await _pay(db, reseller, 999, today - timedelta(days=20), plan=daily)  # outside the 14 days
    other = await make_reseller(db, email="other@example.com")
    await _pay(db, other, 5000, now)                                     # somebody else's money

    r = await client.get("/api/assistant/briefing", headers=auth(token))
    assert r.status_code == 200
    b = r.json()
    assert b["audience"] == "reseller" and b["name"] == "Kwetu WiFi" and b["currency"] == "KES"
    assert b["unavailable"] == [] and b["not_allowed"] == []

    money = b["money"]
    assert money["today"] == 1550 and money["payments_today"] == 3      # the comp counts as a payment only
    assert money["yesterday"] == 200 and money["last7"] == 1750 and money["prev7"] == 300
    assert len(money["daily"]) == 14 and money["daily"][-1]["partial"] is True
    assert money["daily"][-1]["day"] == clock.today.isoformat() and money["daily"][0]["partial"] is False
    assert [d["day"] for d in money["daily"]] == sorted(d["day"] for d in money["daily"])
    assert money["month"] >= 1550

    customers = b["customers"]
    assert customers["total"] == 5 and customers["active"] == 3
    assert customers["expiring_today"] == (1 if soon < clock.tomorrow_start else 0)
    assert customers["expiring_3d"] == 2 and customers["expired_7d"] == 1 and customers["new_7d"] == 5
    assert [c["name"] for c in customers["expiring"]] == ["Jane", "Otieno"]     # soonest first, within a week
    assert customers["expiring"][0]["plan"] == "Daily 50" and customers["expiring"][0]["expiry"].endswith("Z")

    routers = b["routers"]
    assert (routers["total"], routers["online"], routers["offline"], routers["unknown"]) == (3, 1, 1, 1)
    assert [d["name"] for d in routers["down"]] == ["Estate"] and routers["down"][0]["last_online_at"]

    assert b["plans"][0] == {"name": "Monthly 1500", "revenue": 1500, "sales": 1}
    assert b["plans"][1] == {"name": "Daily 50", "revenue": 250, "sales": 3}
    assert b["attention"] == {"failed_payments_24h": 0, "unmatched_payments": 0, "sms_credits": 120,
                              "subscription": b["attention"]["subscription"]}
    assert set(b["attention"]["subscription"]) == {"status", "expires_at", "amount_due"}
    assert b["setup"] == {"routers": 3, "plans": 2, "payment_methods": 0, "customers": 5}

    # Kept for a minute: a new payment shows only once the cache is dropped.
    await _pay(db, reseller, 100, now, plan=daily)
    again = (await client.get("/api/assistant/briefing", headers=auth(token))).json()
    assert again["as_of"] == b["as_of"] and again["money"]["today"] == 1550
    briefing_mod.reset_cache()
    fresh = (await client.get("/api/assistant/briefing", headers=auth(token))).json()
    assert fresh["money"]["today"] == 1650

    # A new account has nothing, and says so with zeros rather than errors.
    other_token = create_access_token(login_token_claims(other), timedelta(hours=1))
    empty = (await client.get("/api/assistant/briefing", headers=auth(other_token))).json()
    assert empty["setup"] == {"routers": 0, "plans": 0, "payment_methods": 0, "customers": 0}
    assert empty["money"]["today"] == 5000 and empty["customers"]["expiring"] == [] and empty["plans"] == []


@pytest.mark.asyncio
async def test_briefing_follows_staff_permissions_view_as_and_admins(client, owner, db):
    import main

    reseller, _ = owner
    _, staff_token = await _staff_token(db, reseller, ["customers.view"])
    b = (await client.get("/api/assistant/briefing", headers=auth(staff_token))).json()
    assert b["name"] == "Cashier Jo" and "customers" in b and "routers" in b
    assert "money" not in b and "plans" not in b                        # revenue is not this cashier's to see
    assert {"money", "plans"} <= set(b["unavailable"]) and {"money", "plans"} <= set(b["not_allowed"])
    assert "customers" not in b["unavailable"]
    assert b["attention"]["sms_credits"] is None and b["attention"]["failed_payments_24h"] is None
    assert b["setup"] == {"routers": 0, "plans": 0, "payment_methods": None, "customers": 0}
    # Reading the figures is not an activity-log entry.
    assert (await db.execute(select(StaffActivityLog))).scalars().all() == []

    catalog = Catalog.from_openapi(main.app.openapi())
    viewer = await briefing_mod.build(catalog, _caller(user_id=reseller.id, viewer_sid=9, viewer_admin_id=1,
                                                       organization="Kwetu WiFi"))
    assert viewer["audience"] == "reseller" and "money" in viewer and viewer["unavailable"] == []

    admin = await make_admin(db, email="home-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    a = (await client.get("/api/assistant/briefing", headers=auth(admin_token))).json()
    assert set(a) == {"as_of", "audience", "name", "unavailable"} and a["audience"] == "admin"
    assert (await client.get("/api/assistant/briefing")).status_code == 401


@pytest.mark.asyncio
async def test_briefing_survives_a_failing_section(client, owner, db, monkeypatch):
    _, token = owner

    async def broken(db, user_id, now):
        raise RuntimeError("boom")

    monkeypatch.setattr(briefing_mod, "_money", broken)
    b = (await client.get("/api/assistant/briefing", headers=auth(token))).json()
    assert "money" not in b and b["unavailable"] == ["money"] and b["not_allowed"] == []
    assert b["customers"]["total"] == 0 and b["routers"]["total"] == 0  # the rest still answers


def test_field_hints_are_kept_only_when_well_formed():
    clean = agent_mod.clean_fields
    assert clean({"label": "date", "value": ["revenue", "transactions"]}) == {
        "label": "date", "value": ["revenue", "transactions"]}
    assert clean({"label": " name ", "value": "revenue"}) == {"label": "name", "value": ["revenue"]}
    assert clean({"value": ["a", "b", "c", "d", "e", "a"]}) == {"value": ["a", "b", "c", "d"]}   # at most four
    assert clean({"label": "x" * 61, "value": [7, None, {"k": 1}]}) is None                    # too long, not names
    assert clean("revenue") is None and clean(None) is None and clean({}) is None
    show = next(t for t in agent_mod.TOOLS if t["name"] == "call_api")["input_schema"]["properties"]["show"]
    assert show["enum"] == ["auto", "table", "card", "none", "tiles", "trend", "bars", "share"]


@pytest.mark.asyncio
async def test_the_model_chooses_the_drawing_never_the_numbers(client, owner, db):
    reseller, token = owner
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "bars",
                                "fields": {"label": "name", "value": ["price", "x" * 80]}}, "tu_1"),
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "pie-chart",
                                "fields": "price"}, "tu_2"),
        text_reply("Daily 50 is your only plan." + chr(10) + "NEXT: Which plan sells most? | Add a weekly plan"),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "compare my plans"}, headers=auth(token))
    events = sse_events(r.text)
    first, second = [e for e in events if e["type"] == "data"]
    assert first["show"] == "bars" and first["fields"] == {"label": "name", "value": ["price"]}
    assert "Daily 50" in json.dumps(first["payload"])              # the figures are the API's
    assert second["show"] == "auto" and "fields" not in second     # an unknown drawing falls back to the page's choice
    assert all(not res["_is_error"] for req in model.requests[1:] for res in tool_results(req))

    stored = (await client.get(f"/api/assistant/conversations/{events[0]['id']}", headers=auth(token))).json()
    kept = [t for t in stored["transcript"] if t["type"] == "data"]
    assert kept[0]["show"] == "bars" and kept[0]["fields"] == {"label": "name", "value": ["price"]}
    assert stored["transcript"][-1]["text"].splitlines()[-1].startswith("NEXT: ")

    system = model.requests[0]["system"][0]["text"]
    assert "NEXT: question one | question two | question three" in system
    assert "figures per day / week / month a trend" in system and "never repeat rows" in system


def test_rollout_buckets_are_fixed_per_account():
    assert not any(home_mod.in_rollout(uid, 0) for uid in range(1, 400))
    assert all(home_mod.in_rollout(uid, 100) for uid in range(1, 400))
    at_30 = {uid for uid in range(1, 2001) if home_mod.in_rollout(uid, 30)}
    at_60 = {uid for uid in range(1, 2001) if home_mod.in_rollout(uid, 60)}
    assert at_30 < at_60                                  # raising the share only adds accounts
    assert 450 < len(at_30) < 750 and 1050 < len(at_60) < 1350


@pytest.mark.asyncio
async def test_who_starts_on_the_assistant(client, owner, db, monkeypatch):
    from app.db.models import AppSetting, AssistantHomeChoice

    from app.db.models import SubscriptionStatus

    reseller, token = owner
    reseller.subscription_status = SubscriptionStatus.ACTIVE     # the rollout moves paying accounts only
    await db.commit()
    trial = await make_reseller(db, email="trial@example.com")   # a trial account is never moved
    trial_token = create_access_token(login_token_claims(trial), timedelta(hours=1))
    admin = await make_admin(db, email="rollout-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    _, staff_token = await _staff_token(db, reseller, ["customers.view"])
    reseller_id, admin_id = reseller.id, admin.id   # read before expire_all() below
    # a partial share (below Everyone) that takes this reseller's bucket in
    monkeypatch.setattr(home_mod, "in_rollout", lambda uid, percent: percent > 0)

    async def status(tok):
        return (await client.get("/api/assistant/status", headers=auth(tok))).json()

    # Nobody is moved until an admin says so.
    assert (await status(token))["home"] is False and (await status(token))["home_choice"] is None
    assert (await client.get("/api/admin/assistant/rollout", headers=auth(admin_token))).json() == {
        "percent": 0, "classic_closed": False, "chose_assistant": 0, "chose_classic": 0,
        "paying_accounts": 1, "paying_inside": 0}
    assert (await client.put("/api/admin/assistant/rollout", json={"percent": 50},
                             headers=auth(token))).status_code == 403
    assert (await client.put("/api/admin/assistant/rollout", json={"percent": 101},
                             headers=auth(admin_token))).status_code == 422

    r = await client.put("/api/admin/assistant/rollout", json={"percent": 50}, headers=auth(admin_token))
    assert r.status_code == 200 and r.json()["percent"] == 50
    db.expire_all()
    assert (await db.get(AppSetting, home_mod.ROLLOUT_KEY)).value == "50"
    assert (await status(token))["classic_closed"] is False   # a partial share leaves the dashboard open
    assert (await status(token))["home"] is True              # the account...
    assert (await status(staff_token))["home"] is True        # ...and its staff, together
    assert (await status(admin_token))["home"] is False       # a platform admin is never moved
    assert (await status(trial_token))["home"] is False       # nor an account that does not pay

    # A person's own choice wins, and is theirs alone.
    r = await client.put("/api/assistant/home", json={"choice": "classic"}, headers=auth(token))
    assert r.json() == {"home": False, "home_choice": "classic"}
    assert (await status(staff_token))["home"] is True
    r = await client.put("/api/assistant/home", json={"choice": "default"}, headers=auth(token))
    assert r.json() == {"home": True, "home_choice": None}
    db.expire_all()
    assert (await db.execute(select(AssistantHomeChoice))).scalars().all() == []

    await client.put("/api/admin/assistant/rollout", json={"percent": 0}, headers=auth(admin_token))
    assert (await status(token))["home"] is False
    assert (await client.put("/api/assistant/home", json={"choice": "assistant"},
                             headers=auth(staff_token))).json() == {"home": True, "home_choice": "assistant"}
    assert (await client.put("/api/assistant/home", json={"choice": "assistant"},
                             headers=auth(admin_token))).json() == {"home": True, "home_choice": "assistant"}
    assert (await status(token))["home"] is False             # the owner did not choose
    assert (await client.put("/api/assistant/home", json={"choice": "nope"},
                             headers=auth(token))).status_code == 422
    report = (await client.get("/api/admin/assistant/rollout", headers=auth(admin_token))).json()
    assert report == {"percent": 0, "classic_closed": False, "chose_assistant": 2, "chose_classic": 0,
                      "paying_accounts": 1, "paying_inside": 0}
    # The staff member's choice is not an activity-log entry.
    logs = (await db.execute(select(StaffActivityLog))).scalars().all()
    assert not any("/api/assistant/home" in (entry.path or "") for entry in logs)

    # A View-as session is the admin looking in: never moved, and without the reseller's choice.
    await client.put("/api/assistant/home", json={"choice": "assistant"}, headers=auth(token))
    viewer = _caller(user_id=reseller_id, viewer_sid=9, viewer_admin_id=admin_id)
    assert await home_mod.home_for(viewer, ready=True) == (False, None)
    await client.put("/api/admin/assistant/rollout", json={"percent": 100}, headers=auth(admin_token))
    assert await home_mod.home_for(viewer, ready=True) == (False, None)
    assert await home_mod.classic_closed(viewer, ready=True) is False

    # Nobody starts on an assistant that is not ready.
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "")
    off = await status(token)
    assert off["enabled"] is False and off["home"] is False and off["home_choice"] == "assistant"


@pytest.mark.asyncio
async def test_everyone_starts_on_the_assistant_and_keeps_the_classic_dashboard(client, owner, db, monkeypatch):
    """At 100% every reseller account with no choice starts on the assistant (trial and staff too);
    a person who picks the classic dashboard starts there, and nothing is closed."""
    reseller, token = owner                                       # a trial account: not paying
    trial_id = reseller.id
    admin = await make_admin(db, email="everyone-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    _, staff_token = await _staff_token(db, reseller, ["customers.view"])
    admin_id = admin.id

    async def status(tok):
        return (await client.get("/api/assistant/status", headers=auth(tok))).json()

    r = await client.put("/api/admin/assistant/rollout", json={"percent": 100}, headers=auth(admin_token))
    assert r.json()["classic_closed"] is False

    for tok in (token, staff_token):                              # trial owner and staff, no choice
        s = await status(tok)
        assert s["home"] is True and s["home_choice"] is None and s["classic_closed"] is False

    # Their own choice of the classic dashboard counts, for them alone.
    r = await client.put("/api/assistant/home", json={"choice": "classic"}, headers=auth(token))
    assert r.json() == {"home": False, "home_choice": "classic"}
    s = await status(token)
    assert s["home"] is False and s["classic_closed"] is False
    assert (await status(staff_token))["home"] is True
    # and going back to the default puts them on the assistant again
    r = await client.put("/api/assistant/home", json={"choice": "default"}, headers=auth(token))
    assert r.json() == {"home": True, "home_choice": None}

    admin_status = await status(admin_token)
    assert admin_status["home"] is False and admin_status["classic_closed"] is False
    viewer = _caller(user_id=trial_id, viewer_sid=9, viewer_admin_id=admin_id)
    assert await home_mod.home_for(viewer, ready=True) == (False, None)
    assert await home_mod.classic_closed(viewer, ready=True) is False

    # An assistant that is not ready never starts anyone there.
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "")
    s = await status(token)
    assert s["enabled"] is False and s["home"] is False and s["classic_closed"] is False


@pytest.mark.asyncio
async def test_briefing_draws_each_router_with_what_it_last_reported(client, owner, db):
    """The home screen's network section: every router, trouble first, with its own live report."""
    from datetime import datetime

    from app.db.models import CustomerStatus
    from app.services import realtime_state

    reseller, token = owner
    now = datetime.utcnow()
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    shop = await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=now,
                             availability_checks=200, availability_successes=199)
    estate = await make_router(db, reseller, name="Estate", last_status=False, last_checked_at=now,
                               last_online_at=now - timedelta(hours=2))
    quiet = await make_router(db, reseller, name="Quiet", last_status=True, last_checked_at=now)
    shop_id, estate_id, quiet_id = shop.id, estate.id, quiet.id
    for i, router_id in enumerate((shop_id, shop_id, estate_id)):
        await make_customer(db, reseller, plan, status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=1),
                            name=f"C{i}", phone=f"25470000010{i}", router_id=router_id)
    await make_customer(db, reseller, plan, status=CustomerStatus.INACTIVE, expiry=now - timedelta(days=1),
                        name="Gone", phone="254700000109", router_id=shop_id)

    total = 256 * 1024 * 1024
    realtime_state._routers[shop_id] = realtime_state.RouterLive(
        router_id=shop_id, received_at=now, interval_seconds=60, cpu_load=41, free_memory=total // 4,
        total_memory=total, uptime="3d04:14:07", version="7.16.1", board="hAP ax2",
        wan_rx_bps=12_400_000.0, wan_tx_bps=2_100_000.0, hotspot_active=14, pppoe_active=3)
    # a report from long ago is not "live"
    realtime_state._routers[quiet_id] = realtime_state.RouterLive(
        router_id=quiet_id, received_at=now - timedelta(hours=2), interval_seconds=60, cpu_load=5)
    try:
        b = (await client.get("/api/assistant/briefing", headers=auth(token))).json()
    finally:
        realtime_state._routers.pop(shop_id, None)
        realtime_state._routers.pop(quiet_id, None)

    network = b["routers"]["list"]
    assert [r["name"] for r in network] == ["Estate", "Shop", "Quiet"]          # down first, then reporting
    by_name = {r["name"]: r for r in network}
    assert by_name["Shop"]["live"] == {
        "cpu": 41, "memory_pct": 75, "uptime": "3d04:14:07", "version": "7.16.1", "board": "hAP ax2",
        "down_bps": 12_400_000.0, "up_bps": 2_100_000.0, "hotspot_online": 14, "pppoe_online": 3,
        "age_seconds": by_name["Shop"]["live"]["age_seconds"],
    }
    assert by_name["Shop"]["reachable_pct"] == 99.5 and by_name["Shop"]["active_customers"] == 2
    assert by_name["Estate"]["status"] == "offline" and by_name["Estate"]["active_customers"] == 1
    assert by_name["Estate"]["live"] is None and by_name["Estate"]["last_online_at"].endswith("Z")
    assert by_name["Quiet"]["live"] is None and by_name["Quiet"]["active_customers"] == 0

    # someone who may see routers but not customers gets no customer counts
    briefing_mod.reset_cache()
    _, staff_token = await _staff_token(db, reseller, ["routers.view"])
    s = (await client.get("/api/assistant/briefing", headers=auth(staff_token))).json()
    assert "routers" in s and "customers" not in s
    assert all(r["active_customers"] is None for r in s["routers"]["list"])


@pytest.mark.asyncio
async def test_briefing_shows_each_routers_ports_and_what_they_are_set_up_for(client, owner, db):
    """The home screen draws every socket: its role from the saved settings, its link from the
    router's own report. A port that had a link and lost it says so; an empty socket does not."""
    from datetime import datetime

    from app.services import realtime_state

    reseller, token = owner
    now = datetime.utcnow()
    site = await make_router(db, reseller, name="Site", last_status=True, last_checked_at=now,
                             pppoe_ports=["ether4"], dual_ports=["ether3"], plain_ports=["ether5"])
    lb = await make_router(db, reseller, name="Twin WAN", last_status=True, last_checked_at=now,
                           lb_enabled=True, lb_config={"wan_ports": ["ether1", "ether2"]})
    dark = await make_router(db, reseller, name="Dark", last_status=False, last_checked_at=now,
                             pppoe_ports=["ether2"])
    site_id, lb_id, dark_id = site.id, lb.id, dark.id

    def port(name, running, last_up="", disabled=False, downs=0):
        return {"name": name, "running": running, "disabled": disabled, "rx_bytes": 0, "tx_bytes": 0,
                "link_downs": downs, "last_link_up": last_up}

    bridge = "bridge"
    realtime_state._routers[site_id] = realtime_state.RouterLive(
        router_id=site_id, received_at=now, interval_seconds=60,
        ports=[port("ether1", True, "nov/24 09:00"), port("ether10", False), port("ether2", True, "nov/24 09:00"),
               port("ether3", True, "x"), port("ether4", True, "x"), port("ether5", True, "x"),
               port("ether6", False, "nov/24 16:00", downs=3), port("ether7", False, "x", disabled=True),
               port("ether8", False), port("wlan1", True, "x")],
        bridge_ports=[{"interface": p, "bridge": bridge} for p in ("ether2", "ether3", "ether4", "ether5", "ether6", "ether7")],
        bridge_hosts={"AA:00:00:00:00:01": "ether2", "AA:00:00:00:00:02": "ether2", "AA:00:00:00:00:03": "ether1"},
        bridge_hosts_at=now)
    # load balanced, and an older report with no bridge list: nothing is called unused
    realtime_state._routers[lb_id] = realtime_state.RouterLive(
        router_id=lb_id, received_at=now, interval_seconds=60,
        ports=[port("ether1", True, "x"), port("ether2", False, "x"), port("ether3", False)])
    # an offline router's last report is not drawn as its ports now
    realtime_state._routers[dark_id] = realtime_state.RouterLive(
        router_id=dark_id, received_at=now, interval_seconds=60, ports=[port("ether1", True, "x")])
    try:
        b = (await client.get("/api/assistant/briefing", headers=auth(token))).json()
    finally:
        for rid in (site_id, lb_id, dark_id):
            realtime_state._routers.pop(rid, None)

    by_name = {r["name"]: r for r in b["routers"]["list"]}
    ports = {p["name"]: p for p in by_name["Site"]["ports"]}
    assert [p["name"] for p in by_name["Site"]["ports"]] == [f"ether{i}" for i in (1, 2, 3, 4, 5, 6, 7, 8, 10)]
    assert {n: p["role"] for n, p in ports.items()} == {
        "ether1": "internet", "ether2": "hotspot", "ether3": "both", "ether4": "pppoe", "ether5": "free",
        "ether6": "hotspot", "ether7": "hotspot", "ether8": "unused", "ether10": "unused"}
    assert ports["ether6"] == {"name": "ether6", "role": "hotspot", "up": False, "disabled": False,
                               "lost_link": True, "link_downs": 3, "devices": 0}
    assert ports["ether2"]["up"] and ports["ether2"]["devices"] == 2 and not ports["ether2"]["lost_link"]
    assert ports["ether1"]["devices"] is None                      # the internet line has no customers behind it
    assert not ports["ether7"]["lost_link"] and ports["ether7"]["disabled"]   # switched off on purpose
    assert not ports["ether8"]["lost_link"] and not ports["ether10"]["lost_link"]  # empty sockets
    assert by_name["Site"]["port_setup"] == {"internet": ["ether1"], "pppoe": ["ether4"], "both": ["ether3"], "free": ["ether5"]}

    twin = {p["name"]: p for p in by_name["Twin WAN"]["ports"]}
    assert twin["ether2"]["role"] == "internet" and twin["ether2"]["lost_link"]
    assert twin["ether3"]["role"] == "hotspot" and twin["ether3"]["devices"] is None and not twin["ether3"]["lost_link"]
    assert by_name["Twin WAN"]["port_setup"]["internet"] == ["ether1", "ether2"]

    assert by_name["Dark"]["ports"] is None
    assert by_name["Dark"]["port_setup"]["pppoe"] == ["ether2"]


# ---------------------------------------------------------------------------
# Forms: a change the person completes before Confirm
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_form_card_is_completed_by_the_person_then_runs(client, owner, db):
    reseller, token = owner
    reseller_id = reseller.id
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d"),
        # only the name is known; the rest is left for the person
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "form": True,
                                "body": {"name": "Weekly 300", "connection_type": "hotspot"},
                                "summary": "New plan"}),
        text_reply("Fill in the plan and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "Can I add a new plan"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    conv_id = events[0]["id"]
    fields = {f["name"]: f for f in card["form"]}
    assert fields["name"]["value"] == "Weekly 300" and fields["name"]["required"]
    assert fields["price"]["required"] and fields["price"]["kind"] in ("number", "integer")
    assert fields["duration_unit"]["kind"] == "select" and fields["duration_unit"]["options"] == ["MINUTES", "HOURS", "DAYS"]
    assert [f["required"] for f in card["form"]] == sorted((f["required"] for f in card["form"]), reverse=True)

    # Confirm with the price still missing: nothing runs and the card is told why
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"speed": "5M/5M", "duration_value": "7", "duration_unit": "days"}}]})
    refused = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert refused["status"] == "pending" and not refused["ok"] and "'price' is required" in refused["detail"]
    db.expire_all()
    assert (await db.execute(select(Plan).where(Plan.user_id == reseller_id))).scalars().all() == []
    action = (await db.execute(select(AssistantAction))).scalars().one()
    assert action.status == "pending"

    # Completed (numbers typed as text, a select in any case): it runs once with those values
    model = use_model([text_reply("Done: Weekly 300 is live.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"price": "300", "speed": "5M/5M", "duration_value": "7",
                                  "duration_unit": "days", "password": "nope", "made_up": 1}}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done" and result["ok"]
    db.expire_all()
    plan = (await db.execute(select(Plan).where(Plan.user_id == reseller_id))).scalars().one()
    assert plan.name == "Weekly 300" and plan.price == 300 and plan.duration_value == 7
    action = (await db.execute(select(AssistantAction))).scalars().one()
    assert action.body["price"] == 300 and action.body["duration_unit"] == "DAYS"
    assert "password" not in action.body and "made_up" not in action.body  # only the form's own fields
    told = model.requests[0]["messages"][-1]["content"][0]["text"]
    assert '"sent"' in told and '"price":300' in told


def test_form_fields_keep_passwords_apart_and_read_lists():
    from app.services.assistant.catalog import Action, apply_form_values, form_fields

    action = Action(method="POST", template="/api/x", title="X", description="", tag="t", body_schema={
        "type": "object", "required": ["name", "router_password"],
        "properties": {
            "name": {"type": "string"}, "router_password": {"type": "string"},
            "limits": {"type": "object", "properties": {"a": {"type": "integer"}}},
            "devices": {"type": "integer", "minimum": 1, "maximum": 5}, "active": {"type": "boolean"},
            "ports": {"type": "array", "items": {"type": "string"}},
            "minutes": {"type": "array", "items": {"type": "integer"}},
            "confirm": {"type": "boolean"},
        },
    })
    fields = form_fields(action, {"name": "A", "router_password": "should-not-echo"})
    assert [f["name"] for f in fields] == ["name", "router_password", "devices", "active", "ports", "minutes"]
    password = next(f for f in fields if f["name"] == "router_password")
    assert password["kind"] == "password" and "value" not in password  # never sent back to the page
    assert next(f for f in fields if f["name"] == "minutes")["item_kind"] == "integer"
    body, secrets, problems = apply_form_values(action, {"name": "A"}, {
        "devices": "9", "active": "on", "router_password": "s3cret", "ports": "ether2, ether3", "minutes": "60,1440"})
    assert problems == ["'devices' must be at most 5"]
    assert body == {"name": "A", "active": True, "ports": ["ether2", "ether3"], "minutes": [60, 1440]}
    assert secrets == {"router_password": "s3cret"}  # apart from the body that is stored


@pytest.mark.asyncio
async def test_a_password_typed_in_a_form_is_used_once_and_kept_nowhere(client, owner, db):
    from app.db.models import ResellerStaff

    reseller, token = owner
    reseller_id = reseller.id
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/staff"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/staff", "form": True,
                                "body": {"name": "Jo Cashier", "email": "jo.cashier@example.com"}, "summary": "New staff"}),
        text_reply("Fill in Jo's login and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "add Jo as staff"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    conv_id = events[0]["id"]
    pw = next(f for f in card["form"] if f["name"] == "password")
    assert pw["kind"] == "password" and pw["required"] and "value" not in pw

    model = use_model([text_reply("Jo can sign in now.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"password": "Very-Secret-91", "permissions": ["customers.view"]}}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done", result
    db.expire_all()
    staff = (await db.execute(select(ResellerStaff).where(ResellerStaff.parent_reseller_id == reseller_id))).scalars().one()
    assert staff.name == "Jo Cashier"
    action = (await db.execute(select(AssistantAction))).scalars().one()
    assert "password" not in (action.body or {})
    convo = await client.get(f"/api/assistant/conversations/{conv_id}", headers=auth(token))
    assert "Very-Secret-91" not in convo.text and "Very-Secret-91" not in r.text
    assert "Very-Secret-91" not in json.dumps(model.requests)


@pytest.mark.asyncio
async def test_a_form_offers_the_persons_own_plans_and_routers_to_pick(client, owner, db):
    reseller, token = owner
    await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    await make_router(db, reseller, name="Main Tower")
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/customers/register"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/customers/register", "form": True,
                                "body": {"name": "Amina"}, "summary": "New customer"}),
        text_reply("Fill in Amina's details and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "add Amina"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    fields = {f["name"]: f for f in card["form"]}
    plan = fields["plan_id"]
    assert plan["kind"] == "select" and plan["value_kind"] == "integer"
    assert list(plan["option_labels"].values()) == ["Weekly 300"]
    if "router_id" in fields:
        assert list(fields["router_id"]["option_labels"].values()) == ["Main Tower"]


@pytest.mark.asyncio
async def test_an_edit_is_a_prefilled_form_and_runs_with_what_the_person_changed(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    plan_id = plan.id
    await db.commit()
    current = {"name": "Weekly 300", "speed": "5M/5M", "price": 350, "duration_value": 7,
               "duration_unit": "DAYS", "connection_type": "hotspot"}
    use_model([
        tool_reply("describe_action", {"method": "PUT", "path": "/api/plans/{plan_id}"}, "tu_d"),
        # no form flag: an edit is shown as a form anyway, filled with what the model sent
        tool_reply("call_api", {"method": "PUT", "path": f"/api/plans/{plan_id}", "body": current,
                                "summary": "Weekly 300 to KES 350"}),
        text_reply("Check the plan and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "weekly to 350"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    assert {f["name"]: f.get("value") for f in card["form"]}["price"] == 350
    conv_id = events[0]["id"]
    use_model([text_reply("Weekly 300 now costs KES 320.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True, "values": {"price": "320"}}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done", result
    db.expire_all()
    assert (await db.get(Plan, plan_id)).price == 320  # what the person typed, not what was proposed


@pytest.mark.asyncio
async def test_a_delete_waits_for_confirm_then_removes_the_record(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Old Promo", price=10, duration_value=1)
    plan_id = plan.id
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "DELETE", "path": "/api/plans/{plan_id}"}, "tu_d"),
        tool_reply("call_api", {"method": "DELETE", "path": f"/api/plans/{plan_id}", "summary": "Delete Old Promo"}),
        text_reply("Ready to delete Old Promo. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "delete old promo"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    assert card["method"] == "DELETE" and not card.get("form")  # nothing to fill in: a plain, red confirm
    assert await db.get(Plan, plan_id) is not None  # still there until Confirm
    conv_id = events[0]["id"]
    use_model([text_reply("Old Promo is deleted.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done", result
    db.expire_all()
    gone = await db.get(Plan, plan_id)
    assert gone is None or getattr(gone, "is_deleted", False) or getattr(gone, "deleted_at", None) is not None


@pytest.mark.asyncio
async def test_saying_a_form_is_ready_without_one_is_sent_back_once(client, owner, db):
    _, token = owner
    model = use_model([
        text_reply("You need a plan first. Fill it in and tap Confirm."),   # nothing proposed
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "form": True, "body": {}}),
        text_reply("The plan form is below."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "Generate 10 vouchers"},
                                           headers=auth(token))).text)
    assert any(e["type"] == "action" and e.get("form") for e in events)
    assert "[Check]" in json.dumps(model.requests[1]["messages"][-1])


@pytest.mark.asyncio
async def test_an_answer_sent_back_by_the_check_is_taken_off_the_screen(client, owner, db):
    """CR-1124-T3: a finished answer (with its NEXT line) said "tap Confirm" with nothing proposed;
    the check sent it back, a card was made and a second answer followed. The person must see one
    answer, with one NEXT line at its end, not both with the first NEXT line in the middle."""
    _, token = owner
    use_model([
        text_reply("The plan is already on screen; tap Confirm on that card.\n\nNEXT: Show my plans | Who is online?"),
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "form": True, "body": {}}),
        text_reply("The plan form is below. It runs when you tap Confirm.\n\nNEXT: Show my plans | Who expires today?"),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "Add a daily plan"},
                                           headers=auth(token))).text)
    assert any(e["type"] == "action" and e.get("form") for e in events)
    assert any(e["type"] == "retract" for e in events)
    shown = visible_text(events)
    assert shown == "The plan form is below. It runs when you tap Confirm.\n\nNEXT: Show my plans | Who expires today?"
    assert shown.count("NEXT:") == 1
    stored = (await client.get(f"/api/assistant/conversations/{events[0]['id']}", headers=auth(token))).json()
    said = [t["text"] for t in stored["transcript"] if t["type"] == "assistant"]
    assert said == [shown]

    # sent back, and the model then adds nothing: the first answer is all there is, so it stays
    use_model([
        text_reply("Fill it in and tap Confirm.\n\nNEXT: Show my plans"),
        text_reply(""),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "Add a weekly plan"},
                                           headers=auth(token))).text)
    assert visible_text(events) == "Fill it in and tap Confirm.\n\nNEXT: Show my plans"


@pytest.mark.asyncio
async def test_only_what_answers_the_question_is_drawn(client, owner, db):
    reseller, token = owner
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_router(db, reseller, name="Main Tower")
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/dashboard/analytics"}, "tu_1"),          # working it out: hidden
        tool_reply("call_api", {"method": "GET", "path": "/api/customers/active", "show": "table"}, "tu_2"),  # empty: said in words
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "table"}, "tu_3"),         # drawn
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "bars"}, "tu_4"),          # same list: replaces it
        tool_reply("call_api", {"method": "GET", "path": "/api/routers", "show": "table"}, "tu_5"),       # drawn (second)
        tool_reply("call_api", {"method": "GET", "path": "/api/dashboard/analytics", "show": "tiles"}, "tu_6"),  # a third: refused
        text_reply("You have one plan, Daily 50."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "which plans do I have?"},
                                           headers=auth(token))).text)
    drawn = [e for e in events if e["type"] == "data"]
    paths = [e["path"] for e in drawn]
    assert paths == ["/api/plans", "/api/plans", "/api/routers"], paths
    assert drawn[1]["replaces"] == drawn[0]["call_id"]  # the page keeps only the newer one
    told = [res for req in model.requests for res in tool_results(req)]
    assert any("Empty, so not drawn" in r.get("display", "") for r in told)
    assert any("results are already on screen" in r.get("display", "") for r in told)


@pytest.mark.asyncio
async def test_active_customers_can_be_filtered_by_when_their_time_ends(client, owner, db):
    from datetime import datetime, timedelta as td

    from app.db.models import CustomerStatus

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    now = datetime.utcnow()
    for name, hours in (("Soon", 5), ("In two days", 47), ("Next week", 24 * 6)):
        await make_customer(db, reseller, plan, name=name, phone=f"2547000000{hours % 100:02d}",
                            status=CustomerStatus.ACTIVE, expiry=now + td(hours=hours))
    await db.commit()
    r = await client.get("/api/customers/active?expires_within_hours=72", headers=auth(token))
    assert r.status_code == 200
    assert sorted(c["name"] for c in r.json()) == ["In two days", "Soon"]
    everyone = await client.get("/api/customers/active", headers=auth(token))
    assert len(everyone.json()) == 3


@pytest.mark.asyncio
async def test_the_customer_list_filters_on_the_server(client, owner, db):
    from datetime import datetime, timedelta as td

    from app.db.models import CustomerStatus

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    now = datetime.utcnow()
    await make_customer(db, reseller, plan, name="Paid Up", phone="254700000001",
                        status=CustomerStatus.ACTIVE, expiry=now + td(days=3))
    await make_customer(db, reseller, plan, name="Ran Out", phone="254700000002",
                        status=CustomerStatus.ACTIVE, expiry=now - td(hours=2))
    await make_customer(db, reseller, plan, name="Gone", phone="254700000003",
                        status=CustomerStatus.INACTIVE, expiry=now - td(days=9))
    pppoe = await make_customer(db, reseller, plan, name="Home Line", phone="254711222333",
                                status=CustomerStatus.ACTIVE, expiry=now + td(days=20))
    pppoe.pppoe_username = "home01"
    await db.commit()

    async def names(q):
        r = await client.get(f"/api/customers?{q}", headers=auth(token))
        assert r.status_code == 200, r.text
        return sorted(c["name"] for c in r.json())

    assert await names("status=active") == ["Home Line", "Paid Up", "Ran Out"]
    assert await names("status=inactive") == ["Gone"]
    assert await names("status=active&overdue=false") == ["Home Line", "Paid Up"]
    assert await names("overdue=true") == ["Gone", "Ran Out"]
    assert await names("connection_type=pppoe") == ["Home Line"]
    assert await names("connection_type=hotspot&status=active") == ["Paid Up", "Ran Out"]
    assert await names("search=0711222333") == ["Home Line"]
    assert await names("search=paid") == ["Paid Up"]
    assert await names("expires=next_7_days") == ["Paid Up"]
    assert await names("expires=past_7_days") == ["Ran Out"]
    assert (await client.get("/api/customers?expires=someday", headers=auth(token))).status_code == 422
    assert (await client.get("/api/customers?status=happy", headers=auth(token))).status_code == 422


@pytest.mark.asyncio
async def test_the_router_list_keeps_only_online_or_offline_ones(client, owner, db, monkeypatch):
    from app.api import router_management

    reseller, token = owner
    await make_router(db, reseller, name="Up One")
    await make_router(db, reseller, name="Down One")
    await db.commit()
    monkeypatch.setattr(router_management, "build_router_status",
                        lambda r, now=None: {"status": "offline" if r.name.startswith("Down") else "online"})

    async def names(q):
        r = await client.get(f"/api/routers{q}", headers=auth(token))
        assert r.status_code == 200, r.text
        return [x["name"] for x in r.json()]

    assert await names("?status=offline") == ["Down One"]
    assert await names("?status=online") == ["Up One"]
    assert sorted(await names("")) == ["Down One", "Up One"]


@pytest.mark.asyncio
async def test_any_list_is_narrowed_by_its_rows_before_it_is_drawn(client, owner, db):
    reseller, token = owner
    weekly = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    daily = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, weekly, name="On Weekly", phone="254700000011")
    await make_customer(db, reseller, daily, name="On Daily", phone="254700000012")
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers", "show": "table",
                                "where": [{"field": "plan.name", "op": "eq", "value": "weekly 300"}]}, "tu_1"),
        text_reply("One customer is on Weekly 300."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "who is on weekly 300?"},
                                           headers=auth(token))).text)
    drawn = [e for e in events if e["type"] == "data"]
    assert [c["name"] for c in drawn[0]["payload"]] == ["On Weekly"]
    told = [res for req in model.requests for res in tool_results(req)]
    assert told[0]["narrowed"] == {"rows_read": 2, "rows_kept": 1}


@pytest.mark.asyncio
async def test_a_rule_on_a_query_parameter_says_to_send_it_as_one(client, owner, db):
    """OPIC 2026-11-24: where online=true on the customer list failed with a bare "no such
    field", and the model fell back to the router's raw hotspot accounts. The error now says
    online is a query parameter of that endpoint, and how to send it."""
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, plan, name="On Daily", phone="254700000012")
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers", "show": "table",
                                "where": [{"field": "online", "op": "eq", "value": True}]}, "tu_1"),
        text_reply("Done."),
    ])
    await client.post("/api/assistant/chat", json={"message": "who is online?"}, headers=auth(token))
    told = [res for req in model.requests for res in tool_results(req)]
    assert "'online' is a query parameter of this endpoint" in told[0]["error"]
    assert '{"online": true}' in told[0]["error"]


@pytest.mark.asyncio
async def test_a_route_of_ids_only_is_never_drawn(client, owner, db):
    """"Who is online" read from /api/realtime/customers/online drew a table of bare ids
    (10 times in a week): it is never drawn, and the model is told which route shows people."""
    reseller, token = owner
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/realtime/customers/online", "show": "table"}, "tu_1"),
        text_reply("Done."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "who is online?"},
                                           headers=auth(token))).text)
    assert not [e for e in events if e["type"] == "data"]
    told = [res for req in model.requests for res in tool_results(req)]
    assert "/api/customers" in told[0]["display"] and '"online": true' in told[0]["display"]


@pytest.mark.asyncio
async def test_a_path_value_sent_in_query_goes_into_the_path(client, owner, db):
    """"/api/customers/{customer_id}" with customer_id in query reads that customer instead
    of failing with "A path value is missing"; with no value anywhere, the error shows where it goes."""
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    c = await make_customer(db, reseller, plan, name="Wanjiru", phone="254700000013")
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers/{customer_id}", "show": "card",
                                "query": {"customer_id": c.id}}, "tu_1"),
        tool_reply("call_api", {"method": "GET", "path": "/api/customers/{customer_id}"}, "tu_2"),
        text_reply("Done."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "show Wanjiru"},
                                           headers=auth(token))).text)
    drawn = [e for e in events if e["type"] == "data"]
    assert drawn and drawn[0]["path"] == f"/api/customers/{c.id}" and drawn[0]["payload"]["name"] == "Wanjiru"
    told = [res for req in model.requests for res in tool_results(req)]
    assert "GET /api/customers/<customer_id>" in told[1]["error"]


@pytest.mark.asyncio
async def test_a_narrowed_list_reads_every_page_first(client, owner, db):
    """"Whose time ends today" read from page one of many would quietly miss the rest."""
    from datetime import datetime, timedelta as td

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    now = datetime.utcnow()
    for i in range(5):
        await make_customer(db, reseller, plan, name=f"Far {i}", phone=f"25470000010{i}", expiry=now + td(days=20))
    await make_customer(db, reseller, plan, name="Last Page", phone="254700000199", expiry=now + td(minutes=30))
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers", "query": {"page": 1, "per_page": 2},
                                "show": "table", "where": [{"field": "expiry", "op": "lte", "value": "now+2h"}]}, "tu_1"),
        text_reply("One customer."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "who runs out soon?"},
                                           headers=auth(token))).text)
    told = [res for req in model.requests for res in tool_results(req)]
    assert told[0]["narrowed"]["rows_read"] == 6, told[0]
    assert told[0]["narrowed"]["rows_kept"] == 1
    assert "warning" not in told[0]["narrowed"]


@pytest.mark.asyncio
async def test_customers_by_plan_on_the_server(client, owner, db):
    reseller, token = owner
    weekly = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    daily = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, weekly, name="On Weekly", phone="254700000021")
    await make_customer(db, reseller, daily, name="On Daily", phone="254700000022")
    await db.commit()
    r = await client.get(f"/api/customers?plan_id={weekly.id}", headers=auth(token))
    assert [c["name"] for c in r.json()] == ["On Weekly"]


@pytest.mark.asyncio
async def test_a_filter_an_action_does_not_have_is_refused_not_ignored(client, owner, db):
    """"Active customers" once came back with inactive ones: the unknown filter was
    dropped and the whole list drawn. Now nothing runs and the model is told why."""
    reseller, token = owner
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "query": {"colour": "blue"}, "show": "table"}, "tu_1"),
        text_reply("Plans have no colour."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "blue plans?"},
                                           headers=auth(token))).text)
    assert not [e for e in events if e["type"] == "data"]   # nothing unfiltered reached the screen
    told = [res for req in model.requests for res in tool_results(req)]
    assert any("has no filter colour" in (r.get("error") or "") for r in told), told


@pytest.mark.asyncio
async def test_the_model_is_told_the_local_time_and_what_is_wrong_with_the_account(client, owner, db):
    from datetime import datetime, timedelta as td

    from app.db.models import InvoiceStatus, SubscriptionInvoice, SubscriptionStatus
    from tests.factories import make_sms_account

    reseller, token = owner
    # no router yet: nobody can buy, so the model is told
    model = use_model([text_reply("Set up a router first.")])
    await client.post("/api/assistant/chat", json={"message": "hi"}, headers=auth(token))
    assert "No router yet" in json.dumps(model.requests[0]["messages"][-1])

    # all well: the local clock, and nothing else
    await make_router(db, reseller, name="Main Tower")
    await db.commit()
    model = use_model([text_reply("Fine.")])
    await client.post("/api/assistant/chat", json={"message": "hi"}, headers=auth(token))
    said = json.dumps(model.requests[0]["messages"][-1])
    assert "EAT" in said and "Account now" not in said

    # suspended with an invoice open, and no SMS credits left
    reseller.subscription_status = SubscriptionStatus.SUSPENDED
    reseller.subscription_expires_at = datetime.utcnow() - td(days=2)
    now = datetime.utcnow()
    db.add(SubscriptionInvoice(user_id=reseller.id, period_start=now - td(days=32), period_end=now - td(days=2),
                               final_charge=1500, currency="KES", status=InvoiceStatus.OVERDUE, due_date=now - td(days=2)))
    await make_sms_account(db, reseller, balance=0)
    await db.commit()
    model = use_model([text_reply("Your account is suspended.")])
    await client.post("/api/assistant/chat", json={"message": "why can't customers buy?"}, headers=auth(token))
    said = json.dumps(model.requests[0]["messages"][-1])
    assert "subscription suspended" in said and "KES 1,500 to pay" in said
    assert "cannot buy internet" in said and "SMS credits: 0" in said


@pytest.mark.asyncio
async def test_an_sms_form_names_the_chosen_customers_and_never_widens_to_everyone(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    amina = await make_customer(db, reseller, plan, name="Amina Wanjiru", phone="254711000001")
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/send"}, "tu_1"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send", "form": True,
                                "body": {"body": "Hi Amina, your time ends today.", "customer_ids": [amina.id]}}, "tu_2"),
        text_reply("Check the message and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "text Amina"}, headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    fields = {f["name"]: f for f in card["form"]}
    assert fields["customer_ids"]["option_labels"] == {str(amina.id): "Amina Wanjiru · 254711000001"}
    assert fields["filter"]["kind"] == "select" and "active" in fields["filter"]["options"]
    # unticking her must not send to everyone
    use_model([text_reply("ok")])
    r = await client.post(f"/api/assistant/conversations/{events[0]['id']}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True, "values": {"customer_ids": []}}]})
    assert "pick at least one customer" in r.text


@pytest.mark.asyncio
async def test_words_written_next_to_a_lookup_are_taken_back_and_times_come_local(client, owner, db):
    from datetime import datetime, timedelta as td

    from app.db.models import CustomerStatus

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, plan, name="Amina", status=CustomerStatus.ACTIVE,
                        expiry=datetime.utcnow() + td(hours=5))
    await db.commit()
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/customers/active"}, "tu_1", text="I'll check who is active."),
        text_reply("Amina is active until 05:12, in about 5 hours."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "who is active?"},
                                           headers=auth(token))).text)
    assert visible_text(events) == "Amina is active until 05:12, in about 5 hours."
    assert any(e["type"] == "retract" for e in events)
    told = json.dumps([res for req in model.requests for res in tool_results(req)])
    assert " EAT, in 5 h" in told  # the model reads the time on the person's clock

    # a lookup and then nothing more to say: the note stays as the answer
    use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/plans", "show": "table"}, "tu_1", text="Here are your plans."),
        text_reply(""),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "my plans"},
                                           headers=auth(token))).text)
    assert visible_text(events) == "Here are your plans."


def test_a_form_shows_only_the_fields_of_the_chosen_kind():
    """One request model, many kinds (a till, a bank account, MTN...): the API says which
    fields go with which kind, and a form shows only those, whatever the request is for."""
    from app.services.assistant.catalog import Action, apply_form_values, form_fields

    schema = {
        "type": "object", "required": ["kind", "label"],
        "properties": {"kind": {"type": "string", "enum": ["till", "bank"]}, "label": {"type": "string"},
                       "till_number": {"type": "string"}, "bank_account": {"type": "string"},
                       "bank_api_key": {"type": "string"}, "note": {"type": "string"}},
        "x-fields-for": {"kind": {"till": ["till_number"], "bank": ["bank_account", "bank_api_key"]}},
        "x-required-for": {"kind": {"till": ["till_number"], "bank": ["bank_account"]}},
    }
    add = _action("POST", "/api/things", schema)
    fields = {f["name"]: f for f in form_fields(add, {"kind": "till", "label": "Shop"})}
    # the person can still switch the kind on the form: the page shows each kind's fields with it
    assert fields["till_number"]["when"] == {"kind": ["till"]} and fields["till_number"]["required"]
    assert fields["bank_account"]["when"] == {"kind": ["bank"]}
    assert "when" not in fields["note"] and "when" not in fields["label"]

    # typed into the bank fields, then chose a till: the bank values are not sent
    body, secrets, problems = apply_form_values(add, {"kind": "till", "label": "Shop"}, {
        "kind": "till", "label": "Shop", "till_number": "123456", "bank_account": "999", "bank_api_key": "s3cret"})
    assert body == {"kind": "till", "label": "Shop", "till_number": "123456"} and not secrets and not problems
    # the chosen kind's own required field
    _, _, problems = apply_form_values(add, {"kind": "bank", "label": "B"}, {"kind": "bank", "label": "B"})
    assert problems == ["'bank_account' is required"]

    # an edit: the kind is the record's own and not on the form; only its fields, none required
    edit_schema = {k: v for k, v in schema.items() if k not in ("required", "x-required-for")}
    edit_schema["properties"] = {k: v for k, v in schema["properties"].items() if k != "kind"}
    edit = _action("PUT", "/api/things/{id}", edit_schema)
    names = [f["name"] for f in form_fields(edit, {}, {"kind": "bank"})]
    assert sorted(names) == ["bank_account", "bank_api_key", "label", "note"]
    assert not any(f["required"] for f in form_fields(edit, {}, {"kind": "bank"}))
    # kind unknown: nothing to go by, every field as before
    assert len(form_fields(edit, {})) == 5


@pytest.mark.asyncio
async def test_editing_a_payment_method_shows_only_its_own_kind(client, owner, db):
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    reseller, token = owner
    pm = ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
                               label="Equity", bank_paybill_number="247247", bank_account_number="0170299999999")
    db.add(pm)
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "PUT", "path": "/api/payment-methods/{method_id}"}, "tu_d"),
        tool_reply("call_api", {"method": "PUT", "path": f"/api/payment-methods/{pm.id}",
                                "body": {"bank_account_number": "0170211111111"}}),
        text_reply("Check the new account number and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "new bank account number"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    names = {f["name"] for f in card["form"]}
    assert {"bank_account_number", "bank_paybill_number", "label"} <= names
    assert not any(n.startswith(("mpesa_", "mtn_", "fapshi_", "zenopay_")) for n in names), names


def _action(method, template, schema):
    from app.services.assistant.catalog import Action

    return Action(method=method, template=template, title="X", description="", tag="t", body_schema=schema)
def test_known_issues_find_the_fault_from_the_persons_own_words():
    from app.services.assistant import known_issues

    for words, expected in [
        ("amelipa lakini hana net", "paid-not-delivered"),
        ("router iko offline kila saa", "router-offline-flapping"),
        ("some sites work some don't since the load balancing", "lb-line-dropping-traffic"),
        ("one AP gives free internet", "ap-in-router-mode"),
        ("SMS haziendi", "sms-not-sending"),
    ]:
        found = known_issues.search(words)
        assert found["matches"][0]["id"] == expected, (words, [m["id"] for m in found["matches"]])
        assert found["check_in_this_order"]["id"] == "triage-order"
        assert all("keywords" not in m for m in found["matches"])  # matching aid, not knowledge
    assert known_issues.search(issue_id="rogue-dhcp")["matches"][0]["id"] == "rogue-dhcp"
    assert "error" in known_issues.search(issue_id="no-such-thing")


def test_known_issues_name_no_reseller_router_or_server():
    """Every reseller reads these: past cases stay general."""
    import re
    from pathlib import Path

    text = (Path(__file__).parent.parent / "app/services/assistant/known_issues.json").read_text(encoding="utf-8")
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)  # IP addresses
    assert not re.search(r"(?<![\d-])(?:\+?254|07|01)\d{8}\b", text)  # phone numbers
    assert not re.search(r"\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b", text, re.I)  # MACs
    assert not re.search(r"(?i)\b(router[- ]?\d{2,}|ssh|hetzner|aws|vault|wireguard|accel-ppp)\b", text)


def test_plan_customer_and_sms_forms_follow_the_choices_that_matter():
    """The dashboard's own rules, read from the API schema: a free trial has no 'was' price,
    FUP fields wait for a data cap, a customer's login fields follow the picked plan's type,
    and a plan picker appears only for an SMS to one plan."""
    import main
    from app.services.assistant.catalog import apply_form_values, form_fields, get_catalog

    catalog = get_catalog(main.app)
    act = lambda m, t: next(a for a in catalog.actions if a.method == m and a.template == t)  # noqa: E731
    plan = {f["name"]: f for f in form_fields(act("POST", "/api/plans/create"), {"plan_type": "free_trial"})}
    assert sorted(plan["original_price"]["when"]["plan_type"]) == ["emergency", "regular", "special_offer"]
    assert plan["trial_once_per_customer"]["when"] == {"connection_type": ["hotspot"], "plan_type": ["free_trial"]}
    assert plan["fup_throttle_profile"]["when"] == {"data_cap_mb": ["*"], "fup_action": ["throttle"]}
    # no cap: the FUP values typed before it was cleared are not sent
    body, _, problems = apply_form_values(act("POST", "/api/plans/create"), {}, {
        "name": "P", "speed": "5M/5M", "price": "50", "duration_value": "1", "duration_unit": "DAYS",
        "connection_type": "hotspot", "data_cap_mb": "", "fup_action": "throttle", "fup_throttle_profile": "1M/1M"})
    assert not problems and not {"fup_action", "fup_throttle_profile"} & set(body)

    customer = {f["name"]: f for f in form_fields(act("POST", "/api/customers/register"), {})}
    assert customer["pppoe_username"]["when"] == {"plan_id.connection_type": ["pppoe"]}
    # a fixed address for a static-IP customer, and optionally for a PPPoE one (as on the classic page)
    assert customer["static_ip"]["when"] == {"plan_id.connection_type": ["pppoe", "static_ip"]}
    assert customer["mac_address"]["when"] == {"plan_id.connection_type": ["hotspot"]}

    send = act("POST", "/api/messaging/send")
    assert {f["name"]: f for f in form_fields(send, {})}["plan_id"]["when"] == {"filter": ["by_plan"]}
    assert apply_form_values(send, {}, {"body": "hi", "filter": "by_plan"})[2] == ["'plan_id' is required"]
    body, _, _ = apply_form_values(send, {}, {"body": "hi", "filter": "all", "plan_id": "3"})
    assert "plan_id" not in body


@pytest.mark.asyncio
async def test_a_customer_form_tells_the_page_each_plans_type(client, owner, db):
    from app.db.models import ConnectionType

    reseller, token = owner
    router = await make_router(db, reseller, name="Main")
    hotspot = await make_plan(db, reseller, name="Daily", price=50, duration_value=1)
    pppoe = await make_plan(db, reseller, name="Home", price=2000, duration_value=30,
                            connection_type=ConnectionType.PPPOE, speed="10M/10M")
    ids = (str(router.id), str(hotspot.id), str(pppoe.id))
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/customers/register"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/customers/register", "form": True,
                                "body": {"name": "John", "phone": "0712345678", "plan_id": pppoe.id}}),
        text_reply("Fill in the PPPoE login and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "new pppoe customer"},
                                           headers=auth(token))).text)
    form = {f["name"]: f for f in next(e for e in events if e["type"] == "action")["form"]}
    assert form["plan_id"]["option_attrs"]["connection_type"] == {ids[1]: "hotspot", ids[2]: "pppoe"}
    assert form["plan_id"]["value"] == ids[2]


def test_a_bars_hint_keeps_the_one_asked_about():
    from app.services.assistant.agent import clean_fields

    assert clean_fields({"label": "name", "value": ["total_mb"], "highlight": " Guest 1766 "})["highlight"] == "Guest 1766"
    assert "highlight" not in clean_fields({"label": "name", "highlight": "x" * 500})


@pytest.mark.asyncio
async def test_the_rating_ask_is_quiet_and_rare(client, owner, db, monkeypatch):
    from datetime import date, datetime
    from app.db.models import AssistantRating, AssistantUsageDaily
    from app.services.assistant import ratings as ratings_mod

    reseller, token = owner
    reseller_id = reseller.id
    admin = await make_admin(db, email="ratings-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))

    async def asks(tok=token):
        return (await client.get("/api/assistant/status", headers=auth(tok))).json()["ask_rating"]

    # Not before they have really used it.
    assert await asks() is False
    db.add(AssistantUsageDaily(day=date.today(), user_id=reseller_id, staff_id=0, questions=ratings_mod.MIN_QUESTIONS))
    await db.commit()
    assert await asks() is True
    assert await asks(admin_token) is False                     # never platform admins

    # Once it has been on screen it stays away for the gap, however often the page loads.
    assert (await client.post("/api/assistant/rating/shown", headers=auth(token))).status_code == 200
    await client.post("/api/assistant/rating/shown", headers=auth(token))
    assert await asks() is False
    db.expire_all()
    row = (await db.execute(select(AssistantRating).where(AssistantRating.user_id == reseller_id))).scalar_one()
    assert row.shown_count == 1 and row.rating is None

    # After the gap it may come back, and after MAX_SHOWS it never does.
    row.shown_at = datetime.utcnow() - timedelta(days=ratings_mod.GAP_DAYS + 1)
    await db.commit()
    assert await asks() is True
    await client.post("/api/assistant/rating/dismiss", headers=auth(token))   # not now: also a gap
    assert await asks() is False
    db.expire_all()
    row = (await db.execute(select(AssistantRating).where(AssistantRating.user_id == reseller_id))).scalar_one()
    row.shown_count, row.shown_at, row.dismissed_at = ratings_mod.MAX_SHOWS, None, None
    await db.commit()
    assert await asks() is False

    # Rating is always possible (from the menu), replaces the earlier one, and ends the asking.
    r = await client.post("/api/assistant/rating", json={"rating": 4, "review": "  Fast, but the charts need work  ", "source": "menu"}, headers=auth(token))
    assert r.status_code == 200 and r.json()["rating"]["rating"] == 4
    assert r.json()["rating"]["review"] == "Fast, but the charts need work"
    r = await client.post("/api/assistant/rating", json={"rating": 5}, headers=auth(token))
    assert r.json()["rating"] == {"rating": 5, "review": "", "updated_at": r.json()["rating"]["updated_at"]}
    assert (await client.get("/api/assistant/rating", headers=auth(token))).json()["rating"]["rating"] == 5
    assert (await client.post("/api/assistant/rating", json={"rating": 6}, headers=auth(token))).status_code == 422
    assert await asks() is False

    # Bitwave sees the average, the spread and the reviews, with whose they are; resellers cannot.
    assert (await client.get("/api/admin/assistant/ratings", headers=auth(token))).status_code == 403
    report = (await client.get("/api/admin/assistant/ratings", headers=auth(admin_token))).json()
    assert report["count"] == 1 and report["average"] == 5
    assert report["distribution"] == {"1": 0, "2": 0, "3": 0, "4": 0, "5": 1}
    assert report["reviews"][0]["account"] == "Kwetu WiFi" and report["reviews"][0]["questions"] == ratings_mod.MIN_QUESTIONS


def test_the_portal_form_offers_hero_photos_with_the_hero_header():
    """The hero header's photo can be one of the built-in ones or the person's own upload,
    and it (with the logo) is asked for only when the header style is Hero, as on the classic page."""
    import main
    from app.api.portal_routes import HERO_PHOTO_PRESETS
    from app.services.assistant.catalog import form_fields, get_catalog

    catalog = get_catalog(main.app)
    edit = next(a for a in catalog.actions if a.method == "PUT" and a.template == "/api/portal/settings")
    fields = {f["name"]: f for f in form_fields(edit, {}, {"header_style": "hero"})}
    photo = fields["header_bg_image_url"]
    assert photo["upload"]["accept"] == "image/*"
    assert [p["label"] for p in photo["presets"]] == [label for label, _ in HERO_PHOTO_PRESETS]
    assert photo["when"] == {"header_style": ["hero"]} and fields["company_logo_url"]["when"] == {"header_style": ["hero"]}


def test_the_portal_form_says_what_each_support_number_does_on_the_login_page():
    """SKYLINK was told both "the WhatsApp button shows with social links" and "there is
    no WhatsApp option". The catalog now says what the portal really does with each field."""
    import main
    from app.services.assistant.catalog import form_fields, get_catalog

    catalog = get_catalog(main.app)
    edit = next(a for a in catalog.actions if a.method == "PUT" and a.template == "/api/portal/settings")
    props = catalog.describe(edit)["body"]["properties"]
    whatsapp = props["portal_support_whatsapp"]["description"]
    assert "not shown" in whatsapp and "portal_support_phone" in whatsapp
    assert "Call Support" in props["portal_support_phone"]["description"]
    assert "show_social_links" in props["whatsapp_group_url"]["description"]
    fields = {f["name"]: f for f in form_fields(edit, {}, {})}
    assert fields["portal_support_whatsapp"]["hint"] == whatsapp[:160]


@pytest.mark.asyncio
async def test_an_mpesa_payment_waits_for_the_pin_instead_of_saying_done(client, owner, db, monkeypatch):
    """Buying SMS credits only sends a PIN prompt: the card waits on the order's status,
    the model is told it is not paid, and the status read says when it is."""
    import app.api.messaging_routes as mr
    from app.db.models import SmsCreditOrder, SmsCreditOrderStatus

    reseller, token = owner

    class _Stk:
        checkout_request_id = "ws_CO_9"
        merchant_request_id = "mr_9"

    async def _fake_stk(**kwargs):
        assert kwargs["phone_number"] == "254712345678"   # "0712 345 678" cleaned the shared way
        return _Stk()
    monkeypatch.setattr(mr, "initiate_stk_push_direct", _fake_stk)

    body = {"quantity": 100, "phone_number": "0712 345 678"}
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/credits/purchase"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/credits/purchase", "body": body,
                                "summary": "Buy 100 SMS"}),
        text_reply("Ready. Tap Confirm."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Buy 100 SMS"}, headers=auth(token))
    events = sse_events(r.text)
    card = next(e for e in events if e["type"] == "action")
    model = use_model([text_reply("Check your phone and enter your PIN.")])
    r = await client.post(f"/api/assistant/conversations/{events[0]['id']}/decide",
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]}, headers=auth(token))
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    order = (await db.execute(select(SmsCreditOrder))).scalar_one()
    assert result["ok"] is True and result["payload"] is None
    assert result["awaiting"]["poll"] == f"/api/messaging/credits/orders/{order.id}"
    assert "254712345678" in result["awaiting"]["message"]
    confirmation = model.requests[0]["messages"][-1]["content"][0]["text"]
    assert "NOT paid yet" in confirmation and '"outcome":"done"' not in confirmation

    status = (await client.get(result["awaiting"]["poll"], headers=auth(token))).json()
    assert status["status"] == "pending" and status["paid"] is False
    order.status = SmsCreditOrderStatus.COMPLETED
    await db.commit()
    status = (await client.get(result["awaiting"]["poll"], headers=auth(token))).json()
    assert status["paid"] is True and status["summary"] == "Paid: 100 SMS added."


@pytest.mark.asyncio
async def test_feature_requests_are_recorded_once_and_ranked(client, owner, db, monkeypatch):
    """A feature nobody built yet: the assistant writes it down without a Confirm; a second
    account asking for the same thing in other words adds a vote, not a second post; Bitwave's
    own order comes first in the admin queue."""
    import app.api.feedback_routes as fr
    from app.db.models import FeedbackComment, FeedbackPost
    from app.services import feature_requests as frs

    async def _no_triage(_post_id):
        return None
    monkeypatch.setattr(fr, "run_feedback_triage", _no_triage)

    reseller, token = owner
    use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/feedback/requests",
                                "body": {"title": "Pick a customer's location on a map",
                                         "asked": "I want to choose the customer's location from a map"}}),
        text_reply("That is not there yet; I have passed it to Bitwave."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Can I pick a customer on a map?"}, headers=auth(token))
    events = sse_events(r.text)
    assert not any(e["type"] == "action" for e in events)     # recorded at once, no card to confirm
    [post] = (await db.execute(select(FeedbackPost))).scalars().all()
    assert post.source == "assistant" and post.upvotes == 1

    other = await make_reseller(db, email="other@example.com", organization_name="Other ISP")
    other_token = create_access_token(login_token_claims(other), timedelta(hours=1))
    r = await client.post("/api/feedback/requests", headers=auth(other_token), json={
        "title": "Map for customer locations", "asked": "show customers locations on a map please"})
    assert r.json()["recorded"] == "added_to_existing" and r.json()["accounts_asking"] == 2
    db.expire_all()
    assert len((await db.execute(select(FeedbackPost))).scalars().all()) == 1
    assert len((await db.execute(select(FeedbackComment))).scalars().all()) == 1
    # asking again from the same account is one vote still
    r = await client.post("/api/feedback/requests", headers=auth(other_token), json={
        "title": "Customer map", "asked": "map of customers", "same_as": post.id})
    assert r.json()["accounts_asking"] == 2

    r = await client.post("/api/feedback/requests", headers=auth(token), json={
        "title": "Export invoices to Excel", "asked": "I need my invoices in excel"})
    assert r.json()["recorded"] == "new"
    excel_id = r.json()["request_id"]

    admin = await make_admin(db, email="fr-admin@example.com")
    admin_token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    assert (await client.put("/api/admin/feedback/order", json={"post_ids": [excel_id]}, headers=auth(token))).status_code == 403
    assert (await client.put("/api/admin/feedback/order", json={"post_ids": [excel_id]}, headers=auth(admin_token))).status_code == 200
    queue = (await client.get("/api/admin/feedback/queue?kind=idea", headers=auth(admin_token))).json()["items"]
    assert [i["id"] for i in queue][0] == excel_id and queue[0]["admin_rank"] == 1
    assert {i["source"] for i in queue} == {"assistant"}
    assert frs.similarity("Export invoices to Excel", "Pick a customer's location on a map") < frs.MATCH_AT


def test_a_customer_form_marks_the_location_for_a_map():
    """The install location is one place picked on a map, not two numbers to type."""
    import main
    from app.services.assistant.catalog import form_fields, get_catalog

    catalog = get_catalog(main.app)
    register = next(a for a in catalog.actions if a.method == "POST" and a.template == "/api/customers/register")
    fields = {f["name"]: f for f in form_fields(register, {})}
    assert fields["latitude"]["geo"] == "lat" and fields["longitude"]["geo"] == "lng"


def test_a_router_is_added_with_a_two_question_setup_form_never_by_hand():
    """As on the classic setup page: the RouterOS version and the Wi-Fi name. The
    RouterBOARD question only for RouterOS 6; payment methods are not asked."""
    import main
    from app.services.assistant.catalog import form_fields, get_catalog

    catalog = get_catalog(main.app)
    assert not any(a.template == "/api/routers/create" for a in catalog.actions)
    setup = next(a for a in catalog.actions if a.method == "POST" and a.template == "/api/provision/create")
    fields = {f["name"]: f for f in form_fields(setup, {}, None)}
    assert fields["vpn_type"]["kind"] == "select" and fields["vpn_type"]["options"] == ["wireguard", "l2tp"]
    assert fields["vpn_type"]["value"] == "wireguard"
    assert fields["is_routerboard"]["when"] == {"vpn_type": ["l2tp"]}
    assert fields["payment_methods"].get("admin_only") is True
    assert "business name" in fields["ssid"]["hint"]


# ---------------------------------------------------------------------------
# SMS reminders: the server's cost, resuming after credits are bought, the draft's language
# ---------------------------------------------------------------------------

REMIND_TODAY = "Send a reminder SMS to the customers whose internet time ends today, asking them to buy again"


@pytest.mark.asyncio
async def test_an_sms_card_opens_with_the_servers_cost_and_one_confirm_sends(client, owner, db, monkeypatch):
    """The cost is the server's: recipients without a phone are left out, a long message counts
    its parts, and the model is handed the same figures it must quote."""
    import app.api.messaging_routes as mr

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    for i in range(3):
        await make_customer(db, reseller, plan, name=f"Guest {i}", phone=f"25471100010{i}")
    await make_customer(db, reseller, plan, name="No phone", phone="")
    await make_sms_account(db, reseller, balance=32)
    await db.commit()

    async def _no_dispatch(cid):
        pass
    monkeypatch.setattr(mr.sms_dispatch, "dispatch_campaign", _no_dispatch)

    text = "Hello, your internet time ends today. " * 5   # 190 GSM-7 characters: 2 parts
    model = use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/send"}, "tu_1"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": text, "filter": "all"}, "summary": "Reminder to everyone"}, "tu_2"),
        text_reply("Ready: 3 recipients, 6 credits. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "remind everyone"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    shown = next(e for e in events if e["type"] == "action_result" and e["action_id"] == card["action_id"])
    assert shown["status"] == "pending" and shown["preview_of"]
    assert shown["preview"]["credits_needed"] == 6 and shown["preview"]["recipients"] == 3
    assert shown["preview"]["parts_per_message"] == 2 and shown["preview"]["without_phone"] == 1
    told = tool_results(model.requests[2])[0]
    assert told["status"] == "waiting_for_confirmation"
    assert told["preview"]["credits_needed"] == 6 and told["preview"]["credits_balance"] == 32
    assert "never your own estimate" in told["preview_note"]

    use_model([text_reply("Sent.")])
    r = await client.post(f"/api/assistant/conversations/{events[0]['id']}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done" and result["ok"] is True
    assert result["payload"]["credits_reserved"] == 6 and result["payload"]["recipient_count"] == 3


@pytest.mark.asyncio
async def test_an_english_request_gets_an_english_draft(client, owner, db):
    """A Swahili draft for someone who wrote English goes back to the model to be written in
    English; only the English card reaches the person."""
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, plan, name="Guest 1", phone="254711000201")
    await make_sms_account(db, reseller, balance=50)
    await db.commit()
    swahili = ("Habari! Muda wako wa internet unaisha leo. Nunua tena kupitia M-Pesa ili uendelee "
               "kuwa online. Asante.")
    english = "Hello! Your internet time ends today. Buy again through M-Pesa to stay online. Thank you."
    model = use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/send"}, "tu_1"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": swahili, "filter": "expiring_today"}}, "tu_2"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": english, "filter": "expiring_today"}}, "tu_3"),
        text_reply("Ready. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": REMIND_TODAY},
                                           headers=auth(token))).text)
    cards = [e for e in events if e["type"] == "action"]
    assert len(cards) == 1 and cards[0]["body"]["body"] == english
    refused = tool_results(model.requests[2])[0]
    assert refused["_is_error"] and "in English" in refused["error"]

    # someone who writes Swahili gets their Swahili draft as it is
    use_model([
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": swahili, "filter": "expiring_today"}}, "tu_4"),
        text_reply("Tayari."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", headers=auth(token), json={
        "message": "Tuma ujumbe kwa wateja wangu ambao muda wao unaisha leo", "conversation_id": events[0]["id"]})).text)
    assert [e["body"]["body"] for e in events if e["type"] == "action"] == [swahili]


@pytest.mark.asyncio
async def test_an_account_set_to_swahili_keeps_a_swahili_draft(client, owner, db):
    reseller, token = owner
    reseller.preferred_language = "sw"
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, plan, name="Guest 1", phone="254711000301")
    await make_sms_account(db, reseller, balance=50)
    await db.commit()
    swahili = "Habari! Muda wako wa internet unaisha leo. Nunua tena ili uendelee kuwa online. Asante."
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/send"}, "tu_1"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": swahili, "filter": "expiring_today"}}, "tu_2"),
        text_reply("Ready."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": REMIND_TODAY},
                                           headers=auth(token))).text)
    assert [e["body"]["body"] for e in events if e["type"] == "action"] == [swahili]


@pytest.mark.asyncio
async def test_paid_credits_bring_the_reminder_card_back_without_asking(client, owner, db, monkeypatch):
    """0 credits: the assistant offers to buy some and promises the reminder. Once M-Pesa says
    paid, the chat carries on by itself and the reminder card is proposed again."""
    import asyncio

    import app.api.assistant_routes as ar
    import app.api.messaging_routes as mr
    from app.db.models import SmsCreditOrder, SmsCreditOrderStatus, SmsCreditTxnKind
    from app.services import sms_credits

    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    guest = await make_customer(db, reseller, plan, name="Guest 4936", phone="254711000401")
    await make_sms_account(db, reseller, balance=0)
    await db.commit()
    monkeypatch.setattr(ar, "PAYMENT_POLL_SECONDS", 0.01)
    monkeypatch.setattr(ar, "PAYMENT_FOLLOW_SECONDS", 20.0)

    class _Stk:
        checkout_request_id = "ws_CO_77"
        merchant_request_id = "mr_77"

    async def _fake_stk(**kwargs):
        return _Stk()
    monkeypatch.setattr(mr, "initiate_stk_push_direct", _fake_stk)

    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/credits/purchase"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/credits/purchase",
                                "body": {"quantity": 10, "phone_number": "0712345678"},
                                "summary": "Buy 10 SMS credits"}, "tu_p"),
        text_reply("Your SMS credits are 0. Buy 10 here; once it is paid I'll send the reminder."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": REMIND_TODAY},
                                           headers=auth(token))).text)
    conversation_id = events[0]["id"]
    buy = next(e for e in events if e["type"] == "action")
    use_model([text_reply("Check your phone and enter the PIN.")])
    r = await client.post(f"/api/assistant/conversations/{conversation_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": buy["action_id"], "approve": True}]})
    assert next(e for e in sse_events(r.text) if e["type"] == "action_result")["awaiting"]["kind"] == "mpesa"

    reminder = "Hello! Your internet time ends today. Buy again to stay online."
    model = use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/messaging/send"}, "tu_s1"),
        tool_reply("call_api", {"method": "POST", "path": "/api/messaging/send",
                                "body": {"body": reminder, "customer_ids": [guest.id]},
                                "summary": "Reminder to Guest 4936"}, "tu_s2"),
        text_reply("Paid: 10 credits added. The reminder is ready, tap Confirm."),
    ])
    # M-Pesa's callback settles the order
    order = (await db.execute(select(SmsCreditOrder))).scalar_one()
    order.status = SmsCreditOrderStatus.COMPLETED
    await sms_credits.grant(db, reseller.id, 10, SmsCreditTxnKind.PURCHASE, reference=f"SMS-{order.id}")
    await db.commit()
    await asyncio.wait_for(asyncio.gather(*list(ar._TASKS)), timeout=15)

    told = model.requests[0]["messages"][-1]["content"][0]["text"]
    assert told.startswith("[Confirmation results]") and '"payment_of":"' + buy["action_id"] + '"' in told
    assert "paid" in told and "propose that step's card now" in told
    conv = (await client.get(f"/api/assistant/conversations/{conversation_id}", headers=auth(token))).json()
    cards = [i for i in conv["transcript"] if i["type"] == "action"]
    assert cards[-1]["path"] == "/api/messaging/send" and cards[-1]["body"]["body"] == reminder
    assert any(i["type"] == "action_result" and i["action_id"] == cards[-1]["action_id"]
               and i.get("preview", {}).get("credits_needed") == 1 for i in conv["transcript"])

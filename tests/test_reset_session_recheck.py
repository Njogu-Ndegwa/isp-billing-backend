"""Reset session looks at the live session first.

A reset is decided while the customer is offline and runs minutes later, after a
Confirm. If their router dialled back in meanwhile, dropping that new session cuts
a connection that works again. The router is a fake: ``/ppp/active`` holds the
sessions each test puts there.
"""
from __future__ import annotations

import json
from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import customer_audit_routes
from app.db.models import ConnectionType, CustomerEvent, CustomerStatus
from app.services.mikrotik_api import MikroTikAPI
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)

RESET = "/api/customers/{customer_id}/reset-session"


class FakeRouter(MikroTikAPI):
    """MikroTikAPI without the socket: the real session-drop code runs against these rows."""

    sessions: list = []
    commands: list = []
    reachable = True
    read_error = None

    def connect(self):
        self.connected = type(self).reachable
        return self.connected

    def disconnect(self):
        self.connected = False

    def send_command(self, command, arguments=None):
        cls = type(self)
        cls.commands.append(command)
        if command == "/ppp/active/print":
            return {"success": True, "data": [dict(s) for s in cls.sessions]}
        if command == "/ppp/active/remove":
            cls.sessions[:] = [s for s in cls.sessions if s[".id"] != arguments["numbers"]]
            return {"success": True, "data": []}
        raise AssertionError(f"unexpected router command {command}")

    def send_command_optimized(self, command, proplist=None, query=None):
        cls = type(self)
        cls.commands.append(command)
        assert command == "/ppp/active/print"
        if cls.read_error:
            return {"error": cls.read_error}
        name = (query or "").removeprefix("?name=")
        return {"success": True, "data": [dict(s) for s in cls.sessions if not query or s["name"] == name]}


def _session(name: str, uptime: str, sid: str = "*1", address: str = "10.20.0.7") -> dict:
    return {".id": sid, "name": name, "service": "pppoe", "caller-id": "AA:BB:CC:00:00:01",
            "address": address, "uptime": uptime}


@pytest.fixture
def ppp(monkeypatch):
    async def inline_guard(router_id, func, *args, **kwargs):
        return func(*args)

    FakeRouter.sessions, FakeRouter.commands = [], []
    FakeRouter.reachable, FakeRouter.read_error = True, None
    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", FakeRouter)
    monkeypatch.setattr("app.services.router_concurrency.run_with_guard", inline_guard)
    customer_audit_routes._last_reset.clear()
    return FakeRouter


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _pppoe_customer(db, *, status=CustomerStatus.ACTIVE, username="acc_0043"):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username=username, status=status)
    return reseller, customer


# -- the rule ----------------------------------------------------------------

@pytest.mark.parametrize("uptimes, fresh_uptime", [
    (["1m12s"], 72),                 # just dialled back in
    (["00:00:40"], 40),              # the clock form RouterOS also uses
    (["9m59s"], 599),
    (["10m"], None),                 # at the limit it is an established session
    (["2d03:04:05"], None),          # the stuck session a reset is for
    (["1w2d", "45s"], 45),           # a second, new session beside an old one: the new one counts
    ([""], None),                    # the router gave no uptime: nothing to go on
    ([], None),
])
def test_only_a_session_that_just_started_is_fresh(uptimes, fresh_uptime):
    rows = [_session("acc_0043", u, sid=f"*{i}") for i, u in enumerate(uptimes)]
    rows.append(_session("someone_else", "5s", sid="*99"))  # another customer's session never counts
    fresh = customer_audit_routes._fresh_session(rows, "acc_0043")
    assert (fresh["uptime_seconds"] if fresh else None) == fresh_uptime


# -- the endpoint --------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_customer_who_just_came_back_online_is_not_dropped(db, ppp):
    reseller, customer = await _pppoe_customer(db)
    ppp.sessions = [_session("acc_0043", "1m12s")]

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    detail = exc.value.detail
    assert exc.value.status_code == 409 and detail["code"] == "customer_already_online"
    assert "already back online" in detail["message"] and "1 minute ago" in detail["message"]
    assert detail["uptime_seconds"] == 72 and detail["ip"] == "10.20.0.7"
    assert len(ppp.sessions) == 1 and "/ppp/active/remove" not in ppp.commands
    assert (await db.execute(select(CustomerEvent))).scalars().all() == []  # nothing happened: nothing logged

    # "Do it anyway" comes seconds later: the refusal must not have started the cooldown
    out = await customer_audit_routes.reset_customer_session(
        customer.id, db, _token(reseller), customer_audit_routes.ResetSessionRequest(force=True))
    assert out["disconnected"] == 1 and ppp.sessions == []
    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert event.event_type == "session_reset" and event.details == {"disconnected": 1, "forced": True}


@pytest.mark.asyncio
@pytest.mark.parametrize("market_code, zone, label", [
    ("KE", "Africa/Nairobi", "EAT"),
    ("ZM", "Africa/Lusaka", "CAT"),
    ("HT", "America/Port-au-Prince", None),  # EST or EDT, depending on the day
])
async def test_the_refusal_gives_the_reconnect_time_in_the_resellers_local_time(
        db, ppp, market_code, zone, label):
    from zoneinfo import ZoneInfo

    reseller, customer = await _pppoe_customer(db)
    reseller.market_code = market_code
    await db.commit()
    ppp.sessions = [_session("acc_0043", "1m12s")]

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    detail = exc.value.detail
    local = datetime.fromisoformat(detail["connected_at"]).astimezone(ZoneInfo(zone))
    assert f"1 minute ago (at {local:%H:%M} {label or local.tzname()})" in detail["message"]
    assert "UTC" not in detail["message"]
    assert exc.value.status_code == 409 and detail["code"] == "customer_already_online"


@pytest.mark.asyncio
async def test_force_drops_a_fresh_session_without_asking(db, ppp):
    reseller, customer = await _pppoe_customer(db)
    ppp.sessions = [_session("acc_0043", "20s"), _session("someone_else", "20s", sid="*2")]

    out = await customer_audit_routes.reset_customer_session(
        customer.id, db, _token(reseller), customer_audit_routes.ResetSessionRequest(force=True))
    assert out["disconnected"] == 1
    assert [s["name"] for s in ppp.sessions] == ["someone_else"]


@pytest.mark.asyncio
async def test_no_live_session_answers_as_before_and_says_nothing_was_dropped(db, ppp):
    reseller, customer = await _pppoe_customer(db)
    ppp.sessions = [_session("someone_else", "30s", sid="*2")]

    out = await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert (out["customer_id"], out["disconnected"]) == (customer.id, 0)
    assert "nothing to drop" in out["message"]
    assert len(ppp.sessions) == 1 and "/ppp/active/remove" not in ppp.commands
    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert "no active session" in event.message


@pytest.mark.asyncio
async def test_an_old_stuck_session_is_dropped_as_before(db, ppp):
    reseller, customer = await _pppoe_customer(db)
    ppp.sessions = [_session("acc_0043", "2d03:04:05")]

    out = await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert out["disconnected"] == 1 and ppp.sessions == []
    assert "dial again" in out["message"]
    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert event.event_type == "session_reset" and event.details == {"disconnected": 1}

    with pytest.raises(HTTPException) as exc:  # a real reset still starts the cooldown
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_a_customer_who_is_not_active_has_no_connection_to_protect(db, ppp):
    # An expired customer's new session can be the walled payment-page one: not "back online".
    reseller, customer = await _pppoe_customer(db, status=CustomerStatus.INACTIVE)
    ppp.sessions = [_session("acc_0043", "30s")]

    out = await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert out["disconnected"] == 1 and ppp.sessions == []


@pytest.mark.asyncio
async def test_when_the_live_session_cannot_be_read_nothing_is_dropped(db, ppp):
    reseller, customer = await _pppoe_customer(db)
    ppp.sessions = [_session("acc_0043", "1m")]
    ppp.read_error = "timeout"

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert exc.value.status_code == 502
    assert len(ppp.sessions) == 1 and customer.id not in customer_audit_routes._last_reset


# -- the assistant ------------------------------------------------------------

def test_the_assistant_is_told_to_look_again_and_cannot_set_force_itself():
    import main

    from app.services.assistant.catalog import get_catalog, reset_catalog

    reset_catalog()
    catalog = get_catalog(main.app)
    action = catalog.get("POST", RESET)
    assert action.overrides == ("force",) and not action.body_required
    assert "right before proposing" in action.description and not action.description.endswith("…")
    assert catalog.describe(action)["set_only_by_the_person"].startswith("force")


@pytest.mark.asyncio
async def test_assistant_reset_of_a_customer_who_came_back_offers_do_it_anyway(client, owner, db, ppp):
    reseller, token = owner
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller, name="Home #2")
    customer = await make_customer(db, reseller, plan, router, name="Fatuma",
                                   pppoe_username="acc_0043", status=CustomerStatus.ACTIVE)
    path = RESET.format(customer_id=customer.id)
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": RESET}, "tu_d"),
        # the model tries to force it itself: the flag is taken off
        tool_reply("call_api", {"method": "POST", "path": path, "body": {"force": True},
                                "summary": "Drop Fatuma's session so her router dials again"}),
        text_reply("Ready to reset Fatuma's session. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "reset fatuma's session"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    assert not card.get("body")
    conv_id = events[0]["id"]

    # she was offline when it was proposed; her router dials back in before the Confirm
    ppp.sessions = [_session("acc_0043", "1m5s")]
    model = use_model([text_reply("Fatuma is already back online, so I left her session alone.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]})
    out = sse_events(r.text)
    result = next(e for e in out if e["type"] == "action_result")
    assert result["status"] == "failed" and result["http_status"] == 409
    assert "already back online" in result["detail"] and "1 minute ago" in result["detail"]
    retry = next(e for e in out if e["type"] == "action")
    assert retry["retry_of"] == card["action_id"] and retry["body"] == {"force": True}
    assert "already back online" in retry["reason"]
    assert "Do it anyway" in json.dumps(model.requests[-1]["messages"][-1])
    assert len(ppp.sessions) == 1  # nothing ran past the refusal

    use_model([text_reply("Her session is reset.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": retry["action_id"], "approve": True}]})
    done = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert done["status"] == "done", done
    assert ppp.sessions == []


@pytest.mark.asyncio
async def test_the_dashboard_button_still_resets_with_no_body(client, owner, db, ppp):
    reseller, token = owner
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="acc_0043",
                                   status=CustomerStatus.ACTIVE)
    path = RESET.format(customer_id=customer.id)
    await db.commit()
    ppp.sessions = [_session("acc_0043", "3h12m5s")]

    r = await client.post(path, headers={**auth(token), "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["disconnected"] == 1 and ppp.sessions == []

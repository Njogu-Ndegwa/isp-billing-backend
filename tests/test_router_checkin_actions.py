"""Router actions over the check-in channel + owed access-credential changes.

What these pin, and why (router 118, 11-13 Nov 2026: tunnel dead, router
checking in over HTTPS, every API-only action silently failing):

* **Allowlist.** Only reboot / heal_tunnel / sync_access_credentials exist;
  a person can queue only reboot and heal_tunnel; every emitted field is
  whitelisted, so nothing a user types can become RouterOS code.
* **Idempotent, expiring, exactly once.** Repeated requests queue one action;
  heal/sync are re-sent without an ack, a bounded number of times, and
  expire; a reboot is sent once and never again, whatever happens next.
* **Only v3 appliers get action lines** (an older one would reject the whole
  frame and lose that check-in's hotspot deliveries).
* **Reboot fallback.** API reachable -> reboot now. Connect failed but the
  router checks in -> queued with an ETA. Timeout -> not queued (the command
  may already have reached the router).
* **Credentials.** A create/revoke the router could not take is recorded as
  pending, delivered by the API retry or over check-in, and a revoke never
  claims the router side is done when the router call failed.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import access_credential_routes as cred_routes
from app.api import router_operations
from app.config import settings
from app.db.models import AccessCredential, AccessCredStatus, RouterCheckinAction
from app.services import access_credential_sync as cred_sync
from app.services import checkin_applier_script as applier
from app.services import checkin_delivery as svc
from app.services import router_checkin_actions as actions
from app.services.access_credentials import _deprovision_direct_api_sync
from app.services.router_script_gate import GATE_BEGIN
from app.services.usage_push_auth import derive_checkin_token
from tests.factories import make_reseller, make_router

IDENT = "Router-0257"
URL = "https://isp.bitwavetechnologies.net/api/router/checkin"


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


@pytest.fixture(autouse=True)
def _clean_state():
    actions.reset_state()
    cred_sync.reset_state()
    yield
    actions.reset_state()
    cred_sync.reset_state()


@pytest_asyncio.fixture
async def setup(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=IDENT)
    return {"db": db, "reseller": reseller, "router": router}


async def _fresh(db, model, ident):
    """Re-read a row written by another session (the service's own)."""
    db.expire_all()
    return await db.get(model, ident)


def _v3(router_id, *, heal=True, now_mono=None):
    actions.note_checkin(router_id, version=3, heal=heal, uptime_seconds=18000,
                         now=datetime.utcnow(), now_mono=now_mono)


# ---------------------------------------------------------------------------
# Allowlist and line whitelists
# ---------------------------------------------------------------------------

def test_allowlist_is_exactly_the_three_actions():
    assert actions.ACTIONS == ("reboot", "heal_tunnel", "sync_access_credentials")
    assert actions.USER_ACTIONS == ("reboot", "heal_tunnel")


@pytest.mark.asyncio
async def test_enqueue_refuses_unknown_action(setup):
    for bad in ("run_script", "/system reset-configuration", "", "REBOOT"):
        with pytest.raises(actions.ActionRefused):
            await actions.enqueue(setup["router"].id, bad)


def test_action_lines_carry_only_a_letter_and_digits():
    assert actions.format_action_line("reboot", 7) == "R,000000000007"
    assert actions.format_action_line("heal_tunnel", 123) == "H,000000000123"
    assert actions.format_action_line("sync_access_credentials", 1) is None
    assert actions.format_action_line("anything", 1) is None


@pytest.mark.parametrize("kw", [
    {"username": 'bob"; /system reset'},
    {"username": "Bob"},  # uppercase is not a valid credential username
    {"username": "a,b"},
    {"password": "line\nbreak"},
    {"password": "x" * 129},
    {"password": "café"},
    {"rate": "5M/5M; /system reboot"},
    {"rate": "5m/5m"},
])
def test_unsafe_credential_fields_are_never_emitted(kw):
    args = {"cred_id": 330, "user_id": 140, "rate": "5M/5M", "username": "tyrell2220",
            "password": "pa$$, \"word\" [x]"}
    args.update(kw)
    assert actions.format_credential_add_line(**args) is None


def test_password_may_hold_commas_and_quotes_as_the_last_field():
    line = actions.format_credential_add_line(330, 140, "5M/5M", "tyrell2220", 'a,b"$[c]')
    assert line == 'C,330,140,5M/5M,tyrell2220,a,b"$[c]'
    assert actions.valid_action_line(line)
    assert actions.format_credential_add_line(330, 140, "-", "home", "x") == "C,330,140,-,home,x"


def test_remove_line_shapes():
    assert actions.format_credential_remove_line(322, "6e:a9:3d:06:34:fe", "denis") == \
        "D,322,6E:A9:3D:06:34:FE,denis"
    assert actions.format_credential_remove_line(322, None, "denis") == "D,322,-,denis"
    assert actions.format_credential_remove_line(322, "not-a-mac", "denis") is None


@pytest.mark.parametrize("line", [
    "R,123", "R,0000000000071", "X,000000000001", "C,1,2,5M/5M,ab,x",  # username too short
    "D,1,-,bob;x", "C,1,2,5M/5M,bob,pw\nR,000000000001", "",
])
def test_render_frame_drops_invalid_action_lines(line):
    frame = svc.render_frame(1, [], 60, action_lines=[line])
    assert frame.splitlines()[0] == "BWE1,1,0,60"


def test_parse_uptime_v6_and_v7():
    assert actions.parse_uptime("5h4m32s") == 5 * 3600 + 4 * 60 + 32
    assert actions.parse_uptime("1w2d3h4m5s") == 604800 + 2 * 86400 + 3 * 3600 + 245
    assert actions.parse_uptime("2d03:04:05") == 2 * 86400 + 3 * 3600 + 245
    assert actions.parse_uptime("00:00:42") == 42
    for bad in ("", "abc", "5x", "1h; rm"):
        assert actions.parse_uptime(bad) is None


def test_report_parses_v3_fields():
    report = svc.parse_checkin_body(
        f"v=3&id={IDENT}&n=0&macs=&u=1d02:03:04&h=1".encode())
    assert report.version == 3 and report.heal_available and not report.ack_only
    assert report.uptime_seconds == 86400 + 7384
    ack = svc.parse_checkin_body(f"v=3&id={IDENT}&ack=1&k=R000000000005,C330&f=D322,bogus".encode())
    assert ack.ack_only and ack.acks == (("R", 5), ("C", 330)) and ack.fails == (("D", 322),)


# ---------------------------------------------------------------------------
# Idempotency, redelivery, expiry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enqueue_is_idempotent_per_router_and_action(setup):
    rid = setup["router"].id
    a = await actions.enqueue(rid, "heal_tunnel")
    b = await actions.enqueue(rid, "heal_tunnel")
    c = await actions.enqueue(rid, "reboot")
    assert a.id == b.id and c.id != a.id


@pytest.mark.asyncio
async def test_heal_is_resent_without_ack_then_fails(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "heal_tunnel")
    t0 = datetime.utcnow()
    assert await actions.exchange(rid, heal_available=True, now=t0) == [f"H,{row.id:012d}"]
    # Within the redelivery window: nothing new.
    assert await actions.exchange(rid, heal_available=True, now=t0 + timedelta(seconds=30)) == []
    # No ack: re-sent (idempotent), up to MAX_DELIVERIES times, then failed.
    t = t0
    for _ in range(actions.MAX_DELIVERIES["heal_tunnel"] - 1):
        t += actions.REDELIVER_AFTER
        assert await actions.exchange(rid, heal_available=True, now=t) == [f"H,{row.id:012d}"]
    t += actions.REDELIVER_AFTER
    assert await actions.exchange(rid, heal_available=True, now=t) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "failed"


@pytest.mark.asyncio
async def test_heal_ack_marks_done_and_stops(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "heal_tunnel")
    t0 = datetime.utcnow()
    await actions.exchange(rid, heal_available=True, now=t0)
    await actions.exchange(rid, acks=[("H", row.id)], send=False, now=t0 + timedelta(seconds=5))
    assert await actions.exchange(rid, heal_available=True, now=t0 + timedelta(minutes=10)) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "done" and row.acknowledged_at is not None


@pytest.mark.asyncio
async def test_heal_without_the_script_fails_instead_of_looping(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "heal_tunnel")
    assert await actions.exchange(rid, heal_available=False) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "failed"


@pytest.mark.asyncio
async def test_pending_action_expires(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "heal_tunnel")
    later = datetime.utcnow() + actions.TTL["heal_tunnel"] + timedelta(seconds=1)
    assert await actions.exchange(rid, heal_available=True, now=later) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "expired"


@pytest.mark.asyncio
async def test_expire_stale_terminalizes_routers_that_stopped_checking_in(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "heal_tunnel")
    assert await actions.expire_stale(datetime.utcnow() + timedelta(hours=1)) == 1
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "expired"


@pytest.mark.asyncio
async def test_no_db_work_without_pending_actions_or_acks(setup, monkeypatch):
    rid = setup["router"].id
    await actions.exchange(rid)  # primes the hint (nothing pending)

    def boom():
        raise AssertionError("exchange must not open a session for an idle router")

    monkeypatch.setattr(actions.database, "async_session", boom)
    assert await actions.exchange(rid) == []


# ---------------------------------------------------------------------------
# Reboot: at most once, never loops
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reboot_is_sent_exactly_once_and_confirmed_by_uptime(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "reboot", reason="tunnel dead")
    t0 = datetime.utcnow()
    assert await actions.exchange(rid, uptime_seconds=18000, now=t0) == [f"R,{row.id:012d}"]
    # The ack POST: accepted, nothing handed out on it.
    assert await actions.exchange(rid, acks=[("R", row.id)], send=False, now=t0 + timedelta(seconds=3)) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "accepted"
    # Next report before the restart shows the same long uptime: still not re-sent.
    assert await actions.exchange(rid, uptime_seconds=18060, now=t0 + timedelta(minutes=3)) == []
    # After the restart the uptime is shorter than the time since delivery: done.
    assert await actions.exchange(rid, uptime_seconds=90, now=t0 + timedelta(minutes=4)) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "done" and row.delivery_count == 1


@pytest.mark.asyncio
async def test_unconfirmed_reboot_is_never_resent(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "reboot")
    t0 = datetime.utcnow()
    await actions.exchange(rid, uptime_seconds=18000, now=t0)
    for minutes in (3, 10, 25, 60):
        assert await actions.exchange(rid, uptime_seconds=18000 + minutes * 60,
                                      now=t0 + timedelta(minutes=minutes)) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "unconfirmed" and row.delivery_count == 1


@pytest.mark.asyncio
async def test_router_refusing_reboot_fails_it(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "reboot")
    await actions.exchange(rid, uptime_seconds=100)
    await actions.exchange(rid, fails=[("R", row.id)], send=False)
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "failed"


@pytest.mark.asyncio
async def test_ack_post_never_hands_out_a_reboot(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "reboot")
    assert await actions.exchange(rid, send=False) == []
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "pending" and row.delivery_count == 0


@pytest.mark.asyncio
async def test_reboot_cooldown(setup):
    rid = setup["router"].id
    row = await actions.enqueue(rid, "reboot")
    t0 = datetime.utcnow()
    await actions.exchange(rid, uptime_seconds=18000, now=t0)
    await actions.exchange(rid, uptime_seconds=30, now=t0 + timedelta(minutes=2))
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "done"
    with pytest.raises(actions.ActionRefused):
        await actions.enqueue(rid, "reboot", now=t0 + timedelta(minutes=5))
    again = await actions.enqueue(rid, "reboot", now=t0 + actions.REBOOT_COOLDOWN + timedelta(minutes=1))
    assert again.id != row.id


@pytest.mark.asyncio
async def test_reboot_goes_after_other_lines(setup):
    rid = setup["router"].id
    reboot = await actions.enqueue(rid, "reboot")
    heal = await actions.enqueue(rid, "heal_tunnel")
    lines = await actions.exchange(rid, heal_available=True, uptime_seconds=18000)
    assert lines == [f"H,{heal.id:012d}", f"R,{reboot.id:012d}"]


# ---------------------------------------------------------------------------
# Endpoint: only v3 appliers get action lines
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(setup, monkeypatch):
    import app.api.router_checkin_routes as routes

    monkeypatch.setattr(svc, "async_session", actions.database.async_session)
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    routes.reset_state()
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", True)
    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", False)
    monkeypatch.setattr(settings, "CHECKIN_MODE", "add")
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", str(setup["router"].id))
    application = FastAPI()
    application.include_router(routes.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _post(client, body):
    svc._last_checkin.clear()
    return await client.post(
        "/api/router/checkin", content=body,
        headers={"Authorization": f"Bearer {derive_checkin_token(IDENT)}", "Content-Type": "text/plain"},
    )


@pytest.mark.asyncio
async def test_old_applier_never_gets_action_lines(client, setup):
    await actions.enqueue(setup["router"].id, "reboot")
    for v in (1, 2):
        resp = await _post(client, f"v={v}&id={IDENT}&n=0&macs=&c=&o=")
        assert resp.status_code == 200
        assert not any(ln[:2] in ("R,", "H,", "C,", "D,") for ln in resp.text.splitlines())


@pytest.mark.asyncio
async def test_v3_check_in_gets_reboot_line_and_ack_is_recorded(client, setup):
    row = await actions.enqueue(setup["router"].id, "reboot")
    resp = await _post(client, f"v=3&id={IDENT}&n=0&macs=&c=&o=&u=5h4m32s&h=1")
    lines = resp.text.splitlines()
    header = lines[0].split(",")
    assert lines[-1] == "END" and int(header[2]) == len(lines) - 2
    assert f"R,{row.id:012d}" in lines
    ack = await _post(client, f"v=3&id={IDENT}&ack=1&k=R{row.id:012d}&f=")
    assert ack.status_code == 200 and ack.text.splitlines()[0].split(",")[2] == "0"
    row = await _fresh(setup["db"], RouterCheckinAction, row.id)
    assert row.state == "accepted"
    assert actions.router_caps(row.router_id).heal is True


@pytest.mark.asyncio
async def test_router_outside_delivery_allowlist_still_gets_actions(client, setup, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "999999")
    row = await actions.enqueue(setup["router"].id, "heal_tunnel")
    resp = await _post(client, f"v=3&id={IDENT}&n=0&macs=&u=1h&h=1")
    assert f"H,{row.id:012d}" in resp.text.splitlines()


@pytest.mark.asyncio
async def test_bad_token_never_reaches_actions(client, setup):
    await actions.enqueue(setup["router"].id, "reboot")
    svc._last_checkin.clear()
    resp = await client.post("/api/router/checkin", content=f"v=3&id={IDENT}&n=0&macs=",
                             headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Reboot endpoint fallback
# ---------------------------------------------------------------------------

def _guard_returning(result):
    async def _run_with_guard(*_args, **_kwargs):
        return result
    return _run_with_guard


@pytest.mark.asyncio
async def test_reachable_router_reboots_now_and_queues_nothing(setup, monkeypatch):
    _v3(setup["router"].id)
    monkeypatch.setattr(router_operations, "run_with_guard",
                        _guard_returning({"success": True, "message": "Reboot command sent to router"}))
    resp = await router_operations.reboot_router(
        setup["router"].id, router_operations.RebootRouterRequest(confirm=True), setup["db"],
        _token(setup["reseller"]))
    assert resp["success"] is True and resp.get("queued") is None
    assert (await setup["db"].execute(select(RouterCheckinAction))).scalars().all() == []


@pytest.mark.asyncio
async def test_unreachable_router_that_checks_in_gets_reboot_queued(setup, monkeypatch):
    rid = setup["router"].id
    _v3(rid)
    actions.note_next_poll(rid, 56)
    monkeypatch.setattr(router_operations, "run_with_guard",
                        _guard_returning({"error": "connect_failed", "message": "timed out"}))
    resp = await router_operations.reboot_router(
        rid, router_operations.RebootRouterRequest(confirm=True, reason="tunnel dead"), setup["db"],
        _token(setup["reseller"]))
    assert resp["success"] is True and resp["queued"] is True and resp["status"] == "queued"
    assert resp["message"] == "queued: the router will restart on its next check-in (about 1 min)"
    row = (await setup["db"].execute(select(RouterCheckinAction))).scalar_one()
    assert row.action == "reboot" and row.state == "pending" and row.reason == "tunnel dead"
    assert row.requested_by_user_id == setup["reseller"].id


@pytest.mark.asyncio
async def test_unreachable_router_without_v3_check_in_still_503(setup, monkeypatch):
    monkeypatch.setattr(router_operations, "run_with_guard",
                        _guard_returning({"error": "connect_failed", "message": "API service not reachable"}))
    with pytest.raises(HTTPException) as exc:
        await router_operations.reboot_router(
            setup["router"].id, router_operations.RebootRouterRequest(confirm=True), setup["db"],
            _token(setup["reseller"]))
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_timeout_is_never_queued(setup, monkeypatch):
    _v3(setup["router"].id)
    monkeypatch.setattr(router_operations, "run_with_guard",
                        _guard_returning({"error": "timeout", "detail": "Router reboot timed out"}))
    with pytest.raises(HTTPException) as exc:
        await router_operations.reboot_router(
            setup["router"].id, router_operations.RebootRouterRequest(confirm=True), setup["db"],
            _token(setup["reseller"]))
    assert exc.value.status_code == 504
    assert (await setup["db"].execute(select(RouterCheckinAction))).scalars().all() == []


def test_stale_capability_is_not_trusted():
    actions.note_checkin(5, version=3, heal=True, uptime_seconds=1, now=datetime.utcnow(), now_mono=0.0)
    assert actions.router_caps(5, now_mono=actions.CAPABILITY_FRESH_SECONDS + 1) is None
    actions.note_checkin(6, version=2, heal=True, uptime_seconds=1, now=datetime.utcnow(), now_mono=0.0)
    assert actions.router_caps(6, now_mono=1.0) is None


# ---------------------------------------------------------------------------
# Access credentials: pending, revoke semantics, delivery
# ---------------------------------------------------------------------------

def _fail(message="Failed to connect to router"):
    async def _call(*_args, **_kwargs):
        return {"error": "connection_failed", "message": message}
    return _call


def _ok():
    async def _call(*_args, **_kwargs):
        return {"success": True}
    return _call


@pytest.mark.asyncio
async def test_create_on_unreachable_router_is_pending_and_queued(setup, monkeypatch):
    monkeypatch.setattr(cred_routes, "provision_credential", _fail())
    resp = await cred_routes.create_credential(
        cred_routes.CreateRequest(router_id=setup["router"].id, username="tyrell2220", password="secret1",
                                  rate_limit="5/5"),
        setup["db"], _token(setup["reseller"]))
    assert resp["provisioned"] is False and resp["pending"] is True
    assert resp["router_status"] == "pending: router unreachable"
    assert resp["router_sync"] == "add" and resp["router_pending"] is True
    rows = (await setup["db"].execute(select(RouterCheckinAction))).scalars().all()
    assert [r.action for r in rows] == ["sync_access_credentials"]


@pytest.mark.asyncio
async def test_revoke_that_failed_on_router_does_not_claim_success(setup, monkeypatch):
    db = setup["db"]
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=setup["router"].id, username="denis",
                            password="pw1234", status=AccessCredStatus.ACTIVE,
                            bound_mac_address="6E:A9:3D:06:34:FE")
    db.add(cred)
    await db.commit()
    monkeypatch.setattr(cred_routes, "deprovision_credential", _fail())
    resp = await cred_routes.revoke_credential(cred.id, db, _token(setup["reseller"]))
    assert resp["status"] == "revoked"  # our login page refuses it at once
    assert resp["router_removed"] is False and resp["pending"] is True
    assert "pending: router unreachable" in resp["warning"]
    await db.refresh(cred)
    assert cred.router_sync == "remove" and cred.router_sync_mac == "6E:A9:3D:06:34:FE"
    assert cred.bound_mac_address is None


@pytest.mark.asyncio
async def test_revoke_that_reached_the_router_says_so(setup, monkeypatch):
    db = setup["db"]
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=setup["router"].id, username="daktari",
                            password="pw1234", status=AccessCredStatus.ACTIVE, router_sync="add")
    db.add(cred)
    await db.commit()
    monkeypatch.setattr(cred_routes, "deprovision_credential", _ok())
    resp = await cred_routes.revoke_credential(cred.id, db, _token(setup["reseller"]))
    assert resp["router_removed"] is True and "pending" not in resp
    await db.refresh(cred)
    assert cred.router_sync is None


@pytest.mark.asyncio
async def test_delete_on_unreachable_router_revokes_and_defers_the_delete(setup, monkeypatch):
    db = setup["db"]
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=setup["router"].id, username="sifuna",
                            password="pw1234", status=AccessCredStatus.ACTIVE)
    db.add(cred)
    await db.commit()
    monkeypatch.setattr(cred_routes, "deprovision_credential", _fail())
    resp = await cred_routes.delete_credential(cred.id, db, _token(setup["reseller"]))
    assert resp["deleted"] is False and resp["revoked"] is True and resp["pending"] is True
    await db.refresh(cred)
    assert cred.status == AccessCredStatus.REVOKED and cred.router_sync == "delete"


def test_deprovision_reports_a_failed_router_remove(monkeypatch):
    class FakeAPI:
        def __init__(self, *a, **k):
            self.last_connect_error = None

        def connect(self):
            return True

        def disconnect(self):
            pass

        def send_command(self, path, args=None):
            if path == "/ip/hotspot/user/print":
                return {"success": True, "data": [{".id": "*1", "name": "denis"}]}
            if path == "/ip/hotspot/user/remove":
                return {"error": "failure: not enough permissions"}
            return {"success": True, "data": []}

    import app.services.access_credentials as ac
    monkeypatch.setattr(ac, "MikroTikAPI", FakeAPI)
    res = _deprovision_direct_api_sync(
        {"ip": "10.0.0.13", "username": "u", "password": "p", "port": 8728},
        {"cred_id": 322, "username": "denis", "bound_mac_address": None})
    assert res["error"] == "remove_failed"


@pytest.mark.asyncio
async def test_credential_lines_go_over_check_in_and_acks_settle_them(setup):
    db = setup["db"]
    rid = setup["router"].id
    add = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="home", password="p,w",
                           rate_limit="5M/5M", status=AccessCredStatus.ACTIVE, router_sync="add")
    rem = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="denis", password="x",
                           status=AccessCredStatus.REVOKED, router_sync="remove",
                           router_sync_mac="6E:A9:3D:06:34:FE")
    gone = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="olduser", password="x",
                            status=AccessCredStatus.REVOKED, router_sync="delete")
    db.add_all([add, rem, gone])
    await db.commit()
    await actions.enqueue(rid, "sync_access_credentials")
    lines = await actions.exchange(rid)
    assert lines == [
        f"C,{add.id},{setup['reseller'].id},5M/5M,home,p,w",
        f"D,{rem.id},6E:A9:3D:06:34:FE,denis",
        f"D,{gone.id},-,olduser",
    ]
    add_id, rem_id, gone_id = add.id, rem.id, gone.id
    await actions.exchange(rid, acks=[("C", add_id), ("D", rem_id), ("D", gone_id)], send=False)
    assert (await _fresh(db, AccessCredential, add_id)).router_sync is None
    assert (await _fresh(db, AccessCredential, rem_id)).router_sync is None
    assert await _fresh(db, AccessCredential, gone_id) is None
    sync = (await db.execute(select(RouterCheckinAction))).scalar_one()
    await actions.exchange(rid, now=datetime.utcnow() + timedelta(minutes=3))
    sync = await _fresh(db, RouterCheckinAction, sync.id)
    assert sync.state == "done"


@pytest.mark.asyncio
async def test_stale_credential_ack_is_ignored(setup):
    db = setup["db"]
    rid = setup["router"].id
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="home", password="pw",
                            status=AccessCredStatus.REVOKED, router_sync="remove")
    db.add(cred)
    await db.commit()
    # An ack for an ADD (from before the revoke) must not clear the owed remove.
    cred_id = cred.id
    await actions.exchange(rid, acks=[("C", cred_id)], send=False)
    assert (await _fresh(db, AccessCredential, cred_id)).router_sync == "remove"


@pytest.mark.asyncio
async def test_api_retry_applies_owed_changes_and_backs_off(setup, monkeypatch):
    db = setup["db"]
    rid = setup["router"].id
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="tyrell2220", password="pw",
                            status=AccessCredStatus.ACTIVE, router_sync="add", router_sync_since=datetime.utcnow())
    db.add(cred)
    await db.commit()
    cred_id = cred.id
    import app.services.access_credentials as ac

    calls = []
    monkeypatch.setattr(ac, "_provision_direct_api_sync",
                        lambda info, payload: calls.append(payload) or {"error": "connection_failed"})
    stats = await cred_sync.retry_pending_credentials_background(now_mono=1000.0)
    assert stats["failed"] == 1 and len(calls) == 1
    # Backed off: not tried again on the next tick.
    stats = await cred_sync.retry_pending_credentials_background(now_mono=1060.0)
    assert stats["tried"] == 0
    monkeypatch.setattr(ac, "_provision_direct_api_sync", lambda info, payload: {"success": True})
    stats = await cred_sync.retry_pending_credentials_background(now_mono=1000.0 + cred_sync.BACKOFF_START_SECONDS)
    assert stats["applied"] == 1
    assert (await _fresh(db, AccessCredential, cred_id)).router_sync is None


# ---------------------------------------------------------------------------
# Router-side scripts (static checks; the bench is where they are proven)
# ---------------------------------------------------------------------------

def _src(**kw):
    return applier.render_checkin_applier_source(identity=IDENT, endpoint_url=URL, **kw)


@pytest.mark.parametrize("forbidden", [
    ":return", "/import", ":global", ":deserialize", ":parse", ":execute", ":onerror", ":timestamp",
    "delimiter=", "/file/read", "dst-path", "/interface wireguard",
])
def test_v3_applier_avoids_unportable_constructs(forbidden):
    assert forbidden not in _src(actions=True)


def test_v3_applier_balances_and_reports_v3():
    src = _src(actions=True)
    assert src.count("{") == src.count("}") and src.count("[") == src.count("]")
    assert src.count("(") == src.count(")") and src.count('"') % 2 == 0
    assert '("v=3&id="' in src and "&u=" in src and "&h=" in src
    assert "__" not in src.replace("DB_MANAGED", "")
    assert '("v=2&id="' in _src() and "/system reboot" not in _src()


def test_v3_applier_restarts_last_only_when_up_five_minutes():
    src = _src(actions=True)
    assert "[/system resource get uptime] > 5m" in src
    # The restart is the very last thing, after the frame was applied and the ack sent.
    assert src.rindex("/system reboot") > src.rindex("&ack=1")
    assert src.rindex("/system reboot") > src.index("# Cadence:")
    # Validation of every line still happens before any change.
    assert src.index(":set frameOk true") < src.index("/ip hotspot user add")


def test_v3_applier_only_removes_users_and_bindings_it_tagged():
    src = _src(actions=True)
    assert ':local tag ("ACCESS_CRED|cred:" . $aid . "|")' in src
    d_block = src[src.index(':if ($kind = "D") do={'):]
    assert "/ip hotspot user remove $u" in d_block
    assert d_block.index("$tag]] = \"num\"") < d_block.index("/ip hotspot user remove $u")
    assert ':if ([:pick $oc 0 11] = "ACCESS_CRED")' in src


def test_v3_applier_keeps_tunnel_transport():
    src = _src(actions=True, tunnel_endpoint_url="http://10.251.0.1:8088/api/router/checkin")
    assert "# bw-checkin-tunnel v1 http://10.251.0.1:8088/api/router/checkin" in src
    assert src.count("&ack=1") == 1


def test_v3_needs_reboot_policy():
    assert "reboot" in applier.POLICY_ACTIONS.split(",")
    assert "reboot" not in applier.POLICY.split(",")
    assert applier.same_policy("read,write,policy,test", "read,write,test,policy")


@pytest.mark.parametrize("kind", ["wg", "sstp"])
def test_heal_script_is_ungated_portable_and_never_reboots(kind):
    src = applier.render_heal_tunnel_source(kind)
    assert GATE_BEGIN not in src  # runs inside the gated applier run
    for forbidden in (":return", "/import", ":global", ":parse", ":execute", "/system reboot"):
        assert forbidden not in src
    assert src.count("{") == src.count("}") and src.count("[") == src.count("]")
    with pytest.raises(ValueError):
        applier.render_heal_tunnel_source("l2tp")


def test_heal_wg_never_enables_wg_aws():
    src = applier.render_heal_tunnel_source("wg")
    assert 'find where name="wg-hz" disabled=yes' in src
    assert 'name="wg-aws" disabled=yes' not in src


def test_install_policy_update_on_existing_applier():
    calls = []

    class FakeAPI:
        def send_command(self, path, args=None):
            calls.append((path, args))
            if path == "/system/script/print":
                return {"data": [{".id": "*1", "name": "bitwave-checkin", "source": "old",
                                  "policy": "read,write,policy,test"}]}
            if path == "/system/scheduler/print":
                return {"data": [{".id": "*2", "name": "bitwave-checkin", "disabled": "false",
                                  "on-event": "/system script run bitwave-checkin",
                                  "policy": "read,write,policy,test"}]}
            return {}

    res = applier.install_checkin_applier(FakeAPI(), identity=IDENT, endpoint_url=URL, actions=True)
    assert res["status"] == "updated"
    sets = {p: a for p, a in calls if p.endswith("/set")}
    assert sets["/system/script/set"]["policy"] == applier.POLICY_ACTIONS
    assert sets["/system/scheduler/set"]["policy"] == applier.POLICY_ACTIONS


def test_rollout_reads_the_current_applier_parameters():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import checkin_actions_rollout as rollout

    src = _src(tunnel_endpoint_url="http://10.251.0.1:8088/api/router/checkin",
               check_certificate="yes-without-crl")
    params = rollout.current_params(src)
    assert params == {"identity": IDENT, "endpoint_url": URL, "check_certificate": "yes-without-crl",
                      "tunnel_endpoint_url": "http://10.251.0.1:8088/api/router/checkin"}
    # Re-rendering v2 from what was read gives back the router's exact source.
    assert applier.render_checkin_applier_source(**params) == src


def test_new_modules_pass_the_session_discipline_guard():
    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "scripts"))
    from check_session_discipline import run_check

    failing, _, _ = run_check(
        ["app/services/router_checkin_actions.py", "app/services/access_credential_sync.py",
         "app/api/router_checkin_action_routes.py", "app/api/router_checkin_routes.py",
         "scripts/checkin_actions_rollout.py", "scripts/access_credential_router_reconcile.py"],
        repo / "scripts" / "session_discipline_allowlist.txt",
    )
    assert failing == []


@pytest.mark.asyncio
async def test_ack_for_a_line_older_than_the_last_change_does_not_clear_it(setup):
    db = setup["db"]
    rid = setup["router"].id
    cred = AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="home", password="old1",
                            status=AccessCredStatus.ACTIVE, router_sync="add")
    db.add(cred)
    await db.commit()
    cred_id = cred.id
    await actions.enqueue(rid, "sync_access_credentials")
    t0 = datetime.utcnow()
    assert (await actions.exchange(rid, now=t0))[0].endswith(",home,old1")
    # Password rotated (router still unreachable) after the line went out.
    cred = await _fresh(db, AccessCredential, cred_id)
    cred.password = "new2"
    cred.updated_at = t0 + timedelta(seconds=10)
    await db.commit()
    await actions.exchange(rid, acks=[("C", cred_id)], send=False, now=t0 + timedelta(seconds=20))
    assert (await _fresh(db, AccessCredential, cred_id)).router_sync == "add"
    lines = await actions.exchange(rid, now=t0 + actions.REDELIVER_AFTER + timedelta(seconds=30))
    assert lines and lines[0].endswith(",home,new2")


@pytest.mark.asyncio
async def test_retry_job_requeues_check_in_sync_for_v3_routers(setup, monkeypatch):
    db = setup["db"]
    rid = setup["router"].id
    db.add(AccessCredential(user_id=setup["reseller"].id, router_id=rid, username="home", password="pw",
                            status=AccessCredStatus.ACTIVE, router_sync="add"))
    await db.commit()
    _v3(rid)
    import app.services.access_credentials as ac
    monkeypatch.setattr(ac, "_provision_direct_api_sync", lambda info, payload: {"error": "connection_failed"})
    await cred_sync.retry_pending_credentials_background(now_mono=1.0)
    rows = (await db.execute(select(RouterCheckinAction))).scalars().all()
    assert [r.action for r in rows] == ["sync_access_credentials"]

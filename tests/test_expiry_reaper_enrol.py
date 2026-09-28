"""Automatic reaper enrolment: hAP lite class boards stay on server-side
removal, other eligible routers get the reaper (app/services/expiry_reaper_enrol.py)."""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db import database
from app.db.models import (
    ConnectionType, CustomerStatus, Router, RouterAuthMethod, SubscriptionStatus,
)
from app.services import expiry_reaper_enrol as enrol
from app.services.expiry_reaper_enrol import (
    MODE_ROUTER, MODE_SERVER, classify_board, needs_tunnel, recheck_after, routeros_version_ok,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

MAC = "AA:BB:CC:00:00:01"


# --- pure rules -------------------------------------------------------------

@pytest.mark.parametrize("board,model,mode", [
    ("hAP lite", "RB941-2nD", MODE_SERVER),
    ("", "RB941-2nD", MODE_SERVER),
    ("hAP mini", "RB931-2nD", MODE_SERVER),
    ("RB951Ui-2HnD", "RB951Ui-2HnD", MODE_ROUTER),
    ("hAP ac lite", "RB952Ui-5ac2nD", MODE_ROUTER),      # not the hAP lite class
    ("hAP ax S", "E62iUGS-2axD5axT", MODE_ROUTER),
    ("RB4011iGS+", "RB4011iGS+", MODE_ROUTER),
    ("hEX S", "RB760iGS", MODE_ROUTER),
])
def test_classify_board(board, model, mode):
    assert classify_board(board, model) == mode


def test_small_older_boards_need_the_tunnel_bigger_ones_do_not():
    assert needs_tunnel("RB951Ui-2HnD", "RB951Ui-2HnD")
    assert not needs_tunnel("hAP ax S", "E62iUGS-2axD5axT")
    assert not needs_tunnel("RB5009UG+S+", "RB5009UG+S+")


def test_routeros_version_floor():
    assert routeros_version_ok("6.49.19 (long-term)") and routeros_version_ok("7.14 (stable)")
    assert not routeros_version_ok("6.42.1") and not routeros_version_ok("garbage")


def test_hardware_decisions_are_rechecked_weekly_passing_ones_in_two_hours():
    assert recheck_after("small board hAP lite") == timedelta(days=7)
    assert recheck_after("unreachable") == timedelta(hours=2)
    assert recheck_after(None) == timedelta(hours=2)


# --- fakes ------------------------------------------------------------------

OPEN_SESSIONS = {"n": 0}


def counting(session_factory):
    @asynccontextmanager
    async def factory():
        OPEN_SESSIONS["n"] += 1
        try:
            async with session_factory() as s:
                yield s
        finally:
            OPEN_SESSIONS["n"] -= 1
    return factory


class FakeRouterOS:
    def __init__(self, identity, *, board="RB951Ui-2HnD", model="RB951Ui-2HnD", version="6.49.19",
                 cpu=10, tunnel=True, reachable=True, scheduler_error=None, clock_ok=True):
        self.identity, self.board, self.model, self.version = identity, board, model, version
        self.cpu, self.tunnel, self.reachable = cpu, tunnel, reachable
        self.scheduler_error, self.clock_ok = scheduler_error, clock_ok
        self.commands = []
        self.bindings = [{".id": "*1", "mac-address": MAC, "comment": "USER:AABBCC000001|EXPIRES:DB_MANAGED"}]
        self.installed = False

    def connect(self):
        # AGENTS.md rule 1: no DB session may be open while we talk to the router.
        assert OPEN_SESSIONS["n"] == 0, "DB session held across RouterOS I/O"
        return self.reachable

    def disconnect(self):
        pass

    def send_command(self, cmd, args=None):
        self.commands.append((cmd, dict(args or {})))
        if cmd == "/system/identity/print":
            return {"data": [{"name": self.identity}]}
        if cmd == "/system/resource/print":
            return {"data": [{"board-name": self.board, "version": self.version, "cpu-load": str(self.cpu)}]}
        if cmd == "/system/routerboard/print":
            return {"data": [{"model": self.model}]}
        if cmd == "/ping":
            return {"data": [{"time": "30ms"}] if self.tunnel else [{"status": "timeout"}]}
        if cmd == "/ip/hotspot/ip-binding/print":
            return {"data": self.bindings}
        if cmd == "/ip/hotspot/ip-binding/set":
            for b in self.bindings:
                if b[".id"] == args[".id"]:
                    b["comment"] = args["comment"]
            return {"data": []}
        if cmd == "/system/scheduler/add":
            if self.scheduler_error:
                return {"error": self.scheduler_error}
            self.installed = True
            return {"data": []}
        if cmd == "/system/script/environment/print":
            return {"data": [{"name": "bwExpClockOk", "value": "true" if self.clock_ok else "false"}]
                    if self.installed else []}
        return {"data": []}

    def did(self, cmd):
        return any(c == cmd for c, _ in self.commands)


@pytest.fixture
def wired(session_factory, monkeypatch):
    OPEN_SESSIONS["n"] = 0
    monkeypatch.setattr(database, "async_session", counting(session_factory))
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_AUTO_ENROL", True)
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_ENROL_BATCH", 5)
    monkeypatch.setattr(enrol, "VERIFY_WAIT_SECONDS", 0)
    monkeypatch.setattr(enrol, "_running", False)
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    routers: dict[str, FakeRouterOS] = {}
    monkeypatch.setattr(enrol, "MikroTikAPI", lambda ip, *a, **k: routers[ip])
    return routers


async def _router(db, ip, identity, reseller=None, **kw):
    reseller = reseller or await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    return await make_router(db, reseller, ip_address=ip, identity=identity, **kw)


async def _reload(db, router_id):
    db.expire_all()
    return (await db.execute(select(Router).where(Router.id == router_id))).scalars().one()


# --- the job ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_switched_off_does_nothing(db, wired, monkeypatch):
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_AUTO_ENROL", False)
    r = await _router(db, "10.0.0.50", "Router-5000")
    wired["10.0.0.50"] = FakeRouterOS("Router-5000")
    assert await enrol.expiry_reaper_enrol_background() == []
    assert wired["10.0.0.50"].commands == []
    assert (await _reload(db, r.id)).expiry_reaper_mode is None


@pytest.mark.asyncio
async def test_sheds_load_when_the_pool_is_busy(db, wired, monkeypatch):
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: True)
    await _router(db, "10.0.0.51", "Router-5001")
    wired["10.0.0.51"] = FakeRouterOS("Router-5001")
    assert await enrol.expiry_reaper_enrol_background() == []
    assert wired["10.0.0.51"].commands == []


@pytest.mark.asyncio
async def test_hap_lite_goes_to_server_side_without_touching_the_router(db, wired):
    r = await _router(db, "10.0.0.52", "Router-5002")
    fake = wired["10.0.0.52"] = FakeRouterOS("Router-5002", board="hAP lite", model="RB941-2nD")
    [o] = await enrol.expiry_reaper_enrol_background()
    assert (o.mode, o.reason) == (MODE_SERVER, "small board hAP lite")
    assert not fake.did("/system/script/add") and not fake.did("/system/ntp/client/set")
    row = await _reload(db, r.id)
    assert (row.expiry_reaper_mode, row.expiry_reaper_enabled) == (MODE_SERVER, False)
    assert row.expiry_reaper_checked_at is not None
    # decided: not probed again on the next run
    fake.commands.clear()
    assert await enrol.expiry_reaper_enrol_background() == []
    assert fake.commands == []


@pytest.mark.asyncio
async def test_standard_board_gets_the_reaper_and_the_flag_after_verify(db, wired):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    r = await _router(db, "10.0.0.53", "Router-5003", reseller=reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    await make_customer(db, reseller, plan, r, mac_address=MAC, status=CustomerStatus.ACTIVE,
                        expiry=datetime.utcnow() + timedelta(hours=3))
    fake = wired["10.0.0.53"] = FakeRouterOS("Router-5003")
    [o] = await enrol.expiry_reaper_enrol_background()
    assert (o.mode, o.reason, o.installed) == (MODE_ROUTER, "installed", True)
    assert fake.did("/system/script/add") and fake.did("/system/scheduler/add")
    assert "EXP:" in fake.bindings[0]["comment"]          # paid customer tagged
    row = await _reload(db, r.id)
    assert row.expiry_reaper_enabled and row.expiry_reaper_mode == MODE_ROUTER
    assert row.expiry_reaper_installed_at is not None


@pytest.mark.asyncio
async def test_unconfirmed_clock_is_not_enabled_and_is_retried(db, wired):
    r = await _router(db, "10.0.0.54", "Router-5004")
    wired["10.0.0.54"] = FakeRouterOS("Router-5004", clock_ok=False)
    [o] = await enrol.expiry_reaper_enrol_background()
    assert o.mode is None and not o.installed
    row = await _reload(db, r.id)
    assert not row.expiry_reaper_enabled and row.expiry_reaper_mode is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kw,reason_start,mode", [
    (dict(reachable=False), "unreachable", None),
    (dict(cpu=95), "busy", None),
    (dict(version="6.40.9"), "RouterOS 6.40.9 too old", MODE_SERVER),
    (dict(tunnel=False), "no tunnel route", MODE_SERVER),
    (dict(scheduler_error="failure: configuration flagged"), "scheduler add refused", MODE_SERVER),
])
async def test_routers_that_cannot_take_the_reaper(db, wired, kw, reason_start, mode):
    r = await _router(db, "10.0.0.55", "Router-5005")
    fake = wired["10.0.0.55"] = FakeRouterOS("Router-5005", **kw)
    [o] = await enrol.expiry_reaper_enrol_background()
    assert o.reason.startswith(reason_start) and o.mode == mode and not o.installed
    assert not (await _reload(db, r.id)).expiry_reaper_enabled
    if kw.get("scheduler_error"):
        # the half-installed script is cleaned up again
        assert fake.did("/system/script/remove") or fake.did("/system/script/print")


@pytest.mark.asyncio
async def test_bigger_board_without_tunnel_still_enrols_over_https(db, wired):
    await _router(db, "10.0.0.56", "Router-5006")
    wired["10.0.0.56"] = FakeRouterOS("Router-5006", board="hAP ax S", model="E62iUGS-2axD5axT",
                                      version="7.20.6", tunnel=False)
    [o] = await enrol.expiry_reaper_enrol_background()
    assert o.installed


@pytest.mark.asyncio
async def test_ineligible_routers_are_never_contacted(db, wired):
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    await _router(db, "10.0.0.60", "Router-5010", reseller=suspended)
    await _router(db, "10.0.0.61", "Router-5011", auth_method=RouterAuthMethod.RADIUS)
    await _router(db, "10.0.0.62", "Router-5012", expiry_reaper_enabled=True)
    await _router(db, "10.0.0.63", "Router-5013", last_status=False)
    for ip, ident in (("10.0.0.60", "Router-5010"), ("10.0.0.61", "Router-5011"),
                      ("10.0.0.62", "Router-5012"), ("10.0.0.63", "Router-5013")):
        wired[ip] = FakeRouterOS(ident)
    assert await enrol.expiry_reaper_enrol_background() == []
    assert all(f.commands == [] for f in wired.values())


@pytest.mark.asyncio
async def test_batch_limit(db, wired, monkeypatch):
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_ENROL_BATCH", 2)
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    for i in range(4):
        await _router(db, f"10.0.1.{i}", f"Router-60{i}0", reseller=reseller)
        wired[f"10.0.1.{i}"] = FakeRouterOS(f"Router-60{i}0", board="hAP lite", model="RB941-2nD")
    assert len(await enrol.expiry_reaper_enrol_background()) == 2
    assert len(await enrol.expiry_reaper_enrol_background()) == 2
    assert await enrol.expiry_reaper_enrol_background() == []


@pytest.mark.asyncio
async def test_identity_mismatch_is_not_touched(db, wired):
    await _router(db, "10.0.0.57", "Router-5007")
    fake = wired["10.0.0.57"] = FakeRouterOS("Router-9999")
    [o] = await enrol.expiry_reaper_enrol_background()
    assert o.reason.startswith("identity mismatch") and o.mode is None
    assert not fake.did("/system/script/add")


# --- tunnel check -------------------------------------------------------------

class _PingFetch:
    def __init__(self, ping_times, fetch):
        self.ping_times, self.fetch = ping_times, fetch

    def send_command(self, cmd, args=None):
        if cmd == "/ping":
            return {"data": [{"time": t} if t else {"status": "timeout"} for t in self.ping_times]}
        if cmd == "/tool/fetch":
            return self.fetch
        return {"data": []}


@pytest.mark.parametrize("pings,fetch,ok", [
    (["30ms", None, None], {"error": "x"}, True),                              # any ping answer
    ([None, None, None], {"error": "failure: closing connection: <401 Unauthorized> 10.251.0.1:8088 (4)"}, True),
    ([None, None, None], {"success": True, "data": [{"status": "finished"}]}, True),
    ([None, None, None], {"error": "failure: connection timeout"}, False),
])
def test_tunnel_reachable_falls_back_to_a_real_http_call(pings, fetch, ok):
    assert enrol.tunnel_reachable(_PingFetch(pings, fetch), "http://10.251.0.1:8088/x") is ok


def test_enrolment_is_on_by_default():
    from app.config import Settings
    assert Settings.model_fields["EXPIRY_REAPER_AUTO_ENROL"].default is True



# --- re-check windows ---------------------------------------------------------

def test_recheck_windows_by_reason_and_router_age():
    now = datetime(2026, 9, 28, 12, 0)
    assert recheck_after("scheduler add refused: failure: configuration flagged") == timedelta(days=7)
    assert recheck_after("RouterOS 6.40.1 too old") == timedelta(days=7)
    assert recheck_after("no tunnel route (RB951Ui-2HnD would use HTTPS)") == timedelta(hours=24)
    assert recheck_after("no hotspot ip-binding table") == timedelta(hours=24)
    assert recheck_after("unreachable", now - timedelta(hours=3), now) == timedelta(minutes=30)
    assert recheck_after("unreachable", now - timedelta(days=5), now) == timedelta(hours=2)
    # a new router's permanent reason still waits a week
    assert recheck_after("small board hAP lite", now - timedelta(hours=1), now) == timedelta(days=7)


@pytest.mark.asyncio
async def test_new_router_unreachable_is_retried_after_30_minutes(db, wired):
    now = datetime.utcnow()
    new = await _router(db, "10.0.2.1", "Router-7001", created_at=now - timedelta(hours=2),
                        expiry_reaper_reason="unreachable",
                        expiry_reaper_checked_at=now - timedelta(minutes=40))
    old = await _router(db, "10.0.2.2", "Router-7002", created_at=now - timedelta(days=9),
                        expiry_reaper_reason="unreachable",
                        expiry_reaper_checked_at=now - timedelta(minutes=40))
    picked = [c.id for c in await enrol.load_candidates(now, 10)]
    assert new.id in picked and old.id not in picked


# --- setup trigger (/complete) ------------------------------------------------

def _sleeps():
    calls = []

    async def sleep(s):
        calls.append(s)
    return calls, sleep


@pytest.mark.asyncio
async def test_setup_trigger_does_nothing_when_switched_off(db, wired, monkeypatch):
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_AUTO_ENROL", False)
    r = await _router(db, "10.0.3.1", "Router-7101")
    wired["10.0.3.1"] = FakeRouterOS("Router-7101")
    calls, sleep = _sleeps()
    assert await enrol.enrol_after_provisioning(r.id, sleep=sleep) is None
    assert calls == [] and wired["10.0.3.1"].commands == []


@pytest.mark.asyncio
async def test_setup_trigger_installs_on_a_new_standard_router(db, wired):
    r = await _router(db, "10.0.3.2", "Router-7102", last_status=None)
    wired["10.0.3.2"] = FakeRouterOS("Router-7102")
    calls, sleep = _sleeps()
    o = await enrol.enrol_after_provisioning(r.id, sleep=sleep)
    assert o.installed and calls == [enrol.SETUP_FIRST_DELAY_SECONDS]
    assert (await _reload(db, r.id)).expiry_reaper_enabled


@pytest.mark.asyncio
async def test_setup_trigger_marks_a_new_hap_lite_server_side_once(db, wired):
    r = await _router(db, "10.0.3.3", "Router-7103")
    fake = wired["10.0.3.3"] = FakeRouterOS("Router-7103", board="hAP lite", model="RB941-2nD")
    calls, sleep = _sleeps()
    o = await enrol.enrol_after_provisioning(r.id, sleep=sleep)
    assert (o.mode, o.reason) == (MODE_SERVER, "small board hAP lite")
    assert calls == [enrol.SETUP_FIRST_DELAY_SECONDS]          # decided: no retries
    assert not fake.did("/system/script/add")


@pytest.mark.asyncio
async def test_setup_trigger_retries_until_the_tunnel_is_up(db, wired):
    r = await _router(db, "10.0.3.4", "Router-7104")
    fake = wired["10.0.3.4"] = FakeRouterOS("Router-7104", reachable=False)
    calls = []

    async def sleep(s):
        calls.append(s)
        if len(calls) == 3:          # tunnel comes up before the third attempt
            fake.reachable = True
    o = await enrol.enrol_after_provisioning(r.id, sleep=sleep)
    assert o.installed
    assert calls == [enrol.SETUP_FIRST_DELAY_SECONDS, *enrol.SETUP_RETRY_DELAYS_SECONDS[:2]]


@pytest.mark.asyncio
async def test_setup_trigger_gives_up_quietly_and_leaves_it_to_the_job(db, wired):
    r = await _router(db, "10.0.3.5", "Router-7105")
    wired["10.0.3.5"] = FakeRouterOS("Router-7105", reachable=False)
    calls, sleep = _sleeps()
    o = await enrol.enrol_after_provisioning(r.id, sleep=sleep)
    assert o.mode is None and o.reason == "unreachable"
    assert calls == [enrol.SETUP_FIRST_DELAY_SECONDS, *enrol.SETUP_RETRY_DELAYS_SECONDS]
    assert (await _reload(db, r.id)).expiry_reaper_reason == "unreachable"


@pytest.mark.asyncio
async def test_setup_trigger_and_periodic_job_never_share_a_router(db, wired, monkeypatch):
    r = await _router(db, "10.0.3.6", "Router-7106")
    wired["10.0.3.6"] = FakeRouterOS("Router-7106")
    monkeypatch.setattr(enrol, "_in_flight", {r.id})
    assert await enrol.expiry_reaper_enrol_background() == []
    calls, sleep = _sleeps()
    assert await enrol.enrol_after_provisioning(r.id, sleep=sleep) is None
    assert wired["10.0.3.6"].commands == []


@pytest.mark.asyncio
async def test_setup_trigger_never_raises(monkeypatch):
    monkeypatch.setattr(enrol.settings, "EXPIRY_REAPER_AUTO_ENROL", True)

    async def boom(*_a, **_k):
        raise RuntimeError("db down")
    monkeypatch.setattr(enrol, "load_candidates", boom)
    calls, sleep = _sleeps()
    assert await enrol.enrol_after_provisioning(1, sleep=sleep) is None


def test_complete_callback_schedules_enrolment():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "provisioning.py").read_text(encoding="utf-8")
    assert "schedule_enrol_after_provisioning(router_obj.id)" in src

"""A saved, dormant load-balancing WAN switches on by itself once its line works.

Router 542 (2026-11-18) was enabled with ether5 dormant (no cable yet); it only
joined when someone pressed "Finish setup". The job must wait for a stable
link before acting, use the dashboard's own enable path, persist in the same
step, never take fleet slots, and never retry a dead line in a loop.
"""

import asyncio
from contextlib import AsyncExitStack
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import CustomerEvent
from app.services import lb_auto_activate as auto
from app.services import mikrotik_background
from app.services.mikrotik_background import RouterLockManager
from tests.factories import make_reseller, make_router

WANS = ["ether1", "ether2"]


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    auto.reset_state()
    monkeypatch.setattr(mikrotik_background, "router_locks", RouterLockManager(max_concurrent=3))
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda *_: False)
    yield
    auto.reset_state()


def _port(running=True, link_downs=2, in_bridge=True, dhcp=None, routes=False):
    return {"running": running, "link_downs": link_downs, "in_bridge": in_bridge,
            "dhcp_status": dhcp, "has_routes": routes}


# --- stability rule (pure) ----------------------------------------------------------

def test_needs_consecutive_stable_checks():
    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS - 1):
        assert auto.update_stability(1, {"ether2": _port()}) == []
    assert auto.update_stability(1, {"ether2": _port()}) == ["ether2"]


def test_a_link_drop_resets_the_count():
    auto.update_stability(1, {"ether2": _port(link_downs=2)})
    auto.update_stability(1, {"ether2": _port(link_downs=2)})
    assert auto.update_stability(1, {"ether2": _port(link_downs=3)}) == []  # flapped
    assert auto.update_stability(1, {"ether2": _port(link_downs=3)}) == []
    assert auto.update_stability(1, {"ether2": _port(link_downs=3)}) == []
    assert auto.update_stability(1, {"ether2": _port(link_downs=3)}) == ["ether2"]


def test_no_link_never_ready():
    for _ in range(5):
        assert auto.update_stability(1, {"ether2": _port(running=False)}) == []


def test_unbound_dhcp_client_is_not_ready():
    for _ in range(5):
        assert auto.update_stability(
            1, {"ether2": _port(in_bridge=False, dhcp="searching...")}) == []


def test_live_port_is_not_dormant():
    ports = {"ether2": _port(routes=True)}
    assert auto.dormant_ports(ports) == []
    for _ in range(5):
        assert auto.update_stability(1, ports) == []


# --- the job ------------------------------------------------------------------------

async def _lb_router(db, dormant=("ether2",)):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    router.lb_enabled = True
    router.lb_config = {"wan_ports": WANS, "applied_at": "2026-11-18T12:00:00"}
    if dormant is not None:
        router.lb_config["dormant_ports"] = list(dormant)
    await db.commit()
    return reseller, router


def _fake_router(monkeypatch, ports, enable_result, calls):
    monkeypatch.setattr(auto, "_dormant_check_sync",
                        lambda info, wans: {"ports": {k: dict(v) for k, v in ports.items()}})

    def fake_enable(info, wans, customers):
        calls.append(wans)
        return enable_result

    import app.api.load_balancing_routes as lbr
    monkeypatch.setattr(lbr, "_lb_enable_sync", fake_enable)


async def test_stable_line_is_activated_persisted_and_logged(db, monkeypatch):
    reseller, router = await _lb_router(db)
    calls = []
    _fake_router(monkeypatch, {"ether2": _port()},
                 {"success": True, "converted_ports": ["ether2"], "dormant_ports": []}, calls)

    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS - 1):
        await auto.auto_activate_dormant_wans_background()
    assert calls == []
    await auto.auto_activate_dormant_wans_background()
    assert calls == [WANS]

    await db.refresh(router)
    assert router.lb_enabled is True
    assert router.lb_config["dormant_ports"] == []
    assert router.lb_config["wan_ports"] == WANS
    events = (await db.execute(select(CustomerEvent).where(
        CustomerEvent.router_id == router.id))).scalars().all()
    assert [e.event_type for e in events] == ["lb_wan_auto_activated"]
    assert events[0].user_id == reseller.id
    assert "ether2" in events[0].message


async def test_dead_line_is_left_staged_and_not_retried_in_a_loop(db, monkeypatch):
    _, router = await _lb_router(db)
    calls = []
    _fake_router(monkeypatch, {"ether2": _port()},
                 {"success": True, "converted_ports": [], "dormant_ports": ["ether2"],
                  "no_internet_ports": ["ether2"]}, calls)

    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS * 4):
        await auto.auto_activate_dormant_wans_background()
    assert calls == [WANS]  # one attempt; backoff holds the rest

    auto._last_attempt[router.id] = datetime.utcnow() - auto.LB_AUTO_ACTIVATE_RETRY_BACKOFF \
        - timedelta(seconds=1)
    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS):
        await auto.auto_activate_dormant_wans_background()
    assert calls == [WANS, WANS]
    events = (await db.execute(select(CustomerEvent).where(
        CustomerEvent.router_id == router.id))).scalars().all()
    assert {e.event_type for e in events} == {"lb_wan_auto_activation_staged"}


async def test_failed_activation_does_not_touch_db(db, monkeypatch):
    _, router = await _lb_router(db)
    calls = []
    _fake_router(monkeypatch, {"ether2": _port()},
                 {"error": "preflight_blocked", "preflight": {"blockers": ["x"]}}, calls)
    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS):
        await auto.auto_activate_dormant_wans_background()
    assert calls == [WANS]
    await db.refresh(router)
    assert router.lb_config["applied_at"] == "2026-11-18T12:00:00"
    assert router.lb_config["dormant_ports"] == ["ether2"]


async def test_router_with_every_line_live_is_skipped_without_io(db, monkeypatch):
    await _lb_router(db, dormant=())
    monkeypatch.setattr(auto, "_dormant_check_sync",
                        lambda *a: pytest.fail("router I/O for a router with no dormant WAN"))
    await auto.auto_activate_dormant_wans_background()


async def test_unknown_state_is_checked_then_cached_when_all_live(db, monkeypatch):
    _, router = await _lb_router(db, dormant=None)  # enabled before this job existed
    calls = []
    _fake_router(monkeypatch, {"ether2": _port(routes=True)}, {}, calls)
    await auto.auto_activate_dormant_wans_background()
    await db.refresh(router)
    assert router.lb_config["dormant_ports"] == []
    assert calls == []


async def test_check_and_activation_do_not_wait_on_fleet_slots(db, monkeypatch):
    _, router = await _lb_router(db)
    calls = []
    _fake_router(monkeypatch, {"ether2": _port()},
                 {"success": True, "converted_ports": ["ether2"], "dormant_ports": []}, calls)
    locks = mikrotik_background.router_locks
    async with AsyncExitStack() as stack:
        for n in range(3):  # every fleet slot held by jobs on other routers
            await stack.enter_async_context(locks.acquire(f"10.9.9.{n}:8728"))
        async with asyncio.timeout(5):
            for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS):
                await auto.auto_activate_dormant_wans_background()
    assert calls == [WANS]


async def test_activation_waits_for_a_dashboard_action_on_the_router(db, monkeypatch):
    _, router = await _lb_router(db)
    order = []

    def fake_enable(info, wans, customers):
        order.append("auto")
        return {"success": True, "converted_ports": ["ether2"], "dormant_ports": []}

    import app.api.load_balancing_routes as lbr
    monkeypatch.setattr(lbr, "_lb_enable_sync", fake_enable)
    monkeypatch.setattr(auto, "_dormant_check_sync", lambda *a: {"ports": {"ether2": _port()}})
    for _ in range(auto.LB_AUTO_ACTIVATE_STABLE_CHECKS - 1):
        await auto.auto_activate_dormant_wans_background()

    locks = mikrotik_background.router_locks
    key = f"{router.ip_address}:{router.port}"
    async with locks.acquire_interactive(key, holder="a load-balancing setup save"):
        job = asyncio.create_task(auto.auto_activate_dormant_wans_background())
        await asyncio.sleep(0.05)
        order.append("user")
    await job
    assert order == ["user", "auto"]


# --- the read-only router check -----------------------------------------------------

def _check(monkeypatch, api):
    from app.services import mikrotik_api
    api.connect = lambda: True
    api.disconnect = lambda: None
    monkeypatch.setattr(mikrotik_api, "MikroTikAPI", lambda *a, **k: api)
    return auto._dormant_check_sync({"ip": "x", "username": "u", "password": "p",
                                     "port": 8728}, WANS)


def test_check_sees_unconverted_port_as_dormant(monkeypatch):
    from tests.test_mikrotik_lb import FakeLBAPI
    api = FakeLBAPI(interfaces=[{"name": "ether1", "running": "true", "link-downs": "0"},
                                {"name": "ether2", "running": "true", "link-downs": "5"}],
                    bridge_ports=[{".id": "*B2", "interface": "ether2", "bridge": "bridge"}])
    st = _check(monkeypatch, api)["ports"]["ether2"]
    assert st == {"running": True, "link_downs": 5, "in_bridge": True,
                  "dhcp_status": None, "has_routes": False}
    assert api.commands == []  # read-only


def test_check_sees_converted_port_as_live(monkeypatch):
    from app.services import mikrotik_lb
    from tests.test_mikrotik_lb import FakeLBAPI
    api = FakeLBAPI(routes=[{"comment": mikrotik_lb._probe_comment("ether2"),
                             "gateway": "10.20.0.1%ether2"}],
                    dhcp_clients=[{"interface": "ether2", "status": "bound"}])
    st = _check(monkeypatch, api)["ports"]["ether2"]
    assert st["has_routes"] is True and st["in_bridge"] is False

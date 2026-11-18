"""Saving a load-balancing setup before the extra line works.

The dashboard promises: "You can save a spare port before its cable is
connected ... this port won't carry traffic until you finish setup". So a WAN
port with no cable, no link, a flapping link, no DHCP lease or no internet
behind its modem must never block the save, and customer traffic must never be
routed into it.
"""

import pytest

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_lb
from tests.factories import make_reseller, make_router
from tests.test_mikrotik_lb import FakeLBAPI, _commands, _no_settle  # noqa: F401
from tests.test_mikrotik_lb_ros6 import _managed_routes, _on_dhcp_add, _router537

WANS = ["ether1", "ether2"]
INFO = {"ip": "x", "username": "u", "password": "p", "port": 8728}


def _run_enable(monkeypatch, api, wans=WANS):
    api.connect = lambda: True
    api.disconnect = lambda: None
    monkeypatch.setattr(lbr, "_connect", lambda info, timeout=45: api)
    return lbr._lb_enable_sync(INFO, wans, [])


def _dead_line(api, probe):
    """The internet does not answer through the WAN whose probe is *probe*."""
    original = api.send_command

    def wrapped(command, arguments=None):
        args = dict(arguments or {})
        if command == "/ping" and args.get("address") == probe:
            api.commands.append((command, args))
            return {"success": True, "data": [{"host": probe, "received": "0"}]}
        return original(command, arguments)

    api.send_command = wrapped


def _table_routes(api, table):
    return [r for r in api.routes if r.get("routing-table") == table
            or r.get("routing-mark") == table]


# --- no cable ---------------------------------------------------------------------

def test_no_cable_preflight_has_no_blocker(monkeypatch):
    api = FakeLBAPI(interfaces=[{"name": "ether1", "running": "true"},
                                {"name": "ether2", "running": "false"}])
    report = mikrotik_lb.lb_preflight(api, WANS)
    assert report["blockers"] == []
    assert report["per_port"]["ether2"]["link"] == "false"


def test_no_cable_save_succeeds_staged_and_traffic_stays_on_wan1(monkeypatch):
    api = FakeLBAPI(interfaces=[{"name": "ether1", "running": "true"},
                                {"name": "ether2", "running": "false"}])
    result = _run_enable(monkeypatch, api)

    assert result["success"] is True
    assert result["dormant_ports"] == ["ether2"]
    assert result["converted_ports"] == []
    # the port was not touched
    assert _commands(api, "/interface/bridge/port/remove") == []
    assert _commands(api, "/ip/dhcp-client/add") == []
    # WAN2's table has no route of its own; its only active candidate is WAN1's probe
    gateways = {r["gateway"] for r in _table_routes(api, "to_wan2")}
    assert gateways <= set(mikrotik_lb.PROBE_IPS[:2])
    assert not any(r.get("dst-address") == mikrotik_lb.PROBE_IPS[1] + "/32"
                   for r in api.routes)  # no probe route through ether2
    assert result["verify"]["pcc_order"]["ok"] is True


# --- link but no DHCP -------------------------------------------------------------

def test_link_without_dhcp_lease_is_saved_as_dormant(monkeypatch):
    api = FakeLBAPI()  # ether2 has link, but nothing ever hands it a lease
    result = _run_enable(monkeypatch, api)

    assert result["success"] is True
    assert result["dormant_ports"] == ["ether2"]
    assert "did not bind" in result["convert"]["ether2"]["aborted"]
    assert not any(r.get("dst-address") == mikrotik_lb.PROBE_IPS[1] + "/32"
                   for r in api.routes)


# --- link + lease but no internet behind the modem --------------------------------

def test_v7_line_without_internet_is_saved_staged_not_counted_working(monkeypatch):
    api = FakeLBAPI()
    _on_dhcp_add(api, {"status": "bound", "gateway": "10.20.0.1", "address": "10.20.0.5/24"})
    _dead_line(api, mikrotik_lb.PROBE_IPS[1])
    result = _run_enable(monkeypatch, api)

    assert result["success"] is True
    assert result["no_internet_ports"] == ["ether2"]
    assert result["dormant_ports"] == ["ether2"]
    assert result["converted_ports"] == []
    # v7: every to_wan2 route is check-gateway=ping on a probe, so the dead
    # line's routes go inactive and its table falls back to WAN1.
    assert all(r.get("check-gateway") == "ping" for r in _table_routes(api, "to_wan2"))


def test_v6_direct_mode_dead_line_routes_are_parked(monkeypatch):
    """Two modems on one subnet: v6 direct routes ping only the modem, which
    answers even when the line behind it is dead. Its routes must be removed."""
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    _dead_line(api, mikrotik_lb.PROBE_IPS[1])
    result = _run_enable(monkeypatch, api)

    assert result["no_internet_ports"] == ["ether2"]
    assert result["dormant_ports"] == ["ether2"]
    assert result["parked"]["parked"] == ["ether2"]
    ping = [a for c, a in api.commands if c == "/ping"
            and a.get("address") == mikrotik_lb.PROBE_IPS[1]][0]
    assert ping["routing-table"] == "to_wan2"
    for comment, route in _managed_routes(api).items():
        assert "%ether2" not in (route.get("gateway") or ""), comment


def test_v6_direct_mode_working_line_keeps_its_routes(monkeypatch):
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    result = _run_enable(monkeypatch, api)

    assert result["no_internet_ports"] == []
    assert result["converted_ports"] == ["ether2"]
    assert any("%ether2" in (r.get("gateway") or "") for r in _managed_routes(api).values())


# --- link flapping ----------------------------------------------------------------

def _sampled(api, samples):
    """/interface/print returns successive *samples* (the last one repeats)."""
    original = api.send_command_optimized
    reads = []

    def wrapped(command, proplist=None, query=None):
        if command == "/interface/print":
            reads.append(proplist)
            rows = samples[min(len(reads) - 1, len(samples) - 1)]
            return {"success": True, "data": [dict(r) for r in rows]}
        return original(command, proplist=proplist, query=query)

    api.send_command_optimized = wrapped
    return reads


def test_preflight_reports_link_flapping_without_blocking():
    api = FakeLBAPI()
    reads = _sampled(api, [
        [{"name": "ether1", "running": "true", "link-downs": "0", "rx-byte": "1000"},
         {"name": "ether2", "running": "true", "link-downs": "4", "rx-byte": "500"}],
        [{"name": "ether1", "running": "true", "link-downs": "0", "rx-byte": "9000"},
         {"name": "ether2", "running": "true", "link-downs": "7", "rx-byte": "600"}],
    ])
    report = mikrotik_lb.lb_preflight(api, WANS)

    assert len(reads) == 2 and "link-downs" in reads[0]
    st = report["per_port"]["ether2"]["link_stability"]
    assert st["flapping"] is True
    assert st["link_downs_during_check"] == 3
    assert st["link_downs"] == 7
    assert report["blockers"] == []
    assert any("ether2's link is unstable" in w and "went down 3 time" in w
               for w in report["warnings"])
    assert not any("ether1" in w and "unstable" in w for w in report["warnings"])


def test_preflight_reports_link_with_no_data_received():
    api = FakeLBAPI()
    _sampled(api, [[{"name": "ether1", "running": "true", "link-downs": "0", "rx-byte": "10"},
                    {"name": "ether2", "running": "true", "link-downs": "0", "rx-byte": "0"}]])
    report = mikrotik_lb.lb_preflight(api, WANS)
    assert report["blockers"] == []
    assert any("ether2 shows a link but has never received any data" in w
               for w in report["warnings"])


def test_preflight_quiet_for_a_stable_spare_port():
    api = FakeLBAPI()
    _sampled(api, [[{"name": "ether1", "running": "true", "link-downs": "1", "rx-byte": "10"},
                    {"name": "ether2", "running": "true", "link-downs": "1", "rx-byte": "20"}]])
    report = mikrotik_lb.lb_preflight(api, WANS)
    assert report["per_port"]["ether2"]["link_stability"]["flapping"] is False
    assert not any("ether2" in w for w in report["warnings"])


# --- the endpoint: staged save persists and says so --------------------------------

async def test_endpoint_saves_setup_with_a_dead_spare_port(db, monkeypatch):
    async def _no_availability(*_a, **_k):
        return None

    async def direct_runner(router_obj, sync_func, *args, **kwargs):
        return sync_func(*args)

    monkeypatch.setattr(lbr, "record_router_availability", _no_availability)
    monkeypatch.setattr(lbr, "_run_locked_router_thread", direct_runner)
    api = FakeLBAPI()
    api.connect = lambda: True
    api.disconnect = lambda: None
    _on_dhcp_add(api, {"status": "bound", "gateway": "10.20.0.1", "address": "10.20.0.5/24"})
    _dead_line(api, mikrotik_lb.PROBE_IPS[1])
    monkeypatch.setattr(lbr, "_connect", lambda info, timeout=45: api)

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    resp = await lbr.enable_load_balancing(
        router.id, lbr.LBEnableRequest(wan_ports=WANS, confirm=True),
        db, {"user_id": reseller.id, "role": reseller.role.value},
    )

    assert resp["success"] is True
    assert resp["dormant_ports"] == ["ether2"]
    assert resp["no_internet_ports"] == ["ether2"]
    assert any("internet does not answer" in w for w in resp["warnings"])
    assert "not carrying traffic yet" in resp["message"]
    await db.refresh(router)
    assert router.lb_enabled is True
    assert router.lb_config["wan_ports"] == WANS

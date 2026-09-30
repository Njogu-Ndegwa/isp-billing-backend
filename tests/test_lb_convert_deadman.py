"""Router-side dead-man switch around WAN port conversion.

On router 537 (2026-09-30) converting ether2 cut the management path mid-change
and left the port half-converted. The dashboard's enable now arms a one-shot
scheduler on the router that reverts the conversion unless the app comes back,
confirms the router is online, and cancels it.
"""

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_lb
from tests.test_mikrotik_lb import FakeLBAPI, _commands, _no_settle  # noqa: F401
from tests.test_mikrotik_lb_ros6 import _on_dhcp_add, _router537

WANS = ["ether1", "ether2"]


def _run_enable(monkeypatch, api):
    api.connect = lambda: True
    api.disconnect = lambda: None
    monkeypatch.setattr(lbr, "_connect", lambda info, timeout=45: api)
    return lbr._lb_enable_sync({"ip": "x", "username": "u", "password": "p", "port": 8728},
                               WANS, [])


def _bound_537():
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    return api


# --- script / scheduling ------------------------------------------------------------

def test_arm_schedules_revert_in_router_time_v6_date_format():
    api = _router537(clock=[{"date": "sep/30/2026", "time": "23:58:30"}])
    report = mikrotik_lb.lb_arm_convert_deadman(api, ["ether2"], WANS)
    assert report["success"] is True, report["steps"]
    sched = _commands(api, "/system/scheduler/add")[0]
    # crosses midnight correctly, in the router's own date format
    assert (sched["start-date"], sched["start-time"]) == ("oct/01/2026", "00:03:30")
    assert sched["name"] == mikrotik_lb.DEADMAN_NAME
    script = sched["on-event"]
    assert '/ip dhcp-client remove [find interface="ether2" comment="ISP_BILLING_WAN2"]' in script
    assert '/interface list member remove [find list="WAN" interface="ether2"]' in script
    assert '/interface bridge port add bridge="bridge" interface="ether2"' in script
    assert script.endswith(f'/system scheduler remove [find name="{mikrotik_lb.DEADMAN_NAME}"]')


def test_arm_uses_iso_dates_on_newer_routeros7():
    api = FakeLBAPI(clock=[{"date": "2026-09-30", "time": "10:00:00"}])
    mikrotik_lb.lb_arm_convert_deadman(api, ["ether2"], WANS)
    sched = _commands(api, "/system/scheduler/add")[0]
    assert (sched["start-date"], sched["start-time"]) == ("2026-09-30", "10:05:00")


def test_arm_does_not_revert_a_list_membership_that_already_existed():
    api = _router537(list_members=[
        {".id": "*M1", "list": "WAN", "interface": "ether1"},
        {".id": "*M2", "list": "WAN", "interface": "ether2"},
    ])
    mikrotik_lb.lb_arm_convert_deadman(api, ["ether2"], WANS)
    assert "interface list member remove" not in _commands(api, "/system/scheduler/add")[0]["on-event"]


def test_arm_refuses_without_a_readable_clock():
    api = _router537(clock=[])
    report = mikrotik_lb.lb_arm_convert_deadman(api, ["ether2"], WANS)
    assert "clock" in report["aborted"]
    assert _commands(api, "/system/scheduler/add") == []


def test_arm_replaces_a_stale_scheduler():
    api = _router537()
    api.schedulers.append({".id": "*S1", "name": mikrotik_lb.DEADMAN_NAME})
    mikrotik_lb.lb_arm_convert_deadman(api, ["ether2"], WANS)
    assert [s[".id"] for s in api.schedulers if s["name"] == mikrotik_lb.DEADMAN_NAME] != ["*S1"]
    assert len([s for s in api.schedulers if s["name"] == mikrotik_lb.DEADMAN_NAME]) == 1


# --- dashboard enable flow ----------------------------------------------------------

def test_enable_arms_before_converting_and_disarms_when_router_is_online(monkeypatch):
    api = _bound_537()
    result = _run_enable(monkeypatch, api)

    assert result["converted_ports"] == ["ether2"]
    order = [c for c, _ in api.commands
             if c in ("/system/scheduler/add", "/interface/bridge/port/remove",
                      "/system/scheduler/remove")]
    assert order == ["/system/scheduler/add", "/interface/bridge/port/remove",
                     "/system/scheduler/remove"]
    assert result["deadman_disarmed"] is True
    assert api.schedulers == []


def test_enable_leaves_revert_armed_when_router_is_offline_after_convert(monkeypatch):
    api = _bound_537()
    api.internet = False
    result = _run_enable(monkeypatch, api)

    assert result["deadman_left_armed"] == ["ether2"]
    assert [s["name"] for s in api.schedulers] == [mikrotik_lb.DEADMAN_NAME]


def test_enable_never_converts_without_the_safety_net(monkeypatch):
    api = _bound_537()
    api.clock = []
    result = _run_enable(monkeypatch, api)

    assert result["deadman_not_armed"] == ["ether2"]
    assert result["converted_ports"] == []
    assert result["dormant_ports"] == ["ether2"]
    assert _commands(api, "/interface/bridge/port/remove") == []


def test_enable_without_linked_secondary_ports_sets_no_scheduler(monkeypatch):
    api = _bound_537()
    api.interfaces = [{"name": "ether1", "running": "true"},
                      {"name": "ether2", "running": "false"}]
    result = _run_enable(monkeypatch, api)

    assert result["dormant_ports"] == ["ether2"]
    assert "deadman" not in result
    assert _commands(api, "/system/scheduler/add") == []

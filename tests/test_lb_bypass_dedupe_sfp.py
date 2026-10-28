"""Dashboard LB enable on a router whose tunnels go to our backends, over SFP+.

Router 487 (RB4011, RouterOS 7.21.4, 2026-10-28) could not enable load
balancing from the dashboard for two reasons:

1. Its WireGuard peers (wg-aws, wg-hz) point at 54.91.202.229 and 91.98.238.12,
   which are also in BACKEND_IPS. lb_apply added each to LB_BYPASS_DST twice,
   RouterOS refused the second add ("already have such entry"), apply was
   marked failed and the enable aborted.
2. WAN2 was sfp-sfpplus1, which the port-name check rejected outright.
"""

import pytest

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_lb
from tests.test_mikrotik_lb import FakeLBAPI, _bind_on_add, _commands, _no_settle  # noqa: F401

BACKEND_PEERS = [
    {"interface": "wg-aws", "endpoint-address": "54.91.202.229"},
    {"interface": "wg-hz", "endpoint-address": "91.98.238.12"},
]


def _bypass_adds(api):
    return [a["address"] for a in _commands(api, "/ip/firewall/address-list/add")
            if a.get("list") == mikrotik_lb.LB_BYPASS_LIST]


def _bypass_entries(api):
    return [a["address"] for a in api.address_lists
            if a.get("list") == mikrotik_lb.LB_BYPASS_LIST]


# --- bug 1: duplicate bypass addresses ----------------------------------------------

def test_apply_adds_one_bypass_entry_per_ip_when_tunnels_point_at_backends():
    api = FakeLBAPI(wg_peers=list(BACKEND_PEERS))
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True, [s for s in report["steps"] if not s["ok"]]
    adds = _bypass_adds(api)
    assert len(adds) == len(set(adds)), adds
    expected = mikrotik_lb.LB_BYPASS_BASE + mikrotik_lb.BACKEND_IPS
    assert sorted(_bypass_entries(api)) == sorted(expected)
    for ip in ("54.91.202.229", "91.98.238.12"):
        assert _bypass_entries(api).count(ip) == 1


def test_apply_still_adds_a_non_backend_endpoint_once():
    api = FakeLBAPI(wg_peers=BACKEND_PEERS + [
        {"interface": "wg-x", "endpoint-address": "203.0.113.9"},
        {"interface": "wg-y", "endpoint-address": "203.0.113.9"},
    ])
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True
    assert _bypass_entries(api).count("203.0.113.9") == 1


def test_already_have_such_entry_counts_as_success():
    # The entry is on the router but the address-list read missed it (slow read,
    # dynamic entry...): RouterOS refuses the add, which is the state we want.
    api = FakeLBAPI()
    original = api.send_command

    def refuse_one(command, arguments=None):
        if (command == "/ip/firewall/address-list/add"
                and (arguments or {}).get("address") == "10.0.0.0/8"):
            api.commands.append((command, dict(arguments or {})))
            return {"error": "failure: already have such entry"}
        return original(command, arguments)

    api.send_command = refuse_one
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True
    step = next(s for s in report["steps"]
                if s["step"] == "address_list.add.LB_BYPASS_DST.10.0.0.0/8")
    assert step["ok"] is True
    assert step["detail"]["already_present"] is True


def test_other_address_list_errors_still_fail_apply():
    api = FakeLBAPI()
    original = api.send_command

    def reject(command, arguments=None):
        if (command == "/ip/firewall/address-list/add"
                and (arguments or {}).get("address") == "10.0.0.0/8"):
            return {"error": "failure: invalid value for argument address"}
        return original(command, arguments)

    api.send_command = reject
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is False


def test_reapply_with_backend_endpoints_adds_nothing():
    api = FakeLBAPI(wg_peers=list(BACKEND_PEERS))
    assert mikrotik_lb.lb_apply(api, ["ether1", "ether2"])["success"] is True
    before = len(api.commands)

    again = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert again["success"] is True
    assert [c for c, _ in api.commands[before:]
            if c == "/ip/firewall/address-list/add"] == []


# --- bug 2: SFP+ port names -------------------------------------------------------

@pytest.mark.parametrize("name", [
    "ether1", "ether10", "sfp1", "sfpplus1", "sfp-sfpplus1", "sfp-sfpplus12",
    "sfp28-1", "qsfpplus1-1", "qsfp28-2-4", "combo1",
])
def test_wan_port_name_accepts_physical_ports(name):
    assert lbr._WAN_PORT_RE.match(name)


@pytest.mark.parametrize("name", [
    "bridge", "bridge1", "vlan10", "ether1.10", "ether1-vlan10", "wlan1", "wifi1",
    "wg-aws", "wg-hz", "wireguard1", "pppoe-out1", "l2tp-out1", "sstp-out1",
    "sfp-sfpplus", "sfp-sfpplus1;", 'sfp-sfpplus1"', "SFP-SFPPLUS1", "", "ether",
    "lte1", "bonding1",
])
def test_wan_port_name_rejects_non_physical_or_unsafe(name):
    assert not lbr._WAN_PORT_RE.match(name)


# --- end to end: the dashboard enable on a router-487-shaped fake -----------------

def _rb4011():
    api = FakeLBAPI(
        ros_version="7.21.4",
        dhcp_clients=[{"interface": "ether1", "status": "bound",
                       "gateway": "192.168.1.1", "address": "192.168.1.50/24"}],
        ip_addresses=[{"address": "192.168.88.1/24", "interface": "bridge"},
                      {"address": "192.168.1.50/24", "interface": "ether1"}],
        interfaces=[{"name": "ether1", "running": "true"},
                    {"name": "sfp-sfpplus1", "running": "true"}],
        list_members=[{".id": "*M1", "list": "WAN", "interface": "ether1"}],
        wg_peers=list(BACKEND_PEERS),
        # the second modem answers on its own address, not on WAN1's gateway
        arp_replies={("sfp-sfpplus1", "192.168.2.1")},
    )
    _bind_on_add(api, "192.168.2.20/24", "192.168.2.1")
    return api


def test_enable_on_sfp_plus_with_backend_tunnels_completes(monkeypatch):
    wans = ["ether1", "sfp-sfpplus1"]
    router_obj = type("R", (), {"pppoe_ports": [], "plain_ports": [], "dual_ports": []})()
    lbr._validate_wan_ports(wans, router_obj)  # no 422

    api = _rb4011()
    api.connect = lambda: True
    api.disconnect = lambda: None
    monkeypatch.setattr(lbr, "_connect", lambda info, timeout=45: api)
    result = lbr._lb_enable_sync(
        {"ip": "x", "username": "u", "password": "p", "port": 8728}, wans, [])

    assert "error" not in result, result.get("error")
    assert result["apply"]["success"] is True
    assert result["success"] is True
    assert result["converted_ports"] == ["sfp-sfpplus1"]
    assert "rollback" not in result
    entries = _bypass_entries(api)
    assert len(entries) == len(set(entries))
    assert entries.count("54.91.202.229") == 1
    assert entries.count("91.98.238.12") == 1
    comments = [a["comment"] for a in _commands(api, "/ip/route/add")]
    assert "ISP_BILLING_VPN_PIN_WGAWS" in comments
    assert "ISP_BILLING_VPN_PIN_WGHZ" in comments
    assert "ISP_BILLING_DUAL_WAN_SFP-SFPPLUS1_PROBE" in comments

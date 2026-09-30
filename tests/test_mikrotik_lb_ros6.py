"""RouterOS 6 support + "second modem already plugged into a LAN port".

Reproduces router 537 "MIKROTIK HOME" (RB951Ui-2HnD, RouterOS 6.49.21) as seen on
2026-09-30: ether1 on modem A (192.168.100.1), ether2 still a hotspot-bridge port
with modem B plugged in — which ALSO answers on 192.168.100.1.
"""

from app.services import mikrotik_lb
from tests.test_mikrotik_lb import FakeLBAPI, _commands, _no_settle  # noqa: F401

MODEM_MAC = "EC:1A:02:A9:FC:8E"


def _router537(**overrides):
    kwargs = dict(
        ros_version="6.49.21 (long-term)",
        dhcp_clients=[{"interface": "ether1", "status": "bound",
                       "gateway": "192.168.100.1", "address": "192.168.100.9/24"}],
        bridge_ports=[{".id": "*B2", "interface": "ether2", "bridge": "bridge"}],
        bridge_hosts=[{"mac-address": MODEM_MAC, "on-interface": "ether2",
                       "local": "false"}],
        ip_addresses=[{"address": "192.168.88.1/24", "interface": "bridge"},
                      {"address": "192.168.100.9/24", "interface": "ether1"}],
        hotspot_hosts=[{"mac-address": MODEM_MAC, "address": "192.168.100.1"}],
        list_members=[{".id": "*M1", "list": "WAN", "interface": "ether1"}],
    )
    kwargs.update(overrides)
    return FakeLBAPI(**kwargs)


def _on_dhcp_add(api, lease):
    original = api.send_command

    def wrapped(command, arguments=None):
        result = original(command, arguments)
        if command == "/ip/dhcp-client/add":
            api.dhcp_clients.append({
                ".id": "*D9", "interface": (arguments or {}).get("interface"),
                "comment": (arguments or {}).get("comment"), **lease,
            })
        return result

    api.send_command = wrapped


# --- version gate -------------------------------------------------------------

def test_preflight_accepts_routeros6():
    api = FakeLBAPI(ros_version="6.49.21 (long-term)")
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert report["blockers"] == []
    assert report["ros_major"] == 6


def test_preflight_unreadable_version_is_not_reported_as_wrong_version():
    api = FakeLBAPI()
    api.system_resources = []
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("Could not read the RouterOS version" in b for b in report["blockers"])
    assert not any("not supported" in b for b in report["blockers"])


def test_preflight_blocks_unsupported_major():
    api = FakeLBAPI(ros_version="5.26")
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("not supported" in b for b in report["blockers"])


# --- apply on v6 vs v7 --------------------------------------------------------------

def test_apply_ros6_uses_routing_mark_and_creates_no_tables():
    api = FakeLBAPI(ros_version="6.49.21 (long-term)")
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True, report["steps"]
    assert report["ros_major"] == 6
    assert not any(cmd.startswith("/routing/table") for cmd, _ in api.commands)
    table_routes = [a for a in _commands(api, "/ip/route/add")
                    if a["comment"].startswith("ISP_BILLING_PCC_WAN")]
    assert len(table_routes) == 4  # own + fallback per table
    for r in table_routes:
        assert "routing-table" not in r
        assert r["routing-mark"] in ("to_wan1", "to_wan2")
        assert r["target-scope"] == "11"
    mangle = _commands(api, "/ip/firewall/mangle/add")
    assert [a["comment"] for a in mangle][:2] == [
        "ISP_BILLING_PCC_UNAUTH_GUARD_V2", "ISP_BILLING_PCC_BYPASS"]
    assert [a["new-routing-mark"] for a in mangle if a["action"] == "mark-routing"] \
        == ["to_wan1", "to_wan2"]


def test_apply_v7_still_uses_routing_tables():
    api = FakeLBAPI()
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert len(_commands(api, "/routing/table/add")) == 2
    table_routes = [a for a in _commands(api, "/ip/route/add")
                    if a["comment"].startswith("ISP_BILLING_PCC_WAN")]
    assert table_routes
    assert all("routing-mark" not in r and r["routing-table"] for r in table_routes)


def test_apply_never_adds_mark_rules_when_guard_add_fails():
    api = FakeLBAPI(fail_commands={"/ip/firewall/mangle/add"})
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert report["success"] is False
    assert "guard" in report["aborted"]
    adds = _commands(api, "/ip/firewall/mangle/add")
    assert [a["comment"] for a in adds] == ["ISP_BILLING_PCC_UNAUTH_GUARD_V2"]


def test_rollback_on_ros6_does_not_fail_on_missing_routing_tables():
    api = FakeLBAPI(ros_version="6.49.21 (long-term)")
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    report = mikrotik_lb.lb_rollback(api)
    assert report["success"] is True, report["steps"]
    assert not [m for m in api.mangle_rules
                if (m.get("comment") or "").startswith("ISP_BILLING")]
    assert not [r for r in api.routes
                if (r.get("comment") or "").startswith("ISP_BILLING")]


# --- modem already on the would-be WAN port ---------------------------------------

def test_preflight_treats_foreign_ip_modem_on_lan_port_as_upstream():
    report = mikrotik_lb.lb_preflight(_router537(), ["ether1", "ether2"])
    assert report["blockers"] == []
    assert report["per_port"]["ether2"]["upstream_devices"] == [
        {"mac": MODEM_MAC, "addresses": ["192.168.100.1"]}]
    assert any("modem" in w for w in report["warnings"])


def test_preflight_still_blocks_when_a_lan_client_shares_the_port():
    api = _router537(
        bridge_hosts=[
            {"mac-address": MODEM_MAC, "on-interface": "ether2", "local": "false"},
            {"mac-address": "AA:BB:CC:00:00:01", "on-interface": "ether2",
             "local": "false"},
        ],
        hotspot_hosts=[
            {"mac-address": MODEM_MAC, "address": "192.168.100.1"},
            {"mac-address": "AA:BB:CC:00:00:01", "address": "192.168.88.40"},
        ],
    )
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("serves customers" in b for b in report["blockers"])


def test_preflight_blocks_silent_device_with_no_known_address():
    report = mikrotik_lb.lb_preflight(_router537(hotspot_hosts=[]), ["ether1", "ether2"])
    assert any("serves customers" in b for b in report["blockers"])


def test_convert_modem_port_and_warn_on_shared_subnet():
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.14/24"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")

    assert report["success"] is True, report["steps"]
    assert report["upstream_devices"][0]["mac"] == MODEM_MAC
    assert _commands(api, "/interface/bridge/port/remove") == [{".id": "*B2"}]
    probe = next(a for a in _commands(api, "/ip/route/add")
                 if a["comment"] == "ISP_BILLING_DUAL_WAN_ETHER2_PROBE")
    # both modems are 192.168.100.1 — only the interface pin tells them apart
    assert probe["gateway"] == "192.168.100.1%ether2"
    assert any("share subnet" in w for w in report["warnings"])
    assert _commands(api, "/interface/list/member/add") == [
        {"list": "WAN", "interface": "ether2"}]


def test_convert_warns_on_identical_wan_addresses():
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.9/24"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")
    assert any("same address" in w for w in report["warnings"])


def test_convert_reverts_modem_port_when_dhcp_never_binds(monkeypatch):
    monkeypatch.setattr(mikrotik_lb, "LB_CONVERT_DHCP_BIND_ATTEMPTS", 2)
    api = _router537()
    _on_dhcp_add(api, {"status": "searching"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")

    assert "did not bind" in report["aborted"]
    assert report["reverted"] is True
    assert _commands(api, "/ip/dhcp-client/remove") == [{".id": "*D9"}]
    assert _commands(api, "/interface/bridge/port/add") == [
        {"bridge": "bridge", "interface": "ether2"}]
    assert any(p["interface"] == "ether2" for p in api.bridge_ports)
    assert not any(d["interface"] == "ether2" for d in api.dhcp_clients)

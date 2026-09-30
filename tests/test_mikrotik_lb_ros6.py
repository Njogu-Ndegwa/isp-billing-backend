"""RouterOS 6 support + "second modem already plugged into a LAN port".

Reproduces router 537 "MIKROTIK HOME" (RB951Ui-2HnD, RouterOS 6.49.21) as seen on
2026-09-30: ether1 on modem A (192.168.100.1), ether2 still a hotspot-bridge port
with modem B plugged in — which ALSO answers on 192.168.100.1.

Facts measured on that router and encoded in the fake / assertions:
  * v6 cannot resolve a recursive route through a gw%iface probe route;
  * v6 drops every .proplist property from the first unknown (v7-only) name on.
"""

from app.services import mikrotik_lb
from tests.test_mikrotik_lb import FakeLBAPI, _commands, _no_settle  # noqa: F401

MODEM_MAC = "EC:1A:02:A9:FC:8E"
V6 = "6.49.21 (long-term)"


def _router537(**overrides):
    kwargs = dict(
        ros_version=V6,
        dhcp_clients=[{"interface": "ether1", "status": "bound",
                       "gateway": "192.168.100.1", "address": "192.168.100.9/24"}],
        bridge_ports=[{".id": "*B2", "interface": "ether2", "bridge": "bridge"}],
        bridge_hosts=[{"mac-address": MODEM_MAC, "on-interface": "ether2",
                       "local": "false"}],
        ip_addresses=[{"address": "192.168.88.1/24", "interface": "bridge"},
                      {"address": "192.168.100.9/24", "interface": "ether1"}],
        # exactly as read live: the hotspot gives the foreign-IP modem a 1:1-NAT
        # alias inside the LAN, and ARP on the bridge carries that alias
        hotspot_hosts=[{"mac-address": MODEM_MAC, "address": "192.168.100.1",
                        "to-address": "192.168.88.151"}],
        arp=[{"mac-address": MODEM_MAC, "address": "192.168.88.151",
              "interface": "bridge"}],
        list_members=[{".id": "*M1", "list": "WAN", "interface": "ether1"}],
        sstp_clients=[{"name": "sstp-hetzner", "connect-to": "91.98.238.12",
                       "disabled": "false"}],
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


def _managed_routes(api):
    return {r["comment"]: r for r in api.routes
            if (r.get("comment") or "").startswith("ISP_BILLING")}


# --- version gate -------------------------------------------------------------

def test_preflight_accepts_routeros6():
    report = mikrotik_lb.lb_preflight(FakeLBAPI(ros_version=V6), ["ether1", "ether2"])
    assert report["blockers"] == []
    assert report["ros_major"] == 6


def test_preflight_unreadable_version_is_not_reported_as_wrong_version():
    api = FakeLBAPI()
    api.system_resources = []
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("Could not read the RouterOS version" in b for b in report["blockers"])
    assert not any("not supported" in b for b in report["blockers"])


def test_preflight_blocks_unsupported_major():
    report = mikrotik_lb.lb_preflight(FakeLBAPI(ros_version="5.26"), ["ether1", "ether2"])
    assert any("not supported" in b for b in report["blockers"])


# --- apply on v6 vs v7 --------------------------------------------------------------

def test_apply_ros6_plain_probe_recursive_routes_with_routing_mark():
    api = FakeLBAPI(ros_version=V6)
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True, report["steps"]
    assert report["ros_major"] == 6
    assert report["route_mode"] == "recursive"
    assert not any(cmd.startswith("/routing/table") for cmd, _ in api.commands)
    routes = _managed_routes(api)
    # v6 cannot recurse through gw%iface: the probe gateway must be plain
    probe = routes["ISP_BILLING_DUAL_WAN_ETHER1_PROBE"]
    assert probe["gateway"] == "41.90.1.1"
    assert probe["scope"] == "10"
    assert routes["ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"]["gateway"] == "8.8.8.8"
    tables = {c: r for c, r in routes.items() if c.startswith("ISP_BILLING_PCC_WAN")}
    assert sorted(tables) == ["ISP_BILLING_PCC_WAN1", "ISP_BILLING_PCC_WAN1_FALLBACK",
                              "ISP_BILLING_PCC_WAN2", "ISP_BILLING_PCC_WAN2_FALLBACK"]
    for r in tables.values():
        assert "routing-table" not in r
        assert r["routing-mark"] in ("to_wan1", "to_wan2")
        assert r["check-gateway"] == "ping"
    assert tables["ISP_BILLING_PCC_WAN2"]["gateway"] == "1.1.1.1"
    assert tables["ISP_BILLING_PCC_WAN2_FALLBACK"]["gateway"] == "8.8.8.8"
    mangle = _commands(api, "/ip/firewall/mangle/add")
    assert [a["comment"] for a in mangle][:2] == [
        "ISP_BILLING_PCC_UNAUTH_GUARD_V2", "ISP_BILLING_PCC_BYPASS"]
    assert [a["new-routing-mark"] for a in mangle if a["action"] == "mark-routing"] \
        == ["to_wan1", "to_wan2"]


def test_apply_ros6_repairs_routes_left_by_the_v7_shape():
    """Router 537 got v7-shaped routes (gw%iface probe) from the first run."""
    api = FakeLBAPI(ros_version=V6, routes=[
        {".id": "*R1", "dst-address": "8.8.8.8/32", "gateway": "41.90.1.1%ether1",
         "scope": "10", "comment": "ISP_BILLING_DUAL_WAN_ETHER1_PROBE"},
        {".id": "*R2", "dst-address": "0.0.0.0/0", "gateway": "8.8.8.8", "distance": "1",
         "check-gateway": "ping", "target-scope": "11",
         "comment": "ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"},
    ])
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    routes = _managed_routes(api)
    assert routes["ISP_BILLING_DUAL_WAN_ETHER1_PROBE"]["gateway"] == "41.90.1.1"
    assert routes["ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"]["target-scope"] == "10"
    assert {"*R1", "*R2"}.isdisjoint(r[".id"] for r in api.routes)


def test_apply_ros6_is_idempotent():
    api = FakeLBAPI(ros_version=V6)
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    before = len(api.commands)
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    new_writes = [c for c, _ in api.commands[before:]
                  if not c.endswith("/print") and c != "/ip/firewall/filter/set"]
    assert new_writes == []


def test_apply_v7_unchanged_uses_routing_tables_and_iface_probes():
    api = FakeLBAPI()
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert "route_mode" not in report
    assert len(_commands(api, "/routing/table/add")) == 2
    routes = _managed_routes(api)
    assert routes["ISP_BILLING_DUAL_WAN_ETHER1_PROBE"]["gateway"] == "41.90.1.1%ether1"
    tables = [r for c, r in routes.items() if c.startswith("ISP_BILLING_PCC_WAN")]
    assert tables and all("routing-mark" not in r and r["target-scope"] == "11"
                          for r in tables)


def test_apply_never_adds_mark_rules_when_guard_add_fails():
    api = FakeLBAPI(fail_commands={"/ip/firewall/mangle/add"})
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert report["success"] is False
    assert "guard" in report["aborted"]
    adds = _commands(api, "/ip/firewall/mangle/add")
    assert [a["comment"] for a in adds] == ["ISP_BILLING_PCC_UNAUTH_GUARD_V2"]


def test_apply_ros6_route_readback_is_not_truncated():
    api = FakeLBAPI(ros_version=V6)
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert report["routes_after"], "v6 must not be asked for v7-only route props"
    assert all("comment" in r for r in report["routes_after"])


def test_rollback_on_ros6_removes_everything():
    api = FakeLBAPI(ros_version=V6)
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    report = mikrotik_lb.lb_rollback(api)
    assert report["success"] is True, report["steps"]
    assert not [m for m in api.mangle_rules
                if (m.get("comment") or "").startswith("ISP_BILLING")]
    assert not _managed_routes(api)


# --- modem already on the would-be WAN port ---------------------------------------

def test_preflight_treats_foreign_ip_modem_on_lan_port_as_upstream():
    report = mikrotik_lb.lb_preflight(_router537(), ["ether1", "ether2"])
    assert report["blockers"] == []
    assert report["per_port"]["ether2"]["upstream_devices"] == [
        {"mac": MODEM_MAC, "addresses": ["192.168.100.1"]}]
    assert any("modem" in w for w in report["warnings"])


def test_modem_host_entry_blinking_out_is_retried():
    api = _router537(hotspot_hosts=[])
    original = api._print
    calls = {"n": 0}

    def flaky(command):
        if command == "/ip/hotspot/host/print":
            calls["n"] += 1
            if calls["n"] >= 2:  # back on the second read
                api.hotspot_hosts = [{"mac-address": MODEM_MAC, "address": "192.168.100.1",
                                      "to-address": "192.168.88.151"}]
        return original(command)

    api._print = flaky
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert report["blockers"] == []


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


# --- convert on v6 ------------------------------------------------------------------

def test_router537_end_to_end_shared_subnet_switches_to_direct_routes():
    api = _router537()
    wans = ["ether1", "ether2"]
    assert mikrotik_lb.lb_apply(api, wans)["route_mode"] == "recursive"

    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.14/24"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1",
                                         wan_ports=wans)

    assert report["success"] is True, report["steps"]
    assert report["route_mode"] == "direct"
    assert _commands(api, "/interface/bridge/port/remove") == [{".id": "*B2"}]
    routes = _managed_routes(api)
    # no recursive probes left — both modems are 192.168.100.1, so only the
    # interface pin tells the lines apart
    assert not [c for c in routes if c.endswith("_PROBE")]
    assert routes["ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"]["gateway"] == "192.168.100.1%ether1"
    assert routes["ISP_BILLING_DUAL_WAN_BACKUP_CHECKED"]["gateway"] == "192.168.100.1%ether2"
    assert routes["ISP_BILLING_DUAL_WAN_BACKUP_CHECKED"]["distance"] == "2"
    assert routes["ISP_BILLING_PCC_WAN1"]["gateway"] == "192.168.100.1%ether1"
    assert routes["ISP_BILLING_PCC_WAN1_FALLBACK"]["gateway"] == "192.168.100.1%ether2"
    assert routes["ISP_BILLING_PCC_WAN2"]["gateway"] == "192.168.100.1%ether2"
    assert routes["ISP_BILLING_PCC_WAN2"]["routing-mark"] == "to_wan2"
    assert routes["ISP_BILLING_PCC_WAN2_FALLBACK"]["gateway"] == "192.168.100.1%ether1"
    assert all(r["check-gateway"] == "ping" for r in routes.values())
    assert any("own LAN subnet" in w for w in report["warnings"])
    assert _commands(api, "/interface/list/member/add") == [
        {"list": "WAN", "interface": "ether2"}]

    # verify maps each WAN mark to its port despite v6 proplist truncation
    api.connections = [
        {"connection-mark": "WAN1_conn", "reply-dst-address": "192.168.100.9:5000"},
        {"connection-mark": "WAN2_conn", "reply-dst-address": "192.168.100.14:5001"},
    ]
    verify = mikrotik_lb.lb_verify(api)
    assert verify["flow_attribution"] == {
        "WAN1_conn": {"correct": 1, "wrong": 0, "unknown": 0},
        "WAN2_conn": {"correct": 1, "wrong": 0, "unknown": 0},
    }


def test_convert_ros6_separate_subnets_keeps_recursive_failover():
    api = _router537()
    wans = ["ether1", "ether2"]
    mikrotik_lb.lb_apply(api, wans)
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.101.1",
                       "address": "192.168.101.20/24"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1",
                                         wan_ports=wans)
    assert report["route_mode"] == "recursive"
    routes = _managed_routes(api)
    assert routes["ISP_BILLING_DUAL_WAN_ETHER2_PROBE"]["gateway"] == "192.168.101.1"
    assert routes["ISP_BILLING_DUAL_WAN_ETHER2_PROBE"]["dst-address"] == "1.1.1.1/32"
    assert routes["ISP_BILLING_DUAL_WAN_BACKUP_CHECKED"]["gateway"] == "1.1.1.1"
    assert not any("own LAN subnet" in w for w in report["warnings"])


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


def test_device_leasing_from_our_dhcp_server_is_always_a_client():
    api = _router537(leases=[{"mac-address": MODEM_MAC, "status": "bound"}])
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("serves customers" in b for b in report["blockers"])


def test_arp_for_a_real_lan_address_still_counts_as_a_client():
    # same MAC also answering on a LAN address that is NOT the hotspot alias
    api = _router537(arp=[{"mac-address": MODEM_MAC, "address": "192.168.88.60",
                           "interface": "bridge"}])
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert any("serves customers" in b for b in report["blockers"])


# --- lessons from the live ether2 DHCP test on router 537 ---------------------------

PIN = "ISP_BILLING_MGMT_PIN_91_98_238_12"


def test_v6_dhcp_client_is_created_enabled():
    """v6 creates /ip dhcp-client entries DISABLED unless told otherwise."""
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")
    assert _commands(api, "/ip/dhcp-client/add")[0]["disabled"] == "no"


def test_masquerade_coverage_lands_before_the_port_gets_an_address():
    api = _router537()
    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")
    order = [c for c, _ in api.commands
             if c in ("/interface/list/member/add", "/ip/dhcp-client/add")]
    assert order == ["/interface/list/member/add", "/ip/dhcp-client/add"]


def test_mgmt_tunnel_pinned_to_wan1_on_apply_then_gets_wan2_fallback():
    api = _router537()
    wans = ["ether1", "ether2"]
    mikrotik_lb.lb_apply(api, wans)
    routes = _managed_routes(api)
    assert routes[PIN] == {**routes[PIN], "dst-address": "91.98.238.12/32",
                           "gateway": "192.168.100.1%ether1", "distance": "1",
                           "check-gateway": "ping"}
    assert PIN + "_FALLBACK" not in routes  # WAN2 not bound yet

    _on_dhcp_add(api, {"status": "bound", "gateway": "192.168.100.1",
                       "address": "192.168.100.3/24"})
    mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1", wan_ports=wans)
    routes = _managed_routes(api)
    assert routes[PIN]["gateway"] == "192.168.100.1%ether1"
    assert routes[PIN + "_FALLBACK"]["gateway"] == "192.168.100.1%ether2"
    assert routes[PIN + "_FALLBACK"]["distance"] == "2"


def test_disabled_or_hostname_tunnels_are_not_pinned():
    api = _router537(sstp_clients=[
        {"connect-to": "91.98.238.12", "disabled": "true"},
        {"connect-to": "vpn.example.net", "disabled": "false"},
    ])
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert not [c for c in _managed_routes(api) if "MGMT_PIN" in c]


def test_revert_also_removes_the_wan_list_membership(monkeypatch):
    monkeypatch.setattr(mikrotik_lb, "LB_CONVERT_DHCP_BIND_ATTEMPTS", 2)
    api = _router537()
    _on_dhcp_add(api, {"status": "searching"})
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")
    assert report["reverted"] is True
    assert not any(m["interface"] == "ether2" for m in api.list_members)


def test_rollback_removes_mgmt_pins():
    api = _router537()
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert PIN in _managed_routes(api)
    mikrotik_lb.lb_rollback(api)
    assert not _managed_routes(api)

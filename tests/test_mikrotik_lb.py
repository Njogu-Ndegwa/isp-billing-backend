"""Service-layer tests for app/services/mikrotik_lb.py.

Uses the FakeMikroTikAPI idiom from tests/test_mikrotik_anti_tethering.py:
subclass MikroTikAPI, set connected=True, record every write command. The fake
here is STATEFUL — adds mutate the printed data — so idempotency (skip objects
whose comment already exists) can be exercised with two real runs.
"""

from datetime import datetime, timedelta

import pytest

from app.services import mikrotik_lb
from app.services.mikrotik_api import MikroTikAPI


class FakeLBAPI(MikroTikAPI):
    def __init__(
        self,
        *,
        dhcp_clients=None,
        hotspots=None,
        interfaces=None,
        bridge_ports=None,
        bridge_hosts=None,
        routing_tables=None,
        routes=None,
        address_lists=None,
        filter_rules=None,
        mangle_rules=None,
        wg_peers=None,
        connections=None,
        hotspot_hosts=None,
        list_members=None,
        nat_rules=None,
        dhcp_networks=None,
        fail_commands=None,
    ):
        self.connected = True
        self.commands = []
        self._id = 0
        self.fail_commands = set(fail_commands or [])
        self.system_resources = [{"version": "7.15.2", "free-memory": "104857600"}]
        self.dhcp_clients = dhcp_clients if dhcp_clients is not None else [
            {"interface": "ether1", "status": "bound",
             "gateway": "41.90.1.1", "address": "41.90.1.20/24"},
        ]
        self.hotspots = hotspots if hotspots is not None else [
            {"name": "hotspot1", "interface": "bridge", "profile": "hsprof1",
             "disabled": "false"},
        ]
        self.interfaces = interfaces if interfaces is not None else [
            {"name": "ether1", "running": "true"},
            {"name": "ether2", "running": "true"},
            {"name": "ether3", "running": "true"},
        ]
        self.bridge_ports = bridge_ports or []
        self.bridge_hosts = bridge_hosts or []
        self.routing_tables = routing_tables or []
        self.routes = routes or []
        self.address_lists = address_lists or []
        self.filter_rules = filter_rules if filter_rules is not None else [
            {".id": "*F1", "action": "fasttrack-connection", "connection-mark": ""},
        ]
        self.mangle_rules = mangle_rules or []
        self.wg_peers = wg_peers or []
        self.connections = connections or []
        self.hotspot_hosts = hotspot_hosts or []
        self.list_members = list_members or []
        self.nat_rules = nat_rules or []
        self.dhcp_networks = dhcp_networks or []

    # -- helpers -----------------------------------------------------------

    def _next_id(self):
        self._id += 1
        return f"*A{self._id:X}"

    def _print(self, command):
        mapping = {
            "/system/resource/print": self.system_resources,
            "/ip/dhcp-client/print": self.dhcp_clients,
            "/interface/print": self.interfaces,
            "/interface/bridge/port/print": self.bridge_ports,
            "/interface/bridge/host/print": self.bridge_hosts,
            "/ip/hotspot/print": self.hotspots,
            "/ip/dhcp-server/network/print": self.dhcp_networks,
            "/ip/firewall/filter/print": self.filter_rules,
            "/ip/firewall/mangle/print": self.mangle_rules,
            "/interface/wireguard/peers/print": self.wg_peers,
            "/routing/table/print": self.routing_tables,
            "/ip/route/print": self.routes,
            "/ip/firewall/address-list/print": self.address_lists,
            "/ip/firewall/connection/print": self.connections,
            "/ip/hotspot/host/print": self.hotspot_hosts,
            "/interface/list/member/print": self.list_members,
            "/ip/firewall/nat/print": self.nat_rules,
        }
        if command in mapping:
            return {"success": True, "data": list(mapping[command])}
        return {"error": f"Unexpected print command: {command}"}

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/ip/firewall/filter/print" and query == "?action=fasttrack-connection":
            return {"success": True,
                    "data": [f for f in self.filter_rules
                             if f.get("action") == "fasttrack-connection"]}
        return self._print(command)

    def _remove_by_id(self, rows, rid):
        rows[:] = [r for r in rows if r.get(".id") != rid]

    def send_command(self, command, arguments=None):
        args = dict(arguments or {})
        if command.endswith("/print"):
            return self._print(command)
        self.commands.append((command, args))
        if command in self.fail_commands:
            return {"error": f"forced failure for {command}"}
        row = {".id": self._next_id(), **args}
        if command == "/routing/table/add":
            self.routing_tables.append(row)
        elif command == "/routing/table/remove":
            self._remove_by_id(self.routing_tables, args.get(".id"))
        elif command == "/ip/route/add":
            self.routes.append(row)
        elif command == "/ip/route/remove":
            self._remove_by_id(self.routes, args.get(".id"))
        elif command == "/ip/firewall/address-list/add":
            self.address_lists.append(row)
        elif command == "/ip/firewall/address-list/remove":
            self._remove_by_id(self.address_lists, args.get(".id"))
        elif command == "/ip/firewall/mangle/add":
            row.setdefault("disabled", "false")
            self.mangle_rules.append(row)
        elif command == "/ip/firewall/mangle/set":
            for r in self.mangle_rules:
                if r.get(".id") == args.get(".id"):
                    r.update({k: v for k, v in args.items() if k != ".id"})
        elif command == "/ip/firewall/mangle/remove":
            self._remove_by_id(self.mangle_rules, args.get(".id"))
        elif command == "/ip/firewall/filter/set":
            for r in self.filter_rules:
                if r.get(".id") == args.get(".id"):
                    r.update({k: v for k, v in args.items() if k != ".id"})
        return {"success": True, "data": []}


@pytest.fixture(autouse=True)
def _no_settle(monkeypatch):
    monkeypatch.setattr(mikrotik_lb, "LB_APPLY_SETTLE_SECONDS", 0)
    monkeypatch.setattr(mikrotik_lb, "LB_CONVERT_SETTLE_SECONDS", 0)
    monkeypatch.setattr(mikrotik_lb, "LB_CONVERT_DHCP_BIND_DELAY_SECONDS", 0)


def _commands(api, command):
    return [args for cmd, args in api.commands if cmd == command]


# ---------------------------------------------------------------------------
# (a) mangle order: GUARD -> BYPASS -> MARK rules -> ROUTE rules
# ---------------------------------------------------------------------------

def test_apply_orders_guard_before_bypass_before_marks_before_routes():
    api = FakeLBAPI()
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    assert report["success"] is True
    mangle_comments = [a["comment"] for a in _commands(api, "/ip/firewall/mangle/add")]
    assert mangle_comments == [
        "ISP_BILLING_PCC_UNAUTH_GUARD_V2",
        "ISP_BILLING_PCC_BYPASS",
        "ISP_BILLING_PCC_MARK_WAN1",
        "ISP_BILLING_PCC_MARK_WAN2",
        "ISP_BILLING_PCC_ROUTE_WAN1",
        "ISP_BILLING_PCC_ROUTE_WAN2",
    ]

    guard = _commands(api, "/ip/firewall/mangle/add")[0]
    assert guard["action"] == "accept"
    assert guard["in-interface"] == "bridge"
    assert guard["hotspot"] == "!auth"
    assert guard["src-address-list"] == "!LB_PAID"

    # PCC mark rules carry the anti-mid-flow and anti-local protections.
    for mark in _commands(api, "/ip/firewall/mangle/add")[2:4]:
        assert mark["connection-state"] == "new"
        assert mark["dst-address-type"] == "!local"
        assert mark["connection-mark"] == "no-mark"


# ---------------------------------------------------------------------------
# (b) PCC classifiers per WAN count
# ---------------------------------------------------------------------------

def test_apply_pcc_classifiers_two_wans():
    api = FakeLBAPI()
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    classifiers = [a["per-connection-classifier"]
                   for a in _commands(api, "/ip/firewall/mangle/add")
                   if a.get("action") == "mark-connection"]
    assert classifiers == ["both-addresses:2/0", "both-addresses:2/1"]


def test_apply_pcc_classifiers_three_wans():
    api = FakeLBAPI()
    mikrotik_lb.lb_apply(api, ["ether1", "ether2", "ether3"])
    classifiers = [a["per-connection-classifier"]
                   for a in _commands(api, "/ip/firewall/mangle/add")
                   if a.get("action") == "mark-connection"]
    assert classifiers == [
        "both-addresses:3/0", "both-addresses:3/1", "both-addresses:3/2",
    ]


# ---------------------------------------------------------------------------
# (c) re-apply is idempotent
# ---------------------------------------------------------------------------

def test_reapply_skips_existing_objects():
    api = FakeLBAPI()
    first = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert first["success"] is True
    adds_after_first = len(api.commands)
    assert adds_after_first > 0

    second = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert second["success"] is True
    new_commands = api.commands[adds_after_first:]
    creating = [c for c, _ in new_commands
                if c in ("/ip/firewall/mangle/add", "/ip/route/add",
                         "/ip/firewall/address-list/add", "/routing/table/add")]
    assert creating == [], f"re-apply created objects again: {creating}"


# ---------------------------------------------------------------------------
# (d) rollback: disable marks FIRST, then routes, guard/bypass only after
# ---------------------------------------------------------------------------

def _applied_api():
    api = FakeLBAPI()
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert report["success"] is True
    api.commands = []  # keep only rollback traffic
    return api


def test_rollback_disables_marks_before_routes_before_guard_removal():
    api = _applied_api()
    id_to_comment = {r[".id"]: r.get("comment") for r in api.mangle_rules}

    report = mikrotik_lb.lb_rollback(api)
    assert report["success"] is True

    disabled = [id_to_comment[a[".id"]]
                for cmd, a in api.commands
                if cmd == "/ip/firewall/mangle/set" and a.get("disabled") == "yes"]
    assert disabled == [
        "ISP_BILLING_PCC_MARK_WAN1",
        "ISP_BILLING_PCC_MARK_WAN2",
        "ISP_BILLING_PCC_ROUTE_WAN1",
        "ISP_BILLING_PCC_ROUTE_WAN2",
    ]

    removed = [id_to_comment.get(a[".id"])
               for cmd, a in api.commands
               if cmd == "/ip/firewall/mangle/remove"]
    # marks removed before routes, guard/bypass strictly last
    assert removed == [
        "ISP_BILLING_PCC_MARK_WAN1",
        "ISP_BILLING_PCC_MARK_WAN2",
        "ISP_BILLING_PCC_ROUTE_WAN1",
        "ISP_BILLING_PCC_ROUTE_WAN2",
        "ISP_BILLING_PCC_UNAUTH_GUARD_V2",
        "ISP_BILLING_PCC_BYPASS",
    ]

    # guard is only touched after every mark rule is already disabled
    ops = [(cmd, id_to_comment.get(a.get(".id")))
           for cmd, a in api.commands
           if cmd in ("/ip/firewall/mangle/set", "/ip/firewall/mangle/remove")]
    guard_idx = next(i for i, (cmd, c) in enumerate(ops)
                     if c == "ISP_BILLING_PCC_UNAUTH_GUARD_V2")
    mark_disable_idx = [i for i, (cmd, c) in enumerate(ops)
                        if cmd == "/ip/firewall/mangle/set"
                        and c and c.startswith("ISP_BILLING_PCC_MARK_")]
    assert all(i < guard_idx for i in mark_disable_idx)

    # fasttrack restored (connection-mark back to "") and cleanup done
    ft_restores = [a for cmd, a in api.commands
                   if cmd == "/ip/firewall/filter/set" and a.get("connection-mark") == ""]
    assert len(ft_restores) == 1
    assert all(a.get("list") != "LB_SRC" for a in api.address_lists)
    assert api.routing_tables == []
    assert all(not (r.get("comment") or "").startswith("ISP_BILLING")
               for r in api.routes)


def test_rollback_restores_fasttrack_after_guard_removal():
    api = _applied_api()
    ordered = []

    original = api.send_command

    def tracking(command, arguments=None):
        ordered.append((command, dict(arguments or {})))
        return original(command, arguments)

    api.send_command = tracking
    mikrotik_lb.lb_rollback(api)

    guard_remove_idx = next(
        i for i, (cmd, a) in enumerate(ordered) if cmd == "/ip/firewall/mangle/remove"
    )
    ft_idx = next(
        i for i, (cmd, a) in enumerate(ordered)
        if cmd == "/ip/firewall/filter/set" and a.get("connection-mark") == ""
    )
    assert ft_idx > guard_remove_idx


# ---------------------------------------------------------------------------
# (e) LB_PAID timeout clamped to [60, 21_000_000]
# ---------------------------------------------------------------------------

def test_seed_paid_timeout_capped_at_routeros_max():
    api = FakeLBAPI(hotspot_hosts=[
        {"mac-address": "AA:BB:CC:DD:EE:01", "address": "192.168.88.50",
         "bypassed": "true"},
    ])
    far_future = datetime.utcnow() + timedelta(days=2000)  # ~172.8M seconds
    report = mikrotik_lb.lb_seed_paid(
        api, [{"mac": "AA:BB:CC:DD:EE:01", "expiry": far_future}]
    )
    adds = _commands(api, "/ip/firewall/address-list/add")
    assert len(adds) == 1
    assert adds[0]["list"] == "LB_PAID"
    assert adds[0]["timeout"] == "21000000s"
    assert report["added"][0]["timeout_s"] == 21_000_000


def test_seed_paid_timeout_has_min_and_always_present():
    api = FakeLBAPI(hotspot_hosts=[
        {"mac-address": "AA:BB:CC:DD:EE:02", "address": "192.168.88.51",
         "bypassed": "true"},
    ])
    nearly_expired = datetime.utcnow() + timedelta(seconds=5)
    mikrotik_lb.lb_seed_paid(
        api, [{"mac": "AA:BB:CC:DD:EE:02", "expiry": nearly_expired}]
    )
    adds = _commands(api, "/ip/firewall/address-list/add")
    assert adds[0]["timeout"] == "60s"


def test_seed_paid_skips_unbypassed_and_offline_hosts():
    api = FakeLBAPI(hotspot_hosts=[
        {"mac-address": "AA:BB:CC:DD:EE:03", "address": "192.168.88.52",
         "bypassed": "false"},
    ])
    expiry = datetime.utcnow() + timedelta(hours=1)
    report = mikrotik_lb.lb_seed_paid(api, [
        {"mac": "AA:BB:CC:DD:EE:03", "expiry": expiry},   # online, not bypassed
        {"mac": "AA:BB:CC:DD:EE:04", "expiry": expiry},   # not online
    ])
    assert _commands(api, "/ip/firewall/address-list/add") == []
    reasons = {s["mac"]: s["why"] for s in report["skipped"]}
    assert "not bypassed" in reasons["AA:BB:CC:DD:EE:03"]
    assert reasons["AA:BB:CC:DD:EE:04"] == "not currently online"


# ---------------------------------------------------------------------------
# (f) recursive routes carry target-scope=11
# ---------------------------------------------------------------------------

def test_apply_recursive_routes_have_target_scope_11():
    api = FakeLBAPI(wg_peers=[
        {"interface": "wg-aws", "endpoint-address": "54.91.202.229"},
        {"interface": "wg-aws2", "endpoint-address": "35.170.199.141"},
    ])
    mikrotik_lb.lb_apply(api, ["ether1", "ether2"])

    route_adds = _commands(api, "/ip/route/add")
    recursive = [r for r in route_adds if r.get("check-gateway") == "ping"]
    assert recursive, "expected recursive checked routes"
    assert all(r.get("target-scope") == "11" for r in recursive)

    # probe host route is interface-qualified and NOT recursive
    probes = [r for r in route_adds
              if r["comment"].endswith("_PROBE")]
    assert probes and all("%" in p["gateway"] and p["scope"] == "10" for p in probes)

    # main checked default for WAN1 exists at distance 1
    primary = next(r for r in route_adds
                   if r["comment"] == "ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED")
    assert primary["distance"] == "1"
    assert primary["target-scope"] == "11"

    # VPN pins: wg-aws pinned to WAN1 probe, wg-aws2 to WAN2 probe
    pin_aws = next(r for r in route_adds
                   if r["comment"] == "ISP_BILLING_VPN_PIN_WGAWS")
    pin_aws2 = next(r for r in route_adds
                    if r["comment"] == "ISP_BILLING_VPN_PIN_WGAWS2")
    assert pin_aws["gateway"] == "8.8.8.8"
    assert pin_aws2["gateway"] == "1.1.1.1"
    assert pin_aws["target-scope"] == "11"


def test_apply_dormant_wan_gets_table_with_fallback_but_no_probe():
    """Second WAN not yet DHCP-bound: no probe/checked default for it, but its
    to_wan2 table exists with a fallback via WAN1's probe."""
    api = FakeLBAPI()
    report = mikrotik_lb.lb_apply(api, ["ether1", "ether2"])
    assert report["success"] is True

    route_adds = _commands(api, "/ip/route/add")
    comments = [r["comment"] for r in route_adds]
    assert "ISP_BILLING_DUAL_WAN_ETHER2_PROBE" not in comments
    assert "ISP_BILLING_DUAL_WAN_BACKUP_CHECKED" not in comments
    to_wan2 = [r for r in route_adds if r.get("routing-table") == "to_wan2"]
    assert {r["gateway"] for r in to_wan2} == {"1.1.1.1", "8.8.8.8"}
    fallback = next(r for r in to_wan2
                    if r["comment"] == "ISP_BILLING_PCC_WAN2_FALLBACK")
    assert fallback["gateway"] == "8.8.8.8"
    assert fallback["distance"] == "2"


# ---------------------------------------------------------------------------
# preflight + convert safety
# ---------------------------------------------------------------------------

def test_preflight_blocks_port_serving_customers():
    api = FakeLBAPI(
        bridge_ports=[{".id": "*B1", "interface": "ether2", "bridge": "bridge"}],
        bridge_hosts=[
            {"mac-address": "11:22:33:44:55:66", "on-interface": "ether2",
             "local": "false"},
        ],
    )
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert report["success"] is False
    assert any("serves customers" in b for b in report["blockers"])
    assert report["verdict"].startswith("BLOCKED")


def test_preflight_ok_on_clean_router():
    api = FakeLBAPI()
    report = mikrotik_lb.lb_preflight(api, ["ether1", "ether2"])
    assert report["blockers"] == []
    assert report["success"] is True
    assert report["per_port"]["ether2"]["link"] == "true"


def test_convert_aborts_when_port_serves_lan_devices():
    api = FakeLBAPI(
        bridge_ports=[{".id": "*B1", "interface": "ether2", "bridge": "bridge"}],
        bridge_hosts=[
            {"mac-address": "11:22:33:44:55:66", "on-interface": "ether2",
             "local": "false"},
        ],
    )
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")
    assert report["success"] is False
    assert "serves devices" in report["aborted"]
    assert _commands(api, "/interface/bridge/port/remove") == []


def test_convert_sets_up_dhcp_probe_and_checked_default():
    api = FakeLBAPI(
        bridge_ports=[{".id": "*B1", "interface": "ether2", "bridge": "bridge"}],
        list_members=[{".id": "*M1", "list": "WAN", "interface": "ether1"}],
    )

    # DHCP binds as soon as the client is added.
    original = api.send_command

    def with_dhcp_bind(command, arguments=None):
        result = original(command, arguments)
        if command == "/ip/dhcp-client/add":
            api.dhcp_clients.append({
                "interface": (arguments or {}).get("interface"),
                "status": "bound", "gateway": "10.20.0.1",
                "address": "10.20.0.5/24",
            })
        return result

    api.send_command = with_dhcp_bind
    report = mikrotik_lb.lb_convert_port(api, "ether2", 1, wan1_port="ether1")

    assert report["success"] is True
    assert report["lease"]["gateway"] == "10.20.0.1"
    dhcp_adds = [a for cmd, a in api.commands if cmd == "/ip/dhcp-client/add"]
    assert dhcp_adds == [{
        "interface": "ether2", "add-default-route": "no",
        "use-peer-dns": "no", "use-peer-ntp": "no",
        "comment": "ISP_BILLING_WAN2",
    }]
    route_adds = [a for cmd, a in api.commands if cmd == "/ip/route/add"]
    probe = next(r for r in route_adds
                 if r["comment"] == "ISP_BILLING_DUAL_WAN_ETHER2_PROBE")
    assert probe["gateway"] == "10.20.0.1%ether2"
    checked = next(r for r in route_adds
                   if r["comment"] == "ISP_BILLING_DUAL_WAN_BACKUP_CHECKED")
    assert checked["target-scope"] == "11"
    assert checked["distance"] == "2"
    # ether2 mirrored into WAN1's interface list for masquerade coverage
    member_adds = [a for cmd, a in api.commands
                   if cmd == "/interface/list/member/add"]
    assert member_adds == [{"list": "WAN", "interface": "ether2"}]


# ---------------------------------------------------------------------------
# verify: the portal-killer state is flagged
# ---------------------------------------------------------------------------

def test_verify_flags_guard_disabled_while_marks_live():
    api = FakeLBAPI(mangle_rules=[
        {".id": "*1", "comment": "ISP_BILLING_PCC_UNAUTH_GUARD_V2",
         "disabled": "true", "packets": "0"},
        {".id": "*2", "comment": "ISP_BILLING_PCC_MARK_WAN1",
         "disabled": "false", "packets": "10"},
    ])
    report = mikrotik_lb.lb_verify(api)
    assert report["success"] is False
    assert any("portal-killer" in w for w in report["warnings"])


def test_verify_flags_lb_paid_entry_held_by_unauth_host():
    api = FakeLBAPI(
        hotspot_hosts=[{"mac-address": "AA:BB:CC:DD:EE:05",
                        "address": "192.168.88.60",
                        "bypassed": "false", "authorized": "false"}],
        address_lists=[{".id": "*L1", "list": "LB_PAID",
                        "address": "192.168.88.60"}],
    )
    report = mikrotik_lb.lb_verify(api)
    assert any("DANGER" in w for w in report["warnings"])
    assert report["success"] is False

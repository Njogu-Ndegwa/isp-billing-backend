"""Re-applying load balancing with a different WAN set, LAN-derived LB_SRC,
and the PCC rule-order check in verify.

Found 2026-11-12 adding a third line to router 606: enable skipped every rule
whose comment already existed, so MARK 2/0 + 2/1 stayed and MARK 3/2 landed
after the ROUTE rules. WAN3 never got a connection and the API said success.
Its customers also sit on 172.172.10.0/24, outside the built-in LB_SRC list.
"""

import pytest

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_lb
from tests.test_mikrotik_lb import FakeLBAPI, _commands, _no_settle  # noqa: F401

W2 = ["ether1", "ether2"]
W3 = ["ether1", "ether2", "ether3"]

MANAGED = ("ISP_BILLING_PCC_UNAUTH_GUARD_V2", "ISP_BILLING_PCC_BYPASS")


def _bound(*ports):
    gws = {"ether1": ("41.90.1.1", "41.90.1.20/24"),
           "ether2": ("10.20.0.1", "10.20.0.5/24"),
           "ether3": ("192.168.101.1", "192.168.101.7/24")}
    return [{"interface": p, "status": "bound", "gateway": gws[p][0],
             "address": gws[p][1]} for p in ports]


def _router(ports=("ether1", "ether2"), **kw):
    kw.setdefault("ip_addresses", [
        {"address": "172.172.10.1/24", "interface": "bridge"},
        {"address": "192.168.89.1/24", "interface": "bridge-pppoe"},
        {"address": "10.0.3.17/32", "interface": "wg-aws"},
        {"address": "41.90.1.20/24", "interface": "ether1", "dynamic": "true"},
    ])
    kw.setdefault("wg_peers", [
        {"interface": "wg-aws", "endpoint-address": "54.91.202.229"},
        {"interface": "wg-aws2", "endpoint-address": "35.170.199.141"},
    ])
    kw.setdefault("interfaces", [{"name": f"ether{i}", "running": "true"} for i in (1, 2, 3)])
    return FakeLBAPI(dhcp_clients=_bound(*ports), **kw)


def _block(api):
    """Managed mangle comments in rule order."""
    return [r.get("comment") for r in api.mangle_rules
            if (r.get("comment") or "") in MANAGED
            or (r.get("comment") or "").startswith(("ISP_BILLING_PCC_MARK_",
                                                    "ISP_BILLING_PCC_ROUTE_"))]


def _expected_block(n):
    return list(MANAGED) + [f"ISP_BILLING_PCC_MARK_WAN{i}" for i in range(1, n + 1)] \
        + [f"ISP_BILLING_PCC_ROUTE_WAN{i}" for i in range(1, n + 1)]


def _classifiers(api):
    return [r["per-connection-classifier"] for r in api.mangle_rules
            if r.get("action") == "mark-connection"]


def _guard_always_first(api):
    """Wrap send_command: after every mangle write, an enabled mark rule must
    never exist without the guard in front of it (the portal-killer state)."""
    original = api.send_command
    violations = []

    def checked(command, arguments=None):
        result = original(command, arguments)
        if command.startswith("/ip/firewall/mangle/") and not command.endswith("/print"):
            rows = api.mangle_rules
            guard = next((i for i, r in enumerate(rows)
                          if r.get("comment") == "ISP_BILLING_PCC_UNAUTH_GUARD_V2"
                          and r.get("disabled") != "yes"), None)
            for i, r in enumerate(rows):
                if (r.get("action") == "mark-connection" and r.get("disabled") not in ("yes", "true")
                        and (guard is None or guard > i)):
                    violations.append((command, r.get("comment")))
        return result

    api.send_command = checked
    return violations


# ---------------------------------------------------------------------------
# 1. 2 -> 3 WANs rebuilds the split in order
# ---------------------------------------------------------------------------

def test_two_to_three_wan_upgrade_rebuilds_three_way_pcc_in_order():
    api = _router(("ether1", "ether2"))
    assert mikrotik_lb.lb_apply(api, W2)["success"] is True
    assert _classifiers(api) == ["both-addresses:2/0", "both-addresses:2/1"]
    # someone's own rule after our block must stay after it
    api.mangle_rules.append({".id": "*U1", "chain": "prerouting", "action": "accept",
                             "comment": "reseller own rule", "disabled": "false"})

    api.dhcp_clients[:] = _bound("ether1", "ether2", "ether3")
    violations = _guard_always_first(api)
    report = mikrotik_lb.lb_apply(api, W3)

    assert report["success"] is True, [s for s in report["steps"] if not s["ok"]]
    assert report["mangle_mode"] == "rebuilt"
    assert violations == []
    assert _block(api) == _expected_block(3)
    assert _classifiers(api) == ["both-addresses:3/0", "both-addresses:3/1",
                                 "both-addresses:3/2"]
    assert api.mangle_rules[-1]["comment"] == "reseller own rule"
    route_rules = [r for r in api.mangle_rules if r.get("action") == "mark-routing"]
    assert [(r["connection-mark"], r["new-routing-mark"]) for r in route_rules] == [
        ("WAN1_conn", "to_wan1"), ("WAN2_conn", "to_wan2"), ("WAN3_conn", "to_wan3")]

    order = mikrotik_lb.lb_pcc_order_check(api.mangle_rules, 3)
    assert order["ok"] is True
    assert order["share"] == {"WAN1": 0.333, "WAN2": 0.333, "WAN3": 0.333}
    assert order["unbalanced_share"] == 0

    # routes follow the new set: to_wan3 exists, every table chains all 3 WANs,
    # the WAN3 probe/checked default exist, and nothing is duplicated.
    assert "to_wan3" in {t.get("name") for t in api.routing_tables}
    comments = [r.get("comment") for r in api.routes]
    assert len(comments) == len(set(comments)), comments
    probes = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    for i in range(3):
        rows = sorted((r for r in api.routes if r.get("routing-table") == f"to_wan{i + 1}"),
                      key=lambda r: int(r["distance"]))
        assert [r["gateway"] for r in rows] == [probes[i], probes[(i + 1) % 3],
                                                 probes[(i + 2) % 3]]
    assert "ISP_BILLING_DUAL_WAN_ETHER3_PROBE" in comments
    assert "ISP_BILLING_DUAL_WAN_WAN3_CHECKED" in comments

    verify = mikrotik_lb.lb_verify(api, W3)
    assert verify["pcc_order"]["ok"] is True
    assert verify["success"] is True


def test_upgrade_adds_new_rules_before_retiring_old_ones():
    """Make-before-break: the 3-way block is in place before any old rule goes,
    so there is no moment where new connections go unbalanced."""
    api = _router(("ether1", "ether2"))
    mikrotik_lb.lb_apply(api, W2)
    api.commands = []
    api.dhcp_clients[:] = _bound("ether1", "ether2", "ether3")
    mikrotik_lb.lb_apply(api, W3)
    mangle_ops = [c for c, _ in api.commands if c.startswith("/ip/firewall/mangle/")]
    first_retire = mangle_ops.index("/ip/firewall/mangle/set")
    assert mangle_ops[:first_retire] == ["/ip/firewall/mangle/add"] * 6
    assert set(mangle_ops[first_retire:]) == {"/ip/firewall/mangle/set",
                                              "/ip/firewall/mangle/remove"}


def test_router606_broken_state_is_flagged_then_repaired():
    """The exact state found on router 606: 2-way split + a 3/2 rule appended
    after the ROUTE rules."""
    api = _router(("ether1", "ether2", "ether3"))
    mikrotik_lb.lb_apply(api, W2)
    api.mangle_rules.append({
        ".id": "*X3", "chain": "prerouting", "action": "mark-connection",
        "new-connection-mark": "WAN3_conn", "passthrough": "yes",
        "src-address-list": "LB_SRC", "connection-mark": "no-mark",
        "connection-state": "new", "dst-address-type": "!local",
        "per-connection-classifier": "both-addresses:3/2",
        "comment": "ISP_BILLING_PCC_MARK_WAN3", "disabled": "false"})
    api.mangle_rules.append({
        ".id": "*X4", "chain": "prerouting", "action": "mark-routing",
        "new-routing-mark": "to_wan3", "passthrough": "no",
        "src-address-list": "LB_SRC", "connection-mark": "WAN3_conn",
        "dst-address-type": "!local",
        "comment": "ISP_BILLING_PCC_ROUTE_WAN3", "disabled": "false"})

    broken = mikrotik_lb.lb_verify(api, W3)
    assert broken["success"] is False
    assert broken["pcc_order"]["unreachable"] == ["WAN3"]
    assert any("WAN3 never receive" in w for w in broken["warnings"])
    # without the configured set, verify still infers 3 WANs from the rules
    assert mikrotik_lb.lb_verify(api)["pcc_order"]["unreachable"] == ["WAN3"]

    assert mikrotik_lb.lb_apply(api, W3)["success"] is True
    assert _block(api) == _expected_block(3)
    assert mikrotik_lb.lb_verify(api, W3)["pcc_order"]["ok"] is True


def test_three_to_two_wan_downgrade_drops_wan3_rules_routes_and_table():
    api = _router(("ether1", "ether2", "ether3"))
    mikrotik_lb.lb_apply(api, W3)
    assert "to_wan3" in {t.get("name") for t in api.routing_tables}

    report = mikrotik_lb.lb_apply(api, W2)
    assert report["success"] is True
    assert _block(api) == _expected_block(2)
    assert _classifiers(api) == ["both-addresses:2/0", "both-addresses:2/1"]
    assert "to_wan3" not in {t.get("name") for t in api.routing_tables}
    left = [r.get("comment") for r in api.routes]
    assert not any("WAN3" in (c or "") or "ETHER3" in (c or "") for c in left), left
    assert not any((r.get("routing-table") == "to_wan3") for r in api.routes)
    # to_wan2's fallback is back on WAN1
    fb = next(r for r in api.routes if r.get("comment") == "ISP_BILLING_PCC_WAN2_FALLBACK")
    assert fb["gateway"] == "8.8.8.8"


def test_misordered_guard_triggers_full_rebuild_with_guard_first():
    api = _router()
    mikrotik_lb.lb_apply(api, W2)
    guard = next(r for r in api.mangle_rules
                 if r["comment"] == "ISP_BILLING_PCC_UNAUTH_GUARD_V2")
    api.mangle_rules.remove(guard)
    api.mangle_rules.append(guard)  # guard now after the marks
    id_to_comment = {r[".id"]: r["comment"] for r in api.mangle_rules}
    api.commands = []

    report = mikrotik_lb.lb_apply(api, W2)
    assert report["success"] is True
    assert report["mangle_mode"] == "rebuilt"
    assert _block(api) == _expected_block(2)
    # break-before-make: the old guard goes only after every old mark is gone,
    # and the new guard is added before any new mark
    removed = [id_to_comment.get(a[".id"]) for c, a in api.commands
               if c == "/ip/firewall/mangle/remove"]
    assert removed.index("ISP_BILLING_PCC_UNAUTH_GUARD_V2") > max(
        removed.index("ISP_BILLING_PCC_MARK_WAN1"), removed.index("ISP_BILLING_PCC_MARK_WAN2"))
    added = [a["comment"] for c, a in api.commands if c == "/ip/firewall/mangle/add"]
    assert added == _expected_block(2)


def test_failed_add_during_rebuild_leaves_old_block_working():
    api = _router(("ether1", "ether2"))
    mikrotik_lb.lb_apply(api, W2)
    before = [dict(r) for r in api.mangle_rules]
    original = api.send_command

    def flaky(command, arguments=None):
        if (command == "/ip/firewall/mangle/add"
                and (arguments or {}).get("comment") == "ISP_BILLING_PCC_ROUTE_WAN2"):
            return {"error": "simulated failure"}
        return original(command, arguments)

    api.send_command = flaky
    report = mikrotik_lb.lb_apply(api, W3)
    assert report["success"] is False
    assert "previous load-balancing rules were left in place" in report["aborted"]
    assert api.mangle_rules == before


def test_verify_flags_mark_without_route_on_first_packet():
    api = FakeLBAPI(mangle_rules=[
        {".id": "*1", "chain": "prerouting", "action": "mark-routing",
         "connection-mark": "WAN2_conn", "new-routing-mark": "to_wan2",
         "passthrough": "no", "comment": "ISP_BILLING_PCC_ROUTE_WAN2"},
        {".id": "*2", "chain": "prerouting", "action": "mark-connection",
         "connection-mark": "no-mark", "new-connection-mark": "WAN1_conn",
         "per-connection-classifier": "both-addresses:2/0", "passthrough": "yes",
         "comment": "ISP_BILLING_PCC_MARK_WAN1"},
        {".id": "*3", "chain": "prerouting", "action": "mark-connection",
         "connection-mark": "no-mark", "new-connection-mark": "WAN2_conn",
         "per-connection-classifier": "both-addresses:2/1", "passthrough": "yes",
         "comment": "ISP_BILLING_PCC_MARK_WAN2"},
        {".id": "*4", "chain": "prerouting", "action": "mark-routing",
         "connection-mark": "WAN1_conn", "new-routing-mark": "to_wan1",
         "passthrough": "no", "comment": "ISP_BILLING_PCC_ROUTE_WAN1"},
    ])
    report = mikrotik_lb.lb_verify(api, W2)
    assert report["success"] is False
    assert report["pcc_order"]["unrouted"] == ["WAN2"]


def test_verify_without_lb_rules_skips_order_check():
    report = mikrotik_lb.lb_verify(FakeLBAPI())
    assert report["pcc_order"]["wans"] == 0
    assert report["success"] is True


# ---------------------------------------------------------------------------
# 2. unchanged re-apply is a no-op
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ros_version", ["7.15.2", "6.49.21"])
def test_unchanged_two_wan_reapply_writes_nothing(ros_version):
    api = _router(("ether1", "ether2"), ros_version=ros_version)
    first = mikrotik_lb.lb_apply(api, W2)
    assert first["success"] is True
    assert first["mangle_mode"] == "installed"
    api.commands = []

    second = mikrotik_lb.lb_apply(api, W2)
    assert second["success"] is True
    assert second["mangle_mode"] == "unchanged"
    assert api.commands == [], api.commands


def test_reapply_accepts_routeros_printed_booleans():
    """RouterOS prints passthrough as true/false where we wrote yes/no; that
    alone must not count as a change."""
    api = _router()
    mikrotik_lb.lb_apply(api, W2)
    for r in api.mangle_rules:
        if "passthrough" in r:
            r["passthrough"] = {"yes": "true", "no": "false"}[r["passthrough"]]
    api.commands = []
    assert mikrotik_lb.lb_apply(api, W2)["mangle_mode"] == "unchanged"
    assert api.commands == []


# ---------------------------------------------------------------------------
# 3. LB_SRC derived from the router's own subnets
# ---------------------------------------------------------------------------

def _list(api, name):
    return {a["address"]: a.get("comment") for a in api.address_lists if a.get("list") == name}


def test_custom_lan_subnet_ends_up_in_lb_src_and_bypass():
    api = _router(dhcp_networks=[{"address": "172.172.20.0/24", "gateway": "172.172.20.1"}])
    report = mikrotik_lb.lb_apply(api, W2)
    assert report["success"] is True

    src = _list(api, "LB_SRC")
    assert "172.172.10.0/24" in src          # hotspot LAN on the bridge
    assert "172.172.20.0/24" in src          # a DHCP server network
    assert "192.168.89.0/24" in src          # built-in still there
    assert src["172.172.10.0/24"].startswith("ISP_BILLING_LB_SRC")
    # never the management tunnel, never the WAN
    assert not any(a.startswith(("10.0.3.", "41.90.1.")) for a in src)

    bypass = _list(api, "LB_BYPASS_DST")
    assert "172.172.10.0/24" in bypass       # LAN-to-LAN traffic is not balanced
    assert "192.168.89.0/24" not in bypass   # already covered by 192.168.0.0/16


def test_wan_and_tunnel_interfaces_are_never_lan():
    api = FakeLBAPI(
        dhcp_clients=_bound("ether1"),
        ip_addresses=[
            {"address": "172.172.10.1/24", "interface": "bridge"},
            {"address": "100.70.1.20/24", "interface": "ether2"},      # a WAN port
            {"address": "10.10.10.2/30", "interface": "sstp-out1"},    # tunnel
            {"address": "10.9.9.1/24", "interface": "ovpn-x"},         # tunnel
            {"address": "172.30.0.1/24", "interface": "vlan9", "disabled": "true"},
            {"address": "10.0.0.1/8", "interface": "bridge2"},         # too broad
        ],
    )
    nets = [x["network"] for x in mikrotik_lb.lb_lan_subnets(api, W2)]
    assert nets == ["172.172.10.0/24"]


def test_rollback_keeps_hand_added_entries_and_reenable_rederives():
    api = _router(address_lists=[
        # hand-added before this fix (no comment), e.g. a routed downstream LAN
        {".id": "*H1", "list": "LB_SRC", "address": "10.77.0.0/24"},
        # an untagged built-in from an older apply: ours, removed on rollback
        {".id": "*H2", "list": "LB_SRC", "address": "192.168.88.0/24"},
    ])
    mikrotik_lb.lb_apply(api, W2)
    report = mikrotik_lb.lb_rollback(api)
    assert report["success"] is True

    src = _list(api, "LB_SRC")
    assert src == {"10.77.0.0/24": None}
    assert report["address_list_kept"] == [
        {"list": "LB_SRC", "address": "10.77.0.0/24", "comment": ""}]
    assert _list(api, "LB_BYPASS_DST") == {}

    mikrotik_lb.lb_apply(api, W2)
    src = _list(api, "LB_SRC")
    assert {"10.77.0.0/24", "172.172.10.0/24", "192.168.88.0/24"} <= set(src)


def test_rollback_removes_duplicate_rules_left_by_an_interrupted_rebuild():
    api = _router()
    mikrotik_lb.lb_apply(api, W2)
    dup = dict(next(r for r in api.mangle_rules
                    if r["comment"] == "ISP_BILLING_PCC_MARK_WAN1"), **{".id": "*DUP"})
    api.mangle_rules.insert(2, dup)
    assert mikrotik_lb.lb_rollback(api)["success"] is True
    assert _block(api) == []


# ---------------------------------------------------------------------------
# 4. enable flow
# ---------------------------------------------------------------------------

def _run_enable(monkeypatch, api, wans):
    api.connect = lambda: True
    api.disconnect = lambda: None
    monkeypatch.setattr(lbr, "_connect", lambda info, timeout=45: api)
    return lbr._lb_enable_sync({"ip": "x", "username": "u", "password": "p", "port": 8728},
                               wans, [])


def test_enable_with_third_line_does_not_put_working_wan2_in_deadman(monkeypatch):
    api = _router(("ether1", "ether2"))
    mikrotik_lb.lb_apply(api, W2)
    # ether3 is a bridge port with the new line's modem (no clients); ether2 is
    # already a working WAN.
    api.bridge_ports = [{".id": "*B3", "interface": "ether3", "bridge": "bridge"}]
    original = api.send_command

    def bind(command, arguments=None):
        result = original(command, arguments)
        if command == "/ip/dhcp-client/add":
            api.dhcp_clients.append(_bound("ether3")[0])
        return result

    api.send_command = bind
    report = _run_enable(monkeypatch, api, W3)

    assert report["success"] is True, report
    assert report["deadman"]["plan"] and [p["port"] for p in report["deadman"]["plan"]] == ["ether3"]
    assert set(report["converted_ports"]) == {"ether2", "ether3"}
    assert report["verify"]["pcc_order"]["ok"] is True
    assert _block(api) == _expected_block(3)


@pytest.mark.asyncio
async def test_enable_endpoint_reports_failure_when_pcc_order_broken(db, monkeypatch):
    from tests.factories import make_reseller, make_router

    async def _no_availability(*_a, **_k):
        return None

    monkeypatch.setattr(lbr, "record_router_availability", _no_availability)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    result = {
        "success": True,
        "preflight": {"blockers": [], "warnings": [], "per_port": {}},
        "apply": {"steps": [], "success": True}, "convert": {},
        "converted_ports": [], "dormant_ports": [], "seed": {},
        "verify": {"success": False, "warnings": ["PCC rule order: WAN3 never"],
                   "pcc_order": {"ok": False, "unreachable": ["WAN3"], "unrouted": []}},
    }

    async def run(router_obj, sync_func, *args, **kwargs):
        return result

    monkeypatch.setattr(lbr, "_run_locked_router_thread", run)
    resp = await lbr.enable_load_balancing(
        router.id, lbr.LBEnableRequest(wan_ports=W3, confirm=True), db,
        {"user_id": reseller.id, "role": reseller.role.value},
    )
    assert resp["success"] is False
    assert "NOT working for WAN3" in resp["message"]
    assert any("WAN3 never" in w for w in resp["warnings"])

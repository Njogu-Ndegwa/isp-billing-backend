"""Multi-WAN PCC load balancing (hotspot-safe), ported from the bench-certified
skill scripts in .claude/skills/setup-dual-wan-lb/ (certified 2026-08-08 on
router 333).

Every function takes an ALREADY-CONNECTED MikroTikAPI instance and is pure-sync
(callers run them in a thread). Every function returns a step-report dict:

    {"steps": [{"step": name, "ok": bool, "detail": ...}], "success": bool, ...}

Domain rules baked in here (breaking these has killed live captive portals):

1. Mangle prerouting order MUST be UNAUTH_GUARD -> BYPASS -> MARK rules ->
   ROUTE rules. The guard (accept, in-interface=<LAN bridge>, hotspot=!auth,
   src-address-list=!LB_PAID) must exist and precede everything else. Never
   leave MARK/ROUTE rules enabled without the guard.
2. Rollback disables the MARK rules FIRST, then ROUTE rules, then removes
   guard/bypass, then restores fasttrack.
3. Fasttrack filter rules are restricted to connection-mark=no-mark while LB
   is enabled and restored on disable.
4. Recursive checked routes need target-scope=11 (default 10 silently fails).
   Probe routes are interface-qualified (gw%iface).
5. PCC mark rules need connection-state=new and dst-address-type=!local.
6. LB_PAID entries are ALWAYS created WITH a timeout, capped at 21,000,000
   seconds (RouterOS max is 35w3d13:13:56 = 21,475,396s). An LB_PAID entry
   outliving its ip-binding breaks the portal for the next holder of that IP.
7. All router objects are comment-tagged ISP_BILLING_* and idempotent.
"""

import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# --- constants (mirroring the skill scripts) --------------------------------

PROBE_IPS = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222")
MIN_WAN_PORTS = 2
MAX_WAN_PORTS = len(PROBE_IPS)  # 4

LB_SRC_NETWORKS = [
    "192.168.88.0/24", "192.168.89.0/24", "192.168.90.0/24", "192.168.91.0/24",
]
BACKEND_IPS = ["54.91.202.229", "35.170.199.141", "91.98.238.12"]
LB_BYPASS_BASE = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10"]

LB_SRC_LIST = "LB_SRC"
LB_BYPASS_LIST = "LB_BYPASS_DST"
LB_PAID_LIST = "LB_PAID"

LB_PAID_MAX_TIMEOUT_SECONDS = 21_000_000
LB_PAID_MIN_TIMEOUT_SECONDS = 60

GUARD_COMMENT = "ISP_BILLING_PCC_UNAUTH_GUARD_V2"
BYPASS_COMMENT = "ISP_BILLING_PCC_BYPASS"
COMMENT_PREFIX = "ISP_BILLING"

# Settle delays after route/rule writes (tests set these to 0).
LB_APPLY_SETTLE_SECONDS = 6
LB_CONVERT_SETTLE_SECONDS = 8
LB_CONVERT_DHCP_BIND_ATTEMPTS = 20
LB_CONVERT_DHCP_BIND_DELAY_SECONDS = 2


def _mark_comment(index: int) -> str:
    return f"ISP_BILLING_PCC_MARK_WAN{index + 1}"


def _route_comment(index: int) -> str:
    return f"ISP_BILLING_PCC_ROUTE_WAN{index + 1}"


def _table_name(index: int) -> str:
    return f"to_wan{index + 1}"


def _table_route_comment(index: int) -> str:
    return f"ISP_BILLING_PCC_WAN{index + 1}"


def _probe_comment(port: str) -> str:
    return f"ISP_BILLING_DUAL_WAN_{port.upper()}_PROBE"


def _checked_comment(index: int) -> str:
    # Keep the bench-certified names for the dual-WAN case.
    if index == 0:
        return "ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"
    if index == 1:
        return "ISP_BILLING_DUAL_WAN_BACKUP_CHECKED"
    return f"ISP_BILLING_DUAL_WAN_WAN{index + 1}_CHECKED"


def _wan_dhcp_comment(index: int) -> str:
    return f"ISP_BILLING_WAN{index + 1}"


def lb_paid_timeout_seconds(expiry: Any, now: Optional[datetime] = None) -> Optional[int]:
    """Seconds-to-expiry clamped into [60, 21_000_000]. None when expiry unusable."""
    if expiry is None:
        return None
    if isinstance(expiry, str):
        try:
            expiry = datetime.fromisoformat(expiry)
        except ValueError:
            return None
    if not isinstance(expiry, datetime):
        return None
    now = now or datetime.utcnow()
    secs = int((expiry - now).total_seconds())
    return max(LB_PAID_MIN_TIMEOUT_SECONDS, min(LB_PAID_MAX_TIMEOUT_SECONDS, secs))


# --- tiny read/write helpers ------------------------------------------------

def _rd(api, cmd: str, proplist: Optional[list] = None, query: Optional[str] = None) -> list:
    if proplist or query:
        r = api.send_command_optimized(cmd, proplist=proplist, query=query)
    else:
        r = api.send_command(cmd)
    return r.get("data", []) if r.get("success") else []


def _step(report: dict, name: str, ok: bool, detail: Any = None) -> None:
    report["steps"].append({"step": name, "ok": ok, "detail": detail})
    if not ok:
        report["success"] = False


def _wr(api, report: dict, name: str, cmd: str, args: Dict[str, str]) -> bool:
    r = api.send_command(cmd, args)
    ok = bool(r.get("success"))
    _step(report, name, ok, {"cmd": cmd, "args": args} if ok
          else {"cmd": cmd, "args": args, "error": r.get("error")})
    return ok


# --- preflight ---------------------------------------------------------------

def lb_preflight(api, wan_ports: List[str]) -> dict:
    """Read-only preflight, generalized to N WAN ports (wan_ports[0] is WAN1)."""
    report: dict = {"steps": [], "success": True, "blockers": [], "warnings": [],
                    "per_port": {}}
    wan1 = wan_ports[0]

    res = _rd(api, "/system/resource/print")
    ver = res[0].get("version", "?") if res else "?"
    report["version"] = ver
    report["board_free_mem_MB"] = (
        round(int(res[0].get("free-memory", 0)) / 1048576) if res else None
    )
    _step(report, "read.system_resource", bool(res), {"version": ver})
    if not ver.startswith("7"):
        report["blockers"].append(f"RouterOS {ver} is not v7 — this recipe is 7.x only")

    dhcp = _rd(api, "/ip/dhcp-client/print")
    w1 = next((d for d in dhcp if d.get("interface") == wan1), None)
    report["wan1_dhcp"] = {k: (w1 or {}).get(k) for k in ("status", "address", "gateway")}
    if not w1 or w1.get("status") != "bound":
        report["blockers"].append(f"{wan1} has no bound DHCP client — WAN1 must work first")
    _step(report, "read.dhcp_clients", True, report["wan1_dhcp"])

    ifs = _rd(api, "/interface/print", ["name", "running"])
    links = {i.get("name"): i.get("running") for i in ifs if i.get("name") in wan_ports}
    bps = _rd(api, "/interface/bridge/port/print", ["interface", "bridge"])
    fdb = _rd(api, "/interface/bridge/host/print", ["mac-address", "on-interface", "local"])

    for idx, port in enumerate(wan_ports):
        in_bridge = next((p.get("bridge") for p in bps if p.get("interface") == port), None)
        macs = [h.get("mac-address") for h in fdb
                if h.get("on-interface") == port and h.get("local") != "true"]
        existing_dhcp = next((d for d in dhcp if d.get("interface") == port), None)
        info = {
            "wan_index": idx,
            "link": links.get(port),
            "in_bridge": in_bridge,
            "macs_learned": macs,
            "dhcp": {k: (existing_dhcp or {}).get(k) for k in ("status", "address", "gateway")}
            if existing_dhcp else None,
        }
        report["per_port"][port] = info
        if idx > 0 and in_bridge and macs:
            report["blockers"].append(
                f"{len(macs)} client MAC(s) learned on {port} while it is a bridge "
                "port — that port serves customers/devices; converting it disconnects "
                "them. Pick another port or move them."
            )
    _step(report, "read.ports", True, report["per_port"])

    hs = _rd(api, "/ip/hotspot/print")
    report["hotspot"] = [{k: h.get(k) for k in ("name", "interface", "profile", "disabled")}
                         for h in hs]
    if not hs:
        report["warnings"].append("no hotspot server found — LB still works, guard is inert")
    report["lan_bridge"] = hs[0].get("interface") if hs else "bridge"
    _step(report, "read.hotspot", True, {"lan_bridge": report["lan_bridge"]})

    dsn = _rd(api, "/ip/dhcp-server/network/print")
    report["dhcp_dns"] = [{k: n.get(k) for k in ("address", "dns-server")} for n in dsn]
    for n in dsn:
        gw = n.get("gateway") or ""
        if n.get("dns-server") and n.get("dns-server") != gw:
            report["warnings"].append(
                f"DHCP network {n.get('address')} hands out DNS {n.get('dns-server')} "
                f"(not the router {gw}) — fleet standard is router-as-DNS; "
                "hardcoded-public-DNS clients still work but resolve unbalanced"
            )

    ft = _rd(api, "/ip/firewall/filter/print", ["connection-mark", "comment"],
             query="?action=fasttrack-connection")
    report["fasttrack"] = ft

    mangle = _rd(api, "/ip/firewall/mangle/print", ["comment", "disabled"])
    existing = [m for m in mangle if (m.get("comment") or "").startswith(COMMENT_PREFIX)]
    report["existing_pcc_rules"] = existing
    if existing:
        report["warnings"].append(
            "ISP_BILLING rules already present — apply is idempotent, but review "
            "state before re-running"
        )

    report["wg_peers"] = _rd(api, "/interface/wireguard/peers/print",
                             ["interface", "endpoint-address", "last-handshake"])

    if report["blockers"]:
        report["verdict"] = "BLOCKED: " + "; ".join(report["blockers"])
        report["success"] = False
    else:
        report["verdict"] = ("OK to proceed (apply is safe now; convert secondary "
                             "ports after their lines are plugged in)")
    return report


# --- apply -------------------------------------------------------------------

def lb_apply(api, wan_ports: List[str]) -> dict:
    """Install routes, tables, address lists, guard + PCC mangle rules for N WANs.

    Safe to run before the secondary lines exist: a dormant WAN's to_wanX table
    falls back onto the next WAN, so traffic keeps flowing via WAN1.
    """
    report: dict = {"steps": [], "success": True}
    n = len(wan_ports)
    probes = list(PROBE_IPS[:n])

    dhcp = _rd(api, "/ip/dhcp-client/print")
    gateways: Dict[str, Optional[str]] = {}
    for port in wan_ports:
        row = next((d for d in dhcp
                    if d.get("interface") == port and d.get("status") == "bound"), None)
        gateways[port] = row.get("gateway") if row else None
    report["gateways"] = gateways
    if not gateways.get(wan_ports[0]):
        report["aborted"] = f"{wan_ports[0]} not DHCP-bound"
        _step(report, "check.wan1_bound", False, report["aborted"])
        return report
    _step(report, "check.wan1_bound", True, gateways[wan_ports[0]])

    hs = _rd(api, "/ip/hotspot/print")
    lan_bridge = hs[0].get("interface") if hs else "bridge"
    report["lan_bridge"] = lan_bridge

    # 1. routing tables to_wan1..to_wanN (fib)
    tables = {t.get("name") for t in _rd(api, "/routing/table/print")}
    for i in range(n):
        name = _table_name(i)
        if name not in tables:
            _wr(api, report, f"routing_table.add.{name}", "/routing/table/add",
                {"name": name, "fib": ""})

    # 2. routes (idempotent by comment)
    have = {r.get("comment") for r in _rd(api, "/ip/route/print", ["comment"])
            if r.get("comment")}
    route_plan: List[tuple] = []
    for i, port in enumerate(wan_ports):
        gw = gateways.get(port)
        if not gw:
            continue  # dormant WAN: no probe/checked-default yet (convert adds them)
        route_plan.append((
            {"dst-address": probes[i] + "/32", "gateway": gw + "%" + port, "scope": "10"},
            _probe_comment(port),
        ))
        route_plan.append((
            {"dst-address": "0.0.0.0/0", "gateway": probes[i], "distance": str(i + 1),
             "check-gateway": "ping", "target-scope": "11"},
            _checked_comment(i),
        ))
    for i in range(n):
        own = probes[i]
        fallback = probes[(i + 1) % n]
        route_plan.append((
            {"dst-address": "0.0.0.0/0", "gateway": own, "routing-table": _table_name(i),
             "distance": "1", "check-gateway": "ping", "target-scope": "11"},
            _table_route_comment(i),
        ))
        route_plan.append((
            {"dst-address": "0.0.0.0/0", "gateway": fallback,
             "routing-table": _table_name(i), "distance": "2",
             "check-gateway": "ping", "target-scope": "11"},
            _table_route_comment(i) + "_FALLBACK",
        ))

    # 3. management VPN pins: wg-aws -> WAN1, wg-aws2 -> WAN2 (when present),
    #    other endpoints round-robin; each gets a fallback via the next WAN.
    peers = _rd(api, "/interface/wireguard/peers/print",
                ["interface", "endpoint-address", "current-endpoint-address"])
    seen_eps: List[str] = []
    rr_counter = 0
    for p in peers:
        ep = p.get("endpoint-address") or p.get("current-endpoint-address")
        if not ep or ep in seen_eps:
            continue
        seen_eps.append(ep)
        iface = p.get("interface", "wg")
        if iface == "wg-aws":
            widx = 0
        elif iface == "wg-aws2" and n >= 2:
            widx = 1
        else:
            widx = rr_counter % n
            rr_counter += 1
        prim = probes[widx]
        sec = probes[(widx + 1) % n]
        tag = "".join(c for c in iface.upper() if c.isalnum())
        route_plan.append((
            {"dst-address": ep + "/32", "gateway": prim, "distance": "1",
             "check-gateway": "ping", "target-scope": "11"},
            "ISP_BILLING_VPN_PIN_" + tag,
        ))
        route_plan.append((
            {"dst-address": ep + "/32", "gateway": sec, "distance": "2",
             "check-gateway": "ping", "target-scope": "11"},
            "ISP_BILLING_VPN_PIN_" + tag + "_FALLBACK",
        ))

    for args, comment in route_plan:
        if comment in have:
            continue
        args = dict(args)
        args["comment"] = comment
        _wr(api, report, f"route.add.{comment}", "/ip/route/add", args)

    # 4. address lists (LB_SRC + LB_BYPASS_DST incl. backends + live wg endpoints)
    al = _rd(api, "/ip/firewall/address-list/print", ["list", "address"])
    have_al = {(a.get("list"), a.get("address")) for a in al}
    for addr in LB_SRC_NETWORKS:
        if (LB_SRC_LIST, addr) not in have_al:
            _wr(api, report, f"address_list.add.{LB_SRC_LIST}.{addr}",
                "/ip/firewall/address-list/add", {"list": LB_SRC_LIST, "address": addr})
    for addr in LB_BYPASS_BASE + BACKEND_IPS + sorted(seen_eps):
        if (LB_BYPASS_LIST, addr) not in have_al:
            _wr(api, report, f"address_list.add.{LB_BYPASS_LIST}.{addr}",
                "/ip/firewall/address-list/add", {"list": LB_BYPASS_LIST, "address": addr})

    # 5. fasttrack restricted to connection-mark=no-mark (record prior state)
    ft = _rd(api, "/ip/firewall/filter/print", [".id", "connection-mark"],
             query="?action=fasttrack-connection")
    report["fasttrack_prior"] = ft
    for rule in ft:
        if rule.get("connection-mark") != "no-mark":
            _wr(api, report, "fasttrack.restrict", "/ip/firewall/filter/set",
                {".id": rule[".id"], "connection-mark": "no-mark"})

    # 6. mangle: GUARD -> BYPASS -> MARK x N -> ROUTE x N. DO NOT reorder.
    have_m = {m.get("comment") for m in _rd(api, "/ip/firewall/mangle/print", ["comment"])}
    mangle_plan: List[tuple] = [
        (GUARD_COMMENT,
         {"chain": "prerouting", "action": "accept",
          "in-interface": lan_bridge, "hotspot": "!auth",
          "src-address-list": "!" + LB_PAID_LIST}),
        (BYPASS_COMMENT,
         {"chain": "prerouting", "action": "accept",
          "src-address-list": LB_SRC_LIST, "dst-address-list": LB_BYPASS_LIST}),
    ]
    for i in range(n):
        mangle_plan.append((
            _mark_comment(i),
            {"chain": "prerouting", "action": "mark-connection",
             "new-connection-mark": f"WAN{i + 1}_conn", "passthrough": "yes",
             "src-address-list": LB_SRC_LIST, "connection-mark": "no-mark",
             "connection-state": "new", "dst-address-type": "!local",
             "per-connection-classifier": f"both-addresses:{n}/{i}"},
        ))
    for i in range(n):
        mangle_plan.append((
            _route_comment(i),
            {"chain": "prerouting", "action": "mark-routing",
             "new-routing-mark": _table_name(i), "passthrough": "no",
             "src-address-list": LB_SRC_LIST, "connection-mark": f"WAN{i + 1}_conn",
             "dst-address-type": "!local"},
        ))
    for comment, args in mangle_plan:
        if comment in have_m:
            continue
        args = dict(args)
        args["comment"] = comment
        _wr(api, report, f"mangle.add.{comment}", "/ip/firewall/mangle/add", args)

    if LB_APPLY_SETTLE_SECONDS:
        time.sleep(LB_APPLY_SETTLE_SECONDS)
    after = _rd(api, "/ip/route/print",
                ["dst-address", "gateway", "immediate-gw", "routing-table",
                 "distance", "active", "comment"])
    report["routes_after"] = [r for r in after
                              if (r.get("comment") or "").startswith(COMMENT_PREFIX)]
    report["mangle_after"] = _rd(api, "/ip/firewall/mangle/print",
                                 ["comment", "packets", "disabled"])
    return report


# --- convert a bridge port into a secondary WAN ------------------------------

def lb_convert_port(api, port: str, wan_index: int, wan1_port: str = "ether1") -> dict:
    """Pull *port* out of the LAN bridge and turn it into WAN<wan_index+1>.

    Hard aborts: no link; port is a bridge member with learned client MACs.
    """
    report: dict = {"steps": [], "success": True}
    probe = PROBE_IPS[wan_index]

    eth = _rd(api, "/interface/print", ["name", "running"])
    running = next((i.get("running") for i in eth if i.get("name") == port), None)
    if running != "true":
        report["aborted"] = f"{port} has no link — plug the uplink in first"
        _step(report, "check.link", False, report["aborted"])
        return report
    _step(report, "check.link", True)

    fdb = _rd(api, "/interface/bridge/host/print", ["mac-address", "on-interface", "local"])
    client_macs = [h.get("mac-address") for h in fdb
                   if h.get("on-interface") == port and h.get("local") != "true"]
    bridge_ports = _rd(api, "/interface/bridge/port/print", [".id", "interface"])
    in_bridge = any(p.get("interface") == port for p in bridge_ports)
    if in_bridge and client_macs:
        report["aborted"] = (
            f"{len(client_macs)} MAC(s) learned on {port} while it is a bridge "
            f"port: {client_macs[:5]} — it serves devices; move them to another "
            "LAN port first"
        )
        _step(report, "check.bridge_macs", False, report["aborted"])
        return report
    _step(report, "check.bridge_macs", True, {"in_bridge": in_bridge})

    for p in bridge_ports:
        if p.get("interface") == port:
            _wr(api, report, f"bridge_port.remove.{port}",
                "/interface/bridge/port/remove", {".id": p[".id"]})

    dhc = _rd(api, "/ip/dhcp-client/print", [".id", "interface"])
    if not any(d.get("interface") == port for d in dhc):
        _wr(api, report, f"dhcp_client.add.{port}", "/ip/dhcp-client/add",
            {"interface": port, "add-default-route": "no",
             "use-peer-dns": "no", "use-peer-ntp": "no",
             "comment": _wan_dhcp_comment(wan_index)})

    gw = None
    for _ in range(LB_CONVERT_DHCP_BIND_ATTEMPTS):
        if LB_CONVERT_DHCP_BIND_DELAY_SECONDS:
            time.sleep(LB_CONVERT_DHCP_BIND_DELAY_SECONDS)
        row = next((d for d in _rd(api, "/ip/dhcp-client/print")
                    if d.get("interface") == port), None)
        if row and row.get("status") == "bound":
            gw = row.get("gateway")
            report["lease"] = {"address": row.get("address"), "gateway": gw}
            break
    if not gw:
        report["aborted"] = (
            f"{port} DHCP did not bind within "
            f"{LB_CONVERT_DHCP_BIND_ATTEMPTS * LB_CONVERT_DHCP_BIND_DELAY_SECONDS}s — "
            "check the upstream hands out DHCP (fiber ONT in bridge mode needs "
            "PPPoE instead)"
        )
        _step(report, "check.dhcp_bound", False, report["aborted"])
        return report
    _step(report, "check.dhcp_bound", True, report["lease"])

    have = {r.get("comment") for r in _rd(api, "/ip/route/print", ["comment"])
            if r.get("comment")}
    if _probe_comment(port) not in have:
        _wr(api, report, f"route.add.{_probe_comment(port)}", "/ip/route/add",
            {"dst-address": probe + "/32", "gateway": gw + "%" + port,
             "scope": "10", "comment": _probe_comment(port)})
    if _checked_comment(wan_index) not in have:
        _wr(api, report, f"route.add.{_checked_comment(wan_index)}", "/ip/route/add",
            {"dst-address": "0.0.0.0/0", "gateway": probe,
             "distance": str(wan_index + 1), "check-gateway": "ping",
             "target-scope": "11", "comment": _checked_comment(wan_index)})

    # masquerade coverage: mirror WAN1's interface-list membership; else explicit rule
    members = _rd(api, "/interface/list/member/print", [".id", "list", "interface"])
    wan_lists = {m.get("list") for m in members if m.get("interface") == wan1_port}
    covered = False
    for wl in wan_lists:
        if not any(m.get("list") == wl and m.get("interface") == port for m in members):
            _wr(api, report, f"interface_list.add.{wl}.{port}",
                "/interface/list/member/add", {"list": wl, "interface": port})
        covered = True
    if not covered:
        nat = _rd(api, "/ip/firewall/nat/print", ["out-interface", "action", "dynamic"])
        if not any(x.get("action") == "masquerade" and x.get("out-interface") == port
                   for x in nat if x.get("dynamic") != "true"):
            _wr(api, report, f"nat.add.masquerade.{port}", "/ip/firewall/nat/add",
                {"chain": "srcnat", "action": "masquerade", "out-interface": port,
                 "comment": f"{_wan_dhcp_comment(wan_index)}_MASQ"})

    if LB_CONVERT_SETTLE_SECONDS:
        time.sleep(LB_CONVERT_SETTLE_SECONDS)
    after = _rd(api, "/ip/route/print", ["dst-address", "immediate-gw", "routing-table",
                                         "distance", "active", "comment"])
    report["active_managed_routes"] = [
        r for r in after
        if (r.get("comment") or "").startswith(COMMENT_PREFIX) and r.get("active") == "true"
    ]
    return report


# --- verify ------------------------------------------------------------------

def lb_verify(api) -> dict:
    """Counters, live conntrack flow attribution, LB_PAID safety cross-check."""
    report: dict = {"steps": [], "success": True, "warnings": []}

    dhcp = _rd(api, "/ip/dhcp-client/print")
    wan_ips: Dict[str, str] = {}
    for d in dhcp:
        if d.get("status") == "bound" and d.get("address"):
            wan_ips[d.get("interface")] = d["address"].split("/")[0]
    report["wan_ips"] = wan_ips
    _step(report, "read.dhcp_clients", True, wan_ips)

    # Map WAN index -> interface via the managed probe routes (gateway "gw%iface").
    routes = _rd(api, "/ip/route/print",
                 ["dst-address", "gateway", "immediate-gw", "routing-table",
                  "active", "comment"])
    index_iface: Dict[int, str] = {}
    for r in routes:
        comment = r.get("comment") or ""
        m = re.fullmatch(r"ISP_BILLING_DUAL_WAN_(.+)_PROBE", comment)
        if not m:
            continue
        gw = r.get("gateway") or ""
        iface = gw.split("%", 1)[1] if "%" in gw else None
        dst = (r.get("dst-address") or "").split("/")[0]
        if iface and dst in PROBE_IPS:
            index_iface[PROBE_IPS.index(dst)] = iface

    mangle = _rd(api, "/ip/firewall/mangle/print", ["comment", "packets", "disabled"])
    counters = {x.get("comment"): {"packets": x.get("packets"), "disabled": x.get("disabled")}
                for x in mangle if (x.get("comment") or "").startswith(COMMENT_PREFIX)}
    report["counters"] = counters
    guard = counters.get(GUARD_COMMENT, {})
    marks_on = any(
        counters.get(c, {}).get("disabled") != "true"
        for c in counters if re.fullmatch(r"ISP_BILLING_PCC_MARK_WAN\d+", c or "")
    )
    if marks_on and (not guard or guard.get("disabled") == "true"):
        report["warnings"].append(
            "CRITICAL: guard disabled/missing while mark rules live — this IS the "
            "portal-killer state; re-enable the guard NOW"
        )
        report["success"] = False

    conns = _rd(api, "/ip/firewall/connection/print")
    attribution: Dict[str, dict] = {}
    known_ips = set(wan_ips.values())
    for c in conns:
        mark = c.get("connection-mark") or ""
        m = re.fullmatch(r"WAN(\d+)_conn", mark)
        if not m:
            continue
        idx = int(m.group(1)) - 1
        bucket = attribution.setdefault(mark, {"correct": 0, "wrong": 0, "unknown": 0})
        rdst = (c.get("reply-dst-address") or "").split(":")[0]
        want = wan_ips.get(index_iface.get(idx, ""), None)
        if want and rdst == want:
            bucket["correct"] += 1
        elif rdst in known_ips:
            bucket["wrong"] += 1
        else:
            bucket["unknown"] += 1
    report["flow_attribution"] = attribution
    report["attribution_note"] = (
        "'wrong' entries are usually connections established before the current "
        "WAN state (srcnat is fixed at birth); judge by FRESH flows only"
    )

    hosts = _rd(api, "/ip/hotspot/host/print",
                ["mac-address", "address", "bypassed", "authorized"])
    report["hosts"] = hosts
    al = _rd(api, "/ip/firewall/address-list/print",
             ["list", "address", "timeout", "comment"])
    paid = [a for a in al if a.get("list") == LB_PAID_LIST]
    report["lb_paid"] = paid
    by_ip = {h.get("address"): h for h in hosts}
    for a in paid:
        h = by_ip.get(a.get("address"))
        if h and h.get("bypassed") != "true" and h.get("authorized") != "true":
            report["warnings"].append(
                f"DANGER: LB_PAID IP {a.get('address')} is held by an UNAUTH host "
                f"({h.get('mac-address')}) — its portal is broken; remove the entry"
            )
            report["success"] = False

    report["active_managed_routes"] = [
        r for r in routes
        if (r.get("comment") or "").startswith(COMMENT_PREFIX) and r.get("active") == "true"
    ]
    report["wg"] = _rd(api, "/interface/wireguard/peers/print",
                       ["interface", "last-handshake"])
    report["reminder"] = (
        "Portal ground truth = a real unauth phone on-site (or watch "
        "customer_payments resume). Counters alone do not prove the portal."
    )
    return report


# --- rollback ----------------------------------------------------------------

def lb_rollback(api) -> dict:
    """Full teardown of the LB state. Ordering is load-bearing:

      1. disable MARK rules   (no NEW connections get marked)
      2. disable ROUTE rules  (existing marks become inert)
      3. remove all ISP_BILLING mangle rules (marks, routes, THEN guard/bypass —
         the guard is only removed after the marks are gone)
      4. restore fasttrack connection-mark=""
      5. remove ISP_BILLING routes, LB address lists, to_wanX routing tables

    Leaves the router on plain WAN1 (its original dynamic DHCP default route).
    Secondary-WAN DHCP clients and interface-list memberships are left in place;
    they are harmless without the routes and make re-enable instant.
    """
    report: dict = {"steps": [], "success": True}

    mangle = _rd(api, "/ip/firewall/mangle/print", [".id", "comment", "disabled"])
    by_comment = {x.get("comment"): x for x in mangle if x.get("comment")}

    def _indexed(pattern: str) -> List[str]:
        found = []
        for comment in by_comment:
            m = re.fullmatch(pattern, comment or "")
            if m:
                found.append((int(m.group(1)), comment))
        return [c for _, c in sorted(found)]

    mark_comments = _indexed(r"ISP_BILLING_PCC_MARK_WAN(\d+)")
    route_comments = _indexed(r"ISP_BILLING_PCC_ROUTE_WAN(\d+)")

    # 1 + 2: disable marks FIRST, then route rules.
    for comment in mark_comments + route_comments:
        row = by_comment[comment]
        if row.get("disabled") == "true":
            _step(report, f"mangle.disable.{comment}", True, "already disabled")
            continue
        _wr(api, report, f"mangle.disable.{comment}", "/ip/firewall/mangle/set",
            {".id": row[".id"], "disabled": "yes"})

    # 3: remove managed mangle rules — marks, routes, then guard/bypass last.
    for comment in mark_comments + route_comments + [GUARD_COMMENT, BYPASS_COMMENT]:
        row = by_comment.get(comment)
        if not row:
            continue
        _wr(api, report, f"mangle.remove.{comment}", "/ip/firewall/mangle/remove",
            {".id": row[".id"]})

    # 4: restore fasttrack.
    ft = _rd(api, "/ip/firewall/filter/print", [".id", "connection-mark"],
             query="?action=fasttrack-connection")
    for rule in ft:
        if rule.get("connection-mark") == "no-mark":
            _wr(api, report, "fasttrack.restore", "/ip/firewall/filter/set",
                {".id": rule[".id"], "connection-mark": ""})

    # 5a: remove LB address-list entries (LB_SRC, LB_BYPASS_DST, LB_PAID).
    al = _rd(api, "/ip/firewall/address-list/print", [".id", "list", "address"])
    for entry in al:
        if entry.get("list") in (LB_SRC_LIST, LB_BYPASS_LIST, LB_PAID_LIST):
            _wr(api, report,
                f"address_list.remove.{entry.get('list')}.{entry.get('address')}",
                "/ip/firewall/address-list/remove", {".id": entry[".id"]})

    # 5b: remove managed routes (probes, checked defaults, to_wan, vpn pins).
    routes = _rd(api, "/ip/route/print", [".id", "comment"])
    for r in routes:
        comment = r.get("comment") or ""
        if comment.startswith(COMMENT_PREFIX):
            _wr(api, report, f"route.remove.{comment}", "/ip/route/remove",
                {".id": r[".id"]})

    # 5c: remove the to_wanX routing tables.
    for t in _rd(api, "/routing/table/print", [".id", "name"]):
        if re.fullmatch(r"to_wan\d+", t.get("name") or ""):
            _wr(api, report, f"routing_table.remove.{t.get('name')}",
                "/routing/table/remove", {".id": t[".id"]})

    report["state"] = ("LB off; router on plain WAN1. Secondary DHCP clients and "
                       "interface-list memberships left in place (harmless).")
    return report


# --- LB_PAID seeding + single-entry helpers ---------------------------------

def lb_seed_paid(api, active_customers: List[dict]) -> dict:
    """Seed LB_PAID from active (paid) customers: [{"mac": ..., "expiry": ...}].

    Only currently-online, BYPASSED hosts are added, always with a timeout of
    seconds-to-expiry clamped into [60, 21_000_000] so entries self-clean and
    can never outlive their binding by more than the clamp window.
    """
    report: dict = {"steps": [], "success": True,
                    "active_customers_with_mac": len(active_customers),
                    "added": [], "skipped": []}
    hosts = _rd(api, "/ip/hotspot/host/print",
                ["mac-address", "address", "bypassed"])
    by_mac = {(h.get("mac-address") or "").upper(): h for h in hosts}
    al = _rd(api, "/ip/firewall/address-list/print", ["list", "address"])
    have = {a.get("address") for a in al if a.get("list") == LB_PAID_LIST}
    now = datetime.utcnow()

    for c in active_customers:
        mac = (c.get("mac") or "").upper()
        if not mac:
            continue
        h = by_mac.get(mac)
        if not h:
            report["skipped"].append({"mac": mac, "why": "not currently online"})
            continue
        if h.get("bypassed") != "true":
            report["skipped"].append({"mac": mac, "why": "host not bypassed (no binding?)"})
            continue
        ip = h.get("address")
        if ip in have:
            report["skipped"].append({"mac": mac, "why": "already in LB_PAID"})
            continue
        secs = lb_paid_timeout_seconds(c.get("expiry"), now=now)
        if secs is None:
            report["skipped"].append({"mac": mac, "why": "no usable expiry"})
            continue
        r = api.send_command("/ip/firewall/address-list/add", {
            "list": LB_PAID_LIST, "address": ip, "timeout": f"{secs}s",
            "comment": f"PAID:{mac}",
        })
        ok = bool(r.get("success"))
        report["added"].append({"mac": mac, "ip": ip, "timeout_s": secs, "ok": ok})
        _step(report, f"lb_paid.add.{ip}", ok,
              None if ok else r.get("error"))
        if ok:
            have.add(ip)
    return report


def lb_add_paid_entry(api, mac_address: str, expiry: Any) -> dict:
    """Best-effort single LB_PAID add for a just-provisioned bypassed customer.

    NEVER raises — a paid customer missing from LB_PAID just doesn't balance,
    which is benign; a provisioning failure over this would not be.
    """
    try:
        mac = (mac_address or "").upper()
        secs = lb_paid_timeout_seconds(expiry)
        if secs is None:
            return {"ok": False, "reason": "no usable expiry"}
        hosts = _rd(api, "/ip/hotspot/host/print",
                    ["mac-address", "address", "bypassed"])
        host = next((h for h in hosts
                     if (h.get("mac-address") or "").upper() == mac), None)
        if not host:
            return {"ok": False, "reason": "hotspot host not found (client offline?)"}
        if host.get("bypassed") != "true":
            return {"ok": False, "reason": "host not bypassed"}
        ip = host.get("address")
        al = _rd(api, "/ip/firewall/address-list/print", ["list", "address"])
        if any(a.get("list") == LB_PAID_LIST and a.get("address") == ip for a in al):
            return {"ok": True, "skipped": "already in LB_PAID", "ip": ip}
        r = api.send_command("/ip/firewall/address-list/add", {
            "list": LB_PAID_LIST, "address": ip, "timeout": f"{secs}s",
            "comment": f"PAID:{mac}",
        })
        if r.get("success"):
            return {"ok": True, "ip": ip, "timeout_s": secs}
        return {"ok": False, "reason": r.get("error") or "add failed"}
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("[LB] lb_add_paid_entry failed for %s: %s", mac_address, exc)
        return {"ok": False, "reason": str(exc)}


def lb_remove_paid_entry(api, client_ip: str) -> dict:
    """Best-effort removal of the LB_PAID entry for *client_ip*. NEVER raises."""
    try:
        if not client_ip:
            return {"ok": False, "reason": "no client ip"}
        al = _rd(api, "/ip/firewall/address-list/print", [".id", "list", "address"])
        removed = 0
        for entry in al:
            if entry.get("list") == LB_PAID_LIST and entry.get("address") == client_ip:
                r = api.send_command("/ip/firewall/address-list/remove",
                                     {".id": entry[".id"]})
                if r.get("success"):
                    removed += 1
        return {"ok": True, "removed": removed}
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("[LB] lb_remove_paid_entry failed for %s: %s", client_ip, exc)
        return {"ok": False, "reason": str(exc)}

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

RouterOS 6 vs 7: the mangle/PCC/guard/fasttrack rules are identical. v6 has no
/routing/table — a route joins a policy table via `routing-mark=` (the table
exists implicitly), where v7 needs the table created first and uses
`routing-table=`. v6 routers carry their management tunnel as SSTP/L2TP (router-
originated, never touched by prerouting mangle) instead of WireGuard peers, so
there are no VPN pins to add there.
"""

import ipaddress
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

SUPPORTED_ROS_MAJORS = (6, 7)
# A secondary line plugged into a port that is still a LAN bridge member shows
# up as learned MAC(s) on that port. We only treat them as the upstream modem
# when there are at most this many and every one holds an address OUTSIDE the
# LAN subnets (a modem keeps its own 192.168.100.1-style IP; customer devices
# lease from the router). Convert still reverts if DHCP then fails to bind.
UPSTREAM_MAX_MACS = 2
LB_CLASSIFY_RETRIES = 3
LB_CLASSIFY_RETRY_DELAY_SECONDS = 3


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


def ros_major(version: Optional[str]) -> Optional[int]:
    """'6.49.21 (long-term)' -> 6; unreadable -> None."""
    m = re.match(r"\s*(\d+)\.", version or "")
    return int(m.group(1)) if m else None


def _read_ros_major(api) -> Optional[int]:
    res = _rd(api, "/system/resource/print")
    return ros_major(res[0].get("version")) if res else None


def _classify_port_macs(api, macs: List[str], lan_bridge: str) -> dict:
    """Split MACs learned on a would-be WAN port into upstream-looking vs clients.

    Upstream-looking = every address we know for the MAC (hotspot host / ARP) is
    outside the LAN bridge's own subnets. A MAC with no known address counts as a
    client (conservative: PPPoE CPEs and silent devices look like that).

    A modem's hotspot-host entry blinks out while it is idle (router 537 lost it
    between preflight and convert), so an inconclusive answer is re-read a few
    times before it counts.
    """
    out = _classify_port_macs_once(api, macs, lan_bridge)
    for _ in range(LB_CLASSIFY_RETRIES):
        if not out["clients"]:
            break
        if LB_CLASSIFY_RETRY_DELAY_SECONDS:
            time.sleep(LB_CLASSIFY_RETRY_DELAY_SECONDS)
        out = _classify_port_macs_once(api, macs, lan_bridge)
    return out


def _classify_port_macs_once(api, macs: List[str], lan_bridge: str) -> dict:
    out: dict = {"upstream": [], "clients": []}
    if not macs:
        return out
    lan_nets = []
    for a in _rd(api, "/ip/address/print", ["address", "interface"]):
        if a.get("interface") != lan_bridge:
            continue
        try:
            lan_nets.append(ipaddress.ip_interface(a.get("address") or "").network)
        except ValueError:
            continue
    known: Dict[str, set] = {}
    # A device with a foreign static IP gets a hotspot 1:1-NAT alias (to-address)
    # inside the LAN, and an ARP entry for that alias on the bridge. The alias is
    # the hotspot's doing, not the device's address — ignore it (router 537's
    # modem: address 192.168.100.1, to-address/ARP 192.168.88.151).
    nat_alias: Dict[str, set] = {}
    for h in _rd(api, "/ip/hotspot/host/print", ["mac-address", "address", "to-address"]):
        mac = (h.get("mac-address") or "").upper()
        if not mac or not h.get("address"):
            continue
        known.setdefault(mac, set()).add(h["address"])
        if h.get("to-address") and h["to-address"] != h["address"]:
            nat_alias.setdefault(mac, set()).add(h["to-address"])
    for row in _rd(api, "/ip/arp/print", ["mac-address", "address"]):
        mac = (row.get("mac-address") or "").upper()
        if mac and row.get("address") and row["address"] not in nat_alias.get(mac, set()):
            known.setdefault(mac, set()).add(row["address"])
    # Anything leasing from our own DHCP server is a LAN client, full stop.
    leased = {(x.get("mac-address") or "").upper()
              for x in _rd(api, "/ip/dhcp-server/lease/print", ["mac-address", "status"])
              if x.get("status") == "bound"}
    for mac in macs:
        if (mac or "").upper() in leased:
            out["clients"].append(mac)
            continue
        ips = set()
        for raw in known.get((mac or "").upper(), set()):
            try:
                ips.add(ipaddress.ip_address(raw))
            except ValueError:
                continue
        foreign = sorted(str(ip) for ip in ips if not any(ip in n for n in lan_nets))
        if lan_nets and ips and len(foreign) == len(ips):
            out["upstream"].append({"mac": mac, "addresses": foreign})
        else:
            out["clients"].append(mac)
    return out


def _port_macs_block(classified: dict) -> bool:
    """True when learned MACs mean the port serves devices (never convert it)."""
    return bool(classified["clients"]) or len(classified["upstream"]) > UPSTREAM_MAX_MACS


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
    major = ros_major(ver) if res else None
    report["ros_major"] = major
    if major is None:
        report["blockers"].append(
            "Could not read the RouterOS version (router slow or unreachable?) — retry"
        )
    elif major not in SUPPORTED_ROS_MAJORS:
        report["blockers"].append(
            f"RouterOS {ver} is not supported — load balancing needs RouterOS 6 or 7"
        )

    hs = _rd(api, "/ip/hotspot/print")
    report["hotspot"] = [{k: h.get(k) for k in ("name", "interface", "profile", "disabled")}
                         for h in hs]
    if not hs:
        report["warnings"].append("no hotspot server found — LB still works, guard is inert")
    report["lan_bridge"] = hs[0].get("interface") if hs else "bridge"
    _step(report, "read.hotspot", True, {"lan_bridge": report["lan_bridge"]})

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
            classified = _classify_port_macs(api, macs, report["lan_bridge"])
            info["upstream_devices"] = classified["upstream"]
            if _port_macs_block(classified):
                report["blockers"].append(
                    f"{len(macs)} client MAC(s) learned on {port} while it is a bridge "
                    "port — that port serves customers/devices; converting it "
                    "disconnects them. Pick another port or move them."
                )
            else:
                seen = ", ".join(f"{u['mac']} ({'/'.join(u['addresses'])})"
                                 for u in classified["upstream"])
                report["warnings"].append(
                    f"{port} is still a LAN port but has what looks like the second "
                    f"line's modem on it: {seen}. Enabling takes {port} out of the "
                    "LAN and puts it back if the modem does not hand out DHCP."
                )
    _step(report, "read.ports", True, report["per_port"])

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


def _fallback_suffix(step: int) -> str:
    if step == 0:
        return ""
    return "_FALLBACK" if step == 1 else f"_FALLBACK{step}"


def _v7_wan_routes(wan_ports: List[str], gateways: Dict[str, Optional[str]],
                   probes: List[str]) -> List[tuple]:
    """v7 probe / checked-default / to_wanX routes (bench-certified shape)."""
    n = len(wan_ports)
    plan: List[tuple] = []
    for i, port in enumerate(wan_ports):
        gw = gateways.get(port)
        if not gw:
            continue  # dormant WAN: no probe/checked-default yet (convert adds them)
        plan.append((
            {"dst-address": probes[i] + "/32", "gateway": gw + "%" + port, "scope": "10"},
            _probe_comment(port),
        ))
        plan.append((
            {"dst-address": "0.0.0.0/0", "gateway": probes[i], "distance": str(i + 1),
             "check-gateway": "ping", "target-scope": "11"},
            _checked_comment(i),
        ))
    for i in range(n):
        # Own probe first, then every OTHER WAN in rotation at increasing distance.
        # A single fallback is sufficient for n=2 (it always lands on the live WAN)
        # but not beyond: with two dormant WANs a 3-WAN table had NO active route,
        # so every flow PCC-marked into it black-holed. Found live on router 247
        # (2026-08-13) between apply and the second/third lines being plugged in.
        for step in range(n):
            plan.append((
                {"dst-address": "0.0.0.0/0", "gateway": probes[(i + step) % n],
                 "routing-table": _table_name(i), "distance": str(step + 1),
                 "check-gateway": "ping", "target-scope": "11"},
                _table_route_comment(i) + _fallback_suffix(step),
            ))
    return plan


# RouterOS 6 routes. Measured on router 537 (6.49.21, 2026-09-30):
#  * a recursive route can NOT resolve through a probe whose gateway is
#    interface-qualified (gw%iface) — it stays "unreachable" whatever the
#    target-scope. Through a plain-gateway probe it resolves at once.
#  * so v6 uses plain-gateway probes (full upstream failover) when every WAN is
#    on its own subnet, and falls back to the classic direct gw%iface routes with
#    check-gateway=ping (failover on modem/cable loss only) when two lines share
#    a subnet — e.g. two ONTs that both answer on 192.168.100.1, where a plain
#    gateway would be ambiguous.
_V6_MANAGED_ROUTE = re.compile(
    r"ISP_BILLING_(DUAL_WAN_.+_PROBE|DUAL_WAN_.+_CHECKED|PCC_WAN\d+(_FALLBACK\d*)?)"
)
_V6_ROUTE_COMPARE = ("dst-address", "gateway", "routing-mark", "distance", "scope",
                     "target-scope", "check-gateway")


def _v6_wan_leases(api, wan_ports: List[str]) -> Dict[str, dict]:
    leases: Dict[str, dict] = {}
    for d in _rd(api, "/ip/dhcp-client/print"):
        port = d.get("interface")
        if port in wan_ports and d.get("status") == "bound" and d.get("gateway"):
            leases[port] = {"gateway": d.get("gateway"), "address": d.get("address")}
    return leases


def _v6_route_plan(wan_ports: List[str], leases: Dict[str, dict]) -> tuple:
    """(mode, [(comment, args)]) for a v6 router, from the current WAN leases."""
    n = len(wan_ports)
    probes = list(PROBE_IPS[:n])
    nets = {}
    for port, lease in leases.items():
        iface = _safe_interface(lease.get("address"))
        if iface:
            nets[port] = iface.network
    bound = list(nets)
    overlap = any(nets[a].overlaps(nets[b])
                  for x, a in enumerate(bound) for b in bound[x + 1:])
    plan: List[tuple] = []
    if not overlap:
        for i, port in enumerate(wan_ports):
            lease = leases.get(port)
            if not lease:
                continue
            plan.append((_probe_comment(port),
                         {"dst-address": probes[i] + "/32", "gateway": lease["gateway"],
                          "scope": "10"}))
            plan.append((_checked_comment(i),
                         {"dst-address": "0.0.0.0/0", "gateway": probes[i],
                          "distance": str(i + 1), "check-gateway": "ping",
                          "target-scope": "10"}))
        for i in range(n):
            for step in range(n):
                plan.append((_table_route_comment(i) + _fallback_suffix(step),
                             {"dst-address": "0.0.0.0/0", "gateway": probes[(i + step) % n],
                              "routing-mark": _table_name(i), "distance": str(step + 1),
                              "check-gateway": "ping", "target-scope": "10"}))
        return "recursive", plan
    for i, port in enumerate(wan_ports):
        lease = leases.get(port)
        if lease:
            plan.append((_checked_comment(i),
                         {"dst-address": "0.0.0.0/0",
                          "gateway": lease["gateway"] + "%" + port,
                          "distance": str(i + 1), "check-gateway": "ping"}))
    for i in range(n):
        for step in range(n):
            port = wan_ports[(i + step) % n]
            lease = leases.get(port)
            if not lease:
                continue
            plan.append((_table_route_comment(i) + _fallback_suffix(step),
                         {"dst-address": "0.0.0.0/0",
                          "gateway": lease["gateway"] + "%" + port,
                          "routing-mark": _table_name(i), "distance": str(step + 1),
                          "check-gateway": "ping"}))
    return "direct", plan


def _v6_reconcile_routes(api, report: dict, wan_ports: List[str]) -> str:
    """Make the router's managed v6 routes match the plan for the current leases.

    Wrong/stale managed routes are removed and re-added; matching ones are left
    alone, so re-running (or converting another port) is cheap and idempotent.
    """
    leases = _v6_wan_leases(api, wan_ports)
    mode, plan = _v6_route_plan(wan_ports, leases)
    wanted = dict(plan)
    existing = _rd(api, "/ip/route/print", [".id", "comment"] + list(_V6_ROUTE_COMPARE))
    for r in existing:
        comment = r.get("comment") or ""
        if not _V6_MANAGED_ROUTE.fullmatch(comment):
            continue
        want = wanted.get(comment)
        if want is not None and all(str(want[k]) == str(r.get(k) or "") for k in want):
            wanted.pop(comment)  # already correct
            continue
        _wr(api, report, f"route.remove.{comment}", "/ip/route/remove", {".id": r[".id"]})
    for comment, args in plan:
        if comment in wanted:
            _wr(api, report, f"route.add.{comment}", "/ip/route/add",
                {**args, "comment": comment})
    report["route_mode"] = mode
    if mode == "direct":
        report.setdefault("warnings", []).append(
            "Two lines share one subnet, so RouterOS 6 routes each line directly "
            "(gw%port). Balancing works; failover reacts to a dead modem or cable but "
            "not to an upstream outage behind a live modem. Give the second modem its "
            "own LAN subnet (e.g. 192.168.101.1) and re-apply for full failover."
        )
    return mode


def _route_proplist(major: Optional[int]) -> List[str]:
    # RouterOS 6 silently drops every property AFTER an unknown name in a
    # .proplist (measured on router 537), so never ask v6 for v7-only fields.
    base = ["dst-address", "gateway", "distance", "active", "comment"]
    if major == 6:
        return base + ["routing-mark", "gateway-status"]
    return base + ["immediate-gw", "routing-table"]


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

    major = _read_ros_major(api)
    report["ros_major"] = major
    if major not in SUPPORTED_ROS_MAJORS:
        report["aborted"] = (
            "could not read the RouterOS version" if major is None
            else f"RouterOS {major}.x is not supported (needs 6 or 7)"
        )
        _step(report, "check.ros_version", False, report["aborted"])
        return report
    _step(report, "check.ros_version", True, major)

    hs = _rd(api, "/ip/hotspot/print")
    lan_bridge = hs[0].get("interface") if hs else "bridge"
    report["lan_bridge"] = lan_bridge

    # 1. routing tables to_wan1..to_wanN (fib). v7 only: on v6 a routing-mark
    #    table exists implicitly as soon as a route carries that mark.
    if major == 7:
        tables = {t.get("name") for t in _rd(api, "/routing/table/print")}
        for i in range(n):
            name = _table_name(i)
            if name not in tables:
                _wr(api, report, f"routing_table.add.{name}", "/routing/table/add",
                    {"name": name, "fib": ""})

    # 2. routes (idempotent by comment). v6 reconciles its own route set (see
    #    _v6_reconcile_routes) after the VPN-pin step, which is v7-only.
    have = {r.get("comment") for r in _rd(api, "/ip/route/print", ["comment"])
            if r.get("comment")}
    route_plan: List[tuple] = []
    if major == 7:
        route_plan.extend(_v7_wan_routes(wan_ports, gateways, probes))

    # 3. management VPN pins: wg-aws -> WAN1, wg-aws2 -> WAN2 (when present),
    #    other endpoints round-robin; each gets a fallback via the next WAN.
    peers = _rd(api, "/interface/wireguard/peers/print",
                ["interface", "endpoint-address", "current-endpoint-address"]) \
        if major == 7 else []
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
    if major == 6:
        _v6_reconcile_routes(api, report, wan_ports)

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
        ok = _wr(api, report, f"mangle.add.{comment}", "/ip/firewall/mangle/add", args)
        if comment == GUARD_COMMENT and not ok:
            # MARK/ROUTE rules without the guard is the portal-killer state.
            report["aborted"] = "unauth guard rule could not be added — no mark rules added"
            return report

    if LB_APPLY_SETTLE_SECONDS:
        time.sleep(LB_APPLY_SETTLE_SECONDS)
    after = _rd(api, "/ip/route/print", _route_proplist(major))
    report["routes_after"] = [r for r in after
                              if (r.get("comment") or "").startswith(COMMENT_PREFIX)]
    report["mangle_after"] = _rd(api, "/ip/firewall/mangle/print",
                                 ["comment", "packets", "disabled"])
    return report


# --- convert a bridge port into a secondary WAN ------------------------------

def lb_convert_port(api, port: str, wan_index: int, wan1_port: str = "ether1",
                    wan_ports: Optional[List[str]] = None) -> dict:
    """Pull *port* out of the LAN bridge and turn it into WAN<wan_index+1>.

    Hard aborts: no link; port is a bridge member with learned client MACs.
    *wan_ports* (all WANs, WAN1 first) lets RouterOS 6 rebuild its whole route
    set; without it the WAN list is taken as [wan1_port, ..., port].
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
    bridge_ports = _rd(api, "/interface/bridge/port/print", [".id", "interface", "bridge"])
    in_bridge = any(p.get("interface") == port for p in bridge_ports)
    upstream_in_lan = False
    if in_bridge and client_macs:
        hs = _rd(api, "/ip/hotspot/print")
        lan_bridge = hs[0].get("interface") if hs else "bridge"
        classified = _classify_port_macs(api, client_macs, lan_bridge)
        if _port_macs_block(classified):
            report["aborted"] = (
                f"{len(client_macs)} MAC(s) learned on {port} while it is a bridge "
                f"port: {client_macs[:5]} — it serves devices; move them to another "
                "LAN port first"
            )
            _step(report, "check.bridge_macs", False, report["aborted"])
            return report
        upstream_in_lan = True
        report["upstream_devices"] = classified["upstream"]
    _step(report, "check.bridge_macs", True,
          {"in_bridge": in_bridge, "upstream_in_lan": upstream_in_lan})

    removed_from: List[str] = []
    for p in bridge_ports:
        if p.get("interface") == port:
            if _wr(api, report, f"bridge_port.remove.{port}",
                   "/interface/bridge/port/remove", {".id": p[".id"]}):
                removed_from.append(p.get("bridge") or "bridge")

    dhc = _rd(api, "/ip/dhcp-client/print", [".id", "interface"])
    added_dhcp = False
    if not any(d.get("interface") == port for d in dhc):
        added_dhcp = _wr(api, report, f"dhcp_client.add.{port}", "/ip/dhcp-client/add",
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
        if upstream_in_lan:
            # We only pulled a port with learned MACs on the strength of the
            # "looks like a modem" heuristic. No lease = not proven; put it back.
            _revert_convert(api, report, port, removed_from, added_dhcp)
        return report
    _step(report, "check.dhcp_bound", True, report["lease"])

    report["warnings"] = []
    lease_if = _safe_interface(report["lease"].get("address"))
    for d in _rd(api, "/ip/dhcp-client/print"):
        if d.get("interface") == port or d.get("status") != "bound":
            continue
        other = _safe_interface(d.get("address"))
        if not (lease_if and other):
            continue
        if lease_if.ip == other.ip:
            report["warnings"].append(
                f"{port} got the same address as {d.get('interface')} "
                f"({lease_if.ip}) — balancing still routes, but change the second "
                "modem's LAN subnet (e.g. 192.168.101.1) to keep the lines apart"
            )
        elif lease_if.network == other.network:
            report["warnings"].append(
                f"{port} and {d.get('interface')} share subnet {lease_if.network} "
                "(both modems use the same LAN range) — works via interface-pinned "
                "gateways; changing the second modem's LAN subnet is cleaner"
            )

    major = _read_ros_major(api)
    if major == 6:
        wans = list(wan_ports) if wan_ports else (
            [wan1_port] + [f"_wan{k + 1}" for k in range(1, wan_index)] + [port])
        _v6_reconcile_routes(api, report, wans)
    else:
        _v7_convert_routes(api, report, port, wan_index, gw, probe)

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
    after = _rd(api, "/ip/route/print", _route_proplist(major))
    report["active_managed_routes"] = [
        r for r in after
        if (r.get("comment") or "").startswith(COMMENT_PREFIX) and r.get("active") == "true"
    ]
    return report


def _v7_convert_routes(api, report: dict, port: str, wan_index: int, gw: str,
                       probe: str) -> None:
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


def _safe_interface(addr: Optional[str]):
    try:
        return ipaddress.ip_interface(addr or "")
    except ValueError:
        return None


def _revert_convert(api, report: dict, port: str, removed_from: List[str],
                    added_dhcp: bool) -> None:
    """Undo a failed convert: drop the DHCP client we added, rejoin the bridge."""
    if added_dhcp:
        for d in _rd(api, "/ip/dhcp-client/print", [".id", "interface", "comment"]):
            if d.get("interface") == port and (d.get("comment") or "").startswith(COMMENT_PREFIX):
                _wr(api, report, f"revert.dhcp_client.remove.{port}",
                    "/ip/dhcp-client/remove", {".id": d[".id"]})
    for bridge in removed_from:
        _wr(api, report, f"revert.bridge_port.add.{port}",
            "/interface/bridge/port/add", {"bridge": bridge, "interface": port})
    report["reverted"] = True


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

    # Map WAN index -> interface via the managed routes: probe routes (v7
    # "gw%iface"; v6 plain gw, matched to its DHCP client) or, in v6 direct mode,
    # each table's own route ("gw%iface").
    major = _read_ros_major(api)
    routes = _rd(api, "/ip/route/print", _route_proplist(major))
    gw_iface = {d.get("gateway"): d.get("interface") for d in dhcp
                if d.get("status") == "bound" and d.get("gateway")}
    index_iface: Dict[int, str] = {}
    for r in routes:
        comment = r.get("comment") or ""
        gw = r.get("gateway") or ""
        iface = gw.split("%", 1)[1] if "%" in gw else None
        if re.fullmatch(r"ISP_BILLING_DUAL_WAN_(.+)_PROBE", comment):
            dst = (r.get("dst-address") or "").split("/")[0]
            iface = iface or gw_iface.get(gw)
            if iface and dst in PROBE_IPS:
                index_iface[PROBE_IPS.index(dst)] = iface
            continue
        m = re.fullmatch(r"ISP_BILLING_PCC_WAN(\d+)", comment)
        if m and iface:
            index_iface.setdefault(int(m.group(1)) - 1, iface)

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

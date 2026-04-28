"""
Dual-mode (PPPoE + Hotspot) port diagnostic.

Walks the same layers our setup_dual_infrastructure() builds, plus
device-specific lookups (ARP / DHCP lease / hotspot host / IP-binding /
active session) and tags every check that the BILLING SYSTEM is the cause
with system_block=True so the operator can see at a glance whether we
(not the customer's hardware/AP/cable) are blocking hotspot.

The function takes an already-connected MikroTikAPI instance.
"""
from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Dict, List, Optional

from app.services.mikrotik_api import (
    DUAL_BRIDGE_IP,
    DUAL_BRIDGE_NAME,
    DUAL_DHCP_SERVER_NAME,
    DUAL_HOTSPOT_NAT_COMMENT,
    DUAL_HOTSPOT_POOL_NAME,
    DUAL_HOTSPOT_POOL_RANGE,
    DUAL_HOTSPOT_PROFILE_NAME,
    DUAL_HOTSPOT_SERVER_NAME,
    MikroTikAPI,
    normalize_mac_address,
)

logger = logging.getLogger(__name__)

OK = "ok"
WARN = "warn"
FAIL = "fail"


def _check(
    category: str,
    name: str,
    status: str,
    detail: str = "",
    fix: Optional[str] = None,
    system_block: bool = False,
) -> Dict[str, Any]:
    return {
        "category": category,
        "name": name,
        "status": status,
        "detail": detail,
        "fix": fix,
        "system_block": system_block,
    }


def _pool_capacity(range_str: str) -> int:
    try:
        start, end = range_str.split("-")
        return int(IPv4Address(end.strip())) - int(IPv4Address(start.strip())) + 1
    except Exception:
        return 0


def diagnose_dual_port(
    api: MikroTikAPI,
    port: Optional[str] = None,
    mac_address: Optional[str] = None,
    customer: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the full layered hotspot diagnostic on a dual-mode port."""
    checks: List[Dict[str, Any]] = []
    system_blocks: List[str] = []

    def push(c: Dict[str, Any]) -> None:
        checks.append(c)
        if c["system_block"] and c["status"] == FAIL:
            system_blocks.append(c["detail"])

    # ----- 1. Router resources -------------------------------------------------
    res = api.get_system_resources()
    if res.get("success"):
        d = res["data"]
        cpu = d.get("cpu_load", 0) or 0
        total = d.get("total_memory", 1) or 1
        free = d.get("free_memory", 0) or 0
        mem_pct = ((total - free) / total * 100) if total else 0
        if cpu > 90:
            push(_check(
                "router", "Router CPU", FAIL,
                f"CPU at {cpu}% — DHCP/hotspot replies are likely being dropped under load.",
                "Find what's loading the router (/tool/profile); enable FastTrack; reboot if needed.",
            ))
        elif cpu > 70:
            push(_check("router", "Router CPU", WARN, f"CPU elevated at {cpu}%"))
        else:
            push(_check("router", "Router resources", OK, f"CPU {cpu}% / RAM {mem_pct:.0f}%"))
    else:
        push(_check("router", "Router resources", WARN,
                    f"Could not read /system/resource: {res.get('error')}"))

    # Connection-tracking (full table => silent traffic loss for new flows)
    ct = api.send_command("/ip/firewall/connection/tracking/print")
    if ct.get("success") and ct.get("data"):
        s = ct["data"][0]
        try:
            total = int(s.get("total-entries", 0) or 0)
            limit = int(s.get("max-entries", 0) or 0)
        except ValueError:
            total, limit = 0, 0
        if limit and total / limit > 0.95:
            push(_check(
                "router", "Connection tracking", FAIL,
                f"conntrack {total}/{limit} ({total/limit:.0%}) — new TCP/UDP flows are being dropped.",
                "/ip/firewall/connection/tracking/set max-entries=131072",
            ))
        elif limit and total / limit > 0.8:
            push(_check("router", "Connection tracking", WARN, f"conntrack {total}/{limit}"))

    # ----- 2. Bridge layout ---------------------------------------------------
    bd = api.get_bridge_ports_status()
    bridges = bd.get("bridges", {}) if bd.get("success") else {}
    port_map: Dict[str, Dict[str, Any]] = {
        p["interface"]: p for p in bd.get("ports", [])
    } if bd.get("success") else {}

    dbr = bridges.get(DUAL_BRIDGE_NAME)
    if not dbr:
        push(_check(
            "dual-bridge", f"Bridge {DUAL_BRIDGE_NAME}", FAIL,
            f"Bridge '{DUAL_BRIDGE_NAME}' is missing — dual-mode infrastructure was never set up or was wiped.",
            f"Re-apply: PUT /api/routers/<id>/dual-ports",
            system_block=True,
        ))
    elif dbr["disabled"]:
        push(_check(
            "dual-bridge", f"Bridge {DUAL_BRIDGE_NAME}", FAIL,
            f"Bridge '{DUAL_BRIDGE_NAME}' is administratively disabled.",
            f"/interface/bridge/enable {DUAL_BRIDGE_NAME}",
            system_block=True,
        ))
    elif not dbr["running"]:
        push(_check(
            "dual-bridge", f"Bridge {DUAL_BRIDGE_NAME}", WARN,
            "Bridge exists but is not running (no member port has link).",
        ))
    else:
        push(_check("dual-bridge", f"Bridge {DUAL_BRIDGE_NAME}", OK, "up & running"))

    # ----- 2b. Port membership + physical link --------------------------------
    if port:
        pinfo = port_map.get(port)
        if not pinfo:
            push(_check(
                "port", f"Port {port}", FAIL,
                f"{port} is not a member of any bridge — hotspot traffic cannot reach the dual hotspot.",
                f"Re-apply dual-ports config so {port} joins '{DUAL_BRIDGE_NAME}'.",
                system_block=True,
            ))
        elif pinfo["bridge"] != DUAL_BRIDGE_NAME:
            push(_check(
                "port", f"Port {port}", FAIL,
                f"{port} is in bridge '{pinfo['bridge']}' but should be in '{DUAL_BRIDGE_NAME}'. "
                f"Hotspot DHCP/captive portal lives on the dual bridge — clients on this port can't reach it.",
                "Re-apply dual-ports config.",
                system_block=True,
            ))
        elif pinfo["disabled"]:
            push(_check(
                "port", f"Port {port}", FAIL,
                f"Bridge port {port} is disabled.",
                f"/interface/bridge/port/enable [find interface={port}]",
                system_block=True,
            ))
        else:
            status = pinfo.get("status") or ""
            if status and status not in ("active",):
                push(_check("port", f"Port {port}", WARN,
                            f"Bridge-port status is '{status}' (expected 'active')."))
            else:
                push(_check("port", f"Port {port}", OK, f"member of {DUAL_BRIDGE_NAME}, active"))

        ifs = api.send_command_optimized(
            "/interface/print",
            proplist=["name", "running", "disabled", "type",
                      "rx-byte", "tx-byte", "last-link-up-time", "last-link-down-time"],
            query=f"?name={port}",
        )
        if ifs.get("success") and ifs.get("data"):
            ip_iface = ifs["data"][0]
            if ip_iface.get("disabled") == "true":
                push(_check(
                    "port", f"Interface {port}", FAIL,
                    f"{port} is administratively disabled on the router.",
                    f"/interface/enable {port}",
                    system_block=True,
                ))
            elif ip_iface.get("running") != "true":
                last_down = ip_iface.get("last-link-down-time", "?")
                push(_check(
                    "port", f"Link {port}", FAIL,
                    f"No physical link on {port} (last down: {last_down}). "
                    f"This matches the customer's report of 'no Wi-Fi' — the AP/CPE plugged into {port} is OFF or the cable is broken.",
                    f"Power-cycle the access point on {port}; check the patch cable.",
                ))
            else:
                push(_check("port", f"Link {port}", OK, "physical link up"))
        else:
            push(_check("port", f"Interface {port}", WARN,
                        f"Could not read interface state: {ifs.get('error')}"))

    # ----- 3. Bridge IP address -----------------------------------------------
    addrs = api.send_command_optimized(
        "/ip/address/print",
        proplist=["address", "interface", "disabled"],
        query=f"?interface={DUAL_BRIDGE_NAME}",
    )
    expected_gw = DUAL_BRIDGE_IP.split("/")[0]
    has_addr = False
    if addrs.get("success"):
        for a in addrs.get("data", []):
            if a.get("disabled") == "true":
                continue
            if a.get("address", "").split("/")[0] == expected_gw:
                has_addr = True
                break
    if has_addr:
        push(_check("dual-bridge", f"Address {DUAL_BRIDGE_IP}", OK))
    else:
        push(_check(
            "dual-bridge", f"Address {DUAL_BRIDGE_IP}", FAIL,
            f"{DUAL_BRIDGE_IP} is missing or disabled on '{DUAL_BRIDGE_NAME}'. "
            "Hotspot clients have no gateway and DHCP cannot answer.",
            "Re-run dual-mode setup.",
            system_block=True,
        ))

    # ----- 4. Dual DHCP server ------------------------------------------------
    dhcp_ok = False
    dhcp = api.send_command_optimized(
        "/ip/dhcp-server/print",
        proplist=["name", "interface", "address-pool", "disabled", "invalid"],
    )
    matched = False
    if dhcp.get("success"):
        for s in dhcp.get("data", []):
            if s.get("name") != DUAL_DHCP_SERVER_NAME:
                continue
            matched = True
            if s.get("disabled") == "true":
                push(_check(
                    "dhcp", DUAL_DHCP_SERVER_NAME, FAIL,
                    "DHCP server is DISABLED — hotspot devices on this port will never get an IP.",
                    f"/ip/dhcp-server/enable [find name={DUAL_DHCP_SERVER_NAME}]",
                    system_block=True,
                ))
            elif s.get("invalid") == "true":
                push(_check(
                    "dhcp", DUAL_DHCP_SERVER_NAME, FAIL,
                    "DHCP server is marked invalid (likely its bound interface is missing).",
                    "Re-run dual-mode setup.",
                    system_block=True,
                ))
            elif s.get("interface") != DUAL_BRIDGE_NAME:
                push(_check(
                    "dhcp", DUAL_DHCP_SERVER_NAME, FAIL,
                    f"DHCP bound to '{s.get('interface')}' not '{DUAL_BRIDGE_NAME}'.",
                    "Re-run dual-mode setup.",
                    system_block=True,
                ))
            elif s.get("address-pool") != DUAL_HOTSPOT_POOL_NAME:
                push(_check(
                    "dhcp", DUAL_DHCP_SERVER_NAME, FAIL,
                    f"DHCP uses pool '{s.get('address-pool')}' not '{DUAL_HOTSPOT_POOL_NAME}'.",
                    "Re-run dual-mode setup.",
                    system_block=True,
                ))
            else:
                dhcp_ok = True
                push(_check("dhcp", DUAL_DHCP_SERVER_NAME, OK, "running on dual bridge"))
            break
    if not matched and dhcp.get("success"):
        push(_check(
            "dhcp", DUAL_DHCP_SERVER_NAME, FAIL,
            f"DHCP server '{DUAL_DHCP_SERVER_NAME}' does not exist on the router.",
            "Re-run dual-mode setup.",
            system_block=True,
        ))
    elif not dhcp.get("success"):
        push(_check("dhcp", "DHCP servers", WARN,
                    f"Could not list DHCP servers: {dhcp.get('error')}"))

    if dhcp_ok:
        used = api.send_command_optimized(
            "/ip/pool/used/print",
            proplist=["pool", "address", "mac-address", "info"],
            query=f"?pool={DUAL_HOTSPOT_POOL_NAME}",
        )
        used_count = len(used.get("data", [])) if used.get("success") else 0
        capacity = _pool_capacity(DUAL_HOTSPOT_POOL_RANGE) or 253
        if capacity and used_count / capacity > 0.95:
            push(_check(
                "dhcp", "DHCP pool capacity", FAIL,
                f"Pool '{DUAL_HOTSPOT_POOL_NAME}' is {used_count}/{capacity} used — exhausted, new clients can't get an IP.",
                "Expand DUAL_HOTSPOT_POOL_RANGE or shorten lease-time.",
                system_block=True,
            ))
        elif capacity and used_count / capacity > 0.8:
            push(_check("dhcp", "DHCP pool capacity", WARN, f"{used_count}/{capacity} used"))
        else:
            push(_check("dhcp", "DHCP pool capacity", OK, f"{used_count}/{capacity} used"))

    # ----- 5. Hotspot profile + server ----------------------------------------
    hp = api.send_command_optimized(
        "/ip/hotspot/profile/print",
        proplist=["name", "hotspot-address", "dns-name", "dns-server", "login-by"],
        query=f"?name={DUAL_HOTSPOT_PROFILE_NAME}",
    )
    if hp.get("success") and hp.get("data"):
        prof = hp["data"][0]
        if prof.get("hotspot-address", "").split("/")[0] != expected_gw:
            push(_check("hotspot", "Profile address", WARN,
                        f"hotspot-address={prof.get('hotspot-address')} expected {expected_gw}"))
        else:
            push(_check("hotspot", DUAL_HOTSPOT_PROFILE_NAME, OK))
    else:
        push(_check(
            "hotspot", DUAL_HOTSPOT_PROFILE_NAME, FAIL,
            f"Hotspot profile '{DUAL_HOTSPOT_PROFILE_NAME}' is missing.",
            "Re-run dual-mode setup.",
            system_block=True,
        ))

    hs = api.send_command_optimized(
        "/ip/hotspot/print",
        proplist=["name", "interface", "profile", "disabled", "invalid"],
        query=f"?name={DUAL_HOTSPOT_SERVER_NAME}",
    )
    if hs.get("success") and hs.get("data"):
        s = hs["data"][0]
        if s.get("disabled") == "true":
            push(_check(
                "hotspot", DUAL_HOTSPOT_SERVER_NAME, FAIL,
                "Hotspot server is DISABLED — captive portal is not served on this port.",
                f"/ip/hotspot/enable [find name={DUAL_HOTSPOT_SERVER_NAME}]",
                system_block=True,
            ))
        elif s.get("invalid") == "true":
            push(_check(
                "hotspot", DUAL_HOTSPOT_SERVER_NAME, FAIL,
                "Hotspot server is marked invalid (interface or profile missing).",
                "Re-run dual-mode setup.",
                system_block=True,
            ))
        elif s.get("interface") != DUAL_BRIDGE_NAME:
            push(_check(
                "hotspot", DUAL_HOTSPOT_SERVER_NAME, FAIL,
                f"Hotspot bound to '{s.get('interface')}' not '{DUAL_BRIDGE_NAME}'.",
                "Re-run dual-mode setup.",
                system_block=True,
            ))
        else:
            push(_check("hotspot", DUAL_HOTSPOT_SERVER_NAME, OK))
    else:
        push(_check(
            "hotspot", DUAL_HOTSPOT_SERVER_NAME, FAIL,
            f"Hotspot server '{DUAL_HOTSPOT_SERVER_NAME}' is missing.",
            "Re-run dual-mode setup.",
            system_block=True,
        ))

    # ----- 6. NAT -------------------------------------------------------------
    nat = api.send_command_optimized(
        "/ip/firewall/nat/print",
        proplist=["chain", "src-address", "out-interface", "action", "disabled", "comment"],
    )
    nat_ok = False
    if nat.get("success"):
        dual_subnet_prefix = expected_gw.rsplit(".", 1)[0]  # 192.168.91
        for r in nat.get("data", []):
            if r.get("comment") == DUAL_HOTSPOT_NAT_COMMENT and r.get("disabled") != "true" \
                    and r.get("action") == "masquerade":
                nat_ok = True
                break
            if (r.get("disabled") != "true"
                    and r.get("action") == "masquerade"
                    and r.get("src-address", "").startswith(dual_subnet_prefix)):
                nat_ok = True
                break
    if nat_ok:
        push(_check("nat", "Dual hotspot masquerade", OK))
    else:
        push(_check(
            "nat", "Dual hotspot masquerade", FAIL,
            f"Masquerade NAT for the dual hotspot subnet is missing or disabled "
            f"(comment '{DUAL_HOTSPOT_NAT_COMMENT}'). Clients will get an IP and pass the captive portal but have no internet.",
            "Re-run dual-mode setup.",
            system_block=True,
        ))

    # ----- 7. PPPoE coexistence on dual bridge --------------------------------
    pppoe = api.send_command_optimized(
        "/interface/pppoe-server/server/print",
        proplist=["service-name", "interface", "disabled"],
        query=f"?interface={DUAL_BRIDGE_NAME}",
    )
    if pppoe.get("success") and any(p.get("disabled") != "true" for p in pppoe.get("data", [])):
        push(_check("pppoe", "PPPoE on dual bridge", OK,
                    f"PPPoE server bound to '{DUAL_BRIDGE_NAME}' (PPPoE side ok)"))
    else:
        push(_check(
            "pppoe", "PPPoE on dual bridge", WARN,
            f"No active PPPoE server on '{DUAL_BRIDGE_NAME}'. If PPPoE works for the customer, "
            "they're attaching via a different bridge — confirm port assignment.",
        ))

    # ----- 8. WAN -------------------------------------------------------------
    wan = api.send_command_optimized(
        "/interface/print",
        proplist=["name", "running", "disabled"],
        query="?name=ether1",
    )
    if wan.get("success") and wan.get("data"):
        w = wan["data"][0]
        if w.get("disabled") == "true":
            push(_check("wan", "WAN ether1", FAIL, "ether1 is disabled — no upstream internet."))
        elif w.get("running") != "true":
            push(_check("wan", "WAN ether1", FAIL, "ether1 is not running — no upstream internet."))
        else:
            push(_check("wan", "WAN ether1", OK))

    # ----- 9. Device-specific (MAC) -------------------------------------------
    if mac_address:
        norm = normalize_mac_address(mac_address)

        arp = api.get_arp_minimal()
        arp_hit = None
        if arp.get("success"):
            for e in arp.get("data", []):
                if normalize_mac_address(e.get("mac-address", "") or "00:00:00:00:00:00") == norm:
                    arp_hit = e
                    break
        if arp_hit:
            push(_check(
                "device", f"ARP {norm}", OK,
                f"router sees device at {arp_hit.get('address')} on {arp_hit.get('interface')}",
            ))
            iface = arp_hit.get("interface", "")
            if iface and iface not in (DUAL_BRIDGE_NAME, port or ""):
                push(_check(
                    "device", "Device interface", WARN,
                    f"Device is reaching the router via '{iface}', not the dual bridge — wired to wrong port?",
                ))
        else:
            push(_check(
                "device", f"ARP {norm}", FAIL,
                "Router has NEVER seen this MAC. The device cannot reach the router at L2 — "
                "consistent with 'no Wi-Fi shown': the AP is off, mis-cabled, or the customer is connecting "
                "to a different SSID. Not a billing-system problem.",
            ))

        leases = api.get_dhcp_leases_minimal()
        lease_hit = None
        if leases.get("success"):
            for l in leases.get("data", []):
                if normalize_mac_address(l.get("mac-address", "") or "00:00:00:00:00:00") == norm:
                    lease_hit = l
                    break
        if lease_hit:
            on_dual = lease_hit.get("server") == DUAL_DHCP_SERVER_NAME
            status = lease_hit.get("status", "")
            level = OK if (status == "bound" and on_dual) else WARN
            push(_check(
                "device", "DHCP lease", level,
                f"address={lease_hit.get('address')} status='{status}' server='{lease_hit.get('server')}'",
            ))
        else:
            push(_check(
                "device", "DHCP lease", WARN,
                "No DHCP lease for this MAC. Either device never asked, DHCP refused, or device is on PPPoE only.",
            ))

        hosts = api.get_hotspot_hosts_minimal()
        host_hit = None
        if hosts.get("success"):
            for h in hosts.get("data", []):
                if normalize_mac_address(h.get("mac-address", "") or "00:00:00:00:00:00") == norm:
                    host_hit = h
                    break
        if host_hit:
            authorized = host_hit.get("authorized") == "true"
            bypassed = host_hit.get("bypassed") == "true"
            push(_check(
                "device", "Hotspot host", OK,
                f"address={host_hit.get('address')} authorized={authorized} bypassed={bypassed}",
            ))
        else:
            push(_check(
                "device", "Hotspot host", WARN,
                "No hotspot host record — device never reached the hotspot interceptor on this router.",
            ))

        ipb = api.get_ip_binding_by_mac(norm)
        if ipb.get("success") and ipb.get("found"):
            t = (ipb["data"].get("type") or "").lower()
            comment = ipb["data"].get("comment", "")
            if t == "blocked":
                push(_check(
                    "device", "IP binding", FAIL,
                    f"ip-binding type=BLOCKED for {norm} (comment '{comment}'). "
                    "Our system / a previous admin action is actively blocking this device.",
                    f"Remove or change type: /ip/hotspot/ip-binding/remove [find mac-address={norm}]",
                    system_block=True,
                ))
            else:
                push(_check("device", "IP binding", OK, f"type='{t}' comment='{comment}'"))
        else:
            push(_check("device", "IP binding", OK,
                        "no ip-binding for this MAC (would hit captive portal as guest)"))

        active = api.get_hotspot_active_minimal()
        active_hit = None
        if active.get("success"):
            for s in active.get("data", []):
                if normalize_mac_address(s.get("mac-address", "") or "00:00:00:00:00:00") == norm:
                    active_hit = s
                    break
        if active_hit:
            push(_check(
                "device", "Active hotspot session", OK,
                f"user={active_hit.get('user')} addr={active_hit.get('address')} uptime={active_hit.get('uptime')}",
            ))

        queues = api.get_simple_queues_minimal()
        if queues.get("success"):
            for q in queues.get("data", []):
                if q.get("disabled") == "true":
                    continue
                target = q.get("target", "")
                ml = q.get("max-limit", "0/0")
                if lease_hit and lease_hit.get("address") and lease_hit["address"] in target:
                    if ml.startswith("0/0") is False:
                        push(_check(
                            "device", f"Simple queue {q.get('name')}", OK,
                            f"target={target} max-limit={ml} (FUP/throttle applied by us)",
                        ))

    # ----- 10. Customer DB context -------------------------------------------
    if customer:
        plan = customer.get("plan") or {}
        ctype = (plan.get("connection_type") or "").lower()
        status_value = (customer.get("status") or "").lower()
        expiry = customer.get("expiry")
        expired = bool(expiry) and expiry < datetime.utcnow()
        info = (
            f"name={customer.get('name')} status={status_value} expiry={expiry} "
            f"plan={plan.get('name')} type={ctype}"
        )

        if status_value and status_value != "active":
            push(_check(
                "billing", "Customer status", FAIL,
                f"Customer status is '{status_value}' in our DB — provisioning won't run.",
                "Verify payment / activate the customer.",
                system_block=True,
            ))
        elif expired:
            push(_check(
                "billing", "Customer expiry", FAIL,
                f"Plan expired at {expiry}. Our scheduler removes the user from MikroTik on expiry.",
                "Renew the plan.",
                system_block=True,
            ))
        else:
            push(_check("billing", "Customer", OK, info))

        if ctype == "pppoe" and not customer.get("mac_address"):
            push(_check(
                "billing", "Customer connection type", WARN,
                "Customer's plan is PPPoE-only — our system will not auto-provision a hotspot bypass for this MAC.",
            ))

    fails = [c for c in checks if c["status"] == FAIL]
    warns = [c for c in checks if c["status"] == WARN]
    verdict = FAIL if fails else (WARN if warns else OK)

    if fails:
        first_block = next((c for c in fails if c["system_block"]), None)
        headline = (first_block or fails[0])["detail"]
    elif warns:
        headline = warns[0]["detail"]
    else:
        headline = "Dual-port hotspot infrastructure looks healthy."

    return {
        "verdict": verdict,
        "headline": headline,
        "system_blocks": system_blocks,
        "summary": {
            "ok": len([c for c in checks if c["status"] == OK]),
            "warn": len(warns),
            "fail": len(fails),
            "total": len(checks),
        },
        "checks": checks,
    }

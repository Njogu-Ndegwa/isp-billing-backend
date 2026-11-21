"""A router check-up: the known faults of a customer's MikroTik, each with its tested fix.

The assistant reads this when a reseller says a router or its hotspot misbehaves
("connected, no internet", "the login page doesn't show", "people browse without
paying"). One RouterOS connection, read-only, a few seconds. Every finding names the
action that repairs it (an existing endpoint the person confirms in the chat), or
says what only someone at the site can do. The assistant never writes RouterOS
commands of its own: the fixes are the ones Bitwave has proven on the fleet
(see the diagnose-customer-router, hotspot-bypass-fix and rogue-dhcp-hotspot notes).
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Optional

from app.services.provisioning import (
    HOTSPOT_SUBNET, PORTAL_ALLOW_COMMENT, PORTAL_ALLOW_LIST, PROXY_RELAY_BLOCK_COMMENT, PROXY_RELAY_PORTS,
)

_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def _rows(result: Any) -> list[dict]:
    if isinstance(result, dict) and result.get("success") and isinstance(result.get("data"), list):
        return [r for r in result["data"] if isinstance(r, dict)]
    return []


def _yes(v: Any) -> bool:
    return str(v).lower() in ("true", "yes")


def _router_date(clock: dict) -> Optional[datetime]:
    """RouterOS 6 says "nov/21/2026", RouterOS 7 says "2026-11-21"."""
    raw = str(clock.get("date") or "").strip().lower()
    m = re.match(r"^([a-z]{3})/(\d{1,2})/(\d{4})$", raw)
    try:
        if m and m.group(1) in _MONTHS:
            return datetime(int(m.group(3)), _MONTHS[m.group(1)], int(m.group(2)), tzinfo=timezone.utc)
        if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
            return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return None


def finding(code: str, severity: str, title: str, detail: str, *, fix: Optional[dict] = None,
            advice: Optional[str] = None) -> dict:
    out = {"code": code, "severity": severity, "title": title, "detail": detail}
    if fix:
        out["fix"] = fix
    if advice:
        out["advice"] = advice
    return out


def check(api, router_id: int, now: Optional[datetime] = None) -> dict:
    """Run the checks on a connected MikroTikAPI. Never changes anything on the router."""
    now = now or datetime.now(timezone.utc)
    found: list[dict] = []
    checked: list[str] = []

    # 1. does the router itself reach the internet (its WAN line)?
    ping = api.send_command("/ping", {"address": "8.8.8.8", "count": "3"})
    rows = _rows(ping)
    counts = [int(r["received"]) for r in rows if str(r.get("received", "")).isdigit()]
    received = max(counts) if counts else sum(1 for r in rows if r.get("time"))
    checked.append("internet line")
    if rows and received == 0:
        found.append(finding(
            "wan_down", "bad", "The router has no internet on its WAN line",
            "It could not ping 8.8.8.8, so no customer can browse whatever the hotspot does.",
            advice="Check the internet cable in port 1 and the line from the provider (modem lights, data bundle). "
                   "Restarting the router does not fix a dead line."))

    # 2. is its clock right? A wrong date breaks HTTPS fetches and the login page
    clock = (_rows(api.send_command("/system/clock/print")) or [{}])[0]
    checked.append("clock")
    date = _router_date(clock)
    if date is not None and abs((date - now.replace(hour=0, minute=0, second=0, microsecond=0)).days) > 1:
        found.append(finding(
            "clock_wrong", "warn", "The router's date is wrong",
            f"It thinks today is {clock.get('date')}. Secure downloads and the login page can fail.",
            advice="Set it under System > Clock in Winbox, or turn on SNTP (System > SNTP Client) so it keeps the time."))

    # 3. the hotspot: a server that is on, its login page in place
    servers = _rows(api.send_command("/ip/hotspot/print"))
    checked.append("hotspot")
    if servers:
        off = [s for s in servers if _yes(s.get("disabled"))]
        if off and len(off) == len(servers):
            found.append(finding(
                "hotspot_disabled", "bad", "The hotspot is switched off",
                f"Hotspot server {off[0].get('name')} is disabled, so nobody is sent to the login page.",
                advice="Turn it back on under IP > Hotspot in Winbox (select it and press the tick)."))
        profiles = _rows(api.send_command("/ip/hotspot/profile/print"))
        in_use = {s.get("profile") for s in servers}
        dirs = {(p.get("html-directory") or "").strip("/") for p in profiles if p.get("name") in in_use}
        files = _rows(api.send_command("/file/print"))
        names = {str(f.get("name") or "").strip("/") for f in files}
        missing = [d for d in dirs if d and f"{d}/login.html" not in names]
        if missing:
            found.append(finding(
                "login_page_missing", "bad", "The hotspot's login page is missing",
                "The hotspot points at a folder with no login.html, so phones connect but never see the Bitwave page.",
                fix={"method": "POST", "path": f"/api/routers/{router_id}/remediate-captive-portal",
                     "summary": "Put the Bitwave login page back on the router"}))

        # 4. the open-proxy bypass (HTTP Injector): the relay block must be there
        rules = _rows(api.send_command("/ip/firewall/filter/print"))
        checked.append("hotspot bypass protection")
        if not any(str(r.get("comment") or "") == PROXY_RELAY_BLOCK_COMMENT for r in rules):
            found.append(finding(
                "proxy_bypass_open", "warn", "The hotspot can be bypassed without paying",
                "The router's web proxy is open as a relay, which apps like HTTP Injector use to browse without "
                "paying. Bitwave's block rule is not on this router.",
                fix={"method": "POST", "path": f"/api/routers/{router_id}/anti-bypass",
                     "summary": "Close the hotspot proxy bypass (HTTP Injector)"}))

        # 5. devices let through without paying (stale bypassed bindings)
        bindings = _rows(api.send_command("/ip/hotspot/ip-binding/print"))
        bypassed = [b for b in bindings if str(b.get("type")) == "bypassed" and not _yes(b.get("disabled"))]
        if len(bypassed) >= 1:
            found.append(finding(
                "bypassed_devices", "info", f"{len(bypassed)} devices skip the login page",
                "Bypassed devices browse without paying. Some are meant to (an access point, a staff phone); "
                "the cleanup removes only those that belong to no paying customer.",
                fix={"method": "POST", "path": f"/api/routers/{router_id}/cleanup-bypassing",
                     "summary": "Remove bypassed devices that belong to no paying customer"}))

    # 6. a second DHCP server on the hotspot network (a customer's router plugged in backwards)
    alerts = _rows(api.send_command("/ip/dhcp-server/alert/print"))
    rogue = [a for a in alerts if a.get("unknown-server") and str(a.get("unknown-server")).strip()]
    checked.append("rogue DHCP")
    if rogue:
        found.append(finding(
            "rogue_dhcp", "bad", "Another router is handing out addresses on the hotspot",
            f"A DHCP server with MAC {rogue[0].get('unknown-server')} answers on {rogue[0].get('interface')}: phones that "
            "take its address skip the hotspot and get no internet or no login page.",
            advice="Find the device with that MAC (often a customer's router with its cable in a LAN port instead of "
                   "WAN) and unplug it or switch it to access-point mode."))

    # 7. a router working too hard
    res = (_rows(api.send_command("/system/resource/print")) or [{}])[0]
    checked.append("load")
    try:
        cpu = int(res.get("cpu-load") or 0)
    except ValueError:
        cpu = 0
    if cpu >= 90:
        found.append(finding(
            "cpu_high", "warn", f"The router is at {cpu}% CPU",
            "At this load pages are slow and logins time out.",
            advice="Ask which customers use the most data right now, or move heavy users to PPPoE."))

    order = {"bad": 0, "warn": 1, "info": 2}
    found.sort(key=lambda f: order.get(f["severity"], 3))
    return {
        "router_id": router_id, "reachable": True, "checked": checked, "findings": found,
        "ok": not any(f["severity"] in ("bad", "warn") for f in found),
        "identity": (_rows(api.send_command("/system/identity/print")) or [{}])[0].get("name"),
    }


def apply_anti_bypass(api, allow_entries: list[str]) -> dict:
    """Bitwave's proven HTTP Injector fix: the hotspot proxy may relay only to the
    portal and backend. Idempotent: our allow entries and rule are replaced by comment."""
    steps = []
    for entry in _rows(api.send_command("/ip/firewall/address-list/print")):
        if entry.get("list") == PORTAL_ALLOW_LIST and entry.get("comment") == PORTAL_ALLOW_COMMENT:
            api.send_command("/ip/firewall/address-list/remove", {".id": entry.get(".id")})
    for address in allow_entries:
        r = api.send_command("/ip/firewall/address-list/add",
                             {"list": PORTAL_ALLOW_LIST, "address": address, "comment": PORTAL_ALLOW_COMMENT})
        steps.append({"step": f"allow {address}", "ok": not r.get("error"), "detail": r.get("error")})
    for rule in _rows(api.send_command("/ip/firewall/filter/print")):
        if rule.get("comment") == PROXY_RELAY_BLOCK_COMMENT:
            api.send_command("/ip/firewall/filter/remove", {".id": rule.get(".id")})
    r = api.send_command("/ip/firewall/filter/add", {
        "chain": "output", "protocol": "tcp", "dst-port": PROXY_RELAY_PORTS,
        "dst-address-list": f"!{PORTAL_ALLOW_LIST}", "dst-address": f"!{HOTSPOT_SUBNET}",
        "action": "reject", "reject-with": "tcp-reset", "comment": PROXY_RELAY_BLOCK_COMMENT,
    })
    steps.append({"step": "proxy relay block", "ok": not r.get("error"), "detail": r.get("error")})
    return {"success": all(s["ok"] for s in steps), "steps": steps}

"""Read-only look inside a router: any of a fixed list of RouterOS menus, printed.

Support troubleshoots a router by reading it: the DHCP servers and leases on the
hotspot LAN, what sits on which bridge port, the hotspot hosts that never log in,
the PPPoE sessions, the log. The dashboard's own pages cover a few of these; this
gives the rest, for the person's own routers only (and staff with routers.view),
read-only: only "print" is ever sent, from a fixed list of menus, and passwords,
keys and secrets in a row are hidden before it leaves.
"""
from __future__ import annotations

import asyncio
import re
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.services.auth import get_current_user, verify_token
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_availability import record_router_availability
from app.services.router_helpers import get_router_by_id
from app.services.router_time import ROUTER_CLOCK_KEYS, read_router_clock, stamp_router_times

router = APIRouter(tags=["routers"])

Menu = Literal[
    # the box
    "/system/resource", "/system/identity", "/system/routerboard", "/system/health", "/system/clock",
    "/system/package", "/system/scheduler", "/log", "/file",
    # ports, bridges, radios, tunnels
    "/interface", "/interface/ethernet", "/interface/bridge", "/interface/bridge/port", "/interface/bridge/host",
    "/interface/wireless", "/interface/wireless/registration-table", "/interface/wifi",
    "/interface/wifi/registration-table", "/interface/pppoe-client", "/interface/pppoe-server/server",
    "/interface/sstp-client", "/interface/l2tp-client", "/interface/vlan",
    # addressing
    "/ip/address", "/ip/route", "/ip/dns", "/ip/arp", "/ip/neighbor", "/ip/pool", "/ip/dhcp-client",
    "/ip/dhcp-server", "/ip/dhcp-server/lease", "/ip/dhcp-server/network",
    # hotspot
    "/ip/hotspot", "/ip/hotspot/profile", "/ip/hotspot/active", "/ip/hotspot/host", "/ip/hotspot/user",
    "/ip/hotspot/ip-binding", "/ip/hotspot/walled-garden", "/ip/hotspot/walled-garden/ip",
    # PPPoE
    "/ppp/active", "/ppp/secret", "/ppp/profile",
    # firewall, queues
    "/ip/firewall/filter", "/ip/firewall/nat", "/ip/firewall/mangle", "/ip/firewall/address-list",
    "/ip/firewall/connection", "/ip/proxy", "/queue/simple", "/queue/tree", "/tool/netwatch",
]

_SECRET = re.compile(r"password|secret|passphrase|private-key|pre-shared|psk|\bkey\b|-key$|token", re.I)
# a script body can hold anything, a password included
_DROPPED = {"on-event", "source", "contents"}
HIDDEN = "(hidden)"


def clean_row(row: dict) -> dict:
    out = {}
    for key, value in row.items():
        if key in _DROPPED:
            continue
        out[key] = HIDDEN if _SECRET.search(key) and value not in (None, "") else value
    return out


def _print_sync(info: dict, menu: str) -> dict:
    api = MikroTikAPI(info["ip"], info["username"], info["password"], info["port"], timeout=20, connect_timeout=5)
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        result = api.send_command(f"{menu}/print")
        # Stamps in a row (log time, last-logged-out, ...) are the router's own
        # clock; the clock read in this session turns them into true UTC.
        rows = result.get("data") or [] if result.get("success") else []
        if any(isinstance(r, dict) and ROUTER_CLOCK_KEYS.intersection(r) for r in rows):
            result["clock"] = read_router_clock(api)
        return result
    finally:
        api.disconnect()


@router.get("/api/routers/{router_id}/routeros")
async def read_router_menu(
    router_id: int,
    menu: Menu = Query(..., description="The RouterOS menu to print, e.g. /ip/dhcp-server/lease"),
    contains: Optional[str] = Query(None, description="Only rows with this text in any value (a MAC, an IP, a name)"),
    limit: int = Query(100, ge=1, le=500, description="At most this many rows (the log: the newest)"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Look inside one of your routers: print a RouterOS menu (read-only).

    For troubleshooting what the dashboard pages do not show: DHCP servers and leases
    (a second DHCP server on the hotspot LAN), bridge ports and the MACs learnt on each
    (which AP a phone sits behind), hotspot hosts and active users, PPPoE sessions and
    secrets, routes, the firewall, queues and the log. Passwords and keys are hidden.
    Nothing on the router is changed.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    info = {"ip": router_obj.ip_address, "username": router_obj.username,
            "password": router_obj.password, "port": router_obj.port}
    name = router_obj.name
    await db.commit()  # no DB connection held while the router answers

    result = await asyncio.to_thread(_print_sync, info, menu)
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "router_inspect")
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {name}")
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"The router refused {menu}: {result['error']}")
    await record_router_availability(db, router_id, True, "router_inspect")

    rows = [stamp_router_times(clean_row(r), result.get("clock")) for r in result.get("data") or []
            if isinstance(r, dict)]
    if contains:
        needle = contains.lower()
        rows = [r for r in rows if any(needle in str(v).lower() for v in r.values())]
    total = len(rows)
    rows = rows[-limit:] if menu == "/log" else rows[:limit]
    return {"router": name, "menu": menu, "count": total, "shown": len(rows), "rows": rows}


@router.get("/api/routers/{router_id}/offline-customers")
async def offline_customers(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Paid customers on this router who are offline right now: who, since when, and why.

    Use for "who is offline", "how many clients are offline", "since when is X offline",
    "did anyone go offline today", "why is X offline". Checks the router live, one
    connection, read-only: PPPoE sessions and each secret's last logout and disconnect
    reason, hotspot sessions and bypassed hosts, and for static-IP customers the router's
    ARP entry and speed queue. Paid = active and not expired; an expired customer is
    never listed as offline. Each row has offline_since (UTC, or null with since_note
    saying why it is unknown), since_source (router, session_history or last_traffic),
    the reason the router gives, the plan and its expiry. counts gives paid, online and
    offline (also per connection type). A router that does not answer is a 503 error
    saying so, never an empty list.
    """
    from datetime import datetime

    from app.services import offline_customers as oc
    from app.services.router_concurrency import run_with_guard

    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    now = datetime.utcnow()
    info = {"ip": router_obj.ip_address, "username": router_obj.username,
            "password": router_obj.password, "port": router_obj.port}
    name = router_obj.name
    last_online = oc.utc_text(router_obj.last_online_at)
    customers = await oc.load_paid_customers(db, router_id, now)
    await db.commit()  # no DB connection held while the router answers

    kinds = {c["connection_type"] for c in customers}
    if customers:
        result = await run_with_guard(router_id, oc.read_presence_sync, info, kinds)
    else:
        result = {"success": True}
    if result.get("error") in ("connect_failed", "timeout", "busy"):
        if result["error"] != "busy":
            await record_router_availability(db, router_id, False, "offline_customers")
        what = {"connect_failed": "did not answer", "timeout": "took too long to answer",
                "busy": "is busy with other checks"}[result["error"]]
        raise HTTPException(status_code=503, detail={
            "message": (f"Router {name} {what}, so who is online cannot be checked right now. "
                        "This is not a list of offline customers; try again shortly."),
            "router_reachable": result["error"] == "busy",
            "router_last_online_at": last_online,
            "paid_customers": len(customers),
        })
    if result.get("error"):
        raise HTTPException(status_code=502, detail={
            "message": f"Router {name} answered but a list could not be read: {result.get('detail') or result['error']}",
            "paid_customers": len(customers),
        })
    if customers:
        await record_router_availability(db, router_id, True, "offline_customers")

    online, offline = oc.classify(customers, result)
    ids = [c["customer_id"] for c in offline]
    latest, used = await oc.load_history(db, ids, now)
    await db.commit()
    return oc.build_report(router_id, name, online, offline, latest, used, result.get("fetched_utc") or now)

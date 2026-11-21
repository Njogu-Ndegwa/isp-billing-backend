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
        return api.send_command(f"{menu}/print")
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

    rows = [clean_row(r) for r in result.get("data") or [] if isinstance(r, dict)]
    if contains:
        needle = contains.lower()
        rows = [r for r in rows if any(needle in str(v).lower() for v in r.values())]
    total = len(rows)
    rows = rows[-limit:] if menu == "/log" else rows[:limit]
    return {"router": name, "menu": menu, "count": total, "shown": len(rows), "rows": rows}

"""Hotspot Wi-Fi name (SSID) of a router: read it, rename it.

See ``app/services/router_wifi.py`` for which interfaces are touched (enabled
access-point masters in the hotspot bridge only; never a station/uplink) and
how the result is verified.

Ownership: ``get_router_by_id`` scopes both routes to the caller's routers
(another reseller gets 404). Staff need ``routers.view`` to read and
``routers.manage`` to rename (``app/services/staff_permissions.py``); renames
by the owner are logged too (OWNER_LOGGED_TEMPLATES), with the old and new
name in the activity line.

DB discipline: the router row is read and the session committed before any
RouterOS I/O; nothing holds a session while the router is talked to.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Router
from app.services import router_wifi
from app.services.auth import get_current_user, verify_token
from app.services.router_availability import record_router_availability
from app.services.router_concurrency import run_with_guard
from app.services.router_helpers import get_router_by_id

logger = logging.getLogger(__name__)
router = APIRouter()

_READ_TIMEOUT = 30
_RENAME_TIMEOUT = 45

# Outcomes where nothing was written: they do not count toward the rate limit.
_NO_WRITE_ERRORS = {"connect_failed", "busy", "cancelled", "no_wireless", "no_eligible_wifi", "state_unreadable"}


class RenameWifiRequest(BaseModel):
    ssid: str = Field(..., max_length=64)
    confirm: bool = False


def _router_info(router_obj: Router) -> dict:
    return {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }


def _set_activity_summary(request: Optional[Request], summary: str) -> None:
    if request is None:
        return
    try:
        request.state.staff_activity_summary = summary[:300]
    except Exception:
        pass


async def _owned_router(db: AsyncSession, router_id: int, token: str):
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    info, name, user_id = _router_info(router_obj), router_obj.name, user.id
    await db.commit()
    return info, name, user_id


async def _raise_for_error(db: AsyncSession, router_id: int, router_name: str, result: dict, what: str) -> None:
    error = result.get("error")
    if not error:
        return
    if error == "busy":
        raise HTTPException(status_code=429, detail=result.get("detail") or "Router is busy, try again shortly")
    if error == "timeout":
        raise HTTPException(status_code=504, detail="The router was slow to answer. Refresh in a minute to see the Wi-Fi name.")
    if error == "connect_failed":
        await record_router_availability(db, router_id, False, what)
        raise HTTPException(
            status_code=503,
            detail=f"Could not reach router {router_name}. Check that it is online, then try again.",
        )
    if error in ("no_wireless", "no_eligible_wifi"):
        raise HTTPException(status_code=409, detail={"code": error, "message": result.get("message"),
                                                     "skipped": result.get("skipped") or []})
    raise HTTPException(status_code=502, detail=result.get("message") or "Could not read the router's Wi-Fi")


@router.get("/api/routers/{router_id}/wifi")
async def get_router_wifi(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Current hotspot Wi-Fi name(s), read live from the router."""
    info, router_name, _user_id = await _owned_router(db, router_id, token)
    result = await run_with_guard(
        router_id, router_wifi.read_wifi_sync, info,
        acquire_timeout_seconds=5, timeout_seconds=_READ_TIMEOUT,
    )
    await _raise_for_error(db, router_id, router_name, result, "wifi_read")
    return {
        "router_id": router_id,
        "router_name": router_name,
        "has_wireless": result["has_wireless"],
        "ssids": result["ssids"],
        "can_rename": any(i["renameable"] for i in result["interfaces"]),
        "rename_in_progress": router_wifi.rename_in_progress(router_id),
        "interfaces": result["interfaces"],
        "message": None if result["has_wireless"] else router_wifi.NO_WIRELESS_MESSAGE,
    }


@router.put("/api/routers/{router_id}/wifi/ssid")
async def rename_router_wifi(
    router_id: int,
    body: RenameWifiRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Rename the hotspot Wi-Fi. Every Wi-Fi client is dropped and must join
    the new name, so ``confirm=true`` is required."""
    try:
        ssid = router_wifi.validate_ssid(body.ssid)
    except router_wifi.InvalidSsid as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to rename the Wi-Fi")

    info, router_name, user_id = await _owned_router(db, router_id, token)

    wait = router_wifi.rate_limit_wait(router_id)
    if wait:
        _set_activity_summary(request, f"Wi-Fi rename on router {router_id} refused: rate limit")
        raise HTTPException(
            status_code=429,
            detail=f"The Wi-Fi on this router was renamed several times in the last hour. "
                   f"Try again in {max(1, wait // 60)} minute(s).",
            headers={"Retry-After": str(wait)},
        )
    claim = router_wifi.try_claim(router_id)
    if claim is None:
        _set_activity_summary(request, f"Wi-Fi rename on router {router_id} refused: another rename running")
        raise HTTPException(status_code=409, detail="A Wi-Fi rename is already running on this router.")

    try:
        result = await run_with_guard(
            router_id, router_wifi.rename_wifi_sync, info, ssid, claim,
            acquire_timeout_seconds=5, timeout_seconds=_RENAME_TIMEOUT,
        )
    finally:
        router_wifi.abandon_if_not_started(claim)

    error = result.get("error")
    if error not in _NO_WRITE_ERRORS:
        router_wifi.record_rename(router_id)

    before = sorted({i.get("ssid_before") or "" for i in result.get("interfaces") or []} - {""})
    names = ", ".join(i["name"] for i in result.get("interfaces") or [])
    if error:
        summary = f"Wi-Fi rename to \"{ssid}\" on router {router_id} failed: {error}"
    else:
        summary = (f"Renamed Wi-Fi on router {router_id} from \"{', '.join(before) or '?'}\" to \"{ssid}\" "
                   f"({names}): {'verified' if result.get('verified') else 'NOT verified'}")
    _set_activity_summary(request, summary)
    logger.info("[wifi-rename] router=%s (%s) user_id=%s %s", router_id, router_name, user_id, summary)

    await _raise_for_error(db, router_id, router_name, result, "wifi_rename")

    if not result.get("verified"):
        failed = [i for i in result["interfaces"] if not i.get("verified")]
        raise HTTPException(
            status_code=502,
            detail={
                "code": "not_verified",
                "message": "The router did not keep the new Wi-Fi name on "
                           + ", ".join(i["name"] for i in failed) + ". Refresh and try again.",
                "interfaces": result["interfaces"],
            },
        )

    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_name,
        "ssid": ssid,
        "previous_ssids": before,
        "verified": True,
        "interfaces": result["interfaces"],
        "skipped": result.get("skipped") or [],
        "message": f"Wi-Fi renamed to \"{ssid}\". Devices on Wi-Fi must now join \"{ssid}\".",
    }

"""Access points behind a router: discover, store the admin password once,
read status, reboot and "make it a safe AP".

See ``app/services/ap_control.py`` for the behaviour and safety rules. The
reseller saves each AP's password once; it is stored Fernet-encrypted and is
never returned by any endpoint here. Agents never see or type it.

Ownership: ``get_router_by_id`` scopes every route to the caller's own routers
(another reseller gets 404). Staff need ``routers.view`` to read and
``routers.manage`` to write (wired in ``app/services/staff_permissions.py``).
Writes go through ``run_with_guard`` with a per-router "one AP write at a time"
claim, and are audited (no secrets) via the staff-activity middleware.

DB discipline: the (decrypted) credential is read in a short session, the
session is committed/closed, the router I/O runs with NO session held, and the
outcome is persisted in a fresh short session.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import database as db_module
from app.db.database import get_db
from app.db.models import Router, RouterApCredential
from app.services.auth import verify_token, get_current_user
from app.services.router_helpers import get_router_by_id
from app.services.router_concurrency import run_with_guard
from app.services.router_availability import record_router_availability
from app.services.payment_gateway import encrypt_credential, decrypt_credential
from app.services import ap_control
from app.services.ap_access import ap_control_allowed, ap_control_scope
from app.services.ap_control import ApCredential

logger = logging.getLogger(__name__)
router = APIRouter()

_AP_WRITE_TIMEOUT = 90
_AP_READ_TIMEOUT = 45


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class SaveApCredentialRequest(BaseModel):
    password: str
    username: str = "admin"
    vendor: str = "Tenda"
    model: Optional[str] = None
    ap_ip: Optional[str] = None


class ConfirmRequest(BaseModel):
    confirm: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _router_info(router_obj: Router) -> Dict[str, Any]:
    return {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }


def _normalise_mac(mac: str) -> str:
    return str(mac or "").strip().upper().replace("-", ":")


def _public_credential(cred: Optional[RouterApCredential]) -> Optional[Dict[str, Any]]:
    """Credential view with NO secret. ``has_password`` is the only hint."""
    if cred is None:
        return None
    return {
        "ap_mac": cred.ap_mac,
        "vendor": cred.vendor,
        "model": cred.model,
        "username": cred.username,
        "has_password": bool(cred.password_encrypted),
        "login_method": cred.login_method,
        "last_login_ok": cred.last_login_ok,
        "locked": (cred.failed_login_count or 0) >= ap_control.MAX_FAILED_LOGINS,
        "failed_login_count": cred.failed_login_count or 0,
        "last_error": cred.last_error,
        "last_status": cred.last_status,
        "last_status_at": cred.last_status_at.isoformat() if cred.last_status_at else None,
        "last_action": cred.last_action,
        "last_action_at": cred.last_action_at.isoformat() if cred.last_action_at else None,
    }


async def _load_router(db: AsyncSession, router_id: int, token: str) -> Router:
    user = await get_current_user(token, db)
    if not ap_control_allowed(getattr(user, "role", None)):
        raise HTTPException(
            status_code=403,
            detail={"code": "ap_control_disabled",
                    "message": "Remote access-point control is not enabled for your account yet."},
        )
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    return router_obj


async def _get_cred_row(db: AsyncSession, router_id: int, ap_mac: str) -> Optional[RouterApCredential]:
    res = await db.execute(select(RouterApCredential).where(
        RouterApCredential.router_id == router_id, RouterApCredential.ap_mac == ap_mac))
    return res.scalar_one_or_none()


def _set_activity_summary(request: Optional[Request], summary: str) -> None:
    if request is None:
        return
    try:
        request.state.staff_activity_summary = summary[:300]
    except Exception:
        pass


async def _persist_outcome(router_id: int, ap_mac: str, action: str, result: Dict[str, Any]) -> None:
    """Record login success/lockout and the last status -- no secrets."""
    async with db_module.async_session() as session:
        cred = await _get_cred_row(session, router_id, ap_mac)
        if cred is None:
            return
        login_ok = result.get("login_ok")
        if login_ok is True:
            cred.last_login_ok = True
            cred.failed_login_count = 0
            if result.get("login_method"):
                cred.login_method = result["login_method"]
        elif result.get("error") in ("login_failed",):
            cred.last_login_ok = False
            cred.failed_login_count = (cred.failed_login_count or 0) + 1
        status = result.get("status")
        if status:
            cred.last_status = status
            cred.last_status_at = datetime.utcnow()
            if status.get("ip"):
                cred.last_ip = status.get("ip")
            # Prefer the detected adapter key (e.g. "F3") over the human model
            # string so later actions pick the right adapter.
            detected = status.get("detected_model")
            if detected:
                cred.model = detected
            elif status.get("model") and not cred.model:
                cred.model = status.get("model")
        if result.get("new_ip"):
            cred.last_ip = result["new_ip"]
        cred.last_action = action
        cred.last_action_at = datetime.utcnow()
        cred.last_error = None if result.get("success") else (result.get("message") or result.get("error"))
        if action == ap_control.ACTION_REBOOT and result.get("success"):
            cred.last_reboot_at = datetime.utcnow()
        await session.commit()


def _raise_for_result(result: Dict[str, Any], router_name: str) -> None:
    error = result.get("error")
    if not error:
        return
    if error == "busy":
        raise HTTPException(status_code=429, detail=result.get("detail", "Router is busy, try again shortly"))
    if error == "timeout":
        raise HTTPException(status_code=504, detail="The router was slow to answer; try again in a minute.")
    if error == "connect_failed":
        raise HTTPException(status_code=503, detail=result.get("message") or f"Failed to connect to router: {router_name}")
    if error == "login_locked":
        raise HTTPException(status_code=423, detail=result.get("message") or "This AP is locked; replace its password.")
    if error == "login_failed":
        raise HTTPException(status_code=502, detail=result.get("message") or "The AP rejected the saved password.")
    if error in ("on_gateway",):
        raise HTTPException(status_code=409, detail=result.get("message"))
    if error in ("no_ip", "no_gateway", "no_free_ip", "gateway_conflict", "not_on_hotspot_lan"):
        raise HTTPException(status_code=409, detail=result.get("message"))
    if error in ("ap_unreachable", "verify_unreachable"):
        raise HTTPException(status_code=502, detail=result.get("message") or "The access point did not answer.")
    raise HTTPException(status_code=502, detail=result.get("message") or "Access-point action failed")


# ---------------------------------------------------------------------------
# Discovery + saved credentials (read)
# ---------------------------------------------------------------------------

@router.get("/api/routers/{router_id}/access-points")
async def list_access_points(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Discover APs behind the router and merge in each saved credential's
    status. Flags which APs should be offered the "Make it a safe AP" button."""
    router_obj = await _load_router(db, router_id, token)
    router_info = _router_info(router_obj)
    router_name = router_obj.name

    creds = (await db.execute(select(RouterApCredential).where(
        RouterApCredential.router_id == router_id))).scalars().all()
    cred_by_mac = {c.ap_mac: c for c in creds}
    await db.commit()

    result = await run_with_guard(
        router_id, ap_control.discover_aps_sync, router_info,
        acquire_timeout_seconds=5, timeout_seconds=_AP_READ_TIMEOUT,
    )
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "ap_discovery")
    _raise_for_result(result, router_name)

    devices = []
    for dev in result.get("devices", []):
        cred = cred_by_mac.get(dev["mac"])
        flags = ap_control.detector_flags(
            cred.last_status if cred else None,
            on_gateway=dev.get("on_gateway", False),
            router_mode_suspect=dev.get("router_mode_suspect", False),
        )
        devices.append({
            **dev,
            "credential": _public_credential(cred),
            "detector": flags,
        })
    # Saved credentials whose AP wasn't seen in this scan (offline) still show.
    seen = {d["mac"] for d in result.get("devices", [])}
    for mac, cred in cred_by_mac.items():
        if mac not in seen:
            devices.append({
                "mac": mac, "ip": cred.last_ip, "hostname": None,
                "vendor": cred.vendor, "sources": [], "router_mode_suspect": False,
                "on_gateway": False, "offline": True,
                "credential": _public_credential(cred),
                "detector": ap_control.detector_flags(cred.last_status),
            })
    return {
        "router_id": router_id, "router_name": router_name,
        "gateway": result.get("gateway"), "subnet": result.get("subnet"),
        "ap_write_in_progress": ap_control.ap_write_in_progress(router_id),
        "access_points": devices,
    }


# ---------------------------------------------------------------------------
# Save / replace the AP password (write-only)
# ---------------------------------------------------------------------------

@router.put("/api/routers/{router_id}/access-points/{ap_mac}/credential")
async def save_ap_credential(
    router_id: int,
    ap_mac: str,
    body: SaveApCredentialRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Store or replace the AP's admin password (encrypted, write-only).

    Saving a new password clears any lockout. The password is never returned.
    """
    if not body.password or len(body.password) > 128:
        raise HTTPException(status_code=400, detail="Provide the AP admin password (max 128 chars)")
    ap_mac = _normalise_mac(ap_mac)
    if len(ap_mac) != 17:
        raise HTTPException(status_code=400, detail="Invalid AP MAC address")
    router_obj = await _load_router(db, router_id, token)

    cred = await _get_cred_row(db, router_id, ap_mac)
    encrypted = encrypt_credential(body.password)
    if cred is None:
        cred = RouterApCredential(router_id=router_id, ap_mac=ap_mac)
        db.add(cred)
    cred.vendor = body.vendor or "Tenda"
    cred.model = body.model or cred.model
    cred.username = body.username or "admin"
    cred.password_encrypted = encrypted
    cred.login_method = None           # re-detect on next use
    cred.last_login_ok = None
    cred.failed_login_count = 0
    cred.last_error = None
    if body.ap_ip:
        cred.last_ip = body.ap_ip
    cred.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(cred)
    _set_activity_summary(request, f"Saved access-point password for {ap_mac} on router {router_id}")
    return {"success": True, "credential": _public_credential(cred)}


@router.delete("/api/routers/{router_id}/access-points/{ap_mac}/credential")
async def delete_ap_credential(
    router_id: int,
    ap_mac: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _load_router(db, router_id, token)
    ap_mac = _normalise_mac(ap_mac)
    cred = await _get_cred_row(db, router_id, ap_mac)
    if cred is None:
        raise HTTPException(status_code=404, detail="No saved password for this access point")
    await db.delete(cred)
    await db.commit()
    _set_activity_summary(request, f"Removed access-point password for {ap_mac} on router {router_id}")
    return {"success": True}


# ---------------------------------------------------------------------------
# Status / reboot / make-safe
# ---------------------------------------------------------------------------

async def _prepare_action(db: AsyncSession, router_id: int, ap_mac: str, token: str):
    router_obj = await _load_router(db, router_id, token)
    ap_mac = _normalise_mac(ap_mac)
    cred_row = await _get_cred_row(db, router_id, ap_mac)
    if cred_row is None or not cred_row.password_encrypted:
        raise HTTPException(status_code=404, detail="No saved password for this access point")
    try:
        password = decrypt_credential(cred_row.password_encrypted)
    except ValueError:
        raise HTTPException(status_code=500, detail="Stored password could not be read; save it again.")
    cred = ApCredential(
        ap_mac=ap_mac, ap_ip=cred_row.last_ip, username=cred_row.username,
        password=password, vendor=cred_row.vendor, model=cred_row.model,
        login_method=cred_row.login_method, failed_login_count=cred_row.failed_login_count or 0,
    )
    router_info = _router_info(router_obj)
    router_name = router_obj.name
    await db.commit()
    return router_info, router_name, cred


@router.get("/api/routers/{router_id}/access-points/{ap_mac}/status")
async def ap_status(
    router_id: int,
    ap_mac: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    router_info, router_name, cred = await _prepare_action(db, router_id, ap_mac, token)
    result = await run_with_guard(
        router_id, ap_control.read_status_sync, router_info, cred,
        acquire_timeout_seconds=5, timeout_seconds=_AP_READ_TIMEOUT,
    )
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "ap_status")
    await _persist_outcome(router_id, cred.ap_mac, ap_control.ACTION_STATUS, result)
    _raise_for_result(result, router_name)
    return {"success": True, "status": result.get("status"), "login_method": result.get("login_method")}


async def _run_write(request, db, router_id, ap_mac, token, action, sync_fn):
    router_info, router_name, cred = await _prepare_action(db, router_id, ap_mac, token)
    claim = ap_control.try_claim(router_id)
    if claim is None:
        _set_activity_summary(request, f"AP {action} on {cred.ap_mac} (router {router_id}) refused: another AP action running")
        raise HTTPException(status_code=409,
                            detail="Another access-point action is running on this router. Wait for it to finish.")
    try:
        result = await run_with_guard(
            router_id, sync_fn, router_info, cred,
            acquire_timeout_seconds=5, timeout_seconds=_AP_WRITE_TIMEOUT,
        )
    finally:
        ap_control.abandon_if_not_started(claim)

    outcome = "ok" if result.get("success") else result.get("error")
    _set_activity_summary(
        request, f"AP {action} on {cred.ap_mac} (router {router_id}): {outcome}"
        + ("" if result.get("success") else f" - {result.get('message') or ''}"))
    logger.info("[ap-control] router=%s (%s) ap=%s action=%s result=%s",
                router_id, router_name, cred.ap_mac, action, outcome)
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, f"ap_{action}")
    await _persist_outcome(router_id, cred.ap_mac, action, result)
    _raise_for_result(result, router_name)
    return result


@router.post("/api/routers/{router_id}/access-points/{ap_mac}/reboot")
async def reboot_access_point(
    router_id: int,
    ap_mac: str,
    request: Request,
    body: Optional[ConfirmRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    body = body or ConfirmRequest()
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to reboot this access point")
    result = await _run_write(request, db, router_id, ap_mac, token,
                              ap_control.ACTION_REBOOT, ap_control.reboot_ap_sync)
    return {"success": True, "message": result.get("message"), "login_method": result.get("login_method")}


@router.post("/api/routers/{router_id}/access-points/{ap_mac}/make-safe")
async def make_access_point_safe(
    router_id: int,
    ap_mac: str,
    request: Request,
    body: Optional[ConfirmRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    body = body or ConfirmRequest()
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to reconfigure this access point")
    result = await _run_write(request, db, router_id, ap_mac, token,
                              ap_control.ACTION_MAKE_SAFE, ap_control.make_safe_ap_sync)
    return {
        "success": True, "message": result.get("message"),
        "new_ip": result.get("new_ip"), "gateway": result.get("gateway"),
        "verified_safe": result.get("verified_safe"), "status": result.get("status"),
        "steps": result.get("steps"),
    }

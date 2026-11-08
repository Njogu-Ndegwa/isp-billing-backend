"""Remote control of a PPPoE customer's own router / CPE (a Tenda) from the
customer page: save the device's admin password once, then check status, reboot,
or disconnect the line so it redials.

See ``app/services/cpe_control.py`` for the behaviour and safety rules. The
device is reached by resolving the customer's **live** PPPoE session on the
MikroTik (``/ppp active`` -> ``address``) and ``/tool fetch`` to that IP on the
device's web-management port; the IP is never stored as the identity.

The admin password is stored Fernet-encrypted and is never returned by any
endpoint here. Agents never see or type it.

Access gate: admin-only for now (``ap_access.ap_control_allowed``, same switch as
the hotspot AP feature). Ownership: the customer is scoped to the caller
(a reseller sees only their own customers; an admin sees all).

DB discipline: the (decrypted) credential + router info are read in a short
session which is then committed/closed; the router I/O runs with NO session
held; the outcome is persisted in a fresh short session.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import database as db_module
from app.db.database import get_db
from app.db.models import Customer, CustomerCpeCredential, Router
from app.services import ap_control, cpe_control
from app.services.ap_access import ap_control_allowed
from app.services.ap_control import ApCredential
from app.services.auth import get_current_user, verify_token
from app.services.customer_router_logs import router_info_of
from app.services.payment_gateway import decrypt_credential, encrypt_credential
from app.services.router_availability import record_router_availability
from app.services.router_concurrency import run_with_guard

logger = logging.getLogger(__name__)
router = APIRouter(tags=["customer-cpe"])

_CPE_WRITE_TIMEOUT = 90
_CPE_READ_TIMEOUT = 45


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class SaveCpeCredentialRequest(BaseModel):
    password: str
    username: str = Field(default="admin", max_length=64)
    vendor: str = Field(default="Tenda", max_length=30)
    model: Optional[str] = Field(default=None, max_length=40)
    port: int = Field(default=cpe_control.DEFAULT_LAN_PORT, ge=1, le=65535)
    device_mac: Optional[str] = Field(default=None, max_length=17)


class ConfirmRequest(BaseModel):
    confirm: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return str(mac).strip().upper().replace("-", ":")


def _public_credential(cred: Optional[CustomerCpeCredential]) -> Optional[Dict[str, Any]]:
    """Credential view with NO secret. ``has_password`` is the only hint."""
    if cred is None:
        return None
    return {
        "customer_id": cred.customer_id,
        "vendor": cred.vendor,
        "model": cred.model,
        "username": cred.username,
        "port": cred.port,
        "device_mac": cred.device_mac,
        "has_password": bool(cred.password_encrypted),
        "login_method": cred.login_method,
        "last_login_ok": cred.last_login_ok,
        "locked": (cred.failed_login_count or 0) >= ap_control.MAX_FAILED_LOGINS,
        "failed_login_count": cred.failed_login_count or 0,
        "last_error": cred.last_error,
        "last_ip": cred.last_ip,
        "last_status": cred.last_status,
        "last_status_at": cred.last_status_at.isoformat() if cred.last_status_at else None,
        "last_action": cred.last_action,
        "last_action_at": cred.last_action_at.isoformat() if cred.last_action_at else None,
    }


async def _load_customer(db: AsyncSession, customer_id: int, token: str):
    user = await get_current_user(token, db)
    if not ap_control_allowed(getattr(user, "role", None)):
        raise HTTPException(
            status_code=403,
            detail={"code": "cpe_control_disabled",
                    "message": "Remote router (CPE) control is not enabled for your account yet."},
        )
    stmt = (
        select(Customer)
        .options(selectinload(Customer.router))
        .where(Customer.id == customer_id)
    )
    role_value = getattr(getattr(user, "role", None), "value", None)
    if role_value != "admin":
        stmt = stmt.where(Customer.user_id == user.id)
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer, user


def _require_pppoe(customer: Customer) -> Router:
    if not customer.pppoe_username:
        raise HTTPException(status_code=400,
                            detail="Router (CPE) control is only for PPPoE customers.")
    router_obj = customer.router
    if router_obj is None:
        raise HTTPException(status_code=400, detail="Customer has no router assigned.")
    return router_obj


async def _get_cred_row(db: AsyncSession, customer_id: int) -> Optional[CustomerCpeCredential]:
    res = await db.execute(select(CustomerCpeCredential).where(
        CustomerCpeCredential.customer_id == customer_id))
    return res.scalar_one_or_none()


def _set_activity_summary(request: Optional[Request], summary: str) -> None:
    if request is None:
        return
    try:
        request.state.staff_activity_summary = summary[:300]
    except Exception:
        pass


async def _persist_outcome(customer_id: int, action: str, result: Dict[str, Any]) -> None:
    """Record login success/lockout and the last status -- no secrets."""
    async with db_module.async_session() as session:
        cred = await _get_cred_row(session, customer_id)
        if cred is None:
            return
        login_ok = result.get("login_ok")
        if login_ok is True:
            cred.last_login_ok = True
            cred.failed_login_count = 0
            if result.get("login_method"):
                cred.login_method = result["login_method"]
        elif result.get("error") == "login_failed":
            cred.last_login_ok = False
            cred.failed_login_count = (cred.failed_login_count or 0) + 1
        status = result.get("status")
        if status:
            cred.last_status = status
            cred.last_status_at = datetime.utcnow()
            if status.get("ip"):
                cred.last_ip = str(status.get("ip"))[:45]
            detected = status.get("detected_model")
            if detected:
                cred.model = detected
            elif status.get("model") and not cred.model:
                cred.model = str(status.get("model"))[:40]
        session_info = result.get("session")
        if isinstance(session_info, dict) and session_info.get("address"):
            cred.last_ip = str(session_info["address"])[:45]
        cred.last_action = action
        cred.last_action_at = datetime.utcnow()
        cred.last_error = None if result.get("success") else str(
            result.get("message") or result.get("error"))[:255]
        if action == cpe_control.ACTION_REBOOT and result.get("success"):
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
        raise HTTPException(status_code=503,
                            detail=result.get("message") or f"Failed to connect to router: {router_name}")
    if error == "offline":
        raise HTTPException(status_code=409, detail=result.get("message"))
    if error == "login_locked":
        raise HTTPException(status_code=423,
                            detail=result.get("message") or "This device is locked; replace its password.")
    if error == "login_failed":
        raise HTTPException(status_code=502,
                            detail=result.get("message") or "The router (CPE) rejected the saved password.")
    if error in ("cpe_unreachable", "cpe_unsupported", "cpe_reboot_failed", "disconnect_failed"):
        raise HTTPException(status_code=502, detail=result.get("message") or "The router (CPE) action failed.")
    raise HTTPException(status_code=502, detail=result.get("message") or "Router (CPE) action failed")


# ---------------------------------------------------------------------------
# Read / save / delete the saved credential
# ---------------------------------------------------------------------------

@router.get("/api/customers/{customer_id}/cpe")
async def get_cpe(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """The saved CPE credential (no secret) plus whether this is a controllable
    PPPoE customer. DB-only; does not touch the router."""
    customer, _user = await _load_customer(db, customer_id, token)
    cred = await _get_cred_row(db, customer_id)
    is_pppoe = bool(customer.pppoe_username) and customer.router is not None
    public = _public_credential(cred)
    await db.commit()
    return {
        "customer_id": customer_id,
        "is_pppoe": is_pppoe,
        "pppoe_username": customer.pppoe_username,
        "suggested_wan_port": cpe_control.DEFAULT_WAN_PORT,
        "credential": public,
    }


@router.put("/api/customers/{customer_id}/cpe/credential")
async def save_cpe_credential(
    customer_id: int,
    body: SaveCpeCredentialRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Store or replace the device's admin password (encrypted, write-only).

    Saving a new password clears any lockout. The password is never returned.
    """
    if not body.password or len(body.password) > 128:
        raise HTTPException(status_code=400, detail="Provide the router (CPE) admin password (max 128 chars)")
    customer, _user = await _load_customer(db, customer_id, token)
    _require_pppoe(customer)

    cred = await _get_cred_row(db, customer_id)
    encrypted = encrypt_credential(body.password)
    if cred is None:
        cred = CustomerCpeCredential(customer_id=customer_id)
        db.add(cred)
    cred.vendor = body.vendor or "Tenda"
    cred.model = body.model or cred.model
    cred.username = body.username or "admin"
    cred.password_encrypted = encrypted
    cred.port = int(body.port) or cpe_control.DEFAULT_LAN_PORT
    cred.device_mac = _normalise_mac(body.device_mac) or cred.device_mac
    cred.login_method = None           # re-detect on next use
    cred.last_login_ok = None
    cred.failed_login_count = 0
    cred.last_error = None
    cred.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(cred)
    _set_activity_summary(request, f"Saved router (CPE) password for customer {customer_id}")
    return {"success": True, "credential": _public_credential(cred)}


@router.delete("/api/customers/{customer_id}/cpe/credential")
async def delete_cpe_credential(
    customer_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _load_customer(db, customer_id, token)
    cred = await _get_cred_row(db, customer_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="No saved password for this router (CPE)")
    await db.delete(cred)
    await db.commit()
    _set_activity_summary(request, f"Removed router (CPE) password for customer {customer_id}")
    return {"success": True}


# ---------------------------------------------------------------------------
# Status / reboot / disconnect
# ---------------------------------------------------------------------------

async def _prepare_action(db: AsyncSession, customer_id: int, token: str):
    customer, user = await _load_customer(db, customer_id, token)
    router_obj = _require_pppoe(customer)
    cred_row = await _get_cred_row(db, customer_id)
    if cred_row is None or not cred_row.password_encrypted:
        raise HTTPException(status_code=404, detail="No saved password for this router (CPE)")
    try:
        password = decrypt_credential(cred_row.password_encrypted)
    except ValueError:
        raise HTTPException(status_code=500, detail="Stored password could not be read; save it again.")
    cred = ApCredential(
        ap_mac=cred_row.device_mac or "", ap_ip=cred_row.last_ip, username=cred_row.username,
        password=password, vendor=cred_row.vendor, model=cred_row.model,
        login_method=cred_row.login_method, failed_login_count=cred_row.failed_login_count or 0,
    )
    ctx = {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_info": router_info_of(router_obj),
        "username": customer.pppoe_username,
        "port": cred_row.port or cpe_control.DEFAULT_LAN_PORT,
        "cred": cred,
    }
    await db.commit()
    return ctx


@router.get("/api/customers/{customer_id}/cpe/status")
async def cpe_status(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    ctx = await _prepare_action(db, customer_id, token)
    result = await run_with_guard(
        ctx["router_id"], cpe_control.read_cpe_status_sync,
        ctx["router_info"], ctx["cred"], ctx["username"], ctx["port"],
        acquire_timeout_seconds=5, timeout_seconds=_CPE_READ_TIMEOUT,
    )
    if result.get("error") == "connect_failed":
        await record_router_availability(db, ctx["router_id"], False, "cpe_status")
    await _persist_outcome(customer_id, cpe_control.ACTION_STATUS, result)
    _raise_for_result(result, ctx["router_name"])
    return {"success": True, "status": result.get("status"), "login_method": result.get("login_method")}


async def _run_write(request, db, customer_id, token, action, sync_fn, *, needs_device: bool):
    ctx = await _prepare_action(db, customer_id, token)
    router_id = ctx["router_id"]
    claim = ap_control.try_claim(router_id)
    if claim is None:
        _set_activity_summary(request, f"CPE {action} on customer {customer_id} refused: another action running")
        raise HTTPException(status_code=409,
                            detail="Another router (CPE/AP) action is running on this router. Wait for it to finish.")

    def worker(*args):
        if not ap_control.begin_claim(claim):
            return {"error": "cancelled", "message": "The request expired before it started."}
        try:
            return sync_fn(*args)
        finally:
            ap_control.release_claim(claim)

    args = ((ctx["router_info"], ctx["cred"], ctx["username"], ctx["port"])
            if needs_device else (ctx["router_info"], ctx["username"]))
    try:
        result = await run_with_guard(
            router_id, worker, *args,
            acquire_timeout_seconds=5, timeout_seconds=_CPE_WRITE_TIMEOUT,
        )
    finally:
        ap_control.abandon_if_not_started(claim)

    outcome = "ok" if result.get("success") else result.get("error")
    _set_activity_summary(
        request, f"CPE {action} on customer {customer_id}: {outcome}"
        + ("" if result.get("success") else f" - {result.get('message') or ''}"))
    logger.info("[cpe-control] customer=%s router=%s action=%s result=%s",
                customer_id, router_id, action, outcome)
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, f"cpe_{action}")
    await _persist_outcome(customer_id, action, result)
    _raise_for_result(result, ctx["router_name"])
    return result


@router.post("/api/customers/{customer_id}/cpe/reboot")
async def reboot_cpe(
    customer_id: int,
    request: Request,
    body: Optional[ConfirmRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    body = body or ConfirmRequest()
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to reboot this router (CPE)")
    result = await _run_write(request, db, customer_id, token,
                              cpe_control.ACTION_REBOOT, cpe_control.reboot_cpe_sync, needs_device=True)
    return {"success": True, "message": result.get("message"), "login_method": result.get("login_method")}


@router.post("/api/customers/{customer_id}/cpe/disconnect")
async def disconnect_cpe(
    customer_id: int,
    request: Request,
    body: Optional[ConfirmRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Fallback restart: drop the PPPoE session so the device redials. This
    reconnects the line; it does not reboot the device."""
    body = body or ConfirmRequest()
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to disconnect the line")
    result = await _run_write(request, db, customer_id, token,
                              cpe_control.ACTION_DISCONNECT, cpe_control.disconnect_cpe_session_sync,
                              needs_device=False)
    return {"success": True, "message": result.get("message"), "disconnected": result.get("disconnected")}

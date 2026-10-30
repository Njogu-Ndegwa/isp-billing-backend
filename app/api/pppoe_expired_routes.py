"""PPPoE expired redirect: the per-router toggle and the portal's public API.

* ``PUT /api/routers/{router_id}/pppoe-expired-redirect`` (owner or staff with
  ``routers.manage``) applies or removes the walled state on the router, then
  stores the flag. Router I/O runs with no DB session held.
* ``GET  /api/public/pppoe/expired/{router_id}`` - what the expired page shows:
  reseller, plans, paybill, and (with ``?u=``) the customer's account status.
* ``GET  /api/public/pppoe/expired/{router_id}/status?u=`` - the page's poll.
* ``POST /api/public/pppoe/expired/pay`` - M-Pesa prompt for that customer.

The public endpoints answer only for routers with the feature on, and return
masked customer details: the page loads for anyone who can reach it, so it must
not become a lookup of names and phone numbers by username.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import database as db_module
from app.db.database import get_db
from app.db.models import (
    CollectionMode,
    ConnectionType,
    Customer,
    CustomerStatus,
    FailureSource,
    MpesaTransaction,
    MpesaTransactionStatus,
    Plan,
    PlanType,
    Router,
    User,
)
from app.services.auth import get_current_user, verify_token
from app.services.plan_cache import get_plans_cached, plan_model_allows_router, sort_portal_plans
from app.services.pppoe_expired_redirect import (
    ensure_expired_infra,
    teardown_expired_infra,
)
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger("pppoe_expired_routes")

router = APIRouter(tags=["pppoe-expired-redirect"])

PAY_DUP_GUARD_SECONDS = 180


# ---------------------------------------------------------------------------
# Toggle
# ---------------------------------------------------------------------------


class ExpiredRedirectToggle(BaseModel):
    enabled: bool


def _router_io(router_info: dict, func_, *args):
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=20, connect_timeout=5,
    )
    if not api.connect():
        return {"error": getattr(api, "last_connect_error", None) or "Failed to connect to router"}
    try:
        return func_(api, *args)
    finally:
        api.disconnect()


async def _locked_router_io(router_info: dict, func_, *args):
    from app.services.mikrotik_background import router_locks

    key = f"{router_info['ip']}:{router_info['port']}"
    async with router_locks.acquire(key):
        return await asyncio.to_thread(_router_io, router_info, func_, *args)


@router.put("/api/routers/{router_id}/pppoe-expired-redirect")
async def set_pppoe_expired_redirect(
    router_id: int,
    request: ExpiredRedirectToggle,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Turn "Redirect expired PPPoE users to payment page" on or off for one router.

    On: the walled profile, pool, firewall/NAT rules and proxy redirect are
    applied (idempotent, so turning it on again repairs a router). Off: walled
    customers lose their secret, as expiry did before, and every walled-state
    object is removed. The flag only changes once the router accepted it.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = (
        await db.execute(select(Router).where(Router.id == router_id, Router.user_id == user.id))
    ).scalar_one_or_none()
    if router_obj is None:
        raise HTTPException(status_code=404, detail="Router not found or does not belong to you")
    if str(getattr(router_obj, "auth_method", "DIRECT_API") or "DIRECT_API").upper() == "RADIUS":
        raise HTTPException(status_code=400, detail="Not available on RADIUS routers")
    router_info = {
        "id": router_obj.id,
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port or 8728,
    }
    config = dict(router_obj.pppoe_expired_redirect_config or {})
    was_enabled = bool(router_obj.pppoe_expired_redirect)
    await db.commit()  # nothing held across the router I/O below

    if request.enabled:
        result = await _locked_router_io(router_info, lambda api: ensure_expired_infra(
            api, router_id=router_info["id"], config=config))
    else:
        result = await _locked_router_io(router_info, teardown_expired_infra, config)
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"Router not updated: {result['error']}")

    async with db_module.async_session() as wdb:
        row = await wdb.get(Router, router_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Router not found")
        row.pppoe_expired_redirect = request.enabled
        if request.enabled:
            row.pppoe_expired_redirect_config = {
                **result["config"],
                "applied_at": datetime.utcnow().isoformat(),
            }
        else:
            row.pppoe_expired_redirect_config = None
        await wdb.commit()

    logger.info(
        "PPPoE expired redirect %s on router %s by user %s",
        "enabled" if request.enabled else "disabled", router_id, user.id,
    )
    if request.enabled:
        message = (
            "Expired PPPoE customers are redirected to the payment page (router repaired)"
            if was_enabled
            else "Expired PPPoE customers will now be redirected to the payment page"
        )
    else:
        released = len(result.get("secrets_removed") or [])
        message = "Expired PPPoE customers are cut off again, as before"
        if released:
            message += f" ({released} waiting on the payment page were disconnected)"
    return {
        "router_id": router_id,
        "pppoe_expired_redirect": request.enabled,
        "message": message,
        "result": result,
    }


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def _mask_phone(phone: Optional[str]) -> Optional[str]:
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) < 7:
        return None
    return f"{'*' * (len(digits) - 3)}{digits[-3:]}"


def _first_name(name: Optional[str]) -> Optional[str]:
    parts = (name or "").strip().split()
    return parts[0] if parts else None


def normalize_phone(phone: Optional[str]) -> Optional[str]:
    """Digits only; Kenyan 07../01.. and 7../1.. become 2547../2541..."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) == 10 and digits[0] == "0" and digits[1] in "17":
        return "254" + digits[1:]
    if len(digits) == 9 and digits[0] in "17":
        return "254" + digits
    return digits or None


async def _enabled_router(db: AsyncSession, router_id: int) -> Router:
    router_obj = await db.get(Router, router_id)
    if router_obj is None or not getattr(router_obj, "pppoe_expired_redirect", False):
        raise HTTPException(status_code=404, detail="Not available on this network")
    return router_obj


async def _find_customer(db: AsyncSession, router_id: int, ident: Optional[str]) -> Optional[Customer]:
    """The PPPoE customer of this router by username or account number."""
    ident = (ident or "").strip()
    if not ident:
        return None
    rows = (
        await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(
                Customer.router_id == router_id,
                Customer.pppoe_username.isnot(None),
                or_(
                    Customer.pppoe_username == ident,
                    func.upper(Customer.account_number) == ident.upper(),
                ),
            )
            .order_by(Customer.id.desc())
            .limit(2)
        )
    ).scalars().all()
    # Prefer the exact username match over an account-number collision.
    for customer in rows:
        if customer.pppoe_username == ident:
            return customer
    return rows[0] if rows else None


def _is_online(customer: Customer, now: datetime) -> bool:
    from app.services.customer_grace import effective_expiry

    return bool(
        customer.status == CustomerStatus.ACTIVE
        and customer.expiry
        and effective_expiry(customer) > now
    )


def _plan_payload(plan: dict) -> dict:
    return {
        "id": plan["id"],
        "name": plan["name"],
        "price": plan["price"],
        "speed": plan.get("speed"),
        "duration_value": plan.get("duration_value"),
        "duration_unit": plan.get("duration_unit"),
        "badge_text": plan.get("badge_text"),
    }


def _purchasable(plan: dict) -> bool:
    return (
        plan.get("connection_type") == ConnectionType.PPPOE.value
        and plan.get("plan_type") != PlanType.FREE_TRIAL.value
        and float(plan.get("price") or 0) > 0
    )


async def _router_plans(db: AsyncSession, router_obj: Router, customer: Optional[Customer]) -> list[dict]:
    from app.db.models import PortalSettings

    visible = await get_plans_cached(db, router_obj.user_id, ConnectionType.PPPOE.value, router_id=router_obj.id)
    plans = [p for p in visible if _purchasable(p)]
    # PPPoE plans are often hidden per-customer plans: always offer theirs.
    current = customer.plan if customer is not None else None
    if (
        current is not None
        and current.user_id == router_obj.user_id
        and current.connection_type == ConnectionType.PPPOE
        and current.plan_type != PlanType.FREE_TRIAL
        and float(current.price or 0) > 0
        and not any(p["id"] == current.id for p in plans)
    ):
        from app.services.plan_cache import _serialize_plan

        plans.insert(0, _serialize_plan(current))
    order = (
        await db.execute(select(PortalSettings.plan_sort_order).where(PortalSettings.user_id == router_obj.user_id))
    ).scalar_one_or_none()
    return [_plan_payload(p) for p in sort_portal_plans(plans, order)]


def _customer_payload(customer: Customer, now: datetime) -> dict:
    status = customer.status.value if customer.status else None
    online = _is_online(customer, now)
    return {
        "username": customer.pppoe_username,
        "account_number": customer.account_number,
        "first_name": _first_name(customer.name),
        "phone_hint": _mask_phone(customer.phone),
        "plan_id": customer.plan_id,
        "plan_name": customer.plan.name if customer.plan else None,
        "plan_price": customer.plan.price if customer.plan else None,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "status": status,
        "paused": customer.paused_at is not None,
        "online": online,
    }


async def _pending_txn(db: AsyncSession, customer_id: int, now: datetime) -> Optional[MpesaTransaction]:
    from datetime import timedelta

    return (
        await db.execute(
            select(MpesaTransaction)
            .where(
                MpesaTransaction.customer_id == customer_id,
                MpesaTransaction.created_at >= now - timedelta(minutes=30),
                ~MpesaTransaction.checkout_request_id.startswith("FAILED-"),
            )
            .order_by(MpesaTransaction.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


@router.get("/api/public/pppoe/expired/{router_id}")
async def expired_page_data(router_id: int, u: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    from app.api.portal_routes import _build_public_response
    from app.db.models import PortalSettings
    from app.services.customer_expiry_notifications import resolve_paybills

    router_obj = await _enabled_router(db, router_id)
    reseller = await db.get(User, router_obj.user_id)
    customer = await _find_customer(db, router_id, u)
    now = datetime.utcnow()
    plans = await _router_plans(db, router_obj, customer)
    paybill = None
    if reseller is not None:
        try:
            paybill = (await resolve_paybills(db, reseller, {router_id})).get(router_id)
        except Exception:
            logger.exception("expired page: paybill lookup failed for router %s", router_id)
    portal_settings = (
        await db.execute(select(PortalSettings).where(PortalSettings.user_id == router_obj.user_id))
    ).scalar_one_or_none()
    payload = {
        "router": {
            "router_id": router_obj.id,
            "name": router_obj.name,
            "business_name": (reseller.business_name or reseller.organization_name) if reseller else None,
            "support_phone": reseller.support_phone if reseller else None,
            "mpesa": "mpesa" in (router_obj.payment_methods or ["mpesa"]),
        },
        "paybill": paybill,
        "plans": plans,
        "customer": _customer_payload(customer, now) if customer else None,
        "lookup": "found" if customer else ("not_found" if u else "none"),
        "portal_settings": _build_public_response(portal_settings, reseller),
    }
    await db.commit()
    return payload


@router.get("/api/public/pppoe/expired/{router_id}/status")
async def expired_page_status(
    router_id: int,
    background_tasks: BackgroundTasks,
    u: str,
    db: AsyncSession = Depends(get_db),
):
    """The page's poll: back online yet, and how the last prompt went."""
    await _enabled_router(db, router_id)
    customer = await _find_customer(db, router_id, u)
    if customer is None:
        raise HTTPException(status_code=404, detail="Account not found on this network")
    now = datetime.utcnow()
    txn = await _pending_txn(db, customer.id, now)
    payment = None
    if txn is not None:
        payment = {
            "status": txn.status.value if txn.status else None,
            "created_at": txn.created_at.isoformat() if txn.created_at else None,
            "result_desc": txn.result_desc if txn.status == MpesaTransactionStatus.failed else None,
        }
        if txn.status == MpesaTransactionStatus.pending:
            # Lost callback? Ask Safaricom (no-op while the prompt is young).
            from app.services.mpesa_transactions import kick_pending_payment_check

            background_tasks.add_task(kick_pending_payment_check, customer.id)
    body = {**_customer_payload(customer, now), "payment": payment}
    await db.commit()
    return body


class ExpiredPayRequest(BaseModel):
    router_id: int
    username: str
    plan_id: Optional[int] = None
    phone: Optional[str] = None  # blank = the phone on file


@router.post("/api/public/pppoe/expired/pay")
async def expired_page_pay(request: ExpiredPayRequest, db: AsyncSession = Depends(get_db)):
    """Send an M-Pesa prompt to renew this PPPoE customer.

    The amount is always the plan's price from the database. A different plan
    is held in pending_update_data and applied by the payment callback, so a
    prompt the customer ignores changes nothing. Provisioning on payment is the
    normal PPPoE path, which takes the customer off the walled profile.
    """
    from app.services.mpesa import initiate_stk_push
    from app.services.payment_gateway import initiate_customer_payment, resolve_collection_payment_method

    router_obj = await _enabled_router(db, request.router_id)
    if "mpesa" not in (router_obj.payment_methods or ["mpesa"]):
        raise HTTPException(status_code=400, detail="Mobile money is not enabled on this network")
    customer = await _find_customer(db, request.router_id, request.username)
    if customer is None:
        raise HTTPException(status_code=404, detail="Account not found on this network")
    if customer.paused_at is not None:
        raise HTTPException(status_code=409, detail="This account is paused. Contact your provider to resume it.")

    reseller = await db.get(User, router_obj.user_id)
    sub = getattr(getattr(reseller, "subscription_status", None), "value", getattr(reseller, "subscription_status", None))
    if reseller is None or sub not in ("active", "trial"):
        raise HTTPException(status_code=503, detail="This service is temporarily unavailable. Please contact your ISP.")

    plan = customer.plan
    if request.plan_id and request.plan_id != customer.plan_id:
        plan = await db.get(Plan, request.plan_id)
    if (
        plan is None
        or plan.user_id != router_obj.user_id
        or plan.connection_type != ConnectionType.PPPOE
        or plan.plan_type == PlanType.FREE_TRIAL
        or float(plan.price or 0) <= 0
        or not plan_model_allows_router(plan, router_obj.id)
    ):
        raise HTTPException(status_code=400, detail="Pick one of the plans shown")

    phone = normalize_phone(request.phone) or normalize_phone(customer.phone)
    if not phone or len(phone) < 9:
        raise HTTPException(status_code=400, detail="Enter the M-Pesa phone number to send the prompt to")

    now = datetime.utcnow()
    recent = await _pending_txn(db, customer.id, now)
    if (
        recent is not None
        and recent.status == MpesaTransactionStatus.pending
        and (now - recent.created_at).total_seconds() < PAY_DUP_GUARD_SECONDS
    ):
        raise HTTPException(status_code=409, detail={
            "status": "payment_in_progress",
            "message": "A prompt was just sent. Check your phone, or wait a moment before trying again.",
        })

    amount = float(plan.price)
    reference = f"PPPOE-EXP-{customer.id}-{now.strftime('%Y%m%d%H%M%S')}"
    account_reference = (reseller.business_name or reseller.organization_name) if reseller else None
    if plan.id != customer.plan_id:
        customer.pending_update_data = json.dumps({
            "requested_at": now.isoformat(),
            "plan_id": plan.id,
            "plan_name": plan.name,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "payment_method": "mobile_money",
            "router_id": router_obj.id,
            "phone": phone,
            "source": "pppoe_expired_page",
        })
    else:
        customer.pending_update_data = None

    payment_method = await resolve_collection_payment_method(db, router_obj.id)
    if payment_method:
        try:
            gw = await initiate_customer_payment(
                db=db, payment_method=payment_method, customer=customer, router=router_obj,
                phone=phone, amount=amount, reference=reference, plan_name=plan.name,
                account_reference=account_reference,
            )
        except Exception as exc:
            await db.rollback()
            logger.warning("expired page: prompt failed for customer %s: %s", customer.id, exc)
            raise HTTPException(status_code=502, detail="Could not send the prompt. Please try again.")
        await db.commit()
        return {
            "status": "sent",
            "gateway": gw.get("gateway"),
            "checkout_request_id": gw.get("checkout_request_id"),
            "amount": amount,
            "phone_hint": _mask_phone(phone),
        }

    owner_shortcode = reseller.mpesa_shortcode if reseller else None
    customer_id, plan_id = customer.id, plan.id
    await db.commit()  # release the connection before Safaricom
    try:
        stk = await initiate_stk_push(
            phone_number=phone, amount=amount, reference=reference,
            user_id=router_obj.user_id, shortcode=owner_shortcode,
            account_reference=account_reference,
        )
    except Exception as exc:
        logger.warning("expired page: STK failed for customer %s: %s", customer_id, exc)
        async with db_module.async_session() as fdb:
            fdb.add(MpesaTransaction(
                checkout_request_id=f"FAILED-{reference}", phone_number=phone, amount=amount,
                reference=reference, customer_id=customer_id, plan_id=plan_id,
                collection_mode=CollectionMode.SYSTEM_COLLECTED,
                status=MpesaTransactionStatus.failed, failure_source=FailureSource.MPESA_API,
                result_code="STK_PUSH_FAILED", result_desc=f"STK Push initiation failed: {str(exc)[:450]}",
                created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
            ))
            await fdb.commit()
        raise HTTPException(status_code=502, detail="Could not send the prompt. Please try again.")

    async with db_module.async_session() as wdb:
        wdb.add(MpesaTransaction(
            checkout_request_id=stk.checkout_request_id,
            merchant_request_id=stk.merchant_request_id,
            phone_number=phone, amount=amount, reference=reference,
            customer_id=customer_id, plan_id=plan_id,
            collection_mode=CollectionMode.SYSTEM_COLLECTED,
            status=MpesaTransactionStatus.pending,
        ))
        await wdb.commit()
    return {
        "status": "sent",
        "gateway": "mpesa",
        "checkout_request_id": stk.checkout_request_id,
        "amount": amount,
        "phone_hint": _mask_phone(phone),
    }

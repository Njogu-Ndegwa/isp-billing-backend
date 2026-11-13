"""PPPoE device lock: "this login only works from the customer's own router".

* ``GET  /api/customers/{id}/pppoe-device-lock`` - state, plus recent rejected
  logins the router logged (only when its log lines were collected).
* ``PUT  /api/customers/{id}/pppoe-device-lock`` ``{"enabled": bool, "mac"?: str}``
  - turn the lock on (learns the device from the live session, or from the
  next connection) or off (clears caller-id on the router). ``mac`` binds a
  specific device by hand.
* ``POST /api/customers/{id}/pppoe-device-lock/allow-new-router`` - forget the
  bound device: caller-id is cleared on the router and the next connection
  that starts after now is learned.
* ``PUT  /api/routers/{id}/pppoe-device-lock-default`` ``{"enabled": bool}`` -
  new PPPoE customers registered on this router start with the lock on.
  Existing customers are not changed.

Behaviour and state: ``app/services/pppoe_device_lock.py``. The DB change is
committed first and the router I/O runs after with no session held; if the
router can't be reached the reconcile job applies it later, and the response
says so.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import database as db_module
from app.db.database import get_db
from app.db.models import Customer, CustomerEvent, Router
from app.services.auth import get_current_user, verify_token
from app.services.customer_events import record_customer_event
from app.services.pppoe_device_lock import lock_fields, normalize_mac, reconcile_customer_now
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger(__name__)
router = APIRouter(tags=["pppoe-device-lock"])

REJECTION_LOOKBACK = timedelta(days=14)


class DeviceLockRequest(BaseModel):
    enabled: bool
    mac: Optional[str] = Field(default=None, max_length=20)


class DeviceLockDefaultRequest(BaseModel):
    enabled: bool


async def _owned_pppoe_customer(db: AsyncSession, customer_id: int, user) -> Customer:
    customer = (await db.execute(
        select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
    )).scalar_one_or_none()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not customer.pppoe_username:
        raise HTTPException(status_code=400, detail="The device lock is only for PPPoE customers")
    if customer.router_id is None:
        raise HTTPException(status_code=400, detail="Customer has no router assigned")
    return customer


async def _recent_rejections(db: AsyncSession, customer_id: int) -> list[dict]:
    """Router log lines about this customer's login being refused.

    Only present when the router's log was read (the "Pull router logs now"
    button on the activity page, or the collector job).
    """
    since = datetime.utcnow() - REJECTION_LOOKBACK
    rows = (await db.execute(
        select(CustomerEvent)
        .where(
            CustomerEvent.customer_id == customer_id,
            CustomerEvent.category == "router_log",
            CustomerEvent.occurred_at >= since,
            or_(
                CustomerEvent.message.ilike("%authentication failed%"),
                CustomerEvent.message.ilike("%caller%"),
                CustomerEvent.message.ilike("%login failed%"),
            ),
        )
        .order_by(CustomerEvent.occurred_at.desc())
        .limit(10)
    )).scalars().all()
    return [
        {"occurred_at": r.occurred_at.isoformat() if r.occurred_at else None, "message": r.message}
        for r in rows
    ]


async def _state(customer_id: int) -> dict:
    async with db_module.async_session() as db:
        row = await db.get(Customer, customer_id)
        fields = lock_fields(row) if row is not None else {}
        rejections = await _recent_rejections(db, customer_id)
        await db.commit()
    return {"customer_id": customer_id, **fields, "recent_rejections": rejections}


def _router_note(outcome: dict) -> Optional[str]:
    if outcome.get("router_updated"):
        return None
    return (
        "The router could not be updated right now"
        + (f" ({outcome['error']})" if outcome.get("error") else "")
        + ". It will be updated automatically when it is reachable."
    )


@router.get("/api/customers/{customer_id}/pppoe-device-lock")
async def get_pppoe_device_lock(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    await _owned_pppoe_customer(db, customer_id, user)
    await db.commit()
    return await _state(customer_id)


@router.put("/api/customers/{customer_id}/pppoe-device-lock")
async def set_pppoe_device_lock(
    customer_id: int,
    request: DeviceLockRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Turn the device lock on or off for one PPPoE customer."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = await _owned_pppoe_customer(db, customer_id, user)

    manual_mac = None
    if request.mac:
        manual_mac = normalize_mac(request.mac)
        if manual_mac is None:
            raise HTTPException(status_code=400, detail="That is not a valid MAC address")

    was_locked = bool(customer.pppoe_device_lock)
    previous_mac = customer.pppoe_bound_mac
    now = datetime.utcnow()
    if request.enabled:
        customer.pppoe_device_lock = True
        if manual_mac:
            customer.pppoe_bound_mac = manual_mac
            customer.pppoe_bound_at = now
            customer.pppoe_lock_learn_after = None
        elif not was_locked:
            # Learn from whatever device is connected now (or connects next).
            customer.pppoe_bound_mac = None
            customer.pppoe_bound_at = None
            customer.pppoe_lock_learn_after = None
    else:
        customer.pppoe_device_lock = False
        customer.pppoe_bound_mac = None
        customer.pppoe_bound_at = None
        customer.pppoe_lock_learn_after = None
    owner_id, router_id = customer.user_id, customer.router_id
    await db.commit()  # nothing held across the router I/O below

    outcome = await reconcile_customer_now(customer_id, actor=user)

    if request.enabled:
        if manual_mac:
            message = f"PPPoE login locked to device {manual_mac} (set by hand)"
        elif outcome.get("learned_mac"):
            message = None  # persist_outcomes recorded the bind
        elif not was_locked:
            message = "PPPoE device lock turned on; waiting for the customer's router to connect"
        else:
            message = None
    else:
        message = (
            f"PPPoE device lock turned off (was locked to {previous_mac})"
            if previous_mac else "PPPoE device lock turned off"
        ) if was_locked else None
    if message:
        await record_customer_event(
            customer_id, "pppoe_device_lock_changed", message,
            actor=user, user_id=owner_id, router_id=router_id,
            details={"enabled": request.enabled, "mac": manual_mac or previous_mac},
        )
    logger.info("[PPPOE-LOCK] customer %s lock=%s by user %s (%s)",
                customer_id, request.enabled, user.id, outcome)

    state = await _state(customer_id)
    return {**state, "router_updated": outcome.get("router_updated", False),
            "router_note": _router_note(outcome)}


@router.post("/api/customers/{customer_id}/pppoe-device-lock/allow-new-router")
async def allow_new_router(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Forget the bound device so the customer can connect a new router.

    The lock stays on: the first connection that starts after now is learned
    as the new device. A session already up (the old router) is not.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = await _owned_pppoe_customer(db, customer_id, user)
    if not customer.pppoe_device_lock:
        raise HTTPException(status_code=400, detail="The device lock is not on for this customer")
    previous_mac = customer.pppoe_bound_mac
    customer.pppoe_bound_mac = None
    customer.pppoe_bound_at = None
    customer.pppoe_lock_learn_after = datetime.utcnow()
    owner_id, router_id = customer.user_id, customer.router_id
    await db.commit()

    outcome = await reconcile_customer_now(customer_id, actor=user)
    await record_customer_event(
        customer_id, "pppoe_device_unbound",
        f"New router allowed: lock to {previous_mac or 'no device'} cleared; "
        "the next router that connects will be locked in",
        actor=user, user_id=owner_id, router_id=router_id,
        details={"previous_mac": previous_mac},
    )
    state = await _state(customer_id)
    return {**state, "router_updated": outcome.get("router_updated", False),
            "router_note": _router_note(outcome)}


@router.put("/api/routers/{router_id}/pppoe-device-lock-default")
async def set_pppoe_device_lock_default(
    router_id: int,
    request: DeviceLockDefaultRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """New PPPoE customers on this router start locked to their first device."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = (await db.execute(
        select(Router).where(Router.id == router_id, Router.user_id == user.id)
    )).scalar_one_or_none()
    if router_obj is None:
        raise HTTPException(status_code=404, detail="Router not found or does not belong to you")
    router_obj.pppoe_lock_new_customers = request.enabled
    await db.commit()
    logger.info("[PPPOE-LOCK] router %s default lock=%s by user %s", router_id, request.enabled, user.id)
    return {
        "router_id": router_id,
        "pppoe_lock_new_customers": request.enabled,
        "message": (
            "New PPPoE customers on this router will be locked to their first router"
            if request.enabled
            else "New PPPoE customers on this router will not be locked"
        ),
    }

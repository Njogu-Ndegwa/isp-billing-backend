"""Opt-in PPPoE router lock (app/services/pppoe_router_lock.py).

* ``GET  /api/pppoe/router-lock`` - is the lock on for this reseller.
* ``PUT  /api/pppoe/router-lock`` - turn it on or off. Turning it on locks every
  existing PPPoE customer to their current router.
* ``POST /api/customers/{customer_id}/pppoe-router-lock/release`` - let one
  customer move once; the router they move to becomes the locked one.

No staff rule is listed for these, so they stay owner-only
(app/services/staff_permissions.py denies unlisted routes to staff).
Database only: nothing is written to any router.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Customer, User
from app.services import pppoe_router_lock
from app.services.auth import get_current_user, verify_token
from app.services.customer_events import record_customer_event
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger("pppoe_router_lock_routes")

router = APIRouter(tags=["pppoe-router-lock"])


class RouterLockToggle(BaseModel):
    enabled: bool


async def _locked_count(db: AsyncSession, user_id: int) -> int:
    return int((await db.execute(
        select(func.count(Customer.id)).where(
            Customer.user_id == user_id,
            Customer.pppoe_locked_router_id.isnot(None),
        )
    )).scalar() or 0)


@router.get("/api/pppoe/router-lock")
async def get_pppoe_router_lock(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    return {
        "enabled": pppoe_router_lock.lock_enabled(user),
        "locked_customers": await _locked_count(db, user.id),
    }


@router.put("/api/pppoe/router-lock")
async def set_pppoe_router_lock(
    request: RouterLockToggle,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Turn "Lock each PPPoE account to its first router" on or off.

    Off keeps the stamps (turning it back on re-locks customers to the same
    routers) but stops enforcing them.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    owner = await db.get(User, user.id)
    if owner is None:
        raise HTTPException(status_code=404, detail="Account not found")
    owner.pppoe_router_lock_enabled = bool(request.enabled)
    newly_locked = 0
    if request.enabled:
        newly_locked = await pppoe_router_lock.lock_existing_customers(db, owner.id)
    await db.commit()
    logger.info(
        "[PPPOE-LOCK] user %s set router lock=%s (newly locked %d)",
        owner.id, request.enabled, newly_locked,
    )
    return {
        "enabled": bool(request.enabled),
        "newly_locked": newly_locked,
        "locked_customers": await _locked_count(db, owner.id),
    }


@router.post("/api/customers/{customer_id}/pppoe-router-lock/release")
async def release_pppoe_router_lock(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Allow this one PPPoE customer to be moved to another router once."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = (await db.execute(
        select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
    )).scalar_one_or_none()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    previous = customer.pppoe_locked_router_id
    customer.pppoe_locked_router_id = None
    await db.commit()
    if previous is not None:
        await record_customer_event(
            customer.id, "pppoe_router_lock_released",
            f"PPPoE router lock released (was router #{previous}); "
            "the next router this customer is moved to becomes the locked one",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )
    return {"success": True, "customer_id": customer.id, "released_router_id": previous}

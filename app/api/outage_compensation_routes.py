"""Power-outage compensation endpoints.

Preview → apply flow, reseller-scoped: the reseller picks the outage window
(and optionally which routers were hit), previews exactly who gets credited
and by how much, then applies. Applying extends each affected customer's
expiry by the downtime — free time, not money, so revenue is untouched.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.outage_compensation import (
    OutageCompensationError,
    OutageOverlapError,
    apply_outage_compensation,
    get_outage_compensation,
    list_outage_compensations,
    list_retryable_items,
    preview_outage_compensation,
)
from app.services.outage_reprovision import schedule_reprovision

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/compensation", tags=["compensation"])


class OutageWindowRequest(BaseModel):
    outage_start: datetime
    outage_end: datetime
    # Omit for "all my routers"; otherwise only the routers the outage hit.
    router_ids: Optional[List[int]] = None
    # Customers the reseller unticked in the preview list.
    exclude_customer_ids: Optional[List[int]] = None
    # Also revive customers whose subscription ran out during/after the outage:
    # credit them from now and push them back onto the router.
    include_expired: bool = False


class OutageApplyRequest(OutageWindowRequest):
    note: Optional[str] = Field(None, max_length=500)
    # Required to re-apply when a previous run overlaps this window.
    allow_duplicate: bool = False


@router.post("/outage/preview")
async def preview_outage(
    request: OutageWindowRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Dry run: list who would be credited and by how much. No writes."""
    user = await get_current_user(token, db)
    try:
        return await preview_outage_compensation(
            db,
            reseller_id=user.id,
            outage_start=request.outage_start,
            outage_end=request.outage_end,
            router_ids=request.router_ids,
            exclude_customer_ids=request.exclude_customer_ids,
            include_expired=request.include_expired,
        )
    except OutageCompensationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/outage")
async def apply_outage(
    request: OutageApplyRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Apply the compensation: extend every affected customer's expiry."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    try:
        return await apply_outage_compensation(
            db,
            reseller_id=user.id,
            outage_start=request.outage_start,
            outage_end=request.outage_end,
            router_ids=request.router_ids,
            exclude_customer_ids=request.exclude_customer_ids,
            note=request.note,
            allow_duplicate=request.allow_duplicate,
            include_expired=request.include_expired,
        )
    except OutageOverlapError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except OutageCompensationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/outage/history")
async def outage_history(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Past compensation runs for the current reseller, newest first."""
    user = await get_current_user(token, db)
    return {"compensations": await list_outage_compensations(db, reseller_id=user.id, limit=limit)}


@router.get("/outage/{compensation_id}")
async def outage_detail(
    compensation_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """One run with its per-customer rows, including how re-provisioning went
    for anyone who had to be revived."""
    user = await get_current_user(token, db)
    detail = await get_outage_compensation(
        db, reseller_id=user.id, compensation_id=compensation_id
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="Compensation run not found")
    return detail


@router.post("/outage/{compensation_id}/retry-provisioning")
async def retry_outage_provisioning(
    compensation_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Re-run the router writes for revived customers that did not make it back
    online -- typically because their router was still dark right after the
    power cut. The time credit itself is already applied and is not touched."""
    user = await get_current_user(token, db)
    item_ids = await list_retryable_items(
        db, reseller_id=user.id, compensation_id=compensation_id
    )
    if item_ids is None:
        raise HTTPException(status_code=404, detail="Compensation run not found")
    if not item_ids:
        return {"queued": 0, "detail": "Nothing to retry"}
    schedule_reprovision(item_ids)
    return {"queued": len(item_ids)}

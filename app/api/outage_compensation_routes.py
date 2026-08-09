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
    list_outage_compensations,
    preview_outage_compensation,
)

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

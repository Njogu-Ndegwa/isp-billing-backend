from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import csv
import io

from app.db.database import get_db
from app.db.models import Voucher, VoucherStatus, Plan, Router
from app.services.auth import verify_token, get_current_user
from app.services.voucher_service import generate_vouchers

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vouchers", tags=["vouchers"])


class GenerateVouchersRequest(BaseModel):
    plan_id: int
    quantity: int = Field(ge=1, le=500, default=1)
    router_id: Optional[int] = None
    expires_at: Optional[datetime] = None


@router.post("/generate")
async def generate_vouchers_api(
    request: GenerateVouchersRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Generate voucher codes. Set quantity=1 for on-demand single voucher."""
    user = await get_current_user(token, db)

    result = await generate_vouchers(
        db=db,
        plan_id=request.plan_id,
        user_id=user.id,
        quantity=request.quantity,
        router_id=request.router_id,
        expires_at=request.expires_at,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.get("")
async def list_vouchers(
    status: Optional[str] = None,
    plan_id: Optional[int] = None,
    router_id: Optional[int] = None,
    batch_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List vouchers with filters. Only returns vouchers owned by the current user."""
    user = await get_current_user(token, db)

    stmt = (
        select(Voucher)
        .options(selectinload(Voucher.plan), selectinload(Voucher.router))
        .where(Voucher.user_id == user.id)
    )

    if status:
        try:
            status_enum = VoucherStatus(status.lower())
            stmt = stmt.where(Voucher.status == status_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Must be one of: {', '.join(s.value for s in VoucherStatus)}",
            )

    if plan_id:
        stmt = stmt.where(Voucher.plan_id == plan_id)
    if router_id:
        stmt = stmt.where(Voucher.router_id == router_id)
    if batch_id:
        stmt = stmt.where(Voucher.batch_id == batch_id)

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = stmt.order_by(Voucher.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(stmt)
    vouchers = result.scalars().all()

    return {
        "vouchers": [_voucher_to_dict(v) for v in vouchers],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page > 0 else 0,
    }


@router.get("/stats")
async def voucher_stats(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get voucher statistics for the current user."""
    user = await get_current_user(token, db)

    base = select(Voucher).where(Voucher.user_id == user.id)

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    available = (await db.execute(
        select(func.count()).select_from(
            base.where(Voucher.status == VoucherStatus.AVAILABLE).subquery()
        )
    )).scalar() or 0

    redeemed = (await db.execute(
        select(func.count()).select_from(
            base.where(Voucher.status == VoucherStatus.REDEEMED).subquery()
        )
    )).scalar() or 0

    expired = (await db.execute(
        select(func.count()).select_from(
            base.where(Voucher.status == VoucherStatus.EXPIRED).subquery()
        )
    )).scalar() or 0

    disabled = (await db.execute(
        select(func.count()).select_from(
            base.where(Voucher.status == VoucherStatus.DISABLED).subquery()
        )
    )).scalar() or 0

    # Revenue from redeemed vouchers
    revenue_stmt = (
        select(func.sum(Plan.price))
        .select_from(Voucher)
        .join(Plan, Voucher.plan_id == Plan.id)
        .where(Voucher.user_id == user.id, Voucher.status == VoucherStatus.REDEEMED)
    )
    revenue = (await db.execute(revenue_stmt)).scalar() or 0

    # Breakdown by plan
    plan_breakdown_stmt = (
        select(Plan.name, Plan.price, Voucher.status, func.count(Voucher.id))
        .join(Plan, Voucher.plan_id == Plan.id)
        .where(Voucher.user_id == user.id)
        .group_by(Plan.name, Plan.price, Voucher.status)
    )
    plan_rows = (await db.execute(plan_breakdown_stmt)).all()

    plans_summary: dict = {}
    for plan_name, price, v_status, count in plan_rows:
        if plan_name not in plans_summary:
            plans_summary[plan_name] = {"price": price, "available": 0, "redeemed": 0, "expired": 0, "disabled": 0, "total": 0}
        plans_summary[plan_name][v_status.value] = count
        plans_summary[plan_name]["total"] += count

    return {
        "total": total,
        "available": available,
        "redeemed": redeemed,
        "expired": expired,
        "disabled": disabled,
        "revenue": float(revenue),
        "by_plan": plans_summary,
    }


@router.get("/download")
async def download_vouchers(
    batch_id: Optional[str] = None,
    status: Optional[str] = None,
    plan_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Download vouchers as CSV."""
    user = await get_current_user(token, db)

    stmt = (
        select(Voucher)
        .options(selectinload(Voucher.plan), selectinload(Voucher.router))
        .where(Voucher.user_id == user.id)
    )

    if batch_id:
        stmt = stmt.where(Voucher.batch_id == batch_id)
    if status:
        try:
            stmt = stmt.where(Voucher.status == VoucherStatus(status.lower()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status filter")
    if plan_id:
        stmt = stmt.where(Voucher.plan_id == plan_id)

    stmt = stmt.order_by(Voucher.created_at.desc())
    result = await db.execute(stmt)
    vouchers = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Code", "Plan", "Price", "Speed", "Duration", "Status", "Router", "Created", "Redeemed At"])

    for v in vouchers:
        writer.writerow([
            v.code,
            v.plan.name if v.plan else "",
            v.plan.price if v.plan else "",
            v.plan.speed if v.plan else "",
            f"{v.plan.duration_value} {v.plan.duration_unit.value}" if v.plan else "",
            v.status.value,
            v.router.name if v.router else "Any",
            v.created_at.strftime("%Y-%m-%d %H:%M") if v.created_at else "",
            v.redeemed_at.strftime("%Y-%m-%d %H:%M") if v.redeemed_at else "",
        ])

    output.seek(0)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"vouchers_{timestamp}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.patch("/{voucher_id}/disable")
async def disable_voucher(
    voucher_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Disable a voucher so it can no longer be redeemed."""
    user = await get_current_user(token, db)

    result = await db.execute(
        select(Voucher).where(Voucher.id == voucher_id, Voucher.user_id == user.id)
    )
    voucher = result.scalar_one_or_none()

    if not voucher:
        raise HTTPException(status_code=404, detail="Voucher not found")

    if voucher.status == VoucherStatus.REDEEMED:
        raise HTTPException(status_code=400, detail="Cannot disable a redeemed voucher")

    voucher.status = VoucherStatus.DISABLED
    await db.commit()

    return {"message": "Voucher disabled", "voucher_id": voucher.id, "code": voucher.code}


def _voucher_to_dict(v: Voucher) -> dict:
    return {
        "id": v.id,
        "code": v.code,
        "status": v.status.value,
        "plan": {
            "id": v.plan.id,
            "name": v.plan.name,
            "price": v.plan.price,
            "speed": v.plan.speed,
            "duration": f"{v.plan.duration_value} {v.plan.duration_unit.value}",
        } if v.plan else None,
        "router": {
            "id": v.router.id,
            "name": v.router.name,
        } if v.router else None,
        "batch_id": v.batch_id,
        "redeemed_by": v.redeemed_by,
        "redeemed_at": v.redeemed_at.isoformat() if v.redeemed_at else None,
        "expires_at": v.expires_at.isoformat() if v.expires_at else None,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }

"""Customer usage / FUP read endpoints (frontend-facing)."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerUsagePeriod,
    Plan,
    UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services.usage_tracking import get_open_period

router = APIRouter(tags=["usage"])


# ------------------------------ Pydantic models ------------------------------


class PeriodOut(BaseModel):
    id: int
    period_start: datetime
    period_end: datetime
    upload_mb: float
    download_mb: float
    total_mb: float
    cap_mb: Optional[int]
    percent_used: Optional[float]
    fup_action: Optional[str]
    fup_triggered_at: Optional[datetime]
    fup_action_taken: Optional[str]
    fup_reverted_at: Optional[datetime]
    fup_active: bool
    closed_at: Optional[datetime]


class UsageOut(BaseModel):
    customer_id: int
    pppoe_username: Optional[str]
    plan_name: Optional[str]
    plan_data_cap_mb: Optional[int]
    plan_fup_action: Optional[str]
    period: Optional[PeriodOut]


class TopUsageItem(BaseModel):
    customer_id: int
    customer_name: Optional[str]
    pppoe_username: Optional[str]
    plan_name: Optional[str]
    cap_mb: Optional[int]
    total_mb: float
    percent_used: Optional[float]
    fup_active: bool


# ------------------------------ Helpers ------------------------------


def _bytes_to_mb(b: int) -> float:
    if not b:
        return 0.0
    return round(int(b) / (1024 * 1024), 2)


def _percent(used_bytes: int, cap_mb: Optional[int]) -> Optional[float]:
    if not cap_mb or cap_mb <= 0:
        return None
    cap_bytes = int(cap_mb) * 1024 * 1024
    if cap_bytes <= 0:
        return None
    return round((int(used_bytes) / cap_bytes) * 100, 2)


def _serialize_period(p: CustomerUsagePeriod) -> PeriodOut:
    fup_active = bool(p.fup_triggered_at and not p.fup_reverted_at)
    return PeriodOut(
        id=p.id,
        period_start=p.period_start,
        period_end=p.period_end,
        upload_mb=_bytes_to_mb(p.upload_bytes or 0),
        download_mb=_bytes_to_mb(p.download_bytes or 0),
        total_mb=_bytes_to_mb(p.total_bytes or 0),
        cap_mb=p.cap_mb_snapshot,
        percent_used=_percent(p.total_bytes or 0, p.cap_mb_snapshot),
        fup_action=p.fup_action_snapshot.value if p.fup_action_snapshot else None,
        fup_triggered_at=p.fup_triggered_at,
        fup_action_taken=p.fup_action_taken.value if p.fup_action_taken else None,
        fup_reverted_at=p.fup_reverted_at,
        fup_active=fup_active,
        closed_at=p.closed_at,
    )


async def _load_customer_scoped(
    db: AsyncSession, customer_id: int, user
) -> Customer:
    """Load a customer enforcing reseller scoping (admins see all)."""
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(Customer.id == customer_id)
    )
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Customer.user_id == user.id)
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not accessible")
    return customer


# ------------------------------ Endpoints ------------------------------


@router.get("/api/customers/{customer_id}/usage", response_model=UsageOut)
async def get_customer_usage(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Current open billing period for the customer + FUP status."""
    user = await get_current_user(token, db)
    customer = await _load_customer_scoped(db, customer_id, user)
    plan = customer.plan
    open_period = await get_open_period(db, customer.id)

    return UsageOut(
        customer_id=customer.id,
        pppoe_username=customer.pppoe_username,
        plan_name=plan.name if plan else None,
        plan_data_cap_mb=plan.data_cap_mb if plan else None,
        plan_fup_action=plan.fup_action.value if (plan and plan.fup_action) else None,
        period=_serialize_period(open_period) if open_period else None,
    )


@router.get(
    "/api/customers/{customer_id}/usage/history",
    response_model=list[PeriodOut],
)
async def get_customer_usage_history(
    customer_id: int,
    limit: int = Query(6, ge=1, le=60),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Past usage periods (most recent first), capped at ``limit``."""
    user = await get_current_user(token, db)
    customer = await _load_customer_scoped(db, customer_id, user)

    result = await db.execute(
        select(CustomerUsagePeriod)
        .where(CustomerUsagePeriod.customer_id == customer.id)
        .order_by(CustomerUsagePeriod.period_start.desc())
        .limit(limit)
    )
    return [_serialize_period(p) for p in result.scalars().all()]


@router.get(
    "/api/resellers/me/usage/top",
    response_model=list[TopUsageItem],
)
async def get_top_usage_for_reseller(
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Top customers by current-period bandwidth (PPPoE only)."""
    user = await get_current_user(token, db)

    customer_filter = [Plan.connection_type == ConnectionType.PPPOE]
    if user.role != UserRole.ADMIN:
        customer_filter.append(Customer.user_id == user.id)

    stmt = (
        select(
            Customer.id.label("customer_id"),
            Customer.name.label("customer_name"),
            Customer.pppoe_username.label("pppoe_username"),
            Plan.name.label("plan_name"),
            CustomerUsagePeriod.cap_mb_snapshot.label("cap_mb"),
            CustomerUsagePeriod.total_bytes.label("total_bytes"),
            CustomerUsagePeriod.fup_triggered_at.label("fup_triggered_at"),
            CustomerUsagePeriod.fup_reverted_at.label("fup_reverted_at"),
        )
        .join(Plan, Customer.plan_id == Plan.id)
        .join(CustomerUsagePeriod, CustomerUsagePeriod.customer_id == Customer.id)
        .where(
            CustomerUsagePeriod.closed_at.is_(None),
            *customer_filter,
        )
        .order_by(CustomerUsagePeriod.total_bytes.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()

    out: list[TopUsageItem] = []
    for r in rows:
        cap_mb = r.cap_mb
        total_bytes = int(r.total_bytes or 0)
        out.append(
            TopUsageItem(
                customer_id=r.customer_id,
                customer_name=r.customer_name,
                pppoe_username=r.pppoe_username,
                plan_name=r.plan_name,
                cap_mb=cap_mb,
                total_mb=_bytes_to_mb(total_bytes),
                percent_used=_percent(total_bytes, cap_mb),
                fup_active=bool(r.fup_triggered_at and not r.fup_reverted_at),
            )
        )
    return out

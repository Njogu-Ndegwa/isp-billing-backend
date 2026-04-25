"""Per-customer usage period tracking.

Each ``Customer`` has at most one *open* ``CustomerUsagePeriod`` row at a time
(``closed_at IS NULL``).  The bandwidth snapshot job calls :func:`record_usage`
to add reset-safe deltas to the open row, and renewal handlers call
:func:`open_new_period` to close the previous row and open a fresh one
anchored to the customer's new ``expiry``.

All functions use the supplied ``AsyncSession`` and DO NOT commit; the caller
controls the transaction boundary so writes can be batched with the snapshot
job's bigger transaction.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Customer,
    CustomerUsagePeriod,
    DurationUnit,
    Plan,
)


def _plan_duration(plan: Optional[Plan]) -> timedelta:
    """Best-effort duration of one plan cycle.  Falls back to 30 days."""
    if not plan:
        return timedelta(days=30)
    value = plan.duration_value or 0
    unit = plan.duration_unit
    if unit == DurationUnit.MINUTES:
        return timedelta(minutes=value)
    if unit == DurationUnit.HOURS:
        return timedelta(hours=value)
    if unit == DurationUnit.DAYS:
        return timedelta(days=value or 30)
    return timedelta(days=30)


def _period_window(customer: Customer, plan: Optional[Plan], now: datetime) -> tuple[datetime, datetime]:
    """Return (period_start, period_end) for a *new* period.

    Anchored to ``customer.expiry`` when available so the period boundary
    aligns with the renewal cycle.
    """
    duration = _plan_duration(plan)
    if customer.expiry:
        period_end = customer.expiry
        period_start = period_end - duration
        if period_start > now:
            period_start = now
    else:
        period_start = customer.created_at or now
        period_end = period_start + duration
    return period_start, period_end


async def get_open_period(
    db: AsyncSession, customer_id: int
) -> Optional[CustomerUsagePeriod]:
    """Return the currently-open period for the customer, or None."""
    result = await db.execute(
        select(CustomerUsagePeriod)
        .where(
            CustomerUsagePeriod.customer_id == customer_id,
            CustomerUsagePeriod.closed_at.is_(None),
        )
        .order_by(CustomerUsagePeriod.period_start.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_or_open_current_period(
    db: AsyncSession,
    customer: Customer,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> CustomerUsagePeriod:
    """Return the open period for ``customer``, creating one if missing.

    ``plan`` should be the customer's current plan (caller may pass a
    pre-loaded relationship to avoid an extra query).  Period boundaries are
    derived from ``customer.expiry`` minus plan duration.
    """
    now = now or datetime.utcnow()
    open_period = await get_open_period(db, customer.id)
    if open_period:
        return open_period

    plan = plan if plan is not None else customer.plan
    period_start, period_end = _period_window(customer, plan, now)

    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=period_start,
        period_end=period_end,
        upload_bytes=0,
        download_bytes=0,
        total_bytes=0,
        cap_mb_snapshot=plan.data_cap_mb if plan else None,
        fup_action_snapshot=plan.fup_action if plan else None,
        created_at=now,
        updated_at=now,
    )
    db.add(period)
    await db.flush()
    return period


async def record_usage(
    db: AsyncSession,
    customer: Customer,
    delta_upload_bytes: int,
    delta_download_bytes: int,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> CustomerUsagePeriod:
    """Add the given deltas onto the current open period and return it.

    Negative deltas are clamped to zero.  If no open period exists, one is
    created lazily.
    """
    delta_upload_bytes = max(0, int(delta_upload_bytes or 0))
    delta_download_bytes = max(0, int(delta_download_bytes or 0))

    period = await get_or_open_current_period(db, customer, plan=plan, now=now)
    if delta_upload_bytes or delta_download_bytes:
        period.upload_bytes = (period.upload_bytes or 0) + delta_upload_bytes
        period.download_bytes = (period.download_bytes or 0) + delta_download_bytes
        period.total_bytes = (period.total_bytes or 0) + delta_upload_bytes + delta_download_bytes
        period.updated_at = now or datetime.utcnow()
    return period


async def close_open_period(
    db: AsyncSession, customer_id: int, now: Optional[datetime] = None
) -> Optional[CustomerUsagePeriod]:
    """Mark the customer's currently-open period as closed.  No-op if none."""
    open_period = await get_open_period(db, customer_id)
    if not open_period:
        return None
    open_period.closed_at = now or datetime.utcnow()
    return open_period


async def open_new_period(
    db: AsyncSession,
    customer: Customer,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> CustomerUsagePeriod:
    """Close any open period and open a fresh one anchored to ``customer.expiry``.

    Called from renewal hooks (payment / m-pesa / momo / zenopay reconciliation)
    AFTER ``customer.expiry`` has been updated.
    """
    now = now or datetime.utcnow()
    await close_open_period(db, customer.id, now=now)
    return await get_or_open_current_period(db, customer, plan=plan, now=now)


async def on_renewal(
    db: AsyncSession,
    customer: Customer,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> Optional[CustomerUsagePeriod]:
    """Renewal hook: close current period, open a new one, and lift any FUP.

    Safe to call for any connection type; FUP revert is a no-op for non-PPPoE.
    All work uses the supplied session (no commit).  Failures are logged and
    swallowed so payment processing is never blocked by a router glitch.
    """
    import logging

    logger = logging.getLogger("usage_tracking")
    now = now or datetime.utcnow()

    try:
        previous = await close_open_period(db, customer.id, now=now)
    except Exception as e:
        logger.error(f"[USAGE] close_open_period failed for customer {customer.id}: {e}")
        previous = None

    try:
        from app.services.fup import revert as fup_revert

        await fup_revert(db, customer, plan=plan, period=previous, now=now)
    except Exception as e:
        logger.error(f"[USAGE] FUP revert failed for customer {customer.id}: {e}")

    try:
        return await get_or_open_current_period(db, customer, plan=plan, now=now)
    except Exception as e:
        logger.error(f"[USAGE] open new period failed for customer {customer.id}: {e}")
        return None

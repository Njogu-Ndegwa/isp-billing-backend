"""Daily FUP reset sweep.

Plans with ``fup_period = "daily"`` measure their data cap per local day. The
reset itself lives in :func:`app.services.fup.evaluate_and_enforce`: whenever a
customer is evaluated after the reset, a trigger from an earlier day is lifted
(full speed restored) and re-armed. Customers who are online get evaluated on
every usage sample anyway, so they come back within minutes of the reset.

This sweep covers the rest: a throttled customer who generates no traffic (a
PPPoE customer who is offline, an idle hotspot device whose queue is gone) is
never sampled, so nothing would ever evaluate them. Every couple of minutes it
picks up open periods on daily plans whose trigger predates today's reset and
runs the same evaluation for each.

Load: only customers FUP actually triggered on yesterday are candidates, in a
small batch per run with a time budget. A customer whose router could not be
reached is skipped for a while instead of blocking the head of the queue. DB
sessions follow the usual rule: the candidate query closes before any router
I/O, and the evaluation commits before it talks to the router.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.database import async_session
from app.db.models import Customer, CustomerStatus, CustomerUsagePeriod, Plan
from app.services.customer_grace import access_floor
from app.services.fup import evaluate_and_enforce
from app.services.usage_tracking import (
    FUP_PERIOD_DAILY,
    daily_fup_reset_utc,
    get_open_period,
)

logger = logging.getLogger("fup")

DAILY_RESET_BATCH = 40
DAILY_RESET_TIME_BUDGET = timedelta(seconds=100)
DAILY_RESET_RETRY_AFTER = timedelta(minutes=10)

# customer_id -> do not retry before. In-memory on purpose: losing it on a
# restart only means one extra attempt.
_retry_after: dict[int, datetime] = {}
_running = False


async def _due_customer_ids(now: datetime, limit: int) -> list[int]:
    reset = daily_fup_reset_utc(now)
    async with async_session() as db:
        rows = (
            await db.execute(
                select(CustomerUsagePeriod.customer_id)
                .join(Customer, Customer.id == CustomerUsagePeriod.customer_id)
                .join(Plan, Plan.id == Customer.plan_id)
                .where(
                    CustomerUsagePeriod.closed_at.is_(None),
                    CustomerUsagePeriod.fup_triggered_at.isnot(None),
                    CustomerUsagePeriod.fup_triggered_at < reset,
                    Plan.fup_period == FUP_PERIOD_DAILY,
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry > access_floor(now),
                )
                .order_by(CustomerUsagePeriod.fup_triggered_at)
                .limit(limit)
            )
        ).scalars().all()
        await db.commit()
    seen: set[int] = set()
    due: list[int] = []
    for customer_id in rows:
        if customer_id in seen:
            continue
        seen.add(customer_id)
        retry_at = _retry_after.get(customer_id)
        if retry_at is not None and retry_at > now:
            continue
        due.append(customer_id)
    return due


async def _reset_one(customer_id: int, now: datetime) -> Optional[bool]:
    """Evaluate one customer. True = reset done, False = still pending, None = gone."""
    reset = daily_fup_reset_utc(now)
    async with async_session() as db:
        customer = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan))
                .where(Customer.id == customer_id)
            )
        ).scalar_one_or_none()
        period = await get_open_period(db, customer_id) if customer else None
        if customer is None or period is None:
            await db.commit()
            return None
        await evaluate_and_enforce(db, customer, period, plan=customer.plan, now=now)
        done = period.fup_triggered_at is None or period.fup_triggered_at >= reset
        await db.commit()
        return done


async def reset_daily_fup_background(now: Optional[datetime] = None) -> dict:
    """APScheduler entrypoint: lift yesterday's daily-FUP throttles."""
    global _running
    if _running:
        return {"skipped": "already_running"}

    from app.services.mikrotik_background import _background_db_pool_is_busy

    if _background_db_pool_is_busy("FUP-DAILY-RESET"):
        return {"skipped": "db_busy"}

    _running = True
    started = datetime.utcnow()
    stats = {"candidates": 0, "reset": 0, "pending": 0, "errors": 0}
    try:
        now = now or datetime.utcnow()
        for stale_id, retry_at in list(_retry_after.items()):
            if retry_at <= now:
                _retry_after.pop(stale_id, None)
        customer_ids = await _due_customer_ids(now, DAILY_RESET_BATCH)
        stats["candidates"] = len(customer_ids)
        for customer_id in customer_ids:
            if datetime.utcnow() - started > DAILY_RESET_TIME_BUDGET:
                break
            try:
                done = await _reset_one(customer_id, now)
            except Exception as exc:
                stats["errors"] += 1
                _retry_after[customer_id] = now + DAILY_RESET_RETRY_AFTER
                logger.error("[FUP] Daily reset failed for customer %s: %s", customer_id, exc)
                continue
            if done:
                stats["reset"] += 1
                _retry_after.pop(customer_id, None)
            elif done is False:
                stats["pending"] += 1
                _retry_after[customer_id] = now + DAILY_RESET_RETRY_AFTER
        if customer_ids:
            logger.info("[FUP] Daily reset sweep: %s", stats)
        return stats
    finally:
        _running = False

"""Daily purge of expired soft-delete tombstones (docs/SOFT_DELETE_PLAN.md).

Rows tombstoned longer than SOFT_DELETE_RETENTION_DAYS ago are permanently
removed, table by table in children-first FK order (reversed
Base.metadata.sorted_tables — derived from the live metadata, so new models
are covered automatically with zero drift).

Ledger rule carried over from the old hard-delete flows: LIVE CustomerPayment
rows keep their revenue value forever, so before purging customers we NULL
customer_id / snapshot the name — exactly what the old delete endpoint did at
delete time. Same for live Voucher.redeemed_by references. DB-level
ON DELETE SET NULL / CASCADE FKs fire naturally here because the purge is a
real DELETE.

Database Session Discipline: one short transaction per table batch, no
network I/O anywhere, and the whole run steps aside when the pool is busy.
A batch that hits an unexpected FK (a live row still referencing a tombstone)
is logged and skipped; it retries on the next run — a referenced row staying
around an extra day is always safer than a broken purge.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import delete as sql_delete, select, update

from app.config import settings
from app.db import database as db_module
from app.db.database import Base, db_pool_snapshot
from app.db.models import Customer, CustomerPayment, Voucher


def async_session():
    """Late-bound so tests that rebind app.db.database.async_session are honored."""
    return db_module.async_session()

logger = logging.getLogger(__name__)

PURGE_BATCH_SIZE = 1000
_POOL_BUSY_THRESHOLD_PERCENT = 50


def _pool_is_busy() -> bool:
    snapshot = db_pool_snapshot()
    percent = snapshot.get("checked_out_percent")
    if isinstance(percent, (int, float)) and percent >= _POOL_BUSY_THRESHOLD_PERCENT:
        logger.warning(
            "[PURGE] Skipping purge run because DB pool is busy (%.2f%%)", percent
        )
        return True
    return False


async def _null_live_ledger_refs(cutoff: datetime) -> None:
    """Detach LIVE ledger rows from customers that are about to be purged."""
    async with async_session() as db:
        purged_customers = (
            select(Customer.id)
            .where(Customer.deleted_at.isnot(None), Customer.deleted_at < cutoff)
            .execution_options(include_deleted=True)
            .scalar_subquery()
        )
        # Snapshot the payer's name first so history keeps showing who paid.
        name_sq = (
            select(Customer.name)
            .where(Customer.id == CustomerPayment.customer_id)
            .execution_options(include_deleted=True)
            .scalar_subquery()
        )
        await db.execute(
            update(CustomerPayment)
            .where(
                CustomerPayment.customer_id.in_(purged_customers),
                CustomerPayment.customer_name.is_(None),
            )
            .values(customer_name=name_sq)
        )
        await db.execute(
            update(CustomerPayment)
            .where(CustomerPayment.customer_id.in_(purged_customers))
            .values(customer_id=None)
        )
        await db.execute(
            update(Voucher)
            .where(Voucher.redeemed_by.in_(purged_customers))
            .values(redeemed_by=None)
        )
        await db.commit()


async def purge_expired_tombstones(retention_days: int | None = None) -> dict:
    """Hard-delete rows whose deleted_at is older than the retention window.

    Returns {table_name: purged_row_count} for observability/tests.
    """
    if _pool_is_busy():
        return {}

    days = retention_days if retention_days is not None else settings.SOFT_DELETE_RETENTION_DAYS
    cutoff = datetime.utcnow() - timedelta(days=days)
    purged: dict[str, int] = {}

    await _null_live_ledger_refs(cutoff)

    # Children first, so parent rows never get purged while a tombstoned
    # child still references them.
    for table in reversed(Base.metadata.sorted_tables):
        if "deleted_at" not in table.c:
            continue
        total = 0
        while True:
            try:
                async with async_session() as db:
                    batch_ids = (
                        select(table.c.id)
                        .where(table.c.deleted_at.isnot(None), table.c.deleted_at < cutoff)
                        .limit(PURGE_BATCH_SIZE)
                    ) if "id" in table.c else None
                    if batch_ids is not None:
                        result = await db.execute(
                            sql_delete(table).where(table.c.id.in_(batch_ids))
                        )
                    else:  # tables with a non-id PK (e.g. app_settings)
                        result = await db.execute(
                            sql_delete(table).where(
                                table.c.deleted_at.isnot(None),
                                table.c.deleted_at < cutoff,
                            )
                        )
                    await db.commit()
                    count = result.rowcount or 0
            except Exception as e:
                logger.warning(
                    "[PURGE] Skipping table %s this run (%s); will retry next run",
                    table.name, e,
                )
                break
            total += count
            if batch_ids is None or count < PURGE_BATCH_SIZE:
                break
        if total:
            purged[table.name] = total
            logger.info("[PURGE] %s: permanently removed %d tombstoned row(s)", table.name, total)

    if purged:
        logger.info("[PURGE] Run complete: %s", purged)
    return purged


async def purge_expired_tombstones_background():
    """Scheduler entrypoint — never raises."""
    try:
        await purge_expired_tombstones()
    except Exception as e:
        logger.error(f"[PURGE] Purge run failed (non-fatal): {e}")

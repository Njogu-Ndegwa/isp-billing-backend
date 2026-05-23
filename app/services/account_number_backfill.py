"""
Backfill missing customers.account_number values.

Isolated as a service module (rather than inline in the CLI script) so the
same code path can later power an admin endpoint and so the logic is
unit-testable against the in-memory test DB without spawning a subprocess.

Idempotent: re-running picks up only the customers that are still missing
an account number. Safe to interrupt mid-run; finished customers stay
populated. Generator handles its own collision retries (see
app.services.account_numbers.generate_account_number), so concurrent
inserts during the backfill window are tolerated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Customer
from app.services.account_numbers import generate_account_number


DEFAULT_BATCH_SIZE = 100


@dataclass
class BackfillReport:
    """Result of a backfill run, returned to the CLI/admin caller."""
    total_missing: int = 0
    assigned: int = 0
    errored: int = 0
    dry_run: bool = True
    sample_assignments: List[dict] = field(default_factory=list)  # capped at 10

    @property
    def remaining(self) -> int:
        return self.total_missing - self.assigned - self.errored


async def _count_missing(db: AsyncSession) -> int:
    result = await db.execute(
        select(Customer.id).where(Customer.account_number.is_(None))
    )
    return len(result.scalars().all())


async def backfill_account_numbers(
    db: AsyncSession,
    *,
    dry_run: bool = True,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> BackfillReport:
    """Assign account_number to every Customer that doesn't have one.

    `dry_run=True` (default): counts how many customers would be touched
    and generates a few sample numbers, but commits nothing.

    `dry_run=False`: commits in batches of `batch_size`. Each batch is its
    own transaction so a mid-run failure only loses the in-flight batch.
    """
    report = BackfillReport(dry_run=dry_run)
    report.total_missing = await _count_missing(db)

    if report.total_missing == 0:
        return report

    if dry_run:
        # Generate a few sample numbers to prove the generator works, but
        # roll them back so nothing persists.
        for _ in range(min(5, report.total_missing)):
            n = await generate_account_number(db)
            report.sample_assignments.append({"account_number": n})
        await db.rollback()
        return report

    # Real run: iterate customers in chunks, assign + commit per batch
    offset = 0
    while True:
        chunk_stmt = (
            select(Customer)
            .where(Customer.account_number.is_(None))
            .order_by(Customer.id)
            .limit(batch_size)
        )
        chunk = (await db.execute(chunk_stmt)).scalars().all()
        if not chunk:
            break

        for customer in chunk:
            try:
                customer.account_number = await generate_account_number(db)
                report.assigned += 1
                if len(report.sample_assignments) < 10:
                    report.sample_assignments.append({
                        "customer_id": customer.id,
                        "account_number": customer.account_number,
                    })
            except Exception:
                report.errored += 1

        await db.commit()
        # After commit, the loop condition (account_number IS NULL) drops
        # the just-assigned rows from the next chunk automatically.
        offset += len(chunk)

    return report

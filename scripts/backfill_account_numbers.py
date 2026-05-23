"""
CLI: assign account_number to all customers that don't yet have one.

Run order in production after migrations/add_customer_account_number.py:

    # 1. Preview (no writes)
    python scripts/backfill_account_numbers.py

    # 2. Apply
    python scripts/backfill_account_numbers.py --apply

    # 3. Verify total_missing -> 0, then flip column NOT NULL
    python migrations/make_customer_account_number_not_null.py

Idempotent: safe to re-run. The actual logic lives in
app.services.account_number_backfill so it stays unit-testable and so an
admin endpoint can later trigger the same code path.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import async_engine, AsyncSessionLocal
from app.services.account_number_backfill import (
    DEFAULT_BATCH_SIZE,
    backfill_account_numbers,
)


def _print_report(report) -> None:
    mode = "DRY-RUN (no writes)" if report.dry_run else "APPLY"
    print(f"=== Account-number backfill: {mode} ===")
    print(f"  total_missing:  {report.total_missing}")
    print(f"  assigned:       {report.assigned}")
    print(f"  errored:        {report.errored}")
    print(f"  remaining:      {report.remaining}")
    if report.sample_assignments:
        label = "sample numbers (preview)" if report.dry_run else "first assignments"
        print(f"  {label}:")
        for s in report.sample_assignments:
            if "customer_id" in s:
                print(f"    customer_id={s['customer_id']} -> {s['account_number']}")
            else:
                print(f"    {s['account_number']}")
    if not report.dry_run and report.remaining == 0:
        print("\nDone. Safe to run migrations/make_customer_account_number_not_null.py")


async def main(dry_run: bool, batch_size: int) -> None:
    try:
        async with AsyncSessionLocal() as db:
            report = await backfill_account_numbers(
                db, dry_run=dry_run, batch_size=batch_size
            )
        _print_report(report)
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Assign customers.account_number to all customers missing one."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit changes. Without this flag, runs in DRY-RUN mode (default).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Customers per transaction batch (default: {DEFAULT_BATCH_SIZE})",
    )
    args = parser.parse_args()

    asyncio.run(main(dry_run=not args.apply, batch_size=args.batch_size))

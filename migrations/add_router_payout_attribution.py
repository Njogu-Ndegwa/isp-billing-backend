"""
Migration: pay each router's earnings to that router's own payment method.

Adds:
- customer_payments.router_id: which router earned this payment (snapshot).
- reseller_payouts.router_id:  which router's balance a payout settled.
- b2b_transactions.router_id:  carries the router through the async callback.

All three are nullable with no default. NULL means "reseller-level", which is
exactly how payouts behaved before this existed, so every historical row keeps
its current meaning and nothing needs backfilling. Revenue recorded before this
column existed stays unattributed and is paid to the reseller's default method.

The startup path in main.py (`run_router_payout_attribution_migrations`) applies
the same change on every boot; this script is for manual repair/inspection.

Idempotent: re-running is safe.

Usage:
    python migrations/add_router_payout_attribution.py
    python migrations/add_router_payout_attribution.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app.db.database import async_engine as engine


TARGETS = [
    ("customer_payments", "ix_customer_payments_router_id"),
    ("reseller_payouts", "ix_reseller_payouts_router_id"),
    ("b2b_transactions", None),
]


async def _column_exists(conn, table: str, column: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_name = :table AND column_name = :column
            """
        ),
        {"table": table, "column": column},
    )
    return result.fetchone() is not None


async def migrate():
    async with engine.begin() as conn:
        for table, index_name in TARGETS:
            if not await _column_exists(conn, table, "router_id"):
                await conn.execute(
                    text(
                        f"""
                        ALTER TABLE {table}
                        ADD COLUMN router_id INTEGER NULL
                        REFERENCES routers(id) ON DELETE SET NULL
                        """
                    )
                )
                print(f"  - {table}.router_id added")
            else:
                print(f"  - {table}.router_id already exists")

            if index_name:
                await conn.execute(
                    text(
                        f"CREATE INDEX IF NOT EXISTS {index_name} "
                        f"ON {table}(router_id)"
                    )
                )
                print(f"  - index {index_name} ready")

        attributed = await conn.execute(
            text("SELECT COUNT(*) FROM customer_payments WHERE router_id IS NOT NULL")
        )
        total = await conn.execute(text("SELECT COUNT(*) FROM customer_payments"))
        print(
            f"  - {attributed.scalar()} of {total.scalar()} payments are router-attributed "
            f"(the rest pay out to the reseller's default method)"
        )

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        for table, index_name in TARGETS:
            if index_name:
                await conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            await conn.execute(
                text(f"ALTER TABLE {table} DROP COLUMN IF EXISTS router_id")
            )
        print("Rollback completed. All payouts revert to a single per-reseller destination.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Per-router payout attribution migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

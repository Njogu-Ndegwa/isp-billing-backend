"""
Migration: Flip customers.account_number from NULL-able to NOT NULL.

Prerequisite: every existing customer must already have a non-null
account_number. Run scripts/backfill_account_numbers.py --apply first
and verify report.remaining == 0.

This migration will FAIL (and roll back cleanly) if any customer is still
missing a number — by design. Better to fail here than to corrupt the
constraint guarantee that every customer has a stable C2B identifier.

Usage:
    python migrations/make_customer_account_number_not_null.py
    python migrations/make_customer_account_number_not_null.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        missing = await conn.execute(text("""
            SELECT COUNT(*) FROM customers WHERE account_number IS NULL
        """))
        missing_count = missing.scalar() or 0
        if missing_count > 0:
            raise RuntimeError(
                f"Refusing to set NOT NULL: {missing_count} customer(s) still "
                "lack an account_number. Run scripts/backfill_account_numbers.py "
                "--apply first."
            )

        await conn.execute(text("""
            ALTER TABLE customers
            ALTER COLUMN account_number SET NOT NULL
        """))
        print("Migration completed: customers.account_number is now NOT NULL.")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE customers
            ALTER COLUMN account_number DROP NOT NULL
        """))
        print("Rollback completed: customers.account_number is now nullable again.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Make customers.account_number NOT NULL")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

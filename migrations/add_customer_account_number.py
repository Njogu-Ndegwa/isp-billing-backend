"""
Migration: Add account_number column to customers table

Adds a nullable VARCHAR(8) account_number with a UNIQUE index. Nullable
initially so existing customers can be backfilled lazily by
scripts/backfill_account_numbers.py. A follow-up migration
(make_customer_account_number_not_null.py) flips it to NOT NULL after
backfill is verified.

This column carries the C2B Paybill BillRefNumber — what a customer types
into the M-Pesa Paybill menu to identify themselves. Format: 8 digits,
Luhn-validated. See app/services/account_numbers.py for the generator.

Usage:
    python migrations/add_customer_account_number.py
    python migrations/add_customer_account_number.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add account_number column and unique index to customers table."""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'customers' AND column_name = 'account_number'
        """))

        if result.fetchone():
            print("Column 'account_number' already exists on customers table. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE customers
            ADD COLUMN account_number VARCHAR(8) NULL
        """))

        await conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS ix_customers_account_number
            ON customers (account_number)
        """))

        print("Migration completed successfully!")
        print("  - Added nullable VARCHAR(8) 'account_number' column to customers")
        print("  - Created unique index ix_customers_account_number")
        print("Next: run scripts/backfill_account_numbers.py --apply to populate.")


async def rollback():
    """Drop account_number column and its unique index."""
    async with engine.begin() as conn:
        await conn.execute(text("""
            DROP INDEX IF EXISTS ix_customers_account_number
        """))
        await conn.execute(text("""
            ALTER TABLE customers
            DROP COLUMN IF EXISTS account_number
        """))
        print("Rollback completed: account_number column and index dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Customer account_number migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

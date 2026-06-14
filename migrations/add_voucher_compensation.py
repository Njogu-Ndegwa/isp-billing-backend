"""
Migration: Add compensation-voucher support.

  * vouchers.voucher_type   — enum (sale | compensation), default 'sale'
  * customer_payments.counts_as_revenue — boolean, default TRUE

A compensation voucher provisions internet identically to a sale voucher but
its recorded payment is flagged counts_as_revenue = FALSE, so it is excluded
from total_revenue and from the 3% hotspot commission base. Existing rows are
all sales / revenue, which the defaults express — no backfill required.

Usage:
    python migrations/add_voucher_compensation.py
    python migrations/add_voucher_compensation.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        # 1. Create the enum type if it does not exist.
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE vouchertype AS ENUM ('sale', 'compensation');
            EXCEPTION WHEN duplicate_object THEN null;
            END $$;
        """))

        # 2. vouchers.voucher_type
        result = await conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'vouchers' AND column_name = 'voucher_type'
        """))
        if result.fetchone():
            print("Column 'vouchers.voucher_type' already exists. Skipping.")
        else:
            await conn.execute(text("""
                ALTER TABLE vouchers
                ADD COLUMN voucher_type vouchertype NOT NULL DEFAULT 'sale'
            """))
            print("  - Added vouchers.voucher_type (default 'sale')")

        # 3. customer_payments.counts_as_revenue
        result = await conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'customer_payments' AND column_name = 'counts_as_revenue'
        """))
        if result.fetchone():
            print("Column 'customer_payments.counts_as_revenue' already exists. Skipping.")
        else:
            await conn.execute(text("""
                ALTER TABLE customer_payments
                ADD COLUMN counts_as_revenue BOOLEAN NOT NULL DEFAULT TRUE
            """))
            print("  - Added customer_payments.counts_as_revenue (default TRUE)")

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE customer_payments DROP COLUMN IF EXISTS counts_as_revenue
        """))
        await conn.execute(text("""
            ALTER TABLE vouchers DROP COLUMN IF EXISTS voucher_type
        """))
        await conn.execute(text("DROP TYPE IF EXISTS vouchertype"))
        print("Rollback completed: voucher_type, counts_as_revenue, vouchertype dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Compensation voucher migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

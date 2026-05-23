"""
Migration: Add wallet_credit_kes column to customers table

C2B Paybill credits overpayments to a per-customer wallet. On the next
renewal, the wallet is applied first so the customer effectively pays
(plan.price - wallet_credit_kes) out of pocket. Wallet is replaced (not
incremented) on each successful activation — see app/services/c2b_handler.py
(added in step 6).

NOT NULL with default 0 and a CHECK constraint preventing negative balances.
Integer kept in Kenya shillings (no fractions), matching Plan.price's type.

Usage:
    python migrations/add_customer_wallet_credit.py
    python migrations/add_customer_wallet_credit.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add wallet_credit_kes column with default 0 and non-negative CHECK."""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'customers' AND column_name = 'wallet_credit_kes'
        """))

        if result.fetchone():
            print("Column 'wallet_credit_kes' already exists. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE customers
            ADD COLUMN wallet_credit_kes INTEGER NOT NULL DEFAULT 0
        """))

        await conn.execute(text("""
            ALTER TABLE customers
            ADD CONSTRAINT ck_customers_wallet_credit_non_negative
            CHECK (wallet_credit_kes >= 0)
        """))

        print("Migration completed successfully!")
        print("  - Added wallet_credit_kes INTEGER NOT NULL DEFAULT 0 on customers")
        print("  - Added CHECK constraint ck_customers_wallet_credit_non_negative")


async def rollback():
    """Drop the CHECK constraint and the column."""
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE customers
            DROP CONSTRAINT IF EXISTS ck_customers_wallet_credit_non_negative
        """))
        await conn.execute(text("""
            ALTER TABLE customers
            DROP COLUMN IF EXISTS wallet_credit_kes
        """))
        print("Rollback completed: wallet_credit_kes column and constraint dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Customer wallet_credit_kes migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

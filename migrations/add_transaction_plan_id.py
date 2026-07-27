"""
Migration: Add plan_id snapshot column to mpesa_transactions and
customer_payments.

The transactions list used to resolve each row's plan through
Customer.plan_id, which is overwritten on every purchase — so all
historical rows silently updated to the customer's latest plan.
Snapshotting the purchased plan on the transaction itself fixes that.

Nullable with ON DELETE SET NULL so deleting a plan preserves the
payment history. Legacy rows stay NULL and the API falls back to the
customer's current plan for them.

Usage:
    python migrations/add_transaction_plan_id.py
    python migrations/add_transaction_plan_id.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine

TABLES = ("mpesa_transactions", "customer_payments")


async def migrate():
    """Add plan_id column + FK to both transaction tables."""
    async with engine.begin() as conn:
        for table in TABLES:
            result = await conn.execute(text(f"""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = '{table}' AND column_name = 'plan_id'
            """))
            if result.fetchone():
                print(f"Column 'plan_id' already exists on {table}. Skipping.")
                continue

            await conn.execute(text(f"""
                ALTER TABLE {table}
                ADD COLUMN plan_id INTEGER
            """))
            await conn.execute(text(f"""
                ALTER TABLE {table}
                ADD CONSTRAINT fk_{table}_plan_id
                FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE SET NULL
            """))
            print(f"  - Added plan_id INTEGER NULL + fk_{table}_plan_id on {table}")

        print("Migration completed successfully!")


async def rollback():
    """Drop the FK constraint and the column from both tables."""
    async with engine.begin() as conn:
        for table in TABLES:
            await conn.execute(text(f"""
                ALTER TABLE {table}
                DROP CONSTRAINT IF EXISTS fk_{table}_plan_id
            """))
            await conn.execute(text(f"""
                ALTER TABLE {table}
                DROP COLUMN IF EXISTS plan_id
            """))
            print(f"  - Dropped plan_id from {table}")
        print("Rollback completed.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Transaction plan_id snapshot migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

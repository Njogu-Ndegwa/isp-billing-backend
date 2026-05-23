"""
Migration: Add c2b_validation_url, c2b_confirmation_url, c2b_registered_at
to reseller_payment_methods.

Resellers using their own paybill (method_type=MPESA_PAYBILL_WITH_KEYS)
register Validation + Confirmation URLs with Safaricom Daraja via
POST /api/payment-methods/{id}/register-c2b (added in step 6). Storing the
URLs here lets us re-register on URL changes and show the operator which
endpoints Safaricom is calling for each paybill.

Usage:
    python migrations/add_c2b_urls_to_payment_methods.py
    python migrations/add_c2b_urls_to_payment_methods.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


COLUMNS = [
    ("c2b_validation_url", "VARCHAR(500) NULL"),
    ("c2b_confirmation_url", "VARCHAR(500) NULL"),
    ("c2b_registered_at", "TIMESTAMP NULL"),
]


async def migrate():
    async with engine.begin() as conn:
        for col_name, col_type in COLUMNS:
            exists = await conn.execute(text(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'reseller_payment_methods'
                  AND column_name = '{col_name}'
            """))
            if exists.fetchone():
                print(f"Column '{col_name}' already exists. Skipping.")
                continue
            await conn.execute(text(f"""
                ALTER TABLE reseller_payment_methods
                ADD COLUMN {col_name} {col_type}
            """))
            print(f"  + Added '{col_name}' {col_type}")
        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        for col_name, _ in COLUMNS:
            await conn.execute(text(f"""
                ALTER TABLE reseller_payment_methods
                DROP COLUMN IF EXISTS {col_name}
            """))
        print("Rollback completed: C2B URL columns dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ResellerPaymentMethod C2B URL migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

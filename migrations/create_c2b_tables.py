"""
Migration: Create c2b_transactions and unmatched_c2b_payments tables.

- c2b_transactions archives every Safaricom C2B confirmation we receive.
  trans_id UNIQUE is the idempotency anchor (Safaricom retries on errors).
- unmatched_c2b_payments buffers payments that didn't auto-apply, so the
  paybill-owning reseller can attribute them to a customer manually.

Both tables are read by handlers introduced in step 6 (app/api/c2b_routes.py
and app/services/c2b_handler.py).

Usage:
    python migrations/create_c2b_tables.py
    python migrations/create_c2b_tables.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        # Enum types (PostgreSQL native enum). IF NOT EXISTS guards re-runs.
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE c2btransactionstatus AS ENUM ('processed', 'unmatched', 'rejected', 'duplicate');
            EXCEPTION WHEN duplicate_object THEN null; END $$;
        """))
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE unmatchedc2breason AS ENUM ('unknown_account', 'amount_too_low', 'wrong_reseller', 'invalid_luhn');
            EXCEPTION WHEN duplicate_object THEN null; END $$;
        """))

        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS c2b_transactions (
                id                  SERIAL PRIMARY KEY,
                trans_id            VARCHAR(64) NOT NULL UNIQUE,
                bill_ref_number     VARCHAR(64) NULL,
                trans_amount        DOUBLE PRECISION NOT NULL,
                msisdn              VARCHAR(20) NULL,
                business_shortcode  VARCHAR(20) NULL,
                payload_json        JSONB NULL,
                status              c2btransactionstatus NOT NULL,
                matched_customer_id INTEGER NULL REFERENCES customers(id) ON DELETE SET NULL,
                matched_reseller_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                received_at         TIMESTAMP NOT NULL DEFAULT NOW(),
                processed_at        TIMESTAMP NULL
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_trans_id ON c2b_transactions(trans_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_bill_ref ON c2b_transactions(bill_ref_number)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_shortcode ON c2b_transactions(business_shortcode)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_matched_customer ON c2b_transactions(matched_customer_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_matched_reseller ON c2b_transactions(matched_reseller_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_c2b_transactions_received_at ON c2b_transactions(received_at)"))

        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS unmatched_c2b_payments (
                id                       SERIAL PRIMARY KEY,
                c2b_transaction_id       INTEGER NOT NULL UNIQUE REFERENCES c2b_transactions(id) ON DELETE CASCADE,
                reason                   unmatchedc2breason NOT NULL,
                assigned_reseller_id     INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                resolved_at              TIMESTAMP NULL,
                resolved_by_user_id      INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                resolution_customer_id   INTEGER NULL REFERENCES customers(id) ON DELETE SET NULL,
                notes                    VARCHAR(500) NULL
            )
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_unmatched_c2b_assigned_reseller ON unmatched_c2b_payments(assigned_reseller_id)"))

        print("Migration completed!")
        print("  - Created c2b_transactions + indexes")
        print("  - Created unmatched_c2b_payments + indexes")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS unmatched_c2b_payments"))
        await conn.execute(text("DROP TABLE IF EXISTS c2b_transactions"))
        await conn.execute(text("DROP TYPE IF EXISTS unmatchedc2breason"))
        await conn.execute(text("DROP TYPE IF EXISTS c2btransactionstatus"))
        print("Rollback completed: C2B tables and enum types dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Create C2B tables")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

"""
Migration: MTN MoMo Collection integration

Adds the database objects required for per-reseller MTN Mobile Money
(RequestToPay) support:

  * Adds ``mtn_momo`` to the ``resellerpaymentmethodtype`` enum (PostgreSQL).
  * Adds 6 new columns to ``reseller_payment_methods``:
        mtn_api_user, mtn_api_key_encrypted, mtn_subscription_key_encrypted,
        mtn_target_environment, mtn_base_url, mtn_currency
  * Creates the ``mtnmomotransactionstatus`` enum (pending/successful/failed).
  * Creates the ``mtn_momo_transactions`` table.

Safe to run multiple times — skips objects that already exist.

Usage:
    python migrations/create_mtn_momo_tables.py

Rollback (drops the table + new columns + the status enum; the added
enum-value ``mtn_momo`` cannot be removed from ``resellerpaymentmethodtype``
without recreating the type, so it is left in place):
    python migrations/create_mtn_momo_tables.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def _table_exists(conn, table_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = :t
            """
        ),
        {"t": table_name},
    )
    return result.fetchone() is not None


async def _column_exists(conn, table_name: str, column_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = :t
              AND column_name = :c
            """
        ),
        {"t": table_name, "c": column_name},
    )
    return result.fetchone() is not None


MTN_COLUMNS: list[tuple[str, str]] = [
    ("mtn_api_user", "VARCHAR(64)"),
    ("mtn_api_key_encrypted", "VARCHAR(500)"),
    ("mtn_subscription_key_encrypted", "VARCHAR(500)"),
    ("mtn_target_environment", "VARCHAR(50)"),
    ("mtn_base_url", "VARCHAR(255)"),
    ("mtn_currency", "VARCHAR(10)"),
]


async def migrate():
    # --- Step 1: extend the existing payment-method-type enum ---------------
    # ``ALTER TYPE ... ADD VALUE`` must commit on its own so later SQL (in
    # particular any code path that persists a row using the new value) can
    # see it.  Older Postgres (<12) also refuses to run ADD VALUE inside a
    # transaction block, so we isolate it in its own ``begin()`` context.
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "ALTER TYPE resellerpaymentmethodtype "
                "ADD VALUE IF NOT EXISTS 'mtn_momo'"
            )
        )
    print("  Ensured enum value: resellerpaymentmethodtype.mtn_momo")

    async with engine.begin() as conn:
        # --- New enum for MTN transaction status -----------------------------
        await conn.execute(
            text(
                """
                DO $$ BEGIN
                    CREATE TYPE mtnmomotransactionstatus AS ENUM (
                        'pending',
                        'successful',
                        'failed'
                    );
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
                """
            )
        )
        print("  Ensured enum type: mtnmomotransactionstatus")

        # --- New columns on reseller_payment_methods -------------------------
        for column_name, column_type in MTN_COLUMNS:
            if not await _column_exists(conn, "reseller_payment_methods", column_name):
                await conn.execute(
                    text(
                        f"ALTER TABLE reseller_payment_methods "
                        f"ADD COLUMN {column_name} {column_type} NULL"
                    )
                )
                print(f"  Added column: reseller_payment_methods.{column_name}")
            else:
                print(f"  Column already present: reseller_payment_methods.{column_name}")

        # --- mtn_momo_transactions table -------------------------------------
        if not await _table_exists(conn, "mtn_momo_transactions"):
            await conn.execute(
                text(
                    """
                    CREATE TABLE mtn_momo_transactions (
                        id SERIAL PRIMARY KEY,
                        reference_id VARCHAR(64) NOT NULL UNIQUE,
                        external_id VARCHAR(64),
                        reseller_id INTEGER NOT NULL REFERENCES users(id),
                        customer_id INTEGER REFERENCES customers(id),
                        amount NUMERIC(10, 2) NOT NULL,
                        currency VARCHAR(10) NOT NULL,
                        phone VARCHAR(20) NOT NULL,
                        status mtnmomotransactionstatus NOT NULL DEFAULT 'pending',
                        financial_transaction_id VARCHAR(128),
                        reason_code VARCHAR(100),
                        reason_message VARCHAR(500),
                        target_environment VARCHAR(50) NOT NULL,
                        payer_message VARCHAR(160),
                        payee_note VARCHAR(160),
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW()
                    )
                    """
                )
            )
            await conn.execute(
                text("CREATE INDEX idx_mtn_momo_reference_id ON mtn_momo_transactions(reference_id)")
            )
            await conn.execute(
                text("CREATE INDEX idx_mtn_momo_external_id ON mtn_momo_transactions(external_id)")
            )
            await conn.execute(
                text("CREATE INDEX idx_mtn_momo_reseller_id ON mtn_momo_transactions(reseller_id)")
            )
            await conn.execute(
                text("CREATE INDEX idx_mtn_momo_customer_id ON mtn_momo_transactions(customer_id)")
            )
            await conn.execute(
                text("CREATE INDEX idx_mtn_momo_status ON mtn_momo_transactions(status)")
            )
            print("  Created table: mtn_momo_transactions")
        else:
            print("  Table mtn_momo_transactions already exists, skipping")

        print("MTN MoMo migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS mtn_momo_transactions CASCADE"))
        print("  Dropped table: mtn_momo_transactions")

        await conn.execute(text("DROP TYPE IF EXISTS mtnmomotransactionstatus"))
        print("  Dropped type:  mtnmomotransactionstatus")

        for column_name, _ in MTN_COLUMNS:
            await conn.execute(
                text(f"ALTER TABLE reseller_payment_methods DROP COLUMN IF EXISTS {column_name}")
            )
            print(f"  Dropped column: reseller_payment_methods.{column_name}")

        # NOTE: removing an enum value from resellerpaymentmethodtype requires
        # recreating the type and re-pointing all columns, which is risky for a
        # rollback script.  We leave ``mtn_momo`` in the enum — rows using it
        # would have been deleted above (CASCADE) or will fail-fast if reused.
        print("Rollback completed (enum value 'mtn_momo' left in place on purpose).")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MTN MoMo tables migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

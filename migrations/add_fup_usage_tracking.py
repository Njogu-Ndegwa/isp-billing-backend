"""
Migration: Add per-customer FUP / monthly usage tracking

- Adds ``data_cap_mb``, ``fup_action``, ``fup_throttle_profile`` columns to ``plans``.
- Adds ``last_upload_bytes`` / ``last_download_bytes`` to ``user_bandwidth_usage`` so
  the bandwidth snapshot job can compute reset-safe deltas.
- Creates ``customer_usage_periods`` table holding per-period cumulative usage
  (anchored to ``customers.expiry``) and FUP enforcement state.

Idempotent: re-running is safe; each ALTER/CREATE is gated on existence checks.

Usage:
    python migrations/add_fup_usage_tracking.py
    python migrations/add_fup_usage_tracking.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


FUP_ENUM_VALUES = ("throttle", "block", "notify_only")


async def _column_exists(conn, table: str, column: str) -> bool:
    result = await conn.execute(text(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = :t AND column_name = :c
        """
    ), {"t": table, "c": column})
    return result.fetchone() is not None


async def _table_exists(conn, table: str) -> bool:
    result = await conn.execute(text(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_name = :t
        """
    ), {"t": table})
    return result.fetchone() is not None


async def _ensure_fup_enum(conn):
    """Create the fupaction enum if it doesn't already exist."""
    exists = await conn.execute(text(
        "SELECT 1 FROM pg_type WHERE typname = 'fupaction'"
    ))
    if exists.fetchone():
        return
    values_sql = ", ".join(f"'{v}'" for v in FUP_ENUM_VALUES)
    await conn.execute(text(f"CREATE TYPE fupaction AS ENUM ({values_sql})"))
    print("  - Created enum 'fupaction'")


async def migrate():
    async with engine.begin() as conn:
        await _ensure_fup_enum(conn)

        if not await _column_exists(conn, "plans", "data_cap_mb"):
            await conn.execute(text(
                "ALTER TABLE plans ADD COLUMN data_cap_mb BIGINT NULL"
            ))
            print("  - plans.data_cap_mb added")
        else:
            print("  - plans.data_cap_mb already exists")

        if not await _column_exists(conn, "plans", "fup_action"):
            await conn.execute(text(
                "ALTER TABLE plans ADD COLUMN fup_action fupaction NULL"
            ))
            print("  - plans.fup_action added")
        else:
            print("  - plans.fup_action already exists")

        if not await _column_exists(conn, "plans", "fup_throttle_profile"):
            await conn.execute(text(
                "ALTER TABLE plans ADD COLUMN fup_throttle_profile VARCHAR(100) NULL"
            ))
            print("  - plans.fup_throttle_profile added")
        else:
            print("  - plans.fup_throttle_profile already exists")

        if not await _column_exists(conn, "user_bandwidth_usage", "last_upload_bytes"):
            await conn.execute(text(
                "ALTER TABLE user_bandwidth_usage "
                "ADD COLUMN last_upload_bytes BIGINT NOT NULL DEFAULT 0"
            ))
            print("  - user_bandwidth_usage.last_upload_bytes added")
        else:
            print("  - user_bandwidth_usage.last_upload_bytes already exists")

        if not await _column_exists(conn, "user_bandwidth_usage", "last_download_bytes"):
            await conn.execute(text(
                "ALTER TABLE user_bandwidth_usage "
                "ADD COLUMN last_download_bytes BIGINT NOT NULL DEFAULT 0"
            ))
            print("  - user_bandwidth_usage.last_download_bytes added")
        else:
            print("  - user_bandwidth_usage.last_download_bytes already exists")

        if not await _table_exists(conn, "customer_usage_periods"):
            await conn.execute(text(
                """
                CREATE TABLE customer_usage_periods (
                    id SERIAL PRIMARY KEY,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    period_start TIMESTAMP NOT NULL,
                    period_end TIMESTAMP NOT NULL,
                    upload_bytes BIGINT NOT NULL DEFAULT 0,
                    download_bytes BIGINT NOT NULL DEFAULT 0,
                    total_bytes BIGINT NOT NULL DEFAULT 0,
                    cap_mb_snapshot BIGINT NULL,
                    fup_action_snapshot fupaction NULL,
                    fup_triggered_at TIMESTAMP NULL,
                    fup_action_taken fupaction NULL,
                    fup_reverted_at TIMESTAMP NULL,
                    closed_at TIMESTAMP NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_customer_period_start UNIQUE (customer_id, period_start)
                )
                """
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_customer_id "
                "ON customer_usage_periods (customer_id)"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_period_start "
                "ON customer_usage_periods (period_start)"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_closed_at "
                "ON customer_usage_periods (closed_at)"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_customer_open "
                "ON customer_usage_periods (customer_id, closed_at)"
            ))
            print("  - customer_usage_periods table created")
        else:
            print("  - customer_usage_periods already exists")

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS customer_usage_periods"))
        await conn.execute(text(
            "ALTER TABLE user_bandwidth_usage DROP COLUMN IF EXISTS last_upload_bytes"
        ))
        await conn.execute(text(
            "ALTER TABLE user_bandwidth_usage DROP COLUMN IF EXISTS last_download_bytes"
        ))
        await conn.execute(text("ALTER TABLE plans DROP COLUMN IF EXISTS fup_throttle_profile"))
        await conn.execute(text("ALTER TABLE plans DROP COLUMN IF EXISTS fup_action"))
        await conn.execute(text("ALTER TABLE plans DROP COLUMN IF EXISTS data_cap_mb"))
        await conn.execute(text("DROP TYPE IF EXISTS fupaction"))
        print("Rollback completed.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="FUP / monthly usage migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

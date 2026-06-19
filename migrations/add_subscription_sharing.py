"""
Migration: Add plan-level customer subscription sharing.

Adds:
- plans.max_shared_users: total devices/customers allowed on one paid plan.
- customers.subscription_owner_id: companion customer rows that share an owner.
- device_pairings subscription sharing metadata.
- subscription_share_codes: one-time codes for phone/laptop-friendly sharing.
- provisioning enum values used for shared-device delivery attempts.

Idempotent: re-running is safe.

Usage:
    python migrations/add_subscription_sharing.py
    python migrations/add_subscription_sharing.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app.db.database import async_engine as engine


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


async def _index_exists(conn, index_name: str) -> bool:
    result = await conn.execute(
        text(
            """
            SELECT 1 FROM pg_indexes
            WHERE indexname = :index_name
            """
        ),
        {"index_name": index_name},
    )
    return result.fetchone() is not None


async def _ensure_enum_value(conn, enum_name: str, value: str) -> None:
    result = await conn.execute(
        text(
            """
            SELECT 1
            FROM pg_type t
            JOIN pg_enum e ON e.enumtypid = t.oid
            WHERE t.typname = :enum_name AND e.enumlabel = :value
            """
        ),
        {"enum_name": enum_name, "value": value},
    )
    if result.fetchone():
        print(f"  - enum {enum_name}.{value} already exists")
        return

    await conn.execute(text(f"ALTER TYPE {enum_name} ADD VALUE '{value}'"))
    print(f"  - enum {enum_name}.{value} added")


async def _ensure_index(conn, index_name: str, table: str, column: str) -> None:
    if await _index_exists(conn, index_name):
        print(f"  - index {index_name} already exists")
        return
    await conn.execute(text(f"CREATE INDEX {index_name} ON {table} ({column})"))
    print(f"  - index {index_name} added")


async def migrate():
    async with engine.begin() as conn:
        await _ensure_enum_value(conn, "provisioningattemptsource", "subscription_share")
        await _ensure_enum_value(conn, "provisioningattemptentrypoint", "subscription_share")

        if not await _column_exists(conn, "plans", "max_shared_users"):
            await conn.execute(
                text(
                    """
                    ALTER TABLE plans
                    ADD COLUMN max_shared_users INTEGER NOT NULL DEFAULT 1
                    """
                )
            )
            print("  - plans.max_shared_users added")
        else:
            print("  - plans.max_shared_users already exists")

        if not await _column_exists(conn, "customers", "subscription_owner_id"):
            await conn.execute(
                text(
                    """
                    ALTER TABLE customers
                    ADD COLUMN subscription_owner_id INTEGER NULL
                    REFERENCES customers(id) ON DELETE SET NULL
                    """
                )
            )
            print("  - customers.subscription_owner_id added")
        else:
            print("  - customers.subscription_owner_id already exists")
        await _ensure_index(
            conn,
            "ix_customers_subscription_owner_id",
            "customers",
            "subscription_owner_id",
        )

        if not await _column_exists(conn, "device_pairings", "subscription_owner_customer_id"):
            await conn.execute(
                text(
                    """
                    ALTER TABLE device_pairings
                    ADD COLUMN subscription_owner_customer_id INTEGER NULL
                    REFERENCES customers(id) ON DELETE SET NULL
                    """
                )
            )
            print("  - device_pairings.subscription_owner_customer_id added")
        else:
            print("  - device_pairings.subscription_owner_customer_id already exists")
        await _ensure_index(
            conn,
            "ix_device_pairings_subscription_owner_customer_id",
            "device_pairings",
            "subscription_owner_customer_id",
        )

        if not await _column_exists(conn, "device_pairings", "is_subscription_share"):
            await conn.execute(
                text(
                    """
                    ALTER TABLE device_pairings
                    ADD COLUMN is_subscription_share BOOLEAN NOT NULL DEFAULT false
                    """
                )
            )
            print("  - device_pairings.is_subscription_share added")
        else:
            print("  - device_pairings.is_subscription_share already exists")

        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS subscription_share_codes (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR(16) UNIQUE NOT NULL,
                    router_id INTEGER NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
                    owner_customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                    status VARCHAR(20) NOT NULL DEFAULT 'active',
                    expires_at TIMESTAMP NOT NULL,
                    redeemed_customer_id INTEGER NULL REFERENCES customers(id) ON DELETE SET NULL,
                    redeemed_pairing_id INTEGER NULL REFERENCES device_pairings(id) ON DELETE SET NULL,
                    redeemed_at TIMESTAMP NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        print("  - subscription_share_codes table ready")
        for index_name, column in [
            ("ix_subscription_share_codes_code", "code"),
            ("ix_subscription_share_codes_owner_customer_id", "owner_customer_id"),
            ("ix_subscription_share_codes_router_id", "router_id"),
            ("ix_subscription_share_codes_status", "status"),
            ("ix_subscription_share_codes_expires_at", "expires_at"),
            ("ix_subscription_share_codes_redeemed_customer_id", "redeemed_customer_id"),
            ("ix_subscription_share_codes_redeemed_pairing_id", "redeemed_pairing_id"),
        ]:
            await _ensure_index(conn, index_name, "subscription_share_codes", column)

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(
            text("DROP INDEX IF EXISTS ix_device_pairings_subscription_owner_customer_id")
        )
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_redeemed_pairing_id"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_redeemed_customer_id"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_expires_at"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_status"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_router_id"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_owner_customer_id"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_subscription_share_codes_code"))
        await conn.execute(text("DROP TABLE IF EXISTS subscription_share_codes"))
        await conn.execute(text("DROP INDEX IF EXISTS ix_customers_subscription_owner_id"))
        await conn.execute(
            text("ALTER TABLE device_pairings DROP COLUMN IF EXISTS is_subscription_share")
        )
        await conn.execute(
            text("ALTER TABLE device_pairings DROP COLUMN IF EXISTS subscription_owner_customer_id")
        )
        await conn.execute(
            text("ALTER TABLE customers DROP COLUMN IF EXISTS subscription_owner_id")
        )
        await conn.execute(
            text("ALTER TABLE plans DROP COLUMN IF EXISTS max_shared_users")
        )
        print(
            "Rollback completed. PostgreSQL enum values are intentionally not removed."
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Subscription sharing migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

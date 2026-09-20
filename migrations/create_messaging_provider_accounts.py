"""
Migration: per-tenant SMS gateway accounts.

Creates messaging_provider_accounts, adds sms_messages.provider_account_id,
and adds the two partial unique indexes that keep exactly one default account
per owner (one for resellers, one for the platform row whose user_id is NULL).

Mirrors the idempotent startup migration in main.py
(run_messaging_migrations) — this script is for manual repair only; startup is
the authoritative path. Idempotent, safe to run repeatedly.

Usage:
    python migrations/create_messaging_provider_accounts.py
    python migrations/create_messaging_provider_accounts.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS messaging_provider_accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NULL REFERENCES users(id),
        provider VARCHAR(50) NOT NULL,
        label VARCHAR(100) NOT NULL,
        sender_id VARCHAR(20),
        credentials JSON NOT NULL DEFAULT '{}',
        is_default BOOLEAN NOT NULL DEFAULT TRUE,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        last_test_at TIMESTAMP NULL,
        last_test_ok BOOLEAN NULL,
        last_test_error VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_messaging_provider_accounts_user_id
    ON messaging_provider_accounts(user_id)
    """,
    # Exactly one default per owner. Two partial indexes, because a NULL
    # user_id never collides in a plain unique constraint.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_messaging_provider_default_per_user
    ON messaging_provider_accounts(user_id)
    WHERE is_default AND user_id IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS uq_messaging_provider_default_platform
    ON messaging_provider_accounts((1))
    WHERE is_default AND user_id IS NULL
    """,
    """
    ALTER TABLE sms_messages
    ADD COLUMN IF NOT EXISTS provider_account_id INTEGER NULL
    REFERENCES messaging_provider_accounts(id)
    """,
]

ROLLBACK = [
    "ALTER TABLE sms_messages DROP COLUMN IF EXISTS provider_account_id",
    "DROP INDEX IF EXISTS uq_messaging_provider_default_platform",
    "DROP INDEX IF EXISTS uq_messaging_provider_default_per_user",
    "DROP TABLE IF EXISTS messaging_provider_accounts",
]


async def main(rollback: bool = False) -> None:
    async with engine.begin() as conn:
        for statement in (ROLLBACK if rollback else STATEMENTS):
            await conn.execute(text(statement))
    print("Rolled back." if rollback else "messaging_provider_accounts ready.")


if __name__ == "__main__":
    asyncio.run(main(rollback="--rollback" in sys.argv))

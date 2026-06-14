"""
Migration: Create app_settings table for platform-wide admin-editable KV settings

A generic key/value store. The first consumer is the compensation-voucher daily
limit (key: "compensation_daily_limit"). Future platform settings can reuse the
same table without schema changes.

Usage:
    python migrations/add_app_settings.py
    python migrations/add_app_settings.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Create the app_settings table if it does not already exist."""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'app_settings'
        """))

        if result.fetchone():
            print("Table 'app_settings' already exists. Skipping.")
            return

        await conn.execute(text("""
            CREATE TABLE app_settings (
                key        VARCHAR(100) PRIMARY KEY,
                value      VARCHAR(500) NOT NULL,
                updated_at TIMESTAMP DEFAULT now()
            )
        """))

        print("Migration completed successfully!")
        print("  - Created table app_settings (key VARCHAR(100) PK, value VARCHAR(500), updated_at TIMESTAMP)")


async def rollback():
    """Drop the app_settings table."""
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS app_settings"))
        print("Rollback completed: app_settings table dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="app_settings table migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

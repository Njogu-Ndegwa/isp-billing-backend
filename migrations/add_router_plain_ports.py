"""
Migration: Add plain_ports field to routers table

Adds support for "plain" port mode — ports that provide internet without
any authentication (no hotspot captive portal, no PPPoE).

Usage:
    python migrations/add_router_plain_ports.py
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add plain_ports column to routers table"""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'plain_ports'
        """))

        if result.fetchone():
            print("Column 'plain_ports' already exists in routers table. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE routers
            ADD COLUMN plain_ports JSON NULL
        """))

        print("Migration completed successfully!")
        print("  - Added 'plain_ports' column (JSON, nullable)")


async def rollback():
    """Remove plain_ports column from routers table"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE routers
            DROP COLUMN IF EXISTS plain_ports
        """))

        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Router plain_ports migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

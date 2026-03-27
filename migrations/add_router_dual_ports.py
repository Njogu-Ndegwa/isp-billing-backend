"""
Migration: Add dual_ports field to routers table

Adds support for "dual" port mode — ports that provide both PPPoE and
Hotspot on the same interface.  The port stays on the hotspot bridge while
a PPPoE server is also bound to that bridge, so PPPoE clients get a PPP
session and non-PPPoE clients hit the captive portal.

Usage:
    python migrations/add_router_dual_ports.py
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add dual_ports column to routers table"""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'dual_ports'
        """))

        if result.fetchone():
            print("Column 'dual_ports' already exists in routers table. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE routers
            ADD COLUMN dual_ports JSON NULL
        """))

        print("Migration completed successfully!")
        print("  - Added 'dual_ports' column (JSON, nullable)")


async def rollback():
    """Remove dual_ports column from routers table"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE routers
            DROP COLUMN IF EXISTS dual_ports
        """))

        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Router dual_ports migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

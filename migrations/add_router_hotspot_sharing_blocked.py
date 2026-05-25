"""
Migration: Add hotspot_sharing_blocked column to routers table

When enabled, the backend pushes a TTL-based firewall rule to the MikroTik
router that drops forwarded packets with TTL=63 (the signature of traffic
from a device tethered behind a phone hotspot). Defaults to False so
existing routers are unaffected.

Usage:
    python migrations/add_router_hotspot_sharing_blocked.py
    python migrations/add_router_hotspot_sharing_blocked.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'hotspot_sharing_blocked'
        """))

        if result.fetchone():
            print("Column 'hotspot_sharing_blocked' already exists. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE routers
            ADD COLUMN hotspot_sharing_blocked BOOLEAN NOT NULL DEFAULT false
        """))

        print("Migration completed successfully!")
        print("  - Added hotspot_sharing_blocked BOOLEAN NOT NULL DEFAULT false on routers")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE routers
            DROP COLUMN IF EXISTS hotspot_sharing_blocked
        """))
        print("Rollback completed: hotspot_sharing_blocked column dropped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Router hotspot_sharing_blocked migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

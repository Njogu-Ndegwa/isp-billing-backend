"""
Migration: Add service-specific byte counters to bandwidth_snapshots.

The counters are per-snapshot deltas from managed simple queues:

    hotspot_upload_bytes / hotspot_download_bytes
    pppoe_upload_bytes / pppoe_download_bytes

They let dashboards graph data consumption split by hotspot vs PPPoE without
creating a new time-series table.

Usage:
    python migrations/add_bandwidth_snapshot_service_usage.py
    python migrations/add_bandwidth_snapshot_service_usage.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


COLUMNS = (
    "hotspot_upload_bytes",
    "hotspot_download_bytes",
    "pppoe_upload_bytes",
    "pppoe_download_bytes",
)


async def migrate():
    async with engine.begin() as conn:
        for column in COLUMNS:
            await conn.execute(text(f"""
                ALTER TABLE bandwidth_snapshots
                ADD COLUMN IF NOT EXISTS {column} BIGINT NOT NULL DEFAULT 0
            """))
            print(f"Ensured bandwidth_snapshots.{column}")
        print("Migration completed successfully.")


async def rollback():
    async with engine.begin() as conn:
        for column in COLUMNS:
            await conn.execute(text(f"""
                ALTER TABLE bandwidth_snapshots
                DROP COLUMN IF EXISTS {column}
            """))
            print(f"Dropped bandwidth_snapshots.{column}")
        print("Rollback completed successfully.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Add hotspot/PPPoE service usage counters to bandwidth_snapshots"
    )
    parser.add_argument("--rollback", action="store_true", help="Drop the service usage columns")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

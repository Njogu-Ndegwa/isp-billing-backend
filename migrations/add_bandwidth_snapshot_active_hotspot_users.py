"""
Migration: Add active_hotspot_users column to bandwidth_snapshots table.

Why:
    The /api/mikrotik/health endpoint used to derive the hotspot user count by
    subtracting the LIVE PPPoE count from the snapshot's COMBINED ``active_queues``
    total. Because the snapshot is up to a few minutes stale while the PPPoE
    reading is live, that subtraction could go negative (users reported seeing
    pppoe=16 with total=14, which is mathematically impossible).

    The fix is to persist the hotspot host count separately on each snapshot so
    the dashboard endpoint can return:

        active_hotspot_users = snapshot.active_hotspot_users  (stable)
        active_pppoe_users   = live from /ppp/active/print
        active_total_users   = hotspot + pppoe                (always consistent)

    ``active_queues`` is left in place as the legacy combined count so existing
    bandwidth-history graphs keep working unchanged.

Backfill strategy:
    For every existing snapshot we set active_hotspot_users = active_queues. That
    is the best we can do without re-querying the router for historical data: it
    over-counts hotspot by the number of PPPoE users that were connected at
    snapshot time. The dashboard endpoint also has a graceful fallback for any
    rows that somehow remain NULL.

Usage:
    python migrations/add_bandwidth_snapshot_active_hotspot_users.py
    python migrations/add_bandwidth_snapshot_active_hotspot_users.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'bandwidth_snapshots'
              AND column_name = 'active_hotspot_users'
        """))

        if result.fetchone():
            print("Column 'active_hotspot_users' already exists on bandwidth_snapshots. Skipping schema change.")
        else:
            await conn.execute(text("""
                ALTER TABLE bandwidth_snapshots
                ADD COLUMN active_hotspot_users INTEGER NOT NULL DEFAULT 0
            """))
            print("Added column 'active_hotspot_users' (INTEGER NOT NULL DEFAULT 0)")

        # Best-effort backfill: copy the legacy combined value into the new
        # column for rows that are still at the default 0. This is intentionally
        # imprecise (it over-counts hotspot by historical PPPoE), but it keeps
        # the dashboard tile non-zero on existing deployments until fresh
        # snapshots have been written.
        backfill = await conn.execute(text("""
            UPDATE bandwidth_snapshots
            SET active_hotspot_users = active_queues
            WHERE active_hotspot_users = 0
              AND active_queues > 0
        """))
        try:
            rowcount = backfill.rowcount
        except Exception:
            rowcount = -1
        print(f"Backfilled active_hotspot_users from active_queues for ~{rowcount} historical row(s).")

        print("Migration completed successfully.")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE bandwidth_snapshots
            DROP COLUMN IF EXISTS active_hotspot_users
        """))
        print("Rollback completed: dropped active_hotspot_users from bandwidth_snapshots.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Add active_hotspot_users to bandwidth_snapshots")
    parser.add_argument("--rollback", action="store_true", help="Drop the active_hotspot_users column")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

"""
Migration: Multi-WAN PCC load balancing state on routers.

Adds:
- routers.lb_enabled: boolean, NOT NULL, default false — LB is live on this router.
- routers.lb_config: JSON, nullable — {"wan_ports": [...], "applied_at": iso8601}.
  Kept across a disable so re-enabling reuses the same WAN ports.
- routers.lb_applied_at: timestamp, nullable — when LB was last applied.

Every existing row gets lb_enabled=false and NULL config/applied_at, which is
exactly the pre-feature behaviour: no router load-balances until explicitly
enabled through the /load-balancing endpoints.

The startup path in main.py (`run_load_balancing_migrations`) applies the same
change on every boot; this script exists for manual repair/inspection only.

Idempotent: re-running is safe.

Usage:
    python migrations/add_router_lb_config.py
    python migrations/add_router_lb_config.py --rollback
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


COLUMNS = (
    ("lb_enabled", "ADD COLUMN lb_enabled BOOLEAN NOT NULL DEFAULT false"),
    ("lb_config", "ADD COLUMN lb_config JSON NULL"),
    ("lb_applied_at", "ADD COLUMN lb_applied_at TIMESTAMP NULL"),
)


async def migrate():
    async with engine.begin() as conn:
        for column, ddl in COLUMNS:
            if not await _column_exists(conn, "routers", column):
                await conn.execute(text(f"ALTER TABLE routers {ddl}"))
                print(f"  - routers.{column} added")
            else:
                print(f"  - routers.{column} already exists")

        enabled = await conn.execute(
            text("SELECT COUNT(*) FROM routers WHERE lb_enabled = true")
        )
        total = await conn.execute(text("SELECT COUNT(*) FROM routers"))
        print(
            f"  - {enabled.scalar()} of {total.scalar()} routers have load "
            f"balancing enabled"
        )

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        for column in ("lb_applied_at", "lb_config", "lb_enabled"):
            await conn.execute(
                text(f"ALTER TABLE routers DROP COLUMN IF EXISTS {column}")
            )
        print("Rollback completed. Load-balancing state removed from routers.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Router load-balancing state migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

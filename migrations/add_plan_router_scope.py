"""
Migration: Tie a plan to specific routers.

Adds:
- plans.router_ids: JSON list of router ids this plan is offered on.

NULL (the value every existing row gets) means "offered on all of the owner's
routers", which is exactly how plans behaved before this column existed. No
backfill is needed and no existing plan changes behaviour.

The startup path in main.py (`run_plan_router_scope_migrations`) applies the same
change on every boot; this script exists for manual repair/inspection only.

Idempotent: re-running is safe.

Usage:
    python migrations/add_plan_router_scope.py
    python migrations/add_plan_router_scope.py --rollback
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


async def migrate():
    async with engine.begin() as conn:
        if not await _column_exists(conn, "plans", "router_ids"):
            await conn.execute(
                text(
                    """
                    ALTER TABLE plans
                    ADD COLUMN router_ids JSON NULL
                    """
                )
            )
            print("  - plans.router_ids added")
        else:
            print("  - plans.router_ids already exists")

        scoped = await conn.execute(
            text("SELECT COUNT(*) FROM plans WHERE router_ids IS NOT NULL")
        )
        total = await conn.execute(text("SELECT COUNT(*) FROM plans"))
        print(
            f"  - {scoped.scalar()} of {total.scalar()} plans are router-scoped "
            f"(the rest are offered on all of their owner's routers)"
        )

        print("Migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE plans DROP COLUMN IF EXISTS router_ids"))
        print("Rollback completed. All plans revert to being offered on every router.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Per-router plan scope migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

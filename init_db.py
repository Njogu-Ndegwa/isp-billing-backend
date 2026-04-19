"""
Database initialization script for PostgreSQL.
Run this after starting the containers to create all tables.
"""
import asyncio
from sqlalchemy import text, inspect
from app.db.database import async_engine, Base
from app.db.models import *  # Import all models

async def init_db():
    async with async_engine.begin() as conn:
        # Drop all tables (use with caution)
        # await conn.run_sync(Base.metadata.drop_all)
        
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    
    print("Database tables created successfully!")


async def migrate_db():
    """
    Apply incremental migrations for columns added after initial table creation.
    Safe to run multiple times - only adds columns that don't already exist.
    """
    async with async_engine.begin() as conn:
        # Check which columns already exist on mpesa_transactions
        def get_columns(connection):
            insp = inspect(connection)
            return [col["name"] for col in insp.get_columns("mpesa_transactions")]
        
        existing_columns = await conn.run_sync(get_columns)
        
        # Add result_code column if missing
        if "result_code" not in existing_columns:
            await conn.execute(text(
                "ALTER TABLE mpesa_transactions ADD COLUMN result_code VARCHAR(50)"
            ))
            print("  Added column: mpesa_transactions.result_code")
        
        # Add result_desc column if missing
        if "result_desc" not in existing_columns:
            await conn.execute(text(
                "ALTER TABLE mpesa_transactions ADD COLUMN result_desc VARCHAR(500)"
            ))
            print("  Added column: mpesa_transactions.result_desc")
        
        # Add failure_source column if missing (client, mpesa_api, server, timeout)
        if "failure_source" not in existing_columns:
            # Create the enum type first, then add the column
            await conn.execute(text(
                "DO $$ BEGIN "
                "CREATE TYPE failuresource AS ENUM ('client', 'mpesa_api', 'server', 'timeout'); "
                "EXCEPTION WHEN duplicate_object THEN NULL; "
                "END $$"
            ))
            await conn.execute(text(
                "ALTER TABLE mpesa_transactions ADD COLUMN failure_source failuresource"
            ))
            print("  Added column: mpesa_transactions.failure_source")

        # Check which columns already exist on routers
        def get_router_columns(connection):
            insp = inspect(connection)
            return [col["name"] for col in insp.get_columns("routers")]

        router_columns = await conn.run_sync(get_router_columns)

        # Add plain_ports column if missing (no-auth port mode)
        if "plain_ports" not in router_columns:
            await conn.execute(text(
                "ALTER TABLE routers ADD COLUMN plain_ports JSON NULL"
            ))
            print("  Added column: routers.plain_ports")

        # Add dual_ports column if missing (PPPoE + Hotspot on same port)
        if "dual_ports" not in router_columns:
            await conn.execute(text(
                "ALTER TABLE routers ADD COLUMN dual_ports JSON NULL"
            ))
            print("  Added column: routers.dual_ports")

        # Check which columns already exist on users
        def get_user_columns(connection):
            insp = inspect(connection)
            return [col["name"] for col in insp.get_columns("users")]

        user_columns = await conn.run_sync(get_user_columns)

        if "last_login_at" not in user_columns:
            await conn.execute(text(
                "ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP NULL"
            ))
            print("  Added column: users.last_login_at")

    print("Database migration completed!")


async def _run_all():
    """Run init_db and migrate_db in a single event loop, then dispose the engine.

    Calling ``asyncio.run()`` twice in the same process would bind the async
    engine's pooled connections to the first loop and then try to reuse them
    from the second loop, raising:
        RuntimeError: ... got Future ... attached to a different loop
    Running both stages in one loop (and disposing the engine at the end)
    avoids that entirely.
    """
    try:
        await init_db()
        await migrate_db()
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        async def _migrate_only():
            try:
                await migrate_db()
            finally:
                await async_engine.dispose()
        asyncio.run(_migrate_only())
    else:
        asyncio.run(_run_all())


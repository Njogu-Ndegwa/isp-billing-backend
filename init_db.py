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
    
    print("Database migration completed!")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        asyncio.run(migrate_db())
    else:
        asyncio.run(init_db())
        asyncio.run(migrate_db())


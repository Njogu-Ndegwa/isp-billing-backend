"""
Migration: Add auth_method field to routers table

This migration adds support for RADIUS authentication on a per-router basis.
Routers can now be configured to use either:
- DIRECT_API: Current method - direct MikroTik API calls (default)
- RADIUS: New method - FreeRADIUS server authentication

Run this migration manually or via alembic.

Usage:
    python migrations/add_router_auth_method.py
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add auth_method column to routers table"""
    async with engine.begin() as conn:
        # Check if column already exists
        result = await conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'routers' AND column_name = 'auth_method'
        """))
        
        if result.fetchone():
            print("Column 'auth_method' already exists in routers table. Skipping.")
            return
        
        # Create the enum type if it doesn't exist
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE routerauthmethod AS ENUM ('DIRECT_API', 'RADIUS');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
        """))
        
        # Add the column with default value DIRECT_API (existing behavior)
        await conn.execute(text("""
            ALTER TABLE routers 
            ADD COLUMN auth_method routerauthmethod NOT NULL DEFAULT 'DIRECT_API'
        """))
        
        # Add RADIUS-specific columns
        await conn.execute(text("""
            ALTER TABLE routers 
            ADD COLUMN IF NOT EXISTS radius_secret VARCHAR(255) NULL,
            ADD COLUMN IF NOT EXISTS radius_nas_identifier VARCHAR(100) NULL
        """))
        
        print("Migration completed successfully!")
        print("  - Added 'auth_method' column (default: DIRECT_API)")
        print("  - Added 'radius_secret' column for RADIUS shared secret")
        print("  - Added 'radius_nas_identifier' column for NAS identification")


async def rollback():
    """Remove auth_method column from routers table"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE routers 
            DROP COLUMN IF EXISTS auth_method,
            DROP COLUMN IF EXISTS radius_secret,
            DROP COLUMN IF EXISTS radius_nas_identifier
        """))
        
        await conn.execute(text("""
            DROP TYPE IF EXISTS routerauthmethod
        """))
        
        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Router auth_method migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()
    
    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

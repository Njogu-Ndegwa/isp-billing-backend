"""
Migration: Add support_phone field to users table

Allows ISP owners/resellers to register a customer support phone number
that is returned to the captive portal via GET /api/public/portal/{identity}.

Usage:
    python migrations/add_user_support_phone.py
    python migrations/add_user_support_phone.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Add support_phone column to users table"""
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'support_phone'
        """))

        if result.fetchone():
            print("Column 'support_phone' already exists in users table. Skipping.")
            return

        await conn.execute(text("""
            ALTER TABLE users 
            ADD COLUMN support_phone VARCHAR(20) NULL
        """))

        print("Migration completed successfully!")
        print("  - Added 'support_phone' column to users table")


async def rollback():
    """Remove support_phone column from users table"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE users 
            DROP COLUMN IF EXISTS support_phone
        """))

        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="User support_phone migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

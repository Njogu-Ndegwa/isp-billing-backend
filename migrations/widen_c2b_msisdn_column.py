"""
Migration: Widen c2b_transactions.msisdn from VARCHAR(20) to VARCHAR(128).

Safaricom C2B v1 returns a SHA256-hashed MSISDN (64 hex chars), and v2
returns a masked number. Both exceed the original 20-char limit.

Usage:
    python migrations/widen_c2b_msisdn_column.py
    python migrations/widen_c2b_msisdn_column.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE c2b_transactions
            ALTER COLUMN msisdn TYPE VARCHAR(128);
        """))
    print("OK — c2b_transactions.msisdn widened to VARCHAR(128)")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE c2b_transactions
            ALTER COLUMN msisdn TYPE VARCHAR(20);
        """))
    print("OK — c2b_transactions.msisdn reverted to VARCHAR(20)")


if __name__ == "__main__":
    if "--rollback" in sys.argv:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

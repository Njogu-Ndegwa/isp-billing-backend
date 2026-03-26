"""
Migration: Add vpn_type, l2tp_username, l2tp_password columns to provisioning_tokens
and relax NOT NULL on wg_private_key, wg_public_key, server_wg_pubkey
(L2TP tokens don't carry WireGuard keys).

Usage:
    python migrations/add_provisioning_vpn_type.py
    python migrations/add_provisioning_vpn_type.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    async with engine.begin() as conn:
        # vpn_type
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_tokens' AND column_name = 'vpn_type'
        """))
        if result.fetchone():
            print("Column 'vpn_type' already exists. Skipping add.")
        else:
            await conn.execute(text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN vpn_type VARCHAR(20) NOT NULL DEFAULT 'wireguard'
            """))
            print("Added 'vpn_type' column (default: wireguard)")

        # l2tp_username
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_tokens' AND column_name = 'l2tp_username'
        """))
        if result.fetchone():
            print("Column 'l2tp_username' already exists. Skipping add.")
        else:
            await conn.execute(text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN l2tp_username VARCHAR NULL
            """))
            print("Added 'l2tp_username' column")

        # l2tp_password
        result = await conn.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_tokens' AND column_name = 'l2tp_password'
        """))
        if result.fetchone():
            print("Column 'l2tp_password' already exists. Skipping add.")
        else:
            await conn.execute(text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN l2tp_password VARCHAR NULL
            """))
            print("Added 'l2tp_password' column")

        # Relax NOT NULL on WireGuard-specific columns (L2TP tokens won't have them)
        for col in ("wg_private_key", "wg_public_key", "server_wg_pubkey"):
            await conn.execute(text(f"""
                ALTER TABLE provisioning_tokens
                ALTER COLUMN {col} DROP NOT NULL
            """))
        print("Relaxed NOT NULL on wg_private_key, wg_public_key, server_wg_pubkey")

    print("\nMigration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE provisioning_tokens
            DROP COLUMN IF EXISTS vpn_type,
            DROP COLUMN IF EXISTS l2tp_username,
            DROP COLUMN IF EXISTS l2tp_password
        """))
        for col in ("wg_private_key", "wg_public_key", "server_wg_pubkey"):
            await conn.execute(text(f"""
                ALTER TABLE provisioning_tokens
                ALTER COLUMN {col} SET NOT NULL
            """))
        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Provisioning vpn_type migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()

    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

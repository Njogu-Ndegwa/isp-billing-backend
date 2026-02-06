"""
Migration: Create RADIUS tables for FreeRADIUS integration

This migration creates the tables required by FreeRADIUS for:
- User authentication (radius_check, radius_reply)
- Group management (radius_groupcheck, radius_groupreply, radius_usergroup)
- Accounting (radius_accounting)
- Post-authentication logging (radius_postauth)

These tables are SEPARATE from your existing tables and won't affect current functionality.

Run this migration manually:
    python migrations/create_radius_tables.py

Rollback:
    python migrations/create_radius_tables.py --rollback
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


async def migrate():
    """Create RADIUS tables for FreeRADIUS integration"""
    async with engine.begin() as conn:
        # Check if tables already exist
        result = await conn.execute(text("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_name = 'radius_check'
        """))
        
        if result.fetchone():
            print("RADIUS tables already exist. Skipping creation.")
            return
        
        # Create radius_check table (authentication attributes)
        # This is where user credentials and limits are stored
        await conn.execute(text("""
            CREATE TABLE radius_check (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                attribute VARCHAR(64) NOT NULL,
                op CHAR(2) NOT NULL DEFAULT ':=',
                value VARCHAR(253) NOT NULL,
                expiry TIMESTAMP NULL,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_check_username ON radius_check(username)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_check_customer ON radius_check(customer_id)
        """))
        
        # Create radius_reply table (reply attributes sent to NAS)
        # This is where bandwidth limits, session timeouts etc. are stored
        await conn.execute(text("""
            CREATE TABLE radius_reply (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                attribute VARCHAR(64) NOT NULL,
                op CHAR(2) NOT NULL DEFAULT ':=',
                value VARCHAR(253) NOT NULL,
                expiry TIMESTAMP NULL,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_reply_username ON radius_reply(username)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_reply_customer ON radius_reply(customer_id)
        """))
        
        # Create radius_groupcheck table (group authentication attributes)
        await conn.execute(text("""
            CREATE TABLE radius_groupcheck (
                id SERIAL PRIMARY KEY,
                groupname VARCHAR(64) NOT NULL,
                attribute VARCHAR(64) NOT NULL,
                op CHAR(2) NOT NULL DEFAULT ':=',
                value VARCHAR(253) NOT NULL
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_groupcheck_groupname ON radius_groupcheck(groupname)
        """))
        
        # Create radius_groupreply table (group reply attributes)
        await conn.execute(text("""
            CREATE TABLE radius_groupreply (
                id SERIAL PRIMARY KEY,
                groupname VARCHAR(64) NOT NULL,
                attribute VARCHAR(64) NOT NULL,
                op CHAR(2) NOT NULL DEFAULT ':=',
                value VARCHAR(253) NOT NULL
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_groupreply_groupname ON radius_groupreply(groupname)
        """))
        
        # Create radius_usergroup table (user-group membership)
        await conn.execute(text("""
            CREATE TABLE radius_usergroup (
                id SERIAL PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                groupname VARCHAR(64) NOT NULL,
                priority INTEGER NOT NULL DEFAULT 1
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_usergroup_username ON radius_usergroup(username)
        """))
        
        # Create radius_accounting table (session accounting)
        # This stores session data: bytes in/out, session time, etc.
        await conn.execute(text("""
            CREATE TABLE radius_accounting (
                id BIGSERIAL PRIMARY KEY,
                acctsessionid VARCHAR(64) NOT NULL,
                acctuniqueid VARCHAR(32) NOT NULL,
                username VARCHAR(64) NOT NULL,
                realm VARCHAR(64),
                nasipaddress VARCHAR(15) NOT NULL,
                nasportid VARCHAR(32),
                nasporttype VARCHAR(32),
                acctstarttime TIMESTAMP,
                acctupdatetime TIMESTAMP,
                acctstoptime TIMESTAMP,
                acctsessiontime INTEGER,
                acctauthentic VARCHAR(32),
                connectinfo_start VARCHAR(128),
                connectinfo_stop VARCHAR(128),
                acctinputoctets BIGINT,
                acctoutputoctets BIGINT,
                calledstationid VARCHAR(50),
                callingstationid VARCHAR(50),
                acctterminatecause VARCHAR(32),
                servicetype VARCHAR(32),
                framedprotocol VARCHAR(32),
                framedipaddress VARCHAR(15),
                framedipv6address VARCHAR(45),
                framedipv6prefix VARCHAR(45),
                framedinterfaceid VARCHAR(44),
                delegatedipv6prefix VARCHAR(45)
            )
        """))
        
        await conn.execute(text("""
            CREATE UNIQUE INDEX idx_radius_acct_unique ON radius_accounting(acctuniqueid)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_acct_username ON radius_accounting(username)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_acct_start ON radius_accounting(acctstarttime)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_acct_stop ON radius_accounting(acctstoptime)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_acct_nasip ON radius_accounting(nasipaddress)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_acct_callingstationid ON radius_accounting(callingstationid)
        """))
        
        # Create radius_postauth table (post-authentication logging)
        await conn.execute(text("""
            CREATE TABLE radius_postauth (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                pass VARCHAR(64),
                reply VARCHAR(32),
                authdate TIMESTAMP NOT NULL DEFAULT NOW(),
                nasipaddress VARCHAR(15),
                calledstationid VARCHAR(50),
                callingstationid VARCHAR(50)
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_postauth_username ON radius_postauth(username)
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_postauth_date ON radius_postauth(authdate)
        """))
        
        # Create nas table (optional - for dynamic client management)
        await conn.execute(text("""
            CREATE TABLE radius_nas (
                id SERIAL PRIMARY KEY,
                nasname VARCHAR(128) NOT NULL,
                shortname VARCHAR(32),
                type VARCHAR(30) DEFAULT 'other',
                ports INTEGER,
                secret VARCHAR(60) NOT NULL,
                server VARCHAR(64),
                community VARCHAR(50),
                description VARCHAR(200),
                router_id INTEGER REFERENCES routers(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        
        await conn.execute(text("""
            CREATE INDEX idx_radius_nas_nasname ON radius_nas(nasname)
        """))
        
        print("RADIUS tables created successfully!")
        print("Tables created:")
        print("  - radius_check (user authentication attributes)")
        print("  - radius_reply (reply attributes - bandwidth, session timeout)")
        print("  - radius_groupcheck (group authentication)")
        print("  - radius_groupreply (group reply attributes)")
        print("  - radius_usergroup (user-group membership)")
        print("  - radius_accounting (session accounting/billing)")
        print("  - radius_postauth (authentication logging)")
        print("  - radius_nas (NAS/router management)")


async def rollback():
    """Drop all RADIUS tables"""
    async with engine.begin() as conn:
        tables = [
            'radius_postauth',
            'radius_accounting', 
            'radius_usergroup',
            'radius_groupreply',
            'radius_groupcheck',
            'radius_reply',
            'radius_check',
            'radius_nas'
        ]
        
        for table in tables:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
            print(f"Dropped table: {table}")
        
        print("Rollback completed successfully!")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RADIUS tables migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    args = parser.parse_args()
    
    if args.rollback:
        asyncio.run(rollback())
    else:
        asyncio.run(migrate())

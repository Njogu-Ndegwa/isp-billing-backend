"""
Migration: Messaging / SMS system.

Creates enums, 8 tables, lean indexes (incl. a partial index on failed
sms_messages), and seeds the messaging_settings singleton (id=1).
Idempotent — safe to run repeatedly.

Usage:
    python migrations/create_messaging_tables.py
    python migrations/create_messaging_tables.py --rollback
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import async_engine as engine


ENUMS = {
    "smscredittxnkind": ["purchase", "send_debit", "refund", "admin_adjustment"],
    "smscreditorderstatus": ["pending", "completed", "failed", "expired"],
    "smscampaignstatus": ["queued", "sending", "completed", "partial", "failed", "canceled"],
    "smsmessagestatus": ["queued", "sent", "delivered", "failed"],
    "smsmessagekind": ["reseller_to_customer", "admin_to_reseller"],
}

TABLES = [
    """
    CREATE TABLE IF NOT EXISTS messaging_settings (
        id SERIAL PRIMARY KEY,
        price_per_sms_kes NUMERIC(6,2) NOT NULL DEFAULT 0.50,
        min_purchase_credits INTEGER NOT NULL DEFAULT 10,
        sender_id VARCHAR(20),
        provider VARCHAR(50) NOT NULL DEFAULT 'talksasa',
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        message_retention_days INTEGER NOT NULL DEFAULT 60,
        bundles JSON,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_accounts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
        balance INTEGER NOT NULL DEFAULT 0,
        total_purchased INTEGER NOT NULL DEFAULT 0,
        total_spent INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT ck_sms_credit_balance_non_negative CHECK (balance >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        change INTEGER NOT NULL,
        balance_after INTEGER NOT NULL,
        kind smscredittxnkind NOT NULL,
        reference VARCHAR(64),
        note VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_credit_orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        quantity INTEGER NOT NULL,
        unit_price NUMERIC(6,2) NOT NULL,
        amount INTEGER NOT NULL,
        phone_number VARCHAR(20) NOT NULL,
        status smscreditorderstatus NOT NULL DEFAULT 'pending',
        mpesa_checkout_request_id VARCHAR(128),
        mpesa_merchant_request_id VARCHAR(128),
        payment_reference VARCHAR(128),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS message_templates (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        name VARCHAR(120) NOT NULL,
        body VARCHAR(1000) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_campaigns (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        body VARCHAR(1000) NOT NULL,
        recipient_count INTEGER NOT NULL,
        segments_per_message INTEGER NOT NULL,
        total_credits INTEGER NOT NULL,
        sent_count INTEGER NOT NULL DEFAULT 0,
        failed_count INTEGER NOT NULL DEFAULT 0,
        refunded_credits INTEGER NOT NULL DEFAULT 0,
        sender_id VARCHAR(20),
        status smscampaignstatus NOT NULL DEFAULT 'queued',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sms_messages (
        id SERIAL PRIMARY KEY,
        campaign_id INTEGER REFERENCES sms_campaigns(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        customer_id INTEGER REFERENCES customers(id),
        recipient_phone VARCHAR(20) NOT NULL,
        body VARCHAR(1000) NOT NULL,
        segments INTEGER NOT NULL,
        credits_charged INTEGER NOT NULL,
        kind smsmessagekind NOT NULL,
        provider VARCHAR(50),
        provider_message_id VARCHAR(128),
        status smsmessagestatus NOT NULL DEFAULT 'queued',
        error VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reseller_inbox_messages (
        id SERIAL PRIMARY KEY,
        recipient_user_id INTEGER NOT NULL REFERENCES users(id),
        sender_user_id INTEGER NOT NULL REFERENCES users(id),
        subject VARCHAR(200),
        body VARCHAR(2000) NOT NULL,
        is_read BOOLEAN NOT NULL DEFAULT FALSE,
        read_at TIMESTAMP,
        sent_sms BOOLEAN NOT NULL DEFAULT FALSE,
        broadcast_id VARCHAR(64),
        created_at TIMESTAMP DEFAULT NOW()
    )
    """,
]

INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_tx_user_created ON sms_credit_transactions(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_orders_checkout ON sms_credit_orders(mpesa_checkout_request_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_credit_orders_user_created ON sms_credit_orders(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_message_templates_user ON message_templates(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_campaigns_user_created ON sms_campaigns(user_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_campaign ON sms_messages(campaign_id)",
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_created ON sms_messages(created_at)",
    "CREATE INDEX IF NOT EXISTS ix_sms_messages_failed ON sms_messages(created_at) WHERE status = 'failed'",
    "CREATE INDEX IF NOT EXISTS ix_inbox_recipient_read ON reseller_inbox_messages(recipient_user_id, is_read)",
]


async def migrate():
    async with engine.begin() as conn:
        for name, values in ENUMS.items():
            vals = ", ".join(f"'{v}'" for v in values)
            await conn.execute(text(
                f"DO $$ BEGIN CREATE TYPE {name} AS ENUM ({vals}); "
                f"EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
            ))
        for ddl in TABLES:
            await conn.execute(text(ddl))
        for ddl in INDEXES:
            await conn.execute(text(ddl))
        await conn.execute(text(
            "ALTER TABLE messaging_settings "
            "ALTER COLUMN price_per_sms_kes SET DEFAULT 0.50"
        ))
        await conn.execute(text(
            "ALTER TABLE messaging_settings "
            "ALTER COLUMN provider SET DEFAULT 'talksasa'"
        ))
        await conn.execute(text(
            "INSERT INTO messaging_settings (id, price_per_sms_kes, provider) "
            "VALUES (1, 0.50, 'talksasa') "
            "ON CONFLICT (id) DO UPDATE SET "
            "price_per_sms_kes = EXCLUDED.price_per_sms_kes, "
            "provider = CASE "
            "WHEN messaging_settings.provider = 'africastalking' "
            "THEN EXCLUDED.provider ELSE messaging_settings.provider END, "
            "updated_at = NOW() "
            "WHERE messaging_settings.price_per_sms_kes = 1.00 "
            "OR messaging_settings.provider = 'africastalking'"
        ))
    print("Messaging migration completed successfully!")


async def rollback():
    async with engine.begin() as conn:
        for t in ["sms_messages", "reseller_inbox_messages", "sms_campaigns",
                  "message_templates", "sms_credit_orders",
                  "sms_credit_transactions", "sms_credit_accounts",
                  "messaging_settings"]:
            await conn.execute(text(f"DROP TABLE IF EXISTS {t} CASCADE"))
        for name in ENUMS:
            await conn.execute(text(f"DROP TYPE IF EXISTS {name}"))
    print("Rollback completed.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Messaging tables migration")
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    asyncio.run(rollback() if args.rollback else migrate())

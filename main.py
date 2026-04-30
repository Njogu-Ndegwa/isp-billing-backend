from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text as sa_text
from app.db.database import get_db, async_engine
from app.services.plan_cache import warm_plan_cache
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ISP Billing SaaS API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Router registrations ---
from app.api.radius_endpoints import router as radius_router
from app.api.radius_hotspot import router as radius_hotspot_router
from app.api.session_monitor import router as session_monitor_router
from app.api.auth_routes import router as auth_router
from app.api.public_routes import router as public_router
from app.api.router_management import router as router_mgmt_router
from app.api.router_operations import router as router_ops_router
from app.api.admin_routes import router as admin_router
from app.api.plan_routes import router as plan_router
from app.api.customer_routes import router as customer_router
from app.api.payment_routes import router as payment_router
from app.api.dashboard_routes import router as dashboard_router
from app.api.mikrotik_routes import router as mikrotik_router
from app.api.ads_routes import router as ads_router
from app.api.ratings_routes import router as ratings_router
from app.api.voucher_routes import router as voucher_router
from app.api.provisioning import router as provisioning_router
from app.api.pppoe_monitor import router as pppoe_monitor_router
from app.api.hotspot_monitor import router as hotspot_monitor_router
from app.api.payment_method_routes import router as payment_method_router
from app.api.zenopay_routes import router as zenopay_router
from app.api.mtn_momo_routes import router as mtn_momo_router
from app.api.admin_reseller_routes import router as admin_reseller_router
from app.api.profile_routes import router as profile_router
from app.api.b2b_routes import router as b2b_router
from app.api.subscription_routes import router as subscription_router
from app.api.device_pairing import router as device_pairing_router
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.api.lead_routes import router as lead_router
from app.api.usage_routes import router as usage_router
from app.api.access_credential_routes import router as access_credential_router
from app.api.shop_routes import router as shop_router

app.include_router(radius_router)
app.include_router(radius_hotspot_router)
app.include_router(session_monitor_router)
app.include_router(auth_router)
app.include_router(public_router)
app.include_router(router_mgmt_router)
app.include_router(router_ops_router)
app.include_router(admin_router)
app.include_router(plan_router)
app.include_router(customer_router)
app.include_router(payment_router)
app.include_router(dashboard_router)
app.include_router(mikrotik_router)
app.include_router(ads_router)
app.include_router(ratings_router)
app.include_router(voucher_router)
app.include_router(provisioning_router)
app.include_router(pppoe_monitor_router)
app.include_router(hotspot_monitor_router)
app.include_router(payment_method_router)
app.include_router(zenopay_router)
app.include_router(mtn_momo_router)
app.include_router(admin_reseller_router)
app.include_router(profile_router)
app.include_router(b2b_router)
app.include_router(subscription_router)
app.include_router(device_pairing_router)
app.include_router(admin_metrics_router)
app.include_router(lead_router)
app.include_router(usage_router)
app.include_router(access_credential_router)
app.include_router(shop_router)

# --- Background job imports ---
from app.services.mikrotik_background import (
    cleanup_expired_users_background,
    collect_bandwidth_snapshot,
    # Exported for late-imports from router files
    remove_user_from_mikrotik,
    router_locks,
    _cleanup_customer_from_mikrotik_sync,
    _cleanup_single_router_hotspot_sync,
)
from app.services.hotspot_provisioning import retry_pending_hotspot_provisioning_background
from app.services.mpesa_transactions import reconcile_pending_mpesa_transactions
from app.services.subscription import reconcile_pending_subscription_payments
from app.services.mpesa_b2b import run_daily_payouts

scheduler = AsyncIOScheduler()


# ============================================================================
# RADIUS Auto-Migration (runs on startup, idempotent)
# ============================================================================
async def run_radius_migrations():
    """
    Automatically apply RADIUS database migrations on startup.
    Safe to run every time - only creates columns/tables that don't exist.
    """
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'routers' AND column_name = 'auth_method'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                DO $$ BEGIN
                    CREATE TYPE routerauthmethod AS ENUM ('DIRECT_API', 'RADIUS');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            await conn.execute(sa_text("""
                ALTER TABLE routers 
                ADD COLUMN auth_method routerauthmethod NOT NULL DEFAULT 'DIRECT_API'
            """))
            await conn.execute(sa_text("""
                ALTER TABLE routers 
                ADD COLUMN IF NOT EXISTS radius_secret VARCHAR(255) NULL,
                ADD COLUMN IF NOT EXISTS radius_nas_identifier VARCHAR(100) NULL
            """))
            logger.info("RADIUS migration: Added auth_method, radius_secret, radius_nas_identifier to routers")
        else:
            logger.info("RADIUS migration: Router columns already exist, skipping")

        # --- Router payment_methods column ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'payment_methods'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE routers
                ADD COLUMN payment_methods JSON NOT NULL DEFAULT '["mpesa", "voucher"]'
            """))
            logger.info("Migration: Added payment_methods column to routers")
        else:
            logger.info("Migration: payment_methods column already exists, skipping")

        # --- Router pppoe_ports column ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'pppoe_ports'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE routers
                ADD COLUMN pppoe_ports JSON NULL
            """))
            logger.info("Migration: Added pppoe_ports column to routers")
        else:
            logger.info("Migration: pppoe_ports column already exists, skipping")

        # --- Router dual_ports column ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'dual_ports'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE routers
                ADD COLUMN dual_ports JSON NULL
            """))
            logger.info("Migration: Added dual_ports column to routers")
        else:
            logger.info("Migration: dual_ports column already exists, skipping")

        # --- Voucher table ---
        result = await conn.execute(sa_text("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'vouchers'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                DO $$ BEGIN
                    CREATE TYPE voucherstatus AS ENUM ('available', 'redeemed', 'expired', 'disabled');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            await conn.execute(sa_text("""
                CREATE TABLE vouchers (
                    id SERIAL PRIMARY KEY,
                    code VARCHAR(9) NOT NULL UNIQUE,
                    plan_id INTEGER NOT NULL REFERENCES plans(id),
                    router_id INTEGER REFERENCES routers(id),
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    status voucherstatus NOT NULL DEFAULT 'available',
                    batch_id VARCHAR(36),
                    redeemed_by INTEGER REFERENCES customers(id),
                    redeemed_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))
            await conn.execute(sa_text("CREATE INDEX idx_vouchers_code ON vouchers(code)"))
            await conn.execute(sa_text("CREATE INDEX idx_vouchers_status ON vouchers(status)"))
            await conn.execute(sa_text("CREATE INDEX idx_vouchers_batch ON vouchers(batch_id)"))
            await conn.execute(sa_text("CREATE INDEX idx_vouchers_user ON vouchers(user_id)"))
            logger.info("Voucher migration: Created vouchers table")
        else:
            logger.info("Voucher migration: Table already exists, skipping")

        # --- Indexes on customer_payments for fast transaction queries ---
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_cp_reseller_id ON customer_payments(reseller_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_cp_created_at ON customer_payments(created_at DESC)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_cp_payment_method ON customer_payments(payment_method)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_cp_lipay_tx_no ON customer_payments(lipay_tx_no)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_mpesa_tx_lipay ON mpesa_transactions(lipay_tx_no)"
        ))
        logger.info("Migration: Ensured indexes exist on customer_payments and mpesa_transactions")

        # --- Provisioning tokens table ---
        result = await conn.execute(sa_text("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'provisioning_tokens'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                DO $$ BEGIN
                    CREATE TYPE provisioningtokenstatus AS ENUM ('pending', 'provisioned', 'expired');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            await conn.execute(sa_text("""
                CREATE TABLE provisioning_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    token VARCHAR(64) NOT NULL UNIQUE,
                    router_name VARCHAR(255) NOT NULL,
                    identity VARCHAR(255) NOT NULL,
                    wireguard_ip VARCHAR(15) NOT NULL,
                    ssid VARCHAR(100) NOT NULL DEFAULT 'Bitwave WiFi',
                    router_admin_password VARCHAR(255) NOT NULL DEFAULT 'admin',
                    wg_private_key TEXT NOT NULL,
                    wg_public_key TEXT NOT NULL,
                    server_wg_pubkey TEXT NOT NULL,
                    server_public_ip VARCHAR(45) NOT NULL,
                    payment_methods JSON NOT NULL DEFAULT '["mpesa", "voucher"]',
                    status provisioningtokenstatus NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT NOW(),
                    provisioned_at TIMESTAMP,
                    router_id INTEGER REFERENCES routers(id)
                )
            """))
            await conn.execute(sa_text(
                "CREATE INDEX idx_provisioning_tokens_token ON provisioning_tokens(token)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_provisioning_tokens_user ON provisioning_tokens(user_id)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_provisioning_tokens_status ON provisioning_tokens(status)"
            ))
            logger.info("Migration: Created provisioning_tokens table")
        else:
            logger.info("Migration: provisioning_tokens table already exists, skipping")

        # --- Provisioning attempts table / provisioning_logs correlation ---
        from app.db.models import ProvisioningAttempt
        await conn.run_sync(
            lambda c: ProvisioningAttempt.__table__.create(c, checkfirst=True)
        )
        await conn.execute(sa_text(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_provisioning_attempts_source "
            "ON provisioning_attempts(source_table, source_pk)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_provisioning_attempts_state_updated "
            "ON provisioning_attempts(provisioning_state, updated_at)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_provisioning_attempts_customer "
            "ON provisioning_attempts(customer_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_provisioning_attempts_external_reference "
            "ON provisioning_attempts(external_reference)"
        ))

        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_logs' AND column_name = 'attempt_id'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE provisioning_logs
                ADD COLUMN attempt_id INTEGER NULL
            """))
            logger.info("Migration: Added attempt_id column to provisioning_logs")
        else:
            logger.info("Migration: provisioning_logs.attempt_id already exists, skipping")

        await conn.execute(sa_text("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'fk_provisioning_logs_attempt_id'
                ) THEN
                    ALTER TABLE provisioning_logs
                    ADD CONSTRAINT fk_provisioning_logs_attempt_id
                    FOREIGN KEY (attempt_id) REFERENCES provisioning_attempts(id);
                END IF;
            END $$;
        """))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_provisioning_logs_attempt_id "
            "ON provisioning_logs(attempt_id)"
        ))

        # --- Provisioning tokens: add vpn_type + L2TP columns, relax WG NOT NULL ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_tokens' AND column_name = 'vpn_type'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN vpn_type VARCHAR(20) NOT NULL DEFAULT 'wireguard'
            """))
            await conn.execute(sa_text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN IF NOT EXISTS l2tp_username VARCHAR NULL,
                ADD COLUMN IF NOT EXISTS l2tp_password VARCHAR NULL
            """))
            for col in ("wg_private_key", "wg_public_key", "server_wg_pubkey"):
                await conn.execute(sa_text(f"""
                    ALTER TABLE provisioning_tokens
                    ALTER COLUMN {col} DROP NOT NULL
                """))
            logger.info("Migration: Added vpn_type, l2tp columns to provisioning_tokens; relaxed WG NOT NULL")
        else:
            logger.info("Migration: provisioning_tokens vpn_type column already exists, skipping")

        # --- Provisioning tokens: add is_routerboard opt-in flag (v6 hEX/RouterBOARD split-FS) ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'provisioning_tokens' AND column_name = 'is_routerboard'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE provisioning_tokens
                ADD COLUMN is_routerboard BOOLEAN NOT NULL DEFAULT FALSE
            """))
            logger.info("Migration: Added is_routerboard column to provisioning_tokens")
        else:
            logger.info("Migration: provisioning_tokens is_routerboard column already exists, skipping")

        # --- PPPoE columns on customers table ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'customers' AND column_name = 'pppoe_username'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE customers
                ADD COLUMN pppoe_username VARCHAR NULL,
                ADD COLUMN pppoe_password VARCHAR NULL
            """))
            logger.info("PPPoE migration: Added pppoe_username, pppoe_password to customers")
        else:
            logger.info("PPPoE migration: Customer PPPoE columns already exist, skipping")

        # --- ConnectionType enum: ensure 'pppoe' value exists ---
        result = await conn.execute(sa_text("""
            SELECT 1 FROM pg_enum
            WHERE enumlabel = 'pppoe'
              AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'connectiontype')
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TYPE connectiontype ADD VALUE IF NOT EXISTS 'pppoe'
            """))
            logger.info("PPPoE migration: Added 'pppoe' to connectiontype enum")
        else:
            logger.info("PPPoE migration: 'pppoe' value already exists in connectiontype enum, skipping")

        # --- Plan emergency/special offer columns ---
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'plans' AND column_name = 'plan_type'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                DO $$ BEGIN
                    CREATE TYPE plantype AS ENUM ('regular', 'emergency', 'special_offer');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            await conn.execute(sa_text("""
                ALTER TABLE plans
                ADD COLUMN plan_type plantype NOT NULL DEFAULT 'regular',
                ADD COLUMN is_hidden BOOLEAN NOT NULL DEFAULT false,
                ADD COLUMN badge_text VARCHAR(100) NULL,
                ADD COLUMN original_price INTEGER NULL,
                ADD COLUMN valid_until TIMESTAMP NULL
            """))
            logger.info("Plan migration: Added plan_type, is_hidden, badge_text, original_price, valid_until to plans")
        else:
            logger.info("Plan migration: Emergency/special offer columns already exist, skipping")

        # --- Router emergency mode columns ---
        result = await conn.execute(sa_text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'emergency_active'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE routers
                ADD COLUMN emergency_active BOOLEAN NOT NULL DEFAULT false,
                ADD COLUMN emergency_message VARCHAR(500) NULL
            """))
            logger.info("Migration: Added emergency_active, emergency_message to routers")
        else:
            logger.info("Migration: Router emergency columns already exist, skipping")

        result = await conn.execute(sa_text("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_name = 'radius_check'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
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
            await conn.execute(sa_text("CREATE INDEX idx_radius_check_username ON radius_check(username)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_check_customer ON radius_check(customer_id)"))
            await conn.execute(sa_text("""
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
            await conn.execute(sa_text("CREATE INDEX idx_radius_reply_username ON radius_reply(username)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_reply_customer ON radius_reply(customer_id)"))
            await conn.execute(sa_text("""
                CREATE TABLE radius_groupcheck (
                    id SERIAL PRIMARY KEY,
                    groupname VARCHAR(64) NOT NULL,
                    attribute VARCHAR(64) NOT NULL,
                    op CHAR(2) NOT NULL DEFAULT ':=',
                    value VARCHAR(253) NOT NULL
                )
            """))
            await conn.execute(sa_text("CREATE INDEX idx_radius_groupcheck_groupname ON radius_groupcheck(groupname)"))
            await conn.execute(sa_text("""
                CREATE TABLE radius_groupreply (
                    id SERIAL PRIMARY KEY,
                    groupname VARCHAR(64) NOT NULL,
                    attribute VARCHAR(64) NOT NULL,
                    op CHAR(2) NOT NULL DEFAULT ':=',
                    value VARCHAR(253) NOT NULL
                )
            """))
            await conn.execute(sa_text("CREATE INDEX idx_radius_groupreply_groupname ON radius_groupreply(groupname)"))
            await conn.execute(sa_text("""
                CREATE TABLE radius_usergroup (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    groupname VARCHAR(64) NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 1
                )
            """))
            await conn.execute(sa_text("CREATE INDEX idx_radius_usergroup_username ON radius_usergroup(username)"))
            await conn.execute(sa_text("""
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
            await conn.execute(sa_text("CREATE UNIQUE INDEX idx_radius_acct_unique ON radius_accounting(acctuniqueid)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_acct_username ON radius_accounting(username)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_acct_start ON radius_accounting(acctstarttime)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_acct_stop ON radius_accounting(acctstoptime)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_acct_nasip ON radius_accounting(nasipaddress)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_acct_callingstationid ON radius_accounting(callingstationid)"))
            await conn.execute(sa_text("""
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
            await conn.execute(sa_text("CREATE INDEX idx_radius_postauth_username ON radius_postauth(username)"))
            await conn.execute(sa_text("CREATE INDEX idx_radius_postauth_date ON radius_postauth(authdate)"))
            await conn.execute(sa_text("""
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
            await conn.execute(sa_text("CREATE INDEX idx_radius_nas_nasname ON radius_nas(nasname)"))
            logger.info("RADIUS migration: Created all RADIUS tables")
        else:
            logger.info("RADIUS migration: Tables already exist, skipping")


# ============================================================================
# Payment Method Migrations (runs on startup, idempotent)
# ============================================================================
async def run_payment_method_migrations():
    """Create tables and columns needed for the multi-payment-method feature."""
    async with async_engine.begin() as conn:
        # Create enum types
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE resellerpaymentmethodtype AS ENUM "
            "('bank_account', 'mpesa_paybill', 'mpesa_paybill_with_keys', 'zenopay'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; "
            "END $$"
        ))
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE collectionmode AS ENUM ('direct', 'system_collected'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; "
            "END $$"
        ))
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE zenopaytransactionstatus AS ENUM ('pending', 'completed', 'failed'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; "
            "END $$"
        ))

        # Create tables via ORM (checkfirst=True is safe to repeat)
        from app.db.models import (
            ResellerPaymentMethod, ZenoPayTransaction, ResellerPayout,
        )
        await conn.run_sync(
            lambda c: ResellerPaymentMethod.__table__.create(c, checkfirst=True)
        )
        await conn.run_sync(
            lambda c: ZenoPayTransaction.__table__.create(c, checkfirst=True)
        )
        await conn.run_sync(
            lambda c: ResellerPayout.__table__.create(c, checkfirst=True)
        )

        # Add payment_method_id FK to routers if missing
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'routers' AND column_name = 'payment_method_id'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE routers
                ADD COLUMN payment_method_id INTEGER NULL
                REFERENCES reseller_payment_methods(id)
            """))
            logger.info("Migration: Added payment_method_id column to routers")

        # Add collection_mode to customer_payments if missing
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'customer_payments' AND column_name = 'collection_mode'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                ALTER TABLE customer_payments
                ADD COLUMN collection_mode collectionmode NULL
            """))
            logger.info("Migration: Added collection_mode column to customer_payments")

        # Create reseller_transaction_charges table if it doesn't exist
        from app.db.models import ResellerTransactionCharge
        await conn.run_sync(
            lambda c: ResellerTransactionCharge.__table__.create(c, checkfirst=True)
        )
        logger.info("Migration: Ensured reseller_transaction_charges table exists")


# ============================================================================
# User column migrations (runs on startup, idempotent)
# ============================================================================
async def run_user_migrations():
    """Add columns to the users table that were introduced after initial creation."""
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'last_login_at'
        """))
        if not result.fetchone():
            await conn.execute(sa_text(
                "ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP NULL"
            ))
            logger.info("Migration: Added last_login_at column to users")
        else:
            logger.info("Migration: users.last_login_at already exists, skipping")


# ============================================================================
# Startup / Shutdown
# ============================================================================
async def run_monitoring_migrations():
    """Create monitoring tables/columns used for router health history."""
    async with async_engine.begin() as conn:
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE routerlogseverity AS ENUM ('info', 'warning', 'error'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; "
            "END $$"
        ))
        await conn.execute(sa_text("""
            ALTER TABLE routers
            ADD COLUMN IF NOT EXISTS last_status BOOLEAN NULL,
            ADD COLUMN IF NOT EXISTS last_checked_at TIMESTAMP NULL,
            ADD COLUMN IF NOT EXISTS last_online_at TIMESTAMP NULL,
            ADD COLUMN IF NOT EXISTS last_status_source VARCHAR(50) NULL,
            ADD COLUMN IF NOT EXISTS availability_checks INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS availability_successes INTEGER NOT NULL DEFAULT 0
        """))
        from app.db.models import RouterLogEntry, RouterAvailabilityCheck  # noqa: F401
        await conn.run_sync(
            lambda c: RouterLogEntry.__table__.create(c, checkfirst=True)
        )
        await conn.run_sync(
            lambda c: RouterAvailabilityCheck.__table__.create(c, checkfirst=True)
        )
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_router_availability_router_checked "
            "ON router_availability_checks(router_id, checked_at)"
        ))


async def run_reconnection_migrations():
    """Create reconnection_attempts table for self-service reconnect (idempotent)."""
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'reconnection_attempts'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                CREATE TABLE reconnection_attempts (
                    id SERIAL PRIMARY KEY,
                    phone VARCHAR NOT NULL,
                    mac_address VARCHAR NOT NULL,
                    router_id INTEGER NOT NULL REFERENCES routers(id),
                    customer_id INTEGER REFERENCES customers(id),
                    success BOOLEAN NOT NULL DEFAULT FALSE,
                    failure_reason VARCHAR(255),
                    old_mac_address VARCHAR,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """))
            await conn.execute(sa_text(
                "CREATE INDEX idx_reconnect_phone ON reconnection_attempts(phone)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_reconnect_mac ON reconnection_attempts(mac_address)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_reconnect_created ON reconnection_attempts(created_at)"
            ))
            logger.info("Migration: Created reconnection_attempts table")
        else:
            logger.info("Migration: reconnection_attempts table already exists, skipping")


# ============================================================================
# Device Pairing Migrations (runs on startup, idempotent)
# ============================================================================
async def run_device_pairing_migrations():
    """Create device_pairings table for companion device pairing (TVs, consoles, etc.)."""
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'device_pairings'
        """))
        if not result.fetchone():
            await conn.execute(sa_text("""
                DO $$ BEGIN
                    CREATE TYPE devicetype AS ENUM ('tv', 'console', 'laptop', 'iot', 'other');
                EXCEPTION
                    WHEN duplicate_object THEN null;
                END $$;
            """))
            await conn.execute(sa_text("""
                CREATE TABLE device_pairings (
                    id SERIAL PRIMARY KEY,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    device_mac VARCHAR NOT NULL,
                    device_name VARCHAR(100),
                    device_type devicetype NOT NULL DEFAULT 'tv',
                    router_id INTEGER NOT NULL REFERENCES routers(id),
                    plan_id INTEGER REFERENCES plans(id),
                    is_active BOOLEAN DEFAULT TRUE,
                    provisioned_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW(),
                    CONSTRAINT uq_device_mac_per_router UNIQUE (device_mac, router_id)
                )
            """))
            await conn.execute(sa_text(
                "CREATE INDEX idx_device_pairings_customer ON device_pairings(customer_id)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_device_pairings_mac ON device_pairings(device_mac)"
            ))
            await conn.execute(sa_text(
                "CREATE INDEX idx_device_pairings_router ON device_pairings(router_id)"
            ))
            logger.info("Migration: Created device_pairings table")
        else:
            logger.info("Migration: device_pairings table already exists, skipping")


# ============================================================================
# B2B Payout Migrations (runs on startup, idempotent)
# ============================================================================
async def run_b2b_migrations():
    """Create tables and enums needed for B2B reseller payouts."""
    async with async_engine.begin() as conn:
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE b2btransactionstatus AS ENUM "
            "('pending', 'completed', 'failed', 'timeout'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; "
            "END $$"
        ))
        from app.db.models import B2BTransaction
        await conn.run_sync(
            lambda c: B2BTransaction.__table__.create(c, checkfirst=True)
        )

        # Add any columns missing from an earlier version of the table
        _b2b_columns = [
            ("conversation_id", "VARCHAR(255)"),
            ("originator_conversation_id", "VARCHAR(255)"),
            ("amount", "FLOAT NOT NULL DEFAULT 0"),
            ("fee", "FLOAT NOT NULL DEFAULT 0"),
            ("net_amount", "FLOAT NOT NULL DEFAULT 0"),
            ("party_a", "VARCHAR(20) NOT NULL DEFAULT ''"),
            ("party_b", "VARCHAR(20) NOT NULL DEFAULT ''"),
            ("account_reference", "VARCHAR(255)"),
            ("command_id", "VARCHAR(50) NOT NULL DEFAULT 'BusinessPayBill'"),
            ("remarks", "VARCHAR(255)"),
            ("result_code", "VARCHAR(50)"),
            ("result_desc", "VARCHAR(500)"),
            ("transaction_id", "VARCHAR(255)"),
            ("payout_id", "INTEGER"),
            ("charge_id", "INTEGER"),
            ("completed_at", "TIMESTAMP"),
        ]
        for col_name, col_type in _b2b_columns:
            await conn.execute(sa_text(
                f"ALTER TABLE b2b_transactions ADD COLUMN IF NOT EXISTS "
                f"{col_name} {col_type}"
            ))

        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_b2b_reseller_id "
            "ON b2b_transactions(reseller_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_b2b_created_at "
            "ON b2b_transactions(created_at)"
        ))
        await conn.execute(sa_text(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_b2b_conversation_id "
            "ON b2b_transactions(conversation_id) WHERE conversation_id IS NOT NULL"
        ))
        logger.info("Migration: Ensured b2b_transactions table and indexes exist")

    async with async_engine.begin() as conn:
        await conn.execute(sa_text(
            "ALTER TABLE b2b_transactions "
            "ADD COLUMN IF NOT EXISTS triggered_by VARCHAR(20) NULL"
        ))


# ============================================================================
# Subscription System Migrations (runs on startup, idempotent)
# ============================================================================
async def _run_sql(label: str, sql: str):
    """Run a single migration step in its own transaction."""
    try:
        async with async_engine.begin() as conn:
            await conn.execute(sa_text(sql))
        logger.info(f"[SUB-MIGRATION] {label}: OK")
    except Exception as e:
        logger.warning(f"[SUB-MIGRATION] {label}: {e}")


async def run_subscription_migrations():
    """Create subscription tables and columns for reseller billing."""

    # Step 1: Create enum types (each in its own transaction)
    await _run_sql("Create subscriptionstatus enum",
        "DO $$ BEGIN "
        "CREATE TYPE subscriptionstatus AS ENUM ('active', 'inactive', 'trial', 'suspended'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    await _run_sql("Create invoicestatus enum",
        "DO $$ BEGIN "
        "CREATE TYPE invoicestatus AS ENUM ('pending', 'paid', 'overdue', 'waived'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    await _run_sql("Create subscriptionpaymentstatus enum",
        "DO $$ BEGIN "
        "CREATE TYPE subscriptionpaymentstatus AS ENUM ('pending', 'completed', 'failed'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )

    # Step 2: Add subscription columns to users table (separate statements)
    await _run_sql("Add users.subscription_status",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
        "subscription_status subscriptionstatus NOT NULL DEFAULT 'trial'"
    )
    await _run_sql("Add users.subscription_expires_at",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
        "subscription_expires_at TIMESTAMP NULL"
    )

    # Step 3: Evolve or create subscriptions table
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = 'subscriptions'"
        ))
        table_exists = result.fetchone() is not None

    if table_exists:
        for col_name, col_type in [
            ("status", "subscriptionstatus DEFAULT 'trial'"),
            ("current_period_start", "TIMESTAMP NULL"),
            ("current_period_end", "TIMESTAMP NULL"),
            ("trial_ends_at", "TIMESTAMP NULL"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("updated_at", "TIMESTAMP DEFAULT NOW()"),
            ("is_active", "BOOLEAN NULL"),
            ("paid_on", "TIMESTAMP NULL"),
            ("expires_on", "TIMESTAMP NULL"),
            ("plan_type", "VARCHAR NULL"),
            ("cost", "FLOAT NULL"),
        ]:
            await _run_sql(f"Add subscriptions.{col_name}",
                f"ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
            )
        for col in ("plan_type", "cost"):
            await _run_sql(f"Make subscriptions.{col} nullable",
                f"DO $$ BEGIN "
                f"ALTER TABLE subscriptions ALTER COLUMN {col} DROP NOT NULL; "
                f"EXCEPTION WHEN undefined_column THEN NULL; WHEN others THEN NULL; "
                f"END $$"
            )
        await _run_sql("Add subscriptions unique user_id constraint",
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_subscriptions_user_id') THEN "
            "BEGIN ALTER TABLE subscriptions ADD CONSTRAINT uq_subscriptions_user_id UNIQUE (user_id); "
            "EXCEPTION WHEN unique_violation THEN NULL; END; "
            "END IF; END $$"
        )
    else:
        await _run_sql("Create subscriptions table",
            "CREATE TABLE subscriptions ("
            "id SERIAL PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES users(id) UNIQUE, "
            "status subscriptionstatus NOT NULL DEFAULT 'trial', "
            "current_period_start TIMESTAMP NULL, "
            "current_period_end TIMESTAMP NULL, "
            "trial_ends_at TIMESTAMP NULL, "
            "created_at TIMESTAMP DEFAULT NOW(), "
            "updated_at TIMESTAMP DEFAULT NOW(), "
            "is_active BOOLEAN NULL, "
            "paid_on TIMESTAMP NULL, "
            "expires_on TIMESTAMP NULL, "
            "plan_type VARCHAR NULL, "
            "cost FLOAT NULL)"
        )

    # Step 4: Create subscription_invoices table
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = 'subscription_invoices'"
        ))
        has_invoices = result.fetchone() is not None

    if not has_invoices:
        await _run_sql("Create subscription_invoices table",
            "CREATE TABLE subscription_invoices ("
            "id SERIAL PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES users(id), "
            "period_start TIMESTAMP NOT NULL, "
            "period_end TIMESTAMP NOT NULL, "
            "hotspot_revenue FLOAT NOT NULL DEFAULT 0, "
            "hotspot_charge FLOAT NOT NULL DEFAULT 0, "
            "pppoe_user_count INTEGER NOT NULL DEFAULT 0, "
            "pppoe_charge FLOAT NOT NULL DEFAULT 0, "
            "gross_charge FLOAT NOT NULL DEFAULT 0, "
            "final_charge FLOAT NOT NULL DEFAULT 0, "
            "status invoicestatus NOT NULL DEFAULT 'pending', "
            "due_date TIMESTAMP NOT NULL, "
            "paid_at TIMESTAMP NULL, "
            "created_at TIMESTAMP DEFAULT NOW(), "
            "CONSTRAINT uq_subscription_invoice_user_period UNIQUE (user_id, period_start))"
        )
        await _run_sql("Index subscription_invoices.user_id",
            "CREATE INDEX IF NOT EXISTS idx_sub_invoices_user ON subscription_invoices(user_id)"
        )
        await _run_sql("Index subscription_invoices.status",
            "CREATE INDEX IF NOT EXISTS idx_sub_invoices_status ON subscription_invoices(status)"
        )
        await _run_sql("Index subscription_invoices.due_date",
            "CREATE INDEX IF NOT EXISTS idx_sub_invoices_due ON subscription_invoices(due_date)"
        )

    # Step 5: Create subscription_payments table
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = 'subscription_payments'"
        ))
        has_payments = result.fetchone() is not None

    if not has_payments:
        await _run_sql("Create subscription_payments table",
            "CREATE TABLE subscription_payments ("
            "id SERIAL PRIMARY KEY, "
            "invoice_id INTEGER REFERENCES subscription_invoices(id), "
            "user_id INTEGER NOT NULL REFERENCES users(id), "
            "amount FLOAT NOT NULL, "
            "payment_method VARCHAR(50) NOT NULL DEFAULT 'mpesa', "
            "payment_reference VARCHAR(255) NULL, "
            "mpesa_checkout_request_id VARCHAR(255) NULL UNIQUE, "
            "phone_number VARCHAR(20) NULL, "
            "status subscriptionpaymentstatus NOT NULL DEFAULT 'pending', "
            "created_at TIMESTAMP DEFAULT NOW())"
        )
        await _run_sql("Index subscription_payments.user_id",
            "CREATE INDEX IF NOT EXISTS idx_sub_payments_user ON subscription_payments(user_id)"
        )
        await _run_sql("Index subscription_payments.invoice_id",
            "CREATE INDEX IF NOT EXISTS idx_sub_payments_invoice ON subscription_payments(invoice_id)"
        )
        await _run_sql("Index subscription_payments.checkout_id",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_payments_checkout "
            "ON subscription_payments(mpesa_checkout_request_id) "
            "WHERE mpesa_checkout_request_id IS NOT NULL"
        )

    # Step 6: Set trial expiry for existing resellers (use text casts for safety)
    await _run_sql("Set trial expiry for resellers (NULL)",
        "UPDATE users SET subscription_expires_at = NOW() + INTERVAL '7 days' "
        "WHERE role::text = 'reseller' AND subscription_status::text = 'trial' "
        "AND subscription_expires_at IS NULL"
    )
    await _run_sql("Reset expired trial dates",
        "UPDATE users SET subscription_expires_at = NOW() + INTERVAL '7 days' "
        "WHERE role::text = 'reseller' AND subscription_status::text = 'trial' "
        "AND subscription_expires_at < NOW()"
    )
    # Step 7: Fix legacy columns that may have been created with NOT NULL
    for col in ("is_active", "paid_on", "expires_on", "plan_type", "cost"):
        await _run_sql(f"Allow NULL on subscriptions.{col}",
            f"ALTER TABLE subscriptions ALTER COLUMN {col} DROP NOT NULL"
        )

    logger.info("Migration: Subscription system tables and columns ready")


async def run_growth_targets_migration():
    """Create growth_targets table if it doesn't exist."""
    async with async_engine.begin() as conn:
        result = await conn.execute(sa_text(
            "SELECT to_regclass('public.growth_targets')"
        ))
        if result.scalar() is None:
            await conn.execute(sa_text("""
                CREATE TABLE growth_targets (
                    id SERIAL PRIMARY KEY,
                    target_id VARCHAR(100) UNIQUE NOT NULL,
                    label VARCHAR(255) NOT NULL,
                    target_value DOUBLE PRECISION NOT NULL,
                    unit VARCHAR(50) NOT NULL,
                    period VARCHAR(100) NOT NULL,
                    inverse BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """))
            logger.info("Migration: Created growth_targets table")
        else:
            logger.info("Migration: growth_targets table already exists, skipping")


# ============================================================================
# FUP / per-customer usage migrations (runs on startup, idempotent)
# ============================================================================
async def run_fup_usage_migrations():
    """Add FUP fields to plans, delta-tracking columns to user_bandwidth_usage,
    and create the customer_usage_periods table.

    Mirrors migrations/add_fup_usage_tracking.py but runs automatically on
    startup so deploys don't require a separate manual step. Idempotent: every
    ALTER/CREATE is gated on a catalog existence check.
    """
    async with async_engine.begin() as conn:
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE fupaction AS ENUM ('throttle', 'block', 'notify_only'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        ))

        await conn.execute(sa_text(
            "ALTER TABLE plans ADD COLUMN IF NOT EXISTS data_cap_mb BIGINT NULL"
        ))
        await conn.execute(sa_text(
            "ALTER TABLE plans ADD COLUMN IF NOT EXISTS fup_action fupaction NULL"
        ))
        await conn.execute(sa_text(
            "ALTER TABLE plans ADD COLUMN IF NOT EXISTS fup_throttle_profile VARCHAR(100) NULL"
        ))

        await conn.execute(sa_text(
            "ALTER TABLE user_bandwidth_usage "
            "ADD COLUMN IF NOT EXISTS last_upload_bytes BIGINT NOT NULL DEFAULT 0"
        ))
        await conn.execute(sa_text(
            "ALTER TABLE user_bandwidth_usage "
            "ADD COLUMN IF NOT EXISTS last_download_bytes BIGINT NOT NULL DEFAULT 0"
        ))

        await conn.execute(sa_text(
            """
            CREATE TABLE IF NOT EXISTS customer_usage_periods (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL REFERENCES customers(id),
                period_start TIMESTAMP NOT NULL,
                period_end TIMESTAMP NOT NULL,
                upload_bytes BIGINT NOT NULL DEFAULT 0,
                download_bytes BIGINT NOT NULL DEFAULT 0,
                total_bytes BIGINT NOT NULL DEFAULT 0,
                cap_mb_snapshot BIGINT NULL,
                fup_action_snapshot fupaction NULL,
                fup_triggered_at TIMESTAMP NULL,
                fup_action_taken fupaction NULL,
                fup_reverted_at TIMESTAMP NULL,
                closed_at TIMESTAMP NULL,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_customer_period_start UNIQUE (customer_id, period_start)
            )
            """
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_customer_id "
            "ON customer_usage_periods (customer_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_period_start "
            "ON customer_usage_periods (period_start)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_closed_at "
            "ON customer_usage_periods (closed_at)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS ix_customer_usage_periods_customer_open "
            "ON customer_usage_periods (customer_id, closed_at)"
        ))
        logger.info(
            "Migration: Ensured FUP enum, plans/user_bandwidth_usage columns, "
            "and customer_usage_periods table"
        )


# ============================================================================
# Access Credentials Migrations (runs on startup, idempotent)
# ============================================================================
async def run_access_credential_migrations():
    """Create access_credentials table for reseller-managed comp hotspot logins."""
    async with async_engine.begin() as conn:
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE accesscredstatus AS ENUM ('active', 'revoked'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        ))

        from app.db.models import AccessCredential
        await conn.run_sync(
            lambda c: AccessCredential.__table__.create(c, checkfirst=True)
        )

        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_access_cred_user "
            "ON access_credentials(user_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_access_cred_router "
            "ON access_credentials(router_id)"
        ))
        await conn.execute(sa_text(
            "CREATE INDEX IF NOT EXISTS idx_access_cred_bound_mac "
            "ON access_credentials(bound_mac_address)"
        ))
        logger.info("Migration: Ensured access_credentials table and indexes exist")


# ============================================================================
# Lead Pipeline Migrations (runs on startup, idempotent)
# ============================================================================
async def run_lead_pipeline_migrations():
    """Create tables for the lead tracking / CRM pipeline module."""
    async with async_engine.begin() as conn:
        # Create enum types
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE leadstage AS ENUM "
            "('new_lead', 'contacted', 'talking', 'installation_help', "
            "'signed_up', 'paying', 'churned', 'lost'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        ))
        await conn.execute(sa_text(
            "DO $$ BEGIN "
            "CREATE TYPE leadactivitytype AS ENUM "
            "('note', 'call', 'dm', 'email', 'meeting', "
            "'stage_change', 'followup_completed', 'other'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
        ))

        # Create tables via ORM
        from app.db.models import LeadSource, Lead, LeadActivity, LeadFollowUp
        await conn.run_sync(lambda c: LeadSource.__table__.create(c, checkfirst=True))
        await conn.run_sync(lambda c: Lead.__table__.create(c, checkfirst=True))
        await conn.run_sync(lambda c: LeadActivity.__table__.create(c, checkfirst=True))
        await conn.run_sync(lambda c: LeadFollowUp.__table__.create(c, checkfirst=True))

        # Seed default lead sources (skip if any already exist)
        result = await conn.execute(sa_text("SELECT COUNT(*) FROM lead_sources"))
        count = result.scalar()
        if count == 0:
            # Find an admin user to assign as owner
            admin_result = await conn.execute(sa_text(
                "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
            ))
            admin_row = admin_result.fetchone()
            if admin_row:
                admin_id = admin_row[0]
                default_sources = [
                    ("Instagram", "Leads from Instagram DMs and comments"),
                    ("TikTok", "Leads from TikTok videos and comments"),
                    ("WhatsApp", "Leads from WhatsApp messages"),
                    ("Referral", "Leads referred by existing customers"),
                    ("Phone Call", "Leads from phone inquiries"),
                    ("Walk-in", "Leads who visited in person"),
                    ("Website", "Leads from website contact forms"),
                    ("Facebook", "Leads from Facebook posts and messages"),
                    ("Other", "Leads from other channels"),
                ]
                for name, desc in default_sources:
                    await conn.execute(sa_text(
                        "INSERT INTO lead_sources (name, description, is_active, user_id, created_at) "
                        "VALUES (:name, :desc, true, :uid, NOW())"
                    ), {"name": name, "desc": desc, "uid": admin_id})
                logger.info(f"Migration: Seeded {len(default_sources)} default lead sources")
            else:
                logger.info("Migration: No admin user found, skipping lead source seeding")
        else:
            logger.info("Migration: Lead sources already populated, skipping seed")

    logger.info("Migration: Lead pipeline tables and enums ready")


async def run_payment_history_migrations():
    """
    Four idempotent schema changes that protect payment history:

    1. Make customer_payments.customer_id nullable — rows survive customer deletion.
    2. Add customer_name snapshot column — displays name even after customer deleted.
    3. Back-fill customer_name from live customers table.
    4. Add balance_correction + balance_corrected_at to reseller_financials — used
       by the /api/admin/repair-balance endpoint to fix balances damaged by past
       cascading deletes without touching non-affected users.
    5. Change router_availability_checks FK from ON DELETE CASCADE → RESTRICT so
       router deletion never silently wipes monitoring history (the deletion handler
       now does this explicitly).
    """
    async with async_engine.begin() as conn:
        # ── 1. Drop NOT NULL on customer_payments.customer_id ──────────────
        await conn.execute(sa_text("""
            DO $$ BEGIN
                ALTER TABLE customer_payments ALTER COLUMN customer_id DROP NOT NULL;
            EXCEPTION WHEN others THEN NULL;
            END $$
        """))

        # ── 2. Add customer_name snapshot column ────────────────────────────
        await conn.execute(sa_text(
            "ALTER TABLE customer_payments "
            "ADD COLUMN IF NOT EXISTS customer_name VARCHAR(255) NULL"
        ))

        # ── 3. Back-fill customer_name for rows that still have a customer_id ─
        await conn.execute(sa_text("""
            UPDATE customer_payments cp
            SET customer_name = c.name
            FROM customers c
            WHERE cp.customer_id = c.id
              AND cp.customer_name IS NULL
        """))

        # ── 4. Balance correction columns on reseller_financials ─────────────
        await conn.execute(sa_text(
            "ALTER TABLE reseller_financials "
            "ADD COLUMN IF NOT EXISTS balance_correction FLOAT NOT NULL DEFAULT 0.0"
        ))
        await conn.execute(sa_text(
            "ALTER TABLE reseller_financials "
            "ADD COLUMN IF NOT EXISTS balance_corrected_at TIMESTAMP NULL"
        ))

        # ── 5. Change router_availability_checks FK: CASCADE → RESTRICT ──────
        # Drop the old FK (name may vary; try both the auto-generated name and a
        # custom one — ignore errors if neither exists).
        await conn.execute(sa_text("""
            DO $$ BEGIN
                ALTER TABLE router_availability_checks
                    DROP CONSTRAINT IF EXISTS router_availability_checks_router_id_fkey;
            EXCEPTION WHEN undefined_object THEN NULL;
            END $$
        """))
        # Re-add with RESTRICT so deletion is always explicit in application code
        await conn.execute(sa_text("""
            DO $$ BEGIN
                ALTER TABLE router_availability_checks
                    ADD CONSTRAINT router_availability_checks_router_id_fkey
                    FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE RESTRICT;
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
        """))

    logger.info("Migration: payment-history preservation + balance-correction + cascade-guard schema ready")


async def run_shop_migrations():
    """Create shop tables (idempotent)."""
    async with async_engine.begin() as conn:
        await conn.execute(sa_text("""
            DO $$ BEGIN
                CREATE TYPE shoporderstatus AS ENUM (
                    'pending','confirmed','processing','shipped','delivered','cancelled'
                );
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
        """))
        await conn.execute(sa_text("""
            DO $$ BEGIN
                CREATE TYPE shoporderpaymentstatus AS ENUM ('unpaid','paid','refunded');
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
        """))
        await conn.execute(sa_text("""
            CREATE TABLE IF NOT EXISTS shop_products (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name VARCHAR(255) NOT NULL,
                description VARCHAR(2000),
                price NUMERIC(10,2) NOT NULL,
                stock_quantity INTEGER NOT NULL DEFAULT 0,
                image_url VARCHAR(500),
                category VARCHAR(100),
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))
        await conn.execute(sa_text("""
            CREATE TABLE IF NOT EXISTS shop_orders (
                id SERIAL PRIMARY KEY,
                order_number VARCHAR(20) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                buyer_name VARCHAR(255) NOT NULL,
                buyer_phone VARCHAR(20) NOT NULL,
                buyer_email VARCHAR(100),
                delivery_address VARCHAR(500),
                total_amount NUMERIC(10,2) NOT NULL,
                status shoporderstatus NOT NULL DEFAULT 'pending',
                payment_status shoporderpaymentstatus NOT NULL DEFAULT 'unpaid',
                mpesa_checkout_request_id VARCHAR(255) UNIQUE,
                mpesa_receipt_number VARCHAR(255),
                notes VARCHAR(500),
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """))
        await conn.execute(sa_text("""
            CREATE TABLE IF NOT EXISTS shop_order_items (
                id SERIAL PRIMARY KEY,
                order_id INTEGER NOT NULL REFERENCES shop_orders(id) ON DELETE CASCADE,
                product_id INTEGER REFERENCES shop_products(id),
                product_name VARCHAR(255) NOT NULL,
                product_price NUMERIC(10,2) NOT NULL,
                quantity INTEGER NOT NULL,
                subtotal NUMERIC(10,2) NOT NULL
            )
        """))
        await conn.execute(sa_text("""
            CREATE TABLE IF NOT EXISTS shop_order_tracking (
                id SERIAL PRIMARY KEY,
                order_id INTEGER NOT NULL REFERENCES shop_orders(id) ON DELETE CASCADE,
                status_label VARCHAR(100) NOT NULL,
                note VARCHAR(500),
                updated_by_user_id INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        # Indexes
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_products_user ON shop_products(user_id)"))
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_products_active ON shop_products(is_active)"))
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_orders_user ON shop_orders(user_id)"))
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_orders_number ON shop_orders(order_number)"))
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_order_items_order ON shop_order_items(order_id)"))
        await conn.execute(sa_text("CREATE INDEX IF NOT EXISTS idx_shop_tracking_order ON shop_order_tracking(order_id)"))
    logger.info("Shop tables ready")


@app.on_event("startup")
async def startup_event():
    try:
        await run_radius_migrations()
        logger.info("RADIUS migrations completed successfully")
    except Exception as e:
        logger.error(f"RADIUS migration failed (non-fatal): {e}")

    try:
        await run_monitoring_migrations()
        logger.info("Monitoring table migrations completed successfully")
    except Exception as e:
        logger.error(f"Monitoring migration failed (non-fatal): {e}")

    try:
        await run_payment_method_migrations()
        logger.info("Payment method migrations completed successfully")
    except Exception as e:
        logger.error(f"Payment method migration failed (non-fatal): {e}")

    try:
        await run_user_migrations()
        logger.info("User migrations completed successfully")
    except Exception as e:
        logger.error(f"User migration failed (non-fatal): {e}")

    try:
        await run_reconnection_migrations()
        logger.info("Reconnection migrations completed successfully")
    except Exception as e:
        logger.error(f"Reconnection migration failed (non-fatal): {e}")

    try:
        await run_device_pairing_migrations()
        logger.info("Device pairing migrations completed successfully")
    except Exception as e:
        logger.error(f"Device pairing migration failed (non-fatal): {e}")

    try:
        await run_b2b_migrations()
        logger.info("B2B payout migrations completed successfully")
    except Exception as e:
        logger.error(f"B2B migration failed (non-fatal): {e}")

    try:
        await run_subscription_migrations()
        logger.info("Subscription migrations completed successfully")
    except Exception as e:
        logger.error(f"Subscription migration failed (non-fatal): {e}")

    try:
        await run_growth_targets_migration()
        logger.info("Growth targets migration completed successfully")
    except Exception as e:
        logger.error(f"Growth targets migration failed (non-fatal): {e}")

    try:
        await run_lead_pipeline_migrations()
        logger.info("Lead pipeline migrations completed successfully")
    except Exception as e:
        logger.error(f"Lead pipeline migration failed (non-fatal): {e}")

    try:
        await run_access_credential_migrations()
        logger.info("Access credential migrations completed successfully")
    except Exception as e:
        logger.error(f"Access credential migration failed (non-fatal): {e}")

    try:
        await run_fup_usage_migrations()
        logger.info("FUP / usage tracking migrations completed successfully")
    except Exception as e:
        logger.error(f"FUP / usage tracking migration failed (non-fatal): {e}")

    try:
        await run_payment_history_migrations()
        logger.info("Payment history migrations completed successfully")
    except Exception as e:
        logger.error(f"Payment history migration failed (non-fatal): {e}")

    try:
        await run_shop_migrations()
        logger.info("Shop migrations completed successfully")
    except Exception as e:
        logger.error(f"Shop migration failed (non-fatal): {e}")

    scheduler.add_job(
        cleanup_expired_users_background,
        trigger=IntervalTrigger(seconds=67),
        id='cleanup_expired_users',
        name='Remove expired hotspot users from MikroTik',
        replace_existing=True,
        max_instances=1
    )
    scheduler.add_job(
        collect_bandwidth_snapshot,
        trigger=IntervalTrigger(seconds=157),
        id='bandwidth_snapshot',
        name='Collect bandwidth statistics',
        replace_existing=True,
        max_instances=1
    )
    scheduler.add_job(
        retry_pending_hotspot_provisioning_background,
        trigger=IntervalTrigger(seconds=97),
        id='retry_pending_hotspot_provisioning',
        name='Retry stranded hotspot provisioning',
        replace_existing=True,
        max_instances=1
    )
    scheduler.add_job(
        reconcile_pending_mpesa_transactions,
        trigger=IntervalTrigger(seconds=90),
        id='reconcile_pending_mpesa',
        name='Reconcile pending M-Pesa transactions via STK Query',
        replace_existing=True,
        max_instances=1
    )
    scheduler.add_job(
        reconcile_pending_subscription_payments,
        trigger=IntervalTrigger(seconds=90),
        id='reconcile_pending_subscription_payments',
        name='Reconcile pending subscription payments via STK Query',
        replace_existing=True,
        max_instances=1
    )
    # --- Subscription scheduler jobs ---
    async def _check_overdue_subscriptions_background():
        from app.services.subscription import check_overdue_invoices
        async for db in get_db():
            try:
                result = await check_overdue_invoices(db)
                logger.info(f"[SUBSCRIPTION] Overdue check: {result}")
            except Exception as e:
                logger.error(f"[SUBSCRIPTION] Overdue check failed: {e}")
            break

    async def _pre_expiry_invoices_background():
        from app.services.subscription import generate_pre_expiry_invoices
        async for db in get_db():
            try:
                result = await generate_pre_expiry_invoices(db)
                logger.info(f"[SUBSCRIPTION] Pre-expiry invoices: {result}")
            except Exception as e:
                logger.error(f"[SUBSCRIPTION] Pre-expiry invoice job failed: {e}")
            break

    scheduler.add_job(
        _pre_expiry_invoices_background,
        trigger=CronTrigger(hour=6, minute=0),
        id='pre_expiry_invoices',
        name='Generate invoices 5 days before expiry',
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=900,
    )
    scheduler.add_job(
        _check_overdue_subscriptions_background,
        trigger=CronTrigger(hour=8, minute=0),
        id='check_overdue_subscriptions',
        name='Check overdue invoices and suspend non-payers',
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=900,
    )

    logger.info("Subscription jobs scheduled: per-user invoices daily at 06:00, overdue/suspension check daily at 08:00")

    # --- Provisioning token cleanup (3:00 AM EAT / 0:00 UTC) ---
    async def _expire_stale_provisioning_tokens():
        from app.services.provisioning import expire_stale_tokens
        try:
            count = await expire_stale_tokens()
            if count:
                logger.info(f"[PROVISION] Nightly cleanup: expired {count} stale token(s)")
        except Exception as e:
            logger.error(f"[PROVISION] Nightly token cleanup failed: {e}")

    scheduler.add_job(
        _expire_stale_provisioning_tokens,
        trigger=CronTrigger(hour=0, minute=0),
        id='expire_stale_provisioning_tokens',
        name='Expire stale provisioning tokens (3:00 AM EAT)',
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=900,
    )

    from app.config import settings as app_settings
    if app_settings.MPESA_B2B_DAILY_PAYOUT_ENABLED:
        scheduler.add_job(
            run_daily_payouts,
            trigger=CronTrigger(hour=23, minute=59),
            id='daily_b2b_payouts',
            name='Daily B2B reseller payouts',
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=900,
        )
        logger.info("B2B daily payout job scheduled at 23:59")
    else:
        logger.info("B2B daily payouts disabled (MPESA_B2B_DAILY_PAYOUT_ENABLED=False)")

    scheduler.start()
    logger.info(
        "Background scheduler started - cleanup every 67s, bandwidth every 157s, "
        "hotspot provisioning retry every 97s, M-Pesa reconciliation every 90s, "
        "stale token cleanup daily at 00:00 UTC (3:00 AM EAT)"
    )

    async for db in get_db():
        await warm_plan_cache(db)
        break
    logger.info("Plan cache warmed up")


@app.on_event("shutdown")
async def shutdown_event():
    scheduler.shutdown()
    logger.info("Background scheduler stopped")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

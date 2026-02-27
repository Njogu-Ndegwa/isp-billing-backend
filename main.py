from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text as sa_text
from app.db.database import get_db, async_engine
from app.services.plan_cache import warm_plan_cache
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
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

# --- Background job imports ---
from app.services.mikrotik_background import (
    cleanup_expired_users_background,
    collect_bandwidth_snapshot,
    # Exported for late-imports from router files
    remove_user_from_mikrotik,
    mikrotik_lock,
    _cleanup_customer_from_mikrotik_sync,
)

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
# Startup / Shutdown
# ============================================================================
@app.on_event("startup")
async def startup_event():
    try:
        await run_radius_migrations()
        logger.info("RADIUS migrations completed successfully")
    except Exception as e:
        logger.error(f"RADIUS migration failed (non-fatal): {e}")

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
    scheduler.start()
    logger.info("Background scheduler started - cleanup every 67s, bandwidth every 157s")

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

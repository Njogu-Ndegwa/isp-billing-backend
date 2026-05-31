from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# ✅ Required for defining models
Base = declarative_base()

# Replace sync driver with async driver
DATABASE_URL = settings.DATABASE_URL
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Create async engine with NullPool for SQLite to avoid connection issues
engine_kwargs = {
    "echo": False,
    "future": True,
}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE_SECONDS,
        pool_pre_ping=True,
    )

async_engine = create_async_engine(DATABASE_URL, **engine_kwargs)


def db_pool_status() -> str:
    pool = async_engine.sync_engine.pool
    status = getattr(pool, "status", None)
    if not callable(status):
        return type(pool).__name__
    return status()


def _classify_db_pool_pressure(snapshot: dict) -> dict:
    patterns = []
    level = "healthy"

    checked_out = snapshot.get("checked_out")
    checked_out_percent = snapshot.get("checked_out_percent")
    checkout_headroom = snapshot.get("checkout_headroom")
    overflow = snapshot.get("overflow")
    max_connections = snapshot.get("configured_max_app_connections")

    if isinstance(checked_out, int) and isinstance(max_connections, int) and checked_out >= max_connections:
        patterns.append("pool_exhausted")
        level = "critical"
    elif checkout_headroom == 0:
        patterns.append("pool_exhausted")
        level = "critical"

    if isinstance(checked_out_percent, (int, float)):
        if checked_out_percent >= 85:
            patterns.append("very_high_pool_checkout")
            level = "critical" if level == "critical" else "warning"
        elif checked_out_percent >= 70:
            patterns.append("high_pool_checkout")
            if level == "healthy":
                level = "warning"
        elif checked_out_percent >= 50:
            patterns.append("moderate_pool_checkout")
            if level == "healthy":
                level = "watch"

    if isinstance(checkout_headroom, int):
        if checkout_headroom <= 2:
            patterns.append("very_low_checkout_headroom")
            level = "critical" if level == "critical" else "warning"
        elif checkout_headroom <= 5:
            patterns.append("low_checkout_headroom")
            if level == "healthy":
                level = "watch"

    if isinstance(overflow, int) and overflow > 0:
        patterns.append("overflow_connections_in_use")
        if level == "healthy":
            level = "watch"

    if not patterns:
        patterns.append("normal_pool_pressure")

    return {
        "level": level,
        "patterns": patterns,
        "read": (
            "Pool is exhausted or close to exhaustion."
            if level == "critical"
            else "Pool pressure is elevated; watch for sustained growth."
            if level == "warning"
            else "Pool pressure is rising but still has room."
            if level == "watch"
            else "Pool pressure looks normal."
        ),
    }


def db_pool_snapshot() -> dict:
    pool = async_engine.sync_engine.pool
    snapshot = {
        "pool_class": type(pool).__name__,
        "status": db_pool_status(),
        "configured_pool_size": settings.DB_POOL_SIZE,
        "configured_max_overflow": settings.DB_MAX_OVERFLOW,
        "configured_pool_timeout_seconds": settings.DB_POOL_TIMEOUT,
        "configured_pool_recycle_seconds": settings.DB_POOL_RECYCLE_SECONDS,
    }

    for key, method_name in (
        ("pool_size", "size"),
        ("checked_in", "checkedin"),
        ("checked_out", "checkedout"),
        ("overflow", "overflow"),
    ):
        method = getattr(pool, method_name, None)
        if callable(method):
            try:
                snapshot[key] = method()
            except Exception:
                snapshot[key] = None

    max_connections = settings.DB_POOL_SIZE + settings.DB_MAX_OVERFLOW
    snapshot["configured_max_app_connections"] = max_connections

    checked_out = snapshot.get("checked_out")
    if isinstance(checked_out, int):
        snapshot["checkout_headroom"] = max(0, max_connections - checked_out)
        snapshot["checked_out_percent"] = round((checked_out / max_connections) * 100, 2) if max_connections else None

    checked_in = snapshot.get("checked_in")
    if isinstance(checked_in, int) and isinstance(checked_out, int):
        snapshot["open_connections_estimate"] = checked_in + checked_out

    snapshot["pressure"] = _classify_db_pool_pressure(snapshot)

    return snapshot

# Create sessionmaker for async sessions
AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Dependency for using DB session in route handlers
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, SQLAlchemyTimeoutError):
                logger.error("Database pool checkout timed out: %s", db_pool_status())
            raise
        finally:
            await session.close()

# Alias for the cleanup worker
async_session = AsyncSessionLocal

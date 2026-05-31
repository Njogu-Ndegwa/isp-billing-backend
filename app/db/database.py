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

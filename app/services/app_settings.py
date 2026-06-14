"""Generic key/value settings service backed by the app_settings table.

Provides get/set helpers and a typed integer accessor with a default fallback.
All three functions are intentionally simple — no caching, no pub/sub.
"""

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AppSetting


async def get_setting(db: AsyncSession, key: str) -> Optional[str]:
    """Return the stored string value for *key*, or None if not set."""
    row = await db.get(AppSetting, key)
    return row.value if row else None


async def set_setting(db: AsyncSession, key: str, value) -> None:
    """Upsert *key* = str(*value*) and commit."""
    row = await db.get(AppSetting, key)
    if row:
        row.value = str(value)
    else:
        db.add(AppSetting(key=key, value=str(value)))
    await db.commit()


async def get_int_setting(db: AsyncSession, key: str, default: int) -> int:
    """Return the stored value cast to int, or *default* if unset or non-numeric."""
    raw = await get_setting(db, key)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default

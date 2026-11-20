"""Who starts on the assistant instead of the classic dashboard.

The assistant home is rolled out to a share of accounts before everyone:

* a person's own choice always wins ("assistant" or "classic", kept in
  ``assistant_home_choices``, one row per (user_id, staff_id));
* with no choice, a reseller account (owner and staff alike, so one office
  sees one thing) is in when ``crc32("assistant-home:{user_id}") % 100`` is
  below the rollout percentage. The bucket is fixed per account, so raising
  the percentage only ever adds accounts;
* platform admins and View-as sessions are never moved by the percentage;
* nobody starts there while the assistant is not ready.

The percentage lives in ``app_settings`` (key ``assistant_home_percent``,
default 0). Every function is one short DB session.
"""
from __future__ import annotations

import time
import zlib
from datetime import datetime
from typing import Optional

from sqlalchemy import delete, func, select

from app.db import database as db_module
from app.db.models import AppSetting, AssistantHomeChoice
from app.services.assistant.caller import Caller

ROLLOUT_KEY = "assistant_home_percent"
CHOICES = ("assistant", "classic")
PERCENT_TTL_SECONDS = 30.0

_percent_cache: Optional[tuple[float, int]] = None


def reset_cache() -> None:
    global _percent_cache
    _percent_cache = None


def in_rollout(user_id: int, percent: int) -> bool:
    """Whether this account's fixed bucket (0-99) is inside the percentage."""
    return zlib.crc32(f"assistant-home:{user_id}".encode()) % 100 < percent


def _clamp(value) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


async def get_percent() -> int:
    global _percent_cache
    now = time.monotonic()
    if _percent_cache is not None and _percent_cache[0] > now:
        return _percent_cache[1]
    async with db_module.async_session() as db:
        row = await db.get(AppSetting, ROLLOUT_KEY)
        percent = _clamp(row.value) if row else 0
    _percent_cache = (now + PERCENT_TTL_SECONDS, percent)
    return percent


async def set_percent(percent: int) -> int:
    global _percent_cache
    percent = _clamp(percent)
    async with db_module.async_session() as db:
        row = await db.get(AppSetting, ROLLOUT_KEY)
        if row:
            row.value = str(percent)
        else:
            db.add(AppSetting(key=ROLLOUT_KEY, value=str(percent)))
        await db.commit()
    _percent_cache = (time.monotonic() + PERCENT_TTL_SECONDS, percent)
    return percent


def _owner(caller: Caller) -> tuple[int, int]:
    return caller.user_id, int(caller.staff_id or 0)


async def get_choice(caller: Caller) -> Optional[str]:
    """The person's own choice. A View-as session has none: it is the admin looking in."""
    if caller.viewer_sid is not None:
        return None
    user_id, staff_id = _owner(caller)
    async with db_module.async_session() as db:
        choice = (await db.execute(
            select(AssistantHomeChoice.choice).where(
                AssistantHomeChoice.user_id == user_id, AssistantHomeChoice.staff_id == staff_id)
        )).scalar_one_or_none()
    return choice if choice in CHOICES else None


async def set_choice(caller: Caller, choice: str) -> Optional[str]:
    """Store "assistant" or "classic"; "default" removes the choice."""
    user_id, staff_id = _owner(caller)
    async with db_module.async_session() as db:
        row = (await db.execute(
            select(AssistantHomeChoice).where(
                AssistantHomeChoice.user_id == user_id, AssistantHomeChoice.staff_id == staff_id)
        )).scalar_one_or_none()
        if choice not in CHOICES:
            if row is not None:
                await db.execute(delete(AssistantHomeChoice).where(AssistantHomeChoice.id == row.id))
            await db.commit()
            return None
        if row is None:
            db.add(AssistantHomeChoice(user_id=user_id, staff_id=staff_id, choice=choice,
                                       updated_at=datetime.utcnow()))
        else:
            row.choice = choice
            row.updated_at = datetime.utcnow()
        await db.commit()
    return choice


async def home_for(caller: Caller, *, ready: bool) -> tuple[bool, Optional[str]]:
    """(the assistant is this person's start page, their own choice)."""
    choice = await get_choice(caller)
    if not ready:
        return False, choice
    if choice == "assistant":
        return True, choice
    if choice == "classic":
        return False, choice
    if caller.role == "admin" or caller.viewer_sid is not None:
        return False, None
    return in_rollout(caller.user_id, await get_percent()), None


async def rollout_report() -> dict:
    percent = await get_percent()
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantHomeChoice.choice, func.count(AssistantHomeChoice.id))
            .group_by(AssistantHomeChoice.choice)
        )).all()
    counts = {choice: int(n) for choice, n in rows}
    return {"percent": percent, "chose_assistant": counts.get("assistant", 0),
            "chose_classic": counts.get("classic", 0)}

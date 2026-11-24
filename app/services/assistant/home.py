"""Who starts on the assistant instead of the classic dashboard.

The assistant home is rolled out to a share of accounts before everyone:

* a person's own choice always wins ("assistant" or "classic", kept in
  ``assistant_home_choices``, one row per (user_id, staff_id));
* with no choice, a paying reseller account (an active subscription; owner
  and staff alike, so one office sees one thing) is in when
  ``crc32("assistant-home:{user_id}") % 100`` is below the rollout
  percentage. The bucket is fixed per account, so raising the percentage only
  ever adds accounts, and an account that starts paying joins if its bucket
  is inside. Trial and suspended accounts are not moved;
* platform admins and View-as sessions are never moved by the percentage;
* nobody starts there while the assistant is not ready;
* at 100% ("Everyone") every reseller account (paying, trial or suspended,
  owner and staff) with no choice of its own starts on the assistant. The
  classic dashboard stays open: someone who picks "classic" under "When I
  sign in, open" starts there. Platform admins and View-as sessions are
  untouched.

Nothing closes the classic dashboard any more (it was closed at Everyone from
2026-11-22 until Dennis asked for the way back on 2026-11-24);
``classic_closed`` is kept, always False, so the status field and the admin
report keep their shape and a device that remembered "closed" opens again.

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
from app.db.models import AppSetting, AssistantHomeChoice, SubscriptionStatus, User
from app.services.assistant.caller import Caller

ROLLOUT_KEY = "assistant_home_percent"
CHOICES = ("assistant", "classic")
PERCENT_TTL_SECONDS = 30.0

_percent_cache: Optional[tuple[float, int]] = None
PAYING_TTL_SECONDS = 300.0
_paying_cache: dict[int, tuple[float, bool]] = {}


def reset_cache() -> None:
    global _percent_cache
    _percent_cache = None
    _paying_cache.clear()


def _status_value(v) -> str:
    return getattr(v, "value", v) or ""


async def is_paying(user_id: int) -> bool:
    """Whether the account has an active (paid) subscription; cached a few minutes."""
    now = time.monotonic()
    hit = _paying_cache.get(user_id)
    if hit is not None and hit[0] > now:
        return hit[1]
    async with db_module.async_session() as db:
        status = (await db.execute(select(User.subscription_status).where(User.id == user_id))).scalar_one_or_none()
    paying = _status_value(status) == SubscriptionStatus.ACTIVE.value
    if len(_paying_cache) > 5000:
        _paying_cache.clear()
    _paying_cache[user_id] = (now + PAYING_TTL_SECONDS, paying)
    return paying


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


EVERYONE = 100


def _exempt(caller: Caller) -> bool:
    return caller.role == "admin" or caller.viewer_sid is not None


async def classic_closed(caller: Caller, *, ready: bool) -> bool:
    """Whether this person may no longer use the classic dashboard: never (it always has a way back)."""
    return False


async def home_for(caller: Caller, *, ready: bool) -> tuple[bool, Optional[str]]:
    """(the assistant is this person's start page, their own choice)."""
    choice = await get_choice(caller)
    if not ready:
        return False, choice
    if choice == "assistant":
        return True, choice
    if choice == "classic":
        return False, choice
    if _exempt(caller):
        return False, None
    percent = await get_percent()
    if percent >= EVERYONE:
        return True, None  # the default for every reseller account, paying or not
    if not in_rollout(caller.user_id, percent):
        return False, None
    return await is_paying(caller.user_id), None


async def rollout_report() -> dict:
    percent = await get_percent()
    async with db_module.async_session() as db:
        rows = (await db.execute(
            select(AssistantHomeChoice.choice, func.count(AssistantHomeChoice.id))
            .group_by(AssistantHomeChoice.choice)
        )).all()
        paying_ids = (await db.execute(
            select(User.id).where(User.subscription_status == SubscriptionStatus.ACTIVE, User.role != "admin")
        )).scalars().all()
    counts = {choice: int(n) for choice, n in rows}
    return {"percent": percent, "classic_closed": False,  # nothing closes it any more
            "chose_assistant": counts.get("assistant", 0),
            "chose_classic": counts.get("classic", 0),
            # the rollout moves paying accounts only: how many there are, and how many are in
            "paying_accounts": len(paying_ids),
            "paying_inside": sum(1 for uid in paying_ids if in_rollout(uid, percent))}

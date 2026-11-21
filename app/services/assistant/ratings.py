"""What the people using the assistant think of it: a 1-5 rating and a review.

One row per person, (user_id, staff_id) as in assistant_usage_daily: a person
can change their rating later, and the row keeps the latest. Ideas for
improvements are not kept here: the chat posts them to the shared feedback
board (feedback_posts, kind "idea"), where they get votes and AI triage.

When to ask (``should_ask``), quietly and rarely: the first time once someone
has asked ``MIN_QUESTIONS`` questions and has not rated it; after it has been
shown (``mark_shown``, whether they answered "not now" or simply scrolled
past) it stays away ``GAP_DAYS``; after ``MAX_SHOWS`` showings we stop asking.
Rating stays one tap away in the menu. Never in View-as, and never for
platform admins. Every function is one short DB session.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, select

from app.db import database as db_module
from app.db.models import AssistantRating, AssistantUsageDaily
from app.services.assistant.caller import Caller

MIN_QUESTIONS = 3
GAP_DAYS = 4
MAX_SHOWS = 3
REVIEW_MAX = 2000


def _owner(caller: Caller) -> tuple[int, int]:
    return caller.user_id, int(caller.staff_id or 0)


async def _row(db, caller: Caller) -> Optional[AssistantRating]:
    user_id, staff_id = _owner(caller)
    return (await db.execute(
        select(AssistantRating).where(AssistantRating.user_id == user_id, AssistantRating.staff_id == staff_id)
    )).scalar_one_or_none()


def _mine(row: Optional[AssistantRating]) -> Optional[dict]:
    if row is None or row.rating is None:
        return None
    return {"rating": row.rating, "review": row.review or "", "updated_at": row.updated_at.isoformat() if row.updated_at else None}


async def mine(caller: Caller) -> Optional[dict]:
    async with db_module.async_session() as db:
        return _mine(await _row(db, caller))


async def should_ask(caller: Caller, now: Optional[datetime] = None) -> bool:
    if caller.read_only or caller.role == "admin":
        return False
    now = now or datetime.utcnow()
    user_id, staff_id = _owner(caller)
    async with db_module.async_session() as db:
        row = await _row(db, caller)
        if row is not None:
            if row.rating is not None or (row.shown_count or 0) >= MAX_SHOWS:
                return False
            times = [t for t in (row.shown_at, row.dismissed_at) if t]
            if times and now - max(times) < timedelta(days=GAP_DAYS):
                return False
        questions = (await db.execute(
            select(func.coalesce(func.sum(AssistantUsageDaily.questions), 0))
            .where(AssistantUsageDaily.user_id == user_id, AssistantUsageDaily.staff_id == staff_id)
        )).scalar()
    return int(questions or 0) >= MIN_QUESTIONS


async def mark_shown(caller: Caller) -> None:
    """The ask was on screen: count it, and start the gap before the next one."""
    if caller.read_only:
        return
    user_id, staff_id = _owner(caller)
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        row = await _row(db, caller)
        if row is None:
            row = AssistantRating(user_id=user_id, staff_id=staff_id, created_at=now, updated_at=now)
            db.add(row)
        # one showing per gap, however many screens drew it
        if not row.shown_at or now - row.shown_at >= timedelta(days=GAP_DAYS):
            row.shown_count = (row.shown_count or 0) + 1
            row.shown_at = now
        await db.commit()


async def submit(caller: Caller, rating: int, review: str = "", source: str = "") -> dict:
    user_id, staff_id = _owner(caller)
    now = datetime.utcnow()
    review = (review or "").strip()[:REVIEW_MAX]
    async with db_module.async_session() as db:
        row = await _row(db, caller)
        if row is None:
            row = AssistantRating(user_id=user_id, staff_id=staff_id, created_at=now)
            db.add(row)
        row.rating = max(1, min(5, int(rating)))
        row.review = review or None
        row.source = (source or "")[:20] or None
        row.updated_at = now
        await db.commit()
        return _mine(row) or {}


async def dismiss(caller: Caller) -> None:
    user_id, staff_id = _owner(caller)
    now = datetime.utcnow()
    async with db_module.async_session() as db:
        row = await _row(db, caller)
        if row is None:
            row = AssistantRating(user_id=user_id, staff_id=staff_id, created_at=now, updated_at=now)
            db.add(row)
        row.dismissed_count = (row.dismissed_count or 0) + 1
        row.dismissed_at = now
        await db.commit()


async def report(limit: int = 50) -> dict:
    """The average, how the stars spread, and the latest reviews with whose they are."""
    from app.db.models import ResellerStaff, User

    async with db_module.async_session() as db:
        spread = (await db.execute(
            select(AssistantRating.rating, func.count(AssistantRating.id))
            .where(AssistantRating.rating.isnot(None)).group_by(AssistantRating.rating)
        )).all()
        dismissed = (await db.execute(
            select(func.count(AssistantRating.id))
            .where(AssistantRating.rating.is_(None), AssistantRating.dismissed_count > 0)
        )).scalar() or 0
        rows = (await db.execute(
            select(AssistantRating, User.organization_name, User.email)
            .join(User, User.id == AssistantRating.user_id, isouter=True)
            .where(AssistantRating.rating.isnot(None))
            .order_by(AssistantRating.updated_at.desc()).limit(max(1, min(limit, 500)))
        )).all()
        staff_ids = {r.AssistantRating.staff_id for r in rows if r.AssistantRating.staff_id}
        staff_names = {}
        if staff_ids:
            staff_names = dict((await db.execute(
                select(ResellerStaff.id, ResellerStaff.name).where(ResellerStaff.id.in_(staff_ids))
            )).all())
        usage = dict((await db.execute(
            select(AssistantUsageDaily.user_id, func.sum(AssistantUsageDaily.questions))
            .where(AssistantUsageDaily.user_id.in_({r.AssistantRating.user_id for r in rows} or {0}))
            .group_by(AssistantUsageDaily.user_id)
        )).all())
    counts = {int(stars): int(n) for stars, n in spread}
    total = sum(counts.values())
    return {
        "count": total,
        "average": round(sum(s * n for s, n in counts.items()) / total, 2) if total else None,
        "distribution": {str(s): counts.get(s, 0) for s in range(1, 6)},
        "dismissed_without_rating": int(dismissed),
        "reviews": [
            {
                "user_id": r.AssistantRating.user_id,
                "account": r.organization_name or r.email or f"Account {r.AssistantRating.user_id}",
                "staff_id": r.AssistantRating.staff_id or None,
                "staff_name": staff_names.get(r.AssistantRating.staff_id) if r.AssistantRating.staff_id else None,
                "rating": r.AssistantRating.rating,
                "review": r.AssistantRating.review or "",
                "questions": int(usage.get(r.AssistantRating.user_id) or 0),
                "updated_at": r.AssistantRating.updated_at.isoformat() if r.AssistantRating.updated_at else None,
            }
            for r in rows
        ],
    }

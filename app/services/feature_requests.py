"""Feature requests: what people asked for that the app cannot do yet.

The assistant records one whenever someone asks for something no action covers
(POST /api/feedback/requests, which runs without a Confirm: it only writes down
what was asked). Requests live on the shared feedback board as ideas, so they get
the board's votes, AI triage (impact, area, duplicate candidates) and admin queue.

Before adding one, the same request is looked for among the open ideas: the one the
assistant names (``same_as``), else the closest by words. A match gets this
account's vote and their words as a comment instead of a second post, so demand
shows as votes on one request. The admin queue ranks by Bitwave's own order first
(``admin_rank``), then by the board's priority score.
"""
from __future__ import annotations

import re
from typing import Optional

from sqlalchemy import func, select

from app.db.models import FeedbackComment, FeedbackKind, FeedbackPost, FeedbackStatus, FeedbackVote

OPEN = (FeedbackStatus.NEW, FeedbackStatus.UNDER_REVIEW, FeedbackStatus.PLANNED, FeedbackStatus.IN_PROGRESS)
MATCH_AT = 0.5   # share of the shorter request's words the other must contain
_STOP = frozenset("""a an and are as at be by can could do for from have how i in is it me my of on or our please
should so that the this to us want we when with would you your add allow able make let lets need page feature
option see show way""".split())


def words(text: str) -> set[str]:
    """The words that carry the meaning, lightly stemmed ("customers" ~ "customer")."""
    out = set()
    for w in re.findall(r"[a-z0-9]+", (text or "").lower()):
        if len(w) < 3 or w in _STOP:
            continue
        out.add(w[:-1] if w.endswith("s") and len(w) > 4 else w)
    return out


def similarity(a: str, b: str) -> float:
    wa, wb = words(a), words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / min(len(wa), len(wb))


async def find_same(db, title: str, body: str, same_as: Optional[int] = None) -> Optional[FeedbackPost]:
    """An open idea that asks for the same thing, if there is one."""
    if same_as:
        post = await db.get(FeedbackPost, same_as)
        if post is not None and post.kind == FeedbackKind.IDEA and post.status in OPEN:
            return post
    candidates = (await db.execute(
        select(FeedbackPost).where(FeedbackPost.kind == FeedbackKind.IDEA, FeedbackPost.status.in_(OPEN))
        .order_by(FeedbackPost.created_at.desc()).limit(400)
    )).scalars().all()
    best, score = None, 0.0
    for post in candidates:
        s = max(similarity(title, f"{post.title} {post.ai_summary or ''}"), similarity(f"{title} {body}", post.title))
        if s > score:
            best, score = post, s
    return best if score >= MATCH_AT else None


async def add_voice(db, post: FeedbackPost, user_id: int, words_said: str) -> None:
    """One more account wants it: their vote (once) and their words."""
    vote = (await db.execute(
        select(FeedbackVote).where(FeedbackVote.post_id == post.id, FeedbackVote.user_id == user_id)
    )).scalar_one_or_none()
    if vote is None:
        db.add(FeedbackVote(post_id=post.id, user_id=user_id, value=1))
    elif vote.value != 1:
        vote.value = 1
    if words_said.strip():
        db.add(FeedbackComment(post_id=post.id, user_id=user_id, body=f"Asked in the assistant: {words_said.strip()}"[:2000]))
        post.comment_count = (post.comment_count or 0) + 1
    await db.flush()
    post.upvotes = (await db.execute(
        select(func.count(FeedbackVote.id)).where(FeedbackVote.post_id == post.id, FeedbackVote.value == 1)
    )).scalar() or 0

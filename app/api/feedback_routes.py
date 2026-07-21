"""Shared feedback board ("Ideas + Bugs") — reseller + admin facing.

Resellers (and the admin) post bug reports / feature ideas, browse the shared
board, upvote/downvote, and comment. Submissions queue AI triage via
BackgroundTasks AFTER the request's transaction commits (see
app/services/feedback_ai.py for the session-discipline rules).

Board responses never expose ai_* triage fields — those are admin-only
(app/api/admin_feedback_routes.py).
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db
from app.db.models import (
    FeedbackComment,
    FeedbackKind,
    FeedbackPost,
    FeedbackStatus,
    FeedbackVote,
    User,
    UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services.feedback_ai import run_feedback_triage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["feedback"])

TRENDING_WINDOW_DAYS = 90
TRENDING_SCAN_LIMIT = 500


async def _require_member(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role not in (UserRole.ADMIN, UserRole.RESELLER):
        raise HTTPException(status_code=403, detail="Not allowed")
    return user


def _enum_value(v):
    return v.value if hasattr(v, "value") else v


def _post_dict(post: FeedbackPost, author: Optional[User],
               my_vote: Optional[int], viewer: User) -> dict:
    return {
        "id": post.id,
        "kind": _enum_value(post.kind),
        "title": post.title,
        "body": post.body,
        "status": _enum_value(post.status),
        "upvotes": post.upvotes or 0,
        "downvotes": post.downvotes or 0,
        "net_votes": (post.upvotes or 0) - (post.downvotes or 0),
        "comment_count": post.comment_count or 0,
        "duplicate_of_id": post.duplicate_of_id,
        "my_vote": my_vote,
        "is_mine": post.user_id == viewer.id,
        "author": {
            "id": author.id if author else post.user_id,
            "name": author.organization_name if author else "Unknown",
            "is_admin": bool(author and author.role == UserRole.ADMIN),
        },
        "created_at": post.created_at.isoformat() if post.created_at else None,
    }


def _visible_to(post: FeedbackPost, user: User) -> bool:
    if post.status != FeedbackStatus.SPAM:
        return True
    return user.role == UserRole.ADMIN or post.user_id == user.id


async def _my_votes(db: AsyncSession, user_id: int,
                    post_ids: list[int]) -> dict[int, int]:
    if not post_ids:
        return {}
    rows = (await db.execute(
        select(FeedbackVote.post_id, FeedbackVote.value)
        .where(FeedbackVote.user_id == user_id,
               FeedbackVote.post_id.in_(post_ids))
    )).all()
    return {pid: value for pid, value in rows}


# ---- Submit ---------------------------------------------------------------

class PostCreate(BaseModel):
    kind: Literal["bug", "idea"]
    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=10, max_length=5000)


@router.post("/api/feedback/posts")
async def create_post(payload: PostCreate, background_tasks: BackgroundTasks,
                      db: AsyncSession = Depends(get_db),
                      token: str = Depends(verify_token)):
    user = await _require_member(token, db)

    utc_midnight = datetime.utcnow().replace(hour=0, minute=0, second=0,
                                             microsecond=0)
    posted_today = (await db.execute(
        select(func.count(FeedbackPost.id)).where(
            FeedbackPost.user_id == user.id,
            FeedbackPost.created_at >= utc_midnight)
    )).scalar() or 0
    if posted_today >= settings.FEEDBACK_DAILY_POST_CAP:
        raise HTTPException(status_code=429,
                            detail="Daily submission limit reached — try again tomorrow")

    post = FeedbackPost(
        user_id=user.id,
        kind=FeedbackKind(payload.kind),
        title=payload.title.strip(),
        body=payload.body.strip(),
        status=FeedbackStatus.NEW,
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)

    # Runs after the response is sent; the transaction above is already
    # committed, and triage opens its own short sessions.
    background_tasks.add_task(run_feedback_triage, post.id)

    return _post_dict(post, user, my_vote=None, viewer=user)


# ---- Browse ---------------------------------------------------------------

@router.get("/api/feedback/posts")
async def list_posts(sort: str = Query("top"),
                     kind: Optional[str] = Query(None),
                     status: Optional[str] = Query(None),
                     mine: bool = Query(False),
                     page: int = Query(1, ge=1),
                     page_size: int = Query(20, ge=1, le=50),
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    user = await _require_member(token, db)
    if sort not in ("top", "new", "trending"):
        raise HTTPException(status_code=400, detail="Invalid sort")

    filters = []
    if kind is not None:
        try:
            filters.append(FeedbackPost.kind == FeedbackKind(kind))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid kind")
    if status is not None:
        try:
            status_enum = FeedbackStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")
        if status_enum == FeedbackStatus.SPAM and user.role != UserRole.ADMIN:
            return {"posts": [], "total": 0, "page": page, "page_size": page_size}
        filters.append(FeedbackPost.status == status_enum)
    else:
        filters.append(FeedbackPost.status != FeedbackStatus.SPAM)
    if mine:
        filters.append(FeedbackPost.user_id == user.id)

    base = select(FeedbackPost, User).join(User, User.id == FeedbackPost.user_id)
    for f in filters:
        base = base.where(f)

    if sort == "trending":
        cutoff = datetime.utcnow() - timedelta(days=TRENDING_WINDOW_DAYS)
        rows = (await db.execute(
            base.where(FeedbackPost.created_at >= cutoff)
            .order_by(FeedbackPost.created_at.desc())
            .limit(TRENDING_SCAN_LIMIT)
        )).all()
        now = datetime.utcnow()

        def gravity(post: FeedbackPost) -> float:
            net = max((post.upvotes or 0) - (post.downvotes or 0), 0)
            age_hours = max((now - (post.created_at or now)).total_seconds() / 3600.0, 0.0)
            return net / math.pow(age_hours + 2.0, 1.5)

        rows.sort(key=lambda r: gravity(r[0]), reverse=True)
        total = len(rows)
        rows = rows[(page - 1) * page_size: page * page_size]
    else:
        count_q = select(func.count(FeedbackPost.id))
        for f in filters:
            count_q = count_q.where(f)
        total = (await db.execute(count_q)).scalar() or 0
        if sort == "new":
            ordered = base.order_by(FeedbackPost.created_at.desc())
        else:  # top
            ordered = base.order_by(
                (FeedbackPost.upvotes - FeedbackPost.downvotes).desc(),
                FeedbackPost.created_at.desc())
        rows = (await db.execute(
            ordered.offset((page - 1) * page_size).limit(page_size)
        )).all()

    votes = await _my_votes(db, user.id, [p.id for p, _ in rows])
    return {
        "posts": [_post_dict(p, a, votes.get(p.id), user) for p, a in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/api/feedback/posts/{post_id}")
async def get_post(post_id: int, db: AsyncSession = Depends(get_db),
                   token: str = Depends(verify_token)):
    user = await _require_member(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None or not _visible_to(post, user):
        raise HTTPException(status_code=404, detail="Post not found")
    author = await db.get(User, post.user_id)

    comment_rows = (await db.execute(
        select(FeedbackComment, User)
        .join(User, User.id == FeedbackComment.user_id)
        .where(FeedbackComment.post_id == post_id)
        .order_by(FeedbackComment.created_at.asc())
    )).all()
    duplicate_of = None
    if post.duplicate_of_id:
        target = await db.get(FeedbackPost, post.duplicate_of_id)
        if target is not None:
            duplicate_of = {"id": target.id, "title": target.title}

    votes = await _my_votes(db, user.id, [post_id])
    result = _post_dict(post, author, votes.get(post_id), user)
    result["duplicate_of"] = duplicate_of
    result["comments"] = [{
        "id": c.id,
        "body": c.body,
        "is_admin": c.is_admin,
        "author_name": u.organization_name,
        "is_mine": c.user_id == user.id,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    } for c, u in comment_rows]
    return result


# ---- Vote -----------------------------------------------------------------

class VoteIn(BaseModel):
    value: Literal[1, -1, 0]


@router.post("/api/feedback/posts/{post_id}/vote")
async def vote_post(post_id: int, payload: VoteIn,
                    db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    user = await _require_member(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None or not _visible_to(post, user):
        raise HTTPException(status_code=404, detail="Post not found")

    existing = (await db.execute(
        select(FeedbackVote).where(FeedbackVote.post_id == post_id,
                                   FeedbackVote.user_id == user.id)
    )).scalar_one_or_none()

    my_vote: Optional[int] = None
    if payload.value == 0 or (existing is not None and existing.value == payload.value):
        # Explicit clear, or clicking the same arrow again toggles it off.
        if existing is not None:
            await db.delete(existing)
    elif existing is not None:
        existing.value = payload.value
        my_vote = payload.value
    else:
        db.add(FeedbackVote(post_id=post_id, user_id=user.id,
                            value=payload.value))
        my_vote = payload.value

    await db.flush()
    # Recompute denormalized counters in the same transaction — cheap and
    # race-safe enough at this scale.
    post.upvotes = (await db.execute(
        select(func.count(FeedbackVote.id)).where(
            FeedbackVote.post_id == post_id, FeedbackVote.value == 1)
    )).scalar() or 0
    post.downvotes = (await db.execute(
        select(func.count(FeedbackVote.id)).where(
            FeedbackVote.post_id == post_id, FeedbackVote.value == -1)
    )).scalar() or 0
    await db.commit()
    return {"upvotes": post.upvotes, "downvotes": post.downvotes,
            "my_vote": my_vote}


# ---- Comments -------------------------------------------------------------

class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@router.post("/api/feedback/posts/{post_id}/comments")
async def comment_post(post_id: int, payload: CommentIn,
                       db: AsyncSession = Depends(get_db),
                       token: str = Depends(verify_token)):
    user = await _require_member(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None or not _visible_to(post, user):
        raise HTTPException(status_code=404, detail="Post not found")

    comment = FeedbackComment(
        post_id=post_id,
        user_id=user.id,
        body=payload.body.strip(),
        is_admin=user.role == UserRole.ADMIN,
    )
    db.add(comment)
    post.comment_count = (post.comment_count or 0) + 1
    await db.commit()
    await db.refresh(comment)
    return {
        "id": comment.id,
        "body": comment.body,
        "is_admin": comment.is_admin,
        "author_name": user.organization_name,
        "is_mine": True,
        "created_at": comment.created_at.isoformat() if comment.created_at else None,
        "comment_count": post.comment_count,
    }

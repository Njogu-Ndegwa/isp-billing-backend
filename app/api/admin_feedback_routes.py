"""Admin-only feedback triage: priority queue, stats, status changes (with
author inbox notification), AI retriage, AI-drafted replies, and Claude Code
work packets.

The draft-reply endpoint deliberately avoids Depends(get_db): auth runs in its
own short session, and the slow Anthropic call happens with NO session open
(Database Session Discipline, AGENTS.md).
"""

import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import database
from app.db.database import get_db
from app.db.models import (
    FeedbackComment,
    FeedbackKind,
    FeedbackPost,
    FeedbackStatus,
    ResellerInboxMessage,
    User,
    UserRole,
)
from app.services.auth import verify_token, get_current_user
from app.services import feedback_queue
from app.services.feedback_ai import (
    CRITICAL_SEVERITY,
    draft_status_reply,
    run_feedback_triage,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-feedback"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _parse_status(value: Optional[str]) -> Optional[FeedbackStatus]:
    if value is None:
        return None
    try:
        return FeedbackStatus(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status")


def _parse_kind(value: Optional[str]) -> Optional[FeedbackKind]:
    if value is None:
        return None
    try:
        return FeedbackKind(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid kind")


# ---- Queue + stats --------------------------------------------------------

@router.get("/api/admin/feedback/queue")
async def get_queue(status: Optional[str] = Query(None),
                    kind: Optional[str] = Query(None),
                    page: int = Query(1, ge=1),
                    page_size: int = Query(25, ge=1, le=100),
                    db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    await _require_admin(token, db)
    items = await feedback_queue.fetch_queue(
        db, status=_parse_status(status), kind=_parse_kind(kind))
    total = len(items)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total,
            "page": page, "page_size": page_size}


@router.get("/api/admin/feedback/stats")
async def get_stats(db: AsyncSession = Depends(get_db),
                    token: str = Depends(verify_token)):
    await _require_admin(token, db)

    by_status_rows = (await db.execute(
        select(FeedbackPost.status, func.count(FeedbackPost.id))
        .group_by(FeedbackPost.status)
    )).all()
    by_status = {(s.value if hasattr(s, "value") else s): n
                 for s, n in by_status_rows}

    open_filter = FeedbackPost.status.in_(feedback_queue.OPEN_STATUSES)
    by_kind_rows = (await db.execute(
        select(FeedbackPost.kind, func.count(FeedbackPost.id))
        .where(open_filter).group_by(FeedbackPost.kind)
    )).all()
    by_kind = {(k.value if hasattr(k, "value") else k): n
               for k, n in by_kind_rows}

    from datetime import datetime, timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    new_this_week = (await db.execute(
        select(func.count(FeedbackPost.id))
        .where(FeedbackPost.created_at >= week_ago)
    )).scalar() or 0
    untriaged = (await db.execute(
        select(func.count(FeedbackPost.id))
        .where(open_filter, FeedbackPost.ai_triaged_at.is_(None))
    )).scalar() or 0
    critical_open = (await db.execute(
        select(func.count(FeedbackPost.id))
        .where(open_filter,
               FeedbackPost.ai_kind == "bug",
               FeedbackPost.ai_severity >= CRITICAL_SEVERITY)
    )).scalar() or 0

    return {
        "by_status": by_status,
        "by_kind": by_kind,
        "open_count": sum(by_kind.values()),
        "new_this_week": new_this_week,
        "untriaged_count": untriaged,
        "critical_open": critical_open,
    }


# ---- Status changes -------------------------------------------------------

class StatusPatch(BaseModel):
    status: Optional[str] = None
    duplicate_of_id: Optional[int] = None


@router.patch("/api/admin/feedback/posts/{post_id}")
async def patch_post(post_id: int, payload: StatusPatch,
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    admin = await _require_admin(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    new_status = _parse_status(payload.status)
    if new_status is None:
        raise HTTPException(status_code=400, detail="status is required")

    duplicate_of_id = payload.duplicate_of_id
    if new_status == FeedbackStatus.DUPLICATE:
        if not duplicate_of_id:
            raise HTTPException(status_code=400,
                                detail="duplicate_of_id is required for duplicate status")
        if duplicate_of_id == post_id:
            raise HTTPException(status_code=400,
                                detail="A post cannot duplicate itself")
        target = await db.get(FeedbackPost, duplicate_of_id)
        if target is None:
            raise HTTPException(status_code=400,
                                detail="duplicate_of_id does not exist")

    msg = await feedback_queue.apply_status_change(
        db, post, new_status, admin, duplicate_of_id=duplicate_of_id)
    await db.commit()
    await db.refresh(post)

    from datetime import datetime
    author = await db.get(User, post.user_id)
    dup_counts = await feedback_queue._dup_counts(db, [post.id])
    item = feedback_queue.queue_item_dict(
        post, author, dup_counts.get(post.id, 0), datetime.utcnow())
    item["notified"] = msg is not None
    return item


# ---- AI: retriage + draft reply -------------------------------------------

@router.post("/api/admin/feedback/posts/{post_id}/retriage")
async def retriage_post(post_id: int, background_tasks: BackgroundTasks,
                        db: AsyncSession = Depends(get_db),
                        token: str = Depends(verify_token)):
    await _require_admin(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    background_tasks.add_task(run_feedback_triage, post_id)
    return {"queued": True, "post_id": post_id}


class DraftIn(BaseModel):
    target_status: Optional[str] = None


@router.post("/api/admin/feedback/posts/{post_id}/draft-reply")
async def draft_reply(post_id: int, payload: DraftIn,
                      token: str = Depends(verify_token)):
    # Auth in its own short session; the LLM call below runs with no session.
    async with database.async_session() as db:
        await _require_admin(token, db)
    if payload.target_status is not None:
        _parse_status(payload.target_status)
    try:
        return await draft_status_reply(post_id, payload.target_status)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


class ReplyIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=2000)
    post_comment: bool = True


@router.post("/api/admin/feedback/posts/{post_id}/reply")
async def send_reply(post_id: int, payload: ReplyIn,
                     db: AsyncSession = Depends(get_db),
                     token: str = Depends(verify_token)):
    admin = await _require_admin(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    comment_id = None
    if payload.post_comment:
        comment = FeedbackComment(post_id=post_id, user_id=admin.id,
                                  body=payload.body, is_admin=True)
        db.add(comment)
        post.comment_count = (post.comment_count or 0) + 1
        await db.flush()
        comment_id = comment.id

    inbox_message_id = None
    if post.user_id != admin.id:
        msg = ResellerInboxMessage(
            recipient_user_id=post.user_id,
            sender_user_id=admin.id,
            subject=payload.subject,
            body=payload.body,
            sent_sms=False,
        )
        db.add(msg)
        await db.flush()
        inbox_message_id = msg.id

    await db.commit()
    return {"comment_id": comment_id, "inbox_message_id": inbox_message_id}


# ---- Claude Code work packet ----------------------------------------------

@router.get("/api/admin/feedback/posts/{post_id}/work-packet")
async def get_work_packet(post_id: int, db: AsyncSession = Depends(get_db),
                          token: str = Depends(verify_token)):
    await _require_admin(token, db)
    post = await db.get(FeedbackPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    author = await db.get(User, post.user_id)

    duplicates = (await db.execute(
        select(FeedbackPost)
        .where(FeedbackPost.duplicate_of_id == post_id)
        .order_by(FeedbackPost.created_at.desc()).limit(10)
    )).scalars().all()
    # Include the AI's unconfirmed duplicate suggestion for context.
    if post.ai_duplicate_of_id and post.ai_duplicate_of_id not in [d.id for d in duplicates]:
        suggestion = await db.get(FeedbackPost, post.ai_duplicate_of_id)
        if suggestion is not None:
            duplicates.append(suggestion)

    comments = (await db.execute(
        select(FeedbackComment, User)
        .join(User, User.id == FeedbackComment.user_id)
        .where(FeedbackComment.post_id == post_id)
        .order_by(FeedbackComment.created_at.desc()).limit(10)
    )).all()

    dup_counts = await feedback_queue._dup_counts(db, [post_id])
    markdown = feedback_queue.build_work_packet_markdown(
        post, author, duplicates, list(reversed(comments)),
        dup_counts.get(post_id, 0))
    return {"post_id": post_id, "markdown": markdown}

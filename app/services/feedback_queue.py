"""Feedback board queue helpers: priority scoring, admin queue, work packets,
and status changes with author notification.

Everything here is DB-only (no network I/O) and safe to call with a
request-scoped session. Shared by the admin feedback endpoints and the
`handle-feedback` Claude Code skill so both produce identical work packets
and identical status-change side effects (author inbox notification).
"""

import logging
import math
from datetime import datetime
from typing import Optional

from sqlalchemy import func, select

from app.db.models import (
    FeedbackComment,
    FeedbackKind,
    FeedbackPost,
    FeedbackStatus,
    ResellerInboxMessage,
    User,
)

logger = logging.getLogger(__name__)

# Statuses that still need admin attention (default admin-queue filter).
OPEN_STATUSES = (
    FeedbackStatus.NEW,
    FeedbackStatus.UNDER_REVIEW,
    FeedbackStatus.PLANNED,
    FeedbackStatus.IN_PROGRESS,
)

# --- Priority formula (v1, tunable) ----------------------------------------
# priority = severity + damped net votes + confirmed duplicates + recency
# Bugs edge out ideas at equal signal. Untriaged posts score severity as 2
# ("unknown = mild") so they surface but don't dominate.
W_SEVERITY = 3.0
W_VOTES = 2.0
W_DUPES = 1.5
W_RECENCY = 2.0
HALF_LIFE_DAYS = 14.0
BUG_BONUS = 1.0
QUEUE_SCAN_LIMIT = 500


def compute_priority(post: FeedbackPost, dup_count: int, now: datetime) -> float:
    net = (post.upvotes or 0) - (post.downvotes or 0)
    age_days = max((now - (post.created_at or now)).total_seconds() / 86400.0, 0.0)
    return round(
        W_SEVERITY * (post.ai_severity or 2)
        + W_VOTES * math.log2(1 + max(net, 0))
        + W_DUPES * dup_count
        + W_RECENCY * 0.5 ** (age_days / HALF_LIFE_DAYS)
        + (BUG_BONUS if post.kind == FeedbackKind.BUG else 0.0),
        2,
    )


def _enum_value(v):
    return v.value if hasattr(v, "value") else v


def queue_item_dict(post: FeedbackPost, author: Optional[User],
                    dup_count: int, now: datetime) -> dict:
    """Full admin-facing dict for one post (board fields + ai_* + priority)."""
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
        "created_at": post.created_at.isoformat() if post.created_at else None,
        "author": {
            "id": author.id if author else post.user_id,
            "name": author.organization_name if author else None,
            "email": author.email if author else None,
        },
        "ai_triaged_at": post.ai_triaged_at.isoformat() if post.ai_triaged_at else None,
        "ai_spam": post.ai_spam,
        "ai_kind": post.ai_kind,
        "ai_severity": post.ai_severity,
        "ai_summary": post.ai_summary,
        "ai_affected_area": post.ai_affected_area,
        "ai_duplicate_of_id": post.ai_duplicate_of_id,
        "ai_error": post.ai_error,
        "dup_count": dup_count,
        "priority": compute_priority(post, dup_count, now),
    }


async def _dup_counts(db, post_ids: list[int]) -> dict[int, int]:
    """Confirmed duplicates pointing at each post, one grouped SELECT."""
    if not post_ids:
        return {}
    rows = (await db.execute(
        select(FeedbackPost.duplicate_of_id, func.count(FeedbackPost.id))
        .where(FeedbackPost.duplicate_of_id.in_(post_ids))
        .group_by(FeedbackPost.duplicate_of_id)
    )).all()
    return {pid: count for pid, count in rows}


async def fetch_queue(db, *, status: Optional[FeedbackStatus] = None,
                      kind: Optional[FeedbackKind] = None,
                      limit: int = QUEUE_SCAN_LIMIT) -> list[dict]:
    """Priority-sorted admin queue. Defaults to open statuses only."""
    now = datetime.utcnow()
    query = select(FeedbackPost, User).join(User, User.id == FeedbackPost.user_id)
    if status is not None:
        query = query.where(FeedbackPost.status == status)
    else:
        query = query.where(FeedbackPost.status.in_(OPEN_STATUSES))
    if kind is not None:
        query = query.where(FeedbackPost.kind == kind)
    query = query.order_by(FeedbackPost.created_at.desc()).limit(limit)

    rows = (await db.execute(query)).all()
    dup_counts = await _dup_counts(db, [p.id for p, _ in rows])
    items = [queue_item_dict(p, u, dup_counts.get(p.id, 0), now) for p, u in rows]
    items.sort(key=lambda item: item["priority"], reverse=True)
    return items


def build_work_packet_markdown(post: FeedbackPost, author: Optional[User],
                               duplicates: list[FeedbackPost],
                               comments: list[tuple[FeedbackComment, Optional[User]]],
                               dup_count: int,
                               now: Optional[datetime] = None) -> str:
    """Self-contained markdown brief for handing a post to Claude Code."""
    now = now or datetime.utcnow()
    kind = _enum_value(post.kind)
    lines = [
        f"# Feedback #{post.id}: {post.title}",
        "",
        f"- Type: {kind}",
        f"- Status: {_enum_value(post.status)}",
        f"- Votes: +{post.upvotes or 0} / -{post.downvotes or 0}"
        f" (net {(post.upvotes or 0) - (post.downvotes or 0)})",
        f"- Priority score: {compute_priority(post, dup_count, now)}",
        f"- Reported by: {author.organization_name if author else 'unknown'}"
        f" (user id {post.user_id})",
        f"- Reported at: {post.created_at.isoformat() if post.created_at else 'unknown'}",
        "",
        "## Report",
        "",
        post.body,
    ]
    if post.ai_triaged_at:
        rationale = ""
        if isinstance(post.ai_raw, dict):
            rationale = post.ai_raw.get("rationale") or ""
        lines += [
            "",
            "## AI triage",
            "",
            f"- Classified as: {post.ai_kind} (severity {post.ai_severity}/5)",
            f"- Affected area: {post.ai_affected_area}",
            f"- Summary: {post.ai_summary}",
        ]
        if rationale:
            lines.append(f"- Rationale: {rationale}")
    elif post.ai_error:
        lines += ["", "## AI triage", "", f"- Triage failed: {post.ai_error}"]
    if duplicates:
        lines += ["", "## Duplicate / related reports", ""]
        for dup in duplicates:
            excerpt = (dup.body or "")[:200]
            lines.append(f"- #{dup.id} \"{dup.title}\": {excerpt}")
    if comments:
        lines += ["", "## Comments", ""]
        for comment, commenter in comments:
            who = commenter.organization_name if commenter else "unknown"
            tag = " (admin)" if comment.is_admin else ""
            lines.append(f"- {who}{tag}: {comment.body}")
    lines += [
        "",
        "## Instructions for Claude Code",
        "",
        "- Work in the isp-billing repo (backend) and/or ../isp-billing-admin"
        " (admin frontend) as the report requires.",
        "- Follow AGENTS.md: schema changes need an idempotent startup migration"
        " in main.py, and never hold a DB session across network/router I/O.",
        "- Run focused tests for the area you touch.",
        "- After the fix is DEPLOYED to production, update this post's status to"
        " 'fixed' (admin endpoint PATCH /api/admin/feedback/posts/{id} or the"
        " handle-feedback skill) so the reporter is notified. Never mark fixed"
        " before deploy.",
    ]
    return "\n".join(lines)


# --- Status changes + author notification ----------------------------------

_STATUS_NOTIFICATIONS: dict[FeedbackStatus, tuple[str, str]] = {
    FeedbackStatus.UNDER_REVIEW: (
        "Your feedback is under review",
        "Thanks for your {kind} \"{title}\" — it's now under review. "
        "We'll keep you posted here.",
    ),
    FeedbackStatus.PLANNED: (
        "Planned: {title}",
        "Good news — your {kind} \"{title}\" is on the roadmap. "
        "We'll message you again when work starts.",
    ),
    FeedbackStatus.IN_PROGRESS: (
        "In progress: {title}",
        "Work has started on your {kind} \"{title}\". "
        "We'll let you know as soon as it ships.",
    ),
    FeedbackStatus.FIXED: (
        "Fixed: {title}",
        "Your {kind} \"{title}\" has been resolved and deployed. "
        "Thank you for reporting it — replies like yours make the platform "
        "better for every ISP on it.",
    ),
    FeedbackStatus.DECLINED: (
        "Update on: {title}",
        "After review we won't be taking action on your {kind} \"{title}\" "
        "for now. It stays on the board, and votes can still bring it back "
        "into planning.",
    ),
    FeedbackStatus.DUPLICATE: (
        "Merged: {title}",
        "Your {kind} \"{title}\" matches an existing report, so we've merged "
        "them — progress updates will happen on the original post.",
    ),
}


async def apply_status_change(db, post: FeedbackPost, new_status: FeedbackStatus,
                              admin: User,
                              duplicate_of_id: Optional[int] = None,
                              ) -> Optional[ResellerInboxMessage]:
    """Set the status and queue the author's inbox notification. Caller commits.

    Returns the inbox row when one was created (author-only in v1; no
    notification for spam, no self-notification when the admin authored the
    post, no re-notification when the status did not change).
    """
    old_status = post.status
    post.status = new_status
    if new_status == FeedbackStatus.DUPLICATE:
        post.duplicate_of_id = duplicate_of_id
    elif duplicate_of_id is not None:
        post.duplicate_of_id = duplicate_of_id

    if new_status == old_status:
        return None
    if new_status in (FeedbackStatus.SPAM, FeedbackStatus.NEW):
        return None
    if post.user_id == admin.id:
        return None
    template = _STATUS_NOTIFICATIONS.get(new_status)
    if template is None:
        return None

    kind_word = "bug report" if post.kind == FeedbackKind.BUG else "idea"
    subject, body = template
    subject = subject.format(title=post.title, kind=kind_word)[:200]
    body = body.format(title=post.title, kind=kind_word)[:2000]
    msg = ResellerInboxMessage(
        recipient_user_id=post.user_id,
        sender_user_id=admin.id,
        subject=subject,
        body=body,
        sent_sms=False,
    )
    db.add(msg)
    return msg

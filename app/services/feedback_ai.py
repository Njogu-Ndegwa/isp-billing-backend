"""AI triage for the feedback board (levelsio "Product Manager robot" style).

Two entry points:

- ``run_feedback_triage(post_id)`` — fired via FastAPI ``BackgroundTasks`` after
  a submission commits. Classifies spam / bug vs feature, scores severity,
  guesses the affected area, flags duplicate candidates, and alerts the admin
  inbox for critical bugs. Never raises; failure leaves the post untriaged with
  ``ai_error`` set (admin can retrigger).
- ``draft_status_reply(post_id, target_status)`` — called inline from the admin
  endpoint; returns an editable ``{subject, body}`` draft. Persists nothing.

Session discipline (AGENTS.md): the Anthropic API call is slow external I/O, so
it NEVER runs with a DB session open. Each step opens its own short session via
``database.async_session()``: read inputs -> close -> call model -> new session
-> persist. AI being disabled/broken never blocks or loses a submission.
"""

import json
import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import (
    FeedbackComment,
    FeedbackPost,
    FeedbackStatus,
    ResellerInboxMessage,
    User,
    UserRole,
)

logger = logging.getLogger(__name__)

# Bugs at or above this AI severity ping the admin inbox immediately.
CRITICAL_SEVERITY = 4
DUP_CANDIDATE_LIMIT = 200
AI_TIMEOUT_SECONDS = 90.0
TRIAGE_MAX_TOKENS = 1200
REPLY_MAX_TOKENS = 1000

AFFECTED_AREAS = [
    "payments_mpesa", "hotspot", "pppoe", "routers_provisioning",
    "messaging_sms", "vouchers", "subscriptions", "dashboard_reports",
    "auth_accounts", "shop", "customer_portal", "other",
]

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_spam": {"type": "boolean"},
        "kind": {"type": "string", "enum": ["bug", "feature", "other"]},
        "severity": {"type": "integer", "enum": [1, 2, 3, 4, 5]},
        "summary": {"type": "string"},
        "affected_area": {"type": "string", "enum": AFFECTED_AREAS},
        "duplicate_candidate_ids": {"type": "array", "items": {"type": "integer"}},
        "rationale": {"type": "string"},
    },
    "required": ["is_spam", "kind", "severity", "summary", "affected_area",
                 "duplicate_candidate_ids", "rationale"],
    "additionalProperties": False,
}

REPLY_SCHEMA = {
    "type": "object",
    "properties": {
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["subject", "body"],
    "additionalProperties": False,
}

_PLATFORM_CONTEXT = (
    "The product is Bitwave, an ISP billing platform used by WISP operators "
    "(resellers) in Kenya and East Africa. It manages M-Pesa payments (STK "
    "push, C2B paybill, B2B payouts), MikroTik routers (hotspot captive "
    "portal and PPPoE provisioning over WireGuard/L2TP management tunnels), "
    "customer/voucher/subscription management, SMS messaging to customers, "
    "and a reseller admin dashboard. Reports are written by resellers — "
    "paying ISP operators — so treat them as customers of the platform."
)

TRIAGE_SYSTEM_PROMPT = (
    "You triage posts on the platform's feedback board (bug reports and "
    "feature ideas). " + _PLATFORM_CONTEXT + "\n\n"
    "Rules:\n"
    "- is_spam: true only for posts that are clearly not genuine product "
    "feedback (ads, gibberish, abuse). When unsure, false.\n"
    "- kind: what the post actually is, regardless of how the reporter "
    "labeled it. 'other' for questions or support requests.\n"
    "- severity (bugs; for features rate impact/demand): 5 = platform or "
    "payments down for many customers; 4 = core flow broken with no "
    "workaround (payments, provisioning, customer access); 3 = feature "
    "broken but a workaround exists; 2 = minor bug or papercut; 1 = "
    "cosmetic issue or nice-to-have idea.\n"
    "- summary: one plain-English sentence an admin can scan in a queue.\n"
    "- affected_area: best guess from the allowed values.\n"
    "- duplicate_candidate_ids: ids ONLY from the provided candidate list "
    "that describe the same underlying issue; empty list when none do.\n"
    "- rationale: 1-3 sentences explaining severity and duplicates."
)

REPLY_SYSTEM_PROMPT = (
    "You draft a short status-update reply from the platform admin to the "
    "reseller who posted feedback. " + _PLATFORM_CONTEXT + "\n\n"
    "Rules:\n"
    "- Warm, concrete, professional; no over-promising and no invented "
    "dates or commitments.\n"
    "- Address the reporter's organization by name when given.\n"
    "- Reflect the target status the admin is moving the post to.\n"
    "- Body must be under 1200 characters, plain text (no markdown).\n"
    "- The admin edits and approves this draft before it is sent, so do "
    "not add placeholders like [name]."
)


def ai_enabled() -> bool:
    return bool(settings.FEEDBACK_AI_ENABLED and settings.ANTHROPIC_API_KEY)


async def _call_model(*, model: str, system: str, user_content: str,
                      schema: dict, max_tokens: int) -> dict:
    """Single Anthropic API call with structured output. Test seam.

    Raises on any failure (missing package, HTTP error, refusal); callers
    decide whether that is fatal.
    """
    try:
        from anthropic import AsyncAnthropic
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError("anthropic package is not installed") from exc

    client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY,
                            timeout=AI_TIMEOUT_SECONDS)
    try:
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_content}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
    finally:
        await client.close()
    if response.stop_reason == "refusal":
        raise RuntimeError("model declined the request")
    text = next(
        (block.text for block in response.content
         if getattr(block, "type", None) == "text"),
        None,
    )
    if not text:
        raise RuntimeError("model returned no text content")
    result = json.loads(text)
    result["_usage"] = {
        "model": model,
        "input_tokens": getattr(response.usage, "input_tokens", None),
        "output_tokens": getattr(response.usage, "output_tokens", None),
    }
    return result


def _render_triage_input(post: dict, candidates: list[dict]) -> str:
    lines = [
        f"New feedback post #{post['id']}",
        f"Reporter-chosen type: {post['kind']}",
        f"Title: {post['title']}",
        "Body:",
        post["body"],
        "",
        "Existing posts (duplicate candidates — use ONLY these ids):",
    ]
    if candidates:
        for c in candidates:
            lines.append(f"- #{c['id']} [{c['status']}] {c['title']}")
    else:
        lines.append("(none)")
    return "\n".join(lines)


async def _resolve_alert_admin_id(db) -> Optional[int]:
    return (await db.execute(
        select(User.id).where(User.role == UserRole.ADMIN)
        .order_by(User.id).limit(1)
    )).scalar_one_or_none()


async def run_feedback_triage(post_id: int) -> None:
    """BackgroundTasks entry point. Never raises."""
    try:
        # Short session #1: read the post + duplicate candidates, then close.
        async with database.async_session() as db:
            post_row = await db.get(FeedbackPost, post_id)
            if post_row is None:
                return
            post = {
                "id": post_row.id,
                "kind": post_row.kind.value,
                "title": post_row.title,
                "body": post_row.body,
                "user_id": post_row.user_id,
            }
            candidate_rows = (await db.execute(
                select(FeedbackPost.id, FeedbackPost.title, FeedbackPost.status)
                .where(FeedbackPost.id != post_id,
                       FeedbackPost.status != FeedbackStatus.SPAM)
                .order_by(FeedbackPost.created_at.desc())
                .limit(DUP_CANDIDATE_LIMIT)
            )).all()
            candidates = [
                {"id": cid, "title": title,
                 "status": status.value if hasattr(status, "value") else status}
                for cid, title, status in candidate_rows
            ]
        candidate_ids = {c["id"] for c in candidates}

        if not ai_enabled():
            return

        # Slow external I/O — no DB session open here.
        triage = await _call_model(
            model=settings.FEEDBACK_TRIAGE_MODEL,
            system=TRIAGE_SYSTEM_PROMPT,
            user_content=_render_triage_input(post, candidates),
            schema=TRIAGE_SCHEMA,
            max_tokens=TRIAGE_MAX_TOKENS,
        )

        # Short session #2: persist the verdict.
        needs_alert = False
        alert_payload: dict[str, Any] = {}
        async with database.async_session() as db:
            post_row = await db.get(FeedbackPost, post_id)
            if post_row is None:
                return
            # Never trust model-invented ids: only candidates we offered count.
            valid_dups = [i for i in triage.get("duplicate_candidate_ids", [])
                          if isinstance(i, int) and i in candidate_ids]
            post_row.ai_triaged_at = datetime.utcnow()
            post_row.ai_spam = bool(triage["is_spam"])
            post_row.ai_kind = triage["kind"]
            post_row.ai_severity = int(triage["severity"])
            post_row.ai_summary = (triage["summary"] or "")[:300]
            post_row.ai_affected_area = triage["affected_area"]
            post_row.ai_duplicate_of_id = valid_dups[0] if valid_dups else None
            post_row.ai_raw = {k: v for k, v in triage.items()
                               if k != "_usage"} | {"usage": triage.get("_usage")}
            post_row.ai_error = None
            if post_row.ai_spam and post_row.status == FeedbackStatus.NEW:
                post_row.status = FeedbackStatus.SPAM
            needs_alert = (
                not post_row.ai_spam
                and triage["kind"] == "bug"
                and int(triage["severity"]) >= CRITICAL_SEVERITY
            )
            alert_payload = {
                "author_id": post_row.user_id,
                "title": post_row.title,
                "summary": post_row.ai_summary,
                "severity": post_row.ai_severity,
                "area": post_row.ai_affected_area,
            }
            await db.commit()

        # Short session #3: critical-bug alert to the admin inbox.
        if needs_alert:
            await _send_critical_alert(post_id, alert_payload)
    except Exception as exc:  # noqa: BLE001 - triage must never break submission
        logger.exception("Feedback triage failed for post %s", post_id)
        try:
            async with database.async_session() as db:
                post_row = await db.get(FeedbackPost, post_id)
                if post_row is not None:
                    post_row.ai_error = str(exc)[:255]
                    await db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("Could not record triage error for post %s", post_id)


async def _send_critical_alert(post_id: int, payload: dict) -> None:
    """Own short session; failure is logged, never raised."""
    try:
        async with database.async_session() as db:
            admin_id = await _resolve_alert_admin_id(db)
            if admin_id is None or admin_id == payload["author_id"]:
                return
            subject = f"Critical bug report #{post_id}: {payload['title']}"[:200]
            body = (
                f"AI triage flagged a critical bug (severity "
                f"{payload['severity']}/5, area: {payload['area']}).\n\n"
                f"{payload['summary']}\n\n"
                f"Review it in Admin > Feedback (post #{post_id})."
            )[:2000]
            db.add(ResellerInboxMessage(
                recipient_user_id=admin_id,
                sender_user_id=payload["author_id"],
                subject=subject,
                body=body,
                sent_sms=False,
            ))
            await db.commit()
            logger.info("Critical feedback alert sent for post %s", post_id)
    except Exception:  # noqa: BLE001
        logger.exception("Critical feedback alert failed for post %s", post_id)


async def draft_status_reply(post_id: int,
                             target_status: Optional[str] = None) -> dict:
    """Draft an admin reply. Raises RuntimeError when AI is unavailable."""
    if not ai_enabled():
        raise RuntimeError("AI drafting is not configured (no API key)")

    # Short session: gather context, then close before the API call.
    async with database.async_session() as db:
        post_row = await db.get(FeedbackPost, post_id)
        if post_row is None:
            raise RuntimeError(f"Feedback post {post_id} not found")
        author = await db.get(User, post_row.user_id)
        comment_rows = (await db.execute(
            select(FeedbackComment, User)
            .join(User, User.id == FeedbackComment.user_id)
            .where(FeedbackComment.post_id == post_id)
            .order_by(FeedbackComment.created_at.desc())
            .limit(10)
        )).all()
        context = {
            "kind": post_row.kind.value,
            "title": post_row.title,
            "body": post_row.body,
            "status": post_row.status.value,
            "net_votes": (post_row.upvotes or 0) - (post_row.downvotes or 0),
            "ai_summary": post_row.ai_summary,
            "author_org": author.organization_name if author else None,
            "comments": [
                {"author": u.organization_name, "is_admin": c.is_admin,
                 "body": c.body}
                for c, u in reversed(comment_rows)
            ],
        }

    user_content = (
        f"Target status: {target_status or context['status']}\n"
        f"Post ({context['kind']}) by {context['author_org'] or 'a reseller'}: "
        f"\"{context['title']}\"\n"
        f"Current status: {context['status']} | net votes: {context['net_votes']}\n"
        f"AI summary: {context['ai_summary'] or '(not triaged)'}\n\n"
        f"Report body:\n{context['body']}\n\n"
        f"Recent comments: {json.dumps(context['comments'])}\n\n"
        "Draft the reply now."
    )
    draft = await _call_model(
        model=settings.FEEDBACK_REPLY_MODEL,
        system=REPLY_SYSTEM_PROMPT,
        user_content=user_content,
        schema=REPLY_SCHEMA,
        max_tokens=REPLY_MAX_TOKENS,
    )
    return {"subject": (draft["subject"] or "")[:200],
            "body": (draft["body"] or "")[:2000]}

"""Per-router status alerts (on by default, opt-out): "went offline" and
"back online" messages.

One flag (``routers.status_alerts_enabled``) covers both directions:

- Offline: a scheduler scan (``scan_and_notify_offline_routers``) notices routers
  that have been confirmed offline for at least MIN_OUTAGE_FOR_ALERTS and sends
  one "went offline" notice per outage. A single failed probe is NOT trusted —
  the debounce is the whole point, since availability is recorded by ~40 code
  paths and one failed connect can be a tunnel blip rather than an outage.
- Online: ``record_router_availability`` calls into here on an offline -> online
  transition and sends the matching "back online" recovery notice.

Delivery is an in-app inbox message (``ResellerInboxMessage``) plus, when the
owner has a phone on file, messaging is enabled, and their SMS credit balance
covers it, an SMS charged to the owner's credits (same single opt-in toggle).
Insufficient credits silently degrade to inbox-only; a failed provider send is
refunded.

Session discipline: message/credit rows are DB-only and run in their OWN short
session (the online path fires AFTER the availability write has committed), so
the hot ``routers`` row lock stays bounded to milliseconds (see Database Session
Discipline in AGENTS.md). The provider SMS send happens in a fire-and-forget
task AFTER that commit — availability is recorded from ~40 code paths, some
customer-facing, so the network call must neither hold a session nor add
latency there. The offline scan sheds load when the DB pool is under pressure,
per the background-work guardrails.

Noise control:
- ``MIN_OUTAGE_FOR_ALERTS``: outages shorter than this produce no message in
  either direction.
- ``NOTIFY_COOLDOWN`` via the per-router ``online_notified_at`` /
  ``offline_notified_at`` stamps, claimed with an atomic UPDATE so concurrent
  writers cannot double-send. The offline stamp doubles as the once-per-outage
  marker (a stamp newer than ``last_online_at`` means this outage was already
  announced).
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, update

from app.config import settings
from app.db import database
from app.db.database import db_pool_snapshot
from app.db.models import (
    MessagingSettings,
    ResellerInboxMessage,
    Router,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    User,
)
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments, resolve_sender_id
from app.services.reseller_welcome import _resolve_sender_admin_id

logger = logging.getLogger(__name__)

ALERT_SMS_CATEGORY = "router_status_alert"

MIN_OUTAGE_FOR_ALERTS = timedelta(minutes=15)
NOTIFY_COOLDOWN = timedelta(minutes=30)
# An offline verdict older than this is stale ("unknown", not confirmed offline):
# offline routers are still re-probed at least every ~30 min by background jobs,
# so a fresh outage always has a recent failed check.
OFFLINE_STATUS_FRESH_WINDOW = timedelta(minutes=90)


def _db_pool_too_busy() -> bool:
    try:
        pressure = (db_pool_snapshot().get("pressure") or {}).get("level")
    except Exception as exc:  # noqa: BLE001 - never fail alerts on telemetry
        logger.warning("Could not read DB pool pressure for status alerts: %s", exc)
        return False
    return pressure in {"warning", "critical"}


def should_consider_recovery_notification(router: Router, checked_at: datetime) -> bool:
    """Cheap pre-check, run inside the availability session BEFORE the status flip.

    True only for a genuine offline -> online transition on an opted-in router
    where the outage lasted at least MIN_OUTAGE_FOR_ALERTS (a never-seen-online
    router coming up for the first time also counts). The cooldown is NOT checked
    here — it is claimed atomically in send_router_recovery_notification.
    """
    if not getattr(router, "status_alerts_enabled", False):
        return False
    if router.last_status is not False:
        return False
    last_online = getattr(router, "last_online_at", None)
    if last_online is not None and (checked_at - last_online) < MIN_OUTAGE_FOR_ALERTS:
        return False
    return True


def _humanize_duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        parts = [f"{hours} hour{'s' if hours != 1 else ''}"]
        if minutes:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        return " ".join(parts)
    days, hours = divmod(hours, 24)
    parts = [f"{days} day{'s' if days != 1 else ''}"]
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    return " ".join(parts)


_OPT_OUT_HINT = (
    " You get this alert because status alerts are enabled for this router; "
    "you can turn them off from the Routers or Messaging page."
)


def render_recovery_notification(name: str, offline_since: Optional[datetime],
                                 now: datetime) -> tuple[str, str]:
    """Return (subject, body) for the "back online" inbox message."""
    subject = f"Router back online: {name}"
    if offline_since is not None and now > offline_since:
        body = (
            f"Your router '{name}' is back online after being offline for about "
            f"{_humanize_duration(now - offline_since)}."
        )
    else:
        body = f"Your router '{name}' is now online."
    return subject, body + _OPT_OUT_HINT


def render_offline_notification(name: str, offline_since: datetime,
                                now: datetime) -> tuple[str, str]:
    """Return (subject, body) for the "went offline" inbox message."""
    subject = f"Router offline: {name}"
    body = (
        f"Your router '{name}' appears to be offline. It was last seen online "
        f"about {_humanize_duration(now - offline_since)} ago. We'll send another "
        "message when it comes back online."
    )
    return subject, body + _OPT_OUT_HINT


async def _queue_alert_sms(db, owner: User, router: Router,
                           sms_body: str) -> tuple[Optional[int], Optional[str]]:
    """Charge the owner's credits and add the QUEUED SMS row. Caller commits.

    Returns (sms_message_id, provider_sender_id), or (None, None) when SMS is
    skipped: dispatch disabled, messaging disabled, no phone on file, or
    insufficient credits (inbox-only in every skip case).
    """
    if not settings.SMS_DISPATCH_ENABLED:
        return None, None
    phone = (owner.support_phone or "").strip()
    if not phone:
        return None, None
    settings_row = await db.get(MessagingSettings, 1)
    if settings_row is not None and not settings_row.enabled:
        return None, None
    segments = count_segments(sms_body)
    if not await sms_credits.try_deduct(
            db, owner.id, segments,
            reference=f"router_alert:{router.id}",
            note=f"Status alert SMS for router '{router.name}'"):
        logger.info(
            "Router %s alert SMS skipped: user %s has insufficient credits",
            router.id, owner.id,
        )
        return None, None
    row = SmsMessage(
        user_id=owner.id,
        recipient_phone=phone,
        body=sms_body,
        segments=segments,
        credits_charged=segments,
        kind=SmsMessageKind.ADMIN_TO_RESELLER,
        category=ALERT_SMS_CATEGORY,
        status=SmsMessageStatus.QUEUED,
    )
    db.add(row)
    await db.flush()
    return row.id, resolve_sender_id(settings_row.sender_id if settings_row else None)


async def _create_alert_messages(
    db, router: Router, subject: str, body: str,
) -> tuple[bool, Optional[int], Optional[str]]:
    """Add the inbox row (+ optional charged SMS row) for the router's owner.

    Caller commits. Returns (created, sms_message_id, provider_sender_id);
    the SMS fields are None when no SMS was queued.
    """
    owner = await db.get(User, router.user_id)
    if not owner:
        return False, None, None
    admin_id = await _resolve_sender_admin_id(db, owner)
    if admin_id is None:
        return False, None, None
    # The SMS is the inbox body minus the opt-out hint (keeps it one segment).
    sms_id, provider_sender = await _queue_alert_sms(
        db, owner, router, body.removesuffix(_OPT_OUT_HINT))
    db.add(ResellerInboxMessage(
        recipient_user_id=owner.id,
        sender_user_id=admin_id,
        subject=subject,
        body=body,
        sent_sms=sms_id is not None,
    ))
    return True, sms_id, provider_sender


async def deliver_alert_sms(sms_id: int, provider_sender_id: Optional[str]) -> None:
    """Send one queued alert SMS, refunding the credits if it did not go out.

    The dispatcher manages its own short sessions, so no DB connection is held
    across the provider call. Never raises.
    """
    try:
        await sms_dispatch.dispatch_admin_sms_messages([sms_id], provider_sender_id)
    except Exception:
        logger.exception("Alert SMS dispatch crashed for sms %s", sms_id)
    try:
        async with database.async_session() as db:
            row = await db.get(SmsMessage, sms_id)
            if row is None:
                return
            if row.status == SmsMessageStatus.QUEUED:
                # Dispatch crashed before persisting a result for this row.
                row.status = SmsMessageStatus.FAILED
                row.error = row.error or "dispatch_error"
            if row.status == SmsMessageStatus.FAILED and row.credits_charged:
                await sms_credits.refund(
                    db, row.user_id, row.credits_charged,
                    reference=f"router_alert_sms:{sms_id}",
                    note="Router alert SMS not delivered")
                row.credits_charged = 0
            await db.commit()
    except Exception:
        logger.exception("Alert SMS settlement failed for sms %s", sms_id)


_alert_sms_tasks: set = set()


def _spawn_alert_sms_dispatch(sms_id: int,
                              provider_sender_id: Optional[str]) -> None:
    """Fire-and-forget the provider send so callers never wait on the network."""
    try:
        task = asyncio.create_task(deliver_alert_sms(sms_id, provider_sender_id))
    except RuntimeError:
        logger.warning("No running event loop; alert SMS %s left queued", sms_id)
        return
    _alert_sms_tasks.add(task)
    task.add_done_callback(_alert_sms_tasks.discard)


async def send_router_recovery_notification(
    router_id: int,
    offline_since: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> bool:
    """Create the "back online" inbox message in its own short session. Never raises.

    Returns True when a message was created, False when skipped (cooldown lost,
    opt-out raced, owner/admin missing) or on error.
    """
    now = now or datetime.utcnow()
    try:
        async with database.async_session() as db:
            # Atomic cooldown claim: only one concurrent writer per cooldown
            # window gets rowcount 1; everyone else skips without a message.
            claim = await db.execute(
                update(Router)
                .where(
                    Router.id == router_id,
                    Router.status_alerts_enabled.is_(True),
                    (Router.online_notified_at.is_(None))
                    | (Router.online_notified_at <= now - NOTIFY_COOLDOWN),
                )
                .values(online_notified_at=now)
            )
            if claim.rowcount != 1:
                await db.rollback()
                return False

            router = await db.get(Router, router_id)
            if not router:
                await db.rollback()
                return False
            subject, body = render_recovery_notification(router.name, offline_since, now)
            created, sms_id, provider_sender = await _create_alert_messages(
                db, router, subject, body)
            if not created:
                await db.rollback()
                return False
            await db.commit()
            logger.info(
                "Router recovery notification sent: router %s -> user %s (sms=%s)",
                router_id, router.user_id, sms_id is not None,
            )
        if sms_id is not None:
            _spawn_alert_sms_dispatch(sms_id, provider_sender)
        return True
    except Exception:
        logger.exception("Router recovery notification failed for router %s", router_id)
        return False


def _offline_candidate_filters(now: datetime):
    """WHERE clauses shared by the scan's SELECT and the per-router claim UPDATE."""
    return (
        Router.status_alerts_enabled.is_(True),
        Router.last_status.is_(False),
        Router.last_checked_at.isnot(None),
        Router.last_checked_at >= now - OFFLINE_STATUS_FRESH_WINDOW,
        Router.last_online_at.isnot(None),
        Router.last_online_at <= now - MIN_OUTAGE_FOR_ALERTS,
        (Router.offline_notified_at.is_(None))
        | (
            (Router.offline_notified_at < Router.last_online_at)
            & (Router.offline_notified_at <= now - NOTIFY_COOLDOWN)
        ),
    )


async def send_router_offline_notification(
    router_id: int,
    now: Optional[datetime] = None,
) -> bool:
    """Create the "went offline" inbox message in its own short session. Never raises.

    Re-verifies the outage conditions in the claim UPDATE, so it is safe even if
    the router recovered between the scan's SELECT and this call.
    """
    now = now or datetime.utcnow()
    try:
        async with database.async_session() as db:
            claim = await db.execute(
                update(Router)
                .where(Router.id == router_id, *_offline_candidate_filters(now))
                .values(offline_notified_at=now)
            )
            if claim.rowcount != 1:
                await db.rollback()
                return False

            router = await db.get(Router, router_id)
            if not router or router.last_online_at is None:
                await db.rollback()
                return False
            subject, body = render_offline_notification(
                router.name, router.last_online_at, now
            )
            created, sms_id, provider_sender = await _create_alert_messages(
                db, router, subject, body)
            if not created:
                await db.rollback()
                return False
            await db.commit()
            logger.info(
                "Router offline notification sent: router %s -> user %s (sms=%s)",
                router_id, router.user_id, sms_id is not None,
            )
        if sms_id is not None:
            _spawn_alert_sms_dispatch(sms_id, provider_sender)
        return True
    except Exception:
        logger.exception("Router offline notification failed for router %s", router_id)
        return False


async def scan_and_notify_offline_routers() -> int:
    """Scheduler entry: send "went offline" notices for confirmed outages.

    Optional background work: skips entirely when the DB pool is under pressure.
    Candidate ids are read in one short session; each notice then claims and
    commits in its own short session. Returns the number of messages sent.
    """
    if _db_pool_too_busy():
        logger.info("Skipping offline-alert scan: DB pool under pressure")
        return 0
    now = datetime.utcnow()
    try:
        async with database.async_session() as db:
            result = await db.execute(
                select(Router.id).where(*_offline_candidate_filters(now))
            )
            candidate_ids = [row[0] for row in result.all()]
    except Exception:
        logger.exception("Offline-alert scan could not list candidates")
        return 0

    sent = 0
    for router_id in candidate_ids:
        if await send_router_offline_notification(router_id, now=now):
            sent += 1
    if candidate_ids:
        logger.info(
            "Offline-alert scan: %s candidate(s), %s notice(s) sent",
            len(candidate_ids), sent,
        )
    return sent

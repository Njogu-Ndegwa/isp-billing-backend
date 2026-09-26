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
- Daily budget per router (2026-09-24, after flapping routers sent one reseller
  52 messages in a day): at most ``MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY`` (3)
  messages per router per local day. The first outage gets "went offline", its
  recovery gets "back online", and any further outage that day gets ONE
  "unstable connection" message that uses up the rest of the day's budget, so a
  flapping router can never produce more than 3 messages a day. The budget is
  claimed with a compare-and-swap UPDATE, so concurrent writers cannot overspend.
- "Back online" is only sent for an outage we actually announced (a first-ever
  online is the one exception) — no orphan recovery messages.
- Per-reseller SMS cap: at most ``MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY`` status
  SMS per reseller per local day across all their routers; beyond that the
  alert is inbox-only.
- ``MIN_OUTAGE_FOR_ALERTS``: outages shorter than this produce no message in
  either direction.
- ``MAX_OUTAGE_AGE_FOR_ALERTS``: "went offline" is only announced while the
  outage is recent; ancient outages (zombie rows from re-registrations,
  decommissioned routers) stay silent.
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

from sqlalchemy import func, select, update

from app.config import settings
from app.core.local_time import local_midnight_utc, local_now
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
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import count_segments, resolve_sender_id
from app.services.reseller_welcome import _resolve_sender_admin_id

logger = logging.getLogger(__name__)

ALERT_SMS_CATEGORY = "router_status_alert"

MIN_OUTAGE_FOR_ALERTS = timedelta(minutes=15)
NOTIFY_COOLDOWN = timedelta(minutes=30)
# Only announce outages that BEGAN recently. An outage older than this is not
# news — the owner already knows, or the row is a zombie left behind by a
# re-registration (2026-07-23: the default-on backfill sent 99 alerts for
# week-plus outages on exactly such rows). Recovery notices are NOT capped:
# a transition back online is always fresh news.
MAX_OUTAGE_AGE_FOR_ALERTS = timedelta(hours=48)
# An offline verdict older than this is stale ("unknown", not confirmed offline):
# offline routers are still re-probed at least every ~30 min by background jobs,
# so a fresh outage always has a recent failed check.
OFFLINE_STATUS_FRESH_WINDOW = timedelta(minutes=90)
# The reachability probe (2026-09-26) started confirming outages nothing had
# noticed. Dennis: no late "went offline" news for outages that began before it
# went live. The cutoff is written ONCE at the first startup that has the probe
# (app_settings row, never overwritten), so restarts don't move it; when the
# row is absent every outage is eligible, as before. Irrelevant after 48 h
# (MAX_OUTAGE_AGE_FOR_ALERTS).
OUTAGE_ALERTS_FROM_SETTING = "router_outage_alerts_from"
MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY = 3
MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY = 4

KIND_OFFLINE = "offline"
KIND_UNSTABLE = "unstable"
KIND_RECOVERY = "recovery"


def _local_day(now: datetime) -> str:
    return local_now(now).strftime("%Y-%m-%d")


def _announced_outage(router: Router) -> bool:
    """True when the current outage's "went offline" message was sent."""
    off = getattr(router, "offline_notified_at", None)
    on = getattr(router, "online_notified_at", None)
    return off is not None and (on is None or off > on)


def decide_daily_kind(router: Router, requested: str, now: datetime,
                      first_ever_online: bool = False) -> Optional[tuple[str, int]]:
    """Apply the per-router daily budget. Returns (kind, new_count) or None.

    Pure function over the row's current budget; the caller persists it with a
    compare-and-swap on (status_alerts_day, status_alerts_sent_today).
    """
    today = _local_day(now)
    used = (router.status_alerts_sent_today or 0) if router.status_alerts_day == today else 0
    if used >= MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY:
        return None
    if requested == KIND_OFFLINE:
        if used == 0:
            return KIND_OFFLINE, 1
        # Second outage today: one "unstable" message, then silence until tomorrow.
        return KIND_UNSTABLE, MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY
    # Recovery: only for an announced outage, or a router's first-ever online
    # (the caller knows that from the pre-transition row: offline_since is None).
    if not (_announced_outage(router) or first_ever_online):
        return None
    return KIND_RECOVERY, used + 1


async def _spend_daily_budget(db, router: Router, new_count: int, now: datetime) -> bool:
    """Compare-and-swap the router's daily budget. Caller commits/rolls back."""
    prev_day = router.status_alerts_day
    prev_count = router.status_alerts_sent_today or 0
    day_match = (Router.status_alerts_day.is_(None) if prev_day is None
                 else Router.status_alerts_day == prev_day)
    result = await db.execute(
        update(Router)
        .where(Router.id == router.id, day_match,
               func.coalesce(Router.status_alerts_sent_today, 0) == prev_count)
        .values(status_alerts_day=_local_day(now), status_alerts_sent_today=new_count)
    )
    return result.rowcount == 1


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


def render_unstable_notification(name: str) -> tuple[str, str]:
    """Return (subject, body) for the once-a-day "unstable connection" message."""
    subject = f"Router connection unstable: {name}"
    body = (
        f"Your router '{name}' has gone offline again today. The connection looks "
        "unstable; please check the router's power and internet link. We won't send "
        "more offline/online alerts for this router until tomorrow."
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
    sent_today = (await db.execute(
        select(func.count(SmsMessage.id)).where(
            SmsMessage.user_id == owner.id,
            SmsMessage.category == ALERT_SMS_CATEGORY,
            SmsMessage.created_at >= local_midnight_utc(),
        )
    )).scalar() or 0
    if sent_today >= MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY:
        logger.info("Router %s alert SMS skipped: owner %s reached the daily SMS cap",
                    router.id, owner.id)
        return None, None
    segments = count_segments(sms_body)
    # The alert is billed to the router's owner, so it follows their gateway:
    # on their own gateway they pay their vendor and owe no portal credits,
    # which also means a zero balance can no longer suppress their alerts.
    bills_credits = await provider_accounts.bills_platform_credits(db, owner.id)
    credits_charged = segments if bills_credits else 0
    if bills_credits and not await sms_credits.try_deduct(
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
        credits_charged=credits_charged,
        kind=SmsMessageKind.ADMIN_TO_RESELLER,
        category=ALERT_SMS_CATEGORY,
        status=SmsMessageStatus.QUEUED,
    )
    db.add(row)
    await db.flush()
    sender_id = await provider_accounts.resolve_sender_id_for(
        db, owner.id, settings_row.sender_id if settings_row else None
    )
    return row.id, sender_id


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
    # The alert is billed to the router's owner, so it goes out on that
    # reseller's own gateway when they have one configured.
    owner_user_id = None
    try:
        async with database.async_session() as db:
            row = await db.get(SmsMessage, sms_id)
            owner_user_id = row.user_id if row is not None else None
    except Exception:
        logger.exception("Could not read owner for alert sms %s", sms_id)
    try:
        await sms_dispatch.dispatch_admin_sms_messages(
            [sms_id], provider_sender_id, owner_user_id=owner_user_id
        )
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
            # Daily budget + "only after an announced outage", decided on the
            # row as it was BEFORE this recovery's cooldown claim.
            before = await db.get(Router, router_id)
            if before is None:
                return False
            decision = decide_daily_kind(before, KIND_RECOVERY, now,
                                         first_ever_online=offline_since is None)
            if decision is None:
                await db.rollback()
                return False
            _, new_count = decision
            if not await _spend_daily_budget(db, before, new_count, now):
                await db.rollback()
                return False
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


async def _outage_alerts_from(db) -> Optional[datetime]:
    """Outages that began before this are not announced (see OUTAGE_ALERTS_FROM_SETTING)."""
    from app.db.models import AppSetting

    setting = await db.get(AppSetting, OUTAGE_ALERTS_FROM_SETTING)
    if setting is None or not setting.value:
        return None
    try:
        return datetime.fromisoformat(setting.value.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return None


def _offline_candidate_filters(now: datetime, alerts_from: Optional[datetime] = None):
    """WHERE clauses shared by the scan's SELECT and the per-router claim UPDATE."""
    extra = (Router.last_online_at >= alerts_from,) if alerts_from is not None else ()
    return extra + (
        Router.status_alerts_enabled.is_(True),
        Router.last_status.is_(False),
        Router.last_checked_at.isnot(None),
        Router.last_checked_at >= now - OFFLINE_STATUS_FRESH_WINDOW,
        Router.last_online_at.isnot(None),
        Router.last_online_at <= now - MIN_OUTAGE_FOR_ALERTS,
        Router.last_online_at >= now - MAX_OUTAGE_AGE_FOR_ALERTS,
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
                .where(Router.id == router_id,
                       *_offline_candidate_filters(now, await _outage_alerts_from(db)))
                .values(offline_notified_at=now)
            )
            if claim.rowcount != 1:
                await db.rollback()
                return False

            router = await db.get(Router, router_id)
            if not router or router.last_online_at is None:
                await db.rollback()
                return False
            await db.refresh(router)
            decision = decide_daily_kind(router, KIND_OFFLINE, now)
            if decision is None or not await _spend_daily_budget(db, router, decision[1], now):
                # Budget spent for today: stay silent (the stamp is rolled back
                # too, so the outage is announced tomorrow if it is still going).
                await db.rollback()
                return False
            if decision[0] == KIND_UNSTABLE:
                subject, body = render_unstable_notification(router.name)
            else:
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
                select(Router.id).where(*_offline_candidate_filters(now, await _outage_alerts_from(db)))
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

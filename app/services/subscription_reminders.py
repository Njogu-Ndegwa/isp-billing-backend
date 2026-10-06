"""Pre-expiry subscription reminders for resellers (admin-funded SMS + inbox).

Why this exists: when a reseller's subscription lapses they are suspended, and
suspension is not just a locked admin panel — ``radius_hotspot`` refuses hotspot
payments for a suspended owner, so their *customers* cannot buy internet either.
A reseller who forgets to renew loses revenue, and so do we. These texts are sent
on the platform's own SMS account (``SmsMessageKind.ADMIN_TO_RESELLER``, the same
path as the signup welcome), never against the reseller's credit balance and
never through a reseller's own gateway.

Three stages per expiry cycle, trial and paid alike:

- ``t72`` ~3 days out: enough runway to find the money (the invoice already
  exists — ``generate_pre_expiry_invoices`` raises it 5 days out).
- ``t24`` ~24 h out.
- ``t2``  ~2 h out: the final nudge.

Quiet hours: ``subscription_expires_at`` inherits the time of day the reseller
last paid, so a naive T-2h lands in the small hours for plenty of accounts. A
reminder falling between 22:00 and 07:00 in the reseller's own market timezone
is held until 07:00 there instead of being burned on a sleeping reseller.

Send deadline: suspension does not happen at the expiry instant — it happens on
the next ``check_overdue_invoices`` run (daily 08:00 UTC). So a reminder stays
worth sending slightly past nominal expiry, and the copy switches to "has
expired" rather than lying about time remaining. Past that run we go quiet.

Session discipline (AGENTS.md): this module is DB-only. Rows are created and
committed in short sessions; the provider call happens afterwards in
``sms_dispatch.dispatch_admin_sms_messages``, which holds no session across the
network. The scan sheds load when the DB pool is under pressure — it runs every
10 minutes and the claim is idempotent, so a skipped tick just sends a few
minutes later.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import database
from app.db.database import db_pool_snapshot
from app.db.models import (
    InvoiceStatus,
    MessagingSettings,
    ResellerInboxMessage,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    SubscriptionExpiryReminder,
    SubscriptionInvoice,
    SubscriptionStatus,
    User, UserRole,
)
from app.services.markets import reseller_market
from app.services.messaging import count_segments
from app.services.reseller_welcome import _resolve_sender_admin_id

logger = logging.getLogger(__name__)

REMINDER_CATEGORY = "subscription_expiry"

DEFAULT_TIMEZONE = "Africa/Nairobi"
QUIET_START_HOUR = 22   # local, inclusive
QUIET_END_HOUR = 7      # local, exclusive — held reminders release at 07:00

# Every market we sell in has a fixed UTC offset and no daylight saving. Used
# when the runtime has no tz database (python:slim images often don't), so a
# missing zoneinfo never silently turns quiet hours into UTC hours.
_FIXED_OFFSETS = {
    "Africa/Nairobi": (3, "EAT"),
    "Africa/Kampala": (3, "EAT"),
    "Africa/Dar_es_Salaam": (3, "EAT"),
    "Africa/Douala": (1, "WAT"),
}

# main.py schedules check_overdue_invoices at 08:00 UTC. That run is what
# actually suspends people, so it is the last moment a reminder can help.
SUSPENSION_RUN_HOUR_UTC = 8

# Ordered longest lead first. Stage keys are persisted, so don't rename them.
STAGES: tuple[tuple[str, timedelta], ...] = (
    ("t72", timedelta(hours=72)),
    ("t24", timedelta(hours=24)),
    ("t2", timedelta(hours=2)),
)
STAGE_LABELS = {"t72": "3 days before", "t24": "24 hours before", "t2": "2 hours before"}

# Deliberately terse: these are billed per 160-char GSM-7 segment on our own
# account. tests/test_subscription_reminders.py asserts they stay at 1 segment.
_SUSPENDED_TAIL = "customers cannot buy internet while you are suspended."
_SMS = {
    # (trial, expired, has_amount)
    (False, False, True): "Bitwave: your subscription expires in about {when}. "
                          "Pay {amount} in the app to stay active - " + _SUSPENDED_TAIL,
    (False, False, False): "Bitwave: your subscription expires in about {when}. "
                           "Renew in the app to stay active - " + _SUSPENDED_TAIL,
    (False, True, True): "Bitwave: your subscription has expired. Pay {amount} "
                         "in the app now - " + _SUSPENDED_TAIL,
    (False, True, False): "Bitwave: your subscription has expired. Renew in the "
                          "app now - " + _SUSPENDED_TAIL,
    (True, False, True): "Bitwave: your free trial ends in about {when}. "
                         "Pay {amount} in the app to stay active - " + _SUSPENDED_TAIL,
    (True, False, False): "Bitwave: your free trial ends in about {when}. "
                          "Subscribe in the app to stay active - " + _SUSPENDED_TAIL,
    (True, True, True): "Bitwave: your free trial has ended. Pay {amount} in "
                        "the app now - " + _SUSPENDED_TAIL,
    (True, True, False): "Bitwave: your free trial has ended. Subscribe in the "
                         "app now - " + _SUSPENDED_TAIL,
}


# --------------------------------------------------------------------------
# Time helpers (pure)
# --------------------------------------------------------------------------

def _zone(tz_name: Optional[str]):
    name = tz_name or DEFAULT_TIMEZONE
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        hours, _ = _FIXED_OFFSETS.get(name, _FIXED_OFFSETS[DEFAULT_TIMEZONE])
        return timezone(timedelta(hours=hours))


def zone_abbreviation(tz_name: Optional[str]) -> str:
    return _FIXED_OFFSETS.get(tz_name or DEFAULT_TIMEZONE, (0, "local time"))[1]


def to_local(when_utc: datetime, tz_name: Optional[str]) -> datetime:
    """Naive UTC (how the DB stores it) -> naive wall-clock in the zone."""
    aware = when_utc.replace(tzinfo=timezone.utc).astimezone(_zone(tz_name))
    return aware.replace(tzinfo=None)


def _from_local(local: datetime, tz_name: Optional[str]) -> datetime:
    aware = local.replace(tzinfo=_zone(tz_name))
    return aware.astimezone(timezone.utc).replace(tzinfo=None)


def shift_out_of_quiet_hours(when_utc: datetime,
                             tz_name: Optional[str] = DEFAULT_TIMEZONE) -> datetime:
    """First moment at or after *when_utc* outside the zone's quiet hours."""
    local = to_local(when_utc, tz_name)
    if local.hour >= QUIET_START_HOUR:
        release = (local + timedelta(days=1)).replace(
            hour=QUIET_END_HOUR, minute=0, second=0, microsecond=0)
    elif local.hour < QUIET_END_HOUR:
        release = local.replace(hour=QUIET_END_HOUR, minute=0, second=0, microsecond=0)
    else:
        return when_utc
    return _from_local(release, tz_name)


def next_suspension_run_at(expires_at: datetime) -> datetime:
    """The check_overdue_invoices run that will actually suspend this reseller."""
    run = expires_at.replace(hour=SUSPENSION_RUN_HOUR_UTC, minute=0,
                             second=0, microsecond=0)
    if run < expires_at:
        run += timedelta(days=1)
    return run


def reminder_send_at(expires_at: datetime, offset: timedelta,
                     tz_name: Optional[str] = DEFAULT_TIMEZONE) -> datetime:
    """When a stage's reminder should go out, after the quiet-hours hold."""
    return shift_out_of_quiet_hours(expires_at - offset, tz_name)


def _open_stages(already_sent: set[str]) -> list[tuple[str, timedelta]]:
    """Stages that can still go out: those shorter than every stage already sent."""
    open_stages: list[tuple[str, timedelta]] = []
    for stage, offset in reversed(STAGES):
        if stage in already_sent:
            break
        open_stages.insert(0, (stage, offset))
    return open_stages


def due_stage(expires_at: datetime, now: datetime, already_sent: set[str],
              tz_name: Optional[str] = DEFAULT_TIMEZONE) -> Optional[str]:
    """Which stage (if any) to send for this expiry right now.

    Picks the *shortest* remaining lead that is due and unsent, so a server that
    was down through an earlier window doesn't fire stages back to back — the
    reseller just gets the one accurate text.
    """
    if now >= next_suspension_run_at(expires_at):
        return None
    for stage, offset in reversed(_open_stages(already_sent)):
        if now >= reminder_send_at(expires_at, offset, tz_name):
            return stage
    return None


def next_planned(expires_at: datetime, now: datetime, already_sent: set[str],
                 tz_name: Optional[str] = DEFAULT_TIMEZONE
                 ) -> Optional[tuple[str, datetime]]:
    """(stage, send_at) of the next reminder this reseller will get, if any.

    A stage that is due now reports ``now``; the admin dashboard shows it as
    "sending now" and the next 10-minute scan picks it up.
    """
    if now >= next_suspension_run_at(expires_at):
        return None
    due = due_stage(expires_at, now, already_sent, tz_name)
    if due is not None:
        return due, now
    for stage, offset in _open_stages(already_sent):
        send_at = reminder_send_at(expires_at, offset, tz_name)
        if send_at > now:
            return stage, send_at
    return None


def humanize_lead(delta: timedelta) -> str:
    """'2 hours' / '23 hours' / '3 days' — rounded, for 'expires in about {x}'."""
    minutes = max(int(delta.total_seconds() // 60), 1)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = round(minutes / 60)
    if hours < 36:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = round(hours / 24)
    return f"{days} day{'s' if days != 1 else ''}"


# --------------------------------------------------------------------------
# Copy
# --------------------------------------------------------------------------

def _format_amount(amount: Optional[float], currency: Optional[str]) -> Optional[str]:
    if amount is None or amount <= 0:
        return None
    from app.services.subscription import format_money
    return format_money(amount, currency)


def render_reminder_sms(expires_at: datetime, now: datetime,
                        amount: Optional[float], currency: Optional[str] = "KES",
                        *, trial: bool = False) -> str:
    """The SMS body. Reads the real remaining time, so late sends stay truthful."""
    amt = _format_amount(amount, currency)
    expired = now >= expires_at
    template = _SMS[(trial, expired, amt is not None)]
    when = None if expired else humanize_lead(expires_at - now)
    return template.format(when=when, amount=amt)


def render_reminder_inbox(expires_at: datetime, now: datetime,
                          amount: Optional[float], currency: Optional[str] = "KES",
                          *, trial: bool = False,
                          tz_name: Optional[str] = DEFAULT_TIMEZONE) -> tuple[str, str]:
    """(subject, body) for the in-app copy — no segment budget, so spell it out."""
    local = to_local(expires_at, tz_name).strftime("%a %d %b at %I:%M%p").replace(" 0", " ")
    zone = zone_abbreviation(tz_name)
    amt = _format_amount(amount, currency)
    charge = amt or "your outstanding balance"
    what = "free trial" if trial else "subscription"
    if now >= expires_at:
        subject = f"Your {what} has {'ended' if trial else 'expired'}"
        opening = (
            f"Your Bitwave {what} {'ended' if trial else 'expired'} on {local} "
            f"{zone}. It has not been cut off yet, but the next billing run will "
            "suspend the account."
        )
    else:
        lead = humanize_lead(expires_at - now)
        verb = "ends" if trial else "expires"
        subject = f"{what.capitalize()} {verb} in about {lead}"
        opening = f"Your Bitwave {what} {verb} on {local} {zone}, in about {lead}."
    body = (
        f"{opening} Pay {charge} from the Subscription page to stay active.\n\n"
        "While an account is suspended your hotspot customers cannot buy "
        "internet either, so renewing early keeps your own sales running."
    )
    return subject, body


# --------------------------------------------------------------------------
# DB paths
# --------------------------------------------------------------------------

def _db_pool_too_busy() -> bool:
    try:
        pressure = (db_pool_snapshot().get("pressure") or {}).get("level")
    except Exception as exc:  # noqa: BLE001 - never fail reminders on telemetry
        logger.warning("Could not read DB pool pressure for subscription reminders: %s", exc)
        return False
    return pressure in {"warning", "critical"}


async def _outstanding(db, user_id: int) -> tuple[Optional[float], Optional[str]]:
    """(balance, currency) of the newest unpaid invoice, or (None, None)."""
    invoice = (await db.execute(
        select(SubscriptionInvoice)
        .where(SubscriptionInvoice.user_id == user_id,
               SubscriptionInvoice.status.in_([InvoiceStatus.PENDING,
                                               InvoiceStatus.OVERDUE]))
        .order_by(SubscriptionInvoice.created_at.desc())
        .limit(1)
    )).scalar_one_or_none()
    if invoice is None:
        return None, None
    from app.services.subscription import get_invoice_amount_paid
    paid = await get_invoice_amount_paid(db, invoice.id)
    return max(invoice.final_charge - paid, 0.0), invoice.currency


async def _sent_stages_by_user(db, keys: list[tuple[int, datetime]]
                               ) -> dict[tuple[int, datetime], dict[str, datetime]]:
    """{(user_id, expires_at): {stage: sent_at}} for every key, in one query."""
    if not keys:
        return {}
    user_ids = {user_id for user_id, _ in keys}
    rows = (await db.execute(
        select(SubscriptionExpiryReminder.user_id,
               SubscriptionExpiryReminder.expires_at,
               SubscriptionExpiryReminder.stage,
               SubscriptionExpiryReminder.created_at)
        .where(SubscriptionExpiryReminder.user_id.in_(user_ids))
    )).all()
    wanted = set(keys)
    out: dict[tuple[int, datetime], dict[str, datetime]] = {k: {} for k in keys}
    for user_id, expires_at, stage, created_at in rows:
        if (user_id, expires_at) in wanted:
            out[(user_id, expires_at)][stage] = created_at
    return out


def _is_trial(status) -> bool:
    return status == SubscriptionStatus.TRIAL


async def send_expiry_reminder(user_id: int, stage: str, expires_at: datetime,
                               now: Optional[datetime] = None) -> Optional[dict]:
    """Create the reminder rows for one reseller in one short session.

    Returns ``{"sms_id": int | None}`` when a reminder was created (``sms_id`` is
    None for an inbox-only reminder, e.g. no phone on file), or None when the
    send was skipped. Never raises.
    """
    now = now or datetime.utcnow()
    try:
        async with database.async_session() as db:
            user = await db.get(User, user_id)
            if user is None or user.role != UserRole.RESELLER:
                return None
            # Re-check under the session: they may have paid since the scan.
            if user.subscription_expires_at != expires_at:
                return None
            if user.subscription_status not in (SubscriptionStatus.ACTIVE,
                                                SubscriptionStatus.TRIAL):
                return None

            phone = (user.support_phone or "").strip() or None

            # The unique constraint is the real guard against a double send.
            claim = SubscriptionExpiryReminder(
                user_id=user_id, stage=stage, expires_at=expires_at, phone=phone)
            db.add(claim)
            try:
                await db.flush()
            except IntegrityError:
                await db.rollback()
                logger.debug("Subscription reminder %s already sent for user %s",
                             stage, user_id)
                return None

            trial = _is_trial(user.subscription_status)
            tz_name = reseller_market(user).timezone
            amount, currency = await _outstanding(db, user_id)
            settings_row = await db.get(MessagingSettings, 1)
            messaging_enabled = bool(settings_row.enabled) if settings_row else True
            send_sms = bool(phone) and messaging_enabled

            sms_id = None
            if send_sms:
                body = render_reminder_sms(expires_at, now, amount, currency, trial=trial)
                segments = count_segments(body)
                sms = SmsMessage(
                    user_id=user_id,
                    recipient_phone=phone,
                    body=body,
                    segments=segments,
                    credits_charged=segments,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER,
                    category=REMINDER_CATEGORY,
                    status=SmsMessageStatus.QUEUED,
                )
                db.add(sms)
                await db.flush()
                sms_id = sms.id
                claim.sms_message_id = sms_id

            sender_admin_id = await _resolve_sender_admin_id(db, user)
            if sender_admin_id is not None:
                subject, inbox_body = render_reminder_inbox(
                    expires_at, now, amount, currency, trial=trial, tz_name=tz_name)
                db.add(ResellerInboxMessage(
                    recipient_user_id=user_id,
                    sender_user_id=sender_admin_id,
                    subject=subject,
                    body=inbox_body,
                    sent_sms=send_sms,
                ))
                claim.inbox_sent = True
            else:
                logger.warning(
                    "No admin user found; subscription reminder inbox skipped for user %s",
                    user_id)

            await db.commit()
            logger.info(
                "Subscription reminder queued: user=%s stage=%s expires=%s sms=%s",
                user_id, stage, expires_at, sms_id,
            )
            return {"sms_id": sms_id}
    except Exception:
        logger.exception("Subscription reminder failed for user %s (stage %s)",
                         user_id, stage)
        return None


def _candidates_query(now: datetime, horizon: timedelta):
    return select(User.id, User.subscription_expires_at, User.market_code).where(
        User.role == UserRole.RESELLER,
        User.subscription_status.in_([SubscriptionStatus.ACTIVE,
                                      SubscriptionStatus.TRIAL]),
        User.subscription_expires_at.isnot(None),
        User.subscription_expires_at <= now + horizon,
        # Past expiry we keep going only until the suspension run (< 1 day).
        User.subscription_expires_at >= now - timedelta(days=1),
    )


async def send_due_subscription_reminders(now: Optional[datetime] = None) -> dict:
    """Scheduler entry: text every reseller whose subscription is about to lapse.

    Candidates are read in one short session; each reminder then claims, writes
    and commits in its own short session, and the provider send happens after
    all sessions are closed.
    """
    now = now or datetime.utcnow()
    result = {"candidates": 0, "sent": 0, "sms_queued": 0, "skipped": 0}

    if _db_pool_too_busy():
        logger.info("Skipping subscription reminders: DB pool under pressure")
        result["skipped"] = 1
        return result

    try:
        async with database.async_session() as db:
            settings_row = await db.get(MessagingSettings, 1)
            if settings_row is not None and not settings_row.subscription_reminders_enabled:
                logger.debug("Subscription reminders disabled in settings")
                return result

            longest_lead = max(offset for _, offset in STAGES)
            rows = (await db.execute(_candidates_query(now, longest_lead))).all()
            sent = await _sent_stages_by_user(
                db, [(user_id, expires_at) for user_id, expires_at, _ in rows])

            due: list[tuple[int, str, datetime]] = []
            for user_id, expires_at, market_code in rows:
                tz_name = reseller_market(_MarketOnly(market_code)).timezone
                stage = due_stage(expires_at, now, set(sent[(user_id, expires_at)]), tz_name)
                if stage is not None:
                    due.append((user_id, stage, expires_at))
    except Exception:
        logger.exception("Subscription reminder scan could not list candidates")
        return result
    # --- Scan session closed; per-reminder sessions below are short and separate ---

    result["candidates"] = len(due)
    sms_ids: list[int] = []
    for user_id, stage, expires_at in due:
        outcome = await send_expiry_reminder(user_id, stage, expires_at, now=now)
        if outcome is None:
            continue
        result["sent"] += 1
        if outcome["sms_id"] is not None:
            sms_ids.append(outcome["sms_id"])
    result["sms_queued"] = len(sms_ids)

    if sms_ids:
        # No DB session held: dispatch opens its own short sessions around the
        # provider call. No owner_user_id: these go out on the platform
        # gateway, never a reseller's own.
        from app.services.messaging import resolve_sender_id
        from app.services.sms_dispatch import dispatch_admin_sms_messages
        async with database.async_session() as db:
            settings_row = await db.get(MessagingSettings, 1)
            configured = settings_row.sender_id if settings_row else None
        await dispatch_admin_sms_messages(sms_ids, resolve_sender_id(configured))

    if due:
        logger.info(
            "Subscription reminders: %s candidate(s), %s sent, %s SMS queued",
            len(due), result["sent"], len(sms_ids),
        )
    return result


class _MarketOnly:
    """Just enough of a User for reseller_market() when only market_code is loaded."""

    def __init__(self, market_code: Optional[str]):
        self.market_code = market_code


# --------------------------------------------------------------------------
# Admin dashboard
# --------------------------------------------------------------------------

def _sms_state(reminder_sms_id: Optional[int], phone: Optional[str],
               sms: Optional[SmsMessage]) -> tuple[str, Optional[str]]:
    """(state, error) of the SMS half of a reminder, for the dashboard."""
    if reminder_sms_id is None:
        return ("no_phone" if not phone else "not_sent"), None
    if sms is None:
        # Sent rows are pruned after messaging_settings.message_retention_days;
        # only SENT/DELIVERED rows are ever pruned.
        return "sent", None
    return sms.status.value if hasattr(sms.status, "value") else str(sms.status), sms.error


async def reminder_overview(db, *, days: int = 7, recent_limit: int = 100,
                            now: Optional[datetime] = None) -> dict:
    """Everything the admin dashboard shows. Read-only, one short session."""
    now = now or datetime.utcnow()
    settings_row = await db.get(MessagingSettings, 1)
    enabled = bool(settings_row.subscription_reminders_enabled) if settings_row else True

    horizon = timedelta(days=days)
    users = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([SubscriptionStatus.ACTIVE,
                                          SubscriptionStatus.TRIAL]),
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at <= now + horizon,
            User.subscription_expires_at >= now - timedelta(days=1),
        ).order_by(User.subscription_expires_at.asc())
    )).scalars().all()
    users = [u for u in users if now < next_suspension_run_at(u.subscription_expires_at)]
    sent = await _sent_stages_by_user(db, [(u.id, u.subscription_expires_at) for u in users])

    upcoming = []
    for u in users:
        tz_name = reseller_market(u).timezone
        stages_sent = sent[(u.id, u.subscription_expires_at)]
        planned = next_planned(u.subscription_expires_at, now, set(stages_sent), tz_name)
        status = u.subscription_status.value if hasattr(u.subscription_status, "value") \
            else str(u.subscription_status)
        upcoming.append({
            "reseller_id": u.id,
            "organization_name": u.organization_name,
            "email": u.email,
            "phone": (u.support_phone or "").strip() or None,
            "subscription_status": status,
            "market": u.market_code,
            "subscription_expires_at": u.subscription_expires_at.isoformat(),
            "hours_until_expiry": round((u.subscription_expires_at - now).total_seconds() / 3600, 1),
            "stages_sent": [
                {"stage": s, "label": STAGE_LABELS.get(s, s), "sent_at": at.isoformat() if at else None}
                for s, at in sorted(stages_sent.items(), key=lambda kv: kv[1] or now)
            ],
            "next_stage": planned[0] if planned else None,
            "next_stage_label": STAGE_LABELS.get(planned[0]) if planned else None,
            "next_send_at": planned[1].isoformat() if planned else None,
        })

    recent_rows = (await db.execute(
        select(SubscriptionExpiryReminder, User, SmsMessage)
        .join(User, User.id == SubscriptionExpiryReminder.user_id)
        .outerjoin(SmsMessage, SmsMessage.id == SubscriptionExpiryReminder.sms_message_id)
        .order_by(SubscriptionExpiryReminder.created_at.desc(),
                  SubscriptionExpiryReminder.id.desc())
        .limit(recent_limit)
    )).all()
    recent = []
    for reminder, user, sms in recent_rows:
        sms_state, sms_error = _sms_state(reminder.sms_message_id, reminder.phone, sms)
        recent.append({
            "id": reminder.id,
            "reseller_id": user.id,
            "organization_name": user.organization_name,
            "email": user.email,
            "stage": reminder.stage,
            "stage_label": STAGE_LABELS.get(reminder.stage, reminder.stage),
            "subscription_expires_at": reminder.expires_at.isoformat(),
            "sent_at": reminder.created_at.isoformat() if reminder.created_at else None,
            "phone": reminder.phone,
            "sms_status": sms_state,
            "sms_error": sms_error,
            "inbox_sent": bool(reminder.inbox_sent),
        })

    # Counted separately from `recent`, which is capped for display.
    week_rows = (await db.execute(
        select(SubscriptionExpiryReminder.sms_message_id,
               SubscriptionExpiryReminder.phone, SmsMessage)
        .outerjoin(SmsMessage, SmsMessage.id == SubscriptionExpiryReminder.sms_message_id)
        .where(SubscriptionExpiryReminder.created_at >= now - timedelta(days=7))
    )).all()
    week_states = [_sms_state(sms_id, phone, sms)[0] for sms_id, phone, sms in week_rows]
    summary = {
        "upcoming": len(upcoming),
        "upcoming_without_phone": sum(1 for u in upcoming if not u["phone"]),
        "sent_last_7_days": len(week_states),
        "sms_sent_last_7_days": sum(1 for s in week_states if s in ("sent", "delivered")),
        "sms_failed_last_7_days": sum(1 for s in week_states if s == "failed"),
        "sms_pending_last_7_days": sum(1 for s in week_states if s == "queued"),
        "inbox_only_last_7_days": sum(1 for s in week_states if s in ("no_phone", "not_sent")),
    }

    return {
        "enabled": enabled,
        "days": days,
        "generated_at": now.isoformat(),
        "stages": [{"stage": s, "label": STAGE_LABELS[s], "hours_before": int(o.total_seconds() // 3600)}
                   for s, o in STAGES],
        "summary": summary,
        "upcoming": upcoming,
        "recent": recent,
    }

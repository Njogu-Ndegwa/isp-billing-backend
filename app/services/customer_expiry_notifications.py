"""Automatic customer SMS after an expired subscription is enforced.

The expiry cleanup job calls this service only after the customer has been
successfully disconnected and committed as INACTIVE.  Messages use the same
campaign, credit, provider, history, and refund path as reseller-authored SMS.

Database work is committed before dispatch is spawned; provider I/O therefore
never runs while a cleanup transaction is open.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import (
    Customer,
    CustomerExpirySmsSettings,
    CustomerStatus,
    MessagingSettings,
    SmsCampaign,
    SmsCampaignStatus,
    SmsCreditAccount,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
    User,
)
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments, resolve_sender_id

logger = logging.getLogger(__name__)

EXPIRY_CATEGORY_PREFIX = "customer_expiry:"
REMINDER_CATEGORY_PREFIX = "expiry_rem:"
DEFAULT_REMINDER_OFFSETS_MINUTES = (1440,)
MIN_REMINDER_OFFSET_MINUTES = 30
MAX_REMINDER_OFFSET_MINUTES = 30 * 24 * 60
MAX_REMINDER_OFFSETS = 5


def expiry_message_category(expiry: datetime) -> str:
    """Stable key for one customer's one paid period (fits VARCHAR(40))."""
    return f"{EXPIRY_CATEGORY_PREFIX}{expiry.strftime('%Y%m%d%H%M%S')}"


def render_expiry_message(organization_name: str | None) -> str:
    brand = (organization_name or "Your internet provider").strip()
    return (
        "Your internet package has expired. Please renew to restore service. "
        f"- {brand}"
    )


def reminder_message_category(expiry: datetime, offset_minutes: int) -> str:
    """Stable key for one reminder in one paid period (fits VARCHAR(40))."""
    return (
        f"{REMINDER_CATEGORY_PREFIX}"
        f"{expiry.strftime('%Y%m%d%H%M%S')}:{offset_minutes}"
    )


def render_reminder_message(organization_name: str | None) -> str:
    brand = (organization_name or "Your internet provider").strip()
    return (
        "Reminder: Your internet package will expire soon. "
        f"Please renew to avoid disconnection. - {brand}"
    )


def _phone_key(phone: str) -> str:
    return "".join(ch for ch in phone if ch.isdigit())


async def _create_campaign(
    db,
    *,
    reseller_id: int,
    recipients: list[tuple[int, str, str]],
    body: str,
    settings_row: MessagingSettings | None,
    credit_note: str,
) -> int | None:
    """Persist one credit-backed campaign. Caller owns the session."""
    segments = count_segments(body)
    total_credits = segments * len(recipients)
    sender_id = resolve_sender_id(
        settings_row.sender_id if settings_row else None
    )

    campaign = SmsCampaign(
        user_id=reseller_id,
        body=body,
        recipient_count=len(recipients),
        segments_per_message=segments,
        total_credits=total_credits,
        sender_id=sender_id,
        status=SmsCampaignStatus.QUEUED,
    )
    db.add(campaign)
    await db.flush()

    if not await sms_credits.try_deduct(
        db,
        reseller_id,
        total_credits,
        reference=f"campaign:{campaign.id}",
        note=credit_note,
    ):
        await db.rollback()
        logger.info(
            "Customer expiry SMS skipped: reseller %s needs %s credit(s)",
            reseller_id,
            total_credits,
        )
        return None

    for customer_id, phone, category in recipients:
        db.add(
            SmsMessage(
                campaign_id=campaign.id,
                user_id=reseller_id,
                customer_id=customer_id,
                recipient_phone=phone,
                body=body,
                segments=segments,
                credits_charged=segments,
                kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                status=SmsMessageStatus.QUEUED,
                category=category,
            )
        )
    await db.commit()
    logger.info(
        "Queued automatic expiry campaign %s for reseller %s: recipients=%s credits=%s",
        campaign.id,
        reseller_id,
        len(recipients),
        total_credits,
    )
    return campaign.id


async def _queue_reseller_expired_campaign(
    reseller_id: int,
    customer_ids: list[int],
    *,
    session_factory: Callable,
    now: datetime,
) -> int | None:
    """Queue one expiry campaign for one reseller, or return None when skipped."""
    async with session_factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        if settings_row is not None and not settings_row.enabled:
            return None

        preferences = await db.get(CustomerExpirySmsSettings, reseller_id)
        if (
            preferences is None
            or not preferences.enabled
            or not preferences.send_at_expiry
        ):
            return None

        reseller = await db.get(User, reseller_id)
        if reseller is None:
            return None

        rows = (
            await db.execute(
                select(Customer.id, Customer.phone, Customer.expiry)
                .where(
                    Customer.id.in_(customer_ids),
                    Customer.user_id == reseller_id,
                    Customer.status == CustomerStatus.INACTIVE,
                    Customer.expiry.isnot(None),
                    Customer.expiry <= now,
                    Customer.phone.isnot(None),
                    Customer.subscription_owner_id.is_(None),
                )
                .order_by(Customer.id)
            )
        ).all()
        if not rows:
            return None

        existing = set(
            (
                await db.execute(
                    select(SmsMessage.customer_id, SmsMessage.category).where(
                        SmsMessage.customer_id.in_([row.id for row in rows]),
                        SmsMessage.category.like(f"{EXPIRY_CATEGORY_PREFIX}%"),
                    )
                )
            ).all()
        )

        recipients: list[tuple[int, str, str]] = []
        seen_phones: set[str] = set()
        for row in rows:
            phone = (row.phone or "").strip()
            phone_key = _phone_key(phone)
            category = expiry_message_category(row.expiry)
            if not phone_key or phone_key in seen_phones:
                continue
            if (row.id, category) in existing:
                continue
            seen_phones.add(phone_key)
            recipients.append((row.id, phone, category))

        if not recipients:
            return None

        return await _create_campaign(
            db,
            reseller_id=reseller_id,
            recipients=recipients,
            body=render_expiry_message(
                reseller.business_name or reseller.organization_name
            ),
            settings_row=settings_row,
            credit_note="Automatic customer expiry notifications",
        )


async def queue_customer_expiry_notifications(
    customer_ids: list[int],
    *,
    session_factory: Callable | None = None,
    now: datetime | None = None,
) -> list[int]:
    """Queue campaigns for newly deactivated customers and return their ids."""
    if not customer_ids or not settings.SMS_DISPATCH_ENABLED:
        return []

    factory = session_factory or database.async_session
    now = now or datetime.utcnow()
    unique_ids = sorted(set(customer_ids))

    async with factory() as db:
        reseller_ids = (
            await db.execute(
                select(Customer.user_id)
                .where(
                    Customer.id.in_(unique_ids),
                    Customer.user_id.isnot(None),
                )
                .distinct()
            )
        ).scalars().all()

    campaign_ids: list[int] = []
    for reseller_id in reseller_ids:
        campaign_id = await _queue_reseller_expired_campaign(
            reseller_id,
            unique_ids,
            session_factory=factory,
            now=now,
        )
        if campaign_id is not None:
            campaign_ids.append(campaign_id)
    return campaign_ids


def _valid_offsets(raw_offsets) -> list[int]:
    return sorted(
        {
            int(value) for value in (raw_offsets or [])
            if isinstance(value, int)
            and MIN_REMINDER_OFFSET_MINUTES
            <= value
            <= MAX_REMINDER_OFFSET_MINUTES
        },
        reverse=True,
    )[:MAX_REMINDER_OFFSETS]


async def collect_due_reminder_groups(
    *,
    session_factory: Callable,
    now: datetime,
) -> dict[tuple[int, int], list[int]]:
    """Return due customer ids grouped by (reseller, offset) in 2-4 reads.

    This is the steady-state polling path. It performs one fleet customer query,
    regardless of how many resellers or reminder offsets are enabled. Resellers
    without a positive SMS balance are excluded because no campaign could be
    queued for them; they become eligible automatically after a top-up.
    """
    async with session_factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        if settings_row is not None and not settings_row.enabled:
            return {}

        preference_rows = (
            await db.execute(
                select(
                    CustomerExpirySmsSettings.user_id,
                    CustomerExpirySmsSettings.reminder_offsets_minutes,
                )
                .join(
                    SmsCreditAccount,
                    SmsCreditAccount.user_id == CustomerExpirySmsSettings.user_id,
                )
                .where(
                    CustomerExpirySmsSettings.enabled.is_(True),
                    SmsCreditAccount.balance > 0,
                )
            )
        ).all()
        offsets_by_reseller = {
            user_id: offsets
            for user_id, raw_offsets in preference_rows
            if (offsets := _valid_offsets(raw_offsets))
        }
        if not offsets_by_reseller:
            return {}

        max_offset = max(
            offset
            for offsets in offsets_by_reseller.values()
            for offset in offsets
        )
        customer_rows = (
            await db.execute(
                select(
                    Customer.id,
                    Customer.user_id,
                    Customer.phone,
                    Customer.expiry,
                )
                .where(
                    Customer.user_id.in_(offsets_by_reseller),
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry.isnot(None),
                    Customer.expiry > now,
                    Customer.expiry <= now + timedelta(minutes=max_offset),
                    Customer.phone.isnot(None),
                    Customer.subscription_owner_id.is_(None),
                )
                .order_by(Customer.user_id, Customer.id)
            )
        ).all()
        if not customer_rows:
            return {}

        existing = set(
            (
                await db.execute(
                    select(SmsMessage.customer_id, SmsMessage.category).where(
                        SmsMessage.customer_id.in_([row.id for row in customer_rows]),
                        SmsMessage.category.like(f"{REMINDER_CATEGORY_PREFIX}%"),
                    )
                )
            ).all()
        )

    groups: dict[tuple[int, int], list[int]] = {}
    seen_phones: dict[tuple[int, int], set[str]] = {}
    for row in customer_rows:
        phone_key = _phone_key((row.phone or "").strip())
        if not phone_key:
            continue
        for offset_minutes in offsets_by_reseller[row.user_id]:
            if row.expiry > now + timedelta(minutes=offset_minutes):
                continue
            category = reminder_message_category(row.expiry, offset_minutes)
            if (row.id, category) in existing:
                continue
            group_key = (row.user_id, offset_minutes)
            group_phone_keys = seen_phones.setdefault(group_key, set())
            if phone_key in group_phone_keys:
                continue
            group_phone_keys.add(phone_key)
            groups.setdefault(group_key, []).append(row.id)
    return groups


async def _queue_reseller_reminder_campaign(
    reseller_id: int,
    offset_minutes: int,
    customer_ids: list[int],
    *,
    session_factory: Callable,
    now: datetime,
) -> int | None:
    """Queue one due pre-expiry reminder campaign for one reseller/offset."""
    async with session_factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        if settings_row is not None and not settings_row.enabled:
            return None

        preferences = await db.get(CustomerExpirySmsSettings, reseller_id)
        configured_offsets = set(
            preferences.reminder_offsets_minutes or []
        ) if preferences else set()
        if (
            preferences is None
            or not preferences.enabled
            or offset_minutes not in configured_offsets
        ):
            return None

        reseller = await db.get(User, reseller_id)
        if reseller is None:
            return None

        rows = (
            await db.execute(
                select(Customer.id, Customer.phone, Customer.expiry)
                .where(
                    Customer.id.in_(customer_ids),
                    Customer.user_id == reseller_id,
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry.isnot(None),
                    Customer.expiry > now,
                    Customer.expiry <= now + timedelta(minutes=offset_minutes),
                    Customer.phone.isnot(None),
                    Customer.subscription_owner_id.is_(None),
                )
                .order_by(Customer.id)
            )
        ).all()
        if not rows:
            return None

        existing = set(
            (
                await db.execute(
                    select(SmsMessage.customer_id, SmsMessage.category).where(
                        SmsMessage.customer_id.in_([row.id for row in rows]),
                        SmsMessage.category.like(f"{REMINDER_CATEGORY_PREFIX}%"),
                    )
                )
            ).all()
        )

        recipients: list[tuple[int, str, str]] = []
        seen_phones: set[str] = set()
        for row in rows:
            phone = (row.phone or "").strip()
            phone_key = _phone_key(phone)
            category = reminder_message_category(row.expiry, offset_minutes)
            if not phone_key or phone_key in seen_phones:
                continue
            if (row.id, category) in existing:
                continue
            seen_phones.add(phone_key)
            recipients.append((row.id, phone, category))

        if not recipients:
            return None

        return await _create_campaign(
            db,
            reseller_id=reseller_id,
            recipients=recipients,
            body=render_reminder_message(
                reseller.business_name or reseller.organization_name
            ),
            settings_row=settings_row,
            credit_note=(
                "Automatic customer pre-expiry reminder "
                f"({offset_minutes} minutes before expiry)"
            ),
        )


async def scan_customer_expiry_reminders(now: datetime | None = None) -> int:
    """Queue and dispatch all due opt-in pre-expiry reminders."""
    if not settings.SMS_DISPATCH_ENABLED:
        return 0
    try:
        pressure = (
            database.db_pool_snapshot().get("pressure") or {}
        ).get("level")
    except Exception:
        pressure = None
    if pressure in {"warning", "critical"}:
        logger.info(
            "Skipping customer expiry reminder scan: DB pool pressure=%s",
            pressure,
        )
        return 0

    now = now or datetime.utcnow()
    groups = await collect_due_reminder_groups(
        session_factory=database.async_session,
        now=now,
    )

    campaign_ids: list[int] = []
    for (reseller_id, offset_minutes), customer_ids in groups.items():
        campaign_id = await _queue_reseller_reminder_campaign(
            reseller_id,
            offset_minutes,
            customer_ids,
            session_factory=database.async_session,
            now=now,
        )
        if campaign_id is not None:
            campaign_ids.append(campaign_id)

    spawn_expiry_campaign_dispatch(campaign_ids)
    if campaign_ids:
        logger.info(
            "Customer expiry reminder scan queued %s campaign(s)",
            len(campaign_ids),
        )
    return len(campaign_ids)


_dispatch_tasks: set[asyncio.Task] = set()


def spawn_expiry_campaign_dispatch(campaign_ids: list[int]) -> None:
    """Dispatch committed campaigns without delaying the expiry cleanup job."""
    for campaign_id in campaign_ids:
        try:
            task = asyncio.create_task(sms_dispatch.dispatch_campaign(campaign_id))
        except RuntimeError:
            logger.warning(
                "No running event loop; expiry campaign %s remains queued",
                campaign_id,
            )
            continue
        _dispatch_tasks.add(task)
        task.add_done_callback(_dispatch_tasks.discard)

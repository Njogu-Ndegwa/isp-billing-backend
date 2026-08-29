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
from datetime import datetime

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import (
    Customer,
    CustomerStatus,
    MessagingSettings,
    SmsCampaign,
    SmsCampaignStatus,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
    User,
)
from app.services import sms_credits, sms_dispatch
from app.services.messaging import count_segments, resolve_sender_id

logger = logging.getLogger(__name__)

EXPIRY_CATEGORY_PREFIX = "customer_expiry:"


def expiry_message_category(expiry: datetime) -> str:
    """Stable key for one customer's one paid period (fits VARCHAR(40))."""
    return f"{EXPIRY_CATEGORY_PREFIX}{expiry.strftime('%Y%m%d%H%M%S')}"


def render_expiry_message(organization_name: str | None) -> str:
    brand = (organization_name or "Your internet provider").strip()
    return (
        "Your internet package has expired. Please renew to restore service. "
        f"- {brand}"
    )


def _phone_key(phone: str) -> str:
    return "".join(ch for ch in phone if ch.isdigit())


async def _queue_reseller_campaign(
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

        body = render_expiry_message(
            reseller.business_name or reseller.organization_name
        )
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
            note="Automatic customer expiry notifications",
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
        campaign_id = await _queue_reseller_campaign(
            reseller_id,
            unique_ids,
            session_factory=factory,
            now=now,
        )
        if campaign_id is not None:
            campaign_ids.append(campaign_id)
    return campaign_ids


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

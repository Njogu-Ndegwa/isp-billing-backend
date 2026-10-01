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

from sqlalchemy import or_, select

from app.config import settings
from app.db import database
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerExpirySmsSettings,
    CustomerStatus,
    DurationUnit,
    MessagingProviderAccount,
    MessagingSettings,
    Plan,
    PortalSettings,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    Router,
    SmsCampaign,
    SmsCampaignStatus,
    SmsCreditAccount,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
    User,
)
from app.services import customer_sms_templates as templates
from app.services import sms_credits, sms_dispatch
from app.services.markets import reseller_market
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import count_segments

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


def render_expiry_message(
    organization_name: str | None,
    *,
    paybill_number: str | None = None,
    account_number: str | None = None,
) -> str:
    """The built-in expiry wording (kept for callers that have no context)."""
    return templates.default_expiry({
        "brand": (organization_name or "Your internet provider").strip(),
        "paybill": (paybill_number or "").strip(),
        "account": (account_number or "").strip(),
    })


def reminder_message_category(expiry: datetime, offset_minutes: int) -> str:
    """Stable key for one reminder in one paid period (fits VARCHAR(40))."""
    return (
        f"{REMINDER_CATEGORY_PREFIX}"
        f"{expiry.strftime('%Y%m%d%H%M%S')}:{offset_minutes}"
    )


def render_reminder_message(
    organization_name: str | None,
    *,
    paybill_number: str | None = None,
    account_number: str | None = None,
) -> str:
    """The built-in reminder wording (kept for callers that have no context)."""
    return templates.default_reminder({
        "brand": (organization_name or "Your internet provider").strip(),
        "paybill": (paybill_number or "").strip(),
        "account": (account_number or "").strip(),
    })


def _phone_key(phone: str) -> str:
    return "".join(ch for ch in phone if ch.isdigit())


def is_textable_phone(phone: str | None) -> bool:
    """A number an SMS gateway can deliver to (not a MAC or placeholder)."""
    digits = _phone_key(phone or "")
    return 9 <= len(digits) <= 15


# ---------------------------------------------------------------------------
# Reseller context shared by every automatic customer message
# ---------------------------------------------------------------------------

async def reseller_support_phone(db, reseller: User) -> str | None:
    portal_phone = (
        await db.execute(
            select(PortalSettings.portal_support_phone).where(
                PortalSettings.user_id == reseller.id
            )
        )
    ).scalar_one_or_none()
    return portal_phone or reseller.support_phone


async def resolve_paybills(
    db, reseller: User, router_ids
) -> dict[int | None, str | None]:
    """Which paybill a customer on each router should pay into.

    The account-number paybill flow is M-Pesa C2B, so outside Kenya there is
    none to advertise. A reseller who registered their own paybill for C2B is
    paid there; everyone else is paid on the platform paybill, which routes
    the payment by the customer's account number.
    """
    router_ids = set(router_ids)
    if reseller_market(reseller).code != "KE":
        return {router_id: None for router_id in router_ids}

    own: dict[int, str] = {}
    known = [router_id for router_id in router_ids if router_id]
    if known:
        rows = (
            await db.execute(
                select(Router.id, ResellerPaymentMethod.mpesa_shortcode)
                .join(
                    ResellerPaymentMethod,
                    Router.payment_method_id == ResellerPaymentMethod.id,
                )
                .where(
                    Router.id.in_(known),
                    Router.user_id == reseller.id,
                    ResellerPaymentMethod.is_active.is_(True),
                    ResellerPaymentMethod.method_type
                    == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
                    ResellerPaymentMethod.c2b_registered_at.isnot(None),
                    ResellerPaymentMethod.mpesa_shortcode.isnot(None),
                )
            )
        ).all()
        own = {router_id: shortcode for router_id, shortcode in rows if shortcode}
    return {
        router_id: own.get(router_id) or settings.MPESA_SHORTCODE
        for router_id in router_ids
    }


async def create_customer_campaign(
    db,
    *,
    reseller_id: int,
    recipients: list[tuple[int, str, str, str]],
    body: str,
    settings_row: MessagingSettings | None,
    credit_note: str,
) -> int | None:
    """Persist one credit-backed campaign. Caller owns the session.

    `recipients` is [(customer_id, phone, category, message body)]. Returns
    None, with the session rolled back, when the reseller cannot pay for it.
    """
    message_segments = [count_segments(recipient[3]) for recipient in recipients]
    segments = max(message_segments)
    # Segments are a property of the message; credits are what we bill for it.
    # A reseller on their own gateway pays their vendor, so the credit cost is
    # zero while the segment counts stay accurate.
    bills_credits = await provider_accounts.bills_platform_credits(db, reseller_id)
    message_credits = message_segments if bills_credits else [0] * len(message_segments)
    total_credits = sum(message_credits)
    sender_id = await provider_accounts.resolve_sender_id_for(
        db, reseller_id, settings_row.sender_id if settings_row else None
    )

    campaign = SmsCampaign(
        user_id=reseller_id,
        body=body[:1000],
        recipient_count=len(recipients),
        segments_per_message=segments,
        total_credits=total_credits,
        sender_id=sender_id,
        status=SmsCampaignStatus.QUEUED,
    )
    db.add(campaign)
    await db.flush()

    if bills_credits and not await sms_credits.try_deduct(
        db,
        reseller_id,
        total_credits,
        reference=f"campaign:{campaign.id}",
        note=credit_note,
    ):
        await db.rollback()
        logger.info(
            "Automatic customer SMS skipped (%s): reseller %s needs %s credit(s)",
            credit_note,
            reseller_id,
            total_credits,
        )
        return None

    for (customer_id, phone, category, message_body), segments_for_message, credits_for_message in zip(
        recipients, message_segments, message_credits
    ):
        db.add(
            SmsMessage(
                campaign_id=campaign.id,
                user_id=reseller_id,
                customer_id=customer_id,
                recipient_phone=phone,
                body=message_body[:1000],
                segments=segments_for_message,
                credits_charged=credits_for_message,
                kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                status=SmsMessageStatus.QUEUED,
                category=category,
            )
        )
    await db.commit()
    logger.info(
        "Queued automatic customer campaign %s (%s) for reseller %s: "
        "recipients=%s credits=%s",
        campaign.id,
        credit_note,
        reseller_id,
        len(recipients),
        total_credits,
    )
    return campaign.id


def _customer_message_columns():
    return (
        Customer.id,
        Customer.phone,
        Customer.expiry,
        Customer.account_number,
        Customer.name,
        Customer.router_id,
        Plan.connection_type,
        Plan.name.label("plan_name"),
    )


async def _queue_expiry_style_campaign(
    db,
    *,
    reseller: User,
    preferences: CustomerExpirySmsSettings,
    rows,
    event: str,
    category_for,
    category_prefix: str,
    settings_row: MessagingSettings | None,
    credit_note: str,
) -> int | None:
    """Render and queue the expiry or reminder message for `rows`.

    `rows` come from `_customer_message_columns()`. Customers already sent
    this period's message, and a second customer on the same phone, are
    skipped.
    """
    existing = set(
        (
            await db.execute(
                select(SmsMessage.customer_id, SmsMessage.category).where(
                    SmsMessage.customer_id.in_([row.id for row in rows]),
                    SmsMessage.category.like(f"{category_prefix}%"),
                )
            )
        ).all()
    )

    custom = templates.custom_template(preferences.custom_templates, event)
    tz_name = reseller_market(reseller).timezone
    support_phone = await reseller_support_phone(db, reseller)
    paybills = await resolve_paybills(db, reseller, {row.router_id for row in rows})

    recipients: list[tuple[int, str, str, str]] = []
    seen_phones: set[str] = set()
    uses_paybill = False
    for row in rows:
        phone = (row.phone or "").strip()
        phone_key = _phone_key(phone)
        category = category_for(row)
        if not is_textable_phone(phone) or phone_key in seen_phones:
            continue
        if (row.id, category) in existing:
            continue
        seen_phones.add(phone_key)
        # The account-number paybill only works for PPPoE: a hotspot payment
        # needs the device on the portal to bind its MAC.
        payment_account = (
            row.account_number
            if row.connection_type == ConnectionType.PPPOE
            else None
        )
        paybill = paybills.get(row.router_id) if payment_account else None
        uses_paybill = uses_paybill or bool(payment_account and paybill)
        context = templates.build_context(
            reseller=reseller,
            tz_name=tz_name,
            customer_name=row.name,
            plan_name=row.plan_name,
            expiry=row.expiry,
            account_number=payment_account,
            paybill=paybill,
            support_phone=support_phone,
        )
        recipients.append((
            row.id,
            phone,
            category,
            templates.render(event, context, preferences.custom_templates),
        ))

    if not recipients:
        return None

    # The campaign row is what the reseller sees in their message history.
    if custom is not None:
        summary = custom
    else:
        summary = templates.render(event, templates.build_context(
            reseller=reseller,
            tz_name=tz_name,
            account_number="[customer account]" if uses_paybill else None,
            paybill=settings.MPESA_SHORTCODE if uses_paybill else None,
        ))

    return await create_customer_campaign(
        db,
        reseller_id=reseller.id,
        recipients=recipients,
        body=summary,
        settings_row=settings_row,
        credit_note=credit_note,
    )


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
                select(*_customer_message_columns())
                .outerjoin(Plan, Customer.plan_id == Plan.id)
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

        return await _queue_expiry_style_campaign(
            db,
            reseller=reseller,
            preferences=preferences,
            rows=rows,
            event=templates.EVENT_EXPIRY,
            category_for=lambda row: expiry_message_category(row.expiry),
            category_prefix=EXPIRY_CATEGORY_PREFIX,
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


def can_pay_for_sms_clause(user_id_column):
    """SQL: the reseller can pay for an automatic SMS right now.

    Either they have platform credits, or they send on their own gateway and
    are not billed credits at all (`accounts.bills_platform_credits`). The
    caller must outer-join SmsCreditAccount on the reseller.
    """
    own_gateway = (
        select(MessagingProviderAccount.id)
        .where(
            MessagingProviderAccount.user_id == user_id_column,
            MessagingProviderAccount.is_active.is_(True),
        )
        .exists()
    )
    return or_(SmsCreditAccount.balance > 0, own_gateway)


_UNIT_MINUTES = {
    DurationUnit.MINUTES: 1,
    DurationUnit.HOURS: 60,
    DurationUnit.DAYS: 24 * 60,
}


def plan_duration_minutes(value, unit) -> int | None:
    if not value or unit is None:
        return None
    try:
        unit = DurationUnit(unit.value if hasattr(unit, "value") else unit)
    except ValueError:
        return None
    return int(value) * _UNIT_MINUTES[unit]


def reminder_fits_plan(offset_minutes: int, period_minutes: int | None) -> bool:
    """Skip a reminder that would land before the middle of a paid period.

    A 1-day reminder on a 1-hour hotspot plan would otherwise fire the moment
    the customer pays. Requiring the reminder to fall no earlier than halfway
    through the plan keeps it meaningful for every plan length.
    """
    if not period_minutes:
        return True
    return offset_minutes * 2 <= period_minutes


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
    who could not pay for a campaign are excluded; they become eligible
    automatically after a top-up.
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
                .outerjoin(
                    SmsCreditAccount,
                    SmsCreditAccount.user_id == CustomerExpirySmsSettings.user_id,
                )
                .where(
                    CustomerExpirySmsSettings.enabled.is_(True),
                    can_pay_for_sms_clause(CustomerExpirySmsSettings.user_id),
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
                    Plan.duration_value,
                    Plan.duration_unit,
                )
                .outerjoin(Plan, Customer.plan_id == Plan.id)
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
        if not is_textable_phone(row.phone):
            continue
        period = plan_duration_minutes(row.duration_value, row.duration_unit)
        for offset_minutes in offsets_by_reseller[row.user_id]:
            if row.expiry > now + timedelta(minutes=offset_minutes):
                continue
            if not reminder_fits_plan(offset_minutes, period):
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
                select(*_customer_message_columns())
                .outerjoin(Plan, Customer.plan_id == Plan.id)
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

        return await _queue_expiry_style_campaign(
            db,
            reseller=reseller,
            preferences=preferences,
            rows=rows,
            event=templates.EVENT_REMINDER,
            category_for=lambda row: reminder_message_category(
                row.expiry, offset_minutes
            ),
            category_prefix=REMINDER_CATEGORY_PREFIX,
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

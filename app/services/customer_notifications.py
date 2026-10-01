"""Event SMS to customers: payment receipts and the PPPoE welcome.

Payment receipts are found by a short polling sweep over recent
``customer_payments`` rather than a hook in every payment path. Payments are
recorded from more than a dozen places (STK callback, C2B, reconcile, RADIUS,
vouchers, MoMo, ZenoPay, Fapshi, manual provision...), all through
``record_customer_payment`` which commits inside the caller's request. A sweep
covers every one of them, adds nothing to those latency-critical paths, and
survives a crash between the payment commit and the send. The
(customer_id, category, user_id) unique index on ``sms_messages`` makes the
send exactly-once even if two sweeps overlap.

The welcome is queued from the dashboard create-customer endpoint only, so a
bulk PPPoE import of existing subscribers never texts them.

Database Session Discipline: every function reads and writes in a short
session, commits, and only then spawns the provider dispatch.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.db import database
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerExpirySmsSettings,
    CustomerPayment,
    MessagingSettings,
    PaymentStatus,
    Plan,
    SmsCreditAccount,
    SmsMessage,
    User,
)
from app.services import customer_sms_templates as templates
from app.services.customer_expiry_notifications import (
    can_pay_for_sms_clause,
    create_customer_campaign,
    is_textable_phone,
    reseller_support_phone,
    resolve_paybills,
    spawn_expiry_campaign_dispatch,
)
from app.services.markets import reseller_market

logger = logging.getLogger(__name__)

RECEIPT_CATEGORY_PREFIX = "receipt:"
WELCOME_CATEGORY = "welcome"
# How far back a sweep looks. Long enough to ride out a missed tick or a short
# DB-pressure pause; short enough that switching receipts on never texts
# customers about payments from hours ago.
RECEIPT_LOOKBACK = timedelta(minutes=10)
RECEIPT_SWEEP_SECONDS = 20


def receipt_category(payment_id: int) -> str:
    return f"{RECEIPT_CATEGORY_PREFIX}{payment_id}"


def _pool_is_busy() -> bool:
    try:
        level = (database.db_pool_snapshot().get("pressure") or {}).get("level")
    except Exception:
        return False
    return level in {"warning", "critical"}


def _is_hotspot(connection_type, pppoe_username: str | None) -> bool:
    if connection_type is not None:
        return connection_type == ConnectionType.HOTSPOT
    return not pppoe_username


# ---------------------------------------------------------------------------
# Payment receipts
# ---------------------------------------------------------------------------

async def collect_due_receipts(
    *,
    session_factory: Callable,
    now: datetime,
) -> dict[int, list[int]]:
    """Payment ids that still need a receipt, grouped by reseller.

    Three reads at most: global switch, opted-in resellers who can pay, and
    one recent-payments query (the dedupe read only runs when there are
    payments).
    """
    async with session_factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        if settings_row is not None and not settings_row.enabled:
            return {}

        preference_rows = (
            await db.execute(
                select(
                    CustomerExpirySmsSettings.user_id,
                    CustomerExpirySmsSettings.receipt_include_hotspot,
                )
                .outerjoin(
                    SmsCreditAccount,
                    SmsCreditAccount.user_id == CustomerExpirySmsSettings.user_id,
                )
                .where(
                    CustomerExpirySmsSettings.payment_receipt_enabled.is_(True),
                    can_pay_for_sms_clause(CustomerExpirySmsSettings.user_id),
                )
            )
        ).all()
        include_hotspot = {user_id: bool(flag) for user_id, flag in preference_rows}
        if not include_hotspot:
            return {}

        payment_rows = (
            await db.execute(
                select(
                    CustomerPayment.id,
                    CustomerPayment.reseller_id,
                    CustomerPayment.customer_id,
                    Customer.phone,
                    Customer.pppoe_username,
                    Plan.connection_type,
                )
                .join(Customer, Customer.id == CustomerPayment.customer_id)
                .outerjoin(Plan, Plan.id == CustomerPayment.plan_id)
                .where(
                    CustomerPayment.created_at >= now - RECEIPT_LOOKBACK,
                    CustomerPayment.reseller_id.in_(include_hotspot),
                    CustomerPayment.amount > 0,
                    CustomerPayment.status == PaymentStatus.COMPLETED,
                    # Compensation vouchers and free trials are not payments.
                    CustomerPayment.counts_as_revenue.is_(True),
                    Customer.user_id == CustomerPayment.reseller_id,
                    Customer.subscription_owner_id.is_(None),
                )
                .order_by(CustomerPayment.id)
            )
        ).all()
        if not payment_rows:
            return {}

        # customer_id first so the lookup rides the unique dedupe index.
        already_sent = set(
            (
                await db.execute(
                    select(SmsMessage.category).where(
                        SmsMessage.customer_id.in_(
                            {row.customer_id for row in payment_rows}
                        ),
                        SmsMessage.category.in_(
                            [receipt_category(row.id) for row in payment_rows]
                        ),
                    )
                )
            ).scalars().all()
        )

    due: dict[int, list[int]] = {}
    for row in payment_rows:
        if receipt_category(row.id) in already_sent:
            continue
        if not is_textable_phone(row.phone):
            continue
        if _is_hotspot(row.connection_type, row.pppoe_username) and not include_hotspot[row.reseller_id]:
            continue
        due.setdefault(row.reseller_id, []).append(row.id)
    return due


async def _queue_reseller_receipts(
    reseller_id: int,
    payment_ids: list[int],
    *,
    session_factory: Callable,
) -> int | None:
    async with session_factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        preferences = await db.get(CustomerExpirySmsSettings, reseller_id)
        reseller = await db.get(User, reseller_id)
        if preferences is None or not preferences.payment_receipt_enabled or reseller is None:
            return None

        rows = (
            await db.execute(
                select(
                    CustomerPayment.id,
                    CustomerPayment.amount,
                    CustomerPayment.payment_reference,
                    Customer.id.label("customer_id"),
                    Customer.phone,
                    Customer.name,
                    Customer.expiry,
                    Customer.account_number,
                    Customer.router_id,
                    Plan.name.label("plan_name"),
                    Plan.connection_type,
                )
                .join(Customer, Customer.id == CustomerPayment.customer_id)
                .outerjoin(Plan, Plan.id == CustomerPayment.plan_id)
                .where(
                    CustomerPayment.id.in_(payment_ids),
                    CustomerPayment.reseller_id == reseller_id,
                )
                .order_by(CustomerPayment.id)
            )
        ).all()
        if not rows:
            return None

        market = reseller_market(reseller)
        support_phone = await reseller_support_phone(db, reseller)
        paybills = await resolve_paybills(db, reseller, {row.router_id for row in rows})
        recipients: list[tuple[int, str, str, str]] = []
        for row in rows:
            payment_account = (
                row.account_number
                if row.connection_type == ConnectionType.PPPOE
                else None
            )
            context = templates.build_context(
                reseller=reseller,
                tz_name=market.timezone,
                customer_name=row.name,
                plan_name=row.plan_name,
                expiry=row.expiry,
                account_number=payment_account,
                paybill=paybills.get(row.router_id) if payment_account else None,
                support_phone=support_phone,
                amount=templates.format_amount(row.amount, market.currency),
                reference=row.payment_reference,
            )
            recipients.append((
                row.customer_id,
                row.phone.strip(),
                receipt_category(row.id),
                templates.render(
                    templates.EVENT_RECEIPT, context, preferences.custom_templates
                ),
            ))

        summary = (
            recipients[0][3]
            if len(recipients) == 1
            else f"Payment receipts ({len(recipients)})"
        )
        try:
            return await create_customer_campaign(
                db,
                reseller_id=reseller_id,
                recipients=recipients,
                body=summary,
                settings_row=settings_row,
                credit_note="Automatic customer payment receipt",
            )
        except IntegrityError:
            # Another sweep queued one of these receipts first.
            await db.rollback()
            return None


async def queue_payment_receipts(
    *,
    session_factory: Callable | None = None,
    now: datetime | None = None,
) -> list[int]:
    """Queue receipts for recent payments; returns the new campaign ids."""
    if not settings.SMS_DISPATCH_ENABLED:
        return []
    factory = session_factory or database.async_session
    now = now or datetime.utcnow()
    due = await collect_due_receipts(session_factory=factory, now=now)
    campaign_ids: list[int] = []
    for reseller_id, payment_ids in due.items():
        campaign_id = await _queue_reseller_receipts(
            reseller_id, payment_ids, session_factory=factory
        )
        if campaign_id is not None:
            campaign_ids.append(campaign_id)
    return campaign_ids


_sweep_running = False


async def send_payment_receipts_background() -> int:
    """APScheduler entrypoint: queue and dispatch due payment receipts."""
    global _sweep_running
    if _sweep_running or not settings.SMS_DISPATCH_ENABLED or _pool_is_busy():
        return 0
    _sweep_running = True
    try:
        campaign_ids = await queue_payment_receipts()
        spawn_expiry_campaign_dispatch(campaign_ids)
        if campaign_ids:
            logger.info("Payment receipt sweep queued %s campaign(s)", len(campaign_ids))
        return len(campaign_ids)
    except Exception as exc:
        logger.error("Payment receipt sweep failed: %s", exc, exc_info=True)
        return 0
    finally:
        _sweep_running = False


# ---------------------------------------------------------------------------
# PPPoE welcome
# ---------------------------------------------------------------------------

async def queue_welcome_message(
    customer_id: int,
    *,
    session_factory: Callable | None = None,
) -> int | None:
    """Queue the welcome SMS for a newly created PPPoE customer, if opted in."""
    if not settings.SMS_DISPATCH_ENABLED:
        return None
    factory = session_factory or database.async_session
    async with factory() as db:
        settings_row = await db.get(MessagingSettings, 1)
        if settings_row is not None and not settings_row.enabled:
            return None

        row = (
            await db.execute(
                select(
                    Customer.id,
                    Customer.user_id,
                    Customer.phone,
                    Customer.name,
                    Customer.expiry,
                    Customer.account_number,
                    Customer.router_id,
                    Customer.pppoe_username,
                    Customer.pppoe_password,
                    Plan.name.label("plan_name"),
                )
                .outerjoin(Plan, Plan.id == Customer.plan_id)
                .where(Customer.id == customer_id)
            )
        ).one_or_none()
        if row is None or row.user_id is None or not row.pppoe_username:
            return None
        if not is_textable_phone(row.phone):
            return None

        preferences = await db.get(CustomerExpirySmsSettings, row.user_id)
        if preferences is None or not preferences.welcome_enabled:
            return None
        reseller = await db.get(User, row.user_id)
        if reseller is None:
            return None

        already = (
            await db.execute(
                select(SmsMessage.id).where(
                    SmsMessage.customer_id == row.id,
                    SmsMessage.category == WELCOME_CATEGORY,
                )
            )
        ).first()
        if already is not None:
            return None

        market = reseller_market(reseller)
        paybills = await resolve_paybills(db, reseller, {row.router_id})
        context = templates.build_context(
            reseller=reseller,
            tz_name=market.timezone,
            customer_name=row.name,
            plan_name=row.plan_name,
            expiry=row.expiry,
            account_number=row.account_number,
            paybill=paybills.get(row.router_id),
            support_phone=await reseller_support_phone(db, reseller),
            username=row.pppoe_username,
            password=row.pppoe_password,
        )
        body = templates.render(
            templates.EVENT_WELCOME, context, preferences.custom_templates
        )
        try:
            return await create_customer_campaign(
                db,
                reseller_id=reseller.id,
                recipients=[(row.id, row.phone.strip(), WELCOME_CATEGORY, body)],
                # The history shows the template, not this customer's password.
                body=(
                    templates.custom_template(
                        preferences.custom_templates, templates.EVENT_WELCOME
                    )
                    or templates.DEFAULT_TEMPLATE_TEXT[templates.EVENT_WELCOME]
                ),
                settings_row=settings_row,
                credit_note="Automatic customer welcome",
            )
        except IntegrityError:
            await db.rollback()
            return None


async def _send_welcome(customer_id: int) -> None:
    try:
        campaign_id = await queue_welcome_message(customer_id)
    except Exception as exc:
        logger.error("Welcome SMS for customer %s failed: %s", customer_id, exc)
        return
    if campaign_id is not None:
        spawn_expiry_campaign_dispatch([campaign_id])


_welcome_tasks: set[asyncio.Task] = set()


def spawn_welcome_message(customer_id: int) -> None:
    """Fire-and-forget from a request handler, after its commit."""
    if not settings.SMS_DISPATCH_ENABLED:
        return
    try:
        task = asyncio.create_task(_send_welcome(customer_id))
    except RuntimeError:
        return
    _welcome_tasks.add(task)
    task.add_done_callback(_welcome_tasks.discard)

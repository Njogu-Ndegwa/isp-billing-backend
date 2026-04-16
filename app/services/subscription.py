from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.db.models import (
    Subscription, SubscriptionInvoice, SubscriptionPayment,
    User, UserRole, SubscriptionStatus, InvoiceStatus, SubscriptionPaymentStatus,
    Customer, CustomerPayment, Plan, ConnectionType, CustomerStatus, PaymentStatus,
)
from datetime import datetime, timedelta
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

def enforce_active_subscription(user: User):
    """
    Raise 403 if the reseller's subscription is not active/trial.
    Call this after get_current_user() in any route that should be gated.
    Admins always pass.
    """
    if hasattr(user, 'role') and hasattr(user.role, 'value'):
        role = user.role.value
    else:
        role = str(user.role) if user.role else ""

    if role == "admin":
        return

    sub_status = user.subscription_status
    if hasattr(sub_status, 'value'):
        sub_status = sub_status.value

    if sub_status not in ("active", "trial"):
        raise HTTPException(
            status_code=403,
            detail="Your subscription is inactive. Please renew your subscription to continue using the service.",
        )


HOTSPOT_RATE = 0.03          # 3% of hotspot revenue
PPPOE_PER_USER = 25.0        # 25 KES per PPPoE user per month
MINIMUM_CHARGE = 500.0        # 500 KES minimum monthly charge
TRIAL_DAYS = 7
GRACE_PERIOD_DAYS = 5
DUE_SOON_THRESHOLD_DAYS = 5


async def calculate_reseller_charges(
    db: AsyncSession, user_id: int, period_start: datetime, period_end: datetime
) -> dict:
    """
    Calculate subscription charges for a reseller based on their usage
    during the given billing period.
    Returns a breakdown dict with all charge components.
    """
    hotspot_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
        .join(Customer, CustomerPayment.customer_id == Customer.id)
        .join(Plan, Customer.plan_id == Plan.id)
        .where(
            CustomerPayment.reseller_id == user_id,
            CustomerPayment.status == PaymentStatus.COMPLETED,
            CustomerPayment.created_at >= period_start,
            CustomerPayment.created_at < period_end,
            Plan.connection_type == ConnectionType.HOTSPOT,
        )
    )).scalar())

    pppoe_user_count = (await db.execute(
        select(func.count(Customer.id))
        .join(Plan, Customer.plan_id == Plan.id)
        .where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE,
            Plan.connection_type == ConnectionType.PPPOE,
        )
    )).scalar() or 0

    hotspot_charge = round(hotspot_revenue * HOTSPOT_RATE, 2)
    pppoe_charge = round(pppoe_user_count * PPPOE_PER_USER, 2)
    gross_charge = round(hotspot_charge + pppoe_charge, 2)
    final_charge = max(gross_charge, MINIMUM_CHARGE)

    return {
        "hotspot_revenue": hotspot_revenue,
        "hotspot_charge": hotspot_charge,
        "pppoe_user_count": pppoe_user_count,
        "pppoe_charge": pppoe_charge,
        "gross_charge": gross_charge,
        "final_charge": final_charge,
    }


async def generate_invoice_for_reseller(
    db: AsyncSession, user_id: int, period_start: datetime, period_end: datetime
) -> SubscriptionInvoice | None:
    """Generate an invoice for a single reseller. Returns None if already exists."""
    existing = (await db.execute(
        select(SubscriptionInvoice).where(
            SubscriptionInvoice.user_id == user_id,
            SubscriptionInvoice.period_start == period_start,
        )
    )).scalar_one_or_none()

    if existing:
        return None

    charges = await calculate_reseller_charges(db, user_id, period_start, period_end)
    due_date = period_end + timedelta(days=GRACE_PERIOD_DAYS)

    invoice = SubscriptionInvoice(
        user_id=user_id,
        period_start=period_start,
        period_end=period_end,
        hotspot_revenue=charges["hotspot_revenue"],
        hotspot_charge=charges["hotspot_charge"],
        pppoe_user_count=charges["pppoe_user_count"],
        pppoe_charge=charges["pppoe_charge"],
        gross_charge=charges["gross_charge"],
        final_charge=charges["final_charge"],
        status=InvoiceStatus.PENDING,
        due_date=due_date,
    )
    db.add(invoice)
    await db.flush()
    return invoice


async def generate_monthly_invoices(db: AsyncSession) -> dict:
    """
    Generate invoices for all active/trial resellers for the previous month.
    Called by the monthly scheduler job.
    """
    now = datetime.utcnow()
    if now.month == 1:
        period_start = datetime(now.year - 1, 12, 1)
    else:
        period_start = datetime(now.year, now.month - 1, 1)
    period_end = datetime(now.year, now.month, 1)

    resellers = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIAL,
            ])
        )
    )).scalars().all()

    created = 0
    skipped = 0
    errors = []

    for reseller in resellers:
        try:
            invoice = await generate_invoice_for_reseller(
                db, reseller.id, period_start, period_end
            )
            if invoice:
                created += 1
            else:
                skipped += 1
        except Exception as e:
            errors.append({"reseller_id": reseller.id, "error": str(e)})
            logger.error(f"[SUBSCRIPTION] Invoice generation failed for reseller {reseller.id}: {e}")

    await db.commit()
    logger.info(f"[SUBSCRIPTION] Monthly invoices: created={created}, skipped={skipped}, errors={len(errors)}")
    return {"created": created, "skipped": skipped, "errors": errors}


async def check_overdue_invoices(db: AsyncSession) -> dict:
    """
    Check for overdue invoices and suspend resellers who haven't paid.
    Called by the daily scheduler job.
    """
    now = datetime.utcnow()

    overdue_invoices = (await db.execute(
        select(SubscriptionInvoice).where(
            SubscriptionInvoice.status == InvoiceStatus.PENDING,
            SubscriptionInvoice.due_date < now,
        )
    )).scalars().all()

    marked_overdue = 0
    suspended = 0

    for invoice in overdue_invoices:
        invoice.status = InvoiceStatus.OVERDUE
        marked_overdue += 1

        user = (await db.execute(
            select(User).where(User.id == invoice.user_id)
        )).scalar_one_or_none()

        if user and user.subscription_status not in (
            SubscriptionStatus.SUSPENDED, SubscriptionStatus.INACTIVE
        ):
            await deactivate_subscription(db, user.id, status=SubscriptionStatus.SUSPENDED)
            suspended += 1
            logger.info(
                f"[SUBSCRIPTION] Suspended reseller {user.id} ({user.email}) "
                f"for overdue invoice #{invoice.id}"
            )

    # Also check trial expirations
    expired_trials = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.TRIAL,
            User.subscription_expires_at < now,
        )
    )).scalars().all()

    trial_expired = 0
    for user in expired_trials:
        await deactivate_subscription(db, user.id, status=SubscriptionStatus.SUSPENDED)
        trial_expired += 1
        logger.info(f"[SUBSCRIPTION] Trial expired for reseller {user.id} ({user.email})")

    await db.commit()
    return {
        "marked_overdue": marked_overdue,
        "suspended": suspended,
        "trial_expired": trial_expired,
    }


async def activate_subscription(db: AsyncSession, user_id: int, months: int = 1):
    """Activate a reseller's subscription and extend the period."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return None

    now = datetime.utcnow()
    new_expiry = now + timedelta(days=months * 30)

    if user.subscription_expires_at and user.subscription_expires_at > now:
        new_expiry = user.subscription_expires_at + timedelta(days=months * 30)

    user.subscription_status = SubscriptionStatus.ACTIVE
    user.subscription_expires_at = new_expiry

    sub = (await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )).scalar_one_or_none()

    if sub:
        sub.status = SubscriptionStatus.ACTIVE
        sub.current_period_start = now
        sub.current_period_end = new_expiry
        sub.updated_at = now
    else:
        sub = Subscription(
            user_id=user_id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=now,
            current_period_end=new_expiry,
            is_active=True,
        )
        db.add(sub)

    try:
        from app.services.lead_tracking import advance_lead_to_paying
        await advance_lead_to_paying(db, user_id)
    except Exception as e:
        logger.warning(f"Lead auto-advance failed (non-fatal): {e}")

    await db.flush()
    return user


async def deactivate_subscription(
    db: AsyncSession, user_id: int, status: SubscriptionStatus = SubscriptionStatus.SUSPENDED
):
    """Deactivate/suspend a reseller's subscription."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return None

    user.subscription_status = status

    sub = (await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )).scalar_one_or_none()

    if sub:
        sub.status = status
        sub.updated_at = datetime.utcnow()

    if status in (SubscriptionStatus.SUSPENDED, SubscriptionStatus.INACTIVE):
        try:
            from app.services.lead_tracking import regress_lead_to_churned
            await regress_lead_to_churned(db, user_id)
        except Exception as e:
            logger.warning(f"Lead auto-churn failed (non-fatal): {e}")

    await db.flush()
    return user


async def get_pending_invoice(db: AsyncSession, user_id: int) -> SubscriptionInvoice | None:
    """Get the most recent unpaid invoice for a reseller."""
    result = await db.execute(
        select(SubscriptionInvoice).where(
            SubscriptionInvoice.user_id == user_id,
            SubscriptionInvoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.OVERDUE]),
        ).order_by(SubscriptionInvoice.created_at.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def get_subscription_summary(db: AsyncSession, user_id: int) -> dict:
    """Full subscription summary for a reseller."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return {}

    # Self-heal: if trial reseller has no expiry date, set it now
    status_val = user.subscription_status.value if hasattr(user.subscription_status, 'value') else user.subscription_status
    if status_val == "trial" and user.subscription_expires_at is None:
        user.subscription_expires_at = datetime.utcnow() + timedelta(days=TRIAL_DAYS)
        await db.commit()
        await db.refresh(user)

    sub = (await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )).scalar_one_or_none()

    pending_invoice = await get_pending_invoice(db, user_id)

    total_paid = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0)).where(
            SubscriptionPayment.user_id == user_id,
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
        )
    )).scalar())

    invoice_count = (await db.execute(
        select(func.count(SubscriptionInvoice.id)).where(
            SubscriptionInvoice.user_id == user_id,
        )
    )).scalar() or 0

    return {
        "status": user.subscription_status.value if hasattr(user.subscription_status, 'value') else user.subscription_status,
        "expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None,
        "trial_ends_at": sub.trial_ends_at.isoformat() if sub and sub.trial_ends_at else None,
        "current_period_start": sub.current_period_start.isoformat() if sub and sub.current_period_start else None,
        "current_period_end": sub.current_period_end.isoformat() if sub and sub.current_period_end else None,
        "total_paid": total_paid,
        "invoice_count": invoice_count,
        "pending_invoice": (
            enrich_invoice(pending_invoice, await get_invoice_amount_paid(db, pending_invoice.id))
            if pending_invoice else None
        ),
    }


async def get_invoice_amount_paid(db: AsyncSession, invoice_id: int) -> float:
    """Total completed payments toward a specific invoice."""
    result = (await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0)).where(
            SubscriptionPayment.invoice_id == invoice_id,
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
        )
    )).scalar()
    return float(result)


def enrich_invoice(invoice: SubscriptionInvoice, amount_paid: float = 0.0) -> dict:
    """Add computed timing fields and payment progress to an invoice dict."""
    now = datetime.utcnow()
    status_val = invoice.status.value if hasattr(invoice.status, 'value') else invoice.status

    days_until_due = (invoice.due_date - now).days if invoice.due_date else 0
    balance_remaining = max(invoice.final_charge - amount_paid, 0.0)

    if status_val in ("paid", "waived"):
        is_overdue = False
        is_due_soon = False
        human_message = "Paid" if status_val == "paid" else "Waived"
    elif days_until_due < 0:
        is_overdue = True
        is_due_soon = False
        human_message = f"Overdue by {abs(days_until_due)} day{'s' if abs(days_until_due) != 1 else ''}"
    elif days_until_due == 0:
        is_overdue = False
        is_due_soon = True
        human_message = "Due today"
    elif days_until_due <= DUE_SOON_THRESHOLD_DAYS:
        is_overdue = False
        is_due_soon = True
        human_message = f"Due in {days_until_due} day{'s' if days_until_due != 1 else ''}"
    else:
        is_overdue = False
        is_due_soon = False
        human_message = f"Due in {days_until_due} day{'s' if days_until_due != 1 else ''}"

    period_label = invoice.period_start.strftime("%B %Y") if invoice.period_start else ""

    return {
        "id": invoice.id,
        "user_id": invoice.user_id,
        "period_start": invoice.period_start.isoformat() if invoice.period_start else None,
        "period_end": invoice.period_end.isoformat() if invoice.period_end else None,
        "period_label": period_label,
        "hotspot_revenue": invoice.hotspot_revenue,
        "hotspot_charge": invoice.hotspot_charge,
        "pppoe_user_count": invoice.pppoe_user_count,
        "pppoe_charge": invoice.pppoe_charge,
        "gross_charge": invoice.gross_charge,
        "final_charge": invoice.final_charge,
        "amount_paid": round(amount_paid, 2),
        "balance_remaining": round(balance_remaining, 2),
        "status": status_val,
        "due_date": invoice.due_date.isoformat() if invoice.due_date else None,
        "paid_at": invoice.paid_at.isoformat() if invoice.paid_at else None,
        "days_until_due": days_until_due,
        "is_overdue": is_overdue,
        "is_due_soon": is_due_soon,
        "human_message": human_message,
        "created_at": invoice.created_at.isoformat() if invoice.created_at else None,
    }


async def record_subscription_payment(
    db: AsyncSession,
    user_id: int,
    invoice_id: int | None,
    amount: float,
    payment_reference: str,
    checkout_request_id: str | None = None,
    phone_number: str | None = None,
) -> SubscriptionPayment:
    """Record a completed subscription payment. Activates only when invoice is fully paid."""
    payment = SubscriptionPayment(
        invoice_id=invoice_id,
        user_id=user_id,
        amount=amount,
        payment_method="mpesa",
        payment_reference=payment_reference,
        mpesa_checkout_request_id=checkout_request_id,
        phone_number=phone_number,
        status=SubscriptionPaymentStatus.COMPLETED,
    )
    db.add(payment)
    await db.flush()

    if invoice_id:
        invoice = (await db.execute(
            select(SubscriptionInvoice).where(SubscriptionInvoice.id == invoice_id)
        )).scalar_one_or_none()
        if invoice:
            total_paid = await get_invoice_amount_paid(db, invoice.id)
            if total_paid >= invoice.final_charge:
                invoice.status = InvoiceStatus.PAID
                invoice.paid_at = datetime.utcnow()
                await activate_subscription(db, user_id, months=1)

    await db.flush()
    return payment


async def get_invoice_alert_for_user(db: AsyncSession, user_id: int) -> dict | None:
    """
    Returns a subscription alert dict for injection into login/dashboard responses.
    Returns None if no alert is needed.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or user.role != UserRole.RESELLER:
        return None

    status_val = user.subscription_status.value if hasattr(user.subscription_status, 'value') else user.subscription_status

    # Self-heal: if trial reseller has no expiry date, set it now
    if status_val == "trial" and user.subscription_expires_at is None:
        user.subscription_expires_at = datetime.utcnow() + timedelta(days=TRIAL_DAYS)
        await db.commit()
        await db.refresh(user)

    pending_invoice = await get_pending_invoice(db, user_id)
    inv_paid = await get_invoice_amount_paid(db, pending_invoice.id) if pending_invoice else 0.0

    if status_val == "suspended":
        message = "Your subscription is suspended. Please pay your outstanding invoice to continue using the service."
    elif pending_invoice:
        enriched = enrich_invoice(pending_invoice, inv_paid)
        remaining = enriched["balance_remaining"]
        if enriched["is_overdue"]:
            message = f"Your {enriched['period_label']} invoice of KES {enriched['final_charge']:,.0f} is overdue."
            if inv_paid > 0:
                message += f" KES {inv_paid:,.0f} paid, KES {remaining:,.0f} remaining."
            else:
                message += " Please pay to avoid suspension."
        elif enriched["is_due_soon"]:
            message = f"Your {enriched['period_label']} invoice of KES {enriched['final_charge']:,.0f} is due in {enriched['days_until_due']} day{'s' if enriched['days_until_due'] != 1 else ''}."
            if inv_paid > 0:
                message += f" KES {inv_paid:,.0f} paid, KES {remaining:,.0f} remaining."
        else:
            return None
    elif status_val == "trial":
        now = datetime.utcnow()
        if user.subscription_expires_at:
            days_left = (user.subscription_expires_at - now).days
            if days_left <= 3:
                message = f"Your free trial ends in {max(days_left, 0)} day{'s' if days_left != 1 else ''}."
            else:
                return None
        else:
            return None
    else:
        return None

    result = {
        "status": status_val,
        "message": message,
    }

    if pending_invoice:
        result["current_invoice"] = enrich_invoice(pending_invoice, inv_paid)

    return result


PRE_EXPIRY_DAYS = 5


async def generate_pre_expiry_invoices(db: AsyncSession) -> dict:
    """
    Generate invoices for resellers whose subscriptions expire within
    PRE_EXPIRY_DAYS. Catches mid-month signups whose trial or subscription
    period ends before the regular 1st-of-month invoice run.
    """
    now = datetime.utcnow()
    cutoff = now + timedelta(days=PRE_EXPIRY_DAYS)

    expiring_resellers = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIAL,
            ]),
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at > now,
            User.subscription_expires_at <= cutoff,
        )
    )).scalars().all()

    created = 0
    skipped = 0
    errors = []

    for reseller in expiring_resellers:
        try:
            existing_pending = await get_pending_invoice(db, reseller.id)
            if existing_pending:
                skipped += 1
                continue

            expires = reseller.subscription_expires_at
            period_start = datetime(expires.year, expires.month, 1)
            period_end = expires

            if period_start >= period_end:
                period_start = period_end - timedelta(days=30)

            already_invoiced = (await db.execute(
                select(SubscriptionInvoice).where(
                    SubscriptionInvoice.user_id == reseller.id,
                    SubscriptionInvoice.period_start == period_start,
                )
            )).scalar_one_or_none()
            if already_invoiced:
                skipped += 1
                continue

            charges = await calculate_reseller_charges(
                db, reseller.id, period_start, period_end
            )

            invoice = SubscriptionInvoice(
                user_id=reseller.id,
                period_start=period_start,
                period_end=period_end,
                hotspot_revenue=charges["hotspot_revenue"],
                hotspot_charge=charges["hotspot_charge"],
                pppoe_user_count=charges["pppoe_user_count"],
                pppoe_charge=charges["pppoe_charge"],
                gross_charge=charges["gross_charge"],
                final_charge=charges["final_charge"],
                status=InvoiceStatus.PENDING,
                due_date=expires,
            )
            db.add(invoice)
            await db.flush()
            created += 1

            logger.info(
                f"[SUBSCRIPTION] Pre-expiry invoice #{invoice.id} generated for "
                f"reseller {reseller.id} ({reseller.email}), "
                f"charge=KES {charges['final_charge']:,.0f}, "
                f"due={expires}"
            )
        except Exception as e:
            errors.append({"reseller_id": reseller.id, "error": str(e)})
            logger.error(
                f"[SUBSCRIPTION] Pre-expiry invoice failed for reseller "
                f"{reseller.id}: {e}"
            )

    await db.commit()
    logger.info(
        f"[SUBSCRIPTION] Pre-expiry invoices: created={created}, "
        f"skipped={skipped}, errors={len(errors)}"
    )
    return {"created": created, "skipped": skipped, "errors": errors}

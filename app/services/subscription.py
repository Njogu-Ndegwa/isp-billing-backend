from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from app.db.models import (
    Subscription, SubscriptionInvoice, SubscriptionPayment,
    User, UserRole, SubscriptionStatus, InvoiceStatus, SubscriptionPaymentStatus,
    Customer, CustomerPayment, Plan, ConnectionType, CustomerStatus, PaymentStatus,
)
from datetime import datetime, timedelta
from fastapi import HTTPException
import calendar
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


def add_calendar_months(dt: datetime, months: int) -> datetime:
    """Advance *dt* by *months* calendar months, keeping the same day-of-month.
    Clamps to the last valid day when the target month is shorter
    (e.g. Jan 31 + 1 month -> Feb 28)."""
    month = dt.month + months
    year = dt.year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


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

    # Catch ACTIVE resellers whose subscription_expires_at has passed but were
    # not suspended via the invoice path (e.g. invoice was never generated, or
    # the pre-expiry window was missed due to downtime/misfire).
    expired_active = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.ACTIVE,
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at < now,
        )
    )).scalars().all()

    active_expired = 0
    for user in expired_active:
        await deactivate_subscription(db, user.id, status=SubscriptionStatus.SUSPENDED)
        active_expired += 1
        logger.info(
            f"[SUBSCRIPTION] Suspended expired ACTIVE reseller {user.id} "
            f"({user.email}), expired at {user.subscription_expires_at}"
        )

    await db.commit()
    return {
        "marked_overdue": marked_overdue,
        "suspended": suspended,
        "trial_expired": trial_expired,
        "active_expired": active_expired,
    }


async def activate_subscription(db: AsyncSession, user_id: int, months: int = 1):
    """Activate a reseller's subscription and extend the period."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        return None

    now = datetime.utcnow()

    # If the user pays before their current period ends, extend from the
    # existing expiry so they don't lose the remaining days.
    base = now
    if user.subscription_expires_at and user.subscription_expires_at > now:
        base = user.subscription_expires_at

    new_expiry = add_calendar_months(base, months)

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
        async with db.begin_nested():
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
            async with db.begin_nested():
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



# ---------------------------------------------------------------------------
# Background reconciliation for subscription payments
# ---------------------------------------------------------------------------

_sub_reconcile_running = False


async def reconcile_pending_subscription_payments():
    """
    Periodically queries Safaricom for pending SubscriptionPayment rows and
    resolves them (complete / fail / expire).  Mirrors the logic in
    reconcile_pending_mpesa_transactions but operates on the subscription
    payment table instead of MpesaTransaction.
    """
    global _sub_reconcile_running
    if _sub_reconcile_running:
        logger.debug("[SUB-RECONCILE] Previous run still active, skipping")
        return
    _sub_reconcile_running = True

    try:
        from app.db.database import async_session
        from app.services.mpesa import query_stk_push_status, get_access_token
        import asyncio

        now = datetime.utcnow()
        query_min_age = timedelta(minutes=2)
        expire_threshold = timedelta(hours=2)

        async with async_session() as db:
            stmt = (
                select(SubscriptionPayment)
                .where(
                    SubscriptionPayment.status == SubscriptionPaymentStatus.PENDING,
                    SubscriptionPayment.created_at < now - query_min_age,
                    SubscriptionPayment.mpesa_checkout_request_id.isnot(None),
                )
                .order_by(SubscriptionPayment.created_at.asc())
                .limit(30)
            )
            result = await db.execute(stmt)
            pending_payments = list(result.scalars().all())

        if not pending_payments:
            return

        to_query = []
        expired_count = 0
        for pay in pending_payments:
            age = now - pay.created_at
            if age > expire_threshold:
                try:
                    async with async_session() as db:
                        p = (await db.execute(
                            select(SubscriptionPayment).where(
                                SubscriptionPayment.id == pay.id
                            )
                        )).scalar_one_or_none()
                        if p and p.status == SubscriptionPaymentStatus.PENDING:
                            p.status = SubscriptionPaymentStatus.FAILED
                            await db.commit()
                            expired_count += 1
                            logger.info(
                                "[SUB-RECONCILE] Expired stale subscription payment %s (age: %s)",
                                pay.id, age,
                            )
                except Exception as exp_err:
                    logger.warning("[SUB-RECONCILE] Failed to expire payment %s: %s", pay.id, exp_err)
            else:
                to_query.append(pay)

        if expired_count:
            logger.info("[SUB-RECONCILE] Expired %d stale subscription payments", expired_count)

        if not to_query:
            return

        to_query.sort(key=lambda p: p.created_at, reverse=True)
        to_query = to_query[:15]

        logger.info("[SUB-RECONCILE] Querying Safaricom for %d pending subscription payments", len(to_query))

        try:
            access_token = await get_access_token()
        except Exception as token_err:
            logger.warning("[SUB-RECONCILE] Cannot get Safaricom token, aborting batch: %s", token_err)
            return

        consecutive_failures = 0
        max_consecutive_failures = 3

        for pay in to_query:
            if consecutive_failures >= max_consecutive_failures:
                logger.warning(
                    "[SUB-RECONCILE] %d consecutive Safaricom failures, aborting remaining queries",
                    consecutive_failures,
                )
                break

            try:
                stk_result = await query_stk_push_status(
                    pay.mpesa_checkout_request_id, access_token=access_token
                )
                consecutive_failures = 0
            except Exception as query_err:
                consecutive_failures += 1
                logger.warning(
                    "[SUB-RECONCILE] Could not query Safaricom for payment %s (checkout %s): %s",
                    pay.id, pay.mpesa_checkout_request_id, query_err,
                )
                await asyncio.sleep(3)
                continue

            result_code = stk_result["result_code"]
            result_desc = stk_result["result_desc"]

            if result_code == 0:
                await _complete_subscription_payment(pay.id)
            elif result_code == -1:
                logger.debug(
                    "[SUB-RECONCILE] Payment %s still processing at Safaricom, will retry later",
                    pay.id,
                )
            else:
                async with async_session() as db:
                    p = (await db.execute(
                        select(SubscriptionPayment).where(SubscriptionPayment.id == pay.id)
                    )).scalar_one_or_none()
                    if p and p.status == SubscriptionPaymentStatus.PENDING:
                        p.status = SubscriptionPaymentStatus.FAILED
                        await db.commit()
                logger.info(
                    "[SUB-RECONCILE] Marked subscription payment %s as failed (code=%s, desc=%s)",
                    pay.id, result_code, result_desc,
                )

            await asyncio.sleep(2)

    except Exception as outer_err:
        logger.exception("[SUB-RECONCILE] Reconciliation job failed: %s", outer_err)
    finally:
        _sub_reconcile_running = False


async def _complete_subscription_payment(payment_id: int):
    """
    Mark a single SubscriptionPayment as completed and activate the
    subscription if the linked invoice is fully paid.  Used by both
    the background reconciler and the manual verify endpoint.
    """
    from app.db.database import async_session

    async with async_session() as db:
        payment = (await db.execute(
            select(SubscriptionPayment).where(SubscriptionPayment.id == payment_id)
        )).scalar_one_or_none()

        if not payment or payment.status != SubscriptionPaymentStatus.PENDING:
            return False

        payment.status = SubscriptionPaymentStatus.COMPLETED

        fully_paid = False
        if payment.invoice_id:
            invoice = (await db.execute(
                select(SubscriptionInvoice).where(
                    SubscriptionInvoice.id == payment.invoice_id
                )
            )).scalar_one_or_none()
            if invoice:
                await db.flush()
                total_paid = await get_invoice_amount_paid(db, invoice.id)
                if total_paid >= invoice.final_charge:
                    invoice.status = InvoiceStatus.PAID
                    invoice.paid_at = datetime.utcnow()
                    fully_paid = True
                    logger.info(
                        "[SUB-RECONCILE] Invoice #%s fully paid (%s / %s)",
                        invoice.id, total_paid, invoice.final_charge,
                    )

        if fully_paid:
            await activate_subscription(db, payment.user_id, months=1)

        await db.commit()
        logger.info(
            "[SUB-RECONCILE] Payment %s completed for reseller %s, invoice #%s, activated=%s",
            payment.id, payment.user_id, payment.invoice_id, fully_paid,
        )
        return True


async def verify_subscription_payments_for_reseller(reseller_id: int) -> dict:
    """
    Look up all pending subscription payments for a reseller,
    query Safaricom for each, and resolve them.  Returns a summary.
    """
    from app.db.database import async_session
    from app.services.mpesa import query_stk_push_status, get_access_token

    async with async_session() as db:
        user = (await db.execute(
            select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
        )).scalar_one_or_none()
        if not user:
            return {
                "reseller_id": reseller_id,
                "error": "Reseller not found",
            }

        stmt = (
            select(SubscriptionPayment)
            .where(
                SubscriptionPayment.user_id == reseller_id,
                SubscriptionPayment.status == SubscriptionPaymentStatus.PENDING,
                SubscriptionPayment.mpesa_checkout_request_id.isnot(None),
            )
            .order_by(SubscriptionPayment.created_at.desc())
            .limit(10)
        )
        result = await db.execute(stmt)
        pending = list(result.scalars().all())

    if not pending:
        return {
            "reseller_id": reseller_id,
            "email": user.email,
            "pending_found": 0,
            "resolved": [],
            "message": "No pending subscription payments found for this reseller.",
        }

    access_token = await get_access_token()
    resolved = []
    for pay in pending:
        try:
            stk_result = await query_stk_push_status(
                pay.mpesa_checkout_request_id, access_token=access_token
            )
        except Exception as e:
            resolved.append({
                "payment_id": pay.id,
                "checkout_request_id": pay.mpesa_checkout_request_id,
                "phone_number": pay.phone_number,
                "amount": pay.amount,
                "status": "query_failed",
                "error": str(e),
            })
            continue

        rc = stk_result["result_code"]
        if rc == 0:
            completed = await _complete_subscription_payment(pay.id)
            resolved.append({
                "payment_id": pay.id,
                "checkout_request_id": pay.mpesa_checkout_request_id,
                "phone_number": pay.phone_number,
                "amount": pay.amount,
                "status": "completed" if completed else "already_processed",
            })
        else:
            resolved.append({
                "payment_id": pay.id,
                "checkout_request_id": pay.mpesa_checkout_request_id,
                "phone_number": pay.phone_number,
                "amount": pay.amount,
                "status": "not_paid",
                "result_code": rc,
                "result_desc": stk_result["result_desc"],
            })

    return {
        "reseller_id": reseller_id,
        "email": user.email,
        "pending_found": len(pending),
        "resolved": resolved,
        "message": f"Checked {len(pending)} pending payment(s) against Safaricom.",
    }


PRE_EXPIRY_DAYS = 5


async def generate_pre_expiry_invoices(db: AsyncSession) -> dict:
    """
    Primary invoice generation job (runs daily).
    Generates an invoice for each reseller whose subscription expires within
    PRE_EXPIRY_DAYS.  Also sweeps recently-expired users who were missed
    (e.g. due to server downtime).

    Billing period logic:
      period_start = last invoice's period_end  (or subscription start)
      period_end   = now  (so the *next* cycle resumes from here)
      due_date     = subscription_expires_at
    """
    now = datetime.utcnow()
    cutoff = now + timedelta(days=PRE_EXPIRY_DAYS)

    # Look-back window: also catch users who expired recently but never got an
    # invoice (e.g. server downtime caused the 5-day window to be missed).
    lookback = now - timedelta(days=PRE_EXPIRY_DAYS)

    expiring_resellers = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIAL,
            ]),
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at >= lookback,
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

            # Determine period_start from the last invoice's period_end, or
            # fall back to the subscription's current_period_start.
            last_invoice = (await db.execute(
                select(SubscriptionInvoice)
                .where(SubscriptionInvoice.user_id == reseller.id)
                .order_by(SubscriptionInvoice.period_end.desc())
                .limit(1)
            )).scalar_one_or_none()

            if last_invoice:
                period_start = last_invoice.period_end
            else:
                sub = (await db.execute(
                    select(Subscription).where(Subscription.user_id == reseller.id)
                )).scalar_one_or_none()
                period_start = sub.current_period_start if sub and sub.current_period_start else (
                    reseller.subscription_expires_at - timedelta(days=30)
                )

            period_end = now
            if period_start >= period_end:
                skipped += 1
                continue

            expires = reseller.subscription_expires_at

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
                f"[SUBSCRIPTION] Invoice #{invoice.id} generated for "
                f"reseller {reseller.id} ({reseller.email}), "
                f"period={period_start.date()}..{period_end.date()}, "
                f"charge=KES {charges['final_charge']:,.0f}, "
                f"due={expires.date()}"
            )
        except Exception as e:
            errors.append({"reseller_id": reseller.id, "error": str(e)})
            logger.error(
                f"[SUBSCRIPTION] Invoice generation failed for reseller "
                f"{reseller.id}: {e}"
            )

    await db.commit()
    logger.info(
        f"[SUBSCRIPTION] Pre-expiry invoices: created={created}, "
        f"skipped={skipped}, errors={len(errors)}"
    )
    return {"created": created, "skipped": skipped, "errors": errors}


async def generate_catchup_invoices(db: AsyncSession) -> dict:
    """
    One-time admin catch-up: generate invoices for ALL active/trial resellers
    who don't currently have a pending/overdue invoice, regardless of how far
    away (or past) their expiry date is.  Use after a deploy to backfill
    users missed by the normal 5-day pre-expiry window.
    """
    now = datetime.utcnow()

    resellers = (await db.execute(
        select(User).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE,
                SubscriptionStatus.TRIAL,
            ]),
            User.subscription_expires_at.isnot(None),
        )
    )).scalars().all()

    created = 0
    skipped = 0
    errors = []

    for reseller in resellers:
        try:
            existing_pending = await get_pending_invoice(db, reseller.id)
            if existing_pending:
                skipped += 1
                continue

            last_invoice = (await db.execute(
                select(SubscriptionInvoice)
                .where(SubscriptionInvoice.user_id == reseller.id)
                .order_by(SubscriptionInvoice.period_end.desc())
                .limit(1)
            )).scalar_one_or_none()

            if last_invoice:
                period_start = last_invoice.period_end
            else:
                sub = (await db.execute(
                    select(Subscription).where(Subscription.user_id == reseller.id)
                )).scalar_one_or_none()
                period_start = sub.current_period_start if sub and sub.current_period_start else (
                    reseller.subscription_expires_at - timedelta(days=30)
                )

            period_end = now
            if period_start >= period_end:
                skipped += 1
                continue

            expires = reseller.subscription_expires_at

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
                f"[SUBSCRIPTION] Catch-up invoice #{invoice.id} for "
                f"reseller {reseller.id} ({reseller.email}), "
                f"period={period_start.date()}..{period_end.date()}, "
                f"charge=KES {charges['final_charge']:,.0f}, "
                f"due={expires.date()}"
            )
        except Exception as e:
            errors.append({"reseller_id": reseller.id, "error": str(e)})
            logger.error(
                f"[SUBSCRIPTION] Catch-up invoice failed for reseller "
                f"{reseller.id}: {e}"
            )

    await db.commit()
    logger.info(
        f"[SUBSCRIPTION] Catch-up invoices: created={created}, "
        f"skipped={skipped}, errors={len(errors)}"
    )
    return {"created": created, "skipped": skipped, "errors": errors}

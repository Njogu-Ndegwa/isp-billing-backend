"""Reseller-subscription invoicing suite (app/services/subscription.py).

The platform bills resellers a SaaS subscription — this is real money:
  * 3% of hotspot revenue collected in the billing period
  * KES 25 per ACTIVE PPPoE user
  * KES 500 minimum monthly charge

Pins:
  * charge math in calculate_reseller_charges (inclusions AND exclusions)
  * generate_invoice_for_reseller idempotency + the DB-level
    UniqueConstraint(user_id, period_start) backstop
  * generate_monthly_invoices / generate_pre_expiry_invoices /
    generate_catchup_invoices selection logic (who gets invoiced, who doesn't)
  * record_subscription_payment: activation only on FULL invoice payment
  * reseller account statement math consistency (see also
    tests/test_payout_balance_sources.py for the canonical balance filters)
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    CollectionMode,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    InvoiceStatus,
    PaymentMethod,
    PaymentStatus,
    Subscription,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    SubscriptionStatus,
)
from app.services.subscription import (
    GRACE_PERIOD_DAYS,
    HOTSPOT_RATE,
    MINIMUM_CHARGE,
    PPPOE_PER_USER,
    PRE_EXPIRY_DAYS,
    calculate_reseller_charges,
    generate_catchup_invoices,
    generate_invoice_for_reseller,
    generate_monthly_invoices,
    generate_pre_expiry_invoices,
    record_subscription_payment,
)
from tests.factories import make_customer, make_plan, make_reseller


PERIOD_START = datetime(2026, 6, 1)
PERIOD_END = datetime(2026, 7, 1)
IN_PERIOD = datetime(2026, 6, 15, 12, 0, 0)


async def _add_payment(
    db,
    reseller,
    customer,
    amount,
    *,
    created_at=IN_PERIOD,
    status=PaymentStatus.COMPLETED,
    counts_as_revenue=True,
    collection_mode=CollectionMode.SYSTEM_COLLECTED,
):
    payment = CustomerPayment(
        customer_id=customer.id if customer else None,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_date=created_at,
        created_at=created_at,
        days_paid_for=30,
        status=status,
        counts_as_revenue=counts_as_revenue,
        collection_mode=collection_mode,
    )
    db.add(payment)
    await db.commit()
    return payment


async def _invoice_count(db, user_id):
    return (
        await db.execute(
            select(func.count(SubscriptionInvoice.id)).where(
                SubscriptionInvoice.user_id == user_id
            )
        )
    ).scalar()


# ---------------------------------------------------------------------------
# calculate_reseller_charges — the money formula
# ---------------------------------------------------------------------------

async def test_charges_hotspot_percent_plus_pppoe_per_user(db):
    reseller = await make_reseller(db)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    pppoe_plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)

    hot_cust = await make_customer(db, reseller, hotspot_plan)
    await _add_payment(db, reseller, hot_cust, 15000.0)
    await _add_payment(db, reseller, hot_cust, 5000.0)

    for _ in range(4):
        await make_customer(
            db, reseller, pppoe_plan, status=CustomerStatus.ACTIVE
        )

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["hotspot_revenue"] == 20000.0
    assert charges["hotspot_charge"] == round(20000.0 * HOTSPOT_RATE, 2)  # 600
    assert charges["pppoe_user_count"] == 4
    assert charges["pppoe_charge"] == 4 * PPPOE_PER_USER  # 100
    assert charges["gross_charge"] == 700.0
    assert charges["final_charge"] == 700.0  # above the minimum, so no bump


async def test_charges_minimum_charge_floor(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    cust = await make_customer(db, reseller, plan)
    await _add_payment(db, reseller, cust, 1000.0)  # 3% = 30 << 500

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["gross_charge"] == 30.0
    assert charges["final_charge"] == MINIMUM_CHARGE


async def test_charges_exclude_non_qualifying_payments(db):
    """Hotspot revenue counts only COMPLETED + counts_as_revenue payments made
    inside [period_start, period_end) by customers whose plan is HOTSPOT."""
    reseller = await make_reseller(db)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    pppoe_plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    hot_cust = await make_customer(db, reseller, hotspot_plan)
    ppp_cust = await make_customer(db, reseller, pppoe_plan)

    await _add_payment(db, reseller, hot_cust, 10000.0)  # the only qualifying row
    await _add_payment(db, reseller, hot_cust, 900.0, status=PaymentStatus.FAILED)
    await _add_payment(db, reseller, hot_cust, 800.0, status=PaymentStatus.PENDING)
    await _add_payment(db, reseller, hot_cust, 700.0, counts_as_revenue=False)
    await _add_payment(
        db, reseller, hot_cust, 600.0, created_at=PERIOD_START - timedelta(seconds=1)
    )
    await _add_payment(db, reseller, hot_cust, 500.0, created_at=PERIOD_END)
    # PPPoE customers are billed per-user, not per-revenue
    await _add_payment(db, reseller, ppp_cust, 400.0)

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["hotspot_revenue"] == 10000.0
    assert charges["hotspot_charge"] == 300.0


async def test_charges_pppoe_counts_only_active_pppoe_customers(db):
    reseller = await make_reseller(db)
    pppoe_plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)

    await make_customer(db, reseller, pppoe_plan, status=CustomerStatus.ACTIVE)
    await make_customer(db, reseller, pppoe_plan, status=CustomerStatus.INACTIVE)
    await make_customer(db, reseller, pppoe_plan, status=CustomerStatus.PENDING)
    # ACTIVE hotspot customer must not be billed the PPPoE per-user fee
    await make_customer(db, reseller, hotspot_plan, status=CustomerStatus.ACTIVE)

    charges = await calculate_reseller_charges(db, reseller.id, PERIOD_START, PERIOD_END)

    assert charges["pppoe_user_count"] == 1
    assert charges["pppoe_charge"] == PPPOE_PER_USER


# ---------------------------------------------------------------------------
# generate_invoice_for_reseller — idempotency + constraint backstop
# ---------------------------------------------------------------------------

async def test_invoice_generated_with_correct_fields(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    cust = await make_customer(db, reseller, plan)
    await _add_payment(db, reseller, cust, 30000.0)

    invoice = await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()

    assert invoice is not None
    assert invoice.user_id == reseller.id
    assert invoice.period_start == PERIOD_START
    assert invoice.period_end == PERIOD_END
    assert invoice.hotspot_revenue == 30000.0
    assert invoice.hotspot_charge == 900.0
    assert invoice.final_charge == 900.0
    assert invoice.status == InvoiceStatus.PENDING
    assert invoice.due_date == PERIOD_END + timedelta(days=GRACE_PERIOD_DAYS)


async def test_duplicate_generation_same_user_period_is_noop(db):
    reseller = await make_reseller(db)

    first = await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()
    second = await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()

    assert first is not None
    assert second is None
    assert await _invoice_count(db, reseller.id) == 1


async def test_db_unique_constraint_blocks_duplicate_user_period(db):
    """uq_subscription_invoice_user_period is the last line of defense if two
    jobs race past the SELECT-then-INSERT check in generate_invoice_for_reseller."""
    reseller = await make_reseller(db)
    await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()

    db.add(
        SubscriptionInvoice(
            user_id=reseller.id,
            period_start=PERIOD_START,
            period_end=PERIOD_END,
            final_charge=500.0,
            status=InvoiceStatus.PENDING,
            due_date=PERIOD_END,
        )
    )
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_same_period_start_different_reseller_both_invoiced(db):
    r1 = await make_reseller(db)
    r2 = await make_reseller(db)

    inv1 = await generate_invoice_for_reseller(db, r1.id, PERIOD_START, PERIOD_END)
    inv2 = await generate_invoice_for_reseller(db, r2.id, PERIOD_START, PERIOD_END)
    await db.commit()

    assert inv1 is not None and inv2 is not None


# ---------------------------------------------------------------------------
# generate_monthly_invoices — previous-calendar-month batch
# ---------------------------------------------------------------------------

def _previous_month_bounds(now):
    if now.month == 1:
        return datetime(now.year - 1, 12, 1), datetime(now.year, 1, 1)
    return datetime(now.year, now.month - 1, 1), datetime(now.year, now.month, 1)


async def test_monthly_invoices_only_active_and_trial_resellers(db):
    active = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    trial = await make_reseller(db, subscription_status=SubscriptionStatus.TRIAL)
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    inactive = await make_reseller(db, subscription_status=SubscriptionStatus.INACTIVE)

    result = await generate_monthly_invoices(db)

    assert result["created"] == 2
    assert result["errors"] == []
    assert await _invoice_count(db, active.id) == 1
    assert await _invoice_count(db, trial.id) == 1
    assert await _invoice_count(db, suspended.id) == 0
    assert await _invoice_count(db, inactive.id) == 0

    expected_start, expected_end = _previous_month_bounds(datetime.utcnow())
    invoice = (
        await db.execute(
            select(SubscriptionInvoice).where(SubscriptionInvoice.user_id == active.id)
        )
    ).scalar_one()
    assert invoice.period_start == expected_start
    assert invoice.period_end == expected_end
    assert invoice.final_charge == MINIMUM_CHARGE  # no usage -> minimum charge


async def test_monthly_invoices_second_run_skips_not_duplicates(db):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)

    first = await generate_monthly_invoices(db)
    second = await generate_monthly_invoices(db)

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["skipped"] == 1
    assert await _invoice_count(db, reseller.id) == 1


# ---------------------------------------------------------------------------
# generate_pre_expiry_invoices — daily selection window
# ---------------------------------------------------------------------------

async def test_pre_expiry_invoices_reseller_expiring_soon(db):
    now = datetime.utcnow()
    reseller = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now + timedelta(days=3),
    )
    sub_start = now - timedelta(days=27)
    db.add(
        Subscription(
            user_id=reseller.id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=sub_start,
            current_period_end=reseller.subscription_expires_at,
        )
    )
    await db.commit()

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 1
    invoice = (
        await db.execute(
            select(SubscriptionInvoice).where(SubscriptionInvoice.user_id == reseller.id)
        )
    ).scalar_one()
    # period_start falls back to the subscription's current_period_start when
    # there is no prior invoice; due date is the subscription expiry itself.
    assert invoice.period_start == sub_start
    assert invoice.due_date == reseller.subscription_expires_at
    assert invoice.period_end <= datetime.utcnow()


async def test_pre_expiry_selection_windows(db):
    now = datetime.utcnow()
    far_future = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now + timedelta(days=PRE_EXPIRY_DAYS + 10),
    )
    recently_expired = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now - timedelta(days=2),
    )
    long_expired = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now - timedelta(days=PRE_EXPIRY_DAYS + 5),
    )
    suspended = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.SUSPENDED,
        subscription_expires_at=now + timedelta(days=1),
    )
    no_expiry = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=None,
    )

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 1
    assert await _invoice_count(db, recently_expired.id) == 1  # look-back sweep
    assert await _invoice_count(db, far_future.id) == 0  # daily job's future work
    assert await _invoice_count(db, long_expired.id) == 0  # outside look-back
    assert await _invoice_count(db, suspended.id) == 0  # not active/trial
    assert await _invoice_count(db, no_expiry.id) == 0  # no expiry anchor


async def test_pre_expiry_skips_reseller_with_pending_invoice(db):
    now = datetime.utcnow()
    reseller = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now + timedelta(days=2),
    )
    await generate_invoice_for_reseller(
        db, reseller.id, now - timedelta(days=30), now - timedelta(days=1)
    )
    await db.commit()

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 0
    assert result["skipped"] == 1
    assert await _invoice_count(db, reseller.id) == 1


async def test_pre_expiry_period_resumes_from_last_invoice(db):
    """Consecutive billing periods must tile with no gap and no overlap:
    the next invoice starts exactly where the last (PAID) one ended."""
    now = datetime.utcnow()
    reseller = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now + timedelta(days=2),
    )
    last_end = now - timedelta(days=10)
    paid = SubscriptionInvoice(
        user_id=reseller.id,
        period_start=now - timedelta(days=40),
        period_end=last_end,
        final_charge=500.0,
        status=InvoiceStatus.PAID,
        due_date=last_end,
        paid_at=last_end,
    )
    db.add(paid)
    await db.commit()

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 1
    new_invoice = (
        await db.execute(
            select(SubscriptionInvoice)
            .where(
                SubscriptionInvoice.user_id == reseller.id,
                SubscriptionInvoice.status == InvoiceStatus.PENDING,
            )
        )
    ).scalar_one()
    assert new_invoice.period_start == last_end


# ---------------------------------------------------------------------------
# generate_catchup_invoices — admin sweep without the look-back restriction
# ---------------------------------------------------------------------------

async def test_catchup_invoices_long_expired_reseller(db):
    """The daily pre-expiry job ignores anyone who expired more than
    PRE_EXPIRY_DAYS ago; catch-up exists precisely to invoice them."""
    now = datetime.utcnow()
    long_expired = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now - timedelta(days=60),
    )

    pre = await generate_pre_expiry_invoices(db)
    assert pre["created"] == 0

    result = await generate_catchup_invoices(db)

    assert result["created"] == 1
    assert await _invoice_count(db, long_expired.id) == 1


async def test_catchup_heals_null_expiry_and_invoices(db):
    reseller = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.TRIAL,
        subscription_expires_at=None,
    )

    result = await generate_catchup_invoices(db)

    assert result["healed"] == 1
    assert result["created"] == 1
    await db.refresh(reseller)
    assert reseller.subscription_expires_at is not None
    invoice = (
        await db.execute(
            select(SubscriptionInvoice).where(SubscriptionInvoice.user_id == reseller.id)
        )
    ).scalar_one()
    assert invoice.due_date == reseller.subscription_expires_at
    assert invoice.final_charge == MINIMUM_CHARGE


async def test_catchup_leaves_comfortably_future_resellers_alone(db):
    now = datetime.utcnow()
    future = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now + timedelta(days=PRE_EXPIRY_DAYS + 20),
    )
    pending_already = await make_reseller(
        db,
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=now - timedelta(days=1),
    )
    await generate_invoice_for_reseller(
        db, pending_already.id, now - timedelta(days=30), now - timedelta(days=1)
    )
    await db.commit()

    result = await generate_catchup_invoices(db)

    assert result["created"] == 0
    assert result["skipped"] == 2
    assert await _invoice_count(db, future.id) == 0
    assert await _invoice_count(db, pending_already.id) == 1


# ---------------------------------------------------------------------------
# record_subscription_payment — activation gated on FULL payment
# ---------------------------------------------------------------------------

async def test_partial_payment_does_not_mark_paid_or_activate(db):
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.SUSPENDED
    )
    invoice = await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()
    assert invoice.final_charge == MINIMUM_CHARGE  # 500

    await record_subscription_payment(
        db, reseller.id, invoice.id, 200.0, payment_reference="PARTIAL-1"
    )
    await db.commit()

    await db.refresh(invoice)
    await db.refresh(reseller)
    assert invoice.status == InvoiceStatus.PENDING
    assert invoice.paid_at is None
    assert reseller.subscription_status == SubscriptionStatus.SUSPENDED


async def test_full_payment_marks_paid_and_activates(db):
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.SUSPENDED
    )
    invoice = await generate_invoice_for_reseller(db, reseller.id, PERIOD_START, PERIOD_END)
    await db.commit()

    await record_subscription_payment(
        db, reseller.id, invoice.id, 200.0, payment_reference="PART-1"
    )
    await record_subscription_payment(
        db, reseller.id, invoice.id, 300.0, payment_reference="PART-2"
    )
    await db.commit()

    await db.refresh(invoice)
    await db.refresh(reseller)
    assert invoice.status == InvoiceStatus.PAID
    assert invoice.paid_at is not None
    assert reseller.subscription_status == SubscriptionStatus.ACTIVE
    assert reseller.subscription_expires_at is not None
    assert reseller.subscription_expires_at > datetime.utcnow() + timedelta(days=27)

    payments = (
        await db.execute(
            select(SubscriptionPayment).where(SubscriptionPayment.user_id == reseller.id)
        )
    ).scalars().all()
    assert all(p.status == SubscriptionPaymentStatus.COMPLETED for p in payments)
    assert sum(p.amount for p in payments) == invoice.final_charge

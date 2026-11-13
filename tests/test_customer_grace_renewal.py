"""Grace never moves the billing date: a payment made during grace extends from
the paid expiry, not from payment time."""

from datetime import datetime, timedelta

from app.db.models import Customer, CustomerStatus, PaymentMethod
from app.services.customer_grace import renewal_expiry
from app.services.outage_compensation import preview_outage_compensation
from app.services.reseller_payments import record_customer_payment
from tests.factories import make_customer, make_plan, make_reseller, make_router


NOW = datetime(2026, 10, 3, 12, 0)
MONTH = timedelta(days=30)


def _customer(expiry, grace_minutes=0):
    return Customer(status=CustomerStatus.ACTIVE, expiry=expiry, grace_period_minutes=grace_minutes)


# --- renewal_expiry --------------------------------------------------------

def test_paid_time_left_extends_from_expiry():
    c = _customer(NOW + timedelta(days=2))
    assert renewal_expiry(c, NOW, MONTH) == NOW + timedelta(days=32)


def test_payment_during_grace_keeps_the_billing_date():
    # Expiry Oct 1, 3-day grace, 30 days paid on Oct 3 -> runs to Oct 31.
    expiry = datetime(2026, 10, 1, 12, 0)
    c = _customer(expiry, grace_minutes=3 * 24 * 60)
    assert renewal_expiry(c, NOW, MONTH) == datetime(2026, 10, 31, 12, 0)


def test_payment_after_grace_ended_starts_from_now():
    c = _customer(NOW - timedelta(days=5), grace_minutes=3 * 24 * 60)
    assert renewal_expiry(c, NOW, MONTH) == NOW + MONTH


def test_no_grace_expired_starts_from_now():
    c = _customer(NOW - timedelta(hours=1))
    assert renewal_expiry(c, NOW, MONTH) == NOW + MONTH


def test_plan_shorter_than_used_grace_starts_from_now():
    # Daily plan bought 2 days into a 3-day grace: expiry + 1 day is already
    # past, so the purchase starts now instead of ending in the past.
    c = _customer(NOW - timedelta(days=2), grace_minutes=3 * 24 * 60)
    assert renewal_expiry(c, NOW, timedelta(days=1)) == NOW + timedelta(days=1)


def test_no_expiry_starts_from_now():
    assert renewal_expiry(_customer(None), NOW, MONTH) == NOW + MONTH


# --- payments --------------------------------------------------------------

async def _pay_30_days(db, reseller, customer):
    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=1500.0,
        payment_method=PaymentMethod.CASH,
        days_paid_for=30,
        payment_reference="grace-renewal-test",
        duration_value=30,
        duration_unit="DAYS",
    )
    await db.refresh(customer)


async def test_payment_in_grace_extends_from_paid_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    paid_expiry = datetime.utcnow().replace(microsecond=0) - timedelta(days=2)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE, expiry=paid_expiry, grace_period_minutes=3 * 24 * 60,
    )

    await _pay_30_days(db, reseller, customer)

    assert customer.expiry == paid_expiry + timedelta(days=30)
    assert customer.status == CustomerStatus.ACTIVE


async def test_payment_after_grace_starts_from_payment_time(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(days=5),
        grace_period_minutes=3 * 24 * 60,
    )

    before = datetime.utcnow()
    await _pay_30_days(db, reseller, customer)

    assert before + timedelta(days=30) <= customer.expiry <= datetime.utcnow() + timedelta(days=30)


# --- outage compensation ---------------------------------------------------

async def test_outage_credit_for_in_grace_customer_extends_paid_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    start, end = now - timedelta(hours=6), now - timedelta(hours=2)
    # Paid time ran out an hour into the outage; still connected on grace.
    paid_expiry = start + timedelta(hours=1)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=paid_expiry,
        grace_period_minutes=24 * 60,
        created_at=now - timedelta(days=30),
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    assert result["skipped_expired"] == []
    assert result["total_customers"] == 1
    row = result["customers"][0]
    assert row["customer_id"] == customer.id
    # Only the paid hour inside the outage is owed, added to the paid expiry.
    assert row["credited_seconds"] == 3600
    assert row["new_expiry"] == (paid_expiry + timedelta(hours=1)).isoformat()

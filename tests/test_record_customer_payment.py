"""
Regression tests for `record_customer_payment` — the function both the STK
callback (payment_routes.py:383) and the reconciliation worker
(mpesa_transactions.py:445) call to extend a customer's expiry after payment.

If any future change shifts the expiry math, the status transition, or the
financial summary side-effect, these tests fail.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    PaymentMethod,
    PaymentStatus,
    ResellerFinancials,
)
from app.services.reseller_payments import record_customer_payment
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_extends_expiry_for_new_customer(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=30, duration_unit=DurationUnit.DAYS, price=500)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.PENDING,
        expiry=None,
    )

    before = datetime.utcnow()
    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=500.0,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=30,
        duration_value=30,
        duration_unit="DAYS",
    )

    await db.refresh(customer)
    expected_min = before + timedelta(days=30) - timedelta(seconds=5)
    expected_max = datetime.utcnow() + timedelta(days=30) + timedelta(seconds=5)

    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry is not None
    assert expected_min <= customer.expiry <= expected_max
    assert payment.amount == 500.0
    assert payment.payment_method == PaymentMethod.MOBILE_MONEY
    assert payment.customer_id == customer.id
    assert payment.reseller_id == reseller.id


async def test_renewal_stacks_on_existing_expiry(db):
    """An active customer paying again should ADD time on top of remaining time,
    not reset to now+duration. This is load-bearing for renewals."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=7, duration_unit=DurationUnit.DAYS)
    router = await make_router(db, reseller)

    starting_expiry = datetime.utcnow() + timedelta(days=3)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=starting_expiry,
    )

    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=plan.price,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=7,
        duration_value=7,
        duration_unit="DAYS",
    )

    await db.refresh(customer)
    expected = starting_expiry + timedelta(days=7)
    # Allow a generous second-level tolerance for any rounding
    assert abs((customer.expiry - expected).total_seconds()) < 2


async def test_expired_customer_starts_fresh_from_now(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=1, duration_unit=DurationUnit.DAYS)
    router = await make_router(db, reseller)

    expired = datetime.utcnow() - timedelta(days=2)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE,
        expiry=expired,
    )

    before = datetime.utcnow()
    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=plan.price,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=1,
        duration_value=1,
        duration_unit="DAYS",
    )
    await db.refresh(customer)

    # Should be ~now + 1 day, NOT (expired + 1 day)
    assert customer.expiry > before + timedelta(days=1) - timedelta(seconds=5)
    assert customer.expiry < datetime.utcnow() + timedelta(days=1) + timedelta(seconds=5)
    assert customer.status == CustomerStatus.ACTIVE


async def test_writes_customer_payment_row_with_snapshot(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, name="Jane Doe")

    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=500.0,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=30,
        payment_reference="RJ7T8K9MNP",
        notes="STK Push test",
        duration_value=30,
        duration_unit="DAYS",
    )

    rows = (await db.execute(select(CustomerPayment))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.customer_name == "Jane Doe"
    assert row.payment_reference == "RJ7T8K9MNP"
    assert row.notes == "STK Push test"
    assert row.status == PaymentStatus.COMPLETED


async def test_updates_reseller_financials(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    c1 = await make_customer(db, reseller, plan, router, name="A", mac_address="AA:11:11:11:11:11")
    c2 = await make_customer(db, reseller, plan, router, name="B", mac_address="BB:22:22:22:22:22")

    for c, amount in [(c1, 500.0), (c2, 300.0)]:
        await record_customer_payment(
            db=db,
            customer_id=c.id,
            reseller_id=reseller.id,
            amount=amount,
            payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=30,
            duration_value=30,
            duration_unit="DAYS",
        )

    fin = (
        await db.execute(select(ResellerFinancials).where(ResellerFinancials.user_id == reseller.id))
    ).scalar_one()
    assert fin.total_revenue == 800.0
    assert fin.total_customers == 2
    assert fin.active_customers == 2
    assert fin.last_payment_date is not None


async def test_rejects_payment_for_customer_owned_by_different_reseller(db):
    reseller_a = await make_reseller(db)
    reseller_b = await make_reseller(db)
    plan = await make_plan(db, reseller_a)
    router = await make_router(db, reseller_a)
    customer = await make_customer(db, reseller_a, plan, router)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await record_customer_payment(
            db=db,
            customer_id=customer.id,
            reseller_id=reseller_b.id,  # wrong owner
            amount=500.0,
            payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=30,
        )
    assert exc.value.status_code == 404

"""
TDD tests: the transactions list must show the plan that was purchased in
each transaction, not the customer's *current* plan.

Bug: /api/mpesa/transactions joined Plan via Customer.plan_id, so every
historical row silently updated to whatever plan the customer bought last.

Fix: snapshot plan_id onto MpesaTransaction / CustomerPayment at creation
time and prefer it when serializing; legacy rows (plan_id NULL) fall back
to the customer's current plan.
"""

from types import SimpleNamespace

import pytest

from app.db.models import (
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _list_transactions(db, monkeypatch, reseller, **kwargs):
    from app.api import payment_routes

    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", fake_current_user)

    return await payment_routes.get_mpesa_transactions(
        router_id=kwargs.get("router_id"),
        payment_method=kwargs.get("payment_method"),
        date=None,
        start_date=None,
        end_date=None,
        status=None,
        limit=200,
        offset=0,
        db=db,
        token="test-token",
    )


async def _setup(db):
    """Reseller with two plans; customer currently on plan_current."""
    reseller = await make_reseller(db)
    plan_bought = await make_plan(db, reseller, price=10, duration_value=2, name="2 Hrs")
    plan_current = await make_plan(db, reseller, price=30, duration_value=12, name="12 Hrs")
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan_current, router,
        mac_address="AA:BB:CC:DD:EE:01",
    )
    return reseller, plan_bought, plan_current, router, customer


async def test_mpesa_row_shows_purchased_plan_not_current(db, monkeypatch):
    reseller, plan_bought, plan_current, router, customer = await _setup(db)

    tx = MpesaTransaction(
        checkout_request_id="ws_CO_TEST_1",
        phone_number=customer.phone,
        amount=10.0,
        reference=f"HOTSPOT-{customer.id}-20260101000000",
        customer_id=customer.id,
        status=MpesaTransactionStatus.completed,
        plan_id=plan_bought.id,  # snapshot of what was actually bought
    )
    db.add(tx)
    await db.commit()

    rows = await _list_transactions(db, monkeypatch, reseller)
    row = next(r for r in rows if r["checkout_request_id"] == "ws_CO_TEST_1")
    assert row["plan"] is not None
    assert row["plan"]["id"] == plan_bought.id, (
        f"Expected purchased plan {plan_bought.id} ('2 Hrs'), "
        f"got {row['plan']['id']} ('{row['plan']['name']}')"
    )


async def test_legacy_mpesa_row_falls_back_to_customer_plan(db, monkeypatch):
    reseller, plan_bought, plan_current, router, customer = await _setup(db)

    tx = MpesaTransaction(
        checkout_request_id="ws_CO_LEGACY_1",
        phone_number=customer.phone,
        amount=30.0,
        reference=f"HOTSPOT-{customer.id}-20260101000001",
        customer_id=customer.id,
        status=MpesaTransactionStatus.completed,
        plan_id=None,  # legacy row created before the snapshot column
    )
    db.add(tx)
    await db.commit()

    rows = await _list_transactions(db, monkeypatch, reseller)
    row = next(r for r in rows if r["checkout_request_id"] == "ws_CO_LEGACY_1")
    assert row["plan"] is not None
    assert row["plan"]["id"] == plan_current.id


async def test_customer_payment_row_shows_purchased_plan(db, monkeypatch):
    reseller, plan_bought, plan_current, router, customer = await _setup(db)

    pay = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=10.0,
        payment_method=PaymentMethod.CASH,
        payment_reference="VOUCHER-1",
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        plan_id=plan_bought.id,
    )
    db.add(pay)
    await db.commit()

    rows = await _list_transactions(db, monkeypatch, reseller, payment_method="cash")
    row = next(r for r in rows if r["payment_reference"] == "VOUCHER-1")
    assert row["plan"] is not None
    assert row["plan"]["id"] == plan_bought.id


async def test_record_customer_payment_snapshots_current_plan(db):
    """The service that records payments must stamp the customer's plan at
    payment time so later plan switches don't rewrite history."""
    from app.services.reseller_payments import record_customer_payment

    reseller, plan_bought, plan_current, router, customer = await _setup(db)

    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=30.0,
        payment_method=PaymentMethod.CASH,
        days_paid_for=1,
    )
    assert payment.plan_id == plan_current.id

    # Customer later switches plans — the recorded payment must not change.
    customer.plan_id = plan_bought.id
    await db.commit()
    await db.refresh(payment)
    assert payment.plan_id == plan_current.id

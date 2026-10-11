"""
A paybill payment below the plan price is held as AMOUNT_TOO_LOW. When the
reseller then moves the customer to a plan the payment covers and activates
them by hand, the activation must consume that held M-Pesa payment, not write
a CASH row. Otherwise the money never reaches the reseller's payout balance
and the unmatched row sits in the queue, where attributing it later would
grant a second period.

Regression for prod 2026-10-11 (customer 28802, trans UJBEGA3QSE).
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import BackgroundTasks
from sqlalchemy import select

from app.api import customer_routes
from app.config import settings
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CollectionMode,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    PaymentMethod,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
)
from app.services import pppoe_provisioning
from app.services.account_numbers import luhn_check_digit
from app.services.c2b_handler import handle_confirmation
from app.services.mpesa_b2b import get_unpaid_balance
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _stub_router_calls(monkeypatch):
    async def _noop(*args, **kwargs):
        return {"ok": True}

    async def _provision(payload):
        return {"success": True}

    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", _provision)


async def _seed(db, *, wallet=0):
    reseller = await make_reseller(db)
    pricey = await make_plan(
        db, reseller, price=1500, duration_value=31,
        duration_unit=DurationUnit.DAYS, connection_type=ConnectionType.PPPOE,
    )
    cheap = await make_plan(
        db, reseller, price=1000, duration_value=31,
        duration_unit=DurationUnit.DAYS, connection_type=ConnectionType.PPPOE,
    )
    router = await make_router(db, reseller)
    base = "6440968"
    customer = await make_customer(
        db, reseller, pricey, router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(days=1),
        mac_address=None,
        pppoe_username="BEN",
        pppoe_password="secret",
        name="Ben",
        account_number=base + luhn_check_digit(base),
        wallet_credit_kes=wallet,
    )
    return reseller, pricey, cheap, customer


async def _pay(db, customer, trans_id, amount):
    payload = {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20261011062855",
        "TransAmount": str(amount),
        "BusinessShortCode": settings.MPESA_SHORTCODE,
        "BillRefNumber": customer.account_number,
        "MSISDN": "254700000000",
    }
    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        await handle_confirmation(payload, db, background_tasks=BackgroundTasks())


async def _activate(db, monkeypatch, reseller, customer, **kwargs):
    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)
    return await customer_routes.activate_pppoe_customer(
        customer.id,
        customer_routes.ActivatePPPoERequest(**kwargs),
        db,
        "token",
    )


async def _move_to_plan(db, customer, plan):
    customer.plan_id = plan.id
    await db.commit()
    await db.refresh(customer, attribute_names=["plan"])


async def _payments(session_factory, customer_id):
    async with session_factory() as s:
        return (
            await s.execute(
                select(CustomerPayment)
                .where(CustomerPayment.customer_id == customer_id)
                .order_by(CustomerPayment.id)
            )
        ).scalars().all()


async def test_activation_after_downgrade_consumes_held_mpesa(db, session_factory, monkeypatch):
    reseller, _, cheap, customer = await _seed(db)
    await _pay(db, customer, "UJBEGA3QSE", 1000)

    async with session_factory() as s:
        um = (await s.execute(select(UnmatchedC2BPayment))).scalar_one()
        assert um.reason == UnmatchedC2BReason.AMOUNT_TOO_LOW
    assert await get_unpaid_balance(db, reseller.id) == 0

    await _move_to_plan(db, customer, cheap)
    response = await _activate(db, monkeypatch, reseller, customer, payment_method="cash")

    assert response["held_mpesa_applied"] == "UJBEGA3QSE"

    payments = await _payments(session_factory, customer.id)
    assert len(payments) == 1
    p = payments[0]
    assert p.payment_method == PaymentMethod.MOBILE_MONEY
    assert p.payment_reference == "UJBEGA3QSE"
    assert p.collection_mode == CollectionMode.SYSTEM_COLLECTED
    assert float(p.amount) == 1000
    assert p.router_id == customer.router_id
    assert p.days_paid_for == 31

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction))).scalar_one()
        assert txn.status == C2BTransactionStatus.PROCESSED
        assert txn.matched_customer_id == customer.id
        um = (await s.execute(select(UnmatchedC2BPayment))).scalar_one()
        assert um.resolved_at is not None
        assert um.resolved_by_user_id == reseller.id
        assert um.resolution_customer_id == customer.id
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.wallet_credit_kes == 0

    assert await get_unpaid_balance(db, reseller.id) == 1000


async def test_held_payment_is_used_once_second_activation_is_cash(db, session_factory, monkeypatch):
    reseller, _, cheap, customer = await _seed(db)
    await _pay(db, customer, "UJHELD0001", 1000)
    await _move_to_plan(db, customer, cheap)

    first = await _activate(db, monkeypatch, reseller, customer)
    second = await _activate(db, monkeypatch, reseller, customer)

    assert first["held_mpesa_applied"] == "UJHELD0001"
    assert second["held_mpesa_applied"] is None
    methods = [p.payment_method for p in await _payments(session_factory, customer.id)]
    assert methods == [PaymentMethod.MOBILE_MONEY, PaymentMethod.CASH]


async def test_hold_kept_when_plan_still_costs_more(db, session_factory, monkeypatch):
    reseller, _, _, customer = await _seed(db)
    await _pay(db, customer, "UJHELD0002", 1000)

    response = await _activate(db, monkeypatch, reseller, customer)

    assert response["held_mpesa_applied"] is None
    payments = await _payments(session_factory, customer.id)
    assert [p.payment_method for p in payments] == [PaymentMethod.CASH]
    async with session_factory() as s:
        um = (await s.execute(select(UnmatchedC2BPayment))).scalar_one()
        assert um.resolved_at is None


async def test_wallet_tops_up_held_payment_and_is_drained(db, session_factory, monkeypatch):
    # 900 held + 200 wallet covers the 1000 plan; 100 stays on the wallet.
    reseller, _, cheap, customer = await _seed(db, wallet=200)
    await _pay(db, customer, "UJHELD0003", 900)
    await _move_to_plan(db, customer, cheap)

    response = await _activate(db, monkeypatch, reseller, customer)

    assert response["held_mpesa_applied"] == "UJHELD0003"
    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.wallet_credit_kes == 100


async def test_explicit_reference_or_opt_out_skips_held_payment(db, session_factory, monkeypatch):
    reseller, _, cheap, customer = await _seed(db)
    await _pay(db, customer, "UJHELD0004", 1000)
    await _move_to_plan(db, customer, cheap)

    with_ref = await _activate(
        db, monkeypatch, reseller, customer,
        payment_method="mobile_money", payment_reference="OTHERREF1",
    )
    opted_out = await _activate(db, monkeypatch, reseller, customer, use_held_mpesa=False)

    assert with_ref["held_mpesa_applied"] is None
    assert opted_out["held_mpesa_applied"] is None
    async with session_factory() as s:
        um = (await s.execute(select(UnmatchedC2BPayment))).scalar_one()
        assert um.resolved_at is None

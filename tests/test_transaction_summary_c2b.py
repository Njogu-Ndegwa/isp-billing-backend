"""Paybill (C2B) payments count in the transactions summary.

A processed paybill payment writes a c2b_transactions row plus a
MOBILE_MONEY customer_payments twin. The summary skips that twin as a
duplicate, so it must read the C2B row itself, or the payment drops out of
the PPPoE/hotspot tiles, the totals and "Collected by Bitwave".
"""
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api import payment_routes
from app.config import settings
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CollectionMode,
    ConnectionType,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _summary(db, monkeypatch, reseller, **kwargs):
    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)
    params = dict(router_id=None, payment_method=None, date=None,
                  start_date=None, end_date=None)
    params.update(kwargs)
    return await payment_routes.get_mpesa_transactions_summary(
        **params, db=db, token="test-token",
    )


async def _seed(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=1000, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(db, reseller, plan, router)
    received = datetime(2026, 11, 10, 20, 5, 44)

    def paybill(trans_id, amount, status, shortcode=settings.MPESA_SHORTCODE):
        db.add(C2BTransaction(
            trans_id=trans_id, bill_ref_number=customer.phone, trans_amount=amount,
            business_shortcode=str(shortcode), status=status,
            matched_customer_id=customer.id, matched_reseller_id=reseller.id,
            received_at=received,
        ))

    paybill("C2BOK1", 1000.0, C2BTransactionStatus.PROCESSED)
    # The customer_payments twin the C2B handler writes; must not double count.
    db.add(CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id, amount=1000.0,
        payment_method=PaymentMethod.MOBILE_MONEY, payment_reference="C2BOK1",
        days_paid_for=30, plan_id=plan.id, status=PaymentStatus.COMPLETED,
        collection_mode=CollectionMode.SYSTEM_COLLECTED, created_at=received,
    ))
    # Not sales: an STK echo (already counted via STK) and an unmatched payment.
    paybill("C2BECHO", 500.0, C2BTransactionStatus.STK_ECHO)
    paybill("C2BUNM", 300.0, C2BTransactionStatus.UNMATCHED)
    # A paybill payment to the reseller's own shortcode settles directly.
    paybill("C2BOWN", 200.0, C2BTransactionStatus.PROCESSED, shortcode="999111")
    await db.commit()
    return reseller, router


async def test_paybill_payment_counts_in_summary(db, monkeypatch):
    reseller, _ = await _seed(db)

    result = await _summary(db, monkeypatch, reseller)

    assert result["connection_type_breakdown"]["pppoe"] == {"count": 2, "amount": 1200.0}
    assert result["settlement_breakdown"]["platform"] == {"count": 1, "amount": 1000.0}
    assert result["settlement_breakdown"]["direct"] == {"count": 1, "amount": 200.0}
    assert result["total_transactions"] == 2
    assert result["total_amount"] == 1200.0
    assert result["method_breakdown"]["mobile_money"] == {"count": 2, "amount": 1200.0}


async def test_paybill_summary_respects_date_and_router_filters(db, monkeypatch):
    reseller, router = await _seed(db)

    november = await _summary(db, monkeypatch, reseller,
                              start_date="2026-11-01", end_date="2026-11-30")
    assert november["total_amount"] == 1200.0

    october = await _summary(db, monkeypatch, reseller,
                             start_date="2026-10-01", end_date="2026-10-31")
    assert october["total_amount"] == 0

    other_router = await _summary(db, monkeypatch, reseller, router_id=router.id + 999)
    assert other_router["total_amount"] == 0

    this_router = await _summary(db, monkeypatch, reseller, router_id=router.id)
    assert this_router["total_amount"] == 1200.0


async def test_paybill_payment_of_another_reseller_is_not_counted(db, monkeypatch):
    await _seed(db)
    other = await make_reseller(db, email="other-c2b@example.com")

    result = await _summary(db, monkeypatch, other)

    assert result["total_transactions"] == 0
    assert result["connection_type_breakdown"]["pppoe"]["amount"] == 0

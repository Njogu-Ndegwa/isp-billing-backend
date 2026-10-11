from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import payment_routes
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    OutageCompensation,
    OutageCompensationItem,
    PaymentMethod,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


def _as(monkeypatch, reseller):
    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)


async def _list(db, **filters):
    params = dict(
        router_id=None,
        customer_id=None,
        payment_method=None,
        date=None,
        start_date=None,
        end_date=None,
        status=None,
        limit=200,
        offset=0,
        settlement=None,
    )
    params.update(filters)
    return await payment_routes.get_mpesa_transactions(db=db, token="test-token", **params)


async def _summary(db, **filters):
    params = dict(router_id=None, payment_method=None, date=None, start_date=None, end_date=None)
    params.update(filters)
    return await payment_routes.get_mpesa_transactions_summary(db=db, token="test-token", **params)


async def test_customer_id_filter_returns_only_that_customers_payments(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    neighbour = await make_customer(db, reseller, plan, router)

    db.add_all([
        MpesaTransaction(
            checkout_request_id="mine-mpesa",
            phone_number=customer.phone,
            amount=100,
            reference="mine-mpesa",
            customer_id=customer.id,
            status=MpesaTransactionStatus.completed,
        ),
        MpesaTransaction(
            checkout_request_id="neighbour-mpesa",
            phone_number=neighbour.phone,
            amount=200,
            reference="neighbour-mpesa",
            customer_id=neighbour.id,
            status=MpesaTransactionStatus.completed,
        ),
        CustomerPayment(
            customer_id=customer.id,
            reseller_id=reseller.id,
            amount=50,
            payment_method=PaymentMethod.CASH,
            payment_reference="mine-cash",
            days_paid_for=1,
        ),
        CustomerPayment(
            customer_id=neighbour.id,
            reseller_id=reseller.id,
            amount=75,
            payment_method=PaymentMethod.CASH,
            payment_reference="neighbour-cash",
            days_paid_for=1,
        ),
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    rows = await _list(db, customer_id=customer.id)

    assert sorted(row["reference"] for row in rows) == ["mine-cash", "mine-mpesa"]
    assert {row["customer"]["id"] for row in rows} == {customer.id}


async def test_gateway_mobile_money_rows_are_listed_without_mpesa_twins(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    db.add_all([
        # ZenoPay writes only this row.
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=1000,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_reference="ZENO-abc",
            days_paid_for=1,
        ),
        # STK twin of the mpesa_transactions row below — must not show twice.
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=100,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_reference="SJ123",
            days_paid_for=1,
        ),
        MpesaTransaction(
            checkout_request_id="stk-1", phone_number=customer.phone, amount=100,
            reference="stk-1", mpesa_receipt_number="SJ123", customer_id=customer.id,
            status=MpesaTransactionStatus.completed,
        ),
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=0,
            payment_method=PaymentMethod.CASH, payment_reference="VOUCHER-XYZ",
            days_paid_for=1,
        ),
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    rows = await _list(db, customer_id=customer.id)
    by_ref = {row["payment_reference"]: row for row in rows}
    assert sorted(by_ref) == ["SJ123", "VOUCHER-XYZ", "ZENO-abc"]
    assert by_ref["ZENO-abc"]["source"] == "zenopay"
    assert by_ref["VOUCHER-XYZ"]["source"] == "voucher"
    assert by_ref["SJ123"]["source"] == "mpesa_stk"

    mobile = await _list(db, customer_id=customer.id, payment_method="mobile_money")
    assert sorted(row["payment_reference"] for row in mobile) == ["SJ123", "ZENO-abc"]

    summary = await _summary(db, payment_method="mobile_money")
    assert summary["total_transactions"] == 2
    assert summary["total_amount"] == 1100


async def test_c2b_row_uses_plan_snapshotted_on_its_payment(db, monkeypatch):
    reseller = await make_reseller(db)
    old_plan = await make_plan(db, reseller, price=500, name="Old plan")
    new_plan = await make_plan(db, reseller, price=900, name="New plan")
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, new_plan, router)

    db.add_all([
        C2BTransaction(
            trans_id="QK1", trans_amount=500, status=C2BTransactionStatus.PROCESSED,
            matched_customer_id=customer.id, matched_reseller_id=reseller.id,
        ),
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=500,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_reference="QK1",
            days_paid_for=30, plan_id=old_plan.id,
        ),
    ])
    await db.commit()
    _as(monkeypatch, reseller)

    rows = await _list(db, customer_id=customer.id)
    assert len(rows) == 1
    assert rows[0]["source"] == "c2b_paybill"
    assert rows[0]["plan"]["name"] == "Old plan"
    assert rows[0]["days_paid_for"] == 30


async def test_customer_payment_summary_totals_and_outage_credits(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    now = datetime.utcnow()

    db.add_all([
        MpesaTransaction(
            checkout_request_id="ok", phone_number=customer.phone, amount=100,
            reference="ok", customer_id=customer.id, status=MpesaTransactionStatus.completed,
        ),
        MpesaTransaction(
            checkout_request_id="bad", phone_number=customer.phone, amount=999,
            reference="bad", customer_id=customer.id, status=MpesaTransactionStatus.failed,
        ),
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=50,
            payment_method=PaymentMethod.CASH, payment_reference="cash-1", days_paid_for=1,
            payment_date=now,
        ),
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=30,
            payment_method=PaymentMethod.CASH, payment_reference="VOUCHER-COMP",
            days_paid_for=1, counts_as_revenue=False,
        ),
        # STK twin: already counted through mpesa_transactions.
        CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=100,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_reference="SJ-OK", days_paid_for=1,
        ),
        C2BTransaction(
            trans_id="QK2", trans_amount=200, status=C2BTransactionStatus.PROCESSED,
            matched_customer_id=customer.id, matched_reseller_id=reseller.id,
        ),
        # Underpaid paybill money: archived against the customer, never applied.
        C2BTransaction(
            trans_id="QK3", trans_amount=10, status=C2BTransactionStatus.UNMATCHED,
            matched_customer_id=customer.id, matched_reseller_id=reseller.id,
        ),
    ])
    compensation = OutageCompensation(
        user_id=reseller.id, router_ids=[router.id],
        outage_start=now - timedelta(hours=3), outage_end=now - timedelta(hours=1),
        note="Fibre cut",
    )
    db.add(compensation)
    await db.flush()
    db.add(OutageCompensationItem(
        compensation_id=compensation.id, customer_id=customer.id, seconds_credited=7200,
    ))
    await db.commit()
    _as(monkeypatch, reseller)

    summary = await payment_routes.get_customer_payment_summary(
        customer_id=customer.id, db=db, token="test-token",
    )

    assert summary["total_paid"] == 350
    assert summary["paid_count"] == 3
    assert summary["last_paid_at"] is not None
    assert summary["not_charged_total"] == 30
    assert summary["not_charged_count"] == 1
    assert [c["seconds_credited"] for c in summary["outage_credits"]] == [7200]
    assert summary["outage_credits"][0]["note"] == "Fibre cut"


async def test_customer_payment_summary_hides_other_resellers_customers(db, monkeypatch):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, other)
    router = await make_router(db, other)
    customer = await make_customer(db, other, plan, router)
    _as(monkeypatch, reseller)

    with pytest.raises(HTTPException) as exc:
        await payment_routes.get_customer_payment_summary(
            customer_id=customer.id, db=db, token="test-token",
        )
    assert exc.value.status_code == 404

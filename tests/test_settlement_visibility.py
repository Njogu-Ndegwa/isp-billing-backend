"""Resellers can tell direct-settled M-Pesa from platform-collected M-Pesa.

  * every M-Pesa row on /api/mpesa/transactions carries ``settlement``
    ('direct' | 'platform') and ``?settlement=`` filters on it;
  * the summary splits completed M-Pesa by settlement;
  * the account statement reports money received directly alongside the
    balance the platform holds (which never includes direct money).
"""

from datetime import datetime

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.customer_routes as cr
import app.api.dashboard_routes as dr
import app.api.payment_routes as pr
from app.db.database import get_db
from app.db.models import (
    CollectionMode,
    Customer,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
)
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_admin_reseller_deletion import _create_radius_tables

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(pr.router)
    application.include_router(dr.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(pr, "get_current_user", _fake)
    monkeypatch.setattr(dr, "get_current_user", _fake)


async def _seed(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=50)
    customer = await make_customer(db, reseller, plan=plan, router=router)
    for i, (mode, amount) in enumerate((
        (CollectionMode.DIRECT, 50.0),
        (CollectionMode.DIRECT, 20.0),
        (CollectionMode.SYSTEM_COLLECTED, 30.0),
        (None, 10.0),  # legacy row: platform
    )):
        db.add(MpesaTransaction(
            checkout_request_id=f"ws_CO_vis_{i}", phone_number="254700000000",
            amount=amount, reference=f"R{i}", customer_id=customer.id, plan_id=plan.id,
            status=MpesaTransactionStatus.completed, collection_mode=mode,
            mpesa_receipt_number=f"RCPT{i}", created_at=datetime.utcnow(),
        ))
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=amount,
            payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
            status=PaymentStatus.COMPLETED, collection_mode=mode,
            payment_reference=f"RCPT{i}",
        ))
    await db.commit()
    return reseller


def _rows(body):
    return body["data"] if isinstance(body, dict) and "data" in body else body


async def test_transactions_carry_and_filter_by_settlement(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    rows = _rows((await client.get("/api/mpesa/transactions")).json())
    by_ref = {r["mpesa_receipt_number"]: r["settlement"] for r in rows if r["payment_method"] == "mobile_money"}
    assert by_ref == {"RCPT0": "direct", "RCPT1": "direct", "RCPT2": "platform", "RCPT3": "platform"}

    direct = _rows((await client.get("/api/mpesa/transactions?settlement=direct")).json())
    assert {r["mpesa_receipt_number"] for r in direct} == {"RCPT0", "RCPT1"}
    platform = _rows((await client.get("/api/mpesa/transactions?settlement=platform")).json())
    assert {r["mpesa_receipt_number"] for r in platform} == {"RCPT2", "RCPT3"}

    assert (await client.get("/api/mpesa/transactions?settlement=bogus")).status_code == 400


async def test_summary_splits_by_settlement(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    summary = (await client.get("/api/mpesa/transactions/summary")).json()
    assert summary["settlement_breakdown"] == {
        "direct": {"count": 2, "amount": 70.0},
        "platform": {"count": 2, "amount": 40.0},
    }


async def test_account_statement_shows_both_halves(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/reseller/account-statement")).json()
    assert body["balance"]["total_direct_received"] == 70.0
    assert body["balance"]["total_system_collected"] == 40.0
    assert body["balance"]["unpaid_balance"] == 40.0
    assert body["period_summary"]["direct_received"] == 70.0
    assert body["period_summary"]["system_collected"] == 40.0


async def test_deleted_customer_payments_stay_in_transactions_and_dashboard(db, client, monkeypatch):
    await _create_radius_tables(db)
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)
    customer = (await db.execute(select(Customer).where(Customer.user_id == reseller.id))).scalar_one()
    router_id = customer.router_id
    payments = (await db.execute(select(CustomerPayment).order_by(CustomerPayment.id))).scalars().all()
    for i, payment in enumerate(payments):
        # Match by original checkout ID even when no receipt was recorded.
        payment.notes = f"M-Pesa STK Push. TX: ws_CO_vis_{i}"
    payments[0].payment_reference = None
    archived = CustomerPayment(
        reseller_id=reseller.id, router_id=router_id, plan_id=customer.plan_id,
        amount=10, days_paid_for=1, payment_method=PaymentMethod.MOBILE_MONEY,
        status=PaymentStatus.COMPLETED, collection_mode=CollectionMode.DIRECT,
        payment_reference="ARCHIVED10", notes="M-Pesa STK Push. TX: ws_CO_removed",
    )
    db.add(archived)
    await db.commit()

    assert (await cr._delete_customer_row(customer.id, db, reseller))["success"]
    retained = (await db.execute(select(MpesaTransaction))).scalars().all()
    assert len(retained) == 4
    assert all(tx.customer_id is None and tx.router_id == router_id for tx in retained)
    assert all(tx.reseller_id == reseller.id for tx in retained)

    transactions = await client.get(f"/api/mpesa/transactions?router_id={router_id}&settlement=direct")
    direct_rows = _rows(transactions.json())
    direct = {r["mpesa_receipt_number"]: r for r in direct_rows}
    assert direct.keys() == {"RCPT0", "RCPT1", "ARCHIVED10"}
    assert len(direct_rows) == 3
    assert direct["ARCHIVED10"]["amount"] == 10
    assert direct["ARCHIVED10"]["manual_provision_supported"] is False

    summary = (await client.get(f"/api/mpesa/transactions/summary?router_id={router_id}")).json()
    assert summary["settlement_breakdown"]["direct"] == {"count": 3, "amount": 80.0}

    overview = (await client.get(f"/api/dashboard/overview?router_id={router_id}")).json()
    assert overview["revenue"]["all_time"] == 120
    assert overview["revenue_by_router"][0]["transaction_count"] == 5
    assert archived.id in {p["payment_id"] for p in overview["recent_transactions"]}

    analytics = (await client.get(f"/api/dashboard/analytics?router_id={router_id}")).json()
    assert analytics["summary"]["totalRevenue"] == 120
    assert analytics["summary"]["totalTransactions"] == 5
    assert analytics["summary"]["uniqueCustomers"] == 0

    daily = (await client.get(f"/api/dashboard/transactions-daily?router_id={router_id}")).json()
    assert daily["totals"]["revenue"] == 120
    assert daily["totals"]["transactions"] == 5

    other_reseller = await make_reseller(db)
    _auth_as(monkeypatch, other_reseller)
    assert _rows((await client.get("/api/mpesa/transactions")).json()) == []


async def test_mpesa_confirmation_after_customer_deletion_is_counted_once(db, client, monkeypatch):
    await _create_radius_tables(db)
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=10)
    customer = await make_customer(db, reseller, plan=plan, router=router)
    checkout_id = "ws_CO_confirm_after_deletion"
    db.add(MpesaTransaction(
        checkout_request_id=checkout_id, phone_number=customer.phone, reference="LATE",
        amount=10, customer_id=customer.id, plan_id=plan.id, collection_mode=CollectionMode.DIRECT,
    ))
    await db.commit()
    assert (await cr._delete_customer_row(customer.id, db, reseller))["success"]

    callback = {"Body": {"stkCallback": {
        "CheckoutRequestID": checkout_id,
        "ResultCode": 0,
        "CallbackMetadata": {"Item": [
            {"Name": "MpesaReceiptNumber", "Value": "LATE10"},
            {"Name": "Amount", "Value": 10},
        ]},
    }}}
    for _ in range(2):
        response = await client.post("/api/mpesa/callback", json=callback)
        assert response.json()["ResultCode"] == 0

    payment = (await db.execute(select(CustomerPayment))).scalar_one()
    assert payment.customer_id is None
    assert payment.payment_reference == "LATE10"
    assert payment.router_id == router.id

    dashboard = (await client.get(f"/api/dashboard/daily-revenue?router_id={router.id}")).json()
    assert dashboard["total_revenue"] == 10
    assert dashboard["total_transactions"] == 1
    transactions = _rows((await client.get(f"/api/mpesa/transactions?router_id={router.id}")).json())
    assert [row["mpesa_receipt_number"] for row in transactions] == ["LATE10"]

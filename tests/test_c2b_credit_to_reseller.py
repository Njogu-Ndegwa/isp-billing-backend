"""Admin action: credit an unmatched platform-paybill payment to a reseller.

Case behind it (8 Nov 2026): a customer paid KES 1,500 to the platform
paybill with a mistyped account number (Luhn failure). The reseller had
already activated that customer as a cash payment, so the money must go to
the reseller's earnings, not to the customer as a second month.

Covers: the credit raises the withdrawable balance by the full amount and
pays out net of the usual Safaricom fee (1,485 for 1,500); the repair-balance
job leaves it alone; a second credit is refused; the customer is untouched;
non-admins and reseller-paybill payments are refused.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

import app.api.c2b_routes as c2b_routes_module
from app.api.admin_reseller_routes import _apply_repair, _compute_repair
from app.api.c2b_routes import router as c2b_router
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CollectionMode,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    PaymentMethod,
    PaymentStatus,
    ResellerPayout,
    StaffActivityLog,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
)
from app.services.account_numbers import luhn_check_digit
from app.services.auth import verify_token
from app.services.mpesa_b2b import compute_fee_breakdown, get_unpaid_balance
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(c2b_router)

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
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def _no_router_io():
    with patch("app.services.c2b_handler.call_pppoe_provision", new=AsyncMock()):
        yield


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(c2b_routes_module, "get_current_user", _fake)


def _payload(trans_id, bill_ref, amount, shortcode=None):
    return {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20261108162800",
        "TransAmount": str(amount),
        "BusinessShortCode": shortcode or settings.MPESA_SHORTCODE,
        "BillRefNumber": bill_ref,
        "MSISDN": "254700000000",
        "FirstName": "Test",
    }


async def _seed(db):
    """Reseller whose customer was activated as CASH, plus an admin."""
    reseller = await make_reseller(db)
    admin = await make_admin(db)
    plan = await make_plan(db, reseller, price=1500, duration_value=30,
                           duration_unit=DurationUnit.DAYS)
    router = await make_router(db, reseller)
    account = "2319731" + luhn_check_digit("2319731")
    expiry = datetime.utcnow().replace(microsecond=0) + timedelta(days=30)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
        account_number=account,
    )
    cash = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id, amount=1500,
        payment_method=PaymentMethod.CASH, days_paid_for=30,
        status=PaymentStatus.COMPLETED,
    )
    db.add(cash)
    await db.commit()
    return reseller, admin, customer, cash, expiry


async def _unmatched_typo(client, session_factory, trans_id="UK80W0VCVF", shortcode=None):
    """Feed the real confirmation webhook a mistyped account (fails Luhn)."""
    bad_ref = "2319312"
    if luhn_check_digit(bad_ref[:-1]) == bad_ref[-1]:
        bad_ref = "2319313"
    resp = await client.post("/api/c2b/confirmation",
                             json=_payload(trans_id, bad_ref, 1500, shortcode))
    assert resp.status_code == 200
    async with session_factory() as s:
        txn = (await s.execute(
            select(C2BTransaction).where(C2BTransaction.trans_id == trans_id)
        )).scalar_one()
        um = (await s.execute(
            select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id)
        )).scalar_one_or_none()
    return txn, um


async def _credit(client, unmatched_id, reseller_id, reason="Paid to wrong account"):
    return await client.post(
        f"/api/admin/c2b/unmatched/{unmatched_id}/credit-reseller",
        json={"reseller_id": reseller_id, "reason": reason},
    )


async def test_credit_raises_withdrawable_by_amount_and_pays_net_1485(
    db, session_factory, client, monkeypatch
):
    reseller, admin, customer, cash, expiry = await _seed(db)
    txn, um = await _unmatched_typo(client, session_factory)
    assert um.reason == UnmatchedC2BReason.INVALID_LUHN
    async with session_factory() as s:
        before = await get_unpaid_balance(s, reseller.id)

    _auth_as(monkeypatch, admin)
    resp = await _credit(client, um.id, reseller.id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["amount"] == 1500
    assert body["net_if_paid_alone"] == 1485

    async with session_factory() as s:
        after = await get_unpaid_balance(s, reseller.id)
        assert after - before == 1500
        # The withdraw screen and the B2B job pay balance minus the transfer fee.
        assert compute_fee_breakdown(after)[2] == 1485

        payment = await s.get(CustomerPayment, body["payment_id"])
        assert payment.customer_id is None and payment.plan_id is None and payment.router_id is None
        assert payment.collection_mode == CollectionMode.SYSTEM_COLLECTED
        assert payment.payment_method == PaymentMethod.MOBILE_MONEY
        assert payment.payment_reference == "UK80W0VCVF"

        txn2 = await s.get(C2BTransaction, txn.id)
        assert txn2.status == C2BTransactionStatus.PROCESSED
        assert txn2.matched_reseller_id == reseller.id
        assert txn2.matched_customer_id is None
        um2 = await s.get(UnmatchedC2BPayment, um.id)
        assert um2.resolved_at is not None
        assert um2.resolved_by_user_id == admin.id
        assert um2.resolution_customer_id is None
        assert "Paid to wrong account" in um2.notes

        audit = (await s.execute(
            select(StaffActivityLog).where(StaffActivityLog.owner_id == reseller.id)
        )).scalars().all()
        assert len(audit) == 1 and "UK80W0VCVF" in audit[0].summary

        # The customer, their cash payment and expiry are untouched.
        c = await s.get(Customer, customer.id)
        assert c.expiry == expiry and c.status == CustomerStatus.ACTIVE
        cust_payments = (await s.execute(
            select(CustomerPayment).where(CustomerPayment.customer_id == customer.id)
        )).scalars().all()
        assert [p.id for p in cust_payments] == [cash.id]
        assert cust_payments[0].amount == 1500
        assert cust_payments[0].payment_method == PaymentMethod.CASH


async def test_repair_balance_does_not_undo_the_credit(db, session_factory, client, monkeypatch):
    reseller, admin, *_ = await _seed(db)
    # Earlier platform revenue already paid out, so the repair compares
    # "since last payout" against the all-time raw balance.
    old = datetime.utcnow() - timedelta(days=3)
    db.add(CustomerPayment(
        customer_id=None, reseller_id=reseller.id, amount=800,
        payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=30,
        status=PaymentStatus.COMPLETED, created_at=old, payment_date=old,
    ))
    db.add(ResellerPayout(reseller_id=reseller.id, amount=800, payment_method="mpesa_b2b",
                          reference="OLD", created_at=old + timedelta(hours=1)))
    await db.commit()

    _txn, um = await _unmatched_typo(client, session_factory)
    _auth_as(monkeypatch, admin)
    assert (await _credit(client, um.id, reseller.id)).status_code == 200

    async with session_factory() as s:
        credited = await get_unpaid_balance(s, reseller.id)
        assert credited == 1500
        info = await _compute_repair(s, reseller.id)
        assert info["proposed_correction"] == 0
        # Run the job's write path anyway (it overwrites the correction).
        await _apply_repair(s, reseller.id, info["proposed_correction"])
        await s.commit()
        assert await get_unpaid_balance(s, reseller.id) == credited


async def test_second_credit_is_refused(db, session_factory, client, monkeypatch):
    reseller, admin, *_ = await _seed(db)
    other = await make_reseller(db)
    _txn, um = await _unmatched_typo(client, session_factory)
    _auth_as(monkeypatch, admin)

    assert (await _credit(client, um.id, reseller.id)).status_code == 200
    again = await _credit(client, um.id, reseller.id)
    assert again.status_code == 409
    elsewhere = await _credit(client, um.id, other.id)
    assert elsewhere.status_code == 409

    # Nor can the customer-attribution path apply it afterwards.
    attr = await client.post(f"/api/c2b/unmatched/{um.id}/attribute", json={"customer_id": 1})
    assert attr.status_code == 409

    async with session_factory() as s:
        n = (await s.execute(
            select(func.count(CustomerPayment.id)).where(
                CustomerPayment.payment_reference == "UK80W0VCVF")
        )).scalar()
        assert n == 1
        assert await get_unpaid_balance(s, other.id) == 0


async def test_non_admin_is_refused_and_nothing_changes(db, session_factory, client, monkeypatch):
    reseller, _admin, *_ = await _seed(db)
    _txn, um = await _unmatched_typo(client, session_factory)
    _auth_as(monkeypatch, reseller)

    resp = await _credit(client, um.id, reseller.id)
    assert resp.status_code == 403

    async with session_factory() as s:
        assert (await s.get(UnmatchedC2BPayment, um.id)).resolved_at is None
        assert await get_unpaid_balance(s, reseller.id) == 0


async def test_reason_is_required(db, session_factory, client, monkeypatch):
    reseller, admin, *_ = await _seed(db)
    _txn, um = await _unmatched_typo(client, session_factory)
    _auth_as(monkeypatch, admin)
    resp = await _credit(client, um.id, reseller.id, reason="   ")
    assert resp.status_code == 400


async def test_unknown_reseller_is_refused(db, session_factory, client, monkeypatch):
    _reseller, admin, *_ = await _seed(db)
    _txn, um = await _unmatched_typo(client, session_factory)
    _auth_as(monkeypatch, admin)
    resp = await _credit(client, um.id, admin.id)  # an admin is not a reseller
    assert resp.status_code == 404
    async with session_factory() as s:
        assert (await s.get(UnmatchedC2BPayment, um.id)).resolved_at is None


async def test_reseller_paybill_payment_is_refused(db, session_factory, client, monkeypatch):
    """Money paid to a reseller's own paybill never reached the platform."""
    reseller, admin, *_ = await _seed(db)
    async with session_factory() as s:
        txn = C2BTransaction(
            trans_id="OWNPAYBILL1", bill_ref_number="123", trans_amount=1500,
            business_shortcode="999111", status=C2BTransactionStatus.UNMATCHED,
            matched_reseller_id=reseller.id,
        )
        s.add(txn)
        await s.flush()
        um = UnmatchedC2BPayment(c2b_transaction_id=txn.id,
                                 reason=UnmatchedC2BReason.UNKNOWN_ACCOUNT,
                                 assigned_reseller_id=reseller.id)
        s.add(um)
        await s.commit()
        um_id = um.id

    _auth_as(monkeypatch, admin)
    resp = await _credit(client, um_id, reseller.id)
    assert resp.status_code == 400
    async with session_factory() as s:
        assert await get_unpaid_balance(s, reseller.id) == 0

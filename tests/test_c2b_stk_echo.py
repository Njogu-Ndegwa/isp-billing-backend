"""
STK echoes: the C2B copy Safaricom sends of an STK push on a paybill that has
C2B URLs registered (production, 23 Oct 2026: reseller 713, shortcode
1365970). The STK callback credits the customer; the C2B copy carries
BillRefNumber = the reseller's business name, fails Luhn, and used to land in
the reseller's unmatched list, where attributing it credited the same money
twice.

Covers both arrival orders over real HTTP (STK callback + C2B confirmation
mounted on one app), that genuine paybill payments are untouched, the 409 on
attributing an already-paid receipt, the unmatched-list and transactions-list
filters, and the backfill.
"""

from datetime import datetime
from types import SimpleNamespace
from typing import List, Tuple
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.api import c2b_routes, payment_routes
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    MpesaTransaction,
    MpesaTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
    UserRole,
)
from app.services.account_numbers import luhn_check_digit
from app.services.auth import verify_token
from app.services.c2b_stk_echo_backfill import backfill_stk_echoes
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio

PAYBILL = "1365970"
RECEIPT = "UJN5JBRWI4"
BUSINESS_NAME = "TEMBO NETWORKS"


# ---------------------------------------------------------------------------
# App + fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def current_user():
    """Mutable holder: tests set .user to whoever is calling the auth'd routes."""
    return SimpleNamespace(user=None)


@pytest_asyncio.fixture
async def app(session_factory, monkeypatch, current_user):
    app = FastAPI()
    app.include_router(payment_routes.router)
    app.include_router(c2b_routes.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    async def _fake_current_user(_token, _db):
        return current_user.user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[verify_token] = lambda: "tok"
    monkeypatch.setattr(c2b_routes, "get_current_user", _fake_current_user)
    monkeypatch.setattr(payment_routes, "get_current_user", _fake_current_user)
    return app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
def provision_calls() -> List[Tuple]:
    return []


@pytest.fixture(autouse=True)
def patched_provisioning(provision_calls, monkeypatch):
    async def _noop(*args, **kwargs):
        return {"ok": True}

    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)

    async def _hotspot(*args, **kwargs):
        provision_calls.append(("hotspot", args, kwargs))

    async def _pppoe(*args, **kwargs):
        provision_calls.append(("pppoe", args, kwargs))

    with patch(
        "app.api.payment_routes.provision_hotspot_customer", new=AsyncMock(side_effect=_hotspot)
    ), patch(
        "app.api.payment_routes.call_pppoe_provision", new=AsyncMock(side_effect=_pppoe)
    ), patch(
        "app.services.c2b_handler.call_pppoe_provision", new=AsyncMock(side_effect=_pppoe)
    ), patch(
        "app.api.c2b_routes.call_pppoe_provision", new=AsyncMock(side_effect=_pppoe)
    ):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_account(base: str) -> str:
    return base + luhn_check_digit(base)


def _c2b_payload(*, trans_id=RECEIPT, bill_ref=BUSINESS_NAME, amount=50, shortcode=PAYBILL) -> dict:
    return {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20261023221500",
        "TransAmount": str(amount),
        "BusinessShortCode": shortcode,
        "BillRefNumber": bill_ref,
        "MSISDN": "254712345678",
        "FirstName": "Hotspot",
        "LastName": "Buyer",
    }


def _stk_payload(checkout_id: str, *, receipt=RECEIPT, amount=50) -> dict:
    return {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "merch-1",
                "CheckoutRequestID": checkout_id,
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {"Item": [
                    {"Name": "Amount", "Value": amount},
                    {"Name": "MpesaReceiptNumber", "Value": receipt},
                    {"Name": "PhoneNumber", "Value": "254712345678"},
                ]},
            }
        }
    }


async def _seed_hotspot_sale(session_factory, *, checkout_id="ws_CO_ECHO_1", shortcode=PAYBILL):
    """Reseller with a C2B-registered paybill and a pending hotspot STK sale on it."""
    async with session_factory() as s:
        reseller = await make_reseller(s, business_name=BUSINESS_NAME)
        s.add(ResellerPaymentMethod(
            user_id=reseller.id,
            method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
            label="Tembo paybill",
            is_active=True,
            mpesa_shortcode=shortcode,
        ))
        plan = await make_plan(s, reseller, price=50, duration_value=1, duration_unit=DurationUnit.DAYS)
        router = await make_router(s, reseller)
        customer = await make_customer(
            s, reseller, plan, router,
            status=CustomerStatus.PENDING,
            mac_address="AA:BB:CC:DD:EE:43",
        )
        s.add(MpesaTransaction(
            checkout_request_id=checkout_id,
            phone_number=customer.phone,
            amount=50.0,
            reference=f"customer-{customer.id}",
            customer_id=customer.id,
            status=MpesaTransactionStatus.pending,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        ))
        await s.commit()
        return reseller, customer, checkout_id


async def _state(session_factory, receipt=RECEIPT):
    async with session_factory() as s:
        txn = (
            await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == receipt))
        ).scalar_one_or_none()
        unmatched = None
        if txn is not None:
            unmatched = (
                await s.execute(
                    select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id)
                )
            ).scalar_one_or_none()
        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.payment_reference == receipt))
        ).scalars().all()
        return txn, unmatched, payments


def _reseller_user(reseller):
    return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)


# ---------------------------------------------------------------------------
# Arrival order
# ---------------------------------------------------------------------------


async def test_stk_callback_first_then_echo_is_archived_without_unmatched_row(
    session_factory, client
):
    reseller, customer, checkout_id = await _seed_hotspot_sale(session_factory)

    resp = await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert resp.json()["ResultCode"] == 0
    resp = await client.post("/api/c2b/confirmation", json=_c2b_payload())
    assert resp.status_code == 200 and resp.json()["ResultCode"] == "0"

    txn, unmatched, payments = await _state(session_factory)
    assert txn.status == C2BTransactionStatus.STK_ECHO
    assert txn.matched_customer_id == customer.id
    assert txn.matched_reseller_id == reseller.id
    assert unmatched is None
    assert len(payments) == 1  # the STK payment only

    async with session_factory() as s:
        wallet = (await s.execute(select(Customer.wallet_credit_kes).where(Customer.id == customer.id))).scalar_one()
        assert (wallet or 0) == 0


async def test_echo_first_then_stk_callback_retires_the_unmatched_row(session_factory, client):
    reseller, customer, checkout_id = await _seed_hotspot_sale(session_factory)

    await client.post("/api/c2b/confirmation", json=_c2b_payload())
    txn, unmatched, _ = await _state(session_factory)
    assert txn.status == C2BTransactionStatus.UNMATCHED
    assert unmatched.reason == UnmatchedC2BReason.INVALID_LUHN
    assert unmatched.assigned_reseller_id == reseller.id
    assert unmatched.resolved_at is None

    resp = await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    assert resp.json()["ResultCode"] == 0

    txn, unmatched, payments = await _state(session_factory)
    assert txn.status == C2BTransactionStatus.STK_ECHO
    assert txn.matched_customer_id == customer.id
    assert unmatched.resolved_at is not None
    assert unmatched.notes == "stk_echo"
    assert unmatched.resolution_customer_id == customer.id
    assert unmatched.resolved_by_user_id is None
    assert len(payments) == 1


async def test_safaricom_retry_of_an_echo_stays_a_noop(session_factory, client):
    _, _, checkout_id = await _seed_hotspot_sale(session_factory)
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    await client.post("/api/c2b/confirmation", json=_c2b_payload())
    await client.post("/api/c2b/confirmation", json=_c2b_payload())

    async with session_factory() as s:
        n = (await s.execute(select(func.count(C2BTransaction.id)))).scalar_one()
        assert n == 1
    _, _, payments = await _state(session_factory)
    assert len(payments) == 1


# ---------------------------------------------------------------------------
# Genuine paybill payments are untouched
# ---------------------------------------------------------------------------


async def test_genuine_paybill_payment_still_matches_by_account_number(session_factory, client):
    # An STK sale exists on the same paybill, with a different receipt.
    reseller, _, checkout_id = await _seed_hotspot_sale(session_factory)
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))

    async with session_factory() as s:
        plan = await make_plan(
            s, reseller, price=500, duration_value=30, duration_unit=DurationUnit.DAYS,
            connection_type=ConnectionType.PPPOE,
        )
        router = await make_router(s, reseller)
        pppoe = await make_customer(
            s, reseller, plan, router,
            status=CustomerStatus.INACTIVE, pppoe_username="pppoe_echo_test",
            mac_address=None, account_number=_valid_account("7130001"),
        )
        pppoe_id, acct = pppoe.id, pppoe.account_number

    await client.post(
        "/api/c2b/confirmation",
        json=_c2b_payload(trans_id="UJNGENUINE1", bill_ref=acct, amount=500),
    )

    txn, unmatched, payments = await _state(session_factory, "UJNGENUINE1")
    assert txn.status == C2BTransactionStatus.PROCESSED
    assert txn.matched_customer_id == pppoe_id
    assert unmatched is None
    assert len(payments) == 1 and payments[0].customer_id == pppoe_id


async def test_genuine_unmatched_payment_still_lands_unmatched(session_factory, client):
    reseller, _, _ = await _seed_hotspot_sale(session_factory)

    await client.post(
        "/api/c2b/confirmation",
        json=_c2b_payload(trans_id="UJNTYPO0001", bill_ref="12345678", amount=500),
    )

    txn, unmatched, payments = await _state(session_factory, "UJNTYPO0001")
    assert txn.status == C2BTransactionStatus.UNMATCHED
    assert unmatched.reason == UnmatchedC2BReason.INVALID_LUHN
    assert unmatched.assigned_reseller_id == reseller.id
    assert unmatched.resolved_at is None
    assert payments == []


# ---------------------------------------------------------------------------
# Attribution guard
# ---------------------------------------------------------------------------


async def test_attributing_an_already_paid_receipt_returns_409_and_changes_nothing(
    session_factory, client, current_user
):
    """The race the guard exists for: an echo that is still open while the
    receipt is already paid (e.g. a row from before this fix)."""
    reseller, customer, checkout_id = await _seed_hotspot_sale(session_factory)
    await client.post("/api/c2b/confirmation", json=_c2b_payload())
    txn, unmatched, _ = await _state(session_factory)

    # Record the STK payment WITHOUT the post-callback retirement, i.e. the
    # state production is in today for the historical rows.
    with patch(
        "app.services.c2b_handler.mark_stk_echo_after_stk_payment", new=AsyncMock(return_value=False)
    ):
        await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    txn, unmatched, payments = await _state(session_factory)
    assert unmatched.resolved_at is None and len(payments) == 1

    current_user.user = _reseller_user(reseller)
    async with session_factory() as s:
        expiry_before = (await s.execute(select(Customer.expiry).where(Customer.id == customer.id))).scalar_one()

    resp = await client.post(
        f"/api/c2b/unmatched/{unmatched.id}/attribute", json={"customer_id": customer.id}
    )
    assert resp.status_code == 409
    assert RECEIPT in resp.json()["detail"]
    assert "twice" in resp.json()["detail"]

    txn, unmatched, payments = await _state(session_factory)
    assert len(payments) == 1  # no second revenue row
    assert unmatched.resolved_at is None
    assert txn.status == C2BTransactionStatus.UNMATCHED
    async with session_factory() as s:
        expiry_after = (await s.execute(select(Customer.expiry).where(Customer.id == customer.id))).scalar_one()
    assert expiry_after == expiry_before  # no extra access


async def test_attributing_a_genuine_unmatched_payment_still_works(session_factory, client, current_user):
    reseller, _, _ = await _seed_hotspot_sale(session_factory)
    async with session_factory() as s:
        plan = await make_plan(
            s, reseller, price=500, duration_value=30, duration_unit=DurationUnit.DAYS,
            connection_type=ConnectionType.PPPOE,
        )
        router = await make_router(s, reseller)
        pppoe = await make_customer(
            s, reseller, plan, router, status=CustomerStatus.INACTIVE,
            pppoe_username="pppoe_attr", mac_address=None, account_number=_valid_account("7130002"),
        )
        pppoe_id = pppoe.id

    await client.post(
        "/api/c2b/confirmation",
        json=_c2b_payload(trans_id="UJNTYPO0002", bill_ref="12345678", amount=500),
    )
    _, unmatched, _ = await _state(session_factory, "UJNTYPO0002")

    current_user.user = _reseller_user(reseller)
    resp = await client.post(
        f"/api/c2b/unmatched/{unmatched.id}/attribute", json={"customer_id": pppoe_id}
    )
    assert resp.status_code == 200, resp.text
    txn, unmatched, payments = await _state(session_factory, "UJNTYPO0002")
    assert txn.status == C2BTransactionStatus.PROCESSED
    assert unmatched.resolved_at is not None
    assert len(payments) == 1


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------


async def test_unmatched_list_excludes_stk_echoes(session_factory, client, current_user):
    reseller, _, checkout_id = await _seed_hotspot_sale(session_factory)
    # Echo arrives first (lands unmatched), STK retires it; plus one genuine typo.
    await client.post("/api/c2b/confirmation", json=_c2b_payload())
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    await client.post(
        "/api/c2b/confirmation",
        json=_c2b_payload(trans_id="UJNTYPO0003", bill_ref="12345678", amount=500),
    )
    current_user.user = _reseller_user(reseller)

    open_rows = (await client.get("/api/c2b/unmatched")).json()
    assert [r["transaction"]["trans_id"] for r in open_rows] == ["UJNTYPO0003"]

    all_rows = (await client.get("/api/c2b/unmatched", params={"resolved": "true"})).json()
    assert [r["transaction"]["trans_id"] for r in all_rows] == ["UJNTYPO0003"]

    with_echo = (
        await client.get("/api/c2b/unmatched", params={"resolved": "true", "include_stk_echo": "true"})
    ).json()
    assert sorted(r["transaction"]["trans_id"] for r in with_echo) == [RECEIPT, "UJNTYPO0003"]


async def test_unmatched_list_hides_an_open_row_whose_c2b_status_is_stk_echo(
    db, session_factory, client, current_user
):
    """Belt and braces: even if an unmatched row were left open, an STK_ECHO
    transaction never shows in the reseller's triage list."""
    reseller = await make_reseller(db)
    txn = C2BTransaction(
        trans_id="UJNOPENECHO", bill_ref_number=BUSINESS_NAME, trans_amount=50,
        business_shortcode=PAYBILL, status=C2BTransactionStatus.STK_ECHO,
        matched_reseller_id=reseller.id, received_at=datetime.utcnow(),
    )
    db.add(txn)
    await db.flush()
    db.add(UnmatchedC2BPayment(
        c2b_transaction_id=txn.id, reason=UnmatchedC2BReason.INVALID_LUHN,
        assigned_reseller_id=reseller.id,
    ))
    await db.commit()
    current_user.user = _reseller_user(reseller)

    assert (await client.get("/api/c2b/unmatched")).json() == []


async def test_transactions_list_shows_the_hotspot_sale_once(session_factory, client, current_user):
    reseller, _, checkout_id = await _seed_hotspot_sale(session_factory)
    await client.post("/api/c2b/confirmation", json=_c2b_payload())
    await client.post("/api/mpesa/callback", json=_stk_payload(checkout_id))
    current_user.user = _reseller_user(reseller)

    rows = (await client.get("/api/mpesa/transactions")).json()
    if isinstance(rows, dict):
        rows = rows.get("transactions") or rows.get("items") or rows.get("data") or []
    receipts = [r.get("mpesa_receipt_number") for r in rows]
    assert receipts.count(RECEIPT) == 1
    assert all(r.get("source") != "c2b_paybill" for r in rows)


# ---------------------------------------------------------------------------
# No double revenue across the whole flow
# ---------------------------------------------------------------------------


async def test_no_double_revenue_for_one_hotspot_sale_either_order(session_factory, client):
    _, c1, co1 = await _seed_hotspot_sale(session_factory, checkout_id="ws_CO_ECHO_A")
    _, c2, co2 = await _seed_hotspot_sale(session_factory, checkout_id="ws_CO_ECHO_B", shortcode="1365971")

    # Order A: STK first. Order B: echo first.
    await client.post("/api/mpesa/callback", json=_stk_payload(co1, receipt="UJNORDERA01"))
    await client.post("/api/c2b/confirmation", json=_c2b_payload(trans_id="UJNORDERA01"))
    await client.post(
        "/api/c2b/confirmation", json=_c2b_payload(trans_id="UJNORDERB01", shortcode="1365971")
    )
    await client.post("/api/mpesa/callback", json=_stk_payload(co2, receipt="UJNORDERB01"))

    async with session_factory() as s:
        rows = (
            await s.execute(
                select(CustomerPayment.customer_id, func.count(), func.sum(CustomerPayment.amount))
                .group_by(CustomerPayment.customer_id)
            )
        ).all()
        assert {r[0]: (r[1], float(r[2])) for r in rows} == {c1.id: (1, 50.0), c2.id: (1, 50.0)}
        open_unmatched = (
            await s.execute(
                select(func.count(UnmatchedC2BPayment.id)).where(UnmatchedC2BPayment.resolved_at.is_(None))
            )
        ).scalar_one()
        assert open_unmatched == 0


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------


async def _seed_historical_echo(session_factory, *, receipt, checkout_id):
    """An echo that landed before the fix: open unmatched row + paid STK sale."""
    reseller, customer, _ = await _seed_hotspot_sale(
        session_factory, checkout_id=checkout_id, shortcode=f"9{checkout_id[-1]}0000"
    )
    async with session_factory() as s:
        mt = (
            await s.execute(select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_id))
        ).scalar_one()
        mt.status = MpesaTransactionStatus.completed
        mt.mpesa_receipt_number = receipt
        s.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=50,
            payment_method=payment_routes.PaymentMethod.MOBILE_MONEY,
            payment_reference=receipt, days_paid_for=1,
        ))
        txn = C2BTransaction(
            trans_id=receipt, bill_ref_number=BUSINESS_NAME, trans_amount=50,
            business_shortcode=PAYBILL, status=C2BTransactionStatus.UNMATCHED,
            matched_reseller_id=reseller.id, received_at=datetime.utcnow(),
        )
        s.add(txn)
        await s.flush()
        um = UnmatchedC2BPayment(
            c2b_transaction_id=txn.id, reason=UnmatchedC2BReason.INVALID_LUHN,
            assigned_reseller_id=reseller.id,
        )
        s.add(um)
        await s.commit()
        return reseller, customer, um.id


async def test_backfill_dry_run_counts_and_writes_nothing(session_factory):
    r1, _, _ = await _seed_historical_echo(session_factory, receipt="UJNHIST0001", checkout_id="co-h1")
    await _seed_historical_echo(session_factory, receipt="UJNHIST0002", checkout_id="co-h2")
    async with session_factory() as s:  # one genuine unmatched row for r1
        txn = C2BTransaction(
            trans_id="UJNHISTREAL", bill_ref_number="12345678", trans_amount=500,
            business_shortcode=PAYBILL, status=C2BTransactionStatus.UNMATCHED,
            matched_reseller_id=r1.id, received_at=datetime.utcnow(),
        )
        s.add(txn)
        await s.flush()
        s.add(UnmatchedC2BPayment(
            c2b_transaction_id=txn.id, reason=UnmatchedC2BReason.INVALID_LUHN,
            assigned_reseller_id=r1.id,
        ))
        await s.commit()

    async with session_factory() as s:
        report = await backfill_stk_echoes(s)
    assert report.dry_run
    assert report.open_unmatched_in_scope == 3
    assert report.echo_candidates == 2
    assert report.via_mpesa_receipt == 2
    assert report.retired == 0 and report.remaining == 2

    async with session_factory() as s:
        statuses = (await s.execute(select(C2BTransaction.status))).scalars().all()
    assert set(statuses) == {C2BTransactionStatus.UNMATCHED}


async def test_backfill_apply_scoped_to_one_reseller(session_factory):
    r1, c1, um1 = await _seed_historical_echo(session_factory, receipt="UJNHIST0003", checkout_id="co-h3")
    r2, _, um2 = await _seed_historical_echo(session_factory, receipt="UJNHIST0004", checkout_id="co-h4")

    async with session_factory() as s:
        report = await backfill_stk_echoes(s, dry_run=False, reseller_id=r1.id)
    assert report.echo_candidates == 1 and report.retired == 1 and report.remaining == 0

    txn, unmatched, payments = await _state(session_factory, "UJNHIST0003")
    assert txn.status == C2BTransactionStatus.STK_ECHO
    assert txn.matched_customer_id == c1.id
    assert unmatched.notes == "stk_echo" and unmatched.resolved_at is not None
    assert len(payments) == 1

    txn2, unmatched2, _ = await _state(session_factory, "UJNHIST0004")
    assert txn2.status == C2BTransactionStatus.UNMATCHED  # other reseller untouched
    assert unmatched2.resolved_at is None

    async with session_factory() as s:  # idempotent re-run
        again = await backfill_stk_echoes(s, dry_run=False, reseller_id=r1.id)
    assert again.echo_candidates == 0 and again.retired == 0

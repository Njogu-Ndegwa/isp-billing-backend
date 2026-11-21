"""Exact payment lookup: ``search`` on GET /api/mpesa/transactions and
GET /api/c2b/unmatched.

A tester asked the assistant "who paid with M-Pesa code TKL3XY9Q2M?". The
only way to answer was to pull a page of up to 200 transactions and scan it,
which misses the payment on a busy account. ``search`` matches the receipt
code (any case) or the payer's phone (07…, 7…, 254…, +254…) inside each
ledger's query, so one call finds it and paging totals count only matches.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.c2b_routes as c2b_routes
import app.api.payment_routes as pr
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
)
from app.services.auth import verify_token
from app.services.payment_numbers import phone_search_variants
from tests.factories import make_customer, make_plan, make_reseller, make_router


RECEIPT = "TKL3XY9Q2M"
PAYBILL_RECEIPT = "QWE123RTY9"
JANE_PHONE = "0711222333"     # saved on the customer as typed
JANE_STK_PHONE = "254711222333"  # what Safaricom puts on the STK row
BOB_PHONE = "254722000111"
PAYER_MSISDN = "254733444555"  # paid Bob's bill from someone else's phone
BOB_FILLERS = 30


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(pr.router)
    application.include_router(c2b_routes.router)

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
    monkeypatch.setattr(c2b_routes, "get_current_user", _fake)


async def _seed(db):
    """Jane's STK payment (the one being looked up) and cash payment, buried
    under 30 newer STK payments of Bob's and one paybill payment for Bob.
    Another reseller has an STK payment from Jane's phone that must never
    show up."""
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=50)
    jane = await make_customer(db, reseller, plan=plan, router=router, phone=JANE_PHONE, name="Jane")
    bob = await make_customer(db, reseller, plan=plan, router=router, phone=BOB_PHONE, name="Bob")
    start = datetime.utcnow() - timedelta(days=2)
    minute = 0

    def at():
        nonlocal minute
        minute += 1
        return start + timedelta(minutes=minute)

    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_jane", phone_number=JANE_STK_PHONE, amount=50, reference="R-jane",
        customer_id=jane.id, plan_id=plan.id, status=MpesaTransactionStatus.completed,
        mpesa_receipt_number=RECEIPT, created_at=at(),
    ))
    db.add(CustomerPayment(
        customer_id=jane.id, reseller_id=reseller.id, amount=30, payment_method=PaymentMethod.CASH,
        days_paid_for=1, status=PaymentStatus.COMPLETED, payment_reference="CASH-jane", created_at=at(),
    ))
    for i in range(BOB_FILLERS):
        db.add(MpesaTransaction(
            checkout_request_id=f"ws_CO_bob_{i}", phone_number=BOB_PHONE, amount=50, reference=f"R{i}",
            customer_id=bob.id, plan_id=plan.id, status=MpesaTransactionStatus.completed,
            mpesa_receipt_number=f"FILL{i:06d}", created_at=at(),
        ))
    db.add(C2BTransaction(
        trans_id=PAYBILL_RECEIPT, trans_amount=40, bill_ref_number="ACC1", msisdn=PAYER_MSISDN,
        business_shortcode="123456", matched_customer_id=bob.id, matched_reseller_id=reseller.id,
        status=C2BTransactionStatus.PROCESSED, received_at=at(),
    ))

    other = await make_reseller(db)
    other_plan = await make_plan(db, other, price=50)
    other_customer = await make_customer(
        db, other, plan=other_plan, router=await make_router(db, other), phone=JANE_PHONE,
    )
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_other", phone_number=JANE_STK_PHONE, amount=99, reference="X",
        customer_id=other_customer.id, plan_id=other_plan.id, status=MpesaTransactionStatus.completed,
        mpesa_receipt_number="OTHER00001", created_at=at(),
    ))
    await db.commit()
    return reseller


async def _search(client, search, **params):
    resp = await client.get("/api/mpesa/transactions", params={"search": search, **params})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _refs(rows):
    return sorted(r["payment_reference"] for r in rows)


# ---------------------------------------------------------------------------
# GET /api/mpesa/transactions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("typed", [RECEIPT, RECEIPT.lower(), f"  {RECEIPT}  "])
async def test_receipt_code_finds_the_one_payment(db, client, monkeypatch, typed):
    _auth_as(monkeypatch, await _seed(db))

    rows = await _search(client, typed)

    assert len(rows) == 1
    assert rows[0]["mpesa_receipt_number"] == RECEIPT
    assert rows[0]["customer"]["name"] == "Jane"


async def test_paybill_trans_id_finds_the_paybill_payment(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    rows = await _search(client, PAYBILL_RECEIPT.lower())

    assert [(r["source"], r["payment_reference"]) for r in rows] == [("c2b_paybill", PAYBILL_RECEIPT)]


async def test_code_buried_under_newer_payments_is_still_found(db, client, monkeypatch):
    """The bug: the payment sat beyond the page the assistant scanned."""
    _auth_as(monkeypatch, await _seed(db))

    first_page = (await client.get("/api/mpesa/transactions", params={"limit": 10})).json()
    assert RECEIPT not in _refs(first_page)

    rows = await _search(client, RECEIPT, limit=10)
    assert _refs(rows) == [RECEIPT]


@pytest.mark.parametrize(
    "typed",
    ["0711222333", "711222333", "254711222333", "+254711222333", "+254 711 222 333", "0711-222-333"],
)
async def test_phone_in_any_format_finds_the_customers_payments(db, client, monkeypatch, typed):
    _auth_as(monkeypatch, await _seed(db))

    rows = await _search(client, typed)

    # Jane's STK row (phone on the row, 254 form) and her cash payment (phone
    # only on the customer, 07 form) -- never the other reseller's row.
    assert _refs(rows) == ["CASH-jane", RECEIPT]


@pytest.mark.parametrize("typed", ["0733444555", "254733444555", "+254733444555"])
async def test_paybill_payer_phone_matches_the_msisdn(db, client, monkeypatch, typed):
    _auth_as(monkeypatch, await _seed(db))

    rows = await _search(client, typed)

    assert _refs(rows) == [PAYBILL_RECEIPT]


@pytest.mark.parametrize("typed", ["ZZZ0000000", "0799999999", "TKL3XY9Q2", "Jane"])
async def test_no_match_returns_nothing(db, client, monkeypatch, typed):
    _auth_as(monkeypatch, await _seed(db))

    assert await _search(client, typed) == []
    paged = await _search(client, typed, page=1, per_page=20)
    assert paged["data"] == [] and paged["total"] == 0 and paged["total_pages"] == 1


async def test_blank_search_is_ignored(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    rows = await _search(client, "   ")

    assert len(rows) == 1 + 1 + BOB_FILLERS + 1


async def test_paging_and_total_agree_with_a_search(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))
    expected = BOB_FILLERS + 1  # Bob's STK rows + the paybill payment matched to him

    everything = await _search(client, "0722000111")
    pages = [await _search(client, "0722000111", page=n, per_page=10) for n in (1, 2, 3, 4)]

    assert len(everything) == expected
    assert [p["total"] for p in pages] == [expected] * 4
    assert [p["total_pages"] for p in pages] == [4] * 4
    assert [len(p["data"]) for p in pages] == [10, 10, 10, 1]
    paged_rows = [r for p in pages for r in p["data"]]
    key = lambda r: (r["source"], r["transaction_id"])  # noqa: E731
    assert [key(r) for r in paged_rows] == [key(r) for r in everything]
    dates = [r["created_at"] for r in paged_rows]
    assert dates == sorted(dates, reverse=True)


async def test_search_combines_with_other_filters(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    cash_only = await _search(client, JANE_PHONE, payment_method="cash")
    mpesa_only = await _search(client, JANE_PHONE, payment_method="mobile_money")

    assert _refs(cash_only) == ["CASH-jane"]
    assert _refs(mpesa_only) == [RECEIPT]


# ---------------------------------------------------------------------------
# GET /api/c2b/unmatched
# ---------------------------------------------------------------------------


async def _seed_unmatched(db):
    reseller = await make_reseller(db)
    rows = [
        # (trans_id, msisdn, bill_ref) oldest first
        ("UNM0000001", "254700111222", "WRONGACC"),
        ("UNM0000002", None, "0700333444"),  # payer typed their phone as the account
        ("UNM0000003", "254700555666", "ACC9"),
    ]
    start = datetime.utcnow() - timedelta(hours=3)
    for i, (trans_id, msisdn, bill_ref) in enumerate(rows):
        txn = C2BTransaction(
            trans_id=trans_id, trans_amount=100, bill_ref_number=bill_ref, msisdn=msisdn,
            business_shortcode="123456", status=C2BTransactionStatus.UNMATCHED,
            received_at=start + timedelta(minutes=i),
        )
        db.add(txn)
        await db.flush()
        db.add(UnmatchedC2BPayment(
            c2b_transaction_id=txn.id, reason=UnmatchedC2BReason.INVALID_LUHN,
            assigned_reseller_id=reseller.id,
        ))
    await db.commit()
    return reseller


async def _unmatched(client, **params):
    resp = await client.get("/api/c2b/unmatched", params=params)
    assert resp.status_code == 200, resp.text
    return sorted(r["transaction"]["trans_id"] for r in resp.json())


async def test_unmatched_search_by_code_phone_and_account(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed_unmatched(db))

    assert await _unmatched(client) == ["UNM0000001", "UNM0000002", "UNM0000003"]
    assert await _unmatched(client, search="unm0000003") == ["UNM0000003"]
    assert await _unmatched(client, search="0700111222") == ["UNM0000001"]
    assert await _unmatched(client, search="+254700111222") == ["UNM0000001"]
    assert await _unmatched(client, search="254700333444") == ["UNM0000002"]
    assert await _unmatched(client, search="ZZZ0000000") == []


async def test_unmatched_search_reaches_past_the_limit(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed_unmatched(db))

    assert await _unmatched(client, limit=1) == ["UNM0000003"]
    assert await _unmatched(client, limit=1, search="UNM0000001") == ["UNM0000001"]


# ---------------------------------------------------------------------------
# phone_search_variants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("typed", ["0711222333", "711222333", "254711222333", "+254 711-222-333"])
def test_kenyan_phone_variants(typed):
    assert sorted(phone_search_variants(typed)) == sorted(
        ["0711222333", "254711222333", "+254711222333", "711222333"]
    )


def test_safaricom_01_numbers_are_kenyan():
    assert "254110000111" in phone_search_variants("0110000111")


@pytest.mark.parametrize("typed", [RECEIPT, "", None, "12345", "Jane"])
def test_not_a_phone(typed):
    assert phone_search_variants(typed) == []


def test_foreign_number_is_matched_as_typed():
    assert sorted(phone_search_variants("+237 6 71 23 45 67")) == ["+237671234567", "237671234567"]

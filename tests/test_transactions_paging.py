"""Paging on GET /api/mpesa/transactions.

The Transactions page sends page/per_page. The endpoint ignored them: every
request returned up to 200 merged rows (~250 KB) and the page derived its
total from those 200, so it could never show more than 10 pages. With both
parameters it now returns one page plus the true total across the three
ledgers (STK, customer_payments outside STK, C2B paybill). Without them the
response is the same plain array as before.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

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
)
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(pr.router)

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


async def _seed(db):
    """7 STK (2 failed), 4 cash, 3 C2B rows for one reseller, plus another
    reseller's rows that must never be counted."""
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, price=50)
    customer = await make_customer(db, reseller, plan=plan, router=router)
    base = datetime.utcnow() - timedelta(days=1)
    minute = 0

    def at():
        nonlocal minute
        minute += 1
        return base + timedelta(minutes=minute)

    for i in range(7):
        db.add(MpesaTransaction(
            checkout_request_id=f"ws_CO_pg_{i}", phone_number="254700000000", amount=50,
            reference=f"R{i}", customer_id=customer.id, plan_id=plan.id,
            status=MpesaTransactionStatus.failed if i < 2 else MpesaTransactionStatus.completed,
            mpesa_receipt_number=f"STK{i}", created_at=at(),
        ))
    for i in range(4):
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=30,
            payment_method=PaymentMethod.CASH, days_paid_for=1, status=PaymentStatus.COMPLETED,
            payment_reference=f"CASH{i}", created_at=at(),
        ))
    for i in range(3):
        db.add(C2BTransaction(
            trans_id=f"C2B{i}", trans_amount=40, bill_ref_number=f"ACC{i}",
            business_shortcode="123456", matched_customer_id=customer.id, matched_reseller_id=reseller.id,
            status=C2BTransactionStatus.PROCESSED, received_at=at(),
        ))
    other = await make_reseller(db)
    other_plan = await make_plan(db, other, price=50)
    other_customer = await make_customer(db, other, plan=other_plan, router=await make_router(db, other))
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_other", phone_number="254700000000", amount=99, reference="X",
        customer_id=other_customer.id, plan_id=other_plan.id, status=MpesaTransactionStatus.completed,
        created_at=at(),
    ))
    await db.commit()
    return reseller


def _key(row):
    return (row["source"], row["transaction_id"])


async def test_unpaged_request_still_returns_the_array(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/mpesa/transactions")).json()

    assert isinstance(body, list) and len(body) == 14


async def test_pages_cover_every_row_once_newest_first_with_true_total(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    everything = (await client.get("/api/mpesa/transactions")).json()
    pages = [
        (await client.get("/api/mpesa/transactions", params={"page": n, "per_page": 5})).json()
        for n in (1, 2, 3)
    ]

    assert [p["total"] for p in pages] == [14, 14, 14]
    assert [p["total_pages"] for p in pages] == [3, 3, 3]
    assert [len(p["data"]) for p in pages] == [5, 5, 4]
    paged_rows = [r for p in pages for r in p["data"]]
    assert [_key(r) for r in paged_rows] == [_key(r) for r in everything]
    dates = [r["created_at"] for r in paged_rows]
    assert dates == sorted(dates, reverse=True)


async def test_total_follows_the_filters(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    for filters, expected in (
        # The status filter has never applied to non-STK rows (cash stays in);
        # paging must keep exactly the rows the unpaged list returns.
        ({"status": "failed"}, 2 + 4),
        ({"payment_method": "cash"}, 4),
        ({"payment_method": "mobile_money"}, 7 + 3),
    ):
        unpaged = (await client.get("/api/mpesa/transactions", params=filters)).json()
        paged = (await client.get(
            "/api/mpesa/transactions", params={"page": 1, "per_page": 20, **filters}
        )).json()
        assert paged["total"] == len(paged["data"]) == len(unpaged) == expected, filters


async def test_count_only_request_is_one_row(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/mpesa/transactions", params={"page": 1, "per_page": 1})).json()

    assert body["total"] == 14 and len(body["data"]) == 1


async def test_huge_per_page_is_capped_not_rejected(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.get("/api/mpesa/transactions", params={"page": 1, "per_page": 10000})

    assert resp.status_code == 200
    body = resp.json()
    assert body["per_page"] == 500 and body["total"] == 14 and len(body["data"]) == 14


async def test_page_zero_is_rejected(db, client, monkeypatch):
    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.get("/api/mpesa/transactions", params={"page": 0, "per_page": 20})

    assert resp.status_code == 422

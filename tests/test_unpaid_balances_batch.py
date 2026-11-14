"""Batched balances on the admin reseller list must equal the payout formula.

GET /api/admin/resellers used to run about seven queries per reseller (~5,000
for 730 resellers, 7-15 s on production). It now computes each figure with one
grouped query for every listed reseller. The unpaid balance is the number the
nightly B2B job pays, so the batched version (mpesa_b2b.get_unpaid_balances)
must match get_unpaid_balance exactly for every row shape.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_reseller_routes as arr
from app.db.database import get_db
from app.db.models import AdSale, AdSalePayment, ResellerPaymentMethod, ResellerPaymentMethodType
from app.services.auth import verify_token
from app.services.mpesa_b2b import get_unpaid_balance, get_unpaid_balances
from tests.factories import make_admin, make_reseller, make_router
from tests.test_admin_balance_repair_unification import (
    _add_charge,
    _add_payment,
    _add_payout,
    _messy_reseller,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(arr.router)

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


_AD_SEQ = {"n": 0}


async def _credit_ad(db, reseller, share: int, *, credited: bool = True, duplicate: bool = False):
    _AD_SEQ["n"] += 1
    n = _AD_SEQ["n"]
    sale = AdSale(
        ad_id=10_000 + n, reseller_user_id=reseller.id, business_name="Shop", business_phone="254700000000",
        price_per_week=200, weeks=1, share_token=f"tok-{n}",
    )
    db.add(sale)
    await db.flush()
    db.add(AdSalePayment(
        sale_id=sale.id, ad_id=sale.ad_id, reseller_user_id=reseller.id, kind="initial", order_key=f"o-{n}",
        weeks=1, price_per_week=200, amount=200, bitwave_fee=200 - share, reseller_share=share,
        phone="254700000000", status="paid", is_duplicate=duplicate,
        credited_at=datetime.utcnow() if credited else None,
    ))
    await db.commit()


async def _resellers_with_every_shape(db):
    now = datetime.utcnow()
    messy = await _messy_reseller(db)              # 675.0 per the canonical test
    with_ads = await _messy_reseller(db)
    await _credit_ad(db, with_ads, 160)            # counts
    await _credit_ad(db, with_ads, 40, credited=False)   # not yet credited
    await _credit_ad(db, with_ads, 99, duplicate=True)   # duplicate prompt
    payouts_only = await make_reseller(db)
    await _add_payout(db, payouts_only, 80.0, created_at=now - timedelta(days=1))
    await _add_charge(db, payouts_only, 5.5, created_at=now)
    fractional = await make_reseller(db)
    for amount in (10.10, 20.20, 30.30):
        await _add_payment(db, fractional, amount, created_at=now - timedelta(hours=3))
    empty = await make_reseller(db)
    return [messy, with_ads, payouts_only, fractional, empty]


async def test_batched_balances_equal_the_payout_formula_for_every_shape(db):
    resellers = await _resellers_with_every_shape(db)

    batched = await get_unpaid_balances(db, [r.id for r in resellers])

    for r in resellers:
        assert batched[r.id] == await get_unpaid_balance(db, r.id), r.id
    assert batched[resellers[0].id] == 675.0
    assert batched[resellers[1].id] == 675.0 + 160
    assert batched[resellers[4].id] == 0.0


async def test_batched_balances_with_no_ids_is_empty(db):
    assert await get_unpaid_balances(db, []) == {}


async def test_reseller_list_rows_match_single_reseller_figures(db, client, monkeypatch):
    resellers = await _resellers_with_every_shape(db)
    router = await make_router(db, resellers[0])
    db.add(ResellerPaymentMethod(
        user_id=resellers[0].id, method_type=ResellerPaymentMethodType.MPESA_PAYBILL,
        label="Own", is_active=True, mpesa_paybill_number="555111",
    ))
    db.add(ResellerPaymentMethod(
        user_id=resellers[0].id, method_type=ResellerPaymentMethodType.MPESA_TILL,
        label="Old", is_active=False, mpesa_till_number="777",
    ))
    await db.commit()
    admin = await make_admin(db)

    async def _fake(token, db_):
        return admin
    monkeypatch.setattr(arr, "get_current_user", _fake)

    body = (await client.get("/api/admin/resellers")).json()
    rows = {row["id"]: row for row in body["resellers"]}

    for r in resellers:
        row = rows[r.id]
        assert row["unpaid_balance"] == await get_unpaid_balance(db, r.id)
        assert row["total_transaction_charges"] == await arr._total_transaction_charges(db, r.id)
    messy = rows[resellers[0].id]
    # All-time revenue counts every revenue row (DIRECT included, comp and the
    # pending row's counts_as_revenue=True included as the old per-row query did).
    assert messy["mpesa_revenue"] == 500.0 + 300.0 + 400.0 + 250.0
    assert messy["router_count"] == 1 and router.user_id == resellers[0].id
    assert messy["payment_methods_count"] == 1
    assert rows[resellers[4].id]["router_count"] == 0
    assert rows[resellers[4].id]["total_revenue"] == 0.0


async def test_reseller_list_filters_and_sorting_still_work(db, client, monkeypatch):
    resellers = await _resellers_with_every_shape(db)
    admin = await make_admin(db)

    async def _fake(token, db_):
        return admin
    monkeypatch.setattr(arr, "get_current_user", _fake)

    unpaid = (await client.get("/api/admin/resellers", params={"filter": "unpaid"})).json()
    by_balance = (await client.get(
        "/api/admin/resellers", params={"sort_by": "unpaid_balance", "sort_order": "desc"}
    )).json()

    unpaid_ids = {row["id"] for row in unpaid["resellers"]}
    assert resellers[0].id in unpaid_ids and resellers[4].id not in unpaid_ids
    assert resellers[2].id not in unpaid_ids  # payouts only: negative balance
    balances = [row["unpaid_balance"] for row in by_balance["resellers"]]
    assert balances == sorted(balances, reverse=True)

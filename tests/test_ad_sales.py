"""Selling ads through Bitwave: the split, the M-Pesa prompt and its guards,
idempotent callbacks, review timing, expiry, renewal, refunds and payouts.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.ad_sales_routes as asr
import app.api.ads_routes as ar
from app.api.ad_sales_routes import router as ad_sales_router
from app.api.ads_routes import router as ads_router
from app.db.database import get_db
from app.db.models import Ad, AdReviewEvent, AdSale, AdSalePayment, SubscriptionStatus
from app.services import ad_sales, mpesa
from app.services.ad_serving import get_live_ads_cached, invalidate_ad_cache
from app.services.auth import verify_token
from app.services.mpesa import StkPushResponse
from app.services.mpesa_b2b import get_unpaid_balance, get_unpaid_balance_by_router
from tests.factories import make_admin, make_reseller

SOLD = {
    "title": "Fresh mandazi", "seller_name": "Mama Njeri Bakery", "phone_number": "0722111222",
    "image_url": "https://media.example/mandazi.webp", "placement": "hero",
    "business_name": "Mama Njeri Bakery", "business_phone": "0722111222",
    "weeks": 2, "price_per_week": 250,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def _fresh_ad_cache():
    await invalidate_ad_cache()
    yield
    await invalidate_ad_cache()


@pytest.fixture
def stk(monkeypatch):
    """Records every STK push instead of calling Safaricom."""
    calls = []

    async def fake_push(**kwargs):
        calls.append(kwargs)
        n = len(calls)
        return StkPushResponse(checkout_request_id=f"ws_CO_{n}", merchant_request_id=f"mr_{n}")

    monkeypatch.setattr(mpesa, "initiate_stk_push_direct", fake_push)
    return calls


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(ads_router)
    application.include_router(ad_sales_router)

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


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(ar, "get_current_user", _fake)
    monkeypatch.setattr(asr, "get_current_user", _fake)


async def _reseller(db, **kw):
    kw.setdefault("subscription_status", SubscriptionStatus.ACTIVE)
    kw.setdefault("support_phone", "0712345678")
    kw.setdefault("business_name", "Acme WiFi")
    return await make_reseller(db, **kw)


def _callback(checkout_id, code=0, receipt="RKX1", amount=500, desc="ok"):
    cb = {"CheckoutRequestID": checkout_id, "ResultCode": code, "ResultDesc": desc}
    if code == 0:
        cb["CallbackMetadata"] = {"Item": [
            {"Name": "Amount", "Value": amount},
            {"Name": "MpesaReceiptNumber", "Value": receipt},
            {"Name": "PhoneNumber", "Value": 254722111222},
        ]}
    return {"Body": {"stkCallback": cb}}


async def _sell(client, monkeypatch, reseller, body=None):
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ad-sales", json=body or SOLD)
    assert r.status_code == 200, r.text
    return r.json()


async def _payments(db, ad_id):
    return list((await db.execute(
        select(AdSalePayment).where(AdSalePayment.ad_id == ad_id).order_by(AdSalePayment.id)
        .execution_options(populate_existing=True)
    )).scalars().all())


async def _ad(db, ad_id) -> Ad:
    return (await db.execute(
        select(Ad).where(Ad.id == ad_id).execution_options(populate_existing=True)
    )).scalar_one()


async def _age_prompts(db, ad_id, minutes):
    for p in await _payments(db, ad_id):
        p.created_at = p.created_at - timedelta(minutes=minutes)
    await db.commit()


async def _live_ids(db):
    await invalidate_ad_cache()
    return {a["id"] for a in await get_live_ads_cached(db)}


async def _approve(client, monkeypatch, admin, ad_id):
    _auth_as(monkeypatch, admin)
    r = await client.post(f"/api/ads/{ad_id}/review", json={"action": "approve"})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# The split and the terms
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("amount,fee,share", [
    (200, 40, 160), (500, 100, 400), (1005, 201, 804), (999, 199, 800),
    (1, 0, 1), (4, 0, 4), (5, 1, 4), (0, 0, 0), (150_000, 30_000, 120_000),
])
def test_split_floors_bitwaves_20_percent_and_gives_the_reseller_the_rest(amount, fee, share):
    assert ad_sales.split_amount(amount) == (fee, share)
    assert fee + share == amount


def test_split_is_whole_shillings_for_every_valid_order():
    for weeks in range(1, 13):
        for price in (200, 201, 333, 999, 1234, 12_500):
            fee, share = ad_sales.split_amount(weeks * price)
            assert isinstance(fee, int) and isinstance(share, int)
            assert fee + share == weeks * price
            assert fee <= weeks * price * 20 / 100 < fee + 1


@pytest.mark.parametrize("weeks,price", [(0, 300), (13, 300), (2, 199), (2, 0), (2, 12_501), (1.5, 300), (2, 250.5)])
def test_bad_terms_are_refused(weeks, price):
    with pytest.raises(Exception) as exc:
        ad_sales.validate_terms(weeks, price)
    assert getattr(exc.value, "status_code", None) == 400


def test_quote_shows_the_shop_total_the_fee_and_the_reseller_share():
    assert ad_sales.quote(3, 250) == {
        "weeks": 3, "price_per_week": 250, "amount": 750,
        "bitwave_fee": 150, "reseller_share": 600, "fee_percent": 20,
    }


@pytest.mark.asyncio
async def test_minimum_price_is_enforced_on_create(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ad-sales", json={**SOLD, "price_per_week": 150})
    assert r.status_code == 400
    assert "200" in r.json()["detail"]
    assert stk == []


# ---------------------------------------------------------------------------
# Selling: prompt goes to the shop from Bitwave's paybill
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_selling_an_ad_prompts_the_shop_on_bitwaves_paybill(client, db, monkeypatch, stk):
    reseller = await _reseller(db, settlement_mode="direct")
    out = await _sell(client, monkeypatch, reseller)

    assert len(stk) == 1
    push = stk[0]
    assert push["phone_number"] == "254722111222"
    assert push["amount"] == 500
    assert "party_b" not in push and "shortcode" not in push   # system paybill = Bitwave's
    assert push["callback_url"].endswith("/api/mpesa/ad-sales/callback")
    assert out["ad"]["slot"] == "reseller" and out["ad"]["status"] == "pending"
    assert out["sale"]["state"] == "awaiting_payment"
    assert out["sale"]["prompt"]["status"] == "waiting_for_pin"
    assert out["sale"]["amount_due"] == 500
    assert out["sale"]["prompt_result"]["sent"] is True
    assert out["ad"]["id"] not in await _live_ids(db)


@pytest.mark.asyncio
async def test_a_reseller_cannot_make_a_free_sold_ad_through_the_old_route(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ads", json={**SOLD, "slot": "reseller"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_an_approved_sold_ad_without_payment_never_runs(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _approve(client, monkeypatch, admin, ad_id)
    ad = await _ad(db, ad_id)
    assert ad.status == "approved" and ad.expires_at is None
    assert ad_id not in await _live_ids(db)


# ---------------------------------------------------------------------------
# Callbacks: paid flips automatically, exactly once
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_paid_then_approved_goes_live_for_the_paid_weeks_from_approval(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]

    r = await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    assert r.json()["ResultCode"] == 0
    p = (await _payments(db, ad_id))[0]
    assert p.status == "paid" and p.mpesa_receipt == "RKX1"
    assert p.bitwave_fee == 100 and p.reseller_share == 400
    assert p.credited_at is None                       # not running yet: nothing credited
    assert await get_unpaid_balance(db, reseller.id) == 0
    assert ad_id not in await _live_ids(db)

    _auth_as(monkeypatch, reseller)
    assert (await client.get(f"/api/ads/{ad_id}/sale")).json()["state"] == "in_review"

    before = datetime.utcnow()
    await _approve(client, monkeypatch, admin, ad_id)
    ad = await _ad(db, ad_id)
    assert ad.starts_at >= before
    assert ad.expires_at - ad.starts_at == timedelta(weeks=2)
    assert ad_id in await _live_ids(db)
    p = (await _payments(db, ad_id))[0]
    assert p.credited_at is not None
    assert await get_unpaid_balance(db, reseller.id) == 400
    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert round(sum(buckets.values()), 2) == 400 and buckets[None] == 400


@pytest.mark.asyncio
async def test_duplicate_callbacks_never_double_credit(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    for _ in range(3):
        await _approve_trust(db, reseller)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    assert out["ad"]["status"] == "approved"           # trusted: auto-approved

    for _ in range(3):
        r = await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
        assert r.json()["ResultCode"] == 0
    ad = await _ad(db, ad_id)
    assert ad.expires_at - ad.starts_at == timedelta(weeks=2)   # not 6 weeks
    assert await get_unpaid_balance(db, reseller.id) == 400


@pytest.mark.asyncio
async def test_reconciler_and_callback_together_credit_once(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    for _ in range(3):
        await _approve_trust(db, reseller)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _age_prompts(db, ad_id, 5)

    async def token(*a, **k):
        return "t"

    async def query(checkout_id, access_token=None):
        return {"result_code": 0, "result_desc": "ok"}

    monkeypatch.setattr(mpesa, "get_access_token", token)
    monkeypatch.setattr(mpesa, "query_stk_push_status", query)
    counts = await ad_sales.reconcile_ad_sale_payments()
    assert counts["paid"] == 1
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", receipt="RKZ9"))
    p = (await _payments(db, ad_id))[0]
    assert p.mpesa_receipt == "RKZ9"                   # receipt filled in later
    assert await get_unpaid_balance(db, reseller.id) == 400


# ---------------------------------------------------------------------------
# The reseller's prompt button: in flight, cancelled, timeout, re-prompt
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_second_prompt_is_blocked_while_one_is_in_flight(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})
    assert r.status_code == 409
    assert len(stk) == 1
    assert (await client.get(f"/api/ads/{ad_id}/sale")).json()["can_resend"] is False


@pytest.mark.asyncio
async def test_cancelled_by_the_shop_shows_the_reason_and_can_be_sent_again(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback",
                      json=_callback("ws_CO_1", code=1032, desc="Request cancelled by user"))
    _auth_as(monkeypatch, reseller)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["prompt"]["status"] == "cancelled"
    assert sale["prompt"]["reason"] == "Request cancelled by user"
    assert sale["state"] == "payment_failed"
    assert sale["can_resend"] is True

    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={"phone": "0733444555"})
    assert r.status_code == 200, r.text
    assert r.json()["prompt"]["status"] == "waiting_for_pin"
    assert stk[-1]["phone_number"] == "254733444555"
    assert len(stk) == 2


@pytest.mark.asyncio
async def test_an_unanswered_prompt_times_out_and_a_late_payment_still_counts(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _age_prompts(db, ad_id, 31)

    async def token(*a, **k):
        return "t"

    async def still_processing(checkout_id, access_token=None):
        raise RuntimeError("The transaction is being processed")

    monkeypatch.setattr(mpesa, "get_access_token", token)
    monkeypatch.setattr(mpesa, "query_stk_push_status", still_processing)
    counts = await ad_sales.reconcile_ad_sale_payments()
    assert counts["timed_out"] == 1
    assert (await _payments(db, ad_id))[0].status == "timed_out"

    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    assert (await _payments(db, ad_id))[0].status == "paid"
    await _approve(client, monkeypatch, admin, ad_id)
    assert ad_id in await _live_ids(db)


@pytest.mark.asyncio
async def test_re_prompt_after_a_stale_prompt_asks_safaricom_first(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _age_prompts(db, ad_id, 2)                    # past the in-flight window

    async def failed(checkout_id, access_token=None):
        return {"result_code": 1037, "result_desc": "DS timeout user cannot be reached"}

    monkeypatch.setattr(mpesa, "query_stk_push_status", failed)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})
    assert r.status_code == 200, r.text
    first, second = await _payments(db, ad_id)
    assert first.status == "timed_out" and first.result_desc.startswith("DS timeout")
    assert second.status == "awaiting_payment" and second.order_key == first.order_key


@pytest.mark.asyncio
async def test_re_prompt_when_the_earlier_prompt_was_actually_paid_sends_nothing(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _age_prompts(db, ad_id, 2)

    async def paid(checkout_id, access_token=None):
        return {"result_code": 0, "result_desc": "ok"}

    monkeypatch.setattr(mpesa, "query_stk_push_status", paid)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})
    assert r.status_code == 200
    assert r.json()["prompt_result"]["sent"] is False
    assert len(stk) == 1
    assert [p.status for p in await _payments(db, ad_id)] == ["paid"]


@pytest.mark.asyncio
async def test_at_most_three_prompts_per_ad_in_ten_minutes(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)              # prompt 1
    ad_id = out["ad"]["id"]
    for n in (1, 2):
        await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{n}", code=1032))
        _auth_as(monkeypatch, reseller)
        r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})   # prompts 2, 3
        assert r.status_code == 200, r.text
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_3", code=1032))
    _auth_as(monkeypatch, reseller)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})
    assert r.status_code == 429
    assert len(stk) == 3
    await _age_prompts(db, ad_id, 11)
    assert (await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})).status_code == 200


@pytest.mark.asyncio
async def test_two_paid_prompts_for_one_order_credit_once_and_flag_a_refund(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await _age_prompts(db, ad_id, 4)

    async def processing(checkout_id, access_token=None):
        raise RuntimeError("still processing")

    monkeypatch.setattr(mpesa, "query_stk_push_status", processing)
    _auth_as(monkeypatch, reseller)
    assert (await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})).status_code == 200
    # The shop pays BOTH prompts.
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_2", receipt="R2"))
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", receipt="R1"))
    first, second = await _payments(db, ad_id)
    assert second.status == "paid" and not second.is_duplicate
    assert first.status == "paid" and first.is_duplicate and first.refund_status == "due"

    await _approve(client, monkeypatch, admin, ad_id)
    ad = await _ad(db, ad_id)
    assert ad.expires_at - ad.starts_at == timedelta(weeks=2)
    assert await get_unpaid_balance(db, reseller.id) == 400


# ---------------------------------------------------------------------------
# Rejection after payment, refunds, takedown
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rejected_after_payment_never_runs_and_waits_for_an_admin_refund(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))

    _auth_as(monkeypatch, admin)
    r = await client.post(f"/api/ads/{ad_id}/review", json={"action": "reject", "note": "Blurry photo"})
    assert r.status_code == 200
    p = (await _payments(db, ad_id))[0]
    assert p.refund_status == "due" and p.credited_at is None
    assert ad_id not in await _live_ids(db)
    assert await get_unpaid_balance(db, reseller.id) == 0

    queue = (await client.get("/api/ad-sales?payout_status=refund_due")).json()
    assert [s["ad_id"] for s in queue["sales"]] == [ad_id]
    assert queue["totals"]["refund_due_total"] == 500

    r = await client.post(f"/api/ad-sales/payments/{p.id}/refund", json={"note": "Sent back by M-Pesa"})
    assert r.status_code == 200 and r.json()["refund_status"] == "refunded"
    # Approving it later doesn't revive refunded money.
    await _approve(client, monkeypatch, admin, ad_id)
    assert ad_id not in await _live_ids(db)


@pytest.mark.asyncio
async def test_only_admins_record_refunds_or_take_ads_down(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    p = (await _payments(db, ad_id))[0]
    _auth_as(monkeypatch, reseller)
    assert (await client.post(f"/api/ad-sales/payments/{p.id}/refund", json={})).status_code == 403
    assert (await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "x"})).status_code == 403


@pytest.mark.asyncio
async def test_takedown_stops_a_live_ad_and_ends_auto_approval(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    for _ in range(3):
        await _approve_trust(db, reseller)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    assert ad_id in await _live_ids(db)

    _auth_as(monkeypatch, admin)
    r = await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading offer"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert ad_id not in await _live_ids(db)

    # An edit doesn't put it back live, and the reseller is no longer trusted.
    _auth_as(monkeypatch, reseller)
    r = await client.put(f"/api/ads/{ad_id}", json={"title": "Fresh mandazi daily"})
    assert r.json()["status"] == "pending"
    out2 = await _sell(client, monkeypatch, reseller, {**SOLD, "title": "Chapati"})
    assert out2["ad"]["status"] == "pending"


@pytest.mark.asyncio
async def test_admin_can_take_down_bitwaves_own_and_house_ads(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    _auth_as(monkeypatch, reseller)
    house = (await client.post("/api/ads", json={
        "title": "Our WiFi", "seller_name": "x", "phone_number": "0712345678",
        "image_url": "https://media.example/w.webp", "placement": "hero",
    })).json()
    assert house["status"] == "approved"
    _auth_as(monkeypatch, admin)
    r = await client.post(f"/api/ads/{house['id']}/takedown", json={"note": "Offensive"})
    assert r.json()["status"] == "rejected"
    _auth_as(monkeypatch, reseller)
    r = await client.put(f"/api/ads/{house['id']}", json={"title": "Our WiFi, fast"})
    assert r.json()["status"] == "pending"          # waits for an admin after a takedown


# ---------------------------------------------------------------------------
# Auto-approve threshold
# ---------------------------------------------------------------------------

async def _approve_trust(db, reseller):
    """One sold ad approved by an admin, as the review history records it."""
    ad = Ad(title="t", seller_name="s", phone_number="0712345678", image_url="https://m/x.webp",
            slot="reseller", owner_user_id=reseller.id, status="approved")
    db.add(ad)
    await db.flush()
    db.add(AdReviewEvent(ad_id=ad.id, owner_user_id=reseller.id, slot="reseller", action="approve"))
    await db.commit()
    return ad


@pytest.mark.asyncio
async def test_sold_ads_auto_approve_after_three_approvals_and_no_rejections(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    for i in range(3):
        out = await _sell(client, monkeypatch, reseller, {**SOLD, "title": f"Offer {i}"})
        assert out["ad"]["status"] == "pending"
        await _approve(client, monkeypatch, admin, out["ad"]["id"])
    out = await _sell(client, monkeypatch, reseller, {**SOLD, "title": "Offer 4"})
    assert out["ad"]["status"] == "approved"
    ad_id = out["ad"]["id"]
    # Paid -> live with no step for anyone.
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}"))
    assert ad_id in await _live_ids(db)


@pytest.mark.asyncio
async def test_one_rejection_keeps_sold_ads_in_review(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    for _ in range(4):
        await _approve_trust(db, reseller)
    rejected = await _sell(client, monkeypatch, reseller)
    assert rejected["ad"]["status"] == "approved"
    db.add(AdReviewEvent(ad_id=rejected["ad"]["id"], owner_user_id=reseller.id, slot="reseller", action="reject"))
    await db.commit()
    out = await _sell(client, monkeypatch, reseller, {**SOLD, "title": "Next"})
    assert out["ad"]["status"] == "pending"


# ---------------------------------------------------------------------------
# Expiry and renewal
# ---------------------------------------------------------------------------

async def _live_sold_ad(client, db, monkeypatch, stk, reseller):
    for _ in range(3):
        await _approve_trust(db, reseller)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}"))
    return ad_id


@pytest.mark.asyncio
async def test_the_ad_stops_by_itself_when_the_paid_weeks_end(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    assert ad_id in await _live_ids(db)
    ad = await _ad(db, ad_id)
    ad.starts_at = datetime.utcnow() - timedelta(weeks=2, minutes=1)
    ad.expires_at = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()
    assert ad_id not in await _live_ids(db)
    _auth_as(monkeypatch, reseller)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "ended" and sale["can_renew"] is True


@pytest.mark.asyncio
async def test_renewal_is_offered_two_days_before_expiry_and_extends_the_end(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    _auth_as(monkeypatch, reseller)
    assert (await client.get(f"/api/ads/{ad_id}/sale")).json()["renewal_due"] is False

    ad = await _ad(db, ad_id)
    end = datetime.utcnow() + timedelta(days=1)
    ad.expires_at = end
    await db.commit()
    await _age_prompts(db, ad_id, 11)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["renewal_due"] is True

    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={"weeks": 1})
    assert r.status_code == 200, r.text
    assert stk[-1]["amount"] == 250 and stk[-1]["phone_number"] == "254722111222"
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RNEW", amount=250))
    ad = await _ad(db, ad_id)
    assert abs((ad.expires_at - end) - timedelta(weeks=1)) < timedelta(seconds=1)
    assert await get_unpaid_balance(db, reseller.id) == 400 + 200


@pytest.mark.asyncio
async def test_renewal_after_the_end_starts_a_new_period_now(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    ad = await _ad(db, ad_id)
    ad.expires_at = datetime.utcnow() - timedelta(days=3)
    await db.commit()
    await _age_prompts(db, ad_id, 11)
    _auth_as(monkeypatch, reseller)
    assert (await client.post(f"/api/ads/{ad_id}/sale/renew", json={})).status_code == 200
    before = datetime.utcnow()
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RN2"))
    ad = await _ad(db, ad_id)
    assert ad.starts_at >= before and ad.expires_at - ad.starts_at == timedelta(weeks=2)
    assert ad_id in await _live_ids(db)


@pytest.mark.asyncio
async def test_a_sold_ads_dates_and_type_cant_be_edited(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    _auth_as(monkeypatch, reseller)
    far = (datetime.utcnow() + timedelta(days=400)).isoformat()
    assert (await client.put(f"/api/ads/{ad_id}", json={"expires_at": far})).status_code == 400
    assert (await client.put(f"/api/ads/{ad_id}", json={"slot": "house"})).status_code == 400


@pytest.mark.asyncio
async def test_a_running_or_unpaid_in_flight_sold_ad_cant_be_deleted(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    _auth_as(monkeypatch, reseller)
    assert (await client.delete(f"/api/ads/{ad_id}")).status_code == 409
    out = await _sell(client, monkeypatch, reseller, {**SOLD, "title": "Another"})
    assert (await client.delete(f"/api/ads/{out['ad']['id']}")).status_code == 409


# ---------------------------------------------------------------------------
# Reports, lists, earnings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_shop_link_shows_views_taps_and_dates_but_nothing_private(client, db, monkeypatch, stk):
    from app.db.models import AdEvent
    reseller = await _reseller(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    db.add_all([
        AdEvent(ad_id=ad_id, event_type="impression", placement="hero", device_key="AA:BB:CC:DD:EE:01", day=today),
        AdEvent(ad_id=ad_id, event_type="impression", placement="hero", device_key="AA:BB:CC:DD:EE:02", day=today),
        AdEvent(ad_id=ad_id, event_type="click", click_type="call", placement="hero", device_key="AA:BB:CC:DD:EE:01", day=today),
    ])
    await db.commit()
    sale = (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one()
    r = await client.get(f"/api/public/promo/{sale.share_token}")
    assert r.status_code == 200
    body = r.json()
    assert body["views"] == 2 and body["taps"] == 1 and body["state"] == "live"
    assert body["live_from"] and body["live_until"]
    text = str(body)
    for private in ("reseller_share", "bitwave_fee", "254722111222", "0722111222", "AA:BB", "router"):
        assert private not in text, private
    assert (await client.get("/api/public/promo/nope")).status_code == 404


@pytest.mark.asyncio
async def test_the_shop_can_send_itself_the_prompt_from_its_link(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", code=1032))
    sale = (await db.execute(select(AdSale).where(AdSale.ad_id == ad_id))).scalar_one()
    report = (await client.get(f"/api/public/promo/{sale.share_token}")).json()
    assert report["payment_due"]["amount"] == 500
    r = await client.post(f"/api/public/promo/{sale.share_token}/pay", json={})
    assert r.status_code == 200 and r.json()["sent"] is True
    r = await client.post(f"/api/public/promo/{sale.share_token}/pay", json={})
    assert r.status_code == 409                         # in flight


@pytest.mark.asyncio
async def test_admin_list_shows_amount_fee_and_payout_status(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    _auth_as(monkeypatch, admin)
    body = (await client.get("/api/ad-sales")).json()
    row = next(s for s in body["sales"] if s["ad_id"] == ad_id)
    assert row["paid_total"] == 500 and row["bitwave_fee_total"] == 100
    assert row["reseller_share_total"] == 400 and row["payout_status"] == "credited"
    assert row["owner_name"] == "Acme WiFi"
    _auth_as(monkeypatch, reseller)
    mine = (await client.get("/api/ad-sales")).json()
    assert mine["review"]["auto_approve"] is True


@pytest.mark.asyncio
async def test_bitwaves_20_percent_is_ad_commission_in_platform_earnings(client, db, monkeypatch, stk):
    from app.services.platform_earnings import compute_platform_earnings
    reseller = await _reseller(db)
    await _live_sold_ad(client, db, monkeypatch, stk, reseller)
    result = await compute_platform_earnings(db, "month")
    streams = {s["key"]: s["total"] for s in result["earnings"]["streams"]}
    assert streams["ad_commission"] == 100
    assert result["earnings"]["ad_commission"] == 100
    assert result["transaction_volume"]["total"] == 0   # ad money is not hotspot volume

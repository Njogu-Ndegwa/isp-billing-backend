"""Dennis's money rules for sold ads (5 Nov 2026): refunds of unused days and the
debit that recovers the reseller's part, time off not using up paid time, price
changes applying from the next renewal, and all of it safe to repeat.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

import app.api.portal_routes as portal_routes
from app.db.database import get_db
from app.db.models import AdSale, AdSalePayment, ResellerPayout, ResellerTransactionCharge
from app.services import ad_sales
from app.services.auth import verify_token
from app.services.mpesa_b2b import compute_fee_breakdown, get_unpaid_balance, get_unpaid_balance_by_router
from tests.factories import make_admin
from tests.test_ad_sales import (  # noqa: F401  (client, app, stk and the autouse ones are fixtures)
    SOLD,
    _ad,
    _age_prompts,
    _auth_as,
    _callback,
    _fresh_ad_cache,
    _live_ids,
    _payments,
    _reseller,
    _selling_open,
    _sell,
    app,
    client,
    stk,
)

ONE_WEEK_200 = {**SOLD, "weeks": 1, "price_per_week": 200}


async def _live(client, db, monkeypatch, stk, reseller, body=None, receipt="RKX1"):
    out = await _sell(client, monkeypatch, reseller, body or ONE_WEEK_200)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt=receipt))
    assert ad_id in await _live_ids(db)
    return ad_id


async def _used(db, ad_id, days):
    """Pretend the ad has already run for this many days."""
    ad = await _ad(db, ad_id)
    ad.starts_at -= timedelta(days=days)
    ad.expires_at -= timedelta(days=days)
    await db.commit()


async def _stay_off(db, ad_id, days):
    """Pretend the ad went off this many days ago: everything moves back together."""
    row = await _sale(db, ad_id)
    row.off_since -= timedelta(days=days)
    ad = await _ad(db, ad_id)
    ad.starts_at -= timedelta(days=days)
    ad.expires_at -= timedelta(days=days)
    await db.commit()


async def _sale(db, ad_id) -> AdSale:
    return (await db.execute(
        select(AdSale).where(AdSale.ad_id == ad_id).execution_options(populate_existing=True)
    )).scalar_one()


async def _recovery_charges(db, reseller):
    return list((await db.execute(
        select(ResellerTransactionCharge).where(
            ResellerTransactionCharge.reseller_id == reseller.id,
            ResellerTransactionCharge.reference.startswith("ad-refund:"),
        )
    )).scalars().all())


async def _fresh_payments(db, ad_id):
    return list((await db.execute(
        select(AdSalePayment).where(AdSalePayment.ad_id == ad_id).order_by(AdSalePayment.id)
        .execution_options(populate_existing=True)
    )).scalars().all())


# ---------------------------------------------------------------------------
# Rule 1: the arithmetic, to the shilling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("amount,paid,unused,expected", [
    (200, 7, 3, (85, 68, 17)),     # 85.71 rounds down; kept 115 splits 23 / 92
    (200, 7, 7, (200, 160, 40)),   # all of it
    (200, 7, 0, (0, 0, 0)),
    (200, 7, 9, (200, 160, 40)),   # never more than was paid
    (1005, 7, 1, (143, 114, 29)),
    (500, 14, 7, (250, 200, 50)),
    (200, 0, 3, (0, 0, 0)),
    (1, 7, 3, (0, 0, 0)),          # 0.43 rounds down: nothing to give back
    (1, 7, 7, (1, 1, 0)),
    (4, 7, 6, (3, 3, 0)),          # no fee on KES 4, so all of it is the reseller's
    (5, 7, 6, (4, 3, 1)),          # kept 1 splits 0 / 1, and the KES 1 fee goes back
    (5, 7, 2, (1, 0, 1)),          # kept 4 still splits 0 / 4
])
def test_refund_for_unused_days(amount, paid, unused, expected):
    assert ad_sales.refund_for_unused_days(amount, paid, unused) == expected


def test_the_refund_and_both_splits_add_up_for_every_order_and_day():
    for weeks in range(1, ad_sales.MAX_WEEKS + 1):
        for price in (1, 2, 3, 4, 5, 6, 9, 10, 199, 200, 201, 333, 999, 1234, 12_500, 20_833):
            amount = weeks * price
            fee, share = ad_sales.split_amount(amount)
            paid_days = weeks * 7
            for unused in range(paid_days + 1):
                refund, reseller_part, bitwave_part = ad_sales.refund_for_unused_days(amount, paid_days, unused)
                assert reseller_part + bitwave_part == refund
                assert 0 <= reseller_part <= share and 0 <= bitwave_part <= fee
                # What each side keeps is exactly the 80/20 of what the shop kept paying.
                assert (fee - bitwave_part, share - reseller_part) == ad_sales.split_amount(amount - refund)


# ---------------------------------------------------------------------------
# Rule 1: takedown after the share was paid out
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_takedown_after_payout_refunds_unused_days_and_debits_the_reseller(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    assert await get_unpaid_balance(db, reseller.id) == 160

    # The nightly payout paid it: KES 155 to the bank plus the KES 5 fee.
    fee, _, net = compute_fee_breakdown(160)
    assert (fee, net) == (5, 155)
    db.add(ResellerPayout(reseller_id=reseller.id, amount=net, payment_method="mpesa_b2b", reference="B2B1"))
    db.add(ResellerTransactionCharge(reseller_id=reseller.id, amount=fee, description="M-Pesa B2B fee", created_by=admin.id))
    await db.commit()
    assert await get_unpaid_balance(db, reseller.id) == 0

    await _used(db, ad_id, 3.5)  # 3 whole days of the 7 are left
    _auth_as(monkeypatch, admin)
    r = await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading"})
    assert r.status_code == 200
    assert r.json()["sale"]["refund_due_total"] == 85
    assert ad_id not in await _live_ids(db)

    p = (await _fresh_payments(db, ad_id))[0]
    assert (p.refund_status, p.refund_amount, p.refund_unused_days) == ("due", 85, 3)
    assert (p.reseller_recovery, p.bitwave_refund_part) == (68, 17)
    assert p.credited_at is not None and p.amount == 200   # what was paid stays on record
    assert "3 of 7" in p.refund_reason and "Misleading" in p.refund_reason

    charges = await _recovery_charges(db, reseller)
    assert [(c.amount, c.reference, c.created_by) for c in charges] == [(68, f"ad-refund:{p.id}", admin.id)]
    assert p.recovery_charge_id == charges[0].id

    # Netted off the payout, not sent anywhere: the balance goes below zero and
    # stays owed, split or not.
    assert await get_unpaid_balance(db, reseller.id) == -68
    buckets = await get_unpaid_balance_by_router(db, reseller.id)
    assert round(sum(buckets.values()), 2) == -68

    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "taken_down" and sale["payout_status"] == "refund_due"
    assert sale["paid_total"] == 200 and sale["shop_net_total"] == 115
    assert sale["reseller_share_net_total"] == 92 and sale["bitwave_fee_net_total"] == 23
    assert sale["reseller_recovered_total"] == 68 and sale["bitwave_refund_part_total"] == 17
    assert sale["payments"][0]["refund_amount"] == 85


@pytest.mark.asyncio
async def test_a_repeat_takedown_or_rejection_or_callback_adds_nothing(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 3.5)
    _auth_as(monkeypatch, admin)
    for _ in range(2):
        assert (await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading"})).status_code == 200
    assert (await client.post(f"/api/ads/{ad_id}/review", json={"action": "reject", "note": "Again"})).status_code == 200
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))

    p = (await _fresh_payments(db, ad_id))[0]
    assert (p.refund_amount, p.reseller_recovery) == (85, 68)
    assert len(await _recovery_charges(db, reseller)) == 1
    assert await get_unpaid_balance(db, reseller.id) == 160 - 68
    queue = (await client.get("/api/ad-sales?payout_status=refund_due")).json()
    assert queue["totals"]["refund_due_total"] == 85

    # Marking it refunded moves the row, not the debit.
    r = await client.post(f"/api/ad-sales/payments/{p.id}/refund", json={})
    assert r.status_code == 200 and r.json()["refund_status"] == "refunded"
    assert r.json()["refund_amount"] == 85
    assert await get_unpaid_balance(db, reseller.id) == 160 - 68
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["refund_due_total"] == 0 and sale["refunded_total"] == 85


@pytest.mark.asyncio
async def test_a_stopped_ad_cant_run_free_when_it_is_put_back(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 3.5)
    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading"})
    r = await client.post(f"/api/ads/{ad_id}/review", json={"action": "approve"})
    assert r.json()["status"] == "approved"
    assert ad_id not in await _live_ids(db)            # the refunded days are gone
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "ended" and sale["can_renew"] is True


@pytest.mark.asyncio
async def test_unused_days_come_off_the_newest_payment_at_its_own_price(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)     # 1 week at 200
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={"weeks": 1, "price_per_week": 700, "confirm_new_price": True})
    assert r.status_code == 200, r.text
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RKX2", amount=700))
    await _used(db, ad_id, 3.5)     # 10 whole days of 14 left: all 7 of the renewal, 3 of the first

    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Closed down"})
    first, renewal = await _fresh_payments(db, ad_id)
    assert (renewal.refund_amount, renewal.reseller_recovery, renewal.bitwave_refund_part) == (700, 560, 140)
    assert (first.refund_amount, first.reseller_recovery, first.bitwave_refund_part) == (85, 68, 17)
    assert sorted(c.amount for c in await _recovery_charges(db, reseller)) == [68, 560]
    assert await get_unpaid_balance(db, reseller.id) == 160 + 560 - 68 - 560
    assert (first.amount, first.price_per_week, renewal.amount, renewal.price_per_week) == (200, 200, 700, 700)


@pytest.mark.asyncio
async def test_rejecting_an_ad_that_ran_refunds_its_unused_days(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 3.5)
    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/review", json={"action": "reject", "note": "Wrong number"})
    p = (await _fresh_payments(db, ad_id))[0]
    assert p.refund_amount == 85 and p.reseller_recovery == 68
    assert p.refund_reason.startswith("Rejected with 3 of 7")
    assert ad_id not in await _live_ids(db)


@pytest.mark.asyncio
async def test_an_ad_that_used_all_its_days_owes_nothing(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 7)
    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Old"})
    p = (await _fresh_payments(db, ad_id))[0]
    assert p.refund_status is None and p.refund_amount is None
    assert await _recovery_charges(db, reseller) == []
    assert await get_unpaid_balance(db, reseller.id) == 160


@pytest.mark.asyncio
async def test_a_renewal_paid_after_the_takedown_is_a_full_refund_with_nothing_to_recover(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    await client.post(f"/api/ads/{ad_id}/sale/renew", json={})
    checkout = f"ws_CO_{len(stk)}"
    await _used(db, ad_id, 7)
    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Closed"})

    await client.post("/api/mpesa/ad-sales/callback", json=_callback(checkout, receipt="RKX2", amount=200))
    p = (await _fresh_payments(db, ad_id))[-1]
    assert p.refund_status == "due" and p.credited_at is None and p.refund_amount is None
    assert await _recovery_charges(db, reseller) == []
    assert await get_unpaid_balance(db, reseller.id) == 160
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["refund_due_total"] == 200
    assert sale["payments"][0]["refund_amount"] == 200


@pytest.mark.asyncio
async def test_earnings_and_reports_take_the_refund_off(client, db, monkeypatch, stk):
    from app.core.cache import cache
    from app.services.platform_earnings import PLATFORM_EARNINGS_CACHE_PREFIX, compute_platform_earnings

    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 3.5)
    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading"})
    await cache.clear_pattern(PLATFORM_EARNINGS_CACHE_PREFIX)
    try:
        result = await compute_platform_earnings(db, "month")
    finally:
        # The cache outlives the test; another test must not read these numbers.
        await cache.clear_pattern(PLATFORM_EARNINGS_CACHE_PREFIX)
    streams = {s["key"]: s["total"] for s in result["earnings"]["streams"]}
    assert streams["ad_commission"] == 40 - 17
    assert result["not_counted"]["ad_refunds_due"] == 85
    assert result["not_counted"]["reseller_transaction_charges"] == 0   # not money Bitwave recovered


# ---------------------------------------------------------------------------
# Rule 3: time off doesn't use up paid time
# ---------------------------------------------------------------------------

def _pair(days_left=7, active=True):
    now = datetime(2026, 11, 5, 12, 0)
    ad = ad_sales.Ad(id=1, slot="reseller", status="approved", is_active=active,
                     starts_at=now, expires_at=now + timedelta(days=days_left))
    sale = ad_sales.AdSale(ad_id=1, reseller_user_id=1, off_since=None, off_seconds_total=0)
    return now, ad, sale


def test_pause_then_resume_moves_the_end_out_by_the_time_off():
    now, ad, sale = _pair()
    ends = ad.expires_at
    ad.is_active = False
    assert ad_sales.apply_off_state(sale, ad, True, now + timedelta(days=2)) is True
    assert sale.off_since == now + timedelta(days=2)
    # The clock is stopped: 5 days are left however long it stays off.
    assert ad_sales.paid_until(ad, sale, now + timedelta(days=4)) - (now + timedelta(days=4)) == timedelta(days=5)
    assert ad_sales.paid_until(ad, sale, now + timedelta(days=30)) - (now + timedelta(days=30)) == timedelta(days=5)
    assert ad.expires_at == ends

    ad.is_active = True
    assert ad_sales.apply_off_state(sale, ad, True, now + timedelta(days=5)) is True
    assert ad.expires_at == ends + timedelta(days=3)
    assert sale.off_since is None and sale.off_seconds_total == 3 * 86_400
    # Doing it twice changes nothing.
    assert ad_sales.apply_off_state(sale, ad, True, now + timedelta(days=6)) is False
    assert ad.expires_at == ends + timedelta(days=3)


def test_two_pauses_add_up_and_overlapping_reasons_count_once():
    now, ad, sale = _pair()
    ends = ad.expires_at
    t = lambda days: now + timedelta(days=days)  # noqa: E731

    ad.is_active = False
    ad_sales.apply_off_state(sale, ad, True, t(1))
    ad_sales.apply_off_state(sale, ad, False, t(2))         # Show Ads off too: one clock
    assert sale.off_since == t(1)
    ad.is_active = True
    ad_sales.apply_off_state(sale, ad, False, t(3))         # resumed, Show Ads still off
    assert sale.off_since == t(1) and ad.expires_at == ends
    ad_sales.apply_off_state(sale, ad, True, t(4))          # Show Ads on: 3 days off in all
    assert sale.off_since is None and ad.expires_at == ends + timedelta(days=3)

    ad.is_active = False
    ad_sales.apply_off_state(sale, ad, True, t(5))
    ad.is_active = True
    ad_sales.apply_off_state(sale, ad, True, t(7))
    assert ad.expires_at == ends + timedelta(days=5)
    assert sale.off_seconds_total == 5 * 86_400


def test_an_ad_past_its_end_has_nothing_to_protect():
    now, ad, sale = _pair()
    ad.is_active = False
    assert ad_sales.apply_off_state(sale, ad, True, now + timedelta(days=8)) is False
    assert sale.off_since is None


@pytest.mark.asyncio
async def test_pausing_a_live_ad_through_the_api_gives_the_days_back(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    ends = (await _ad(db, ad_id)).expires_at
    _auth_as(monkeypatch, reseller)

    assert (await client.put(f"/api/ads/{ad_id}", json={"is_active": False})).status_code == 200
    assert ad_id not in await _live_ids(db)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "paused" and sale["clock_stopped"] is True and sale["off_reason"] == "paused"
    assert (await _ad(db, ad_id)).expires_at == ends

    row = await _sale(db, ad_id)
    row.off_since -= timedelta(days=3)    # it stayed off for 3 days
    await db.commit()
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert datetime.fromisoformat(sale["live_until"]) - ends >= timedelta(days=3)

    r = await client.put(f"/api/ads/{ad_id}", json={"is_active": True})
    assert r.status_code == 200
    ad = await _ad(db, ad_id)
    assert timedelta(days=3) <= ad.expires_at - ends < timedelta(days=3, minutes=1)
    assert ad_id in await _live_ids(db)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "live" and sale["clock_stopped"] is False
    assert sale["off_seconds_total"] >= 3 * 86_400


@pytest.mark.asyncio
async def test_a_live_edit_doesnt_stop_the_clock(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    ends = (await _ad(db, ad_id)).expires_at
    _auth_as(monkeypatch, reseller)
    await client.put(f"/api/ads/{ad_id}", json={"title": "New words"})
    assert (await _sale(db, ad_id)).off_since is None
    assert (await _ad(db, ad_id)).expires_at == ends


@pytest.mark.asyncio
async def test_show_ads_off_then_on_through_the_portal_settings_route(client, db, monkeypatch, stk, session_factory):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    ends = (await _ad(db, ad_id)).expires_at

    portal_app = FastAPI()
    portal_app.include_router(portal_routes.router)

    async def _db():
        async with session_factory() as s:
            yield s
            await s.commit()

    async def _me(token, db):
        return reseller

    portal_app.dependency_overrides[get_db] = _db
    portal_app.dependency_overrides[verify_token] = lambda: "tok"
    monkeypatch.setattr(portal_routes, "get_current_user", _me)
    async with AsyncClient(transport=ASGITransport(app=portal_app), base_url="http://test") as portal:
        r = await portal.put("/api/portal/settings", json={"show_ads": False})
        assert r.status_code == 200, r.text
        row = await _sale(db, ad_id)
        assert row.off_since is not None
        _auth_as(monkeypatch, reseller)
        sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
        assert sale["state"] == "paused" and sale["off_reason"] == "show_ads_off"

        row.off_since -= timedelta(days=2)
        await db.commit()
        r = await portal.put("/api/portal/settings", json={"show_ads": True})
        assert r.status_code == 200, r.text
    assert (await _sale(db, ad_id)).off_since is None
    ad = await _ad(db, ad_id)
    assert timedelta(days=2) <= ad.expires_at - ends < timedelta(days=2, minutes=1)


@pytest.mark.asyncio
async def test_takedown_while_paused_refunds_the_days_still_owed(client, db, monkeypatch, stk):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 3.5)
    _auth_as(monkeypatch, reseller)
    await client.put(f"/api/ads/{ad_id}", json={"is_active": False})
    # Off for longer than the raw end date: 3 whole days are still owed.
    await _stay_off(db, ad_id, 10)

    _auth_as(monkeypatch, admin)
    await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Closed"})
    p = (await _fresh_payments(db, ad_id))[0]
    assert p.refund_amount == 85 and p.refund_unused_days == 3
    assert (await _sale(db, ad_id)).off_since is None
    # Coming back later can't move the end date out again.
    ad = await _ad(db, ad_id)
    ends = ad.expires_at
    ad_sales.apply_off_state(await _sale(db, ad_id), ad, True, datetime.utcnow())
    assert ad.expires_at == ends


@pytest.mark.asyncio
async def test_a_renewal_paid_during_time_off_keeps_the_days_owed_and_waits(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    await client.put(f"/api/ads/{ad_id}", json={"is_active": False})
    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={})
    assert r.status_code == 200, r.text
    # Off so long that the raw end date has passed: the days are still owed.
    await _stay_off(db, ad_id, 30)

    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RKX2", amount=200))
    assert (await _sale(db, ad_id)).off_since is not None
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    left = datetime.fromisoformat(sale["live_until"]) - datetime.utcnow()
    assert timedelta(days=13, hours=23) < left <= timedelta(days=14)   # 7 + 7, nothing lost

    await client.put(f"/api/ads/{ad_id}", json={"is_active": True})
    ad = await _ad(db, ad_id)
    assert timedelta(days=13, hours=23) < ad.expires_at - datetime.utcnow() <= timedelta(days=14)
    assert ad_id in await _live_ids(db)
    assert await get_unpaid_balance(db, reseller.id) == 320


@pytest.mark.asyncio
async def test_a_payment_while_paused_starts_a_period_that_waits(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller, ONE_WEEK_200)
    ad_id = out["ad"]["id"]
    _auth_as(monkeypatch, reseller)
    await client.put(f"/api/ads/{ad_id}", json={"is_active": False})
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1"))
    assert (await _sale(db, ad_id)).off_since is not None
    assert await get_unpaid_balance(db, reseller.id) == 160
    await _stay_off(db, ad_id, 2)
    await client.put(f"/api/ads/{ad_id}", json={"is_active": True})
    ad = await _ad(db, ad_id)
    assert timedelta(days=6, hours=23) < ad.expires_at - datetime.utcnow() <= timedelta(days=7)


@pytest.mark.asyncio
async def test_a_paused_or_show_ads_off_paid_ad_cant_be_deleted(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _used(db, ad_id, 6)
    _auth_as(monkeypatch, reseller)
    await client.put(f"/api/ads/{ad_id}", json={"is_active": False})
    await _stay_off(db, ad_id, 5)   # the raw end date has passed, a day is still owed
    assert (await client.delete(f"/api/ads/{ad_id}")).status_code == 409


# ---------------------------------------------------------------------------
# Rule 4: gross split. The price is the reseller's (Dennis, 6 Nov 2026)
# ---------------------------------------------------------------------------

def test_the_split_is_on_the_gross_amount_and_no_mpesa_fee_is_taken():
    q = ad_sales.quote(1, 200)
    assert (q["amount"], q["bitwave_fee"], q["reseller_share"]) == (200, 40, 160)


@pytest.mark.parametrize("price,ok", [(12_501, True), (250_000, True), (250_001, False)])
def test_the_only_ceiling_is_one_mpesa_payment(price, ok):
    assert ad_sales.MAX_TOTAL == 250_000
    if ok:
        assert ad_sales.validate_terms(1, price)[1] == price
    else:
        with pytest.raises(Exception):
            ad_sales.validate_terms(1, price)


# ---------------------------------------------------------------------------
# Tiny prices: the money still adds up and nothing goes negative
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("price,fee,share,refund,reseller_part,bitwave_part", [
    (1, 0, 1, 0, 0, 0),     # 3 of 7 days of KES 1 is under a shilling: no refund, no debit
    (4, 0, 4, 1, 1, 0),
    (5, 1, 4, 2, 1, 1),     # kept 3 splits 0 / 3
])
@pytest.mark.asyncio
async def test_a_tiny_payment_goes_live_credits_and_stops_cleanly(client, db, monkeypatch, stk, price, fee, share,
                                                                  refund, reseller_part, bitwave_part):
    reseller, admin = await _reseller(db), await make_admin(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller, {**SOLD, "weeks": 1, "price_per_week": price})
    p = (await _fresh_payments(db, ad_id))[0]
    assert (p.amount, p.bitwave_fee, p.reseller_share) == (price, fee, share) and p.credited_at is not None
    assert await get_unpaid_balance(db, reseller.id) == share

    await _used(db, ad_id, 3.5)     # 3 whole days of the 7 are left
    _auth_as(monkeypatch, admin)
    for _ in range(2):              # and repeating it adds nothing
        assert (await client.post(f"/api/ads/{ad_id}/takedown", json={"note": "Misleading"})).status_code == 200
    assert ad_id not in await _live_ids(db)

    p = (await _fresh_payments(db, ad_id))[0]
    charges = await _recovery_charges(db, reseller)
    assert await get_unpaid_balance(db, reseller.id) == share - reseller_part >= 0
    if refund:
        assert (p.refund_status, p.refund_amount) == ("due", refund)
        assert (p.reseller_recovery, p.bitwave_refund_part) == (reseller_part, bitwave_part)
        assert [c.amount for c in charges] == [reseller_part]
    else:
        assert p.refund_status is None and charges == []
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["state"] == "taken_down"
    assert sale["shop_net_total"] == price - refund
    assert sale["reseller_share_net_total"] + sale["bitwave_fee_net_total"] == price - refund


@pytest.mark.asyncio
async def test_a_kes_1_renewal_and_shop_link_prompt_work(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller, {**SOLD, "weeks": 1, "price_per_week": 3})
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    r = await client.post(f"/api/ads/{ad_id}/sale/renew",
                          json={"weeks": 2, "price_per_week": 1, "confirm_new_price": True})
    assert r.status_code == 200, r.text
    assert stk[-1]["amount"] == 2
    assert r.json()["due_price_per_week"] == 1 and r.json()["price_changed_from"] == 3

    await _age_prompts(db, ad_id, 20)
    sale = await _sale(db, ad_id)
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))
    r = await client.post(f"/api/public/promo/{sale.share_token}/pay", json={})
    assert r.status_code == 200, r.text
    assert stk[-1]["amount"] == 2

    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RKX2", amount=2))
    renewal = (await _fresh_payments(db, ad_id))[-1]
    assert (renewal.status, renewal.amount, renewal.bitwave_fee, renewal.reseller_share) == ("paid", 2, 0, 2)
    assert (await _sale(db, ad_id)).price_per_week == 1


@pytest.mark.parametrize("body", [
    {"price_per_week": 0, "confirm_new_price": True},
    {"weeks": 0},
    {"weeks": 12, "price_per_week": 20_834, "confirm_new_price": True},
])
@pytest.mark.asyncio
async def test_a_renewal_with_bad_terms_is_refused_instead_of_falling_back(client, db, monkeypatch, stk, body):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    sent = len(stk)
    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json=body)
    assert r.status_code == 400
    assert len(stk) == sent and len(await _fresh_payments(db, ad_id)) == 1


@pytest.mark.asyncio
async def test_an_order_at_the_old_top_price_can_still_be_sent_again(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller, {**SOLD, "weeks": 12, "price_per_week": 12_500})
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))
    await _age_prompts(db, ad_id, 20)
    assert (await client.post(f"/api/ads/{ad_id}/sale/prompt", json={})).status_code == 200
    assert stk[-1]["amount"] == 150_000


# ---------------------------------------------------------------------------
# Rule 6: a new price applies from the next renewal, and the shop is told
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_new_price_needs_the_reseller_to_say_the_shop_was_told(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    sent = len(stk)

    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={"price_per_week": 300})
    assert r.status_code == 409 and "KES 200" in r.json()["detail"] and "KES 300" in r.json()["detail"]
    assert len(stk) == sent and len(await _payments(db, ad_id)) == 1

    # The same price needs nothing.
    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={})
    assert r.status_code == 200 and len(stk) == sent + 1


@pytest.mark.asyncio
async def test_a_new_price_leaves_the_paid_period_alone_until_the_renewal_is_paid(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    ends = (await _ad(db, ad_id)).expires_at
    _auth_as(monkeypatch, reseller)

    r = await client.post(f"/api/ads/{ad_id}/sale/renew", json={"price_per_week": 300, "confirm_new_price": True})
    assert r.status_code == 200, r.text
    sale = r.json()
    assert sale["price_per_week"] == 200                     # still the price in force
    assert sale["due_price_per_week"] == 300 and sale["price_changed_from"] == 200
    assert sale["amount_due"] == 300

    # The shop's link shows both prices, before it pays.
    token = (await _sale(db, ad_id)).share_token
    due = (await client.get(f"/api/public/promo/{token}")).json()["payment_due"]
    assert (due["price_per_week"], due["previous_price_per_week"], due["amount"]) == (300, 200, 300)

    first, renewal = await _fresh_payments(db, ad_id)
    assert (first.price_per_week, first.amount, first.bitwave_fee, first.reseller_share) == (200, 200, 40, 160)
    assert (renewal.price_per_week, renewal.amount, renewal.bitwave_fee, renewal.reseller_share) == (300, 300, 60, 240)
    assert (await _ad(db, ad_id)).expires_at == ends

    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", receipt="RKX2", amount=300))
    assert (await _sale(db, ad_id)).price_per_week == 300
    assert (await _ad(db, ad_id)).expires_at == ends + timedelta(weeks=1)
    assert await get_unpaid_balance(db, reseller.id) == 160 + 240
    first, renewal = await _fresh_payments(db, ad_id)
    assert (first.price_per_week, first.amount) == (200, 200)
    sale = (await client.get(f"/api/ads/{ad_id}/sale")).json()
    assert sale["price_changed_from"] is None and sale["due_price_per_week"] is None


@pytest.mark.asyncio
async def test_a_renewal_nobody_paid_leaves_the_price_as_it_was(client, db, monkeypatch, stk):
    reseller = await _reseller(db)
    ad_id = await _live(client, db, monkeypatch, stk, reseller)
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    await client.post(f"/api/ads/{ad_id}/sale/renew", json={"price_per_week": 300, "confirm_new_price": True})
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))
    assert (await _sale(db, ad_id)).price_per_week == 200

    # Sending it again at the price already on it needs no second confirmation,
    # from the reseller or from the shop's own link.
    await _age_prompts(db, ad_id, 20)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={"weeks": 1, "price_per_week": 300})
    assert r.status_code == 200, r.text
    assert r.json()["due_price_per_week"] == 300
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))
    await _age_prompts(db, ad_id, 20)
    token = (await _sale(db, ad_id)).share_token
    r = await client.post(f"/api/public/promo/{token}/pay", json={})
    assert r.status_code == 200 and r.json()["sent"] is True
    assert (await _fresh_payments(db, ad_id))[-1].price_per_week == 300

    # A different price on the waiting renewal does need it.
    await client.post("/api/mpesa/ad-sales/callback", json=_callback(f"ws_CO_{len(stk)}", code=1032))
    await _age_prompts(db, ad_id, 20)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={"weeks": 1, "price_per_week": 400})
    assert r.status_code == 409
    n = (await db.execute(select(func.count()).select_from(AdSalePayment).where(AdSalePayment.ad_id == ad_id))).scalar()
    assert n == 4


@pytest.mark.asyncio
async def test_the_first_order_can_still_change_price_with_no_extra_step(client, db, monkeypatch, stk):
    """The flow an unpaid test ad is on: nothing here may get in its way."""
    reseller = await _reseller(db)
    out = await _sell(client, monkeypatch, reseller, ONE_WEEK_200)
    ad_id = out["ad"]["id"]
    await client.post("/api/mpesa/ad-sales/callback", json=_callback("ws_CO_1", code=1032))
    await _age_prompts(db, ad_id, 20)
    _auth_as(monkeypatch, reseller)
    r = await client.post(f"/api/ads/{ad_id}/sale/prompt", json={"weeks": 2, "price_per_week": 250})
    assert r.status_code == 200, r.text
    assert r.json()["price_per_week"] == 250 and r.json()["weeks"] == 2 and r.json()["amount_due"] == 500
    assert r.json()["price_changed_from"] is None

"""Review rules (Dennis, 4 Nov 2026): the house-ad lock, the blocked-word
list, the Kenyan phone check, and the admin-editable rules."""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.ad_sales_routes as asr
import app.api.ads_routes as ar
from app.api.ad_sales_routes import router as ad_sales_router
from app.api.ads_routes import router as ads_router
from app.db.database import get_db
from app.db.models import PortalSettings, SubscriptionStatus
from app.services import ad_review, ad_sales
from app.services.ad_serving import invalidate_ad_cache
from app.services.auth import verify_token
from tests.factories import make_admin, make_reseller

HOUSE = {
    "title": "Fast WiFi, KES 20 an hour", "seller_name": "Anything", "phone_number": "0712345678",
    "image_url": "https://media.example/wifi.webp", "placement": "hero",
}


@pytest.fixture(autouse=True)
def _selling_open(monkeypatch):
    """The pilot switch has its own tests in test_ad_selling_access.py."""
    async def yes(db, reseller_id):
        return True
    monkeypatch.setattr(ad_sales, "selling_allowed", yes)


@pytest_asyncio.fixture(autouse=True)
async def _fresh_ad_cache():
    await invalidate_ad_cache()
    yield


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(ads_router)
    application.include_router(ad_sales_router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s
            await s.commit()

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
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


# ---------------------------------------------------------------------------
# House-ad lock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_own_promo_is_named_after_the_network_and_goes_live(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    r = await client.post("/api/ads", json=HOUSE)
    assert r.status_code == 200, r.text
    assert r.json()["seller_name"] == "Acme WiFi"
    assert r.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_own_promo_cannot_carry_another_businesss_phone(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    r = await client.post("/api/ads", json={**HOUSE, "phone_number": "0722999888"})
    assert r.status_code == 400
    assert "An ad I sold" in r.json()["detail"]
    r = await client.post("/api/ads", json={**HOUSE, "whatsapp_number": "0722999888"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_own_promo_accepts_the_support_number_in_any_format(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    for phone in ("+254 712 345 678", "254712345678", "712345678"):
        r = await client.post("/api/ads", json={**HOUSE, "phone_number": phone})
        assert r.status_code == 200, (phone, r.text)


@pytest.mark.asyncio
async def test_own_promo_accepts_the_portal_support_numbers(client, db, monkeypatch):
    reseller = await _reseller(db, support_phone=None)
    db.add(PortalSettings(user_id=reseller.id, portal_support_phone="0700111222",
                          portal_support_whatsapp="0700333444"))
    await db.commit()
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ads", json={**HOUSE, "phone_number": "0700111222", "whatsapp_number": "0700333444"})
    assert r.status_code == 200, r.text
    r = await client.post("/api/ads", json={**HOUSE, "phone_number": "0712345678"})
    assert r.status_code == 400                         # the account phone isn't on this portal


@pytest.mark.asyncio
async def test_own_promo_needs_a_support_number_first(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db, support_phone=None))
    r = await client.post("/api/ads", json=HOUSE)
    assert r.status_code == 400
    assert "support phone" in r.json()["detail"]


@pytest.mark.asyncio
async def test_editing_an_own_promo_keeps_it_locked(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    ad = (await client.post("/api/ads", json=HOUSE)).json()
    r = await client.put(f"/api/ads/{ad['id']}", json={"seller_name": "Mama Njeri Bakery"})
    assert r.status_code == 200
    assert r.json()["seller_name"] == "Acme WiFi"
    r = await client.put(f"/api/ads/{ad['id']}", json={"phone_number": "0722999888"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Blocked words and phones
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,hits", [
    ("Bet now and win", ["bet"]),
    ("Better WiFi for less", []),
    ("Quick MKOPO today", ["mkopo"]),
    ("Loaned laptops", []),
    ("Crypto & forex signals", ["crypto", "forex"]),
    ("XXX videos", ["xxx"]),
    ("Unisex salon, best odds-on haircut", ["odds"]),
    ("Fresh mandazi", []),
])
def test_blocked_words_match_whole_words_only(text, hits):
    assert ad_review.find_blocked_words([text], ad_review.DEFAULT_BLOCKED_WORDS) == hits


@pytest.mark.asyncio
async def test_a_betting_ad_is_refused_on_create_edit_and_sale(client, db, monkeypatch):
    reseller = await _reseller(db)
    db.add(PortalSettings(user_id=reseller.id, show_ads=True))
    await db.commit()
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ads", json={**HOUSE, "description": "Jackpot every Friday"})
    assert r.status_code == 400 and "jackpot" in r.json()["detail"]
    ad = (await client.post("/api/ads", json=HOUSE)).json()
    r = await client.put(f"/api/ads/{ad['id']}", json={"title": "Sportpesa odds here"})
    assert r.status_code == 400
    r = await client.post("/api/ad-sales", json={
        **HOUSE, "title": "Instant loans", "business_name": "Pesa Fast",
        "business_phone": "0722111222", "weeks": 1, "price_per_week": 300,
    })
    assert r.status_code == 400 and "loans" in r.json()["detail"]


@pytest.mark.asyncio
async def test_the_blocked_list_is_admin_editable(client, db, monkeypatch):
    reseller, admin = await _reseller(db), await make_admin(db)
    _auth_as(monkeypatch, reseller)
    assert (await client.get("/api/ad-review/rules")).status_code == 403
    _auth_as(monkeypatch, admin)
    r = await client.get("/api/ad-review/rules")
    assert "betting" in r.json()["blocked_words"] and r.json()["auto_approve_after"] == 3
    r = await client.put("/api/ad-review/rules", json={"blocked_words": ["Shisha", " herbal cure ", "shisha"]})
    assert r.json()["blocked_words"] == ["shisha", "herbal cure"]

    _auth_as(monkeypatch, reseller)
    assert (await client.post("/api/ads", json={**HOUSE, "title": "Shisha lounge"})).status_code == 400
    assert (await client.post("/api/ads", json={**HOUSE, "title": "Bet now"})).status_code == 200


@pytest.mark.asyncio
async def test_kenyan_resellers_need_a_kenyan_mobile_number(client, db, monkeypatch):
    reseller = await _reseller(db)
    db.add(PortalSettings(user_id=reseller.id, show_ads=True))
    await db.commit()
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ad-sales", json={
        **HOUSE, "phone_number": "+237677123456", "business_name": "Shop",
        "business_phone": "0722111222", "weeks": 1, "price_per_week": 300,
    })
    assert r.status_code == 400
    assert "Kenyan" in r.json()["detail"]


@pytest.mark.asyncio
async def test_selling_through_bitwave_is_kenya_only_for_now(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db, market_code="CM"))
    r = await client.post("/api/ad-sales", json={
        **HOUSE, "business_name": "Shop", "business_phone": "0722111222",
        "weeks": 1, "price_per_week": 300,
    })
    assert r.status_code == 400
    assert "Kenya" in r.json()["detail"]


@pytest.mark.asyncio
async def test_media_is_required(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    r = await client.post("/api/ads", json={**HOUSE, "image_url": None})
    assert r.status_code == 400

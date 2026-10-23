"""Hero ads: which ads a router's portal gets, who may create/edit/approve
them, how views and taps are counted, and the R2 upload signer."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

import app.api.ads_routes as ar
from app.api.ads_routes import router as ads_router
from app.db.database import get_db
from app.db.models import Ad, AdEvent, SubscriptionStatus
from app.services import ad_media
from app.services.ad_serving import (
    HERO_MAX, ads_for_router, build_event_rows, device_key_for,
    invalidate_ad_cache, select_ads_for_router,
)
from app.services.auth import verify_token
from tests.factories import make_admin, make_reseller, make_router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def _fresh_ad_cache():
    await invalidate_ad_cache()
    yield
    await invalidate_ad_cache()


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(ads_router)

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


async def _reseller(db):
    return await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)


async def _ad(db, **overrides) -> Ad:
    defaults = dict(
        title="Red onions", seller_name="Wanjiku Greens", phone_number="0712000111",
        image_url="https://media.example/onions.webp", placement="hero", media_type="image",
        slot="platform", status="approved", is_active=True, priority=0,
    )
    defaults.update(overrides)
    ad = Ad(**defaults)
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    return ad


def _live(ad_id, **kw):
    base = {
        "id": ad_id, "placement": "hero", "slot": "platform", "priority": 0,
        "_owner_user_id": None, "_router_ids": None,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Which ads a router gets
# ---------------------------------------------------------------------------

def test_router_gets_bitwave_ads_and_only_its_owners_ads():
    live = [
        _live(1),                                       # Bitwave, network-wide
        _live(2, _owner_user_id=7, slot="house"),       # this router's owner
        _live(3, _owner_user_id=8, slot="house"),       # another reseller
    ]
    ids = [a["id"] for a in select_ads_for_router(live, router_id=50, owner_user_id=7)]
    assert ids == [1, 2]


def test_router_targeting_limits_an_ad_to_listed_routers():
    live = [_live(1, _router_ids=[50, 51]), _live(2, _router_ids=[99])]
    assert [a["id"] for a in select_ads_for_router(live, 50, 7)] == [1]


def test_hero_order_is_sponsor_then_sold_then_promo_and_capped():
    live = [
        _live(1, _owner_user_id=7, slot="house"),
        _live(2, _owner_user_id=7, slot="reseller"),
        _live(3, slot="platform"),
        _live(4, slot="platform"),
        _live(5, placement="local"),
    ]
    out = select_ads_for_router(live, 50, 7)
    hero = [a["id"] for a in out if a["placement"] == "hero"]
    assert hero == [3, 4, 2][:HERO_MAX]
    assert [a["id"] for a in out if a["placement"] == "local"] == [5]


def test_public_ads_never_carry_targeting_keys():
    out = select_ads_for_router([_live(1, _router_ids=[50])], 50, 7)
    assert all(not k.startswith("_") for k in out[0])


@pytest.mark.asyncio
async def test_only_approved_ads_inside_their_dates_reach_a_portal(db):
    reseller = await _reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    live = await _ad(db, title="live")
    await _ad(db, title="pending", status="pending")
    await _ad(db, title="rejected", status="rejected")
    await _ad(db, title="paused", is_active=False)
    await _ad(db, title="not yet", starts_at=now + timedelta(days=1))
    await _ad(db, title="over", expires_at=now - timedelta(minutes=1))

    ads = await ads_for_router(db, router.id, reseller.id, show_ads=True)
    assert [a["id"] for a in ads] == [live.id]


@pytest.mark.asyncio
async def test_ads_switched_off_returns_nothing(db):
    reseller = await _reseller(db)
    router = await make_router(db, reseller)
    await _ad(db)
    assert await ads_for_router(db, router.id, reseller.id, show_ads=False) == []


# ---------------------------------------------------------------------------
# Creating, editing, approving
# ---------------------------------------------------------------------------

AD_BODY = {
    "title": "WiFi at home", "seller_name": "Acme", "phone_number": "0712345678",
    "image_url": "https://media.example/tech.webp", "placement": "hero",
}


@pytest.mark.asyncio
async def test_reseller_ad_starts_pending_and_is_theirs(client, db, monkeypatch):
    reseller = await _reseller(db)
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ads", json=AD_BODY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["owner_user_id"] == reseller.id
    assert body["slot"] == "house"


@pytest.mark.asyncio
async def test_admin_ad_is_bitwaves_and_approved(client, db, monkeypatch):
    admin = await make_admin(db)
    _auth_as(monkeypatch, admin)
    r = await client.post("/api/ads", json=AD_BODY)
    body = r.json()
    assert body["status"] == "approved"
    assert body["owner_user_id"] is None
    assert body["slot"] == "platform"


@pytest.mark.asyncio
async def test_reseller_cannot_target_someone_elses_router(client, db, monkeypatch):
    reseller = await _reseller(db)
    other = await _reseller(db)
    theirs = await make_router(db, other)
    _auth_as(monkeypatch, reseller)
    r = await client.post("/api/ads", json={**AD_BODY, "router_ids": [theirs.id]})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_reseller_cannot_see_edit_or_delete_another_resellers_ad(client, db, monkeypatch):
    owner = await _reseller(db)
    intruder = await _reseller(db)
    ad = await _ad(db, owner_user_id=owner.id, slot="house")
    _auth_as(monkeypatch, intruder)
    assert (await client.get(f"/api/ads/manage/{ad.id}")).status_code == 404
    assert (await client.put(f"/api/ads/{ad.id}", json={"title": "mine now"})).status_code == 404
    assert (await client.delete(f"/api/ads/{ad.id}")).status_code == 404
    listing = (await client.get("/api/ads/manage")).json()
    assert listing["ads"] == []


@pytest.mark.asyncio
async def test_editing_content_sends_an_approved_ad_back_for_review(client, db, monkeypatch):
    reseller = await _reseller(db)
    ad = await _ad(db, owner_user_id=reseller.id, slot="house", status="approved")
    _auth_as(monkeypatch, reseller)

    r = await client.put(f"/api/ads/{ad.id}", json={"is_active": False})
    assert r.json()["status"] == "approved"      # pausing needs no review

    r = await client.put(f"/api/ads/{ad.id}", json={"title": "New offer"})
    assert r.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_only_admins_review_and_a_rejection_needs_a_reason(client, db, monkeypatch):
    reseller = await _reseller(db)
    admin = await make_admin(db)
    ad = await _ad(db, owner_user_id=reseller.id, slot="house", status="pending")

    _auth_as(monkeypatch, reseller)
    assert (await client.post(f"/api/ads/{ad.id}/review", json={"action": "approve"})).status_code == 403

    _auth_as(monkeypatch, admin)
    assert (await client.post(f"/api/ads/{ad.id}/review", json={"action": "reject"})).status_code == 400
    r = await client.post(f"/api/ads/{ad.id}/review", json={"action": "reject", "note": "Blurry photo"})
    assert r.json()["status"] == "rejected"
    assert r.json()["review_note"] == "Blurry photo"
    r = await client.post(f"/api/ads/{ad.id}/review", json={"action": "approve"})
    assert r.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_video_ad_needs_a_video(client, db, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    r = await client.post("/api/ads", json={**AD_BODY, "media_type": "video"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_advertiser_list_is_admin_only(client, db, monkeypatch):
    _auth_as(monkeypatch, await _reseller(db))
    assert (await client.get("/api/advertisers")).status_code == 403


# ---------------------------------------------------------------------------
# Counting views and taps
# ---------------------------------------------------------------------------

def test_device_key_prefers_a_valid_mac():
    assert device_key_for("aa-bb-cc-11-22-33", "dev_1", "s") == "AA:BB:CC:11:22:33"
    assert device_key_for("not a mac", "dev_1", "s") == "dev_1"
    assert device_key_for(None, None, None) is None


def test_event_rows_skip_dead_ads_unknown_placements_and_no_device():
    rows = build_event_rows(ad_ids=[1, 2, 2, "x"], event_type="impression", placement="hero",
                            device_key="dev", live_ad_ids={1})
    assert [r["ad_id"] for r in rows] == [1]
    assert build_event_rows(ad_ids=[1], event_type="impression", placement="banner",
                            device_key="dev", live_ad_ids={1}) == []
    assert build_event_rows(ad_ids=[1], event_type="impression", placement="hero",
                            device_key=None, live_ad_ids={1}) == []


@pytest.mark.asyncio
async def test_impressions_count_once_per_device_per_day_and_never_touch_the_ad_row(client, db):
    ad = await _ad(db)
    body = {"ad_ids": [ad.id], "placement": "hero", "device_id": "dev_1", "mac_address": "AA:BB:CC:11:22:33"}
    for _ in range(3):
        assert (await client.post("/api/ads/impression", json=body)).status_code == 200
    await client.post("/api/ads/impression", json={**body, "placement": "wait_screen"})
    await client.post("/api/ads/impression", json={**body, "mac_address": "AA:BB:CC:11:22:44"})

    n = (await db.execute(select(func.count()).select_from(AdEvent))).scalar()
    assert n == 3  # hero once, wait screen once, second phone once
    await db.refresh(ad)
    assert (ad.views_count or 0) == 0


@pytest.mark.asyncio
async def test_clicks_are_recorded_and_bad_ones_quietly_ignored(client, db):
    ad = await _ad(db)
    ok = await client.post("/api/ads/click", json={
        "ad_id": ad.id, "click_type": "call", "placement": "hero", "device_id": "dev_1",
    })
    bad = await client.post("/api/ads/click", json={"ad_id": ad.id, "click_type": "explode", "device_id": "dev_1"})
    dead = await client.post("/api/ads/click", json={"ad_id": 9999, "click_type": "call", "device_id": "dev_1"})
    assert ok.status_code == bad.status_code == dead.status_code == 200
    events = (await db.execute(select(AdEvent))).scalars().all()
    assert [(e.event_type, e.click_type, e.placement) for e in events] == [("click", "call", "hero")]


@pytest.mark.asyncio
async def test_stats_split_by_placement(client, db, monkeypatch):
    reseller = await _reseller(db)
    ad = await _ad(db, owner_user_id=reseller.id, slot="house")
    for placement in ("hero", "wait_screen"):
        await client.post("/api/ads/impression", json={"ad_ids": [ad.id], "placement": placement, "device_id": "d1"})
    _auth_as(monkeypatch, reseller)
    stats = (await client.get(f"/api/ads/{ad.id}/stats")).json()
    assert stats["impressions"] == 2
    assert set(stats["by_placement"]) == {"hero", "wait_screen"}


# ---------------------------------------------------------------------------
# Media uploads
# ---------------------------------------------------------------------------

def test_presign_matches_the_aws_documented_example():
    # AWS S3 docs, "Authenticating Requests: Using Query Parameters".
    url = ad_media.presign_url(
        method="GET", host="examplebucket.s3.amazonaws.com", path="/test.txt",
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", expires=86400, now=datetime(2013, 5, 24),
    )
    assert url.endswith(
        "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    )


def test_uploads_report_when_storage_is_not_set_up(monkeypatch):
    monkeypatch.setattr(ad_media.settings, "R2_BUCKET", "")
    with pytest.raises(ad_media.MediaNotConfigured):
        ad_media.create_upload("image/webp", 1000, "r1")


def test_upload_slot_checks_type_and_size(monkeypatch):
    for key, value in {
        "R2_ACCOUNT_ID": "acct", "R2_ACCESS_KEY_ID": "AK", "R2_SECRET_ACCESS_KEY": "SK",
        "R2_BUCKET": "ads", "AD_MEDIA_PUBLIC_BASE": "https://isp.example.com/media",
    }.items():
        monkeypatch.setattr(ad_media.settings, key, value)
    with pytest.raises(ad_media.MediaRejected):
        ad_media.create_upload("image/gif", 1000, "r1")
    with pytest.raises(ad_media.MediaRejected):
        ad_media.create_upload("video/mp4", 50 * 1024 * 1024, "r1")
    ticket = ad_media.create_upload("video/mp4", 1_000_000, "r12")
    assert ticket.upload_url.startswith("https://acct.r2.cloudflarestorage.com/ads/ads/")
    assert "X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost" in ticket.upload_url
    assert ticket.public_url.startswith("https://isp.example.com/media/ads/")
    assert ticket.public_url.endswith(".mp4")


# ---------------------------------------------------------------------------
# Review triggers, owner names and filters
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resaving_unchanged_values_keeps_the_ad_live(client, db, monkeypatch):
    reseller = await _reseller(db)
    ad = await _ad(db, owner_user_id=reseller.id, slot="house", status="approved")
    _auth_as(monkeypatch, reseller)
    r = await client.put(f"/api/ads/{ad.id}", json={"title": ad.title, "phone_number": ad.phone_number})
    assert r.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_moving_an_ad_into_the_hero_is_reviewed(client, db, monkeypatch):
    reseller = await _reseller(db)
    ad = await _ad(db, owner_user_id=reseller.id, slot="house", status="approved", placement="local")
    _auth_as(monkeypatch, reseller)
    r = await client.put(f"/api/ads/{ad.id}", json={"placement": "hero"})
    assert r.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_admin_list_names_owners_and_filters_by_owner(client, db, monkeypatch):
    a = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE, business_name="Acme WiFi")
    b = await _reseller(db)
    await _ad(db, owner_user_id=a.id, slot="house")
    await _ad(db, owner_user_id=b.id, slot="house")
    await _ad(db)  # Bitwave's
    _auth_as(monkeypatch, await make_admin(db))

    only_a = (await client.get(f"/api/ads/manage?owner_user_id={a.id}")).json()["ads"]
    assert [x["owner_name"] for x in only_a] == ["Acme WiFi"]
    ours = (await client.get("/api/ads/manage?bitwave_only=true")).json()["ads"]
    assert [x["owner_name"] for x in ours] == ["Bitwave"]


@pytest.mark.asyncio
async def test_only_bitwave_ads_can_be_relinked_to_an_advertiser(client, db, monkeypatch):
    from app.db.models import Advertiser
    adv = Advertiser(name="Wanjiku", phone_number="0712000111")
    db.add(adv)
    await db.commit()
    reseller = await _reseller(db)
    theirs = await _ad(db, owner_user_id=reseller.id, slot="house")
    ours = await _ad(db)

    _auth_as(monkeypatch, await make_admin(db))
    assert (await client.put(f"/api/ads/{ours.id}", json={"advertiser_id": adv.id})).json()["advertiser_id"] == adv.id
    assert (await client.put(f"/api/ads/{theirs.id}", json={"advertiser_id": adv.id})).status_code == 400

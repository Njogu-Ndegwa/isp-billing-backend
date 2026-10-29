"""Ads management is Bitwave-admin only.

Ads on main have no owner and are served to every captive portal, so a
reseller (or a staff login, which authenticates as its reseller) must not be
able to create a network-wide ad, edit or delete anyone's ad, or read the
per-device click and impression records. The public portal endpoints stay open.
"""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.ads_routes as ads_routes
from app.db.database import get_db
from app.db.models import Ad, Advertiser
from app.services.auth import verify_token
from tests.factories import make_admin, make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(ads_routes.router)

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
    monkeypatch.setattr(ads_routes, "get_current_user", _fake)


async def _make_ad(db, **overrides):
    advertiser = Advertiser(name="Shop", business_name="Shop Ltd", phone_number="0712345678")
    db.add(advertiser)
    await db.commit()
    await db.refresh(advertiser)
    defaults = dict(
        advertiser_id=advertiser.id, title="Original", image_url="https://x.test/a.jpg",
        seller_name="Shop", phone_number="0712345678",
    )
    defaults.update(overrides)
    ad = Ad(**defaults)
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    return ad


def _ad_body(advertiser_id):
    return {
        "advertiser_id": advertiser_id, "title": "Network-wide", "image_url": "https://x.test/b.jpg",
        "seller_name": "Me", "phone_number": "0700000000",
    }


@pytest.mark.asyncio
async def test_reseller_cannot_create_ad(db, client, monkeypatch):
    ad = await _make_ad(db)
    _auth_as(monkeypatch, await make_reseller(db, subscription_status="active"))

    resp = await client.post("/api/ads", json=_ad_body(ad.advertiser_id))

    assert resp.status_code == 403
    count = len((await db.execute(select(Ad))).scalars().all())
    assert count == 1


@pytest.mark.asyncio
async def test_reseller_cannot_edit_or_delete_an_ad(db, client, monkeypatch):
    ad = await _make_ad(db)
    _auth_as(monkeypatch, await make_reseller(db, subscription_status="active"))

    put = await client.put(f"/api/ads/{ad.id}", json={"title": "Hijacked", "is_active": False})
    delete = await client.delete(f"/api/ads/{ad.id}")

    assert put.status_code == 403
    assert delete.status_code == 403
    ad_id = ad.id
    db.expire_all()
    kept = (await db.execute(select(Ad).where(Ad.id == ad_id))).scalar_one()
    assert kept.title == "Original"
    assert kept.is_active is True


@pytest.mark.asyncio
async def test_reseller_cannot_manage_advertisers_or_read_ad_analytics(db, client, monkeypatch):
    ad = await _make_ad(db)
    _auth_as(monkeypatch, await make_reseller(db, subscription_status="active"))

    for method, url, body in [
        ("post", "/api/advertisers", {"name": "X", "phone_number": "0711111111"}),
        ("get", "/api/advertisers", None),
        ("get", f"/api/ads/{ad.id}/clicks", None),
        ("get", f"/api/ads/{ad.id}/impressions", None),
        ("get", "/api/ads/analytics", None),
    ]:
        kwargs = {"json": body} if body is not None else {}
        resp = await getattr(client, method)(url, **kwargs)
        assert resp.status_code == 403, (method, url, resp.status_code)


@pytest.mark.asyncio
async def test_admin_can_still_create_edit_and_delete(db, client, monkeypatch):
    ad = await _make_ad(db)
    _auth_as(monkeypatch, await make_admin(db))

    created = await client.post("/api/ads", json=_ad_body(ad.advertiser_id))
    assert created.status_code == 200
    new_id = created.json()["id"]

    put = await client.put(f"/api/ads/{ad.id}", json={"title": "Edited"})
    assert put.status_code == 200
    assert put.json()["title"] == "Edited"

    delete = await client.delete(f"/api/ads/{new_id}")
    assert delete.status_code == 200

    advertisers = await client.get("/api/advertisers")
    assert advertisers.status_code == 200


@pytest.mark.asyncio
async def test_public_portal_endpoints_stay_open(db, client, monkeypatch):
    ad = await _make_ad(db)

    async def _no_auth(token, db):
        raise AssertionError("public ads endpoints must not authenticate")
    monkeypatch.setattr(ads_routes, "get_current_user", _no_auth)

    listed = await client.get("/api/ads")
    assert listed.status_code == 200
    assert [a["id"] for a in listed.json()["ads"]] == [ad.id]

    click = await client.post("/api/ads/click", json={"ad_id": ad.id, "click_type": "call"})
    assert click.status_code == 200
    impression = await client.post("/api/ads/impression", json={"ad_ids": [ad.id]})
    assert impression.status_code == 200

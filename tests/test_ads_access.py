"""Who may touch which ad, end to end through the real app.

Replaces the admin-only guard from the security hotfix (#281): ads now have an
owner, so a reseller manages their own ads (pending review, their own routers)
and never a Bitwave ad or another reseller's. Staff logins act as their
reseller, limited by the staff permission map: "Captive portal" staff get the
owner's ad rights, "View dashboard" staff can only read.
"""

from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import Ad, Advertiser, ResellerStaff, SubscriptionStatus
from app.services import staff_access
from app.services import staff_permissions as perms
from app.services.ad_serving import invalidate_ad_cache
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_admin, make_reseller

AD_BODY = {
    "title": "WiFi at home", "seller_name": "Acme", "phone_number": "0712345678",
    "image_url": "https://media.example/tech.webp", "placement": "hero",
}


@pytest.fixture(autouse=True)
def _fresh_staff_cache(monkeypatch):
    staff_access.reset_cache()

    async def no_sms(*args, **kwargs):
        pass
    monkeypatch.setattr(staff_access, "alert_owner", no_sms)
    yield
    staff_access.reset_cache()


@pytest_asyncio.fixture(autouse=True)
async def _fresh_ad_cache():
    await invalidate_ad_cache()
    yield
    await invalidate_ad_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user):
    token = create_access_token(login_token_claims(user), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


async def _staff_headers(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Staff", email=f"staff{owner.id}-{len(permissions)}@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


async def _reseller(db):
    return await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)


async def _ad(db, **overrides) -> Ad:
    defaults = dict(
        title="Bitwave promo", seller_name="Bitwave", phone_number="0712000111",
        image_url="https://media.example/promo.webp", placement="hero", media_type="image",
        slot="platform", status="approved", is_active=True, priority=0,
    )
    defaults.update(overrides)
    ad = Ad(**defaults)
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    return ad


# ---------------------------------------------------------------------------
# Resellers: own ads only, never network-wide
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reseller_cannot_create_a_network_wide_ad(client, db):
    reseller = await _reseller(db)
    r = await client.post("/api/ads", json={**AD_BODY, "slot": "platform"}, headers=_bearer(reseller))
    assert r.status_code == 400
    r = await client.post("/api/ads", json=AD_BODY, headers=_bearer(reseller))
    assert r.status_code == 200, r.text
    assert r.json()["owner_user_id"] == reseller.id
    assert r.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_reseller_cannot_edit_delete_or_read_a_bitwave_ad(client, db):
    ad = await _ad(db)
    ad_id = ad.id
    h = _bearer(await _reseller(db))

    assert (await client.put(f"/api/ads/{ad_id}", json={"title": "Hijacked", "is_active": False}, headers=h)).status_code == 404
    assert (await client.delete(f"/api/ads/{ad_id}", headers=h)).status_code == 404
    for path in ("manage/{id}", "{id}/stats", "{id}/clicks", "{id}/impressions"):
        r = await client.get("/api/ads/" + path.format(id=ad_id), headers=h)
        assert r.status_code == 404, (path, r.status_code)

    db.expire_all()
    kept = (await db.execute(select(Ad).where(Ad.id == ad_id))).scalar_one()
    assert kept.title == "Bitwave promo"
    assert kept.is_active is True


@pytest.mark.asyncio
async def test_advertisers_are_admin_only_and_analytics_is_scoped(client, db):
    await _ad(db)
    db.add(Advertiser(name="Shop", phone_number="0700000000"))
    await db.commit()
    reseller = await _reseller(db)

    assert (await client.get("/api/advertisers", headers=_bearer(reseller))).status_code == 403
    assert (await client.post("/api/advertisers", json={"name": "X", "phone_number": "0711111111"},
                              headers=_bearer(reseller))).status_code == 403
    analytics = await client.get("/api/ads/analytics", headers=_bearer(reseller))
    assert analytics.status_code == 200
    assert analytics.json()["total_ads"] == 0  # the Bitwave ad is not theirs

    admin = await make_admin(db)
    assert (await client.get("/api/advertisers", headers=_bearer(admin))).status_code == 200
    assert (await client.get("/api/ads/analytics", headers=_bearer(admin))).json()["total_ads"] == 1


@pytest.mark.asyncio
async def test_public_portal_endpoints_need_no_login(client, db):
    ad = await _ad(db)
    listed = await client.get("/api/ads")
    assert listed.status_code == 200
    assert [a["id"] for a in listed.json()["ads"]] == [ad.id]
    assert (await client.post("/api/ads/click", json={"ad_id": ad.id, "click_type": "call"})).status_code == 200
    assert (await client.post("/api/ads/impression", json={"ad_ids": [ad.id]})).status_code == 200


# ---------------------------------------------------------------------------
# Staff
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_portal_staff_manage_the_owners_ads(client, db):
    owner = await _reseller(db)
    h = await _staff_headers(db, owner, ["portal.manage"])

    created = await client.post("/api/ads", json=AD_BODY, headers=h)
    assert created.status_code == 200, created.text
    assert created.json()["owner_user_id"] == owner.id
    assert created.json()["status"] == "pending"
    ad_id = created.json()["id"]

    assert (await client.get("/api/ads/manage", headers=h)).json()["pagination"]["total"] == 1
    assert (await client.put(f"/api/ads/{ad_id}", json={"is_active": False}, headers=h)).status_code == 200
    assert (await client.get(f"/api/ads/{ad_id}/clicks", headers=h)).status_code == 200
    # Upload signing is reached (R2 is not configured in tests, hence 503, not 403).
    up = await client.post("/api/ads/media/upload-url", json={"content_type": "image/webp", "size": 1000}, headers=h)
    assert up.status_code == 503
    assert (await client.delete(f"/api/ads/{ad_id}", headers=h)).status_code == 200


@pytest.mark.asyncio
async def test_portal_staff_cannot_review_or_see_advertisers(client, db):
    owner = await _reseller(db)
    ad = await _ad(db, owner_user_id=owner.id, slot="house", status="pending")
    h = await _staff_headers(db, owner, ["portal.manage"])
    review = await client.post(f"/api/ads/{ad.id}/review", json={"action": "approve"}, headers=h)
    assert review.status_code == 403
    assert review.json().get("code") == "staff_permission_denied"
    assert (await client.get("/api/advertisers", headers=h)).status_code == 403


@pytest.mark.asyncio
async def test_view_only_staff_can_read_but_not_change_ads(client, db):
    owner = await _reseller(db)
    ad = await _ad(db, owner_user_id=owner.id, slot="house", status="approved")
    h = await _staff_headers(db, owner, ["dashboard.view"])

    assert (await client.get("/api/ads/manage", headers=h)).status_code == 200
    assert (await client.get(f"/api/ads/manage/{ad.id}", headers=h)).status_code == 200
    assert (await client.get(f"/api/ads/{ad.id}/stats", headers=h)).status_code == 200
    assert (await client.get("/api/ads/analytics", headers=h)).status_code == 200

    for method, path, body in [
        ("POST", "/api/ads", AD_BODY),
        ("PUT", f"/api/ads/{ad.id}", {"title": "x"}),
        ("DELETE", f"/api/ads/{ad.id}", None),
        ("POST", "/api/ads/media/upload-url", {"content_type": "image/webp", "size": 1000}),
        ("GET", f"/api/ads/{ad.id}/clicks", None),
    ]:
        r = await client.request(method, path, json=body, headers=h)
        assert r.status_code == 403, (method, path, r.status_code)
        assert r.json()["code"] == "staff_permission_denied"


@pytest.mark.asyncio
async def test_staff_without_portal_or_dashboard_rights_get_no_ads(client, db):
    owner = await _reseller(db)
    h = await _staff_headers(db, owner, ["customers.view", "routers.view"])
    r = await client.get("/api/ads/manage", headers=h)
    assert r.status_code == 403
    assert r.json()["code"] == "staff_permission_denied"


def test_every_ads_route_is_mapped_or_deliberately_admin_only():
    """Deny by default: a new ads route must be added to the staff map on purpose."""
    import main
    admin_only = {("POST", "/api/ads/{ad_id}/review"), ("GET", "/api/advertisers"), ("POST", "/api/advertisers")}
    public = {("POST", "/api/ads/click"), ("POST", "/api/ads/impression")}
    for route in main.app.routes:
        path = getattr(route, "path", "")
        if not (path.startswith("/api/ads") or path.startswith("/api/advertisers")):
            continue
        for method in getattr(route, "methods", set()) - {"HEAD", "OPTIONS"}:
            key = (method, path)
            rule, _ = perms.match_rule(method, path.replace("{ad_id}", "7"))
            if key in admin_only or key in public:
                assert rule is None, key
            else:
                assert rule is not None, key

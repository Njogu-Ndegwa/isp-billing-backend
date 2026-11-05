"""The portal's neutral paths answer exactly like the old /api/ads ones.

Ad blockers block URLs like /ads and /ads/click, so the portal calls
/api/public/spots*. Both sets stay public and run the same handlers: the old
paths are still called by portal pages cached on phones.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import ads_routes
from app.db.models import Ad, AdEvent
from app.services.ad_serving import invalidate_ad_cache

PAIRS = [
    ("GET", "/api/ads", ads_routes.PORTAL_LIST_PATH),
    ("POST", "/api/ads/click", ads_routes.PORTAL_TAP_PATH),
    ("POST", "/api/ads/impression", ads_routes.PORTAL_SEEN_PATH),
]
BLOCKED_WORDS = {"ad", "ads", "advert", "banner", "sponsor", "promo", "click", "impression", "track", "pixel"}


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


async def _ad(db) -> Ad:
    ad = Ad(
        title="Bitwave offer", seller_name="Bitwave", phone_number="0712000111",
        image_url="https://media.example/offer.webp", placement="hero", media_type="image",
        slot="platform", status="approved", is_active=True, priority=0,
    )
    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    return ad


def _handler(method, path):
    import main
    for route in main.app.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", ()):
            return route.endpoint
    raise AssertionError(f"{method} {path} is not registered")


@pytest.mark.parametrize("method,old,new", PAIRS)
def test_both_paths_share_one_handler(method, old, new):
    assert _handler(method, old) is _handler(method, new)


@pytest.mark.parametrize("path", [p[2] for p in PAIRS])
def test_neutral_paths_stay_free_of_blocked_words(path):
    assert not BLOCKED_WORDS & set(path.strip("/").split("/"))


@pytest.mark.asyncio
async def test_list_needs_no_login_and_matches_the_old_path(client, db):
    ad = await _ad(db)
    old = await client.get("/api/ads")
    new = await client.get(ads_routes.PORTAL_LIST_PATH)
    assert new.status_code == 200
    assert [a["id"] for a in new.json()["ads"]] == [ad.id]
    assert new.json() == old.json()


@pytest.mark.asyncio
async def test_views_and_taps_count_through_the_neutral_paths(client, db):
    ad = await _ad(db)
    body = {"device_id": "dev_neutral", "placement": "hero"}
    seen = await client.post(ads_routes.PORTAL_SEEN_PATH, json={**body, "ad_ids": [ad.id]})
    tap = await client.post(ads_routes.PORTAL_TAP_PATH, json={**body, "ad_id": ad.id, "click_type": "call"})
    assert seen.status_code == 200 and seen.json()["success"] is True
    assert tap.status_code == 200 and tap.json()["success"] is True

    kinds = (await db.execute(select(AdEvent.event_type).where(AdEvent.ad_id == ad.id))).scalars().all()
    assert sorted(kinds) == ["click", "impression"]

"""A reseller's own photo as the captive-portal hero background.

Stored in the existing `portal_settings.header_bg_image_url` column, uploaded
through a tighter presigned slot than ads get, and served from the media host
that is already in every router's walled garden. Presets and everyone who never
uploads must stay exactly as they were.
"""

import pytest
import pytest_asyncio
from fastapi import HTTPException

import app.api.portal_routes as pr
from app.api.portal_routes import (
    HeroImageUploadRequest,
    PortalSettingsUpdate,
    _build_public_response,
    create_hero_image_upload,
    update_portal_settings,
)
from app.db.models import SubscriptionStatus
from app.services import ad_media
from tests.factories import make_reseller

BASE = "https://isp.example.com/media"
HERO = f"{BASE}/c/2026/11/r12-0123456789abcdef.jpg"
PRESET = "https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=750&h=370&fit=crop&q=80"
DEFAULT_PRESET_ID = "photo-1523805009345-7448845a9e53"


@pytest.fixture
def storage(monkeypatch):
    for key, value in {
        "R2_ACCOUNT_ID": "acct", "R2_ACCESS_KEY_ID": "key", "R2_SECRET_ACCESS_KEY": "secret",
        "R2_BUCKET": "media", "AD_MEDIA_PUBLIC_BASE": BASE,
    }.items():
        monkeypatch.setattr(ad_media.settings, key, value)


@pytest_asyncio.fixture
async def reseller(db, monkeypatch):
    user = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)

    async def _fake(token, session):
        return user

    monkeypatch.setattr(pr, "get_current_user", _fake)
    return user


async def test_upload_slot_is_a_small_photo_on_the_media_host(storage, reseller, db):
    ticket = await create_hero_image_upload(
        HeroImageUploadRequest(content_type="image/jpeg", size=80_000), db=db, token="t",
    )
    assert ticket["public_url"].startswith(f"{BASE}/c/")
    assert ticket["public_url"].endswith(".jpg")
    assert ad_media.is_portal_hero_url(ticket["public_url"])
    assert ticket["max_bytes"] == ad_media.HERO_MAX_BYTES
    # The size is signed, so storage refuses a bigger body than was approved.
    assert "content-length" in ticket["upload_url"]
    assert ticket["method"] == "PUT"


@pytest.mark.parametrize("content_type,size", [
    ("video/mp4", 80_000),
    ("image/png", 80_000),
    ("image/gif", 80_000),
    ("image/svg+xml", 80_000),
    ("image/jpeg", 0),
    ("image/jpeg", ad_media.HERO_MAX_BYTES + 1),
])
async def test_upload_slot_refuses_anything_else(storage, reseller, db, content_type, size):
    with pytest.raises(HTTPException) as exc:
        await create_hero_image_upload(
            HeroImageUploadRequest(content_type=content_type, size=size), db=db, token="t",
        )
    assert exc.value.status_code == 400


async def test_upload_slot_says_when_storage_is_off(storage, reseller, db, monkeypatch):
    monkeypatch.setattr(ad_media.settings, "R2_BUCKET", "")
    with pytest.raises(HTTPException) as exc:
        await create_hero_image_upload(
            HeroImageUploadRequest(content_type="image/jpeg", size=1000), db=db, token="t",
        )
    assert exc.value.status_code == 503


def test_ad_upload_limits_did_not_move(storage):
    """Ads share the signer; the hero's tighter cap must not touch them."""
    assert ad_media.create_upload("image/png", 1024 * 1024, "r1").max_bytes == 2 * 1024 * 1024
    assert ad_media.create_upload("video/mp4", 1_000_000, "r1").max_bytes == 12 * 1024 * 1024


async def test_saved_photo_reaches_the_public_payload(storage, reseller, db):
    resp = await update_portal_settings(PortalSettingsUpdate(header_bg_image_url=HERO), db=db, token="t")
    assert resp["settings"]["header_bg_image_url"] == HERO
    settings = await pr._get_or_create_settings(db, reseller.id)
    assert _build_public_response(settings, reseller)["header_bg_image_url"] == HERO


@pytest.mark.parametrize("bad", [
    f"{BASE}/c/2026/11/r12-abc.mp4",
    f"{BASE}/c/2026/11/r12-abc.png",
    f"{BASE}/ads/2026/11/r12-abc.jpg",
    f"{BASE}/c/2026/11/../../x.jpg",
    f"{BASE}/c/2026/11/x.jpg?a=b",
    f'{BASE}/c/2026/11/x.jpg"onerror="alert(1)',
])
async def test_other_links_on_the_media_host_are_refused(storage, reseller, db, bad):
    with pytest.raises(HTTPException) as exc:
        await update_portal_settings(PortalSettingsUpdate(header_bg_image_url=bad), db=db, token="t")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("kept", [PRESET, "https://example.com/hero-bg.jpg"])
async def test_presets_and_existing_values_still_save_unchanged(storage, reseller, db, kept):
    resp = await update_portal_settings(PortalSettingsUpdate(header_bg_image_url=kept), db=db, token="t")
    assert resp["settings"]["header_bg_image_url"] == kept


async def test_saving_other_settings_keeps_the_default_preset(storage, reseller, db):
    resp = await update_portal_settings(PortalSettingsUpdate(welcome_title="Hi"), db=db, token="t")
    assert DEFAULT_PRESET_ID in resp["settings"]["header_bg_image_url"]


def test_no_settings_row_gets_the_same_default_preset_as_before():
    assert DEFAULT_PRESET_ID in _build_public_response(None, None)["header_bg_image_url"]

"""Portal colour theme — `portal_settings.color_theme`.

The admin app (isp-frontend-admin `app/lib/portalThemes.ts`) and the captive
portal (isp-frontend `script.js` THEMES) offer:

    sunset_orange, ocean_blue, emerald_green, bright_violet, rose_gold, slate_gray

The backend still only knew the old name `midnight_purple`, so a reseller who
picked "Bright Violet" and pressed Save got a 422 (ChapNET, 2026-10-22).

Contract asserted here:
  * every theme the admin app offers saves;
  * `midnight_purple` rows saved before the rename still validate (the admin
    app re-sends the stored value), but it is no longer advertised;
  * junk is still rejected;
  * a saved `bright_violet` reaches the captive portal payload unchanged.
"""

import pytest
from pydantic import ValidationError

import app.api.portal_routes as pr
from app.api.portal_routes import (
    LEGACY_THEMES,
    OFFERED_THEMES,
    PortalSettingsUpdate,
    get_portal_settings,
    update_portal_settings,
)
from app.api.public_routes import get_portal_data
from app.db.models import PortalSettings, SubscriptionStatus
from app.services.plan_cache import invalidate_plan_cache
from tests.factories import make_reseller, make_router

# Mirror of isp-frontend-admin/app/lib/portalThemes.ts PortalColorTheme and
# isp-frontend/script.js THEMES. Change together.
ADMIN_APP_THEMES = {
    "sunset_orange",
    "ocean_blue",
    "emerald_green",
    "bright_violet",
    "rose_gold",
    "slate_gray",
}


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("theme", sorted(ADMIN_APP_THEMES))
def test_every_theme_the_admin_app_offers_is_accepted(theme):
    assert PortalSettingsUpdate(color_theme=theme).color_theme == theme


def test_bright_violet_is_accepted():
    assert PortalSettingsUpdate(color_theme="bright_violet").color_theme == "bright_violet"


def test_legacy_midnight_purple_is_still_accepted():
    """Rows saved before the rename must keep validating when re-sent."""
    assert PortalSettingsUpdate(color_theme="midnight_purple").color_theme == "midnight_purple"


@pytest.mark.parametrize("junk", ["purple", "BRIGHT_VIOLET", "bright violet", "", "deep_teal", "burnt_amber"])
def test_unknown_theme_is_rejected(junk):
    with pytest.raises(ValidationError) as exc:
        PortalSettingsUpdate(color_theme=junk)
    msg = str(exc.value)
    assert "color_theme must be one of" in msg
    assert "bright_violet" in msg
    # The error lists what a reseller can pick, not the legacy alias.
    assert "midnight_purple" not in msg


def test_omitting_the_theme_is_fine():
    assert PortalSettingsUpdate().color_theme is None


def test_offered_themes_match_the_admin_app_exactly():
    assert OFFERED_THEMES == ADMIN_APP_THEMES
    assert LEGACY_THEMES == {"midnight_purple"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def as_user(monkeypatch):
    """Make the portal routes treat `token` as already resolved to `user`."""
    holder = {}

    async def _fake(token, db):
        return holder["user"]

    monkeypatch.setattr(pr, "get_current_user", _fake)
    return holder


async def test_saving_bright_violet_persists_and_reaches_the_captive_portal(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, reseller, identity="theme-violet")
    as_user["user"] = reseller

    result = await update_portal_settings(
        request=PortalSettingsUpdate(color_theme="bright_violet"), db=db, token="t"
    )
    assert result["updated_fields"] == ["color_theme"]
    assert result["settings"]["color_theme"] == "bright_violet"

    await invalidate_plan_cache()
    payload = await get_portal_data(identity=site.identity, db=db)
    assert payload["portal_settings"]["color_theme"] == "bright_violet"


async def test_existing_midnight_purple_row_is_served_unchanged(db):
    """No rewrite of stored values: the portal gets exactly what was saved."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="theme-legacy")
    db.add(PortalSettings(user_id=reseller.id, color_theme="midnight_purple"))
    await db.commit()

    await invalidate_plan_cache()
    payload = await get_portal_data(identity=site.identity, db=db)
    assert payload["portal_settings"]["color_theme"] == "midnight_purple"


async def test_available_themes_lists_bright_violet_not_the_legacy_name(db, as_user):
    reseller = await make_reseller(db)
    as_user["user"] = reseller

    result = await get_portal_settings(db=db, token="t")
    assert "bright_violet" in result["available_themes"]
    assert "midnight_purple" not in result["available_themes"]
    assert set(result["available_themes"]) == ADMIN_APP_THEMES

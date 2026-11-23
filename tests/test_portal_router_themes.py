"""Per-router captive portal themes: `portal_router_themes`.

A reseller (Xtiv Mose, 2026-11-23) asked for each router on one account to
have its own portal look. Packages could already be scoped per router through
`Plan.router_ids`, but the look lived only in `portal_settings`, one row per
account.

Contract asserted here:
  * a router with no override serves exactly the account's settings, so
    existing accounts look the same as before;
  * two routers on one account can show different themes, and a third router
    with nothing of its own keeps the account default;
  * an override only replaces the fields it sets, and the rest follows the
    account (including later changes to the account);
  * account-wide settings (ads, support phone, package order) cannot be
    overridden per router;
  * a field sent as null, or a reset, puts the router back on the default;
  * a reseller cannot read or change another reseller's router.
"""

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

import app.api.portal_routes as pr
from app.api.portal_routes import (
    PortalSettingsUpdate,
    RouterThemeUpdate,
    get_public_portal_settings,
    get_router_theme_settings,
    list_router_themes,
    reset_router_theme,
    update_portal_settings,
    update_router_theme,
)
from app.api.public_routes import get_portal_data
from app.db.models import PortalRouterTheme, PortalSettings, SubscriptionStatus
from app.services.plan_cache import invalidate_plan_cache
from tests.factories import make_reseller, make_router


@pytest.fixture
def as_user(monkeypatch):
    """Make the portal routes treat `token` as already resolved to `user`."""
    holder = {}

    async def _fake(token, db):
        return holder["user"]

    monkeypatch.setattr(pr, "get_current_user", _fake)
    return holder


async def _portal(db, site):
    await invalidate_plan_cache()
    return (await get_portal_data(identity=site.identity, db=db))["portal_settings"]


# ---------------------------------------------------------------------------
# Body validation
# ---------------------------------------------------------------------------

def test_router_theme_validates_like_the_account_settings():
    assert RouterThemeUpdate(color_theme="emerald_green").color_theme == "emerald_green"
    with pytest.raises(ValidationError):
        RouterThemeUpdate(color_theme="not_a_theme")
    with pytest.raises(ValidationError):
        RouterThemeUpdate(header_style="giant")


@pytest.mark.parametrize("field", ["show_ads", "portal_support_phone", "plan_sort_order", "portal_language"])
def test_account_wide_settings_cannot_be_set_per_router(field):
    with pytest.raises(ValidationError):
        RouterThemeUpdate(**{field: "x"})


def test_theme_fields_match_the_override_table():
    columns = set(PortalRouterTheme.__table__.columns.keys()) - {
        "id", "router_id", "user_id", "created_at", "updated_at",
    }
    assert set(pr.ROUTER_THEME_FIELDS) == columns
    assert set(RouterThemeUpdate.model_fields) == columns
    # Every overridable field is a real account setting too.
    assert columns <= set(PortalSettings.__table__.columns.keys())


# ---------------------------------------------------------------------------
# Existing accounts are unchanged
# ---------------------------------------------------------------------------

async def test_router_without_override_serves_the_account_settings_unchanged(db):
    reseller = await make_reseller(db, business_name="Xtiv Net")
    site = await make_router(db, reseller, identity="rt-plain")
    db.add(PortalSettings(
        user_id=reseller.id, color_theme="ocean_blue", header_style="minimal",
        company_logo_url="https://cdn.example/logo.png", footer_text="Karibu",
    ))
    await db.commit()

    reference = pr._build_account_public_response(
        (await db.execute(select(PortalSettings).where(PortalSettings.user_id == reseller.id))).scalar_one(),
        reseller,
    )
    assert await _portal(db, site) == reference
    assert await get_public_portal_settings(router_id=site.id, db=db) == reference


async def test_account_with_no_settings_at_all_still_gets_defaults(db):
    reseller = await make_reseller(db, business_name="Fresh ISP")
    site = await make_router(db, reseller, identity="rt-fresh")

    payload = await _portal(db, site)
    assert payload == pr._build_account_public_response(None, reseller)
    assert payload["color_theme"] == "slate_gray"
    assert payload["welcome_title"] == "Fresh ISP"


# ---------------------------------------------------------------------------
# Two routers, two looks
# ---------------------------------------------------------------------------

async def test_two_routers_on_one_account_show_different_themes(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    shop = await make_router(db, reseller, identity="rt-shop")
    estate = await make_router(db, reseller, identity="rt-estate")
    plain = await make_router(db, reseller, identity="rt-other")
    as_user["user"] = reseller

    await update_portal_settings(
        request=PortalSettingsUpdate(color_theme="ocean_blue", welcome_title="Xtiv WiFi"),
        db=db, token="t",
    )
    await update_router_theme(
        router_id=shop.id,
        request=RouterThemeUpdate(color_theme="cherry_red", header_style="compact",
                                  welcome_title="Xtiv Shop"),
        db=db, token="t",
    )
    await update_router_theme(
        router_id=estate.id,
        request=RouterThemeUpdate(color_theme="emerald_green",
                                  company_logo_url="https://cdn.example/estate.png"),
        db=db, token="t",
    )

    shop_p, estate_p, plain_p = [await _portal(db, r) for r in (shop, estate, plain)]

    assert (shop_p["color_theme"], shop_p["header_style"], shop_p["welcome_title"]) == (
        "cherry_red", "compact", "Xtiv Shop")
    assert (estate_p["color_theme"], estate_p["company_logo_url"]) == (
        "emerald_green", "https://cdn.example/estate.png")
    # Not overridden on the estate router: follows the account.
    assert estate_p["welcome_title"] == "Xtiv WiFi"
    assert estate_p["header_style"] == "hero"
    # The third router keeps the default, and the public endpoint agrees.
    assert plain_p["color_theme"] == "ocean_blue"
    assert plain_p["welcome_title"] == "Xtiv WiFi"
    assert (await get_public_portal_settings(router_id=shop.id, db=db))["color_theme"] == "cherry_red"
    assert (await get_public_portal_settings(router_id=plain.id, db=db))["color_theme"] == "ocean_blue"


async def test_an_override_follows_later_account_changes_for_fields_it_does_not_set(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, reseller, identity="rt-follow")
    as_user["user"] = reseller

    await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(color_theme="hot_pink"), db=db, token="t",
    )
    await update_portal_settings(
        request=PortalSettingsUpdate(color_theme="royal_blue", footer_text="New footer"),
        db=db, token="t",
    )

    payload = await _portal(db, site)
    assert payload["color_theme"] == "hot_pink"
    assert payload["footer_text"] == "New footer"


async def test_account_wide_settings_stay_account_wide_on_an_overridden_router(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE,
                                   support_phone="0700000001")
    site = await make_router(db, reseller, identity="rt-wide")
    as_user["user"] = reseller

    await update_portal_settings(
        request=PortalSettingsUpdate(plan_sort_order="price_asc", portal_language="sw",
                                     portal_support_whatsapp="0711111111"),
        db=db, token="t",
    )
    await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(color_theme="amber_gold"), db=db, token="t",
    )

    payload = await _portal(db, site)
    assert payload["plan_sort_order"] == "price_asc"
    assert payload["portal_language"] == "sw"
    assert payload["portal_support_whatsapp"] == "0711111111"
    assert payload["portal_support_phone"] == "0700000001"


async def test_overridden_but_empty_title_falls_back_to_business_name(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE,
                                   business_name="Xtiv Net")
    site = await make_router(db, reseller, identity="rt-title")
    as_user["user"] = reseller

    await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(welcome_title=""), db=db, token="t",
    )
    assert (await _portal(db, site))["welcome_title"] == "Xtiv Net"


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

async def test_admin_view_shows_effective_settings_and_what_is_overridden(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, reseller, identity="rt-admin", name="Shop")
    other = await make_router(db, reseller, identity="rt-admin2", name="Estate")
    as_user["user"] = reseller

    before = await get_router_theme_settings(router_id=site.id, db=db, token="t")
    assert before["has_override"] is False
    assert before["overridden_fields"] == []
    assert before["settings"] == before["account_settings"]

    await update_router_theme(
        router_id=site.id,
        request=RouterThemeUpdate(color_theme="teal_lagoon", show_welcome_banner=False),
        db=db, token="t",
    )
    after = await get_router_theme_settings(router_id=site.id, db=db, token="t")
    assert after["has_override"] is True
    assert set(after["overridden_fields"]) == {"color_theme", "show_welcome_banner"}
    assert after["settings"]["color_theme"] == "teal_lagoon"
    assert after["settings"]["show_welcome_banner"] is False
    assert after["account_settings"]["color_theme"] == "slate_gray"

    listing = await list_router_themes(db=db, token="t")
    by_id = {r["router_id"]: r for r in listing["routers"]}
    assert by_id[site.id]["has_override"] is True
    assert by_id[other.id]["has_override"] is False
    assert set(listing["theme_fields"]) == set(pr.ROUTER_THEME_FIELDS)


async def test_sending_a_field_as_null_puts_it_back_on_the_default(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, reseller, identity="rt-null")
    as_user["user"] = reseller

    await update_router_theme(
        router_id=site.id,
        request=RouterThemeUpdate(color_theme="cherry_red", footer_text="Shop"),
        db=db, token="t",
    )
    result = await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(color_theme=None), db=db, token="t",
    )
    assert result["overridden_fields"] == ["footer_text"]
    assert (await _portal(db, site))["color_theme"] == "slate_gray"

    # Clearing the last field leaves nothing of its own: the row goes away.
    result = await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(footer_text=None), db=db, token="t",
    )
    assert result["has_override"] is False
    rows = (await db.execute(select(PortalRouterTheme))).scalars().all()
    assert rows == []


async def test_reset_puts_the_router_back_on_the_account_default(db, as_user):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, reseller, identity="rt-reset")
    as_user["user"] = reseller

    await update_router_theme(
        router_id=site.id, request=RouterThemeUpdate(color_theme="rose_gold"), db=db, token="t",
    )
    result = await reset_router_theme(router_id=site.id, db=db, token="t")
    assert result["has_override"] is False
    assert (await _portal(db, site))["color_theme"] == "slate_gray"

    # Resetting a router that already uses the default is harmless.
    again = await reset_router_theme(router_id=site.id, db=db, token="t")
    assert again["has_override"] is False


async def test_a_reseller_cannot_touch_another_resellers_router(db, as_user):
    owner = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    intruder = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    site = await make_router(db, owner, identity="rt-owned")
    as_user["user"] = intruder

    for call in (
        lambda: get_router_theme_settings(router_id=site.id, db=db, token="t"),
        lambda: update_router_theme(router_id=site.id, request=RouterThemeUpdate(color_theme="hot_pink"), db=db, token="t"),
        lambda: reset_router_theme(router_id=site.id, db=db, token="t"),
    ):
        with pytest.raises(HTTPException) as exc:
            await call()
        assert exc.value.status_code == 404

    assert (await db.execute(select(PortalRouterTheme))).scalars().all() == []
    listing = await list_router_themes(db=db, token="t")
    assert listing["routers"] == []

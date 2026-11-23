from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator
from typing import Optional, Literal
from datetime import datetime

from app.db.database import get_db
from app.db.models import PortalRouterTheme, PortalSettings, Router, User
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.router_helpers import get_router_by_id
from app.services.plan_cache import DEFAULT_PLAN_SORT_ORDER, VALID_PLAN_SORT_ORDERS

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["portal"])


# ─────────────────────────────────────────────────────────────────────────────
# Supported preset values (validated in Pydantic models)
# ─────────────────────────────────────────────────────────────────────────────

# The themes the admin app offers (isp-frontend-admin portalThemes.ts) and the
# captive portal can paint (isp-frontend script.js THEMES). Keep all three in
# step: the admin app renamed midnight_purple to bright_violet and the backend
# never followed, so saving "Bright Violet" was rejected with a 422.
OFFERED_THEMES = {
    "ocean_blue",
    "emerald_green",
    "sunset_orange",
    "bright_violet",
    "rose_gold",
    "slate_gray",
    "teal_lagoon",
    "royal_blue",
    "cherry_red",
    "amber_gold",
    "hot_pink",
    "charcoal_black",
}

# Still accepted so rows saved before the rename keep validating when the
# admin app re-sends them, but no longer advertised. Stored values are never
# rewritten.
LEGACY_THEMES = {"midnight_purple"}

VALID_THEMES = OFFERED_THEMES | LEGACY_THEMES

VALID_HEADER_STYLES = {"standard", "minimal", "hero", "compact"}
VALID_LANGUAGES = {"en", "sw", "fr"}
VALID_ANNOUNCEMENT_TYPES = {"info", "warning", "success"}

# VALID_PLAN_SORT_ORDERS is imported from app.services.plan_cache — the public
# portal endpoint sorts with the same table, so there is one source of truth.


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

# The built-in photos for the hero header, as the classic portal page offers them
# (app/settings/portal-customization in the admin frontend); the Nature one is the default.
HERO_PHOTO_PRESETS = (
    ("City", "https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=750&h=370&fit=crop&q=80"),
    ("People", "https://images.unsplash.com/photo-1529156069898-49953e39b3ac?w=750&h=370&fit=crop&q=80"),
    ("Nature", "https://images.unsplash.com/photo-1523805009345-7448845a9e53?w=750&h=370&fit=crop&q=80"),
    ("Café", "https://images.unsplash.com/photo-1554118811-1e0d58224f24?w=750&h=370&fit=crop&q=80"),
    ("Tech", "https://images.unsplash.com/photo-1518770660439-4636190af475?w=750&h=370&fit=crop&q=80"),
)


def _portal_form_schema(schema: dict) -> None:
    """What a form needs that the validators below already know: the allowed values of
    each choice (as picks, not free text), which fields only matter once their switch is
    on (an announcement's text, the welcome banner's words, the social links), and the
    pictures the person uploads from their phone (logo, header photo), with the built-in
    hero photos to pick from instead."""
    props = schema.get("properties", {})
    for name, values in (("color_theme", OFFERED_THEMES), ("header_style", VALID_HEADER_STYLES),
                         ("portal_language", VALID_LANGUAGES), ("announcement_type", VALID_ANNOUNCEMENT_TYPES),
                         ("plan_sort_order", VALID_PLAN_SORT_ORDERS)):
        if isinstance(props.get(name), dict):
            props[name]["enum"] = sorted(values)
    for name in ("company_logo_url", "header_bg_image_url"):
        if isinstance(props.get(name), dict):
            props[name]["x-upload"] = {"accept": "image/*", "ticket": "/api/ads/media/upload-url"}
    if isinstance(props.get("header_bg_image_url"), dict):
        props["header_bg_image_url"]["x-presets"] = [{"label": label, "value": url} for label, url in HERO_PHOTO_PRESETS]
    schema["x-fields-for"] = {
        # the photo and the logo belong to the hero header, as on the classic page
        "header_style": {"hero": ["header_bg_image_url", "company_logo_url"]},
        "show_announcement": {"true": ["announcement_type", "announcement_text"]},
        "show_welcome_banner": {"true": ["welcome_title", "welcome_subtitle"]},
        "show_social_links": {"true": ["facebook_url", "whatsapp_group_url", "instagram_url"]},
    }


class PortalSettingsUpdate(BaseModel):
    model_config = ConfigDict(json_schema_extra=_portal_form_schema)

    # Theme
    color_theme: Optional[str] = None
    # Header
    header_style: Optional[str] = None
    show_ads: Optional[bool] = None
    show_welcome_banner: Optional[bool] = None
    welcome_title: Optional[str] = None
    welcome_subtitle: Optional[str] = None
    # Branding
    company_logo_url: Optional[str] = Field(None, description="Shown above your title on the hero header, instead of the Wi-Fi icon. Square works best.")
    header_bg_image_url: Optional[str] = Field(None, description="The photo behind your title on the hero header: pick a built-in one, or upload your own.")
    # Footer
    footer_text: Optional[str] = None
    # Support
    portal_support_phone: Optional[str] = None
    portal_support_whatsapp: Optional[str] = None
    # Toggles
    show_ratings: Optional[bool] = None
    show_reconnect_button: Optional[bool] = None
    show_social_links: Optional[bool] = None
    # Social links
    facebook_url: Optional[str] = None
    whatsapp_group_url: Optional[str] = None
    instagram_url: Optional[str] = None
    # Announcement
    show_announcement: Optional[bool] = Field(None, description="A notice banner on the hotspot login page (maintenance, a price change); not an ad.")
    announcement_type: Optional[str] = None
    announcement_text: Optional[str] = None
    # Localisation
    portal_language: Optional[str] = None
    # Plans section
    plans_section_title: Optional[str] = None
    featured_plan_ids: Optional[str] = Field(None, description="Plans highlighted at the top of the login page (comma-separated ids). To keep a plan off the page, hide the plan instead.")
    show_plan_speed: Optional[bool] = None
    plan_sort_order: Optional[str] = None

    @field_validator("color_theme")
    @classmethod
    def validate_theme(cls, v):
        if v is not None and v not in VALID_THEMES:
            raise ValueError(f"color_theme must be one of: {', '.join(sorted(OFFERED_THEMES))}")
        return v

    @field_validator("header_style")
    @classmethod
    def validate_header_style(cls, v):
        if v is not None and v not in VALID_HEADER_STYLES:
            raise ValueError(f"header_style must be one of: {', '.join(sorted(VALID_HEADER_STYLES))}")
        return v

    @field_validator("portal_language")
    @classmethod
    def validate_language(cls, v):
        if v is not None and v not in VALID_LANGUAGES:
            raise ValueError(f"portal_language must be one of: {', '.join(sorted(VALID_LANGUAGES))}")
        return v

    @field_validator("announcement_type")
    @classmethod
    def validate_announcement_type(cls, v):
        if v is not None and v not in VALID_ANNOUNCEMENT_TYPES:
            raise ValueError(f"announcement_type must be one of: {', '.join(sorted(VALID_ANNOUNCEMENT_TYPES))}")
        return v

    @field_validator("plan_sort_order")
    @classmethod
    def validate_plan_sort_order(cls, v):
        if v is not None and v not in VALID_PLAN_SORT_ORDERS:
            raise ValueError(f"plan_sort_order must be one of: {', '.join(sorted(VALID_PLAN_SORT_ORDERS))}")
        return v


# The part of the portal a single router can override: its look. Everything
# else (support contacts, ads, ratings, language, package order) stays
# account-wide. Mirrors the columns of PortalRouterTheme.
ROUTER_THEME_FIELDS = (
    "color_theme",
    "header_style",
    "show_welcome_banner",
    "welcome_title",
    "welcome_subtitle",
    "company_logo_url",
    "header_bg_image_url",
    "footer_text",
)


class RouterThemeUpdate(BaseModel):
    """Body of PUT /api/portal/router-themes/{router_id}.

    Only the fields sent change. A field sent as null goes back to the account
    default for this router, and a field never set follows the account default.
    Other portal settings are rejected because they are account-wide.
    """
    model_config = ConfigDict(extra="forbid")

    color_theme: Optional[str] = None
    header_style: Optional[str] = None
    show_welcome_banner: Optional[bool] = None
    welcome_title: Optional[str] = None
    welcome_subtitle: Optional[str] = None
    company_logo_url: Optional[str] = None
    header_bg_image_url: Optional[str] = None
    footer_text: Optional[str] = None

    @field_validator("color_theme")
    @classmethod
    def validate_theme(cls, v):
        return PortalSettingsUpdate.validate_theme(v)

    @field_validator("header_style")
    @classmethod
    def validate_header_style(cls, v):
        return PortalSettingsUpdate.validate_header_style(v)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _settings_to_dict(s: PortalSettings) -> dict:
    return {
        "id": s.id,
        "user_id": s.user_id,
        # Theme
        "color_theme": s.color_theme,
        # Header
        "header_style": s.header_style,
        "show_ads": s.show_ads,
        "show_welcome_banner": s.show_welcome_banner,
        "welcome_title": s.welcome_title,
        "welcome_subtitle": s.welcome_subtitle,
        # Branding
        "company_logo_url": s.company_logo_url,
        "header_bg_image_url": s.header_bg_image_url,
        # Footer
        "footer_text": s.footer_text,
        # Support
        "portal_support_phone": s.portal_support_phone,
        "portal_support_whatsapp": s.portal_support_whatsapp,
        # Toggles
        "show_ratings": s.show_ratings,
        "show_reconnect_button": s.show_reconnect_button,
        "show_social_links": s.show_social_links,
        # Social
        "facebook_url": s.facebook_url,
        "whatsapp_group_url": s.whatsapp_group_url,
        "instagram_url": s.instagram_url,
        # Announcement
        "show_announcement": s.show_announcement,
        "announcement_type": s.announcement_type,
        "announcement_text": s.announcement_text,
        # Localisation
        "portal_language": s.portal_language,
        # Plans
        "plans_section_title": s.plans_section_title,
        "featured_plan_ids": s.featured_plan_ids,
        "show_plan_speed": s.show_plan_speed,
        "plan_sort_order": s.plan_sort_order or DEFAULT_PLAN_SORT_ORDER,
        # Timestamps
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


async def _get_or_create_settings(db: AsyncSession, user_id: int) -> PortalSettings:
    """Return existing portal settings or create a default row."""
    result = await db.execute(
        select(PortalSettings).where(PortalSettings.user_id == user_id)
    )
    settings = result.scalar_one_or_none()
    if settings is None:
        settings = PortalSettings(user_id=user_id)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings


async def get_router_theme(db: AsyncSession, router_id: int) -> Optional[PortalRouterTheme]:
    """This router's own theme, or None when it uses the account default."""
    result = await db.execute(
        select(PortalRouterTheme).where(PortalRouterTheme.router_id == router_id)
    )
    return result.scalar_one_or_none()


def _overridden_fields(theme: Optional[PortalRouterTheme]) -> list:
    if theme is None:
        return []
    return [f for f in ROUTER_THEME_FIELDS if getattr(theme, f) is not None]


def _apply_router_theme(settings: dict, theme: Optional[PortalRouterTheme]) -> dict:
    """Lay a router's own theme over the account settings, field by field."""
    merged = dict(settings)
    for field in _overridden_fields(theme):
        merged[field] = getattr(theme, field)
    return merged


async def _owned_router(db: AsyncSession, router_id: int, user: User) -> Router:
    role = user.role.value if hasattr(user.role, "value") else user.role
    router_obj = await get_router_by_id(db, router_id, user.id, role)
    if router_obj is None:
        raise HTTPException(status_code=404, detail="Router not found")
    return router_obj


async def _router_theme_payload(db: AsyncSession, router_obj: Router) -> dict:
    account = _settings_to_dict(await _get_or_create_settings(db, router_obj.user_id))
    theme = await get_router_theme(db, router_obj.id)
    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "has_override": theme is not None,
        "overridden_fields": _overridden_fields(theme),
        "theme_fields": list(ROUTER_THEME_FIELDS),
        # What this router's portal shows: the account settings with this
        # router's own theme laid over them.
        "settings": _apply_router_theme(account, theme),
        "account_settings": account,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Admin endpoints (auth required)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/portal/settings")
async def get_portal_settings(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Get the current portal customization settings for the authenticated reseller.
    Returns default values if settings have never been saved.
    """
    user = await get_current_user(token, db)
    settings = await _get_or_create_settings(db, user.id)
    return {
        "settings": _settings_to_dict(settings),
        "available_themes": sorted(OFFERED_THEMES),
        "available_header_styles": sorted(VALID_HEADER_STYLES),
        "available_languages": sorted(VALID_LANGUAGES),
        "available_announcement_types": sorted(VALID_ANNOUNCEMENT_TYPES),
        "available_plan_sort_orders": sorted(VALID_PLAN_SORT_ORDERS),
    }


@router.put("/api/portal/settings")
async def update_portal_settings(
    request: PortalSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Update portal customization settings for the authenticated reseller.
    Only fields included in the request body are changed (partial update).
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    settings = await _get_or_create_settings(db, user.id)

    updatable_fields = [
        "color_theme", "header_style", "show_ads", "show_welcome_banner",
        "welcome_title", "welcome_subtitle", "company_logo_url",
        "header_bg_image_url", "footer_text", "portal_support_phone",
        "portal_support_whatsapp", "show_ratings", "show_reconnect_button",
        "show_social_links", "facebook_url", "whatsapp_group_url",
        "instagram_url", "show_announcement", "announcement_type",
        "announcement_text", "portal_language", "plans_section_title",
        "featured_plan_ids", "show_plan_speed", "plan_sort_order",
    ]

    changed = []
    for field in updatable_fields:
        value = getattr(request, field, None)
        if value is not None:
            setattr(settings, field, value)
            changed.append(field)

    # Allow explicit false/empty-string updates for boolean/string fields
    bool_fields = [
        "show_ads", "show_welcome_banner", "show_ratings",
        "show_reconnect_button", "show_social_links", "show_announcement",
        "show_plan_speed",
    ]
    for field in bool_fields:
        raw = request.model_fields_set  # fields that were explicitly provided
        if field in raw and field not in changed:
            setattr(settings, field, getattr(request, field))
            changed.append(field)

    settings.updated_at = datetime.utcnow()
    # Show Ads off stops the clock on the reseller's sold ads; on moves their
    # end dates out by the time it was off.
    if "show_ads" in changed:
        from app.services.ad_sales import on_show_ads_changed
        await on_show_ads_changed(db, user.id, bool(settings.show_ads))
    await db.commit()
    await db.refresh(settings)
    if "show_ads" in changed:
        from app.services.ad_serving import invalidate_ad_cache
        await invalidate_ad_cache()

    logger.info("Portal settings updated for user %s: %s", user.id, changed)

    return {
        "message": "Portal settings updated successfully",
        "updated_fields": changed,
        "settings": _settings_to_dict(settings),
    }


@router.post("/api/portal/settings/reset")
async def reset_portal_settings(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Reset all portal settings back to defaults for the authenticated reseller.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    result = await db.execute(
        select(PortalSettings).where(PortalSettings.user_id == user.id)
    )
    settings = result.scalar_one_or_none()

    if settings:
        await db.delete(settings)
        await db.commit()

    # Re-create with all defaults. That turns Show Ads off (see update above).
    settings = PortalSettings(user_id=user.id)
    db.add(settings)
    from app.services.ad_sales import on_show_ads_changed
    await on_show_ads_changed(db, user.id, False)
    await db.commit()
    await db.refresh(settings)

    return {
        "message": "Portal settings reset to defaults",
        "settings": _settings_to_dict(settings),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Per-router themes (auth required)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/portal/router-themes")
async def list_router_themes(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Every router on the account, and whether it has its own portal theme."""
    user = await get_current_user(token, db)
    routers = (await db.execute(
        select(Router).where(Router.user_id == user.id).order_by(Router.name, Router.id)
    )).scalars().all()
    themes = {
        t.router_id: t
        for t in (await db.execute(
            select(PortalRouterTheme).where(PortalRouterTheme.user_id == user.id)
        )).scalars().all()
    }
    return {
        "theme_fields": list(ROUTER_THEME_FIELDS),
        "routers": [
            {
                "router_id": r.id,
                "router_name": r.name,
                "identity": r.identity,
                "has_override": r.id in themes,
                "overridden_fields": _overridden_fields(themes.get(r.id)),
                "updated_at": (
                    themes[r.id].updated_at.isoformat()
                    if r.id in themes and themes[r.id].updated_at else None
                ),
            }
            for r in routers
        ],
    }


@router.get("/api/portal/router-themes/{router_id}")
async def get_router_theme_settings(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """What this router's captive portal shows, and which fields are its own."""
    user = await get_current_user(token, db)
    router_obj = await _owned_router(db, router_id, user)
    return await _router_theme_payload(db, router_obj)


@router.put("/api/portal/router-themes/{router_id}")
async def update_router_theme(
    router_id: int,
    request: RouterThemeUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Give this router its own look. Only the fields sent change; a field sent
    as null goes back to the account default for this router."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await _owned_router(db, router_id, user)

    theme = await get_router_theme(db, router_obj.id)
    if theme is None:
        theme = PortalRouterTheme(router_id=router_obj.id, user_id=router_obj.user_id)
        db.add(theme)

    changed = [f for f in ROUTER_THEME_FIELDS if f in request.model_fields_set]
    for field in changed:
        setattr(theme, field, getattr(request, field))
    theme.updated_at = datetime.utcnow()

    if not _overridden_fields(theme):
        # Nothing of its own left, so the router is back on the default.
        if theme.id is not None:
            await db.delete(theme)
        else:
            db.expunge(theme)
    await db.commit()

    logger.info("Portal theme for router %s (user %s) updated: %s", router_obj.id, user.id, changed)
    payload = await _router_theme_payload(db, router_obj)
    payload["message"] = "Router theme updated"
    payload["updated_fields"] = changed
    return payload


@router.delete("/api/portal/router-themes/{router_id}")
async def reset_router_theme(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Put this router back on the account's default theme."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await _owned_router(db, router_id, user)

    theme = await get_router_theme(db, router_obj.id)
    if theme is not None:
        await db.delete(theme)
        await db.commit()
    logger.info("Portal theme for router %s (user %s) reset to default", router_obj.id, user.id)
    payload = await _router_theme_payload(db, router_obj)
    payload["message"] = "Router now uses the default theme"
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Public endpoint (no auth) — called by captive portal frontend
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/public/portal/settings/{router_id}")
async def get_public_portal_settings(
    router_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Fetch portal customization settings for a specific router (public, no auth).
    Called by the captive portal frontend to apply the correct theme/layout.
    Falls back to system defaults when the reseller hasn't configured anything.
    """
    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    # Get reseller info for fallback support phone
    user_result = await db.execute(
        select(User).where(User.id == router_obj.user_id)
    )
    reseller = user_result.scalar_one_or_none()

    result = await db.execute(
        select(PortalSettings).where(PortalSettings.user_id == router_obj.user_id)
    )
    settings = result.scalar_one_or_none()
    router_theme = await get_router_theme(db, router_obj.id)

    # A missing account row means defaults, served without persisting a row.
    return _build_public_response(settings, reseller, router_theme)


def _build_public_response(
    settings: Optional[PortalSettings],
    reseller: Optional[User],
    router_theme: Optional[PortalRouterTheme] = None,
) -> dict:
    """Build the public-facing settings payload with sensible fallbacks.

    `router_theme` is this router's own look, if it has one; its set fields
    win over the account settings. Without one the payload is exactly the
    account's, as it was before per-router themes existed.
    """
    payload = _build_account_public_response(settings, reseller)
    overridden = _overridden_fields(router_theme)
    for field in overridden:
        payload[field] = getattr(router_theme, field)
    if "welcome_title" in overridden and not payload["welcome_title"]:
        # Same fallback as the account title: the business name.
        payload["welcome_title"] = (
            (reseller.business_name or reseller.organization_name) if reseller else None
        )
    return payload


def _build_account_public_response(settings: Optional[PortalSettings], reseller: Optional[User]) -> dict:
    """The account-wide public payload, with sensible fallbacks."""

    fallback_support_phone = reseller.support_phone if reseller else None
    org_name = reseller.organization_name if reseller else None
    business_name = reseller.business_name if reseller else None

    if settings is None:
        return {
            "color_theme": "slate_gray",
            "header_style": "hero",
            "show_ads": False,
            "show_welcome_banner": True,
            "welcome_title": business_name or org_name,
            "welcome_subtitle": None,
            "company_logo_url": None,
            "header_bg_image_url": "https://images.unsplash.com/photo-1523805009345-7448845a9e53?w=750&h=370&fit=crop&q=80",
            "footer_text": None,
            "portal_support_phone": fallback_support_phone,
            "portal_support_whatsapp": None,
            "show_ratings": True,
            "show_reconnect_button": True,
            "show_social_links": False,
            "facebook_url": None,
            "whatsapp_group_url": None,
            "instagram_url": None,
            "show_announcement": False,
            "announcement_type": "info",
            "announcement_text": None,
            "portal_language": "en",
            "plans_section_title": None,
            "featured_plan_ids": None,
            "show_plan_speed": True,
            "plan_sort_order": DEFAULT_PLAN_SORT_ORDER,
        }

    return {
        "color_theme": settings.color_theme,
        "header_style": settings.header_style,
        "show_ads": settings.show_ads,
        "show_welcome_banner": settings.show_welcome_banner,
        "welcome_title": settings.welcome_title or business_name or org_name,
        "welcome_subtitle": settings.welcome_subtitle,
        "company_logo_url": settings.company_logo_url,
        "header_bg_image_url": settings.header_bg_image_url,
        "footer_text": settings.footer_text,
        "portal_support_phone": settings.portal_support_phone or fallback_support_phone,
        "portal_support_whatsapp": settings.portal_support_whatsapp,
        "show_ratings": settings.show_ratings,
        "show_reconnect_button": settings.show_reconnect_button,
        "show_social_links": settings.show_social_links,
        "facebook_url": settings.facebook_url,
        "whatsapp_group_url": settings.whatsapp_group_url,
        "instagram_url": settings.instagram_url,
        "show_announcement": settings.show_announcement,
        "announcement_type": settings.announcement_type,
        "announcement_text": settings.announcement_text,
        "portal_language": settings.portal_language,
        "plans_section_title": settings.plans_section_title,
        "featured_plan_ids": settings.featured_plan_ids,
        "show_plan_speed": settings.show_plan_speed,
        "plan_sort_order": settings.plan_sort_order or DEFAULT_PLAN_SORT_ORDER,
    }

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, HttpUrl, field_validator
from typing import Optional, Literal
from datetime import datetime

from app.db.database import get_db
from app.db.models import PortalSettings, Router, User
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services import ad_media
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

class PortalSettingsUpdate(BaseModel):
    # Theme
    color_theme: Optional[str] = None
    # Header
    header_style: Optional[str] = None
    show_ads: Optional[bool] = None
    show_welcome_banner: Optional[bool] = None
    welcome_title: Optional[str] = None
    welcome_subtitle: Optional[str] = None
    # Branding
    company_logo_url: Optional[str] = None
    header_bg_image_url: Optional[str] = None
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
    show_announcement: Optional[bool] = None
    announcement_type: Optional[str] = None
    announcement_text: Optional[str] = None
    # Localisation
    portal_language: Optional[str] = None
    # Plans section
    plans_section_title: Optional[str] = None
    featured_plan_ids: Optional[str] = None
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


class HeroImageUploadRequest(BaseModel):
    content_type: str
    size: int


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


def _check_hero_image_url(url: Optional[str]) -> None:
    """A link on our media host must be a hero photo, not a video or an ad path.

    Anything else (the preset links the dashboard sends, values already stored)
    is left alone: the portal only loads bundled presets for those, so they keep
    rendering exactly as they did.
    """
    base = ad_media.public_media_base()
    if url and base and url.startswith(f"{base}/") and not ad_media.is_portal_hero_url(url):
        raise HTTPException(status_code=400, detail="header_bg_image_url must be uploaded through the dashboard")


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
    _check_hero_image_url(request.header_bg_image_url)

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


@router.post("/api/portal/settings/hero-image/upload-url")
async def create_hero_image_upload(
    request: HeroImageUploadRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """A presigned PUT for the reseller's own hero photo. The browser uploads
    straight to storage, then saves public_url as header_bg_image_url."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    try:
        ticket = ad_media.create_portal_hero_upload(
            request.content_type, request.size, owner_label=f"r{user.id}",
        )
    except ad_media.MediaNotConfigured as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ad_media.MediaRejected as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "upload_url": ticket.upload_url,
        "public_url": ticket.public_url,
        "key": ticket.key,
        "content_type": ticket.content_type,
        "max_bytes": ticket.max_bytes,
        "expires_in": ticket.expires_in,
        "method": "PUT",
        "headers": {"Content-Type": ticket.content_type},
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

    if settings is None:
        # Return defaults without persisting a row
        return _build_public_response(None, reseller)

    return _build_public_response(settings, reseller)


def _build_public_response(settings: Optional[PortalSettings], reseller: Optional[User]) -> dict:
    """Build the public-facing settings payload with sensible fallbacks."""

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

"""Which ads a captive portal shows, and how their views and taps are counted.

Serving
-------
Every live, approved ad is read in one query and cached for AD_CACHE_TTL
seconds; each portal request then filters that list in memory for its router.
So a portal load costs no ad query at all on a warm cache, and an ad edit
shows up within a minute (sooner: every write path calls invalidate_ad_cache).

An ad reaches a router when:
  * it is active, approved, and inside its starts_at / expires_at window;
  * its owner is Bitwave (owner_user_id NULL) or the reseller who owns the
    router; and
  * its router_ids is NULL (all of the owner's routers, or the whole network
    for a Bitwave ad) or lists this router.

Hero ads come first in slot order (Bitwave's sponsor, then ads the reseller
sold, then the reseller's own promo) and are capped at HERO_MAX so the hero
never turns into a slideshow nobody finishes.

Counting
--------
record_ad_events() inserts one ad_events row per ad, placement, device and UTC
day, skipping duplicates. Nothing on this path updates an ads row: the old
per-load views_count/clicks_count increments did, which is the hot-row lock
pattern behind the pool incidents (AGENTS.md, Database Session Discipline).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import select

from app.core.cache import cache
from app.db import database as db_module
from app.db.models import Ad, AdEvent
from app.services.plan_cache import normalize_router_ids

logger = logging.getLogger(__name__)

AD_CACHE_KEY = "ads:live"
AD_CACHE_TTL = 60
HERO_MAX = 3
LOCAL_MAX = 8

PLACEMENTS = ("hero", "local")
MEDIA_TYPES = ("image", "video")
IMAGE_FITS = ("cover", "contain")
SLOTS = ("platform", "reseller", "house")
STATUSES = ("pending", "approved", "rejected")
SLOT_ORDER = {"platform": 0, "reseller": 1, "house": 2}

# Where a view or tap happened. "showcase_carousel" is what portals from
# before hero ads send; it is kept so their counts still land somewhere.
EVENT_PLACEMENTS = ("hero", "wait_screen", "success_page", "local", "showcase_carousel")
CLICK_TYPES = ("call", "whatsapp", "view_details")
MAX_EVENT_ADS = 10

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------

def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def serialize_portal_ad(ad: Ad) -> dict:
    """What a portal needs to render the ad, plus the targeting keys used to
    filter it (stripped by public_ad before anything leaves the server)."""
    return {
        "id": ad.id,
        "title": ad.title,
        "description": ad.description,
        "image_url": ad.image_url,
        "seller_name": ad.seller_name,
        "seller_location": ad.seller_location,
        "phone_number": ad.phone_number,
        "whatsapp_number": ad.whatsapp_number,
        "price": ad.price,
        "price_value": ad.price_value,
        "badge_type": ad.badge_type.value if ad.badge_type else None,
        "badge_text": ad.badge_text,
        "category": ad.category,
        "placement": ad.placement or "local",
        "media_type": ad.media_type or "image",
        "video_url": ad.video_url,
        "poster_url": ad.poster_url,
        "image_fit": ad.image_fit or "cover",
        "bg_color": ad.bg_color,
        "slot": ad.slot or "platform",
        "priority": ad.priority or 0,
        "_owner_user_id": ad.owner_user_id,
        "_router_ids": normalize_router_ids(ad.router_ids),
    }


def public_ad(ad: dict) -> dict:
    return {k: v for k, v in ad.items() if not k.startswith("_")}


async def _load_live_ads(db) -> list[dict]:
    now = datetime.utcnow()
    result = await db.execute(
        select(Ad)
        .where(Ad.is_active == True)  # noqa: E712
        .where(Ad.status == "approved")
        .where((Ad.starts_at == None) | (Ad.starts_at <= now))  # noqa: E711
        .where((Ad.expires_at == None) | (Ad.expires_at > now))  # noqa: E711
        .order_by(Ad.priority.desc(), Ad.created_at.desc(), Ad.id.desc())
    )
    return [serialize_portal_ad(ad) for ad in result.scalars().all()]


async def get_live_ads_cached(db) -> list[dict]:
    async def fetch():
        return await _load_live_ads(db)
    return await cache.get_or_set(AD_CACHE_KEY, fetch, AD_CACHE_TTL)


async def invalidate_ad_cache() -> None:
    await cache.clear_pattern("ads:")


def ad_allows_router(ad: dict, router_id: Optional[int], owner_user_id: Optional[int]) -> bool:
    owner = ad.get("_owner_user_id")
    if owner is not None and owner != owner_user_id:
        return False
    scope = ad.get("_router_ids")
    if scope is None:
        return True
    return router_id is not None and int(router_id) in scope


def select_ads_for_router(
    live: Iterable[dict], router_id: Optional[int], owner_user_id: Optional[int]
) -> list[dict]:
    """Hero ads (slot order, then the cached priority order) then local ads."""
    allowed = [a for a in live if ad_allows_router(a, router_id, owner_user_id)]
    hero = [a for a in allowed if a["placement"] == "hero"]
    # sorted() is stable, so ads within a slot keep the priority order.
    hero = sorted(hero, key=lambda a: SLOT_ORDER.get(a["slot"], len(SLOT_ORDER)))[:HERO_MAX]
    local = [a for a in allowed if a["placement"] != "hero"][:LOCAL_MAX]
    return [public_ad(a) for a in hero + local]


async def ads_for_router(db, router_id: int, owner_user_id: int, show_ads: bool) -> list[dict]:
    """The ads one router's portal should show. Empty when the reseller has ads off."""
    if not show_ads:
        return []
    live = await get_live_ads_cached(db)
    return select_ads_for_router(live, router_id, owner_user_id)


async def network_ads(db, limit: int = 20) -> list[dict]:
    """Bitwave ads that run network-wide: what the legacy public /api/ads
    feed may show, since it has no router to scope to."""
    live = await get_live_ads_cached(db)
    rows = [a for a in live if a["_owner_user_id"] is None and a["_router_ids"] is None]
    return [public_ad(a) for a in rows[:limit]]


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------

def device_key_for(mac: Optional[str], device_id: Optional[str], session_id: Optional[str]) -> Optional[str]:
    """MAC when the portal knows it (one per phone, survives a cleared
    browser), else the portal's stored device id, else the session."""
    if mac:
        norm = mac.strip().upper().replace("-", ":")
        if _MAC_RE.match(norm):
            return norm
    for value in (device_id, session_id):
        if value and value.strip():
            return value.strip()[:64]
    return None


def build_event_rows(
    *,
    ad_ids: Iterable,
    event_type: str,
    placement: Optional[str],
    device_key: Optional[str],
    live_ad_ids: set,
    router_identity: Optional[str] = None,
    click_type: str = "",
    now: Optional[datetime] = None,
) -> list[dict]:
    """Rows worth storing: only ads that are actually live, a known
    placement and a device to de-duplicate on. Anything else is dropped
    silently: this is a public endpoint and the portal must never see an
    error from it."""
    if not device_key:
        return []
    placement = placement if placement in EVENT_PLACEMENTS else None
    if placement is None:
        return []
    now = now or datetime.utcnow()
    day = now.strftime("%Y-%m-%d")
    rows, seen = [], set()
    for raw in list(ad_ids)[:MAX_EVENT_ADS]:
        try:
            ad_id = int(raw)
        except (TypeError, ValueError):
            continue
        if ad_id in seen or ad_id not in live_ad_ids:
            continue
        seen.add(ad_id)
        rows.append({
            "ad_id": ad_id,
            "event_type": event_type,
            "click_type": click_type or "",
            "placement": placement,
            "device_key": device_key,
            "router_identity": (router_identity or "")[:100] or None,
            "day": day,
            "created_at": now,
        })
    return rows


async def record_ad_events(rows: list[dict]) -> int:
    """Insert in a session of its own, skipping a repeat of the same ad,
    event, placement, device and day. Returns how many rows were new."""
    if not rows:
        return 0
    async with db_module.async_session() as session:
        dialect = session.bind.dialect.name if session.bind is not None else ""
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        elif dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert
        else:  # pragma: no cover - production is Postgres, tests SQLite/Postgres
            session.add_all(AdEvent(**r) for r in rows)
            await session.commit()
            return len(rows)
        stmt = insert(AdEvent).values(rows).on_conflict_do_nothing(
            index_elements=["ad_id", "event_type", "click_type", "placement", "device_key", "day"]
        )
        result = await session.execute(stmt)
        await session.commit()
        return result.rowcount if result.rowcount is not None and result.rowcount >= 0 else len(rows)

"""Ads: who may create and edit them, approval, the portal's view/tap beacons,
stats, and media upload slots.

Ownership (hero ads, 2026-10):
  * Bitwave (an admin) creates "platform" ads. They are approved on creation
    and run network-wide or on the routers listed in router_ids.
  * A reseller creates ads only for their own routers: "house" (their own
    promo) or "reseller" (one they sold). Every reseller ad starts pending and
    needs an admin's approval before any portal shows it; editing its content
    sends it back to pending.
  * A reseller sees, edits and deletes only their own ads. Before this, any
    reseller could edit or delete any ad and publish to every portal.

Serving and counting live in app/services/ad_serving.py.
"""

import logging
import re
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import (
    Ad, AdBadgeType, AdClick, AdEvent, Advertiser, Router, User, UserRole,
)
from app.services import ad_media
from app.services.ad_serving import (
    CLICK_TYPES, IMAGE_FITS, MEDIA_TYPES, PLACEMENTS, STATUSES,
    build_event_rows, device_key_for, get_live_ads_cached, invalidate_ad_cache,
    network_ads, record_ad_events,
)
from app.services.auth import get_current_user, verify_token
from app.services.plan_cache import normalize_router_ids
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ads"])

_BADGES = {"hot": AdBadgeType.HOT, "new": AdBadgeType.NEW, "sale": AdBadgeType.SALE}
_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ]{9,16}$")
# Content edits that send a reseller's approved ad back for review.
_REVIEWED_FIELDS = {
    "title", "description", "image_url", "seller_name", "seller_location",
    "phone_number", "whatsapp_number", "price", "media_type", "video_url",
    "poster_url", "category", "placement",
}


# ========================================
# Request models
# ========================================

class AdClickRequest(BaseModel):
    ad_id: int
    click_type: str  # "call", "whatsapp", "view_details"
    placement: Optional[str] = None
    device_id: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    referrer: Optional[str] = None
    mac_address: Optional[str] = None
    router_identity: Optional[str] = None


class AdImpressionRequest(BaseModel):
    ad_ids: list[int]
    placement: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    mac_address: Optional[str] = None
    router_identity: Optional[str] = None


class AdvertiserCreateRequest(BaseModel):
    name: str
    business_name: Optional[str] = None
    phone_number: str
    email: Optional[str] = None


class AdCreateRequest(BaseModel):
    title: str
    seller_name: str
    phone_number: str
    advertiser_id: Optional[int] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    seller_location: Optional[str] = None
    whatsapp_number: Optional[str] = None
    price: Optional[str] = None
    price_value: Optional[float] = None
    badge_type: Optional[str] = None
    badge_text: Optional[str] = None
    category: Optional[str] = None
    priority: int = 0
    starts_at: Optional[str] = None
    expires_at: Optional[str] = None
    placement: str = "local"
    media_type: str = "image"
    video_url: Optional[str] = None
    poster_url: Optional[str] = None
    image_fit: str = "cover"
    bg_color: Optional[str] = None
    slot: Optional[str] = None          # admin: "platform"; reseller: "house" (default) or "reseller"
    router_ids: Optional[list[int]] = None


class AdUpdateRequest(BaseModel):
    advertiser_id: Optional[int] = None     # admin only; Bitwave ads
    title: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    seller_name: Optional[str] = None
    seller_location: Optional[str] = None
    phone_number: Optional[str] = None
    whatsapp_number: Optional[str] = None
    price: Optional[str] = None
    price_value: Optional[float] = None
    badge_type: Optional[str] = None
    badge_text: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[int] = None
    starts_at: Optional[str] = None
    expires_at: Optional[str] = None
    is_active: Optional[bool] = None
    placement: Optional[str] = None
    media_type: Optional[str] = None
    video_url: Optional[str] = None
    poster_url: Optional[str] = None
    image_fit: Optional[str] = None
    bg_color: Optional[str] = None
    slot: Optional[str] = None
    router_ids: Optional[list[int]] = None


class AdReviewRequest(BaseModel):
    action: str            # "approve" | "reject"
    note: Optional[str] = None


class MediaUploadRequest(BaseModel):
    content_type: str
    size: int


# ========================================
# Helpers
# ========================================

def _is_admin(user: User) -> bool:
    return user.role == UserRole.ADMIN


def _require_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Only Bitwave admins can do this")


def _parse_dt(value: Optional[str], field: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field} is not a valid date")
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def _check_choice(value: str, allowed, field: str) -> str:
    if value not in allowed:
        raise HTTPException(status_code=400, detail=f"{field} must be one of: {', '.join(allowed)}")
    return value


def _check_media_url(url: Optional[str], field: str) -> Optional[str]:
    """Portals load media before the customer has internet, so it must come
    from a host in the walled garden: our media base once R2 is set up."""
    if url is None or url == "":
        return None
    url = url.strip()
    base = ad_media.public_media_base()
    if base:
        if not url.startswith(base + "/"):
            raise HTTPException(status_code=400, detail=f"{field} must be uploaded through the dashboard")
    elif not url.startswith("https://"):
        raise HTTPException(status_code=400, detail=f"{field} must be an https:// link")
    return url[:500]


def _check_phone(phone: Optional[str], field: str) -> Optional[str]:
    if phone is None or phone == "":
        return None
    phone = phone.strip()
    if not _PHONE_RE.match(phone):
        raise HTTPException(status_code=400, detail=f"{field} must be a phone number, e.g. 0712 345 678")
    return phone


def _check_media_complete(ad: Ad) -> None:
    if ad.media_type == "video" and not ad.video_url:
        raise HTTPException(status_code=400, detail="A video ad needs a video")
    if ad.media_type == "image" and not ad.image_url:
        raise HTTPException(status_code=400, detail="A photo ad needs a photo")


async def _check_router_scope(db: AsyncSession, user: User, router_ids) -> Optional[list[int]]:
    """None = all routers. A reseller may only target routers they own."""
    ids = normalize_router_ids(router_ids)
    if ids is None:
        return None
    q = select(Router.id).where(Router.id.in_(ids))
    if not _is_admin(user):
        q = q.where(Router.user_id == user.id)
    found = set((await db.execute(q)).scalars().all())
    missing = [i for i in ids if i not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"Unknown router(s): {', '.join(map(str, missing))}")
    return ids


async def _load_owned_ad(db: AsyncSession, user: User, ad_id: int) -> Ad:
    ad = (await db.execute(select(Ad).where(Ad.id == ad_id))).scalar_one_or_none()
    # A reseller asking for someone else's ad gets the same answer as for a
    # missing one, so ids can't be probed.
    if not ad or (not _is_admin(user) and ad.owner_user_id != user.id):
        raise HTTPException(status_code=404, detail="Ad not found")
    return ad


def _serialize_manage(ad: Ad, stats: Optional[dict] = None, owner_name: Optional[str] = None) -> dict:
    stats = stats or {}
    return {
        "id": ad.id,
        "advertiser_id": ad.advertiser_id,
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
        "is_active": ad.is_active,
        "priority": ad.priority,
        "placement": ad.placement,
        "media_type": ad.media_type,
        "video_url": ad.video_url,
        "poster_url": ad.poster_url,
        "image_fit": ad.image_fit,
        "bg_color": ad.bg_color,
        "slot": ad.slot,
        "owner_user_id": ad.owner_user_id,
        # Who to show as the owner: the reseller's business, or Bitwave.
        "owner_name": owner_name if ad.owner_user_id is not None else "Bitwave",
        "router_ids": normalize_router_ids(ad.router_ids),
        "status": ad.status,
        "review_note": ad.review_note,
        "reviewed_at": ad.reviewed_at.isoformat() if ad.reviewed_at else None,
        "starts_at": ad.starts_at.isoformat() if ad.starts_at else None,
        "expires_at": ad.expires_at.isoformat() if ad.expires_at else None,
        "created_at": ad.created_at.isoformat() if ad.created_at else None,
        # Unique devices per day, summed, over the last 30 days.
        "views_count": int(stats.get("impression", 0)),
        "clicks_count": int(stats.get("click", 0)),
    }


async def _event_totals(db: AsyncSession, ad_ids: list[int], days: int = 30) -> dict:
    if not ad_ids:
        return {}
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = (await db.execute(
        select(AdEvent.ad_id, AdEvent.event_type, func.count())
        .where(AdEvent.ad_id.in_(ad_ids), AdEvent.day >= since)
        .group_by(AdEvent.ad_id, AdEvent.event_type)
    )).all()
    totals: dict = {}
    for ad_id, event_type, n in rows:
        totals.setdefault(ad_id, {})[event_type] = n
    return totals


async def _owner_names(db: AsyncSession, owner_ids) -> dict:
    ids = {i for i in owner_ids if i is not None}
    if not ids:
        return {}
    rows = (await db.execute(
        select(User.id, User.business_name, User.organization_name).where(User.id.in_(ids))
    )).all()
    return {uid: (business or org) for uid, business, org in rows}


def _apply_fields(ad: Ad, data: dict) -> None:
    """Validate and copy the fields present in `data` onto the ad."""
    for field in ("title", "seller_name"):
        if field in data:
            value = (data[field] or "").strip()
            if not value:
                raise HTTPException(status_code=400, detail=f"{field} cannot be empty")
            setattr(ad, field, value[:150 if field == "title" else 100])
    for field, limit in (("description", 500), ("seller_location", 200), ("price", 50),
                         ("badge_text", 50), ("category", 50)):
        if field in data:
            value = (data[field] or "").strip()
            setattr(ad, field, value[:limit] or None)
    if "phone_number" in data:
        phone = _check_phone(data["phone_number"], "phone_number")
        if not phone:
            raise HTTPException(status_code=400, detail="phone_number cannot be empty")
        ad.phone_number = phone
    if "whatsapp_number" in data:
        ad.whatsapp_number = _check_phone(data["whatsapp_number"], "whatsapp_number")
    if "price_value" in data:
        ad.price_value = data["price_value"]
    if "badge_type" in data:
        ad.badge_type = _BADGES.get((data["badge_type"] or "").lower())
    if "priority" in data and data["priority"] is not None:
        ad.priority = int(data["priority"])
    if "starts_at" in data:
        ad.starts_at = _parse_dt(data["starts_at"], "starts_at")
    if "expires_at" in data:
        ad.expires_at = _parse_dt(data["expires_at"], "expires_at")
    if "placement" in data and data["placement"] is not None:
        ad.placement = _check_choice(data["placement"], PLACEMENTS, "placement")
    if "media_type" in data and data["media_type"] is not None:
        ad.media_type = _check_choice(data["media_type"], MEDIA_TYPES, "media_type")
    if "image_fit" in data and data["image_fit"] is not None:
        ad.image_fit = _check_choice(data["image_fit"], IMAGE_FITS, "image_fit")
    for field in ("image_url", "video_url", "poster_url"):
        if field in data:
            setattr(ad, field, _check_media_url(data[field], field))
    if "bg_color" in data:
        color = (data["bg_color"] or "").strip()
        if color and not _COLOR_RE.match(color):
            raise HTTPException(status_code=400, detail="bg_color must look like #14532D")
        ad.bg_color = color or None
    if ad.starts_at and ad.expires_at and ad.expires_at <= ad.starts_at:
        raise HTTPException(status_code=400, detail="The end date must be after the start date")


# ========================================
# Advertisers (Bitwave admins only: the list holds other businesses' contacts)
# ========================================

@router.post("/api/advertisers")
async def create_advertiser(
    request: AdvertiserCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    _require_admin(user)
    advertiser = Advertiser(
        name=request.name,
        business_name=request.business_name,
        phone_number=request.phone_number,
        email=request.email,
    )
    db.add(advertiser)
    await db.commit()
    await db.refresh(advertiser)
    return {
        "id": advertiser.id,
        "name": advertiser.name,
        "business_name": advertiser.business_name,
        "phone_number": advertiser.phone_number,
        "email": advertiser.email,
        "is_active": advertiser.is_active,
        "created_at": advertiser.created_at.isoformat(),
    }


@router.get("/api/advertisers")
async def get_advertisers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    _require_admin(user)
    result = await db.execute(select(Advertiser).order_by(Advertiser.created_at.desc()))
    return [
        {
            "id": a.id,
            "name": a.name,
            "business_name": a.business_name,
            "phone_number": a.phone_number,
            "email": a.email,
            "is_active": a.is_active,
            "created_at": a.created_at.isoformat(),
        }
        for a in result.scalars().all()
    ]


# ========================================
# Managing ads (signed in)
# ========================================

@router.get("/api/ads/manage")
async def list_manage_ads(
    status: Optional[str] = None,
    placement: Optional[str] = None,
    owner_user_id: Optional[int] = None,
    bitwave_only: bool = False,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Admins see every ad; a reseller sees their own. ?status=pending is the
    review queue. Admins can narrow to one reseller (?owner_user_id=) or to
    Bitwave's own ads (?bitwave_only=true)."""
    user = await get_current_user(token, db)
    page, per_page = max(page, 1), min(max(per_page, 1), 100)
    q = select(Ad)
    if not _is_admin(user):
        q = q.where(Ad.owner_user_id == user.id)
    elif bitwave_only:
        q = q.where(Ad.owner_user_id == None)  # noqa: E711
    elif owner_user_id is not None:
        q = q.where(Ad.owner_user_id == owner_user_id)
    if status:
        q = q.where(Ad.status == _check_choice(status, STATUSES, "status"))
    if placement:
        q = q.where(Ad.placement == _check_choice(placement, PLACEMENTS, "placement"))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    ads = (await db.execute(
        q.order_by(Ad.created_at.desc(), Ad.id.desc()).offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()
    totals = await _event_totals(db, [a.id for a in ads])
    names = await _owner_names(db, [a.owner_user_id for a in ads])
    return {
        "ads": [_serialize_manage(a, totals.get(a.id), names.get(a.owner_user_id)) for a in ads],
        "pagination": {
            "page": page, "per_page": per_page, "total": total,
            "total_pages": (total + per_page - 1) // per_page,
        },
    }


@router.get("/api/ads/manage/{ad_id}")
async def get_manage_ad(
    ad_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ad = await _load_owned_ad(db, user, ad_id)
    totals = await _event_totals(db, [ad.id])
    names = await _owner_names(db, [ad.owner_user_id])
    return _serialize_manage(ad, totals.get(ad.id), names.get(ad.owner_user_id))


@router.post("/api/ads")
async def create_ad(
    request: AdCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    admin = _is_admin(user)

    if admin:
        slot = request.slot or "platform"
        if slot != "platform":
            raise HTTPException(status_code=400, detail="Bitwave ads use the platform slot")
    else:
        slot = request.slot or "house"
        if slot not in ("house", "reseller"):
            raise HTTPException(status_code=400, detail="slot must be house or reseller")
        if request.advertiser_id is not None:
            raise HTTPException(status_code=400, detail="Only Bitwave ads can be linked to an advertiser")
    if request.advertiser_id is not None:
        exists = (await db.execute(select(Advertiser.id).where(Advertiser.id == request.advertiser_id))).scalar_one_or_none()
        if not exists:
            raise HTTPException(status_code=404, detail="Advertiser not found")

    ad = Ad(
        advertiser_id=request.advertiser_id,
        owner_user_id=None if admin else user.id,
        slot=slot,
        status="approved" if admin else "pending",
        reviewed_at=datetime.utcnow() if admin else None,
        reviewed_by=user.id if admin else None,
        is_active=True,
        priority=0,
    )
    data = request.model_dump(exclude={"advertiser_id", "slot", "router_ids"})
    if not admin:
        data.pop("priority", None)  # ordering among paid ads is Bitwave's call
    _apply_fields(ad, data)
    _check_media_complete(ad)
    ad.router_ids = await _check_router_scope(db, user, request.router_ids)

    db.add(ad)
    await db.commit()
    await db.refresh(ad)
    await invalidate_ad_cache()
    logger.info("Ad #%s created by user %s (%s, %s)", ad.id, user.id, ad.slot, ad.status)
    return _serialize_manage(ad)


@router.put("/api/ads/{ad_id}")
async def update_ad(
    ad_id: int,
    request: AdUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    ad = await _load_owned_ad(db, user, ad_id)
    admin = _is_admin(user)

    data = request.model_dump(exclude_unset=True)
    if "advertiser_id" in data:
        advertiser_id = data.pop("advertiser_id")
        if not admin or ad.owner_user_id is not None:
            raise HTTPException(status_code=400, detail="Only Bitwave ads can be linked to an advertiser")
        if advertiser_id is not None:
            found = (await db.execute(select(Advertiser.id).where(Advertiser.id == advertiser_id))).scalar_one_or_none()
            if not found:
                raise HTTPException(status_code=404, detail="Advertiser not found")
        ad.advertiser_id = advertiser_id
    slot = data.pop("slot", None)
    if slot is not None:
        allowed = ("platform",) if ad.owner_user_id is None else ("house", "reseller")
        ad.slot = _check_choice(slot, allowed, "slot")
    if "router_ids" in data:
        ad.router_ids = await _check_router_scope(db, user, data.pop("router_ids"))
    if not admin:
        data.pop("priority", None)
    is_active = data.pop("is_active", None)

    before = {f: getattr(ad, f) for f in _REVIEWED_FIELDS}
    _apply_fields(ad, data)
    _check_media_complete(ad)
    if is_active is not None:
        ad.is_active = bool(is_active)

    # A reseller changing what customers see goes back to the review queue.
    # Compared by value, so re-saving the form unchanged keeps it live.
    changed = any(getattr(ad, f) != before[f] for f in _REVIEWED_FIELDS)
    if not admin and changed and ad.status != "pending":
        ad.status = "pending"
        ad.review_note = None
        ad.reviewed_at = None
        ad.reviewed_by = None

    await db.commit()
    await db.refresh(ad)
    await invalidate_ad_cache()
    totals = await _event_totals(db, [ad.id])
    names = await _owner_names(db, [ad.owner_user_id])
    return _serialize_manage(ad, totals.get(ad.id), names.get(ad.owner_user_id))


@router.delete("/api/ads/{ad_id}")
async def delete_ad(
    ad_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ad = await _load_owned_ad(db, user, ad_id)
    # Legacy click rows reference the ad; ad_events have no FK and are kept
    # so past reports still add up.
    await db.execute(delete(AdClick).where(AdClick.ad_id == ad_id))
    await db.delete(ad)
    await db.commit()
    await invalidate_ad_cache()
    logger.info("Ad #%s deleted by user %s", ad_id, user.id)
    return {"message": f"Ad #{ad_id} deleted successfully"}


@router.post("/api/ads/{ad_id}/review")
async def review_ad(
    ad_id: int,
    request: AdReviewRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    _require_admin(user)
    ad = await _load_owned_ad(db, user, ad_id)
    action = _check_choice(request.action, ("approve", "reject"), "action")
    note = (request.note or "").strip()[:300] or None
    if action == "reject" and not note:
        raise HTTPException(status_code=400, detail="Say why the ad was rejected, so the reseller can fix it")
    ad.status = "approved" if action == "approve" else "rejected"
    ad.review_note = note
    ad.reviewed_at = datetime.utcnow()
    ad.reviewed_by = user.id
    await db.commit()
    await db.refresh(ad)
    await invalidate_ad_cache()
    logger.info("Ad #%s %sd by admin %s", ad_id, action, user.id)
    return _serialize_manage(ad)


@router.post("/api/ads/media/upload-url")
async def create_media_upload(
    request: MediaUploadRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """A presigned PUT for one photo or video. The browser uploads straight
    to storage, then saves the returned public_url on the ad."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    try:
        ticket = ad_media.create_upload(
            request.content_type, request.size,
            owner_label="bitwave" if _is_admin(user) else f"r{user.id}",
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


# ========================================
# Public: the portal's legacy feed and its view/tap beacons
# ========================================

@router.get("/api/ads")
async def get_ads(
    page: int = 1,
    per_page: int = 20,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Network-wide Bitwave ads, for portals whose combined /public/portal
    call failed. Router-scoped and reseller ads only come through that call."""
    ads = await network_ads(db, limit=100)
    if category:
        ads = [a for a in ads if a.get("category") == category]
    page, per_page = max(page, 1), min(max(per_page, 1), 50)
    total = len(ads)
    chunk = ads[(page - 1) * per_page: page * per_page]
    for a in chunk:
        a["whatsapp_number"] = a.get("whatsapp_number") or a.get("phone_number")
    return {
        "ads": chunk,
        "pagination": {
            "page": page, "per_page": per_page, "total": total,
            "total_pages": (total + per_page - 1) // per_page,
        },
    }


async def _live_ad_ids(db: AsyncSession) -> set:
    return {a["id"] for a in await get_live_ads_cached(db)}


@router.post("/api/ads/click")
async def record_ad_click(
    request: AdClickRequest,
    db: AsyncSession = Depends(get_db),
):
    """A tap on an ad's button. Counted once per ad, placement, button and
    device per day. Always answers success: the portal must never show an
    error for a beacon."""
    click_type = (request.click_type or "").lower()
    rows = []
    if click_type in CLICK_TYPES:
        live = await _live_ad_ids(db)
        await db.commit()  # release the request's connection before writing
        rows = build_event_rows(
            ad_ids=[request.ad_id], event_type="click", click_type=click_type,
            placement=request.placement or "local", live_ad_ids=live,
            device_key=device_key_for(request.mac_address, request.device_id, request.session_id),
            router_identity=request.router_identity,
        )
    try:
        await record_ad_events(rows)
    except Exception as e:  # a beacon must never fail the portal
        logger.warning("Ad click not recorded: %s", e)
    return {"success": True, "message": "Click recorded"}


@router.post("/api/ads/impression")
async def record_ad_impression(
    request: AdImpressionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Ads that were on screen. Counted once per ad, placement and device per day."""
    live = await _live_ad_ids(db)
    await db.commit()
    rows = build_event_rows(
        ad_ids=request.ad_ids or [], event_type="impression",
        placement=request.placement or "showcase_carousel", live_ad_ids=live,
        device_key=device_key_for(request.mac_address, request.device_id, request.session_id),
        router_identity=request.router_identity,
    )
    try:
        await record_ad_events(rows)
    except Exception as e:
        logger.warning("Ad impression not recorded: %s", e)
    return {"success": True, "message": f"Impression recorded for {len(rows)} ads"}


# ========================================
# Stats (signed in; resellers see their own ads only)
# ========================================

@router.get("/api/ads/analytics")
async def get_ads_analytics(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    days = min(max(days, 1), 365)
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    now = datetime.utcnow()

    ads_q = select(Ad.id)
    if not _is_admin(user):
        ads_q = ads_q.where(Ad.owner_user_id == user.id)
    ad_ids = list((await db.execute(ads_q)).scalars().all())
    active_q = ads_q.where(
        Ad.is_active == True, Ad.status == "approved",  # noqa: E712
        (Ad.expires_at == None) | (Ad.expires_at > now),  # noqa: E711
    )
    active_ads = len((await db.execute(active_q)).scalars().all())

    by_type, by_placement, per_ad = {}, {}, {}
    if ad_ids:
        rows = (await db.execute(
            select(AdEvent.ad_id, AdEvent.event_type, AdEvent.click_type, AdEvent.placement, func.count())
            .where(AdEvent.ad_id.in_(ad_ids), AdEvent.day >= since)
            .group_by(AdEvent.ad_id, AdEvent.event_type, AdEvent.click_type, AdEvent.placement)
        )).all()
        for ad_id, event_type, click_type, placement, n in rows:
            per_ad.setdefault(ad_id, {"impression": 0, "click": 0})[event_type] += n
            slot = by_placement.setdefault(placement, {"impressions": 0, "clicks": 0})
            slot["impressions" if event_type == "impression" else "clicks"] += n
            if event_type == "click":
                by_type[click_type] = by_type.get(click_type, 0) + n

    top_ids = sorted(per_ad, key=lambda i: per_ad[i]["click"], reverse=True)[:5]
    titles = {}
    if top_ids:
        titles = dict((await db.execute(select(Ad.id, Ad.title).where(Ad.id.in_(top_ids)))).all())
    return {
        "period_days": days,
        "total_ads": len(ad_ids),
        "active_ads": active_ads,
        "total_clicks": sum(v["click"] for v in per_ad.values()),
        "clicks_by_type": {ct: by_type.get(ct, 0) for ct in CLICK_TYPES},
        "total_impressions": sum(v["impression"] for v in per_ad.values()),
        "by_placement": by_placement,
        "top_ads_by_clicks": [
            {"id": i, "title": titles.get(i), "clicks_count": per_ad[i]["click"], "views_count": per_ad[i]["impression"]}
            for i in top_ids
        ],
    }


@router.get("/api/ads/{ad_id}/stats")
async def get_ad_stats(
    ad_id: int,
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Daily unique views and taps for one ad, split by placement."""
    user = await get_current_user(token, db)
    ad = await _load_owned_ad(db, user, ad_id)
    days = min(max(days, 1), 365)
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = (await db.execute(
        select(AdEvent.day, AdEvent.placement, AdEvent.event_type, func.count())
        .where(AdEvent.ad_id == ad.id, AdEvent.day >= since)
        .group_by(AdEvent.day, AdEvent.placement, AdEvent.event_type)
        .order_by(AdEvent.day)
    )).all()
    daily: dict = {}
    by_placement: dict = {}
    for day, placement, event_type, n in rows:
        key = "impressions" if event_type == "impression" else "clicks"
        daily.setdefault(day, {"day": day, "impressions": 0, "clicks": 0})[key] += n
        by_placement.setdefault(placement, {"impressions": 0, "clicks": 0})[key] += n
    return {
        "ad_id": ad.id,
        "period_days": days,
        "impressions": sum(d["impressions"] for d in daily.values()),
        "clicks": sum(d["clicks"] for d in daily.values()),
        "by_placement": by_placement,
        "daily": list(daily.values()),
    }


async def _event_page(db, ad_id, event_type, page, per_page, click_type=None):
    q = select(AdEvent).where(AdEvent.ad_id == ad_id, AdEvent.event_type == event_type)
    if click_type:
        q = q.where(AdEvent.click_type == click_type.lower())
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar() or 0
    page, per_page = max(page, 1), min(max(per_page, 1), 200)
    events = (await db.execute(
        q.order_by(AdEvent.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()
    return events, {"page": page, "per_page": per_page, "total": total}


@router.get("/api/ads/{ad_id}/clicks")
async def get_ad_clicks(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    click_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ad = await _load_owned_ad(db, user, ad_id)
    events, pagination = await _event_page(db, ad.id, "click", page, per_page, click_type)
    return {
        "ad_id": ad.id,
        "ad_title": ad.title,
        "clicks": [
            {
                "id": e.id,
                "click_type": e.click_type,
                "placement": e.placement,
                "device_id": e.device_key,
                "mac_address": e.device_key if ":" in e.device_key else None,
                "session_id": None,
                "router_identity": e.router_identity,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "pagination": pagination,
    }


@router.get("/api/ads/{ad_id}/impressions")
async def get_ad_impressions(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    user = await get_current_user(token, db)
    ad = await _load_owned_ad(db, user, ad_id)
    events, pagination = await _event_page(db, ad.id, "impression", page, per_page)
    return {
        "ad_id": ad.id,
        "ad_title": ad.title,
        "impressions": [
            {
                "id": e.id,
                "device_id": e.device_key,
                "session_id": None,
                "placement": e.placement,
                "router_identity": e.router_identity,
                "ad_ids": [e.ad_id],
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "pagination": pagination,
    }

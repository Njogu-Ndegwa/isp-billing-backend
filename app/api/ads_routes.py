from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete, cast, String
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Ad, AdClick, AdImpression, AdClickType, Advertiser, AdBadgeType
from app.services.auth import verify_token, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ads"])


# ========================================
# Pydantic Models
# ========================================

class AdClickRequest(BaseModel):
    ad_id: int
    click_type: str  # "view_details", "call", "whatsapp"
    device_id: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    referrer: Optional[str] = None
    mac_address: Optional[str] = None

class AdImpressionRequest(BaseModel):
    ad_ids: list[int]
    device_id: Optional[str] = None
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    placement: Optional[str] = None

class AdvertiserCreateRequest(BaseModel):
    name: str
    business_name: Optional[str] = None
    phone_number: str
    email: Optional[str] = None

class AdCreateRequest(BaseModel):
    advertiser_id: int
    title: str
    description: Optional[str] = None
    image_url: str
    seller_name: str
    seller_location: Optional[str] = None
    phone_number: str
    whatsapp_number: Optional[str] = None
    price: Optional[str] = None
    price_value: Optional[float] = None
    badge_type: Optional[str] = None  # "hot", "new", "sale"
    badge_text: Optional[str] = None
    category: Optional[str] = None
    priority: int = 0
    expires_at: Optional[str] = None  # ISO datetime string


class AdUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    seller_name: Optional[str] = None
    seller_location: Optional[str] = None
    phone_number: Optional[str] = None
    whatsapp_number: Optional[str] = None
    price: Optional[str] = None
    price_value: Optional[float] = None
    badge_type: Optional[str] = None  # "hot", "new", "sale", or null to clear
    badge_text: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[int] = None
    expires_at: Optional[str] = None  # ISO datetime string
    is_active: Optional[bool] = None


# ========================================
# Advertiser Endpoints
# ========================================

@router.post("/api/advertisers")
async def create_advertiser(
    request: AdvertiserCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new advertiser."""
    await get_current_user(token, db)
    try:
        advertiser = Advertiser(
            name=request.name,
            business_name=request.business_name,
            phone_number=request.phone_number,
            email=request.email
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
            "created_at": advertiser.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating advertiser: {e}")
        raise HTTPException(status_code=500, detail="Failed to create advertiser")


@router.get("/api/advertisers")
async def get_advertisers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """List all advertisers."""
    await get_current_user(token, db)
    result = await db.execute(select(Advertiser).order_by(Advertiser.created_at.desc()))
    advertisers = result.scalars().all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "business_name": a.business_name,
            "phone_number": a.phone_number,
            "email": a.email,
            "is_active": a.is_active,
            "created_at": a.created_at.isoformat()
        }
        for a in advertisers
    ]


# ========================================
# Ad CRUD Endpoints (Auth Required)
# ========================================

@router.post("/api/ads")
async def create_ad(
    request: AdCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new ad."""
    await get_current_user(token, db)
    try:
        # Validate advertiser exists
        adv_result = await db.execute(select(Advertiser).where(Advertiser.id == request.advertiser_id))
        if not adv_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Advertiser not found")
        
        # Parse badge_type
        badge_type = None
        if request.badge_type:
            badge_map = {"hot": AdBadgeType.HOT, "new": AdBadgeType.NEW, "sale": AdBadgeType.SALE}
            badge_type = badge_map.get(request.badge_type.lower())
        
        # Parse expires_at (strip timezone for naive datetime)
        expires_at = None
        if request.expires_at:
            dt = datetime.fromisoformat(request.expires_at.replace("Z", "+00:00"))
            expires_at = dt.replace(tzinfo=None) if dt.tzinfo else dt
        
        ad = Ad(
            advertiser_id=request.advertiser_id,
            title=request.title,
            description=request.description,
            image_url=request.image_url,
            seller_name=request.seller_name,
            seller_location=request.seller_location,
            phone_number=request.phone_number,
            whatsapp_number=request.whatsapp_number,
            price=request.price,
            price_value=request.price_value,
            badge_type=badge_type,
            badge_text=request.badge_text,
            category=request.category,
            priority=request.priority,
            expires_at=expires_at
        )
        db.add(ad)
        await db.commit()
        await db.refresh(ad)
        
        logger.info(f"Ad created: #{ad.id} - {ad.title}")
        
        return {
            "id": ad.id,
            "title": ad.title,
            "advertiser_id": ad.advertiser_id,
            "created_at": ad.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating ad: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create ad: {str(e)}")


@router.delete("/api/ads/{ad_id}")
async def delete_ad(
    ad_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Delete an ad by ID (cascades to clicks and impressions)."""
    await get_current_user(token, db)
    try:
        result = await db.execute(select(Ad).where(Ad.id == ad_id))
        ad = result.scalar_one_or_none()
        
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        # Delete related clicks first
        await db.execute(delete(AdClick).where(AdClick.ad_id == ad_id))
        
        await db.delete(ad)
        await db.commit()
        
        logger.info(f"Ad deleted: #{ad_id}")
        
        return {"message": f"Ad #{ad_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting ad: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete ad: {str(e)}")


@router.put("/api/ads/{ad_id}")
async def update_ad(
    ad_id: int,
    request: AdUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update an ad by ID."""
    await get_current_user(token, db)
    try:
        result = await db.execute(select(Ad).where(Ad.id == ad_id))
        ad = result.scalar_one_or_none()
        
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        # Update fields if provided
        if request.title is not None:
            ad.title = request.title
        if request.description is not None:
            ad.description = request.description
        if request.image_url is not None:
            ad.image_url = request.image_url
        if request.seller_name is not None:
            ad.seller_name = request.seller_name
        if request.seller_location is not None:
            ad.seller_location = request.seller_location
        if request.phone_number is not None:
            ad.phone_number = request.phone_number
        if request.whatsapp_number is not None:
            ad.whatsapp_number = request.whatsapp_number
        if request.price is not None:
            ad.price = request.price
        if request.price_value is not None:
            ad.price_value = request.price_value
        if request.badge_type is not None:
            badge_map = {"hot": AdBadgeType.HOT, "new": AdBadgeType.NEW, "sale": AdBadgeType.SALE}
            ad.badge_type = badge_map.get(request.badge_type.lower())
        if request.badge_text is not None:
            ad.badge_text = request.badge_text
        if request.category is not None:
            ad.category = request.category
        if request.priority is not None:
            ad.priority = request.priority
        if request.expires_at is not None:
            dt = datetime.fromisoformat(request.expires_at.replace("Z", "+00:00"))
            ad.expires_at = dt.replace(tzinfo=None) if dt.tzinfo else dt
        if request.is_active is not None:
            ad.is_active = request.is_active
        
        await db.commit()
        await db.refresh(ad)
        
        logger.info(f"Ad updated: #{ad_id}")
        
        return {
            "id": ad.id,
            "title": ad.title,
            "is_active": ad.is_active,
            "updated_at": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating ad: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update ad: {str(e)}")


# ========================================
# Public Ad Endpoints (No Auth)
# ========================================

@router.get("/api/ads")
async def get_ads(
    page: int = 1,
    per_page: int = 20,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Fetch active ads (public, no auth required).
    Used by the captive portal to display ads to guests.
    Returns paginated ads sorted by priority (highest first), then by created_at.
    """
    try:
        now = datetime.utcnow()
        
        # Build query for active, non-expired ads
        query = select(Ad).where(
            Ad.is_active == True,
            (Ad.expires_at == None) | (Ad.expires_at > now)
        )
        
        if category:
            query = query.where(Ad.category == category)
        
        # Order by priority (desc) then created_at (desc)
        query = query.order_by(Ad.priority.desc(), Ad.created_at.desc())
        
        # Count total
        count_query = select(Ad).where(
            Ad.is_active == True,
            (Ad.expires_at == None) | (Ad.expires_at > now)
        )
        if category:
            count_query = count_query.where(Ad.category == category)
        
        count_result = await db.execute(select(func.count()).select_from(count_query.subquery()))
        total = count_result.scalar() or 0
        
        # Paginate
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        result = await db.execute(query)
        ads = result.scalars().all()
        
        # Format response
        ads_data = []
        for ad in ads:
            ads_data.append({
                "id": ad.id,
                "title": ad.title,
                "description": ad.description,
                "image_url": ad.image_url,
                "seller_name": ad.seller_name,
                "seller_location": ad.seller_location,
                "phone_number": ad.phone_number,
                "whatsapp_number": ad.whatsapp_number or ad.phone_number,
                "price": ad.price,
                "price_value": ad.price_value,
                "badge_type": ad.badge_type.value if ad.badge_type else None,
                "badge_text": ad.badge_text,
                "category": ad.category,
                "is_active": ad.is_active,
                "priority": ad.priority,
                "views_count": ad.views_count,
                "clicks_count": ad.clicks_count,
                "created_at": ad.created_at.isoformat() if ad.created_at else None,
                "expires_at": ad.expires_at.isoformat() if ad.expires_at else None,
                "advertiser_id": ad.advertiser_id
            })
        
        return {
            "ads": ads_data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page if per_page > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Error fetching ads: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch ads")


@router.post("/api/ads/click")
async def record_ad_click(
    request: AdClickRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Record when a user clicks/interacts with an ad.
    click_type: "view_details", "call", "whatsapp"
    """
    try:
        # Validate ad exists
        ad_result = await db.execute(select(Ad).where(Ad.id == request.ad_id))
        ad = ad_result.scalar_one_or_none()
        
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        # Map click_type string to enum
        click_type_map = {
            "view_details": AdClickType.VIEW_DETAILS,
            "call": AdClickType.CALL,
            "whatsapp": AdClickType.WHATSAPP
        }
        click_type = click_type_map.get(request.click_type.lower())
        if not click_type:
            raise HTTPException(status_code=400, detail="Invalid click_type")
        
        # Create click record
        ad_click = AdClick(
            ad_id=request.ad_id,
            click_type=click_type,
            device_id=request.device_id,
            user_agent=request.user_agent,
            session_id=request.session_id,
            referrer=request.referrer,
            mac_address=request.mac_address
        )
        db.add(ad_click)
        
        # Increment ad clicks_count
        ad.clicks_count = (ad.clicks_count or 0) + 1
        
        await db.commit()
        await db.refresh(ad_click)
        
        logger.info(f"📊 Ad click recorded: Ad #{request.ad_id}, Type: {request.click_type}")
        
        return {
            "success": True,
            "click_id": f"click_{ad_click.id}",
            "message": "Click recorded"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error recording ad click: {e}")
        raise HTTPException(status_code=500, detail="Failed to record click")


@router.post("/api/ads/impression")
async def record_ad_impression(
    request: AdImpressionRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Record when ads are displayed to a user.
    """
    try:
        if not request.ad_ids:
            raise HTTPException(status_code=400, detail="ad_ids cannot be empty")
        
        # Create impression record
        impression = AdImpression(
            ad_ids=request.ad_ids,
            device_id=request.device_id,
            session_id=request.session_id,
            placement=request.placement
        )
        db.add(impression)
        
        # Increment views_count for each ad
        for ad_id in request.ad_ids:
            ad_result = await db.execute(select(Ad).where(Ad.id == ad_id))
            ad = ad_result.scalar_one_or_none()
            if ad:
                ad.views_count = (ad.views_count or 0) + 1
        
        await db.commit()
        
        logger.info(f"📊 Ad impression recorded: {len(request.ad_ids)} ads")
        
        return {
            "success": True,
            "message": f"Impression recorded for {len(request.ad_ids)} ads"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error recording ad impression: {e}")
        raise HTTPException(status_code=500, detail="Failed to record impression")


# ========================================
# Ad Analytics Endpoints (Auth Required)
# ========================================

@router.get("/api/ads/{ad_id}/clicks")
async def get_ad_clicks(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    click_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get click records for a specific ad."""
    await get_current_user(token, db)
    try:
        # Verify ad exists
        ad_result = await db.execute(select(Ad).where(Ad.id == ad_id))
        ad = ad_result.scalar_one_or_none()
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        query = select(AdClick).where(AdClick.ad_id == ad_id)
        
        if click_type:
            click_type_map = {"view_details": AdClickType.VIEW_DETAILS, "call": AdClickType.CALL, "whatsapp": AdClickType.WHATSAPP}
            ct = click_type_map.get(click_type.lower())
            if ct:
                query = query.where(AdClick.click_type == ct)
        
        query = query.order_by(AdClick.created_at.desc())
        
        # Count
        count_result = await db.execute(select(func.count()).select_from(select(AdClick).where(AdClick.ad_id == ad_id).subquery()))
        total = count_result.scalar() or 0
        
        # Paginate
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        result = await db.execute(query)
        clicks = result.scalars().all()
        
        return {
            "ad_id": ad_id,
            "ad_title": ad.title,
            "clicks": [
                {
                    "id": c.id,
                    "click_type": c.click_type.value if c.click_type else None,
                    "device_id": c.device_id,
                    "mac_address": c.mac_address,
                    "session_id": c.session_id,
                    "created_at": c.created_at.isoformat() if c.created_at else None
                }
                for c in clicks
            ],
            "pagination": {"page": page, "per_page": per_page, "total": total}
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching ad clicks: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch clicks")


@router.get("/api/ads/{ad_id}/impressions")
async def get_ad_impressions(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get impression records that include this ad."""
    await get_current_user(token, db)
    try:
        # Verify ad exists
        ad_result = await db.execute(select(Ad).where(Ad.id == ad_id))
        ad = ad_result.scalar_one_or_none()
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        # Query impressions where ad_id is in the ad_ids JSON array
        query = select(AdImpression).where(
            AdImpression.ad_ids.contains([ad_id])
        ).order_by(AdImpression.created_at.desc())
        
        # Count
        count_q = select(func.count()).select_from(
            select(AdImpression).where(AdImpression.ad_ids.contains([ad_id])).subquery()
        )
        count_result = await db.execute(count_q)
        total = count_result.scalar() or 0
        
        # Paginate
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        result = await db.execute(query)
        impressions = result.scalars().all()
        
        return {
            "ad_id": ad_id,
            "ad_title": ad.title,
            "impressions": [
                {
                    "id": i.id,
                    "device_id": i.device_id,
                    "session_id": i.session_id,
                    "placement": i.placement,
                    "ad_ids": i.ad_ids,
                    "created_at": i.created_at.isoformat() if i.created_at else None
                }
                for i in impressions
            ],
            "pagination": {"page": page, "per_page": per_page, "total": total}
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching ad impressions: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch impressions")


@router.get("/api/ads/analytics")
async def get_ads_analytics(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get aggregated analytics for all ads."""
    await get_current_user(token, db)
    try:
        now = datetime.utcnow()
        since = now - timedelta(days=days)
        
        # Total ads
        ads_result = await db.execute(select(func.count()).select_from(Ad))
        total_ads = ads_result.scalar() or 0
        
        # Active ads
        active_result = await db.execute(
            select(func.count()).select_from(
                select(Ad).where(Ad.is_active == True, (Ad.expires_at == None) | (Ad.expires_at > now)).subquery()
            )
        )
        active_ads = active_result.scalar() or 0
        
        # Total clicks in period
        clicks_result = await db.execute(
            select(func.count()).select_from(
                select(AdClick).where(AdClick.created_at >= since).subquery()
            )
        )
        total_clicks = clicks_result.scalar() or 0
        
        # Clicks by type
        clicks_by_type = {}
        for ct in AdClickType:
            ct_result = await db.execute(
                select(func.count()).select_from(
                    select(AdClick).where(AdClick.created_at >= since, AdClick.click_type == ct).subquery()
                )
            )
            clicks_by_type[ct.value] = ct_result.scalar() or 0
        
        # Total impressions in period
        impressions_result = await db.execute(
            select(func.count()).select_from(
                select(AdImpression).where(AdImpression.created_at >= since).subquery()
            )
        )
        total_impressions = impressions_result.scalar() or 0
        
        # Top 5 ads by clicks
        top_ads_result = await db.execute(
            select(Ad).order_by(Ad.clicks_count.desc()).limit(5)
        )
        top_ads = top_ads_result.scalars().all()
        
        return {
            "period_days": days,
            "total_ads": total_ads,
            "active_ads": active_ads,
            "total_clicks": total_clicks,
            "clicks_by_type": clicks_by_type,
            "total_impressions": total_impressions,
            "top_ads_by_clicks": [
                {"id": a.id, "title": a.title, "clicks_count": a.clicks_count, "views_count": a.views_count}
                for a in top_ads
            ]
        }
    except Exception as e:
        logger.error(f"Error fetching ads analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch analytics")

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Customer, CustomerRating, CustomerStatus
from app.services.auth import verify_token, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ratings"])


class UpdateLocationRequest(BaseModel):
    latitude: float
    longitude: float

class SubmitRatingRequest(BaseModel):
    phone: str  # Identify customer by phone number
    rating: int  # 1-5 stars
    comment: Optional[str] = None
    service_quality: Optional[int] = None  # 1-5
    support_rating: Optional[int] = None  # 1-5
    value_for_money: Optional[int] = None  # 1-5
    latitude: Optional[float] = None  # Optional location at time of rating
    longitude: Optional[float] = None

class CaptureLocationRequest(BaseModel):
    phone: str  # Identify customer by phone number
    latitude: float
    longitude: float


@router.post("/api/customers/{customer_id}/location")
async def update_customer_location(
    customer_id: int,
    request: UpdateLocationRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Update customer location (lat/long) - for use when staff/technician is at customer premises
    """
    try:
        user = await get_current_user(token, db)
        stmt = select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        customer.latitude = request.latitude
        customer.longitude = request.longitude
        customer.location_captured_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "success": True,
            "message": "Location updated successfully",
            "customer_id": customer_id,
            "latitude": request.latitude,
            "longitude": request.longitude
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating customer location: {e}")
        raise HTTPException(status_code=500, detail="Failed to update location")


@router.post("/api/customers/location/by-phone")
async def capture_location_by_phone(
    request: CaptureLocationRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Capture customer location by phone number.
    Works for both existing customers and new phone numbers.
    For new numbers, creates a customer record with the location.
    """
    try:
        # Find customer by phone number (get most recent)
        stmt = select(Customer).where(Customer.phone == request.phone).order_by(Customer.created_at.desc())
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        is_new_customer = False
        
        if not customer:
            # Create new customer with just phone and location
            customer = Customer(
                phone=request.phone,
                latitude=request.latitude,
                longitude=request.longitude,
                location_captured_at=datetime.utcnow()
            )
            db.add(customer)
            is_new_customer = True
        else:
            # Update existing customer's location
            customer.latitude = request.latitude
            customer.longitude = request.longitude
            customer.location_captured_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(customer)
        
        return {
            "success": True,
            "message": "Location captured successfully",
            "customer_id": customer.id,
            "customer_name": customer.name,
            "latitude": request.latitude,
            "longitude": request.longitude,
            "is_new_customer": is_new_customer
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error capturing location by phone: {e}")
        raise HTTPException(status_code=500, detail="Failed to capture location")


@router.post("/api/ratings/submit")
async def submit_customer_rating(
    request: SubmitRatingRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a rating from anyone - identified by phone number.
    Works for both existing customers and new phone numbers.
    Call this after a purchase or service interaction to collect feedback.
    """
    try:
        # Validate rating values
        if not 1 <= request.rating <= 5:
            raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
        
        for field_name, value in [
            ("service_quality", request.service_quality),
            ("support_rating", request.support_rating),
            ("value_for_money", request.value_for_money)
        ]:
            if value is not None and not 1 <= value <= 5:
                raise HTTPException(status_code=400, detail=f"{field_name} must be between 1 and 5")
        
        # Try to find customer by phone number (optional - ratings work for non-customers too)
        stmt = select(Customer).where(Customer.phone == request.phone).order_by(Customer.created_at.desc())
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        # Use provided location, or fallback to customer's stored location if customer exists
        lat = request.latitude
        lng = request.longitude
        if customer and not lat:
            lat = customer.latitude
        if customer and not lng:
            lng = customer.longitude
        
        # Create rating record (customer_id can be None for non-customers)
        rating = CustomerRating(
            customer_id=customer.id if customer else None,
            phone=request.phone,
            rating=request.rating,
            comment=request.comment,
            service_quality=request.service_quality,
            support_rating=request.support_rating,
            value_for_money=request.value_for_money,
            latitude=lat,
            longitude=lng
        )
        
        db.add(rating)
        await db.commit()
        await db.refresh(rating)
        
        return {
            "success": True,
            "message": "Thank you for your feedback!",
            "rating_id": rating.id,
            "customer_id": customer.id if customer else None,
            "is_existing_customer": customer is not None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting rating: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit rating")


@router.get("/api/ratings")
async def get_ratings(
    include_location: bool = True,
    min_rating: Optional[int] = None,
    max_rating: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get all customer ratings with optional location data.
    Filter by rating range and paginate results.
    Includes ratings from non-customers (anonymous ratings by phone).
    """
    try:
        user = await get_current_user(token, db)
        stmt = (
            select(CustomerRating)
            .outerjoin(Customer, CustomerRating.customer_id == Customer.id)
            .order_by(CustomerRating.created_at.desc())
        )
        
        # Filter by authenticated user's ID
        stmt = stmt.where(
            or_(
                Customer.user_id == user.id,
                CustomerRating.customer_id.is_(None),
                Customer.user_id.is_(None)
            )
        )
        
        if min_rating:
            stmt = stmt.where(CustomerRating.rating >= min_rating)
        if max_rating:
            stmt = stmt.where(CustomerRating.rating <= max_rating)
        
        stmt = stmt.offset(offset).limit(limit)
        
        result = await db.execute(stmt)
        ratings = result.scalars().all()
        
        # Get customer details
        response_data = []
        for r in ratings:
            customer = None
            if r.customer_id:
                customer_stmt = select(Customer).where(Customer.id == r.customer_id)
                customer_result = await db.execute(customer_stmt)
                customer = customer_result.scalar_one_or_none()
            
            rating_data = {
                "id": r.id,
                "customer_id": r.customer_id,
                "customer_name": customer.name if customer else None,
                "phone": r.phone,
                "rating": r.rating,
                "comment": r.comment,
                "service_quality": r.service_quality,
                "support_rating": r.support_rating,
                "value_for_money": r.value_for_money,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "is_anonymous": r.customer_id is None
            }
            
            if include_location:
                rating_data["latitude"] = r.latitude
                rating_data["longitude"] = r.longitude
            
            response_data.append(rating_data)
        
        return {
            "success": True,
            "count": len(response_data),
            "ratings": response_data
        }
    except Exception as e:
        logger.error(f"Error fetching ratings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch ratings")


@router.get("/api/ratings/summary")
async def get_ratings_summary(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get ratings summary with averages and distribution.
    Includes ratings from non-customers (anonymous ratings by phone).
    """
    try:
        user = await get_current_user(token, db)
        stmt = (
            select(CustomerRating)
            .outerjoin(Customer, CustomerRating.customer_id == Customer.id)
        )
        
        # Filter by authenticated user's ID
        stmt = stmt.where(
            or_(
                Customer.user_id == user.id,
                CustomerRating.customer_id.is_(None),
                    Customer.user_id.is_(None)
                )
            )
        
        result = await db.execute(stmt)
        ratings = result.scalars().all()
        
        if not ratings:
            return {
                "success": True,
                "total_ratings": 0,
                "average_rating": 0,
                "distribution": {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
            }
        
        total = len(ratings)
        avg_rating = sum(r.rating for r in ratings) / total
        avg_service = sum(r.service_quality for r in ratings if r.service_quality) / max(1, len([r for r in ratings if r.service_quality]))
        avg_support = sum(r.support_rating for r in ratings if r.support_rating) / max(1, len([r for r in ratings if r.support_rating]))
        avg_value = sum(r.value_for_money for r in ratings if r.value_for_money) / max(1, len([r for r in ratings if r.value_for_money]))
        
        distribution = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for r in ratings:
            distribution[r.rating] += 1
        
        return {
            "success": True,
            "total_ratings": total,
            "average_rating": round(avg_rating, 2),
            "average_service_quality": round(avg_service, 2),
            "average_support_rating": round(avg_support, 2),
            "average_value_for_money": round(avg_value, 2),
            "distribution": distribution
        }
    except Exception as e:
        logger.error(f"Error fetching ratings summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch summary")


@router.get("/api/customers/map")
async def get_customers_map_data(
    status: Optional[str] = None,
    with_ratings: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get all customers with location data for map visualization.
    Returns only customers that have latitude/longitude set.
    Optionally include their average rating.
    Includes customers without user_id (created via location capture).
    """
    try:
        user = await get_current_user(token, db)
        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan))
            .where(
                Customer.latitude.isnot(None),
                Customer.longitude.isnot(None)
            )
        )
        
        # Filter by authenticated user's ID
        stmt = stmt.where(
            or_(
                Customer.user_id == user.id,
                Customer.user_id.is_(None)
            )
        )
        
        if status:
            stmt = stmt.where(Customer.status == CustomerStatus(status))
        
        result = await db.execute(stmt)
        customers = result.scalars().all()
        
        map_data = []
        for c in customers:
            customer_data = {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "status": c.status.value if c.status else None,
                "plan_name": c.plan.name if c.plan else None,
                "latitude": c.latitude,
                "longitude": c.longitude,
                "location_captured_at": c.location_captured_at.isoformat() if c.location_captured_at else None,
                "has_user": c.user_id is not None
            }
            
            if with_ratings:
                # Get average rating for this customer
                rating_stmt = select(CustomerRating).where(CustomerRating.customer_id == c.id)
                rating_result = await db.execute(rating_stmt)
                ratings = rating_result.scalars().all()
                
                if ratings:
                    customer_data["average_rating"] = round(sum(r.rating for r in ratings) / len(ratings), 2)
                    customer_data["total_ratings"] = len(ratings)
                else:
                    customer_data["average_rating"] = None
                    customer_data["total_ratings"] = 0
            
            map_data.append(customer_data)
        
        return {
            "success": True,
            "total_customers": len(map_data),
            "customers": map_data
        }
    except Exception as e:
        logger.error(f"Error fetching map data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch map data")


@router.get("/api/ratings/by-location")
async def get_ratings_by_location(
    min_lat: Optional[float] = None,
    max_lat: Optional[float] = None,
    min_lng: Optional[float] = None,
    max_lng: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get ratings filtered by geographic area (bounding box).
    Useful for seeing ratings in specific locations/zones.
    Includes ratings from non-customers (anonymous ratings by phone).
    """
    try:
        user = await get_current_user(token, db)
        stmt = (
            select(CustomerRating)
            .outerjoin(Customer, CustomerRating.customer_id == Customer.id)
            .where(
                CustomerRating.latitude.isnot(None),
                CustomerRating.longitude.isnot(None)
            )
        )
        
        # Filter by authenticated user's ID
        stmt = stmt.where(
            or_(
                Customer.user_id == user.id,
                CustomerRating.customer_id.is_(None),
                Customer.user_id.is_(None)
            )
        )
        
        if min_lat is not None:
            stmt = stmt.where(CustomerRating.latitude >= min_lat)
        if max_lat is not None:
            stmt = stmt.where(CustomerRating.latitude <= max_lat)
        if min_lng is not None:
            stmt = stmt.where(CustomerRating.longitude >= min_lng)
        if max_lng is not None:
            stmt = stmt.where(CustomerRating.longitude <= max_lng)
        
        result = await db.execute(stmt)
        ratings = result.scalars().all()
        
        # Calculate area stats
        if ratings:
            avg_rating = sum(r.rating for r in ratings) / len(ratings)
        else:
            avg_rating = 0
        
        ratings_data = []
        for r in ratings:
            customer = None
            if r.customer_id:
                customer_stmt = select(Customer).where(Customer.id == r.customer_id)
                customer_result = await db.execute(customer_stmt)
                customer = customer_result.scalar_one_or_none()
            
            ratings_data.append({
                "id": r.id,
                "customer_name": customer.name if customer else None,
                "phone": r.phone,
                "rating": r.rating,
                "comment": r.comment,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "is_anonymous": r.customer_id is None
            })
        
        return {
            "success": True,
            "area_stats": {
                "total_ratings": len(ratings),
                "average_rating": round(avg_rating, 2),
                "bounds": {
                    "min_lat": min_lat,
                    "max_lat": max_lat,
                    "min_lng": min_lng,
                    "max_lng": max_lng
                }
            },
            "ratings": ratings_data
        }
    except Exception as e:
        logger.error(f"Error fetching ratings by location: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch ratings")

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Router, Customer, Plan, CustomerStatus
from app.services.auth import verify_token, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["customers"])


class CustomerRegisterRequest(BaseModel):
    name: str
    phone: str
    plan_id: int
    router_id: int
    mac_address: Optional[str] = None
    pppoe_username: Optional[str] = None
    pppoe_password: Optional[str] = None
    static_ip: Optional[str] = None


class UpdateLocationRequest(BaseModel):
    latitude: float
    longitude: float


@router.post("/api/customers/register")
async def register_customer_api(
    request: CustomerRegisterRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Register a new customer"""
    try:
        user = await get_current_user(token, db)
        
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id, Plan.user_id == user.id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Validate router exists
        router_stmt = select(Router).where(Router.id == request.router_id, Router.user_id == user.id)
        router_result = await db.execute(router_stmt)
        router_obj = router_result.scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        # Check if customer with MAC already exists
        if request.mac_address:
            existing_customer_stmt = select(Customer).where(Customer.mac_address == request.mac_address)
            existing_result = await db.execute(existing_customer_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Customer with this MAC address already exists")
        
        # Create customer
        customer = Customer(
            name=request.name,
            phone=request.phone,
            mac_address=request.mac_address,
            pppoe_username=request.pppoe_username,
            pppoe_password=request.pppoe_password,
            static_ip=request.static_ip,
            status=CustomerStatus.INACTIVE,
            plan_id=request.plan_id,
            user_id=user.id,
            router_id=request.router_id
        )
        
        db.add(customer)
        await db.commit()
        await db.refresh(customer)
        
        logger.info(f"Customer registered: {customer.id} by user {user.id}")
        
        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "pppoe_username": customer.pppoe_username,
            "static_ip": customer.static_ip,
            "status": customer.status.value,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "user_id": customer.user_id,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "created_at": customer.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering customer: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register customer: {str(e)}")


@router.get("/api/customers")
async def get_customers_api(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all customers for the authenticated user"""
    try:
        user = await get_current_user(token, db)
        
        stmt = select(Customer).where(Customer.user_id == user.id).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        )
        result = await db.execute(stmt)
        customers = result.scalars().all()
        
        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c in customers
        ]
    except Exception as e:
        logger.error(f"Error fetching customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch customers")


@router.get("/api/customers/active")
async def get_active_customers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all currently active guests"""
    try:
        user = await get_current_user(token, db)
        stmt = select(Customer).where(
            Customer.user_id == user.id,
            Customer.status == CustomerStatus.ACTIVE
        ).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).order_by(Customer.expiry)
        
        result = await db.execute(stmt)
        customers = result.scalars().all()
        
        now = datetime.utcnow()
        
        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "hours_remaining": (c.expiry - now).total_seconds() / 3600 if c.expiry and c.expiry > now else 0,
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c in customers
        ]
    except Exception as e:
        logger.error(f"Error fetching active customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch active customers")


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

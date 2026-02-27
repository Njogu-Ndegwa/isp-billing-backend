from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Router, Customer
from app.services.auth import verify_token, get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["routers"])


class RouterCreateRequest(BaseModel):
    name: str
    identity: Optional[str] = None
    ip_address: str
    username: str
    password: str
    port: int = 8728


class RouterIdentityUpdate(BaseModel):
    identity: str


@router.get("/api/routers")
async def get_routers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all routers for a user"""
    user = await get_current_user(token, db)
    stmt = select(Router).where(Router.user_id == user.id)
    result = await db.execute(stmt)
    routers = result.scalars().all()
    return [{"id": r.id, "name": r.name, "identity": r.identity, "ip_address": r.ip_address, "port": r.port, "auth_method": getattr(r, 'auth_method', 'DIRECT_API') or 'DIRECT_API'} for r in routers]


@router.post("/api/routers/create")
async def create_router_api(
    request: RouterCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new router"""
    try:
        user = await get_current_user(token, db)
        existing_router_stmt = select(Router).filter(
            Router.ip_address == request.ip_address,
            Router.user_id == user.id
        )
        existing_result = await db.execute(existing_router_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Router with this IP address already exists")
        
        router_obj = Router(
            user_id=user.id,
            name=request.name,
            identity=request.identity,
            ip_address=request.ip_address,
            username=request.username,
            password=request.password,
            port=request.port
        )
        
        db.add(router_obj)
        await db.commit()
        await db.refresh(router_obj)
        
        logger.info(f"Router created: {router_obj.id} by user {user.id}")
        
        return {
            "id": router_obj.id,
            "name": router_obj.name,
            "identity": router_obj.identity,
            "ip_address": router_obj.ip_address,
            "username": router_obj.username,
            "port": router_obj.port,
            "user_id": router_obj.user_id,
            "created_at": router_obj.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create router: {str(e)}")


@router.get("/api/routers/by-identity/{identity}")
async def get_router_by_identity(
    identity: str,
    db: AsyncSession = Depends(get_db)
):
    """Lookup router by MikroTik system identity (for frontend captive portal)"""
    stmt = select(Router).where(Router.identity == identity)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()
    
    if not router_obj:
        raise HTTPException(status_code=404, detail=f"Router with identity '{identity}' not found")
    
    return {
        "router_id": router_obj.id,
        "name": router_obj.name,
        "identity": router_obj.identity,
        "user_id": router_obj.user_id,
        "auth_method": getattr(router_obj, 'auth_method', 'DIRECT_API') or 'DIRECT_API'
    }


@router.put("/api/routers/{router_id}/identity")
async def update_router_identity(
    router_id: int,
    request: RouterIdentityUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update router's MikroTik system identity"""
    user = await get_current_user(token, db)
    stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
    result = await db.execute(stmt)
    router_obj = result.scalar_one_or_none()
    
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    
    existing_stmt = select(Router).where(Router.identity == request.identity, Router.id != router_id)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Identity already assigned to another router")
    
    router_obj.identity = request.identity
    await db.commit()
    
    return {
        "id": router_obj.id,
        "name": router_obj.name,
        "identity": router_obj.identity,
        "message": "Identity updated successfully"
    }


@router.put("/api/routers/{router_id}")
async def update_router(
    router_id: int,
    request: RouterCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update router details"""
    try:
        user = await get_current_user(token, db)
        stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        router_obj.name = request.name
        router_obj.ip_address = request.ip_address
        router_obj.username = request.username
        router_obj.password = request.password
        router_obj.port = request.port
        
        await db.commit()
        await db.refresh(router_obj)
        
        return {
            "id": router_obj.id,
            "name": router_obj.name,
            "ip_address": router_obj.ip_address,
            "username": router_obj.username,
            "port": router_obj.port,
            "user_id": router_obj.user_id,
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update router: {str(e)}")


@router.delete("/api/routers/{router_id}")
async def delete_router(
    router_id: int,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Delete a router.
    
    Args:
        router_id: ID of the router to delete
        force: If True, reassign customers to no router. If False, fail if customers exist.
    
    Returns:
        Success message with details
    """
    try:
        user = await get_current_user(token, db)
        stmt = select(Router).where(Router.id == router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        router_name = router_obj.name
        router_ip = router_obj.ip_address
        
        customer_count_stmt = select(func.count(Customer.id)).where(Customer.router_id == router_id)
        customer_count_result = await db.execute(customer_count_stmt)
        customer_count = customer_count_result.scalar() or 0
        
        if customer_count > 0:
            if not force:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Router has {customer_count} customer(s) assigned. Use force=true to reassign them to no router."
                )
            
            update_customers_stmt = (
                update(Customer)
                .where(Customer.router_id == router_id)
                .values(router_id=None)
            )
            await db.execute(update_customers_stmt)
            logger.info(f"Reassigned {customer_count} customers from router {router_name} to no router")
        
        await db.delete(router_obj)
        await db.commit()
        
        logger.info(f"Deleted router: {router_name} ({router_ip})")
        
        return {
            "success": True,
            "message": f"Router '{router_name}' deleted successfully",
            "router_id": router_id,
            "customers_reassigned": customer_count if force else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete router: {str(e)}")

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Router, Customer, CustomerStatus, ProvisioningLog, BandwidthSnapshot
from app.services.auth import verify_token, get_current_user
import logging
import asyncio

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
                    detail=f"Router has {customer_count} customer(s) assigned. Use force=true to delete them from the router."
                )
            
            # Fetch active customers to clean them off MikroTik
            active_customers_stmt = select(Customer).where(
                Customer.router_id == router_id,
                Customer.status == CustomerStatus.ACTIVE
            )
            active_result = await db.execute(active_customers_stmt)
            active_customers = active_result.scalars().all()
            
            # Remove each active customer from MikroTik
            mikrotik_cleaned = 0
            if active_customers:
                from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
                
                router_info = {
                    "ip": router_obj.ip_address,
                    "username": router_obj.username,
                    "password": router_obj.password,
                    "port": router_obj.port,
                    "name": router_obj.name
                }
                
                def _cleanup_router_users(r_info, customers_data):
                    api = MikroTikAPI(r_info["ip"], r_info["username"], r_info["password"], r_info["port"])
                    removed = 0
                    try:
                        if not api.connected:
                            return removed
                        for mac, username in customers_data:
                            try:
                                api.remove_hotspot_user(username)
                                api.remove_ip_binding(mac)
                                api.remove_simple_queue(mac)
                                removed += 1
                            except Exception as e:
                                logger.warning(f"Failed to clean up {mac} from router: {e}")
                    finally:
                        api.disconnect()
                    return removed
                
                customers_data = []
                for c in active_customers:
                    if c.mac_address:
                        normalized = normalize_mac_address(c.mac_address)
                        customers_data.append((normalized, normalized.replace(":", "")))
                
                try:
                    mikrotik_cleaned = await asyncio.to_thread(_cleanup_router_users, router_info, customers_data)
                    logger.info(f"Cleaned {mikrotik_cleaned} users from MikroTik router {router_name}")
                except Exception as e:
                    logger.warning(f"MikroTik cleanup failed for router {router_name}: {e}. Proceeding with DB cleanup.")
            
            # Set all customers on this router to INACTIVE and unassign
            update_customers_stmt = (
                update(Customer)
                .where(Customer.router_id == router_id)
                .values(router_id=None, status=CustomerStatus.INACTIVE)
            )
            await db.execute(update_customers_stmt)
            logger.info(f"Set {customer_count} customers from router {router_name} to INACTIVE")
        
        # Clean up related records that reference this router
        await db.execute(
            update(ProvisioningLog)
            .where(ProvisioningLog.router_id == router_id)
            .values(router_id=None)
        )
        await db.execute(
            update(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router_id)
            .values(router_id=None)
        )
        
        await db.delete(router_obj)
        await db.commit()
        
        logger.info(f"Deleted router: {router_name} ({router_ip})")
        
        return {
            "success": True,
            "message": f"Router '{router_name}' deleted successfully",
            "router_id": router_id,
            "customers_deactivated": customer_count if force else 0,
            "mikrotik_cleaned": mikrotik_cleaned if force and customer_count > 0 else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete router: {str(e)}")

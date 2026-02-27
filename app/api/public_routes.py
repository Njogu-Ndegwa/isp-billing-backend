from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from sqlalchemy.orm import selectinload
from typing import Dict, Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Router, Customer, Plan, Ad, CustomerStatus
from app.services.mikrotik_api import MikroTikAPI, validate_mac_address, normalize_mac_address
from app.services.router_helpers import get_router_by_id
from app.services.plan_cache import get_plans_cached
from app.config import settings

import logging
import asyncio
import hashlib

logger = logging.getLogger(__name__)

router = APIRouter(tags=["public"])


# ---------------------------------------------------------------------------
# Private sync helpers (run in thread pool to avoid blocking the event loop)
# ---------------------------------------------------------------------------

def _register_mac_on_mikrotik_sync(router_info: dict, registration_data: dict) -> dict:
    """
    Synchronous function to register MAC on MikroTik.
    Runs in thread pool to not block async event loop.
    CRITICAL: This is used during customer registration - must not block other customers!
    """
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connection_failed", "message": "Failed to connect to router"}
    
    try:
        normalized_mac = registration_data["normalized_mac"]
        username = registration_data["username"]
        router_name = router_info["name"]
        router_user_id = router_info["user_id"]
        
        # Check if MAC address is already registered
        existing_users = api.send_command("/ip/hotspot/user/print")
        if existing_users.get("success") and existing_users.get("data"):
            for user in existing_users["data"]:
                if user.get("name", "").upper() == username.upper():
                    return {"error": "already_registered", "message": "MAC address already registered"}
        
        # Prepare user arguments
        bandwidth_limit = registration_data.get("bandwidth_limit")
        profile_name = "default"
        if bandwidth_limit:
            rate_limit = api._parse_speed_to_mikrotik(bandwidth_limit)
            profile_name = f"plan_{rate_limit.replace('/', '_')}"
            api._ensure_hotspot_profile(profile_name, rate_limit)
        
        args = {
            "name": username,
            "password": username,
            "profile": profile_name,
            "disabled": "no",
            "comment": registration_data.get("comment", f"MAC: {normalized_mac} | Router: {router_name} | Guest")
        }
        
        if registration_data.get("time_limit"):
            args["limit-uptime"] = registration_data["time_limit"]
        
        # Create hotspot user
        result = api.send_command("/ip/hotspot/user/add", args)
        if "error" in result:
            return {"error": "user_creation_failed", "message": result["error"]}
        
        # Add IP binding for seamless access
        binding_args = {
            "mac-address": normalized_mac,
            "type": "bypassed",
            "comment": f"Auto-registered: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} | Router: {router_name} | Guest"
        }
        binding_result = api.send_command("/ip/hotspot/ip-binding/add", binding_args)
        if "error" in binding_result and "already exists" in binding_result.get("error", ""):
            bindings = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings.get("success") and bindings.get("data"):
                for b in bindings["data"]:
                    if normalize_mac_address(b.get("mac-address", "")) == normalized_mac:
                        api.send_command("/ip/hotspot/ip-binding/set", {
                            "numbers": b[".id"],
                            "type": "bypassed"
                        })
                        break
        
        # Handle bandwidth limit
        queue_result = None
        dhcp_lease_result = None
        assigned_ip = None
        
        if bandwidth_limit:
            mac_hash = int(hashlib.md5(normalized_mac.encode()).hexdigest()[:4], 16)
            assigned_ip = f"192.168.1.{100 + (mac_hash % 150)}"
            
            dhcp_lease_args = {
                "mac-address": normalized_mac,
                "address": assigned_ip,
                "server": "defconf",
                "comment": f"Auto-assigned for {username} | Router: {router_name} | Guest"
            }
            dhcp_lease_result = api.send_command("/ip/dhcp-server/lease/add", dhcp_lease_args)
            
            if dhcp_lease_result.get("success") and "error" not in dhcp_lease_result:
                queue_args = {
                    "name": f"queue_{username}",
                    "target": f"{assigned_ip}/32",
                    "max-limit": bandwidth_limit,
                    "comment": f"Bandwidth limit for {normalized_mac} | Router: {router_name} | Guest"
                }
                queue_result = api.send_command("/queue/simple/add", queue_args)
                
                if "error" in queue_result:
                    logger.warning(f"Failed to set bandwidth limit: {queue_result['error']}")
                    if dhcp_lease_result.get("data") and len(dhcp_lease_result["data"]) > 0:
                        lease_id = dhcp_lease_result["data"][0].get(".id")
                        if lease_id:
                            api.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease_id})
        
        logger.info(f"[THREAD] MAC {normalized_mac} registered on router {router_name}")
        
        return {
            "success": True,
            "assigned_ip": assigned_ip,
            "binding_created": binding_result.get("success", False) if binding_result else False,
            "queue_created": queue_result.get("success", False) if queue_result else False
        }
    finally:
        api.disconnect()


def _check_mac_status_sync(router_info: dict, normalized_mac: str, username: str, router_id: int) -> dict:
    """
    Synchronous function to check MAC status on MikroTik.
    Runs in thread pool to not block async event loop.
    """
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "Failed to connect", "router_name": router_info.get("name", "Unknown")}
    
    try:
        # Check if user exists
        existing_users = api.send_command("/ip/hotspot/user/print")
        user_found = False
        user_details = None

        if existing_users.get("success") and existing_users.get("data"):
            for user in existing_users["data"]:
                if user.get("name", "").upper() == username.upper():
                    user_found = True
                    user_details = {
                        "registered": True,
                        "username": user.get("name"),
                        "disabled": user.get("disabled") == "true",
                        "profile": user.get("profile"),
                        "comment": user.get("comment", ""),
                        "mac_address": normalized_mac,
                        "router_id": router_id
                    }
                    break

        if not user_found:
            return {
                "registered": False,
                "mac_address": normalized_mac,
                "router_id": router_id
            }

        # Check for active sessions
        active_sessions = api.send_command("/ip/hotspot/active/print")
        is_active = False
        session_info = None

        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                if session.get("user") == username:
                    is_active = True
                    session_info = {
                        "login_time": session.get("login-time"),
                        "uptime": session.get("uptime"),
                        "bytes_in": session.get("bytes-in"),
                        "bytes_out": session.get("bytes-out"),
                        "address": session.get("address")
                    }
                    break

        user_details["active_session"] = is_active
        if session_info:
            user_details["session_info"] = session_info

        return user_details
    finally:
        api.disconnect()


def _disconnect_user_session_sync(router_info: dict, username: str) -> dict:
    """Synchronous function to disconnect user session. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connection_failed"}
    
    try:
        active_sessions = api.send_command("/ip/hotspot/active/print")
        disconnected_sessions = 0

        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                if session.get("user") == username:
                    session_id = session.get(".id")
                    if session_id:
                        disconnect_result = api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                        if disconnect_result.get("success", True):
                            disconnected_sessions += 1

        return {"success": True, "disconnected_sessions": disconnected_sessions}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# MAC address registration endpoint (NO JWT REQUIRED - for guests)
@router.post("/api/clients/mac-register/{router_id}")
async def register_mac_address(
    router_id: int,
    registration: Dict[str, str],
    db: AsyncSession = Depends(get_db)
):
    """
    Register a MAC address for hotspot access.
    This endpoint is for guest users, so no authentication required.
    Router ID is used to associate the registration with the router owner.
    Runs MikroTik operations in thread pool to not block other requests.

    Expected payload:
    {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "time_limit": "24h" or "7d" (optional),
        "bandwidth_limit": "1M/2M" (optional)
    }
    """
    # First, verify the router exists and get its details
    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        logger.warning(f"Registration attempt on non-existent router ID: {router_id}")
        raise HTTPException(status_code=404, detail="Router not found")

    # Validate MAC address
    mac_address = registration.get("mac_address")
    if not mac_address or not validate_mac_address(mac_address):
        logger.warning(f"Invalid MAC address format: {mac_address}")
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    # Calculate expires_at before sending to thread
    expires_at = None
    comment = f"MAC: {normalized_mac} | Router: {router_obj.name} | Owner: {router_obj.user_id} | Guest"
    if registration.get("time_limit"):
        current_time = datetime.utcnow()
        time_limit = registration["time_limit"]
        
        if time_limit.endswith('m'):
            minutes = int(time_limit[:-1])
            expires_at = current_time + timedelta(minutes=minutes)
        elif time_limit.endswith('h'):
            hours = int(time_limit[:-1])
            expires_at = current_time + timedelta(hours=hours)
        elif time_limit.endswith('d'):
            days = int(time_limit[:-1])
            expires_at = current_time + timedelta(days=days)
        
        if expires_at:
            comment += f" | Expires: {expires_at.strftime('%Y-%m-%d %H:%M')}"

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name,
        "user_id": router_obj.user_id
    }
    
    registration_data = {
        "normalized_mac": normalized_mac,
        "username": username,
        "bandwidth_limit": registration.get("bandwidth_limit"),
        "time_limit": registration.get("time_limit"),
        "comment": comment
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_register_mac_on_mikrotik_sync, router_info, registration_data)
    
    # Handle errors from thread
    if result.get("error"):
        error_type = result["error"]
        error_message = result.get("message", "Unknown error")
        
        if error_type == "connection_failed":
            logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
            raise HTTPException(status_code=500, detail="Failed to connect to router")
        elif error_type == "already_registered":
            logger.warning(f"MAC address {normalized_mac} already registered on router {router_obj.name}")
            raise HTTPException(status_code=409, detail="MAC address already registered")
        elif error_type == "user_creation_failed":
            logger.error(f"Failed to create hotspot user: {error_message}")
            raise HTTPException(status_code=400, detail=error_message)
        else:
            raise HTTPException(status_code=500, detail=f"Registration failed: {error_message}")

    logger.info(f"MAC {normalized_mac} registered on router {router_obj.name} (ID: {router_id}, Owner: {router_obj.user_id})")

    return {
        "success": True,
        "message": f"MAC address {normalized_mac} registered successfully",
        "user_details": {
            "username": username,
            "mac_address": normalized_mac,
            "router_id": router_id,
            "router_name": router_obj.name,
            "router_owner_id": router_obj.user_id,
            "registered_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "bandwidth_limit": registration.get("bandwidth_limit"),
            "assigned_ip": result.get("assigned_ip"),
            "binding_created": result.get("binding_created", False),
            "queue_created": result.get("queue_created", False)
        }
    }


# Public router info endpoint (no auth required)
@router.get("/api/public/router/{router_id}")
async def get_public_router_info(
    router_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get basic router information for guest users.
    This can be used by captive portals to show router/ISP details.
    """
    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    # Return only public information
    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "location": getattr(router_obj, 'location', None),
        "isp_name": getattr(router_obj, 'isp_name', None),
        "description": getattr(router_obj, 'description', None),
        "contact_info": getattr(router_obj, 'contact_info', None),
    }


# MAC registration status check (no auth required)
@router.get("/api/public/mac-status/{router_id}/{mac_address}")
async def check_mac_registration_status(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Check if a MAC address is registered on a specific router.
    Useful for captive portals to determine user status.
    Runs MikroTik operations in thread pool to not block other requests.
    """
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_check_mac_status_sync, router_info, normalized_mac, username, router_id)
    
    if result.get("error"):
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    return result


# Disconnect user endpoint (no auth required - for self-service)
@router.post("/api/public/disconnect/{router_id}/{mac_address}")
async def disconnect_user_session(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Disconnect a user session. Can be used for self-service logout.
    Runs MikroTik operations in thread pool to not block other requests.
    """
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_disconnect_user_session_sync, router_info, username)
    
    if result.get("error"):
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    return {
        "success": True,
        "message": f"Disconnected {result['disconnected_sessions']} session(s) for MAC {normalized_mac}",
        "mac_address": normalized_mac,
        "sessions_disconnected": result["disconnected_sessions"]
    }


@router.delete("/api/public/remove-bypassed/{router_id}/{mac_address}")
async def remove_bypassed_user_public(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Remove expired user from MikroTik (hotspot user + bindings + queues + dhcp lease)
    Also updates database status to INACTIVE.
    No JWT required.
    """
    # Late import to avoid circular dependency — this function is shared with
    from app.services.mikrotik_background import remove_user_from_mikrotik

    logger.info(f"[REMOVE-BYPASSED] Endpoint hit! router_id={router_id}, mac={mac_address}")
    
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    # Verify router exists
    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    # Use shared cleanup function
    result = await remove_user_from_mikrotik(mac_address, db)
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to remove user"))
    
    return {
        "success": True,
        "message": f"User with MAC {result['mac_address']} removed from MikroTik and set to INACTIVE",
        "customer_id": result.get("customer_id"),
        "mac_address": result["mac_address"],
        "router_id": router_id,
        "removed_items": result.get("removed", {})
    }


@router.delete("/api/public/cleanup-blocked-bindings")
async def cleanup_blocked_bindings_public():
    """
    Remove all blocked IP bindings from MikroTik (public endpoint).
    Blocked bindings prevent captive portal redirect - they need to be removed
    so users can see the login page again.
    
    Call this to fix users stuck with blocked status.
    """
    
    try:
        api = MikroTikAPI(
            settings.MIKROTIK_HOST,
            settings.MIKROTIK_USERNAME,
            settings.MIKROTIK_PASSWORD,
            settings.MIKROTIK_PORT,
            timeout=15,
            connect_timeout=5
        )
        
        if not api.connect():
            raise HTTPException(status_code=500, detail="Failed to connect to router")
        
        try:
            bindings = api.send_command("/ip/hotspot/ip-binding/print")
            removed_count = 0
            removed_macs = []
            
            if bindings.get("success") and bindings.get("data"):
                for b in bindings["data"]:
                    binding_type = b.get("type", "")
                    # Remove blocked bindings (type=blocked shows as "B" in Winbox)
                    if binding_type == "blocked":
                        mac = b.get("mac-address", "unknown")
                        api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                        removed_count += 1
                        removed_macs.append(mac)
                        logger.info(f"[CLEANUP-BLOCKED] Removed blocked binding for {mac}")
            
            return {
                "success": True,
                "message": f"Removed {removed_count} blocked bindings",
                "removed_count": removed_count,
                "removed_macs": removed_macs
            }
        finally:
            api.disconnect()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[CLEANUP-BLOCKED] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/public/sync-queue/{customer_id}")
async def sync_customer_queue(
    customer_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Sync/apply bandwidth queue for a customer.
    Call this after payment to ensure speed limit is applied.
    Finds customer's current IP and creates/updates the simple queue.
    """
    try:
        # Get customer with plan
        stmt = select(Customer).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).where(Customer.id == customer_id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        if not customer.mac_address:
            raise HTTPException(status_code=400, detail="Customer has no MAC address")
        
        if not customer.plan or not customer.plan.speed:
            raise HTTPException(status_code=400, detail="Customer has no plan with speed limit")
        
        # Connect to the customer's assigned router (fallback to default settings)
        router_ip = customer.router.ip_address if customer.router else settings.MIKROTIK_HOST
        router_username = customer.router.username if customer.router else settings.MIKROTIK_USERNAME
        router_password = customer.router.password if customer.router else settings.MIKROTIK_PASSWORD
        router_port = customer.router.port if customer.router else settings.MIKROTIK_PORT

        api = MikroTikAPI(
            router_ip,
            router_username,
            router_password,
            router_port,
            timeout=15,
            connect_timeout=5
        )
        
        if not api.connect():
            raise HTTPException(status_code=500, detail="Failed to connect to router")
        
        try:
            normalized_mac = normalize_mac_address(customer.mac_address)
            username = normalized_mac.replace(":", "")
            rate_limit = api._parse_speed_to_mikrotik(customer.plan.speed)
            
            # Find client IP from multiple sources
            client_ip = None
            
            # Check DHCP leases
            leases = api.send_command("/ip/dhcp-server/lease/print")
            if leases.get("success") and leases.get("data"):
                for lease in leases["data"]:
                    if normalize_mac_address(lease.get("mac-address", "")) == normalized_mac:
                        client_ip = lease.get("address")
                        break
            
            # Check hotspot hosts
            if not client_ip:
                hosts = api.send_command("/ip/hotspot/host/print")
                if hosts.get("success") and hosts.get("data"):
                    for host in hosts["data"]:
                        if normalize_mac_address(host.get("mac-address", "")) == normalized_mac:
                            client_ip = host.get("address")
                            break
            
            # Check ARP
            if not client_ip:
                arp = api.send_command("/ip/arp/print")
                if arp.get("success") and arp.get("data"):
                    for entry in arp["data"]:
                        if normalize_mac_address(entry.get("mac-address", "")) == normalized_mac:
                            client_ip = entry.get("address")
                            break
            
            if not client_ip:
                api.disconnect()
                return {
                    "success": False,
                    "message": "Client not currently connected. Queue will be applied when they connect.",
                    "customer_id": customer_id,
                    "mac_address": customer.mac_address
                }
            
            # Create or update queue
            queue_args = {
                "name": f"queue_{username}",
                "target": f"{client_ip}/32",
                "max-limit": rate_limit,
                "comment": f"Bandwidth limit for MAC: {customer.mac_address} -> IP: {client_ip}"
            }
            
            # Try update first, then add
            queue_result = api.send_command("/queue/simple/set", {
                "numbers": f"queue_{username}",
                "target": f"{client_ip}/32",
                "max-limit": rate_limit
            })
            
            if "error" in queue_result:
                queue_result = api.send_command("/queue/simple/add", queue_args)
            
            api.disconnect()
            
            return {
                "success": True,
                "message": f"Queue synced for customer {customer.name}",
                "customer_id": customer_id,
                "mac_address": customer.mac_address,
                "client_ip": client_ip,
                "rate_limit": rate_limit,
                "queue_result": queue_result
            }
            
        finally:
            api.disconnect()
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SYNC-QUEUE] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/public/plans/{router_id}")
async def get_public_plans(
    router_id: int,
    connection_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get available plans for a specific router (public, no auth required).
    Used by the captive portal to show plans to guests before they pay.
    Only returns plans belonging to the router's owner.
    """
    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    return await get_plans_cached(db, router_obj.user_id, connection_type)


@router.get("/api/public/ads")
async def get_public_ads(
    page: int = 1,
    per_page: int = 20,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Fetch active ads for captive portal display (public, no auth required).
    Returns paginated active ads sorted by priority then created_at.
    """
    try:
        offset = (page - 1) * per_page

        stmt = (
            select(Ad)
            .where(Ad.is_active == True)
            .where(or_(Ad.expires_at == None, Ad.expires_at > datetime.utcnow()))
            .order_by(Ad.priority.desc(), Ad.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )

        if category:
            stmt = stmt.where(Ad.category == category)

        result = await db.execute(stmt)
        ads = result.scalars().all()

        count_stmt = select(func.count(Ad.id)).where(
            Ad.is_active == True,
            or_(Ad.expires_at == None, Ad.expires_at > datetime.utcnow())
        )
        if category:
            count_stmt = count_stmt.where(Ad.category == category)
        total_result = await db.execute(count_stmt)
        total = total_result.scalar() or 0

        return {
            "ads": [
                {
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
                }
                for ad in ads
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page if per_page > 0 else 0,
        }
    except Exception as e:
        logger.error(f"Error fetching public ads: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch ads")

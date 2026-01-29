from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.db.database import get_db, async_engine
from app.db.models import Router, Customer, Plan, ProvisioningLog, ConnectionType, CustomerStatus, MpesaTransaction, MpesaTransactionStatus, User, CustomerPayment, BandwidthSnapshot, UserBandwidthUsage, Ad, AdClick, AdImpression, AdClickType, Advertiser, AdBadgeType
from app.services.auth import verify_token, get_current_user
from app.services.billing import make_payment
from app.services.mikrotik_api import MikroTikAPI, validate_mac_address, normalize_mac_address
from app.services.mpesa_transactions import update_mpesa_transaction_status
from app.services.plan_cache import get_plans_cached, invalidate_plan_cache, warm_plan_cache
from app.config import settings
import logging
from sqlalchemy.orm import selectinload
import json
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import hashlib
from pprint import pformat
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ISP Billing SaaS API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scheduler and cleanup flag
scheduler = AsyncIOScheduler()
cleanup_running = False
mikrotik_lock = asyncio.Lock()  # Global lock to prevent concurrent MikroTik API access

# MikroTik dashboard cache (avoid hammering the router)
_mikrotik_cache = {"data": None, "timestamp": None}
_mikrotik_cache_ttl = 300  # seconds - limit to once per 5 minutes

# MikroTik health cache per router (lighter TTL for real-time feel)
_health_cache = {}  # router_id -> {"data": ..., "timestamp": ...}
_health_cache_ttl = 30  # seconds - balance between freshness and load


def _fetch_mikrotik_data_sync():
    """Synchronous MikroTik fetch - runs in thread pool to not block event loop"""
    api = MikroTikAPI(
        settings.MIKROTIK_HOST,
        settings.MIKROTIK_USERNAME,
        settings.MIKROTIK_PASSWORD,
        settings.MIKROTIK_PORT,
        timeout=20
    )
    if not api.connect():
        return None
    
    resources = api.get_system_resources()
    health = api.get_health()
    active_sessions = api.get_active_hotspot_users()
    traffic = api.get_interface_traffic()
    speed_stats = api.get_queue_speed_stats()
    api.disconnect()
    
    return {
        "resources": resources,
        "health": health,
        "active_sessions": active_sessions,
        "traffic": traffic,
        "speed_stats": speed_stats
    }


def _fetch_top_users_sync():
    """Get queue data for top users analysis"""
    api = MikroTikAPI(
        settings.MIKROTIK_HOST,
        settings.MIKROTIK_USERNAME,
        settings.MIKROTIK_PASSWORD,
        settings.MIKROTIK_PORT,
        timeout=20
    )
    if not api.connect():
        return None
    
    queues = api.send_command("/queue/simple/print")
    api.disconnect()
    return queues

async def get_router_by_id(
    db: AsyncSession,
    router_id: int,
    user_id: int | None = None,
    role: str | None = None
) -> Router | None:
    stmt = select(Router).where(Router.id == router_id)
    if role != "admin" and user_id is not None:
        stmt = stmt.where(Router.user_id == user_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()

def connect_to_router(router: Router) -> MikroTikAPI:
    """Create MikroTik API connection using router-specific credentials"""
    api = MikroTikAPI(
        router.ip_address,
        router.username,
        router.password,
        router.port
    )
    return api

# Shared function to remove user from MikroTik
async def remove_user_from_mikrotik(mac_address: str, db: AsyncSession) -> dict:
    """
    Remove user from MikroTik router and update database status
    
    Removes from these MikroTik locations:
    1. /ip/hotspot/user (the user account)
    2. /ip/hotspot/ip-binding (MAC address bindings - for bypassed users)
    3. /queue/simple (bandwidth limits)
    4. /ip/dhcp-server/lease (DHCP leases)
    5. /ip/hotspot/active (disconnect active sessions - CRITICAL for re-login)
    
    Returns dict with success status and details
    """
    try:
        normalized_mac = normalize_mac_address(mac_address)
        username = normalized_mac.replace(":", "")
        
        # Update database first - include router relationship
        customer_stmt = select(Customer).options(selectinload(Customer.router)).where(Customer.mac_address == normalized_mac)
        customer_result = await db.execute(customer_stmt)
        customer = customer_result.scalar_one_or_none()
        
        if not customer:
            return {"success": False, "error": "Customer not found in database"}
        
        customer.status = CustomerStatus.INACTIVE
        await db.commit()
        logger.info(f"[CLEANUP] Customer {customer.id} set to INACTIVE in database")
        
        # Get router credentials - use customer's assigned router or fallback to settings
        if customer.router:
            router = customer.router
            api = MikroTikAPI(
                router.ip_address,
                router.username,
                router.password,
                router.port
            )
            logger.info(f"[CLEANUP] Connecting to router {router.name} at {router.ip_address}")
        else:
            # Fallback to global settings if no router assigned
            api = MikroTikAPI(
                settings.MIKROTIK_HOST,
                settings.MIKROTIK_USERNAME,
                settings.MIKROTIK_PASSWORD,
                settings.MIKROTIK_PORT
            )
            logger.warning(f"[CLEANUP] Customer {customer.id} has no router assigned, using default settings")
        
        if not api.connect():
            logger.error(f"[CLEANUP] Failed to connect to MikroTik for {normalized_mac}")
            return {"success": False, "error": "Failed to connect to MikroTik"}
        
        removed = {"user": False, "bindings": 0, "queues": 0, "leases": 0}
        
        # 1. Remove hotspot user (from Users tab)
        users = api.send_command("/ip/hotspot/user/print")
        if users.get("success") and users.get("data"):
            for u in users["data"]:
                if u.get("name") == username:
                    api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                    removed["user"] = True
                    logger.info(f"[CLEANUP] Removed hotspot user: {username}")
                    break
        
        # 2. Remove IP bindings (from IP Bindings tab - this is where bypassed users are)
        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if bindings.get("success") and bindings.get("data"):
            for b in bindings["data"]:
                binding_mac = b.get("mac-address", "").upper()
                binding_name = b.get("name", "").upper()
                # Match by MAC address OR by name field (which is set to username for bypassed users)
                if binding_mac == normalized_mac.upper() or binding_name == username.upper():
                    api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                    removed["bindings"] += 1
                    logger.info(f"[CLEANUP] Removed IP binding: {binding_name} ({binding_mac})")
        
        # 3. Remove queues (from Queues section) - search by name OR MAC in comment
        queues = api.send_command("/queue/simple/print")
        if queues.get("success") and queues.get("data"):
            for q in queues["data"]:
                queue_name = q.get("name", "")
                queue_comment = q.get("comment", "")
                # Match by queue name OR by MAC address in comment
                if (queue_name == f"queue_{username}" or 
                    normalized_mac.upper() in queue_comment.upper() or
                    mac_address.upper() in queue_comment.upper()):
                    api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                    removed["queues"] += 1
                    logger.info(f"[CLEANUP] Removed queue: {queue_name}")
        
        # 4. Remove DHCP leases
        leases = api.send_command("/ip/dhcp-server/lease/print")
        logger.info(f"[CLEANUP-DHCP] Searching for leases to remove. Target MAC: {normalized_mac}")
        if leases.get("success") and leases.get("data"):
            logger.info(f"[CLEANUP-DHCP] Found {len(leases['data'])} total DHCP leases")
            for l in leases["data"]:
                lease_mac = l.get("mac-address", "")
                lease_ip = l.get("address", "N/A")
                lease_id = l.get(".id", "N/A")
                logger.info(f"[CLEANUP-DHCP] Checking lease: ID={lease_id}, MAC={lease_mac}, IP={lease_ip}")
                if lease_mac:
                    # Normalize both MACs to compare without separators
                    lease_mac_clean = lease_mac.replace(":", "").replace("-", "").upper()
                    normalized_mac_clean = normalized_mac.replace(":", "").replace("-", "").upper()
                    logger.info(f"[CLEANUP-DHCP] Comparing: '{lease_mac_clean}' vs '{normalized_mac_clean}'")
                    if lease_mac_clean == normalized_mac_clean:
                        remove_result = api.send_command("/ip/dhcp-server/lease/remove", {"numbers": l[".id"]})
                        removed["leases"] += 1
                        logger.info(f"[CLEANUP-DHCP] ✓ Removed DHCP lease: {lease_mac} (ID: {lease_id}, IP: {lease_ip})")
                        if "error" in remove_result:
                            logger.error(f"[CLEANUP-DHCP] Remove command returned error: {remove_result['error']}")
                    else:
                        logger.info(f"[CLEANUP-DHCP] ✗ No match, skipping")
                else:
                    logger.warning(f"[CLEANUP-DHCP] Lease {lease_id} has no MAC address")
        else:
            logger.warning(f"[CLEANUP-DHCP] Failed to fetch leases or no data returned: {leases}")
        
        logger.info(f"[CLEANUP-DHCP] Total leases removed: {removed['leases']}")
        
        # 5. Disconnect active hotspot sessions (CRITICAL - prevents re-login issues)
        active_sessions = api.send_command("/ip/hotspot/active/print")
        removed["active_sessions"] = 0
        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                session_user = session.get("user", "").upper()
                session_mac = session.get("mac-address", "").upper()
                # Match by username OR MAC address
                if session_user == username.upper() or session_mac == normalized_mac.upper():
                    session_id = session.get(".id")
                    if session_id:
                        api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                        removed["active_sessions"] += 1
                        logger.info(f"[CLEANUP] Disconnected active session: {session_user} ({session_mac})")
        
        api.disconnect()
        
        logger.info(f"[CLEANUP] Successfully cleaned up {normalized_mac}: {removed}")
        
        return {
            "success": True,
            "customer_id": customer.id,
            "mac_address": normalized_mac,
            "removed": removed
        }
        
    except Exception as e:
        logger.error(f"[CLEANUP] Error removing user {mac_address}: {e}")
        return {"success": False, "error": str(e)}

# Synchronous MikroTik cleanup - runs in thread pool to not block event loop
def _cleanup_customer_from_mikrotik_sync(router_customers_map: dict) -> dict:
    """
    Synchronous function to remove expired customers from MikroTik.
    Runs in a separate thread to avoid blocking the async event loop.
    
    Args:
        router_customers_map: Dict mapping router info to customer list
            {
                "router_ip:port": {
                    "router": {ip, username, password, port, name},
                    "customers": [{id, name, mac_address, expiry}, ...]
                }
            }
    
    Returns:
        Dict with results: {removed: [], failed: [], routers_connected: int}
    """
    results = {"removed": [], "failed": [], "routers_connected": 0}
    
    if not router_customers_map:
        return results
    
    for router_key, router_data in router_customers_map.items():
        router_info = router_data["router"]
        customers_data = router_data["customers"]
        
        if not customers_data:
            continue
        
        logger.info(f"[CRON] Processing {len(customers_data)} customers on router {router_info['name']} ({router_info['ip']})")
        
        api = MikroTikAPI(
            router_info["ip"],
            router_info["username"],
            router_info["password"],
            router_info["port"]
        )
        
        if not api.connect():
            logger.error(f"[CRON] Failed to connect to router {router_info['name']} at {router_info['ip']}")
            for cust in customers_data:
                results["failed"].append({"id": cust["id"], "error": f"Failed to connect to router {router_info['name']}"})
            continue
        
        results["routers_connected"] += 1
        
        for cust in customers_data:
            try:
                normalized_mac = normalize_mac_address(cust["mac_address"])
                username = normalized_mac.replace(":", "")
                
                logger.info(f"[CRON] Processing expired customer {cust['id']}: {cust['name']} ({normalized_mac})")
                
                removed = {
                    "user": False, 
                    "binding_removed": False, 
                    "hosts": 0,
                    "queues": 0, 
                    "leases": 0,
                    "active_sessions": 0
                }
                
                # STEP 1: Get client's current IP (needed for host removal)
                client_ip = api.get_client_ip_by_mac(normalized_mac)
                if client_ip:
                    logger.info(f"[CRON] Found client IP: {client_ip} for MAC {normalized_mac}")
                
                # STEP 2: REMOVE the IP binding completely (not block!)
                bindings = api.send_command("/ip/hotspot/ip-binding/print")
                if bindings.get("success") and bindings.get("data"):
                    for b in bindings["data"]:
                        binding_mac = b.get("mac-address", "").upper()
                        if normalize_mac_address(binding_mac) == normalized_mac:
                            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                            removed["binding_removed"] = True
                            logger.info(f"[CRON] Removed IP binding for {normalized_mac}")
                
                # STEP 3: Remove from hotspot hosts (forces IMMEDIATE disconnect)
                hosts = api.send_command("/ip/hotspot/host/print")
                if hosts.get("success") and hosts.get("data"):
                    for host in hosts["data"]:
                        host_mac = host.get("mac-address", "").upper()
                        host_ip = host.get("address", "")
                        if normalize_mac_address(host_mac) == normalized_mac or host_ip == client_ip:
                            api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
                            removed["hosts"] += 1
                            logger.info(f"[CRON] Removed host entry: {host_mac} / {host_ip}")
                
                # STEP 4: Remove hotspot user
                users = api.send_command("/ip/hotspot/user/print")
                if users.get("success") and users.get("data"):
                    for u in users["data"]:
                        if u.get("name", "") == username:
                            api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                            removed["user"] = True
                            logger.info(f"[CRON] Removed hotspot user: {username}")
                            break
                
                # STEP 5: Disconnect any active sessions
                active_sessions = api.send_command("/ip/hotspot/active/print")
                if active_sessions.get("success") and active_sessions.get("data"):
                    for session in active_sessions["data"]:
                        session_mac = session.get("mac-address", "").upper()
                        session_user = session.get("user", "").upper()
                        if normalize_mac_address(session_mac) == normalized_mac or session_user == username.upper():
                            api.send_command("/ip/hotspot/active/remove", {"numbers": session[".id"]})
                            removed["active_sessions"] += 1
                            logger.info(f"[CRON] Disconnected active session: {session_user}")
                
                # STEP 6: Remove queues (simple queues)
                queues = api.send_command("/queue/simple/print")
                if queues.get("success") and queues.get("data"):
                    for q in queues["data"]:
                        queue_name = q.get("name", "")
                        queue_comment = q.get("comment", "")
                        if (queue_name == f"queue_{username}" or 
                            queue_name == f"plan_{username}" or
                            normalized_mac.upper() in queue_comment.upper() or
                            f"MAC:{cust['mac_address']}" in queue_comment):
                            api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                            removed["queues"] += 1
                            logger.info(f"[CRON] Removed queue: {queue_name}")
                
                # STEP 7: Remove DHCP lease (forces client to re-request IP)
                leases = api.send_command("/ip/dhcp-server/lease/print")
                if leases.get("success") and leases.get("data"):
                    for lease in leases["data"]:
                        if normalize_mac_address(lease.get("mac-address", "")) == normalized_mac:
                            api.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease[".id"]})
                            removed["leases"] += 1
                            logger.info(f"[CRON] Removed DHCP lease for {normalized_mac}")
                
                results["removed"].append({"id": cust["id"], "details": removed})
                logger.info(f"[CRON] ✓ Expired customer {cust['name']} removed: {removed}")
                
            except Exception as e:
                results["failed"].append({"id": cust["id"], "error": str(e)})
                logger.error(f"[CRON] Failed to remove customer {cust['id']}: {e}")
        
        api.disconnect()
    
    return results


# Background cleanup function for expired users
async def cleanup_expired_users_background():
    """
    Background task to remove expired users from MikroTik.
    MikroTik operations run in a thread pool to avoid blocking the event loop.
    Groups customers by router for multi-router support.
    """
    global cleanup_running
    
    # Prevent overlapping runs
    if cleanup_running:
        logger.warning("[CRON] Previous cleanup still running, skipping this run")
        return
    
    cleanup_running = True
    start_time = datetime.utcnow()
    
    try:
        # STEP 1: Query expired customers from database with router info (async)
        async with AsyncSession(async_engine) as db:
            now = datetime.utcnow()
            
            stmt = select(Customer).options(
                selectinload(Customer.router)
            ).where(
                Customer.status == CustomerStatus.ACTIVE,
                Customer.expiry.isnot(None),
                Customer.expiry <= now,
                Customer.mac_address.isnot(None)
            )
            
            result = await db.execute(stmt)
            expired_customers = result.scalars().all()
            
            if not expired_customers:
                return
            
            logger.info(f"[CRON] Found {len(expired_customers)} expired customers to cleanup")
            
            # Group customers by router (can't pass ORM objects to thread)
            router_customers_map = {}
            no_router_customers = []
            
            for c in expired_customers:
                if not c.mac_address:
                    continue
                    
                customer_data = {
                    "id": c.id,
                    "name": c.name,
                    "mac_address": c.mac_address,
                    "expiry": c.expiry
                }
                
                if c.router:
                    router_key = f"{c.router.ip_address}:{c.router.port}"
                    if router_key not in router_customers_map:
                        router_customers_map[router_key] = {
                            "router": {
                                "ip": c.router.ip_address,
                                "username": c.router.username,
                                "password": c.router.password,
                                "port": c.router.port,
                                "name": c.router.name
                            },
                            "customers": []
                        }
                    router_customers_map[router_key]["customers"].append(customer_data)
                else:
                    # Fallback to default settings for customers without router
                    no_router_customers.append(customer_data)
            
            # Add no-router customers to default router
            if no_router_customers:
                default_key = f"{settings.MIKROTIK_HOST}:{settings.MIKROTIK_PORT}"
                if default_key not in router_customers_map:
                    router_customers_map[default_key] = {
                        "router": {
                            "ip": settings.MIKROTIK_HOST,
                            "username": settings.MIKROTIK_USERNAME,
                            "password": settings.MIKROTIK_PASSWORD,
                            "port": settings.MIKROTIK_PORT,
                            "name": "Default Router"
                        },
                        "customers": []
                    }
                router_customers_map[default_key]["customers"].extend(no_router_customers)
            
            logger.info(f"[CRON] Grouped customers across {len(router_customers_map)} router(s)")
            
            # STEP 2: Run MikroTik cleanup in thread pool (non-blocking!)
            mikrotik_results = await asyncio.to_thread(_cleanup_customer_from_mikrotik_sync, router_customers_map)
            
            # STEP 3: Update database based on results (async)
            # ONLY mark as INACTIVE if MikroTik removal SUCCEEDED
            # Failed removals stay ACTIVE so next cleanup run retries them
            if mikrotik_results["routers_connected"] > 0:
                successful_ids = [r["id"] for r in mikrotik_results["removed"]]
                failed_ids = [r["id"] for r in mikrotik_results["failed"]]
                
                for customer in expired_customers:
                    if customer.id in successful_ids:
                        customer.status = CustomerStatus.INACTIVE
                    # Keep failed ones as ACTIVE for retry
                
                await db.commit()
                
                if failed_ids:
                    logger.warning(f"[CRON] {len(failed_ids)} customers kept ACTIVE for retry: {failed_ids}")
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            removed_count = len(mikrotik_results["removed"])
            failed_count = len(mikrotik_results["failed"])
            logger.info(f"[CRON] Cleanup completed in {duration:.2f}s: {removed_count} removed, {failed_count} failed")
            
    except Exception as e:
        logger.error(f"[CRON] Cleanup job failed: {e}")
    finally:
        cleanup_running = False


# Background sync function for active user queues (runs every 60 seconds)
async def sync_active_user_queues():
    """
    Sync queues for active customers - ensures rate limits are applied even if IP changed.
    Supports multiple routers by grouping customers by their assigned router.
    """
    try:
        async with AsyncSession(async_engine) as db:
            now = datetime.utcnow()
            
            # Query active customers with MAC addresses and router info
            stmt = select(Customer).where(
                Customer.status == CustomerStatus.ACTIVE,
                Customer.mac_address.isnot(None),
                Customer.expiry > now
            ).options(selectinload(Customer.plan), selectinload(Customer.router))
            
            result = await db.execute(stmt)
            active_customers = result.scalars().all()
            
            if not active_customers:
                return
            
            # Group customers by router
            router_customers = {}
            for customer in active_customers:
                if not customer.plan or not customer.mac_address:
                    continue
                
                if customer.router:
                    router_key = f"{customer.router.ip_address}:{customer.router.port}"
                    if router_key not in router_customers:
                        router_customers[router_key] = {
                            "router": customer.router,
                            "customers": []
                        }
                    router_customers[router_key]["customers"].append(customer)
                else:
                    # Fallback to default settings
                    default_key = f"{settings.MIKROTIK_HOST}:{settings.MIKROTIK_PORT}"
                    if default_key not in router_customers:
                        router_customers[default_key] = {
                            "router": None,  # Will use settings
                            "customers": []
                        }
                    router_customers[default_key]["customers"].append(customer)
            
            total_synced = 0
            
            # Process each router
            for router_key, data in router_customers.items():
                router = data["router"]
                customers = data["customers"]
                
                if router:
                    api = MikroTikAPI(
                        router.ip_address,
                        router.username,
                        router.password,
                        router.port
                    )
                    router_name = router.name
                else:
                    api = MikroTikAPI(
                        settings.MIKROTIK_HOST,
                        settings.MIKROTIK_USERNAME,
                        settings.MIKROTIK_PASSWORD,
                        settings.MIKROTIK_PORT
                    )
                    router_name = "Default Router"
                
                if not api.connect():
                    logger.warning(f"[SYNC] Failed to connect to {router_name}")
                    continue
                
                synced = 0
                for customer in customers:
                    try:
                        normalized_mac = normalize_mac_address(customer.mac_address)
                        username = normalized_mac.replace(":", "")
                        rate_limit = api._parse_speed_to_mikrotik(customer.plan.speed)
                        
                        # Get current IP
                        client_ip = api.get_client_ip_by_mac(normalized_mac)
                        if not client_ip:
                            continue
                        
                        # Check if queue exists and targets correct IP
                        queues = api.send_command("/queue/simple/print")
                        queue_exists = False
                        
                        if queues.get("success") and queues.get("data"):
                            for q in queues["data"]:
                                if q.get("name") == f"plan_{username}":
                                    queue_exists = True
                                    if client_ip not in q.get("target", ""):
                                        # Update queue with new IP
                                        api.send_command("/queue/simple/set", {
                                            "numbers": q[".id"],
                                            "target": f"{client_ip}/32",
                                            "max-limit": rate_limit
                                        })
                                        logger.info(f"[SYNC] Updated queue for {username} -> {client_ip} on {router_name}")
                                        synced += 1
                                    break
                        
                        # Create queue if doesn't exist
                        if not queue_exists:
                            api.send_command("/queue/simple/add", {
                                "name": f"plan_{username}",
                                "target": f"{client_ip}/32",
                                "max-limit": rate_limit,
                                "comment": f"MAC:{customer.mac_address}|Plan rate limit"
                            })
                            logger.info(f"[SYNC] Created queue for {username} -> {client_ip} on {router_name}")
                            synced += 1
                            
                    except Exception as e:
                        logger.error(f"[SYNC] Error syncing customer {customer.id} on {router_name}: {e}")
                
                api.disconnect()
                total_synced += synced
            
            if total_synced > 0:
                logger.info(f"[SYNC] Synced {total_synced} queues across {len(router_customers)} router(s)")
                
    except Exception as e:
        logger.error(f"[SYNC] Queue sync failed: {e}")


# @app.post("/api/lipay/callback")
# async def mpesa_callback(payload: dict, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
#     logger.info(f"--- M-Pesa Callback Received: {json.dumps(payload, indent=2)}")

#     # Extract values from the incoming payload
#     mac_address = payload.get("customer_ref")
#     status = payload.get("status")
#     amount = payload.get("amount")
#     tx_no = payload.get("lipay_tx_no")

#     logger.info(f"Parsed payload - mac_address: {mac_address}, status: {status}, amount: {amount}, tx_no: {tx_no}")

#     if not mac_address:
#         logger.error("Missing MAC Address in callback")
#         return {"ResultCode": 1, "ResultDesc": "Missing MAC Address"}

#     # Fetch customer with plan and router details
#     stmt = (
#         select(Customer)
#         .options(selectinload(Customer.plan), selectinload(Customer.router))
#         .where(Customer.mac_address == mac_address)
#     )
#     result = await db.execute(stmt)
#     customer = result.scalar_one_or_none()
#     logger.info(f"Customers found for MAC {mac_address}: {'1' if customer else '0'}")

#     if not customer:
#         logger.error(f"No customer found for MAC {mac_address}")
#         return {"ResultCode": 1, "ResultDesc": "Customer not found"}

#     if status == "completed":
#         logger.info(f"PAYMENT CONFIRMED for customer {customer.id} ({mac_address}). Checking pending_update_data...")
#         pending_update_data = customer.pending_update_data
#         logger.info(f"Raw pending_update_data for customer {customer.id}: {pending_update_data}")

#         now = datetime.utcnow()
#         plan = customer.plan
#         router = customer.router

#         if pending_update_data:
#             # Handle existing customer with pending update data
#             if isinstance(pending_update_data, str):
#                 try:
#                     pending_update_data = json.loads(pending_update_data)
#                     logger.info(f"Parsed pending_update_data for customer {customer.id}: {json.dumps(pending_update_data)}")
#                 except json.JSONDecodeError as e:
#                     logger.error(f"Invalid JSON in pending_update_data for customer {customer.id}: {e}")
#                     return {"ResultCode": 1, "ResultDesc": "Invalid pending update data format"}

#             duration_value = pending_update_data.get("duration_value")
#             duration_unit = pending_update_data.get("duration_unit")
#             applied_plan_id = pending_update_data.get("plan_id")
#             requested_router_id = pending_update_data.get("router_id")

#             if duration_value is None or duration_unit is None or requested_router_id is None:
#                 logger.error(f"Missing duration_value, duration_unit, or router_id in pending_update_data for customer {customer.id}: {json.dumps(pending_update_data)}")
#                 return {"ResultCode": 1, "ResultDesc": "Missing required fields in pending update data"}

#             # Convert duration to days or hours for MikroTik
#             if duration_unit.upper() == "DAYS":
#                 time_limit = f"{int(duration_value)}d"
#             elif duration_unit.upper() == "HOURS":
#                 time_limit = f"{int(duration_value)}h"
#             else:
#                 logger.error(f"Unsupported duration_unit {duration_unit} for customer {customer.id}")
#                 return {"ResultCode": 1, "ResultDesc": f"Unsupported duration unit: {duration_unit}"}

#             # Fetch the plan from pending_update_data
#             plan_stmt = select(Plan).where(Plan.id == applied_plan_id)
#             plan_result = await db.execute(plan_stmt)
#             plan = plan_result.scalar_one_or_none()

#             if not plan:
#                 logger.error(f"Pending plan_id {applied_plan_id} not found for customer {customer.id}")
#                 return {"ResultCode": 1, "ResultDesc": "Plan for extension not found"}

#             # Fetch the router from pending_update_data
#             router_stmt = select(Router).where(Router.id == requested_router_id)
#             router_result = await db.execute(router_stmt)
#             router = router_result.scalar_one_or_none()

#             if not router:
#                 logger.error(f"Router with id {requested_router_id} not found for customer {customer.id}")
#                 return {"ResultCode": 1, "ResultDesc": f"Router with id {requested_router_id} not found"}

#             # Calculate new expiry
#             if duration_unit.upper() == "DAYS":
#                 if customer.expiry and customer.expiry > now:
#                     new_expiry = customer.expiry + timedelta(days=int(duration_value))
#                     logger.info(f"Customer has unexpired time. Old expiry: {customer.expiry}, days to add: {duration_value}")
#                 else:
#                     new_expiry = now + timedelta(days=int(duration_value))
#                     logger.info(f"Customer has expired. Setting expiry from now: {now}, days: {duration_value}")
#             elif duration_unit.upper() == "HOURS":
#                 if customer.expiry and customer.expiry > now:
#                     new_expiry = customer.expiry + timedelta(hours=int(duration_value))
#                     logger.info(f"Customer has unexpired time. Old expiry: {customer.expiry}, hours to add: {duration_value}")
#                 else:
#                     new_expiry = now + timedelta(hours=int(duration_value))
#                     logger.info(f"Customer has expired. Setting expiry from now: {now}, hours: {duration_value}")

#             # Update customer
#             customer.expiry = new_expiry
#             customer.plan_id = applied_plan_id
#             customer.router_id = requested_router_id
#             customer.status = CustomerStatus.ACTIVE
#             customer.pending_update_data = None  # Clear pending data

#             logger.info(f"[AUDIT] Applied pending_update_data: {json.dumps(pending_update_data)}")
#             logger.info(f"[AUDIT] Customer {customer.id}: Plan set to {plan.name} ({plan.id}), expiry updated to {new_expiry}, router_id updated to {requested_router_id}")

#         else:
#             # Handle new customer (no pending_update_data)
#             if not plan or not router:
#                 logger.error(f"Customer {customer.id} missing plan or router configuration")
#                 return {"ResultCode": 1, "ResultDesc": "Customer missing plan or router configuration"}

#             # Use the customer's current plan duration
#             duration_value = plan.duration_value
#             duration_unit = plan.duration_unit.value

#             if duration_unit.upper() == "DAYS":
#                 time_limit = f"{int(duration_value)}d"
#                 new_expiry = now + timedelta(days=int(duration_value))
#                 logger.info(f"New customer: Setting expiry from now: {now}, days: {duration_value}")
#             elif duration_unit.upper() == "HOURS":
#                 time_limit = f"{int(duration_value)}h"
#                 new_expiry = now + timedelta(hours=int(duration_value))
#                 logger.info(f"New customer: Setting expiry from now: {now}, hours: {duration_value}")
#             else:
#                 logger.error(f"Unsupported duration_unit {duration_unit} for customer {customer.id}")
#                 return {"ResultCode": 1, "ResultDesc": f"Unsupported duration unit: {duration_unit}"}

#             # Update customer
#             customer.expiry = new_expiry
#             customer.status = CustomerStatus.ACTIVE

#             logger.info(f"[AUDIT] New customer {customer.id}: Plan set to {plan.name} ({plan.id}), expiry set to {new_expiry}")

#         # Commit customer updates
#         await db.commit()

#         # Log payment details
#         logger.info(f"[AUDIT] Payment success: {json.dumps(payload)}")
#         logger.info(f"[AUDIT] Customer {customer.id} new expiry: {customer.expiry}")

#         # Prepare payload for MikroTik provisioning
#         if router and plan:
#             hotspot_payload = {
#                 "mac_address": customer.mac_address,
#                 "username": customer.mac_address.replace(":", ""),
#                 "password": customer.mac_address.replace(":", ""),
#                 "time_limit": time_limit,
#                 "bandwidth_limit": f"{plan.speed}",
#                 "comment": f"Payment successful for {customer.name} on {datetime.utcnow().isoformat()}",
#                 "router_ip": router.ip_address,
#                 "router_username": router.username,
#                 "router_password": router.password,
#             }
#             logger.info(f"Prepared MikroTik Payload:\n{json.dumps(hotspot_payload, indent=2)}")
#             background_tasks.add_task(call_mikrotik_bypass, hotspot_payload)
#         else:
#             logger.error(f"Missing router or plan for customer {customer.id}")
#             return {"ResultCode": 1, "ResultDesc": "Missing router or plan configuration"}

#         return {
#             "ResultCode": 0,
#             "ResultDesc": f"Customer {customer.id} updated to ACTIVE and MikroTik user created. New expiry: {customer.expiry}"
#         }

#     elif status == "failed":
#         customer.status = CustomerStatus.INACTIVE
#         await db.commit()
#         logger.info(f"Customer {customer.id} status set to INACTIVE due to failed payment")
#         return {"ResultCode": 0, "ResultDesc": "Customer updated to INACTIVE"}

#     else:
#         logger.info(f"Payment status for customer {customer.id}: {status} (no action taken)")
#         return {"ResultCode": 0, "ResultDesc": f"No action taken for status: {status}"}
@app.post("/api/mpesa/callback")
async def mpesa_direct_callback(payload: dict, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Handle standard M-Pesa STK Push callback"""
    logger.info(f"--- M-Pesa Direct Callback Received: {json.dumps(payload, indent=2)}")
    
    try:
        # Extract M-Pesa callback data
        body = payload.get("Body", {})
        stk_callback = body.get("stkCallback", {})
        
        checkout_request_id = stk_callback.get("CheckoutRequestID")
        merchant_request_id = stk_callback.get("MerchantRequestID")
        result_code = stk_callback.get("ResultCode")
        result_desc = stk_callback.get("ResultDesc")
        
        if not checkout_request_id:
            logger.error("Missing CheckoutRequestID in callback")
            return {"ResultCode": 1, "ResultDesc": "Missing CheckoutRequestID"}
        
        # Look up transaction
        from app.db.models import MpesaTransaction, MpesaTransactionStatus
        stmt = select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_request_id)
        result = await db.execute(stmt)
        mpesa_txn = result.scalar_one_or_none()
        
        if not mpesa_txn:
            logger.error(f"Transaction not found for CheckoutRequestID: {checkout_request_id}")
            return {"ResultCode": 1, "ResultDesc": "Transaction not found"}
        
        # DUPLICATE CALLBACK PROTECTION: Skip if already processed
        if mpesa_txn.status in (MpesaTransactionStatus.completed, MpesaTransactionStatus.failed):
            logger.warning(f"Duplicate callback ignored for {checkout_request_id} - status: {mpesa_txn.status.value}")
            return {"ResultCode": 0, "ResultDesc": "Already processed"}
        
        # Extract callback metadata
        callback_metadata = stk_callback.get("CallbackMetadata", {})
        items = callback_metadata.get("Item", [])
        
        receipt_number = None
        amount = None
        phone_number = None
        
        for item in items:
            name = item.get("Name")
            if name == "MpesaReceiptNumber":
                receipt_number = item.get("Value")
            elif name == "Amount":
                amount = item.get("Value")
            elif name == "PhoneNumber":
                phone_number = item.get("Value")
        
        # Update transaction status
        if result_code == 0:
            mpesa_txn.status = MpesaTransactionStatus.completed
            mpesa_txn.mpesa_receipt_number = receipt_number
            status = "completed"
        else:
            mpesa_txn.status = MpesaTransactionStatus.failed
            status = "failed"
        
        mpesa_txn.updated_at = datetime.utcnow()
        await db.commit()
        
        # Get customer via transaction
        customer_id = mpesa_txn.customer_id
        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            logger.error(f"Customer {customer_id} not found")
            return {"ResultCode": 1, "ResultDesc": "Customer not found"}
        
        # Process payment similar to lipay callback
        if status == "completed":
            logger.info(f"PAYMENT CONFIRMED for customer {customer.id}")
            
            # Record payment
            from app.services.reseller_payments import record_customer_payment
            from app.db.models import PaymentMethod
            
            # Check for pending plan change (customer paying for a different plan)
            pending_data = None
            if customer.pending_update_data:
                try:
                    pending_data = json.loads(customer.pending_update_data) if isinstance(customer.pending_update_data, str) else customer.pending_update_data
                except (json.JSONDecodeError, TypeError):
                    pending_data = None
            
            # Use pending plan data if available, otherwise use customer's current plan
            if pending_data and pending_data.get("plan_id"):
                # Fetch the plan they're actually paying for
                pending_plan_stmt = select(Plan).where(Plan.id == pending_data["plan_id"])
                pending_plan_result = await db.execute(pending_plan_stmt)
                plan = pending_plan_result.scalar_one_or_none() or customer.plan
                
                # Update customer's plan_id to the new plan
                if plan:
                    customer.plan_id = plan.id
                    logger.info(f"[PLAN] Updated customer {customer.id} plan_id to {plan.id} ({plan.name})")
            else:
                plan = customer.plan
            
            duration_value = plan.duration_value if plan else 1
            duration_unit = plan.duration_unit.value.upper() if plan else "DAYS"
            
            logger.info(f"[PLAN DEBUG] Customer {customer.id} - Plan: {plan.name if plan else 'None'}, "
                       f"duration_value: {duration_value}, duration_unit: {duration_unit}")
            
            # Clear pending_update_data after applying
            customer.pending_update_data = None
            
            # Calculate days_paid_for for financial tracking (minimum 1 day)
            if duration_unit == "MINUTES":
                days_paid_for = max(1, duration_value // (24 * 60))  # minutes to days
            elif duration_unit == "HOURS":
                days_paid_for = max(1, duration_value // 24)  # hours to days
            else:  # DAYS
                days_paid_for = duration_value
            
            payment = await record_customer_payment(
                db=db,
                customer_id=customer.id,
                reseller_id=customer.user_id,
                amount=float(amount or mpesa_txn.amount),
                payment_method=PaymentMethod.MOBILE_MONEY,
                days_paid_for=days_paid_for,
                payment_reference=receipt_number,
                notes=f"M-Pesa STK Push. TX: {checkout_request_id}",
                duration_value=duration_value,
                duration_unit=duration_unit
            )
            
            logger.info(f"[AUDIT] Payment recorded: ID {payment.id}, Amount: {amount}, Days: {days_paid_for}")
            
            # Provision to MikroTik if hotspot
            if customer.mac_address and customer.router:
                router = customer.router
                
                # Convert duration to MikroTik format (m=minutes, h=hours, d=days)
                duration_unit = plan.duration_unit.value.upper()
                if duration_unit == "MINUTES":
                    time_limit = f"{int(duration_value)}m"
                elif duration_unit == "HOURS":
                    time_limit = f"{int(duration_value)}h"
                elif duration_unit == "DAYS":
                    time_limit = f"{int(duration_value)}d"
                else:
                    time_limit = f"{int(duration_value)}h"  # Default to hours
                
                hotspot_payload = {
                    "mac_address": customer.mac_address,
                    "username": customer.mac_address.replace(":", ""),
                    "password": customer.mac_address.replace(":", ""),
                    "time_limit": time_limit,
                    "bandwidth_limit": f"{plan.speed}",
                    "comment": f"Payment successful for {customer.name}",
                    "router_ip": router.ip_address,
                    "router_username": router.username,
                    "router_password": router.password,
                    "router_port": router.port,
                }
                logger.info(f"Prepared MikroTik Payload for customer {customer.id} -> Router: {router.ip_address}")
                background_tasks.add_task(call_mikrotik_bypass, hotspot_payload)
            
            return {"ResultCode": 0, "ResultDesc": "Payment processed successfully"}
        
        else:
            logger.info(f"Payment failed for customer {customer.id}")
            customer.status = CustomerStatus.INACTIVE
            await db.commit()
            return {"ResultCode": 0, "ResultDesc": "Payment failed"}
            
    except Exception as e:
        logger.error(f"Error processing M-Pesa callback: {str(e)}")
        return {"ResultCode": 1, "ResultDesc": f"Error: {str(e)}"}

async def call_mikrotik_bypass(hotspot_payload: dict):
    try:
        # Use router-specific credentials from payload, fallback to global settings
        router_ip = hotspot_payload.get("router_ip", settings.MIKROTIK_HOST)
        router_username = hotspot_payload.get("router_username", settings.MIKROTIK_USERNAME)
        router_password = hotspot_payload.get("router_password", settings.MIKROTIK_PASSWORD)
        router_port = hotspot_payload.get("router_port", settings.MIKROTIK_PORT)
        
        logger.info(f"Connecting to MikroTik router at {router_ip}:{router_port}")
        
        api = MikroTikAPI(
            router_ip,
            router_username,
            router_password,
            router_port
        )

        if not api.connect():
            logger.error(f"Failed to connect to MikroTik router at {router_ip}")
            return

        result = api.add_customer_bypass_mode(
            hotspot_payload["mac_address"],
            hotspot_payload["username"],
            hotspot_payload["password"],
            hotspot_payload["time_limit"],
            hotspot_payload["bandwidth_limit"],
            hotspot_payload["comment"],
            router_ip,
            router_username,
            router_password
        )

        logger.info(f"MikroTik API Response: {json.dumps(result, indent=2)}")
        
        # If queue wasn't created (client not connected), retry after delay
        queue_result = result.get("queue_result", {})
        if queue_result and queue_result.get("pending"):
            logger.info(f"Queue pending for {hotspot_payload['mac_address']}, will retry in 5 seconds...")
            await asyncio.sleep(5)
            
            if not api.connected:
                api.connect()
            
            if api.connected:
                normalized_mac = normalize_mac_address(hotspot_payload["mac_address"])
                username = normalized_mac.replace(":", "")
                rate_limit = api._parse_speed_to_mikrotik(hotspot_payload["bandwidth_limit"])
                
                # Try to find client IP now
                client_ip = api.get_client_ip_by_mac(normalized_mac)
                
                if client_ip:
                    # Create simple queue (no interface = matches all)
                    retry_result = api.send_command("/queue/simple/add", {
                        "name": f"plan_{username}",
                        "target": f"{client_ip}/32",
                        "max-limit": rate_limit,
                        "comment": f"MAC:{hotspot_payload['mac_address']}|Plan rate limit"
                    })
                    logger.info(f"[RETRY] Queue created for {username} -> {client_ip}: {retry_result}")
                else:
                    logger.warning(f"[RETRY] Still no IP for {hotspot_payload['mac_address']} - queue will be synced later")
        
        api.disconnect()
    except Exception as e:
        logger.error(f"Error while processing MikroTik bypass: {e}")

# MAC address registration endpoint (NO JWT REQUIRED - for guests)
@app.post("/api/clients/mac-register/{router_id}")
async def register_mac_address(
    router_id: int,
    registration: Dict[str, str],
    db: AsyncSession = Depends(get_db)
):
    """
    Register a MAC address for hotspot access.
    This endpoint is for guest users, so no authentication required.
    Router ID is used to associate the registration with the router owner.

    Expected payload:
    {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "time_limit": "24h" or "7d" (optional),
        "bandwidth_limit": "1M/2M" (optional)
    }
    """
    # First, verify the router exists and get its details
    router = await get_router_by_id(db, router_id)
    if not router:
        logger.warning(f"Registration attempt on non-existent router ID: {router_id}")
        raise HTTPException(status_code=404, detail="Router not found")

    # Validate MAC address
    mac_address = registration.get("mac_address")
    if not mac_address or not validate_mac_address(mac_address):
        logger.warning(f"Invalid MAC address format: {mac_address}")
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    # Connect to the router using router-specific credentials
    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        # Check if MAC address is already registered
        existing_users = api.send_command("/ip/hotspot/user/print")
        if existing_users.get("success") and existing_users.get("data"):
            for user in existing_users["data"]:
                if user.get("name", "").upper() == username.upper():
                    logger.warning(f"MAC address {normalized_mac} already registered on router {router.name}")
                    raise HTTPException(status_code=409, detail="MAC address already registered")

        # Prepare user arguments - use rate-limited profile if bandwidth_limit provided
        bandwidth_limit = registration.get("bandwidth_limit")
        profile_name = "default"
        if bandwidth_limit:
            # Create/update rate-limited profile
            rate_limit = api._parse_speed_to_mikrotik(bandwidth_limit)
            profile_name = f"plan_{rate_limit.replace('/', '_')}"
            api._ensure_hotspot_profile(profile_name, rate_limit)
        
        args = {
            "name": username,
            "password": username,
            "profile": profile_name,
            "disabled": "no"
        }

        # Handle time limit if provided
        expires_at = None
        if registration.get("time_limit"):
            args["limit-uptime"] = registration["time_limit"]
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

            # Add router owner info to comment for tracking
            comment = f"MAC: {normalized_mac} | Router: {router.name} | Owner: {router.user_id} | Guest"
            if expires_at:
                comment += f" | Expires: {expires_at.strftime('%Y-%m-%d %H:%M')}"
            args["comment"] = comment
        else:
            # Add router owner info even without time limit
            args["comment"] = f"MAC: {normalized_mac} | Router: {router.name} | Owner: {router.user_id} | Guest"

        # Create hotspot user
        result = api.send_command("/ip/hotspot/user/add", args)
        if "error" in result:
            logger.error(f"Failed to create hotspot user: {result['error']}")
            raise HTTPException(status_code=400, detail=result["error"])

        # Add IP binding for seamless access (bypassed = no login required)
        binding_args = {
            "mac-address": normalized_mac,
            "type": "bypassed",
            "comment": f"Auto-registered: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} | Router: {router.name} | Guest"
        }
        binding_result = api.send_command("/ip/hotspot/ip-binding/add", binding_args)
        if "error" in binding_result and "already exists" in binding_result.get("error", ""):
            # Update existing binding to bypassed
            bindings = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings.get("success") and bindings.get("data"):
                for b in bindings["data"]:
                    if normalize_mac_address(b.get("mac-address", "")) == normalized_mac:
                        api.send_command("/ip/hotspot/ip-binding/set", {
                            "numbers": b[".id"],
                            "type": "bypassed"
                        })
                        break

        # Handle bandwidth limit - use mangle+queue tree for MAC-based limiting
        queue_result = None
        dhcp_lease_result = None
        assigned_ip = None

        if registration.get("bandwidth_limit"):
            # Generate a consistent IP based on MAC hash
            mac_hash = int(hashlib.md5(normalized_mac.encode()).hexdigest()[:4], 16)
            assigned_ip = f"192.168.1.{100 + (mac_hash % 150)}"

            # Add DHCP lease
            dhcp_lease_args = {
                "mac-address": normalized_mac,
                "address": assigned_ip,
                "server": "defconf",
                "comment": f"Auto-assigned for {username} | Router: {router.name} | Guest"
            }
            dhcp_lease_result = api.send_command("/ip/dhcp-server/lease/add", dhcp_lease_args)

            # Add queue rule if DHCP lease was successful
            if dhcp_lease_result.get("success") and "error" not in dhcp_lease_result:
                queue_args = {
                    "name": f"queue_{username}",
                    "target": f"{assigned_ip}/32",
                    "max-limit": registration["bandwidth_limit"],
                    "comment": f"Bandwidth limit for {normalized_mac} | Router: {router.name} | Guest"
                }
                queue_result = api.send_command("/queue/simple/add", queue_args)

                if "error" in queue_result:
                    logger.warning(f"Failed to set bandwidth limit: {queue_result['error']}")
                    # Remove DHCP lease if queue creation failed
                    if dhcp_lease_result.get("data") and len(dhcp_lease_result["data"]) > 0:
                        lease_id = dhcp_lease_result["data"][0].get(".id")
                        if lease_id:
                            api.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease_id})

        # Log the registration for the router owner (for billing/tracking)
        logger.info(f"MAC {normalized_mac} registered on router {router.name} (ID: {router_id}, Owner: {router.user_id})")

        return {
            "success": True,
            "message": f"MAC address {normalized_mac} registered successfully",
            "user_details": {
                "username": username,
                "mac_address": normalized_mac,
                "router_id": router_id,
                "router_name": router.name,
                "router_owner_id": router.user_id,
                "registered_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat() if expires_at else None,
                "bandwidth_limit": registration.get("bandwidth_limit"),
                "assigned_ip": assigned_ip,
                "binding_created": binding_result.get("success", False),
                "queue_created": queue_result.get("success", False) if queue_result else False
            }
        }

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Unexpected error during MAC registration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")
    finally:
        api.disconnect()

# Public router info endpoint (no auth required)
@app.get("/api/public/router/{router_id}")
async def get_public_router_info(
    router_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get basic router information for guest users.
    This can be used by captive portals to show router/ISP details.
    """
    router = await get_router_by_id(db, router_id)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")

    # Return only public information
    return {
        "router_id": router.id,
        "router_name": router.name,
        "location": getattr(router, 'location', None),
        "isp_name": getattr(router, 'isp_name', None),
        "description": getattr(router, 'description', None),
        "contact_info": getattr(router, 'contact_info', None),
    }

# MAC registration status check (no auth required)
@app.get("/api/public/mac-status/{router_id}/{mac_address}")
async def check_mac_registration_status(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Check if a MAC address is registered on a specific router.
    Useful for captive portals to determine user status.
    """
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    router = await get_router_by_id(db, router_id)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

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

    except Exception as e:
        logger.error(f"Error checking MAC status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")
    finally:
        api.disconnect()

# Disconnect user endpoint (no auth required - for self-service)
@app.post("/api/public/disconnect/{router_id}/{mac_address}")
async def disconnect_user_session(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Disconnect a user session. Can be used for self-service logout.
    """
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    router = await get_router_by_id(db, router_id)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")

    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        # Find and disconnect active sessions
        active_sessions = api.send_command("/ip/hotspot/active/print")
        disconnected_sessions = 0

        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                if session.get("user") == username:
                    session_id = session.get(".id")
                    if session_id:
                        disconnect_result = api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                        if disconnect_result.get("success", True):  # Success if no error
                            disconnected_sessions += 1

        return {
            "success": True,
            "message": f"Disconnected {disconnected_sessions} session(s) for MAC {normalized_mac}",
            "mac_address": normalized_mac,
            "sessions_disconnected": disconnected_sessions
        }

    except Exception as e:
        logger.error(f"Error disconnecting user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Disconnect failed: {str(e)}")
    finally:
        api.disconnect()

# Router list endpoint
@app.get("/api/routers")
async def get_routers(
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """Get all routers for a user"""
    stmt = select(Router).where(Router.user_id == user_id)
    result = await db.execute(stmt)
    routers = result.scalars().all()
    return [{"id": r.id, "name": r.name, "ip_address": r.ip_address, "port": r.port} for r in routers]

# Get router users endpoint (requires auth)
@app.get("/api/routers/{router_id}/users")
async def get_router_users(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all hotspot users for a specific router"""
    user = await get_current_user(token, db)
    router = await get_router_by_id(db, router_id, user.user_id, user.role)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        users_result = api.send_command("/ip/hotspot/user/print")
        active_sessions_result = api.send_command("/ip/hotspot/active/print")

        users = []
        active_sessions = {}

        # Build active sessions map
        if active_sessions_result.get("success") and active_sessions_result.get("data"):
            for session in active_sessions_result["data"]:
                username = session.get("user")
                if username:
                    active_sessions[username] = session

        # Build users list
        if users_result.get("success") and users_result.get("data"):
            for user in users_result["data"]:
                username = user.get("name", "")
                user_info = {
                    "username": username,
                    "profile": user.get("profile", ""),
                    "disabled": user.get("disabled") == "true",
                    "comment": user.get("comment", ""),
                    "uptime_limit": user.get("limit-uptime", ""),
                    "active": username in active_sessions
                }

                # Add session info if active
                if username in active_sessions:
                    session = active_sessions[username]
                    user_info["session"] = {
                        "address": session.get("address"),
                        "login_time": session.get("login-time"),
                        "uptime": session.get("uptime"),
                        "bytes_in": session.get("bytes-in"),
                        "bytes_out": session.get("bytes-out")
                    }

                users.append(user_info)

        return {
            "router_id": router_id,
            "router_name": router.name,
            "users": users,
            "total_users": len(users),
            "active_sessions": len(active_sessions)
        }

    except Exception as e:
        logger.error(f"Error getting router users: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get users: {str(e)}")
    finally:
        api.disconnect()




@app.delete("/api/routers/{router_id}/users/{username}")
async def remove_router_user(
    router_id: int,
    username: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Remove a hotspot user from router"""
    user = await get_current_user(token, db)
    router = await get_router_by_id(db, router_id, user.user_id, user.role)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        # First disconnect any active sessions
        active_sessions = api.send_command("/ip/hotspot/active/print")
        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                if session.get("user") == username:
                    session_id = session.get(".id")
                    if session_id:
                        api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})

        # Remove the user
        users_result = api.send_command("/ip/hotspot/user/print")
        user_id = None

        if users_result.get("success") and users_result.get("data"):
            for user in users_result["data"]:
                if user.get("name") == username:
                    user_id = user.get(".id")
                    break

        if not user_id:
            raise HTTPException(status_code=404, detail="User not found")

        remove_result = api.send_command("/ip/hotspot/user/remove", {"numbers": user_id})

        if "error" in remove_result:
            raise HTTPException(status_code=400, detail=remove_result["error"])

        # Also remove IP bindings and queues if they exist
        # Convert username back to MAC format for cleanup
        if len(username) == 12 and username.isalnum():
            mac_address = ':'.join(username[i:i+2] for i in range(0, 12, 2))

            # Remove IP bindings
            bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings_result.get("success") and bindings_result.get("data"):
                for binding in bindings_result["data"]:
                    if binding.get("mac-address", "").upper() == mac_address.upper():
                        binding_id = binding.get(".id")
                        if binding_id:
                            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})

            # Remove queues
            queues_result = api.send_command("/queue/simple/print")
            if queues_result.get("success") and queues_result.get("data"):
                for queue in queues_result["data"]:
                    if queue.get("name") == f"queue_{username}":
                        queue_id = queue.get(".id")
                        if queue_id:
                            api.send_command("/queue/simple/remove", {"numbers": queue_id})

        return {
            "success": True,
            "message": f"User {username} removed successfully",
            "username": username,
            "router_id": router_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to remove user: {str(e)}")
    finally:
        api.disconnect()

# Router stats endpoint (requires auth)
@app.get("/api/router_stats/{router_id}")
async def get_router_stats(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get router statistics and active users"""
    user = await get_current_user(token, db)
    router = await get_router_by_id(db, router_id, user.user_id, user.role)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        # Get hotspot users
        users_result = api.send_command("/ip/hotspot/user/print")
        total_users = 0
        if users_result.get("success") and users_result.get("data"):
            total_users = len(users_result["data"])

        # Get active sessions
        active_sessions_result = api.send_command("/ip/hotspot/active/print")
        active_sessions = 0
        active_users = []

        if active_sessions_result.get("success") and active_sessions_result.get("data"):
            active_sessions = len(active_sessions_result["data"])
            for session in active_sessions_result["data"]:
                active_users.append({
                    "username": session.get("user"),
                    "address": session.get("address"),
                    "login_time": session.get("login-time"),
                    "uptime": session.get("uptime"),
                    "bytes_in": session.get("bytes-in"),
                    "bytes_out": session.get("bytes-out")
                })

        # Get router system info
        system_result = api.send_command("/system/resource/print")
        system_info = {}
        if system_result.get("success") and system_result.get("data"):
            data = system_result["data"][0] if system_result["data"] else {}
            system_info = {
                "cpu_load": data.get("cpu-load"),
                "uptime": data.get("uptime"),
                "free_memory": data.get("free-memory"),
                "total_memory": data.get("total-memory"),
                "version": data.get("version"),
                "board_name": data.get("board-name")
            }

        return {
            "router_id": router_id,
            "router_name": router.name,
            "total_users": total_users,
            "active_sessions": active_sessions,
            "active_users": active_users,
            "system_info": system_info,
            "last_updated": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting router stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get router stats: {str(e)}")
    finally:
        api.disconnect()

# Sync router users endpoint (requires auth)
@app.post("/api/routers/{router_id}/sync")
async def sync_router_users_with_database(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Sync router users with database customers"""
    user = await get_current_user(token, db)
    router = await get_router_by_id(db, router_id, user.user_id, user.role)
    if not router:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    api = connect_to_router(router)
    if not api.connect():
        logger.error(f"Failed to connect to router {router.name} at {router.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    try:
        # Get all users from router
        users_result = api.send_command("/ip/hotspot/user/print")
        router_users = []
        if users_result.get("success") and users_result.get("data"):
            router_users = users_result["data"]

        # Get customers assigned to this router
        customers_result = await db.execute(
            select(Customer).where(Customer.router_id == router_id)
        )
        db_customers = customers_result.scalars().all()

        sync_report = {
            "router_users": len(router_users),
            "db_customers": len(db_customers),
            "synced": 0,
            "errors": []
        }

        # Create sets for comparison
        router_usernames = {user.get("name", "").lower() for user in router_users}
        db_usernames = {customer.username.lower() for customer in db_customers if customer.username}

        # Find mismatches
        only_in_router = router_usernames - db_usernames
        only_in_db = db_usernames - router_usernames

        sync_report["only_in_router"] = list(only_in_router)
        sync_report["only_in_db"] = list(only_in_db)
        sync_report["synced"] = len(router_usernames & db_usernames)

        return sync_report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error syncing router users: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sync failed: {str(e)}")
    finally:
        api.disconnect()

@app.delete("/api/public/remove-bypassed/{router_id}/{mac_address}")
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
    logger.info(f"[REMOVE-BYPASSED] Endpoint hit! router_id={router_id}, mac={mac_address}")
    
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    # Verify router exists
    router = await get_router_by_id(db, router_id)
    if not router:
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

@app.post("/api/admin/cleanup-inactive-users")
async def cleanup_all_inactive_users(
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """
    One-time cleanup: Remove ALL inactive users from MikroTik
    (They're already marked inactive in DB but still in MikroTik)
    """
    try:
        # Find all INACTIVE customers with MAC addresses
        stmt = select(Customer).where(
            Customer.status == CustomerStatus.INACTIVE,
            Customer.mac_address.isnot(None),
            Customer.user_id == user_id
        )
        result = await db.execute(stmt)
        inactive_customers = result.scalars().all()
        
        if not inactive_customers:
            return {
                "success": True,
                "message": "No inactive customers found",
                "removed": 0,
                "failed": 0
            }
        
        logger.info(f"[CLEANUP-ALL] Found {len(inactive_customers)} inactive customers to remove from MikroTik")
        
        removed_count = 0
        failed_count = 0
        details = []
        
        # Connect once to MikroTik
        api = MikroTikAPI(
            settings.MIKROTIK_HOST,
            settings.MIKROTIK_USERNAME,
            settings.MIKROTIK_PASSWORD,
            settings.MIKROTIK_PORT
        )
        
        if not api.connect():
            raise HTTPException(status_code=500, detail="Failed to connect to MikroTik")
        
        for customer in inactive_customers:
            try:
                normalized_mac = normalize_mac_address(customer.mac_address)
                username = normalized_mac.replace(":", "")
                
                removed = {"user": False, "bindings": 0, "queues": 0, "leases": 0}
                
                # Remove hotspot user
                users = api.send_command("/ip/hotspot/user/print")
                if users.get("success") and users.get("data"):
                    for u in users["data"]:
                        if u.get("name") == username:
                            api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                            removed["user"] = True
                            break
                
                # Remove IP bindings
                bindings = api.send_command("/ip/hotspot/ip-binding/print")
                if bindings.get("success") and bindings.get("data"):
                    for b in bindings["data"]:
                        if b.get("mac-address", "").upper() == normalized_mac.upper():
                            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                            removed["bindings"] += 1
                
                # Remove queues
                queues = api.send_command("/queue/simple/print")
                if queues.get("success") and queues.get("data"):
                    for q in queues["data"]:
                        if q.get("name") == f"queue_{username}":
                            api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                            removed["queues"] += 1
                
                # Remove DHCP leases
                leases = api.send_command("/ip/dhcp-server/lease/print")
                if leases.get("success") and leases.get("data"):
                    for l in leases["data"]:
                        if l.get("mac-address", "").upper() == normalized_mac.upper():
                            api.send_command("/ip/dhcp-server/lease/remove", {"numbers": l[".id"]})
                            removed["leases"] += 1
                
                removed_count += 1
                details.append({
                    "customer_id": customer.id,
                    "mac": normalized_mac,
                    "removed": removed
                })
                logger.info(f"[CLEANUP-ALL] Removed {customer.name} ({normalized_mac}): {removed}")
                
            except Exception as e:
                failed_count += 1
                logger.error(f"[CLEANUP-ALL] Failed to remove customer {customer.id}: {e}")
                details.append({
                    "customer_id": customer.id,
                    "mac": customer.mac_address,
                    "error": str(e)
                })
        
        api.disconnect()
        
        return {
            "success": True,
            "message": f"Cleanup complete: {removed_count} removed, {failed_count} failed",
            "total_inactive": len(inactive_customers),
            "removed": removed_count,
            "failed": failed_count,
            "details": details
        }
        
    except Exception as e:
        logger.error(f"[CLEANUP-ALL] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _cleanup_recently_expired_sync(customers_data: list, delay_ms: int = 200) -> dict:
    """
    Synchronous function to remove recently expired users from MikroTik.
    Runs in thread pool to avoid blocking. Fetches data once, then processes.
    
    Args:
        customers_data: List of {id, name, mac_address, status, expiry}
        delay_ms: Delay between removal operations in milliseconds
    """
    import time
    
    results = {
        "removed": [],
        "failed": [],
        "connected": False,
        "still_in_mikrotik": 0
    }
    
    if not customers_data:
        return results
    
    delay_sec = delay_ms / 1000.0
    
    api = MikroTikAPI(
        settings.MIKROTIK_HOST,
        settings.MIKROTIK_USERNAME,
        settings.MIKROTIK_PASSWORD,
        settings.MIKROTIK_PORT
    )
    
    if not api.connect():
        logger.error("[CLEANUP-RECENT] Failed to connect to MikroTik")
        return results
    
    results["connected"] = True
    
    try:
        # FETCH ALL DATA ONCE (reduces API calls significantly)
        logger.info("[CLEANUP-RECENT] Fetching MikroTik data...")
        time.sleep(delay_sec)
        
        all_bindings = api.send_command("/ip/hotspot/ip-binding/print")
        time.sleep(delay_sec)
        
        all_users = api.send_command("/ip/hotspot/user/print")
        time.sleep(delay_sec)
        
        all_active = api.send_command("/ip/hotspot/active/print")
        time.sleep(delay_sec)
        
        all_hosts = api.send_command("/ip/hotspot/host/print")
        time.sleep(delay_sec)
        
        all_queues = api.send_command("/queue/simple/print")
        time.sleep(delay_sec)
        
        all_leases = api.send_command("/ip/dhcp-server/lease/print")
        
        logger.info("[CLEANUP-RECENT] Data fetched, processing customers...")
        
        # Build lookup sets for faster matching
        bindings_data = all_bindings.get("data", []) if all_bindings.get("success") else []
        users_data = all_users.get("data", []) if all_users.get("success") else []
        active_data = all_active.get("data", []) if all_active.get("success") else []
        hosts_data = all_hosts.get("data", []) if all_hosts.get("success") else []
        queues_data = all_queues.get("data", []) if all_queues.get("success") else []
        leases_data = all_leases.get("data", []) if all_leases.get("success") else []
        
        for cust in customers_data:
            try:
                normalized_mac = normalize_mac_address(cust["mac_address"])
                username = normalized_mac.replace(":", "")
                
                removed = {
                    "user": False,
                    "bindings": 0,
                    "queues": 0,
                    "leases": 0,
                    "active_sessions": 0,
                    "hosts": 0,
                    "was_in_mikrotik": False
                }
                
                # 1. Remove IP bindings
                for b in bindings_data:
                    binding_mac = normalize_mac_address(b.get("mac-address", ""))
                    if binding_mac == normalized_mac:
                        api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                        removed["bindings"] += 1
                        removed["was_in_mikrotik"] = True
                        time.sleep(delay_sec)
                
                # 2. Remove hotspot user
                for u in users_data:
                    if u.get("name") == username:
                        api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                        removed["user"] = True
                        removed["was_in_mikrotik"] = True
                        time.sleep(delay_sec)
                        break
                
                # 3. Disconnect active sessions
                for session in active_data:
                    session_mac = normalize_mac_address(session.get("mac-address", ""))
                    session_user = session.get("user", "")
                    if session_mac == normalized_mac or session_user == username:
                        api.send_command("/ip/hotspot/active/remove", {"numbers": session[".id"]})
                        removed["active_sessions"] += 1
                        removed["was_in_mikrotik"] = True
                        time.sleep(delay_sec)
                
                # 4. Remove from hosts
                for host in hosts_data:
                    host_mac = normalize_mac_address(host.get("mac-address", ""))
                    if host_mac == normalized_mac:
                        api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
                        removed["hosts"] += 1
                        time.sleep(delay_sec)
                
                # 5. Remove queues
                for q in queues_data:
                    queue_name = q.get("name", "")
                    if queue_name == f"queue_{username}" or queue_name == f"plan_{username}":
                        api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                        removed["queues"] += 1
                        time.sleep(delay_sec)
                
                # 6. Remove DHCP leases
                for l in leases_data:
                    lease_mac = normalize_mac_address(l.get("mac-address", ""))
                    if lease_mac == normalized_mac:
                        api.send_command("/ip/dhcp-server/lease/remove", {"numbers": l[".id"]})
                        removed["leases"] += 1
                        time.sleep(delay_sec)
                
                if removed["was_in_mikrotik"]:
                    results["still_in_mikrotik"] += 1
                
                results["removed"].append({
                    "id": cust["id"],
                    "name": cust["name"],
                    "mac": normalized_mac,
                    "db_status": cust["status"],
                    "expiry": cust["expiry"],
                    "details": removed
                })
                logger.info(f"[CLEANUP-RECENT] ✓ {cust['name']} ({normalized_mac}): {removed}")
                
            except Exception as e:
                results["failed"].append({
                    "id": cust["id"],
                    "name": cust["name"],
                    "error": str(e)
                })
                logger.error(f"[CLEANUP-RECENT] ✗ {cust['name']}: {e}")
        
    except Exception as e:
        logger.error(f"[CLEANUP-RECENT] Error during processing: {e}")
    finally:
        api.disconnect()
    
    return results


@app.post("/api/admin/cleanup-recently-expired")
async def cleanup_recently_expired_users(
    hours: int = 12,
    user_id: int = 1,
    delay_ms: int = 200,
    db: AsyncSession = Depends(get_db)
):
    """
    Remove users expired in the last N hours from MikroTik, regardless of DB status.
    Non-blocking: runs MikroTik operations in thread pool with delays between requests.
    
    Args:
        hours: Look back period (default 12 hours)
        user_id: Reseller ID
        delay_ms: Delay between MikroTik API calls in milliseconds (default 200ms)
    """
    try:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)
        
        # Find customers expired in the last N hours (ANY status - ACTIVE or INACTIVE)
        stmt = select(Customer).where(
            Customer.expiry.isnot(None),
            Customer.expiry >= cutoff,
            Customer.expiry <= now,
            Customer.mac_address.isnot(None),
            Customer.user_id == user_id
        )
        result = await db.execute(stmt)
        expired_customers = result.scalars().all()
        
        if not expired_customers:
            return {
                "success": True,
                "message": f"No customers expired in the last {hours} hours",
                "total_expired": 0,
                "processed": 0,
                "failed": 0,
                "still_active_in_mikrotik": 0
            }
        
        logger.info(f"[CLEANUP-RECENT] Found {len(expired_customers)} customers expired in last {hours}h")
        
        # Prepare data for sync function (can't pass ORM objects to thread)
        customers_data = [
            {
                "id": c.id,
                "name": c.name,
                "mac_address": c.mac_address,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None
            }
            for c in expired_customers
        ]
        
        # Run MikroTik operations in thread pool (non-blocking!)
        mikrotik_results = await asyncio.to_thread(
            _cleanup_recently_expired_sync,
            customers_data,
            delay_ms
        )
        
        if not mikrotik_results["connected"]:
            raise HTTPException(status_code=500, detail="Failed to connect to MikroTik")
        
        return {
            "success": True,
            "message": f"Cleanup complete for last {hours} hours",
            "total_expired": len(expired_customers),
            "processed": len(mikrotik_results["removed"]),
            "failed": len(mikrotik_results["failed"]),
            "still_active_in_mikrotik": mikrotik_results["still_in_mikrotik"],
            "details": mikrotik_results["removed"],
            "errors": mikrotik_results["failed"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[CLEANUP-RECENT] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/public/cleanup-blocked-bindings")
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
            settings.MIKROTIK_PORT
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

@app.post("/api/public/sync-queue/{customer_id}")
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
        
        # Connect to MikroTik
        api = MikroTikAPI(
            settings.MIKROTIK_HOST,
            settings.MIKROTIK_USERNAME,
            settings.MIKROTIK_PASSWORD,
            settings.MIKROTIK_PORT
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

# ============================================
# REST API ENDPOINTS FOR CRUD OPERATIONS
# ============================================

# User Management Endpoints
class UserRegisterRequest(BaseModel):
    email: str
    password: str
    role: str
    organization_name: str

@app.post("/api/users/register")
async def register_user_api(
    request: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user (admin or reseller)"""
    try:
        from app.services.auth import create_user
        from app.db.models import UserRole
        
        # Validate role
        try:
            role_enum = UserRole(request.role.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'reseller'")
        
        # Check if user already exists
        existing_user_stmt = select(User).filter(User.email == request.email.lower())
        existing_result = await db.execute(existing_user_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="User with this email already exists")
        
        user = await create_user(db, request.email, request.password, role_enum, request.organization_name)
        
        return {
            "id": user.id,
            "email": user.email,
            "user_code": user.user_code,
            "role": user.role.value,
            "organization_name": user.organization_name,
            "created_at": user.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/auth/login")
async def login_api(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login and get JWT token"""
    try:
        from app.services.auth import authenticate_user
        from app.core.security import create_access_token
        
        user = await authenticate_user(db, request.email, request.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        # Create JWT token
        token_data = {
            "user_code": user.user_code,
            "user_id": user.id,
            "role": user.role.value,
            "organization_name": user.organization_name
        }
        access_token = create_access_token(token_data)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role.value,
                "organization_name": user.organization_name
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

# Router Management Endpoints
class RouterCreateRequest(BaseModel):
    name: str
    identity: Optional[str] = None  # MikroTik system identity (for frontend lookup)
    ip_address: str
    username: str
    password: str
    port: int = 8728
    user_id: int = 1  # Default to user_id 1 for testing (REMOVE IN PRODUCTION)

@app.post("/api/routers/create")
async def create_router_api(
    request: RouterCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new router (authentication temporarily disabled for testing)"""
    try:
        # Check if router with same IP already exists for this user
        existing_router_stmt = select(Router).filter(
            Router.ip_address == request.ip_address,
            Router.user_id == request.user_id
        )
        existing_result = await db.execute(existing_router_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Router with this IP address already exists")
        
        # Create new router
        router = Router(
            user_id=request.user_id,
            name=request.name,
            identity=request.identity,
            ip_address=request.ip_address,
            username=request.username,
            password=request.password,
            port=request.port
        )
        
        db.add(router)
        await db.commit()
        await db.refresh(router)
        
        logger.info(f"Router created: {router.id} by user {request.user_id}")
        
        return {
            "id": router.id,
            "name": router.name,
            "identity": router.identity,
            "ip_address": router.ip_address,
            "username": router.username,
            "port": router.port,
            "user_id": router.user_id,
            "created_at": router.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create router: {str(e)}")

@app.get("/api/routers/by-identity/{identity}")
async def get_router_by_identity(
    identity: str,
    db: AsyncSession = Depends(get_db)
):
    """Lookup router by MikroTik system identity (for frontend captive portal)"""
    stmt = select(Router).where(Router.identity == identity)
    result = await db.execute(stmt)
    router = result.scalar_one_or_none()
    
    if not router:
        raise HTTPException(status_code=404, detail=f"Router with identity '{identity}' not found")
    
    return {
        "router_id": router.id,
        "name": router.name,
        "identity": router.identity,
        "user_id": router.user_id
    }

class RouterIdentityUpdate(BaseModel):
    identity: str

@app.put("/api/routers/{router_id}/identity")
async def update_router_identity(
    router_id: int,
    request: RouterIdentityUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update router's MikroTik system identity"""
    stmt = select(Router).where(Router.id == router_id)
    result = await db.execute(stmt)
    router = result.scalar_one_or_none()
    
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    
    # Check if identity already exists on another router
    existing_stmt = select(Router).where(Router.identity == request.identity, Router.id != router_id)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Identity already assigned to another router")
    
    router.identity = request.identity
    await db.commit()
    
    return {
        "id": router.id,
        "name": router.name,
        "identity": router.identity,
        "message": "Identity updated successfully"
    }

@app.post("/api/routers/{router_id}/cleanup-expired")
async def cleanup_expired_customers_for_router(
    router_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Manually trigger cleanup of expired customers for a specific router.
    Removes expired users from MikroTik and marks them as INACTIVE in database.
    """
    try:
        # Verify router exists
        router = await get_router_by_id(db, router_id)
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        
        now = datetime.utcnow()
        
        # Find expired customers for this router
        stmt = select(Customer).where(
            Customer.router_id == router_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry.isnot(None),
            Customer.expiry <= now,
            Customer.mac_address.isnot(None)
        )
        
        result = await db.execute(stmt)
        expired_customers = result.scalars().all()
        
        if not expired_customers:
            return {
                "success": True,
                "message": "No expired customers found for this router",
                "router_id": router_id,
                "router_name": router.name,
                "cleaned_up": 0
            }
        
        # Prepare data for sync cleanup
        router_customers_map = {
            f"{router.ip_address}:{router.port}": {
                "router": {
                    "ip": router.ip_address,
                    "username": router.username,
                    "password": router.password,
                    "port": router.port,
                    "name": router.name
                },
                "customers": [
                    {
                        "id": c.id,
                        "name": c.name,
                        "mac_address": c.mac_address,
                        "expiry": c.expiry
                    }
                    for c in expired_customers
                ]
            }
        }
        
        # Run cleanup in thread pool
        mikrotik_results = await asyncio.to_thread(_cleanup_customer_from_mikrotik_sync, router_customers_map)
        
        # Update database
        successful_ids = [r["id"] for r in mikrotik_results["removed"]]
        for customer in expired_customers:
            if customer.id in successful_ids:
                customer.status = CustomerStatus.INACTIVE
        
        await db.commit()
        
        return {
            "success": True,
            "message": f"Cleanup completed for router {router.name}",
            "router_id": router_id,
            "router_name": router.name,
            "expired_found": len(expired_customers),
            "cleaned_up": len(mikrotik_results["removed"]),
            "failed": len(mikrotik_results["failed"]),
            "details": mikrotik_results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cleaning up router {router_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

# Plan Management Endpoints
class PlanCreateRequest(BaseModel):
    name: str
    speed: str
    price: int
    duration_value: int
    duration_unit: str
    connection_type: str
    router_profile: Optional[str] = None
    user_id: int = 1  # Default to user_id 1 for testing (REMOVE IN PRODUCTION)

@app.post("/api/plans/create")
async def create_plan_api(
    request: PlanCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new internet plan (authentication temporarily disabled for testing)"""
    try:
        # user = await get_current_user(token, db)  # Temporarily disabled for testing
        
        # Validate price and duration
        if request.price < 0:
            raise HTTPException(status_code=400, detail="Price cannot be negative")
        if request.duration_value < 1:
            raise HTTPException(status_code=400, detail="Duration value must be at least 1")
        
        # Validate connection type
        try:
            connection_type_enum = ConnectionType(request.connection_type.lower())
        except ValueError:
            valid_types = [ct.value for ct in ConnectionType]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid connection type. Must be one of: {', '.join(valid_types)}"
            )
        
        # Validate duration unit
        try:
            from app.db.models import DurationUnit
            duration_unit_enum = DurationUnit(request.duration_unit.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid duration unit. Must be 'DAYS' or 'HOURS'"
            )
        
        # Check for duplicate plan name
        existing_plan_stmt = select(Plan).filter(
            Plan.name == request.name,
            Plan.user_id == request.user_id
        )
        existing_result = await db.execute(existing_plan_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Plan with this name already exists")
        
        # Create new plan
        plan = Plan(
            name=request.name,
            speed=request.speed,
            price=request.price,
            duration_value=request.duration_value,
            duration_unit=duration_unit_enum,
            connection_type=connection_type_enum,
            user_id=request.user_id,
            router_profile=request.router_profile
        )
        
        db.add(plan)
        await db.commit()
        await db.refresh(plan)
        
        # Invalidate plan cache after creating new plan
        await invalidate_plan_cache()
        
        logger.info(f"Plan created: {plan.id} by user {request.user_id}")
        
        return {
            "id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "price": plan.price,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "connection_type": plan.connection_type.value,
            "router_profile": plan.router_profile,
            "user_id": plan.user_id,
            "created_at": plan.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create plan: {str(e)}")

@app.get("/api/plans")
async def get_plans_api(
    user_id: Optional[int] = None,
    connection_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get all plans with optional filters (user_id, connection_type) - CACHED"""
    try:
        return await get_plans_cached(db, user_id, connection_type)
    except Exception as e:
        logger.error(f"Error fetching plans: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch plans")

class PlanUpdateRequest(BaseModel):
    name: Optional[str] = None
    speed: Optional[str] = None
    price: Optional[int] = None
    duration_value: Optional[int] = None
    duration_unit: Optional[str] = None
    connection_type: Optional[str] = None
    router_profile: Optional[str] = None

@app.put("/api/plans/{plan_id}")
async def update_plan_api(
    plan_id: int,
    request: PlanUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing plan"""
    try:
        stmt = select(Plan).where(Plan.id == plan_id)
        result = await db.execute(stmt)
        plan = result.scalar_one_or_none()
        
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Update fields if provided
        if request.name is not None:
            plan.name = request.name
        if request.speed is not None:
            plan.speed = request.speed
        if request.price is not None:
            plan.price = request.price
        if request.duration_value is not None:
            plan.duration_value = request.duration_value
        if request.duration_unit is not None:
            try:
                from app.db.models import DurationUnit
                plan.duration_unit = DurationUnit(request.duration_unit.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid duration_unit. Must be MINUTES, HOURS, or DAYS")
        if request.connection_type is not None:
            try:
                plan.connection_type = ConnectionType(request.connection_type.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid connection_type")
        if request.router_profile is not None:
            plan.router_profile = request.router_profile
        
        await db.commit()
        await db.refresh(plan)
        await invalidate_plan_cache()
        
        logger.info(f"Plan {plan_id} updated: duration_value={plan.duration_value}, duration_unit={plan.duration_unit.value}")
        
        return {
            "id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "price": plan.price,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "connection_type": plan.connection_type.value,
            "router_profile": plan.router_profile
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update plan: {str(e)}")

# Customer Management Endpoints
class CustomerRegisterRequest(BaseModel):
    name: str
    phone: str
    plan_id: int
    router_id: int
    mac_address: Optional[str] = None
    pppoe_username: Optional[str] = None
    pppoe_password: Optional[str] = None
    static_ip: Optional[str] = None
    user_id: int = 1  # Default to user_id 1 for testing (REMOVE IN PRODUCTION)

class HotspotPaymentRequest(BaseModel):
    phone: str
    plan_id: int
    mac_address: str
    router_id: int
    name: Optional[str] = None
    payment_method: str = "mobile_money"  # mobile_money or cash
    payment_reference: Optional[str] = None

class InitiateMpesaPaymentRequest(BaseModel):
    customer_id: int
    amount: float
    phone: str

@app.post("/api/mpesa/initiate-payment")
async def initiate_mpesa_payment_api(
    request: InitiateMpesaPaymentRequest,
    db: AsyncSession = Depends(get_db)
):
    """Initiate M-Pesa payment for existing customer"""
    try:
        from app.services.mpesa import initiate_stk_push
        from app.services.mpesa_transactions import save_mpesa_transaction, link_transaction_to_customer
        
        # Validate input parameters
        if request.amount <= 0:
            raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
        
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")
        
        # Validate customer exists
        stmt = select(Customer).where(Customer.id == request.customer_id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        reference = f"PAYMENT-{request.customer_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        stk_response = await initiate_stk_push(
            phone_number=request.phone,
            amount=request.amount,
            reference=reference,
            user_id=customer.user_id,
            mac_address=customer.mac_address
        )
        
        if not stk_response:
            raise HTTPException(status_code=400, detail="Failed to initiate mobile money payment. Please try again.")
        
        # Save transaction to database
        transaction = await save_mpesa_transaction(
            db=db,
            checkout_request_id=stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            phone_number=request.phone,
            amount=request.amount,
            reference=reference,
            merchant_request_id=stk_response.get("merchantRequestId") or stk_response.get("merchant_request_id")
        )
        
        # Link transaction to customer
        await link_transaction_to_customer(
            db=db,
            checkout_request_id=stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            customer_id=request.customer_id
        )
        
        logger.info(f"STK Push initiated for customer {request.customer_id}, checkout_request_id: {stk_response.get('checkoutRequestId')}")
        
        return {
            "message": "Mobile money payment initiated successfully. Please check your phone to complete payment.",
            "checkout_request_id": stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            "customer_id": request.customer_id,
            "status": "PENDING"
        }
        
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error initiating M-Pesa payment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate payment: {str(e)}")

@app.post("/api/hotspot/register-and-pay")
async def register_hotspot_and_pay_api(
    request: HotspotPaymentRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register guest hotspot user and initiate payment"""
    try:
        from app.services.mpesa import initiate_stk_push
        from app.services.reseller_payments import record_customer_payment
        from app.db.models import PaymentMethod
        
        # Validate payment method
        try:
            payment_method_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            valid_methods = [method.value for method in PaymentMethod]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
            )
        
        # Validate router exists and get user_id
        router_stmt = select(Router).where(Router.id == request.router_id)
        router_result = await db.execute(router_stmt)
        router = router_result.scalar_one_or_none()
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        user_id = router.user_id
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        # Validate phone number
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")

        # Check if customer exists by MAC
        customer_stmt = select(Customer).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).where(Customer.mac_address == request.mac_address)
        customer_result = await db.execute(customer_stmt)
        existing_customer = customer_result.scalar_one_or_none()
        if existing_customer:
            # Store intended change in pending_update_data
            pending_data = {
                "requested_at": datetime.utcnow().isoformat(),
                "plan_id": request.plan_id,
                "plan_name": plan.name,
                "duration_value": plan.duration_value,
                "duration_unit": plan.duration_unit.value,
                "payment_method": payment_method_enum.value,
                "router_id": request.router_id,
                "phone": request.phone,
                "name": request.name,
                "requested_by_user_id": user_id
            }
            existing_customer.pending_update_data = json.dumps(pending_data)
            existing_customer.status = CustomerStatus.PENDING if payment_method_enum == PaymentMethod.MOBILE_MONEY else CustomerStatus.ACTIVE
            existing_customer.router_id = request.router_id  # Update router_id
            existing_customer.plan_id = request.plan_id      # Update plan_id
            if request.name:
                existing_customer.name = request.name
            existing_customer.phone = request.phone
            customer = existing_customer
            await db.flush()
        else:
            # Create new customer
            customer_name = request.name if request.name else f"Guest {request.phone[-4:]}"
            customer = Customer(
                name=customer_name,
                phone=request.phone,
                mac_address=request.mac_address,
                status=CustomerStatus.INACTIVE,
                plan_id=request.plan_id,
                user_id=user_id,
                router_id=request.router_id
            )
            db.add(customer)
            await db.flush()
        
        if payment_method_enum == PaymentMethod.MOBILE_MONEY:
            try:
                reference = f"HOTSPOT-{customer.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                
                # Initiate STK push and get response
                stk_response = await initiate_stk_push(
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference
                )
                
                # Store transaction mapping for callback lookup
                from app.db.models import MpesaTransaction, MpesaTransactionStatus
                mpesa_txn = MpesaTransaction(
                    checkout_request_id=stk_response.checkout_request_id,
                    merchant_request_id=stk_response.merchant_request_id,
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference,
                    customer_id=customer.id,
                    status=MpesaTransactionStatus.pending
                )
                db.add(mpesa_txn)
                await db.flush()
                
                # Now update status and commit
                customer.status = CustomerStatus.PENDING
                await db.commit()
                await db.refresh(customer)
                
                logger.info(f"STK Push initiated for customer {customer.id} ({request.mac_address})")
            except Exception as e:
                customer_id = getattr(customer, "id", None)
                await db.rollback()
                logger.exception("Payment initiation failed for customer %s", customer_id)
                
                raise HTTPException(status_code=400, detail=f"Mobile money payment initiation failed: {str(e)}")
        else:
            # For cash payments, process immediately
            try:
                await record_customer_payment(
                    db, customer.id, user_id, float(plan.price),
                    payment_method_enum, plan.duration_value, request.payment_reference
                )
                customer.status = CustomerStatus.ACTIVE
                await db.commit()
            except Exception as e:
                await db.rollback()
                logger.error(f"Cash payment processing failed for customer {customer.id}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")
        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "status": customer.status.value,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "message": "STK Push sent to phone" if payment_method_enum == PaymentMethod.MOBILE_MONEY else "Payment recorded successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in hotspot registration and payment")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register and initiate payment: {str(e)}")

@app.get("/api/hotspot/payment-status/{customerId}")
async def get_payment_status(
    customerId: int,
    db: AsyncSession = Depends(get_db)
):
    """Get payment status for a customer"""
    try:
        stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(Customer.id == customerId)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        return {
            "customer_id": customer.id,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_id": customer.plan_id,
            "plan_name": customer.plan.name if customer.plan else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting payment status for customer {customerId}")
        raise HTTPException(status_code=500, detail=f"Failed to get payment status: {str(e)}")

@app.post("/api/customers/register")
async def register_customer_api(
    request: CustomerRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new customer (authentication temporarily disabled for testing)"""
    try:
        # user = await get_current_user(token, db)  # Temporarily disabled for testing
        
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id, Plan.user_id == request.user_id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Validate router exists
        router_stmt = select(Router).where(Router.id == request.router_id, Router.user_id == request.user_id)
        router_result = await db.execute(router_stmt)
        router = router_result.scalar_one_or_none()
        if not router:
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
            user_id=request.user_id,
            router_id=request.router_id
        )
        
        db.add(customer)
        await db.commit()
        await db.refresh(customer)
        
        logger.info(f"Customer registered: {customer.id} by user {request.user_id}")
        
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

@app.get("/api/customers")
async def get_customers_api(
    user_id: int = 1,  # Default to user_id 1 for testing (REMOVE IN PRODUCTION)
    db: AsyncSession = Depends(get_db)
):
    """Get all customers (authentication temporarily disabled for testing)"""
    try:
        # user = await get_current_user(token, db)  # Temporarily disabled for testing
        
        stmt = select(Customer).where(Customer.user_id == user_id).options(
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

# M-Pesa Transaction Endpoints
@app.get("/api/mpesa/transactions")
async def get_mpesa_transactions(
    router_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    status: Optional[str] = None,
    user_id: int = 1,  # Default to user_id 1 for testing
    db: AsyncSession = Depends(get_db)
):
    """
    Get M-Pesa transactions with filters
    
    Query Parameters:
    - router_id: Filter by specific router (optional)
    - start_date: Start date (ISO format: 2025-10-20 or 2025-10-20T10:30:00)
    - end_date: End date (ISO format: 2025-10-21 or 2025-10-21T23:59:59)
    - status: Filter by status (pending, completed, failed, expired)
    - user_id: Owner/reseller ID (defaults to 1 for testing)
    """
    try:
        # Build base query joining transactions with customers and routers
        stmt = select(MpesaTransaction, Customer, Router, Plan).join(
            Customer, MpesaTransaction.customer_id == Customer.id, isouter=True
        ).join(
            Router, Customer.router_id == Router.id, isouter=True
        ).join(
            Plan, Customer.plan_id == Plan.id, isouter=True
        ).where(
            (Customer.user_id == user_id) | (MpesaTransaction.customer_id == None)
        )
        
        # Apply router filter
        if router_id:
            stmt = stmt.where(Router.id == router_id)
        
        # Apply date range filter
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                stmt = stmt.where(MpesaTransaction.created_at >= start_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                # If only date provided, set to end of day
                if 'T' not in end_date:
                    end_dt = end_dt.replace(hour=23, minute=59, second=59)
                stmt = stmt.where(MpesaTransaction.created_at <= end_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
        
        # Apply status filter
        if status:
            try:
                status_enum = MpesaTransactionStatus(status.lower())
                stmt = stmt.where(MpesaTransaction.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: pending, completed, failed, expired")
        
        # Order by most recent first
        stmt = stmt.order_by(MpesaTransaction.created_at.desc())
        
        result = await db.execute(stmt)
        transactions = result.all()
        
        return [
            {
                "transaction_id": tx.id,
                "checkout_request_id": tx.checkout_request_id,
                "phone_number": tx.phone_number,
                "amount": float(tx.amount),
                "reference": tx.reference,
                "lipay_tx_no": tx.lipay_tx_no,
                "status": tx.status.value,
                "mpesa_receipt_number": tx.mpesa_receipt_number,
                "transaction_date": tx.transaction_date.isoformat() if tx.transaction_date else None,
                "created_at": tx.created_at.isoformat(),
                "customer": {
                    "id": customer.id,
                    "name": customer.name,
                    "phone": customer.phone,
                    "mac_address": customer.mac_address,
                    "status": customer.status.value
                } if customer else None,
                "router": {
                    "id": router.id,
                    "name": router.name,
                    "ip_address": router.ip_address
                } if router else None,
                "plan": {
                    "id": plan.id,
                    "name": plan.name,
                    "price": plan.price,
                    "duration_value": plan.duration_value,
                    "duration_unit": plan.duration_unit.value
                } if plan else None
            }
            for tx, customer, router, plan in transactions
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching M-Pesa transactions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch transactions: {str(e)}")

@app.get("/api/mpesa/transactions/summary")
async def get_mpesa_transactions_summary(
    router_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """
    Get M-Pesa transactions summary with statistics
    
    Returns:
    - Total transactions
    - Total amount
    - Breakdown by status
    - Breakdown by router (if applicable)
    """
    try:
        from sqlalchemy import func
        
        # Build base query
        stmt = select(MpesaTransaction, Customer, Router).join(
            Customer, MpesaTransaction.customer_id == Customer.id, isouter=True
        ).join(
            Router, Customer.router_id == Router.id, isouter=True
        ).where(
            (Customer.user_id == user_id) | (MpesaTransaction.customer_id == None)
        )
        
        # Apply filters
        if router_id:
            stmt = stmt.where(Router.id == router_id)
        
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            stmt = stmt.where(MpesaTransaction.created_at >= start_dt)
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if 'T' not in end_date:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            stmt = stmt.where(MpesaTransaction.created_at <= end_dt)
        
        result = await db.execute(stmt)
        transactions = result.all()
        
        # Calculate statistics
        total_transactions = len(transactions)
        total_amount = sum(float(tx.amount) for tx, _, _ in transactions)
        
        # Breakdown by status
        status_breakdown = {}
        for tx, _, _ in transactions:
            status = tx.status.value
            if status not in status_breakdown:
                status_breakdown[status] = {"count": 0, "amount": 0}
            status_breakdown[status]["count"] += 1
            status_breakdown[status]["amount"] += float(tx.amount)
        
        # Breakdown by router
        router_breakdown = {}
        for tx, customer, router in transactions:
            if router:
                router_name = router.name
                if router_name not in router_breakdown:
                    router_breakdown[router_name] = {"count": 0, "amount": 0, "router_id": router.id}
                router_breakdown[router_name]["count"] += 1
                router_breakdown[router_name]["amount"] += float(tx.amount)
        
        return {
            "total_transactions": total_transactions,
            "total_amount": total_amount,
            "status_breakdown": status_breakdown,
            "router_breakdown": router_breakdown,
            "period": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching transaction summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch summary: {str(e)}")

@app.get("/")
def read_root():
    return {"message": "ISP Billing SaaS API", "version": "1.0.0", "updated": "2025-11-02-v2"}

@app.get("/api/test-remove/{router_id}/{mac_address}")
def test_remove_endpoint(router_id: int, mac_address: str):
    """Test endpoint to verify routing works"""
    return {
        "endpoint_hit": True,
        "router_id": router_id,
        "mac_address": mac_address,
        "message": "Endpoint is working! Route parameters received correctly."
    }

@app.api_route("/api/remove-user/{router_id}/{mac_address}", methods=["GET", "POST", "DELETE"])
async def remove_user_all_methods(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Remove expired user from MikroTik and update database status to INACTIVE
    Supports GET, POST, DELETE methods
    """
    logger.info(f"[REMOVE-USER] Endpoint hit! router_id={router_id}, mac={mac_address}")
    
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    # Verify router exists
    router = await get_router_by_id(db, router_id)
    if not router:
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

# Dashboard Overview Endpoint
@app.get("/api/dashboard/overview")
async def get_dashboard_overview(
    user_id: int = 1,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get dashboard overview with key business metrics
    
    Query params:
    - user_id: Reseller/user ID (default 1)
    - router_id: Optional router ID to filter metrics for a specific router
    
    Returns:
    - Total revenue (today, this week, this month, all time)
    - Active guests count
    - Total guests count
    - Revenue by router (or single router if router_id specified)
    - Revenue by plan
    - Recent transactions
    """
    try:
        from sqlalchemy import func
        from datetime import date, timedelta
        
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_start = today_start - timedelta(days=now.weekday())
        month_start = datetime(now.year, now.month, 1)
        
        # Get all customers for this user (optionally filtered by router)
        customers_stmt = select(Customer).where(Customer.user_id == user_id)
        if router_id:
            customers_stmt = customers_stmt.where(Customer.router_id == router_id)
        customers_result = await db.execute(customers_stmt)
        all_customers = customers_result.scalars().all()
        
        total_customers = len(all_customers)
        active_customers = sum(1 for c in all_customers if c.status == CustomerStatus.ACTIVE)
        
        # Get revenue from customer_payments
        from app.db.models import CustomerPayment
        
        # Build base filter conditions for payments (joins through Customer for router filtering)
        if router_id:
            # When router_id is specified, join with Customer to filter by router
            # Total revenue all time
            total_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id
            )
            total_revenue_result = await db.execute(total_revenue_stmt)
            total_revenue = float(total_revenue_result.scalar() or 0)
            
            # Today's revenue
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue_result = await db.execute(today_revenue_stmt)
            today_revenue = float(today_revenue_result.scalar() or 0)
            
            # This week's revenue
            week_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= week_start
            )
            week_revenue_result = await db.execute(week_revenue_stmt)
            week_revenue = float(week_revenue_result.scalar() or 0)
            
            # This month's revenue
            month_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= month_start
            )
            month_revenue_result = await db.execute(month_revenue_stmt)
            month_revenue = float(month_revenue_result.scalar() or 0)
        else:
            # No router filter - original behavior
            # Total revenue all time
            total_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id
            )
            total_revenue_result = await db.execute(total_revenue_stmt)
            total_revenue = float(total_revenue_result.scalar() or 0)
            
            # Today's revenue
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue_result = await db.execute(today_revenue_stmt)
            today_revenue = float(today_revenue_result.scalar() or 0)
            
            # This week's revenue
            week_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= week_start
            )
            week_revenue_result = await db.execute(week_revenue_stmt)
            week_revenue = float(week_revenue_result.scalar() or 0)
            
            # This month's revenue
            month_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= month_start
            )
            month_revenue_result = await db.execute(month_revenue_stmt)
            month_revenue = float(month_revenue_result.scalar() or 0)
        
        # Revenue by router
        router_revenue_stmt = select(
            Router.id,
            Router.name,
            func.count(CustomerPayment.id).label('transaction_count'),
            func.sum(CustomerPayment.amount).label('revenue')
        ).join(
            Customer, Customer.router_id == Router.id
        ).join(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Router.user_id == user_id
        )
        if router_id:
            router_revenue_stmt = router_revenue_stmt.where(Router.id == router_id)
        router_revenue_stmt = router_revenue_stmt.group_by(Router.id, Router.name)
        
        router_revenue_result = await db.execute(router_revenue_stmt)
        router_revenue = [
            {
                "router_id": row.id,
                "router_name": row.name,
                "transaction_count": row.transaction_count,
                "revenue": float(row.revenue or 0)
            }
            for row in router_revenue_result
        ]
        
        # Revenue by plan (filtered by router if specified)
        plan_revenue_stmt = select(
            Plan.id,
            Plan.name,
            Plan.price,
            func.count(CustomerPayment.id).label('sales_count'),
            func.sum(CustomerPayment.amount).label('revenue')
        ).join(
            Customer, Customer.plan_id == Plan.id
        ).join(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Plan.user_id == user_id
        )
        if router_id:
            plan_revenue_stmt = plan_revenue_stmt.where(Customer.router_id == router_id)
        plan_revenue_stmt = plan_revenue_stmt.group_by(Plan.id, Plan.name, Plan.price)
        
        plan_revenue_result = await db.execute(plan_revenue_stmt)
        plan_revenue = [
            {
                "plan_id": row.id,
                "plan_name": row.name,
                "plan_price": row.price,
                "sales_count": row.sales_count,
                "revenue": float(row.revenue or 0)
            }
            for row in plan_revenue_result
        ]
        
        # Recent transactions (last 10)
        recent_txn_stmt = select(CustomerPayment, Customer, Plan).join(
            Customer, CustomerPayment.customer_id == Customer.id
        ).join(
            Plan, Customer.plan_id == Plan.id, isouter=True
        ).where(
            CustomerPayment.reseller_id == user_id
        )
        if router_id:
            recent_txn_stmt = recent_txn_stmt.where(Customer.router_id == router_id)
        recent_txn_stmt = recent_txn_stmt.order_by(CustomerPayment.created_at.desc()).limit(10)
        
        recent_txn_result = await db.execute(recent_txn_stmt)
        recent_transactions = [
            {
                "payment_id": payment.id,
                "amount": float(payment.amount),
                "customer_name": customer.name,
                "customer_phone": customer.phone,
                "plan_name": plan.name if plan else None,
                "payment_date": payment.created_at.isoformat(),
                "payment_method": payment.payment_method.value
            }
            for payment, customer, plan in recent_txn_result
        ]
        
        # Expiring soon (next 24 hours)
        expiring_soon_date = now + timedelta(hours=24)
        expiring_stmt = select(Customer).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry.isnot(None),
            Customer.expiry <= expiring_soon_date,
            Customer.expiry > now
        )
        if router_id:
            expiring_stmt = expiring_stmt.where(Customer.router_id == router_id)
        expiring_stmt = expiring_stmt.order_by(Customer.expiry)
        
        expiring_result = await db.execute(expiring_stmt)
        expiring_soon = [
            {
                "customer_id": c.id,
                "customer_name": c.name,
                "customer_phone": c.phone,
                "mac_address": c.mac_address,
                "expiry": c.expiry.isoformat(),
                "hours_remaining": (c.expiry - now).total_seconds() / 3600
            }
            for c in expiring_result.scalars().all()
        ]
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "revenue": {
                "today": today_revenue,
                "this_week": week_revenue,
                "this_month": month_revenue,
                "all_time": total_revenue
            },
            "customers": {
                "total": total_customers,
                "active": active_customers,
                "inactive": total_customers - active_customers
            },
            "revenue_by_router": router_revenue,
            "revenue_by_plan": plan_revenue,
            "recent_transactions": recent_transactions,
            "expiring_soon": expiring_soon,
            "generated_at": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching dashboard overview: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch dashboard: {str(e)}")

@app.get("/api/dashboard/analytics")
async def get_dashboard_analytics(
    user_id: int = 1,
    router_id: Optional[int] = None,
    days: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    preset: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Comprehensive analytics endpoint with flexible filtering.
    
    Query params (priority: start_date/end_date > preset > days):
    - router_id: Optional router ID to filter analytics for a specific router
    - start_date: YYYY-MM-DD (inclusive)
    - end_date: YYYY-MM-DD (inclusive, defaults to today)
    - preset: today, yesterday, this_week, last_week, this_month, last_month, 
              this_year, last_7_days, last_30_days, last_90_days, all_time
    - days: Number of days back from today (default 7, kept for backward compatibility)
    """
    try:
        import asyncio
        import concurrent.futures
        from sqlalchemy import extract, case, distinct, func
        from collections import defaultdict
        
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        today_end = today_start + timedelta(days=1)
        
        # Determine date range based on params (priority: dates > preset > days)
        if start_date or end_date:
            try:
                filter_start = datetime.strptime(start_date, "%Y-%m-%d") if start_date else today_start
                filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) if end_date else today_end
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
            period_label = f"{start_date or 'start'} to {end_date or 'today'}"
            period_days = (filter_end - filter_start).days
        elif preset:
            presets = {
                "today": (today_start, today_end),
                "yesterday": (today_start - timedelta(days=1), today_start),
                "this_week": (today_start - timedelta(days=today_start.weekday()), today_end),
                "last_week": (
                    today_start - timedelta(days=today_start.weekday() + 7),
                    today_start - timedelta(days=today_start.weekday())
                ),
                "this_month": (datetime(now.year, now.month, 1), today_end),
                "last_month": (
                    datetime(now.year, now.month, 1) - timedelta(days=1),
                    datetime(now.year, now.month, 1)
                ),
                "this_year": (datetime(now.year, 1, 1), today_end),
                "last_7_days": (today_start - timedelta(days=6), today_end),
                "last_30_days": (today_start - timedelta(days=29), today_end),
                "last_90_days": (today_start - timedelta(days=89), today_end),
                "all_time": (datetime(2020, 1, 1), today_end),
            }
            # Fix last_month to get correct range
            if preset == "last_month":
                first_of_this_month = datetime(now.year, now.month, 1)
                last_month_end = first_of_this_month
                if now.month == 1:
                    last_month_start = datetime(now.year - 1, 12, 1)
                else:
                    last_month_start = datetime(now.year, now.month - 1, 1)
                presets["last_month"] = (last_month_start, last_month_end)
            
            if preset not in presets:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid preset. Choose from: {', '.join(presets.keys())}"
                )
            filter_start, filter_end = presets[preset]
            period_label = preset.replace("_", " ").title()
            period_days = (filter_end - filter_start).days
        else:
            # Default: use days param (default 7)
            days = days or 7
            filter_start = today_start - timedelta(days=days - 1)  # Include today
            filter_end = today_end
            period_label = f"Last {days} days"
            period_days = days
        
        # Build both DB queries
        payments_stmt = select(
            CustomerPayment, Customer, Plan
        ).join(
            Customer, CustomerPayment.customer_id == Customer.id
        ).outerjoin(
            Plan, Customer.plan_id == Plan.id
        ).where(
            CustomerPayment.reseller_id == user_id,
            CustomerPayment.created_at >= filter_start,
            CustomerPayment.created_at < filter_end
        )
        if router_id:
            payments_stmt = payments_stmt.where(Customer.router_id == router_id)
        payments_stmt = payments_stmt.order_by(CustomerPayment.created_at.desc())
        
        active_customers_stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        if router_id:
            active_customers_stmt = active_customers_stmt.where(Customer.router_id == router_id)
        
        # Execute DB queries sequentially (AsyncSession doesn't support concurrent operations)
        payments_result = await db.execute(payments_stmt)
        active_result = await db.execute(active_customers_stmt)
        
        all_payments = payments_result.all()
        active_customers = active_result.scalars().all()
        
        # Process payments data
        daily_data = defaultdict(lambda: {
            "transactions": [],
            "phones": set(),
            "hourly_activity": defaultdict(int),
            "hourly_revenue": defaultdict(float),
            "plan_counts": defaultdict(int),
            "plan_revenue": defaultdict(float),
            "hourly_by_plan": defaultdict(lambda: defaultdict(int)),
            "phone_totals": defaultdict(float)
        })
        
        plan_colors = {
            0: "#ef4444", 1: "#f97316", 2: "#eab308", 3: "#22c55e",
            4: "#3b82f6", 5: "#a855f7", 6: "#ec4899", 7: "#14b8a6"
        }
        
        unique_customers_set = set()
        
        for payment, customer, plan in all_payments:
            date_key = payment.created_at.strftime("%Y-%m-%d")
            hour = payment.created_at.hour
            amount = float(payment.amount)
            phone = customer.phone[-4:] if customer.phone else "unknown"
            plan_name = plan.name if plan else "Unknown"
            unique_customers_set.add(customer.id)
            
            day = daily_data[date_key]
            day["transactions"].append({
                "time": payment.created_at.strftime("%H:%M:%S"),
                "amount": amount,
                "phone": phone,
                "plan": plan_name
            })
            day["phones"].add(customer.phone)
            day["hourly_activity"][hour] += 1
            day["hourly_revenue"][hour] += amount
            day["plan_counts"][plan_name] += 1
            day["plan_revenue"][plan_name] += amount
            day["hourly_by_plan"][plan_name][hour] += 1
            day["phone_totals"][customer.phone] += amount
        
        # Build response for each day
        days_output = {}
        for date_key in sorted(daily_data.keys(), reverse=True):
            day = daily_data[date_key]
            date_obj = datetime.strptime(date_key, "%Y-%m-%d")
            
            phone_counts = defaultdict(int)
            for tx in day["transactions"]:
                phone_counts[tx["phone"]] += 1
            repeat_customers = sum(1 for c in phone_counts.values() if c > 1)
            
            purchase_counts = {"1_purchase": 0, "2_purchases": 0, "3_purchases": 0, "4plus_purchases": 0}
            for count in phone_counts.values():
                if count == 1:
                    purchase_counts["1_purchase"] += 1
                elif count == 2:
                    purchase_counts["2_purchases"] += 1
                elif count == 3:
                    purchase_counts["3_purchases"] += 1
                else:
                    purchase_counts["4plus_purchases"] += 1
            
            top_spenders = sorted(
                [{"phone": p[-4:], "amount": a} for p, a in day["phone_totals"].items()],
                key=lambda x: x["amount"],
                reverse=True
            )[:5]
            
            plans_list = []
            for idx, (plan_name, count) in enumerate(sorted(day["plan_counts"].items(), key=lambda x: x[1], reverse=True)):
                plans_list.append({
                    "name": plan_name,
                    "count": count,
                    "revenue": day["plan_revenue"][plan_name],
                    "color": plan_colors.get(idx % 8, "#6b7280")
                })
            
            total_revenue = sum(day["plan_revenue"].values())
            unique_users = len(day["phones"])
            
            cumulative_rev = 0.0
            cumulative_txn = 0
            hourly_cumulative = []
            for h in range(24):
                rev = day["hourly_revenue"].get(h, 0.0)
                txn = day["hourly_activity"].get(h, 0)
                cumulative_rev += rev
                cumulative_txn += txn
                hourly_cumulative.append({
                    "hour": h,
                    "hourLabel": f"{h:02d}:00",
                    "revenue": round(rev, 2),
                    "transactions": txn,
                    "cumulativeRevenue": round(cumulative_rev, 2),
                    "cumulativeTransactions": cumulative_txn
                })
            
            days_output[date_key] = {
                "date": date_key,
                "dateLabel": date_obj.strftime("%B %d, %Y"),
                "totalTransactions": len(day["transactions"]),
                "totalRevenue": total_revenue,
                "uniqueUsers": unique_users,
                "avgDailySpendPerUser": round(total_revenue / unique_users, 2) if unique_users > 0 else 0,
                "repeatCustomers": repeat_customers,
                "repeatCustomerPercent": round((repeat_customers / unique_users) * 100, 1) if unique_users > 0 else 0,
                "plans": plans_list,
                "hourlyActivity": dict(day["hourly_activity"]),
                "hourlyRevenue": {k: round(v, 2) for k, v in day["hourly_revenue"].items()},
                "hourlyCumulative": hourly_cumulative,
                "hourlyByPlan": {k: dict(v) for k, v in day["hourly_by_plan"].items()},
                "topSpenders": top_spenders,
                "firstTransaction": day["transactions"][-1]["time"] if day["transactions"] else None,
                "lastTransaction": day["transactions"][0]["time"] if day["transactions"] else None,
                "userPurchaseCounts": purchase_counts
            }
        
        # Calculate summary
        total_txns = sum(d["totalTransactions"] for d in days_output.values())
        total_rev = sum(d["totalRevenue"] for d in days_output.values())
        total_users = sum(d["uniqueUsers"] for d in days_output.values())
        unique_customers_count = len(unique_customers_set)
        
        daily_trend = [
            {
                "date": d["date"],
                "label": d["dateLabel"],
                "transactions": d["totalTransactions"],
                "revenue": d["totalRevenue"],
                "users": d["uniqueUsers"]
            }
            for d in sorted(days_output.values(), key=lambda x: x["date"])
        ]
        
        hourly_totals = defaultdict(lambda: {"transactions": 0, "revenue": 0.0})
        for day in days_output.values():
            for hour, count in day["hourlyActivity"].items():
                hourly_totals[hour]["transactions"] += count
            for hour, rev in day["hourlyRevenue"].items():
                hourly_totals[hour]["revenue"] += rev
        
        hourly_pattern = [
            {"hour": h, "transactions": hourly_totals[h]["transactions"], "revenue": round(hourly_totals[h]["revenue"], 2)}
            for h in range(24)
        ]
        
        plan_totals = defaultdict(lambda: {"count": 0, "revenue": 0.0})
        for day in days_output.values():
            for plan in day["plans"]:
                plan_totals[plan["name"]]["count"] += plan["count"]
                plan_totals[plan["name"]]["revenue"] += plan["revenue"]
        
        plan_performance = [
            {"name": name, "count": data["count"], "revenue": round(data["revenue"], 2)}
            for name, data in sorted(plan_totals.items(), key=lambda x: x[1]["revenue"], reverse=True)
        ]
        
        today_key = today_start.strftime("%Y-%m-%d")
        today_data = days_output.get(today_key, {})
        today_revenue = today_data.get("totalRevenue", 0)
        today_transactions = today_data.get("totalTransactions", 0)
        
        days_with_data = len(days_output) if days_output else 1
        avg_daily_revenue = round(total_rev / period_days, 2) if period_days > 0 else 0
        avg_daily_transactions = round(total_txns / period_days, 2) if period_days > 0 else 0
        avg_transaction_value = round(total_rev / total_txns, 2) if total_txns > 0 else 0
        avg_revenue_per_customer = round(total_rev / unique_customers_count, 2) if unique_customers_count > 0 else 0
        
        # Calculate speed averages from already-fetched active_customers
        total_download = 0.0
        total_upload = 0.0
        speed_count = 0
        
        for customer in active_customers:
            if customer.plan and customer.plan.speed:
                speed = customer.plan.speed
                if "/" in speed:
                    parts = speed.split("/")
                    download = _parse_speed_value(parts[0])
                    upload = _parse_speed_value(parts[1]) if len(parts) > 1 else download
                    total_download += download
                    total_upload += upload
                    speed_count += 1
        
        avg_download_mbps = round(total_download / speed_count, 2) if speed_count > 0 else 0
        avg_upload_mbps = round(total_upload / speed_count, 2) if speed_count > 0 else 0
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "extractedAt": now.isoformat(),
            "period": {
                "label": period_label,
                "days": period_days,
                "startDate": filter_start.strftime("%Y-%m-%d"),
                "endDate": (filter_end - timedelta(days=1)).strftime("%Y-%m-%d"),
            },
            "summary": {
                "totalTransactions": total_txns,
                "totalRevenue": round(total_rev, 2),
                "totalUniqueUsers": total_users,
                "uniqueCustomers": unique_customers_count,
                "avgRevenuePerDay": round(total_rev / days_with_data, 2) if days_with_data else 0,
                "avgTransactionsPerDay": round(total_txns / days_with_data, 2) if days_with_data else 0
            },
            "today": {
                "date": today_key,
                "revenue": round(today_revenue, 2),
                "transactions": today_transactions,
                "hourlyCumulative": today_data.get("hourlyCumulative", [])
            },
            "averages": {
                "dailyRevenue": avg_daily_revenue,
                "dailyTransactions": avg_daily_transactions,
                "transactionValue": avg_transaction_value,
                "revenuePerCustomer": avg_revenue_per_customer,
                "downloadSpeedMbps": avg_download_mbps,
                "uploadSpeedMbps": avg_upload_mbps
            },
            "activeCustomers": len(active_customers),
            "dailyTrend": daily_trend,
            "hourlyPattern": hourly_pattern,
            "planPerformance": plan_performance,
            "days": days_output
        }
        
    except Exception as e:
        logger.error(f"Error fetching analytics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch analytics: {str(e)}")

# Get Active Guests Endpoint
@app.get("/api/customers/active")
async def get_active_customers(
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """Get all currently active guests"""
    try:
        stmt = select(Customer).where(
            Customer.user_id == user_id,
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

# Get Plan Performance Endpoint
@app.get("/api/plans/performance")
async def get_plan_performance(
    user_id: int = 1,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get performance metrics for each plan
    
    Shows:
    - Total sales per plan
    - Revenue per plan
    - Average revenue per sale
    - Current active customers per plan
    """
    try:
        from sqlalchemy import func
        from app.db.models import CustomerPayment
        
        # Base query for plan performance
        stmt = select(
            Plan.id,
            Plan.name,
            Plan.price,
            Plan.duration_value,
            Plan.duration_unit,
            func.count(Customer.id.distinct()).label('total_customers'),
            func.count(CustomerPayment.id).label('total_sales'),
            func.sum(CustomerPayment.amount).label('total_revenue')
        ).outerjoin(
            Customer, Customer.plan_id == Plan.id
        ).outerjoin(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Plan.user_id == user_id
        )
        
        # Apply date filters if provided
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            stmt = stmt.where(CustomerPayment.created_at >= start_dt)
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if 'T' not in end_date:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            stmt = stmt.where(CustomerPayment.created_at <= end_dt)
        
        stmt = stmt.group_by(Plan.id, Plan.name, Plan.price, Plan.duration_value, Plan.duration_unit)
        
        result = await db.execute(stmt)
        
        # Get active customers per plan
        active_stmt = select(
            Plan.id,
            func.count(Customer.id).label('active_count')
        ).join(
            Customer, Customer.plan_id == Plan.id
        ).where(
            Plan.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE
        ).group_by(Plan.id)
        
        active_result = await db.execute(active_stmt)
        active_counts = {row.id: row.active_count for row in active_result}
        
        plans = []
        for row in result:
            total_revenue = float(row.total_revenue or 0)
            total_sales = row.total_sales or 0
            avg_revenue = total_revenue / total_sales if total_sales > 0 else 0
            
            plans.append({
                "plan_id": row.id,
                "plan_name": row.name,
                "plan_price": row.price,
                "duration": f"{row.duration_value} {row.duration_unit.lower()}",
                "total_customers": row.total_customers,
                "total_sales": total_sales,
                "total_revenue": total_revenue,
                "average_revenue_per_sale": round(avg_revenue, 2),
                "active_customers": active_counts.get(row.id, 0)
            })
        
        return {
            "plans": plans,
            "period": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching plan performance: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch plan performance: {str(e)}")

# Update Router Endpoint
@app.put("/api/routers/{router_id}")
async def update_router(
    router_id: int,
    request: RouterCreateRequest,
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """Update router details"""
    try:
        # Get existing router
        stmt = select(Router).where(Router.id == router_id, Router.user_id == user_id)
        result = await db.execute(stmt)
        router = result.scalar_one_or_none()
        
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        
        # Update fields
        router.name = request.name
        router.ip_address = request.ip_address
        router.username = request.username
        router.password = request.password
        router.port = request.port
        
        await db.commit()
        await db.refresh(router)
        
        return {
            "id": router.id,
            "name": router.name,
            "ip_address": router.ip_address,
            "username": router.username,
            "port": router.port,
            "user_id": router.user_id,
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating router: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update router: {str(e)}")

# Delete Plan Endpoint
@app.delete("/api/plans/{plan_id}")
async def delete_plan(
    plan_id: int,
    user_id: int = 1,
    db: AsyncSession = Depends(get_db)
):
    """Delete a plan (only if no active customers using it)"""
    try:
        from sqlalchemy import func
        
        # Check if plan exists
        plan_stmt = select(Plan).where(Plan.id == plan_id, Plan.user_id == user_id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Check for active customers using this plan
        active_stmt = select(func.count(Customer.id)).where(
            Customer.plan_id == plan_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        active_result = await db.execute(active_stmt)
        active_count = active_result.scalar()
        
        if active_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete plan. {active_count} active customer(s) are using this plan"
            )
        
        # Set plan_id to NULL for inactive/expired customers
        from sqlalchemy import update
        await db.execute(
            update(Customer).where(Customer.plan_id == plan_id).values(plan_id=None)
        )
        
        await db.delete(plan)
        await db.commit()
        
        # Invalidate plan cache after deletion
        await invalidate_plan_cache()
        
        return {
            "success": True,
            "message": f"Plan '{plan.name}' deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete plan: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# MikroTik Health and Stats Endpoints
@app.get("/api/mikrotik/health")
async def get_mikrotik_health(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get MikroTik router health metrics (CPU, memory, disk, uptime, traffic).
    
    Cached for 30 seconds per router to prevent overloading MikroTik.
    """
    global _health_cache
    
    cache_key = router_id if router_id else "default"
    
    # Check cache first
    if cache_key in _health_cache:
        cached = _health_cache[cache_key]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _health_cache_ttl:
            # Return cached data with cache info
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result
    
    try:
        # Get router by ID or use default settings
        if router_id:
            router = await get_router_by_id(db, router_id)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found")
            api = connect_to_router(router)
            router_name = router.name
        else:
            api = MikroTikAPI(
                settings.MIKROTIK_HOST,
                settings.MIKROTIK_USERNAME,
                settings.MIKROTIK_PASSWORD,
                settings.MIKROTIK_PORT
            )
            router_name = "Default Router"
        
        if not api.connect():
            # Return stale cache if available when router unreachable
            if cache_key in _health_cache:
                result = _health_cache[cache_key]["data"].copy()
                result["cached"] = True
                result["cache_age_seconds"] = (datetime.utcnow() - _health_cache[cache_key]["timestamp"]).total_seconds()
                result["stale"] = True
                return result
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        
        # Fetch all data from router
        resources = api.get_system_resources()
        health = api.get_health()
        interface_traffic = api.get_interface_traffic()
        hotspot_hosts = api.get_hotspot_hosts()
        arp_entries = api.get_arp_entries()
        dhcp_leases = api.get_dhcp_leases()
        
        api.disconnect()
        
        if resources.get("error"):
            raise HTTPException(status_code=500, detail=resources["error"])
        
        res_data = resources.get("data", {})
        total_mem = res_data.get("total_memory", 1)
        free_mem = res_data.get("free_memory", 0)
        total_hdd = res_data.get("total_hdd_space", 1)
        free_hdd = res_data.get("free_hdd_space", 0)
        
        # Process interface traffic data - include ALL interfaces
        interfaces = []
        if interface_traffic.get("success"):
            for iface in interface_traffic.get("data", []):
                interfaces.append({
                    "name": iface.get("name", ""),
                    "type": iface.get("type", ""),
                    "running": iface.get("running", False),
                    "disabled": iface.get("disabled", False),
                    "rx_bytes": iface.get("rx_byte", 0),
                    "tx_bytes": iface.get("tx_byte", 0),
                    "rx_packets": iface.get("rx_packet", 0),
                    "tx_packets": iface.get("tx_packet", 0),
                    "rx_errors": iface.get("rx_error", 0),
                    "tx_errors": iface.get("tx_error", 0)
                })
        
        # Active devices from multiple sources
        hotspot_data = hotspot_hosts if hotspot_hosts.get("success") else {}
        arp_data = arp_entries if arp_entries.get("success") else {}
        dhcp_data = dhcp_leases if dhcp_leases.get("success") else {}
        
        result = {
            "system": {
                "uptime": res_data.get("uptime", ""),
                "version": res_data.get("version", ""),
                "platform": res_data.get("platform", ""),
                "board_name": res_data.get("board_name", ""),
                "architecture": res_data.get("architecture_name", ""),
                "cpu": res_data.get("cpu", ""),
                "cpu_count": res_data.get("cpu_count", 1),
                "cpu_frequency_mhz": res_data.get("cpu_frequency", 0)
            },
            "cpu_load_percent": res_data.get("cpu_load", 0),
            "memory": {
                "total_bytes": total_mem,
                "free_bytes": free_mem,
                "used_bytes": total_mem - free_mem,
                "used_percent": round(((total_mem - free_mem) / total_mem) * 100, 1) if total_mem > 0 else 0
            },
            "storage": {
                "total_bytes": total_hdd,
                "free_bytes": free_hdd,
                "used_bytes": total_hdd - free_hdd,
                "used_percent": round(((total_hdd - free_hdd) / total_hdd) * 100, 1) if total_hdd > 0 else 0
            },
            "health_sensors": health.get("data", {}),
            "active_devices": {
                "hotspot_hosts_total": hotspot_data.get("total", 0),
                "hotspot_authorized": hotspot_data.get("authorized", 0),
                "hotspot_bypassed": hotspot_data.get("bypassed", 0),
                "arp_entries": arp_data.get("count", 0),
                "dhcp_leases_total": dhcp_data.get("total", 0),
                "dhcp_leases_active": dhcp_data.get("active", 0),
                "note": "hotspot_bypassed shows bypassed users, arp_entries shows all active network devices"
            },
            "interfaces": interfaces,
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Update cache
        _health_cache[cache_key] = {
            "data": result,
            "timestamp": datetime.utcnow()
        }
        
        result["cached"] = False
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching MikroTik health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/mikrotik")
async def get_dashboard_mikrotik():
    """Get all MikroTik data for dashboard. Cached 30s, runs in thread to not block."""
    global _mikrotik_cache
    
    # Return cached data if fresh
    if _mikrotik_cache["data"] and _mikrotik_cache["timestamp"]:
        age = (datetime.utcnow() - _mikrotik_cache["timestamp"]).total_seconds()
        if age < _mikrotik_cache_ttl:
            return _mikrotik_cache["data"]
    
    try:
        # Run in thread pool to not block async event loop
        raw = await asyncio.to_thread(_fetch_mikrotik_data_sync)
        
        if not raw:
            if _mikrotik_cache["data"]:
                return _mikrotik_cache["data"]
            raise HTTPException(status_code=503, detail="Failed to connect to MikroTik router")
        
        resources = raw["resources"]
        if resources.get("error"):
            if _mikrotik_cache["data"]:
                return _mikrotik_cache["data"]
            raise HTTPException(status_code=500, detail=resources["error"])
        
        res_data = resources.get("data", {})
        total_mem = res_data.get("total_memory", 1)
        free_mem = res_data.get("free_memory", 0)
        total_hdd = res_data.get("total_hdd_space", 1)
        free_hdd = res_data.get("free_hdd_space", 0)
        
        speed_data = raw["speed_stats"].get("data", {})
        
        result = {
            "system": {
                "uptime": res_data.get("uptime", ""),
                "version": res_data.get("version", ""),
                "platform": res_data.get("platform", ""),
                "boardName": res_data.get("board_name", ""),
                "architecture": res_data.get("architecture_name", ""),
                "cpu": res_data.get("cpu", ""),
                "cpuCount": res_data.get("cpu_count", 1),
                "cpuFrequencyMhz": res_data.get("cpu_frequency", 0)
            },
            "cpuLoadPercent": res_data.get("cpu_load", 0),
            "memory": {
                "totalBytes": total_mem,
                "freeBytes": free_mem,
                "usedBytes": total_mem - free_mem,
                "usedPercent": round(((total_mem - free_mem) / total_mem) * 100, 1) if total_mem > 0 else 0
            },
            "storage": {
                "totalBytes": total_hdd,
                "freeBytes": free_hdd,
                "usedBytes": total_hdd - free_hdd,
                "usedPercent": round(((total_hdd - free_hdd) / total_hdd) * 100, 1) if total_hdd > 0 else 0
            },
            "healthSensors": raw["health"].get("data", {}),
            "activeSessions": raw["active_sessions"].get("data", []),
            "activeSessionCount": len(raw["active_sessions"].get("data", [])),
            "interfaces": raw["traffic"].get("data", []),
            "speedStats": {
                "totalUploadMbps": speed_data.get("total_upload_mbps", 0),
                "totalDownloadMbps": speed_data.get("total_download_mbps", 0),
                "avgUploadMbps": speed_data.get("avg_upload_mbps", 0),
                "avgDownloadMbps": speed_data.get("avg_download_mbps", 0),
                "activeQueues": speed_data.get("active_queues", 0),
                "totalQueues": speed_data.get("total_queues", 0)
            },
            "generatedAt": datetime.utcnow().isoformat()
        }
        
        # Update cache
        _mikrotik_cache["data"] = result
        _mikrotik_cache["timestamp"] = datetime.utcnow()
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching dashboard MikroTik data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mikrotik/traffic")
async def get_mikrotik_traffic(
    interface: Optional[str] = None,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get MikroTik interface traffic statistics"""
    try:
        if router_id:
            router = await get_router_by_id(db, router_id)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found")
            api = connect_to_router(router)
            router_name = router.name
        else:
            api = MikroTikAPI(
                settings.MIKROTIK_HOST,
                settings.MIKROTIK_USERNAME,
                settings.MIKROTIK_PASSWORD,
                settings.MIKROTIK_PORT
            )
            router_name = "Default Router"
        
        if not api.connect():
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        
        traffic = api.get_interface_traffic(interface)
        api.disconnect()
        
        if traffic.get("error"):
            raise HTTPException(status_code=500, detail=traffic["error"])
        
        return {
            "interfaces": traffic.get("data", []),
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching MikroTik traffic: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mikrotik/active-sessions")
async def get_mikrotik_active_sessions(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get currently active hotspot sessions with traffic data"""
    try:
        if router_id:
            router = await get_router_by_id(db, router_id)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found")
            api = connect_to_router(router)
            router_name = router.name
        else:
            api = MikroTikAPI(
                settings.MIKROTIK_HOST,
                settings.MIKROTIK_USERNAME,
                settings.MIKROTIK_PASSWORD,
                settings.MIKROTIK_PORT
            )
            router_name = "Default Router"
        
        if not api.connect():
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        
        sessions = api.get_active_hotspot_users()
        api.disconnect()
        
        if sessions.get("error"):
            raise HTTPException(status_code=500, detail=sessions["error"])
        
        return {
            "sessions": sessions.get("data", []),
            "total_sessions": len(sessions.get("data", [])),
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching active sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mikrotik/bandwidth-history")
async def get_bandwidth_history(
    hours: int = 24,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical bandwidth data for graphing. Default last 24 hours.
    
    Query params:
    - hours: Number of hours of history (default 24)
    - router_id: Optional router ID to filter bandwidth history for a specific router
    """
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = select(BandwidthSnapshot).where(BandwidthSnapshot.recorded_at >= since)
        
        # Filter by router_id if provided
        if router_id:
            query = query.where(BandwidthSnapshot.router_id == router_id)
        
        result = await db.execute(query.order_by(BandwidthSnapshot.recorded_at.asc()))
        snapshots = result.scalars().all()
        
        data = []
        for s in snapshots:
            data.append({
                "timestamp": s.recorded_at.isoformat(),
                "routerId": s.router_id,
                "totalUploadMbps": round(s.total_upload_bps / 1000000, 2),
                "totalDownloadMbps": round(s.total_download_bps / 1000000, 2),
                "avgUploadMbps": round(s.avg_upload_bps / 1000000, 2),
                "avgDownloadMbps": round(s.avg_download_bps / 1000000, 2),
                "activeQueues": s.active_queues,
                "activeSessions": s.active_sessions
            })
        
        # Get router name if specified
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "history": data,
            "count": len(data),
            "periodHours": hours,
            "generatedAt": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching bandwidth history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/mikrotik/top-users")
async def get_top_bandwidth_users(
    limit: int = 10, 
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get top bandwidth users sorted by total download.
    Reads from cached DB data (updated every 2 min by background job).
    
    Query params:
    - limit: Number of top users to return (default 10)
    - router_id: Optional router ID to filter users for a specific router
    """
    try:
        # Build query with optional router filtering
        if router_id:
            # Join with Customer to filter by router
            query = select(UserBandwidthUsage).join(
                Customer, UserBandwidthUsage.customer_id == Customer.id
            ).where(
                Customer.router_id == router_id
            ).order_by(UserBandwidthUsage.download_bytes.desc()).limit(limit)
        else:
            query = select(UserBandwidthUsage).order_by(
                UserBandwidthUsage.download_bytes.desc()
            ).limit(limit)
        
        result = await db.execute(query)
        usage_records = result.scalars().all()
        
        users = []
        for u in usage_records:
            total_bytes = u.upload_bytes + u.download_bytes
            
            # Get customer info
            customer_name = None
            customer_phone = None
            customer_router_id = None
            if u.customer_id:
                cust_result = await db.execute(
                    select(Customer).where(Customer.id == u.customer_id)
                )
                customer = cust_result.scalar_one_or_none()
                if customer:
                    customer_name = customer.name
                    customer_phone = customer.phone
                    customer_router_id = customer.router_id
            
            users.append({
                "mac": u.mac_address,
                "target": u.target_ip,
                "queueName": u.queue_name,
                "uploadBytes": u.upload_bytes,
                "downloadBytes": u.download_bytes,
                "totalBytes": total_bytes,
                "uploadMB": round(u.upload_bytes / (1024 * 1024), 2),
                "downloadMB": round(u.download_bytes / (1024 * 1024), 2),
                "totalMB": round(total_bytes / (1024 * 1024), 2),
                "downloadGB": round(u.download_bytes / (1024 * 1024 * 1024), 2),
                "maxLimit": u.max_limit,
                "lastUpdated": u.last_updated.isoformat() if u.last_updated else None,
                "customerId": u.customer_id,
                "customerName": customer_name,
                "customerPhone": customer_phone,
                "routerId": customer_router_id
            })
        
        # Get total count (with optional router filter)
        if router_id:
            count_query = select(UserBandwidthUsage).join(
                Customer, UserBandwidthUsage.customer_id == Customer.id
            ).where(Customer.router_id == router_id)
        else:
            count_query = select(UserBandwidthUsage)
        count_result = await db.execute(count_query)
        total_count = len(count_result.scalars().all())
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "topUsers": users,
            "totalTracked": total_count,
            "generatedAt": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching top users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Daily Revenue Metrics Endpoint (for cumulative plotting)
@app.get("/api/dashboard/daily-revenue")
async def get_daily_revenue_metrics(
    user_id: int = 1,
    router_id: Optional[int] = None,
    date: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get hourly cumulative revenue for a specific day.
    Returns data suitable for plotting revenue accumulation throughout the day.
    
    Query params:
    - router_id: Optional router ID to filter revenue for a specific router
    - date: YYYY-MM-DD format (defaults to today)
    """
    try:
        from sqlalchemy import func, extract
        from app.db.models import CustomerPayment
        
        # Parse date or use today
        if date:
            try:
                target_date = datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
        else:
            target_date = datetime.utcnow()
        
        day_start = datetime(target_date.year, target_date.month, target_date.day)
        day_end = day_start + timedelta(days=1)
        
        # Get all payments for the day ordered by time
        if router_id:
            payments_stmt = select(
                CustomerPayment.amount,
                CustomerPayment.created_at
            ).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= day_start,
                CustomerPayment.created_at < day_end,
                Customer.router_id == router_id
            ).order_by(CustomerPayment.created_at)
        else:
            payments_stmt = select(
                CustomerPayment.amount,
                CustomerPayment.created_at
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= day_start,
                CustomerPayment.created_at < day_end
            ).order_by(CustomerPayment.created_at)
        
        result = await db.execute(payments_stmt)
        payments = result.all()
        
        # Build hourly breakdown with cumulative totals
        hourly_data = {}
        cumulative = 0.0
        transaction_count = 0
        
        for hour in range(24):
            hourly_data[hour] = {
                "hour": hour,
                "hour_label": f"{hour:02d}:00",
                "revenue": 0.0,
                "transactions": 0,
                "cumulative_revenue": 0.0,
                "cumulative_transactions": 0
            }
        
        for payment in payments:
            hour = payment.created_at.hour
            amount = float(payment.amount)
            hourly_data[hour]["revenue"] += amount
            hourly_data[hour]["transactions"] += 1
        
        # Calculate cumulative values
        for hour in range(24):
            cumulative += hourly_data[hour]["revenue"]
            transaction_count += hourly_data[hour]["transactions"]
            hourly_data[hour]["cumulative_revenue"] = round(cumulative, 2)
            hourly_data[hour]["cumulative_transactions"] = transaction_count
        
        # Convert to list sorted by hour
        hourly_list = [hourly_data[h] for h in range(24)]
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "date": day_start.strftime("%Y-%m-%d"),
            "date_label": day_start.strftime("%B %d, %Y"),
            "total_revenue": round(cumulative, 2),
            "total_transactions": transaction_count,
            "hourly": hourly_list,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching daily revenue: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    user_id: int = 1,
    router_id: Optional[int] = None,
    period: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """
    Get dashboard statistics with proper averages based on period.
    
    Query params:
    - router_id: Optional router ID to filter stats for a specific router
    - period: Number of days to calculate stats for (7, 30, 90, etc.)
    
    Returns averages calculated over the specified period.
    """
    try:
        from sqlalchemy import func
        from app.db.models import CustomerPayment
        
        now = datetime.utcnow()
        period_start = now - timedelta(days=period)
        today_start = datetime(now.year, now.month, now.day)
        
        # Build queries with optional router filtering
        if router_id:
            # Total revenue in period (with router filter)
            period_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_revenue = float((await db.execute(period_revenue_stmt)).scalar() or 0)
            
            # Total transactions in period
            period_txn_stmt = select(func.count(CustomerPayment.id)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_transactions = (await db.execute(period_txn_stmt)).scalar() or 0
            
            # Unique customers in period
            period_customers_stmt = select(func.count(func.distinct(CustomerPayment.customer_id))).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_unique_customers = (await db.execute(period_customers_stmt)).scalar() or 0
            
            # Today's stats
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start,
                Customer.router_id == router_id
            )
            today_revenue = float((await db.execute(today_revenue_stmt)).scalar() or 0)
            
            today_txn_stmt = select(func.count(CustomerPayment.id)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start,
                Customer.router_id == router_id
            )
            today_transactions = (await db.execute(today_txn_stmt)).scalar() or 0
        else:
            # Original queries without router filter
            # Total revenue in period
            period_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_revenue = float((await db.execute(period_revenue_stmt)).scalar() or 0)
            
            # Total transactions in period
            period_txn_stmt = select(func.count(CustomerPayment.id)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_transactions = (await db.execute(period_txn_stmt)).scalar() or 0
            
            # Unique customers in period
            period_customers_stmt = select(func.count(func.distinct(CustomerPayment.customer_id))).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_unique_customers = (await db.execute(period_customers_stmt)).scalar() or 0
            
            # Today's stats
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue = float((await db.execute(today_revenue_stmt)).scalar() or 0)
            
            today_txn_stmt = select(func.count(CustomerPayment.id)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_transactions = (await db.execute(today_txn_stmt)).scalar() or 0
        
        # Calculate averages for the period
        avg_daily_revenue = round(period_revenue / period, 2) if period > 0 else 0
        avg_daily_transactions = round(period_transactions / period, 2) if period > 0 else 0
        avg_transaction_value = round(period_revenue / period_transactions, 2) if period_transactions > 0 else 0
        avg_revenue_per_customer = round(period_revenue / period_unique_customers, 2) if period_unique_customers > 0 else 0
        
        # Get plan speed averages (from active customers)
        active_customers_stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        if router_id:
            active_customers_stmt = active_customers_stmt.where(Customer.router_id == router_id)
        active_result = await db.execute(active_customers_stmt)
        active_customers = active_result.scalars().all()
        
        total_download = 0.0
        total_upload = 0.0
        speed_count = 0
        
        for customer in active_customers:
            if customer.plan and customer.plan.speed:
                speed = customer.plan.speed
                # Parse speed format like "5M/2M" or "10/5"
                if "/" in speed:
                    parts = speed.split("/")
                    download = _parse_speed_value(parts[0])
                    upload = _parse_speed_value(parts[1]) if len(parts) > 1 else download
                    total_download += download
                    total_upload += upload
                    speed_count += 1
        
        avg_download_speed = round(total_download / speed_count, 2) if speed_count > 0 else 0
        avg_upload_speed = round(total_upload / speed_count, 2) if speed_count > 0 else 0
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "period_days": period,
            "period_start": period_start.isoformat(),
            "today": {
                "revenue": today_revenue,
                "transactions": today_transactions
            },
            "period_totals": {
                "revenue": round(period_revenue, 2),
                "transactions": period_transactions,
                "unique_customers": period_unique_customers
            },
            "averages": {
                "daily_revenue": avg_daily_revenue,
                "daily_transactions": avg_daily_transactions,
                "transaction_value": avg_transaction_value,
                "revenue_per_customer": avg_revenue_per_customer,
                "download_speed_mbps": avg_download_speed,
                "upload_speed_mbps": avg_upload_speed
            },
            "active_customers": len(active_customers),
            "generated_at": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def _parse_speed_value(speed_str: str) -> float:
    """Parse speed string like '5M', '10', '512K' into Mbps float"""
    speed_str = speed_str.strip().upper()
    try:
        if speed_str.endswith('G'):
            return float(speed_str[:-1]) * 1000
        elif speed_str.endswith('M'):
            return float(speed_str[:-1])
        elif speed_str.endswith('K'):
            return float(speed_str[:-1]) / 1000
        else:
            # Assume Mbps if no unit
            return float(speed_str)
    except ValueError:
        return 0.0

def _fetch_bandwidth_data_sync_for_router(router_info: dict):
    """Sync helper for bandwidth collection from a specific router - runs in thread"""
    api = MikroTikAPI(
        router_info["ip_address"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15
    )
    if not api.connect():
        logger.warning(f"[BANDWIDTH] Failed to connect to router ID {router_info['id']} at {router_info['ip_address']}")
        return None
    
    active_sessions = api.get_active_hotspot_users()
    traffic = api.get_interface_traffic()
    speed_stats = api.get_queue_speed_stats()
    queues = api.send_command("/queue/simple/print")
    hotspot_hosts = api.get_hotspot_hosts()
    arp_entries = api.get_arp_entries()
    api.disconnect()
    
    # Log what we got from MikroTik for debugging
    logger.info(f"[BANDWIDTH] Router {router_info['id']} raw data:")
    logger.info(f"  - Hotspot active sessions: {len(active_sessions.get('data', []))}")
    logger.info(f"  - Hotspot hosts total: {hotspot_hosts.get('total', 0)}, bypassed: {hotspot_hosts.get('bypassed', 0)}")
    logger.info(f"  - ARP entries: {arp_entries.get('count', 0)}")
    logger.info(f"  - Queue stats: active_queues={speed_stats.get('data', {}).get('active_queues', 0)}, total_queues={speed_stats.get('data', {}).get('total_queues', 0)}")
    
    # Log all interfaces with their traffic
    if traffic.get("success"):
        logger.info(f"  - Interfaces found:")
        for iface in traffic.get("data", []):
            rx_mb = round(iface.get("rx_byte", 0) / 1048576, 2)
            tx_mb = round(iface.get("tx_byte", 0) / 1048576, 2)
            logger.info(f"    * {iface.get('name')}: running={iface.get('running')}, rx={rx_mb}MB, tx={tx_mb}MB")
    else:
        logger.warning(f"  - Interface traffic fetch failed: {traffic.get('error', 'unknown')}")
    
    return {
        "router_id": router_info["id"],
        "active_sessions": active_sessions, 
        "traffic": traffic, 
        "speed_stats": speed_stats, 
        "queues": queues,
        "hotspot_hosts": hotspot_hosts,
        "arp_entries": arp_entries
    }

def _fetch_bandwidth_data_sync():
    """Sync helper for bandwidth collection from default router - runs in thread (legacy)"""
    api = MikroTikAPI(
        settings.MIKROTIK_HOST,
        settings.MIKROTIK_USERNAME,
        settings.MIKROTIK_PASSWORD,
        settings.MIKROTIK_PORT,
        timeout=15
    )
    if not api.connect():
        return None
    active_sessions = api.get_active_hotspot_users()
    traffic = api.get_interface_traffic()
    speed_stats = api.get_queue_speed_stats()
    queues = api.send_command("/queue/simple/print")
    api.disconnect()
    return {"router_id": None, "active_sessions": active_sessions, "traffic": traffic, "speed_stats": speed_stats, "queues": queues}


async def collect_bandwidth_snapshot():
    """Collect bandwidth stats from all routers using interface counters for accurate averaging"""
    try:
        now = datetime.utcnow()
        
        async for db in get_db():
            # Get all routers from database
            routers_result = await db.execute(select(Router))
            routers = routers_result.scalars().all()
            
            if not routers:
                logger.warning("No routers found in database for bandwidth collection")
                return
            
            # Collect from each router
            for router in routers:
                try:
                    router_info = {
                        "id": router.id,
                        "ip_address": router.ip_address,
                        "username": router.username,
                        "password": router.password,
                        "port": router.port
                    }
                    
                    raw = await asyncio.to_thread(_fetch_bandwidth_data_sync_for_router, router_info)
                    if not raw:
                        logger.warning(f"Failed to connect to router {router.name} ({router.ip_address}) for bandwidth snapshot")
                        continue
                    
                    active_sessions = raw["active_sessions"]
                    traffic = raw["traffic"]
                    speed_stats = raw["speed_stats"]
                    router_id = raw["router_id"]
                    hotspot_hosts = raw.get("hotspot_hosts", {})
                    arp_entries = raw.get("arp_entries", {})
                    
                    # Find best interface for traffic measurement
                    # Priority: 1) bridge interfaces, 2) ether1 (WAN), 3) any running ether
                    total_rx = 0
                    total_tx = 0
                    selected_interface = None
                    
                    interfaces = traffic.get("data", [])
                    
                    # First try: find a bridge interface (various naming conventions)
                    for iface in interfaces:
                        name = iface.get("name", "").lower()
                        if iface.get("running") and ("bridge" in name):
                            total_rx = iface.get("rx_byte", 0)
                            total_tx = iface.get("tx_byte", 0)
                            selected_interface = iface.get("name")
                            break
                    
                    # Second try: use ether1 (typically WAN interface)
                    if not selected_interface:
                        for iface in interfaces:
                            if iface.get("name") == "ether1" and iface.get("running"):
                                total_rx = iface.get("rx_byte", 0)
                                total_tx = iface.get("tx_byte", 0)
                                selected_interface = "ether1"
                                break
                    
                    # Third try: sum all running ether interfaces
                    if not selected_interface:
                        for iface in interfaces:
                            name = iface.get("name", "")
                            if name.startswith("ether") and iface.get("running"):
                                total_rx += iface.get("rx_byte", 0)
                                total_tx += iface.get("tx_byte", 0)
                        if total_rx > 0 or total_tx > 0:
                            selected_interface = "all-ethers-summed"
                    
                    logger.info(f"[BANDWIDTH] Router {router_id}: Using interface '{selected_interface}' for traffic - rx={total_rx}, tx={total_tx}")
                    
                    speed_data = speed_stats.get("data", {})
                    
                    # Get previous snapshot for THIS router to calculate rate
                    prev_result = await db.execute(
                        select(BandwidthSnapshot)
                        .where(BandwidthSnapshot.router_id == router_id)
                        .order_by(BandwidthSnapshot.recorded_at.desc())
                        .limit(1)
                    )
                    prev = prev_result.scalar_one_or_none()
                    
                    # Calculate actual average bps from byte counter difference
                    avg_download_bps = 0.0
                    avg_upload_bps = 0.0
                    time_diff = 0
                    if prev and prev.interface_rx_bytes > 0:
                        time_diff = (now - prev.recorded_at).total_seconds()
                        if time_diff > 0:
                            # For WAN interface (ether1): rx = download, tx = upload
                            # For bridge: same perspective
                            byte_diff_rx = total_rx - prev.interface_rx_bytes
                            byte_diff_tx = total_tx - prev.interface_tx_bytes
                            
                            # Handle counter reset (when router reboots, counters reset)
                            if byte_diff_rx >= 0 and byte_diff_tx >= 0:
                                avg_download_bps = (byte_diff_rx * 8) / time_diff  # bytes to bits
                                avg_upload_bps = (byte_diff_tx * 8) / time_diff
                                
                                logger.info(f"[BANDWIDTH] Router {router_id}: time_diff={time_diff:.1f}s, byte_diff_rx={byte_diff_rx}, byte_diff_tx={byte_diff_tx}")
                                logger.info(f"[BANDWIDTH] Router {router_id}: Calculated avg_download={avg_download_bps/1000000:.2f}Mbps, avg_upload={avg_upload_bps/1000000:.2f}Mbps")
                            else:
                                logger.warning(f"[BANDWIDTH] Router {router_id}: Counter reset detected (negative diff), skipping rate calc")
                    else:
                        logger.info(f"[BANDWIDTH] Router {router_id}: No previous snapshot or rx_bytes=0, first measurement")
                    
                    # Use hotspot hosts (bypassed) + ARP as better active device count
                    active_devices = hotspot_hosts.get("bypassed", 0) + hotspot_hosts.get("authorized", 0)
                    if active_devices == 0:
                        active_devices = arp_entries.get("count", 0)
                    
                    snapshot = BandwidthSnapshot(
                        router_id=router_id,
                        total_upload_bps=int(speed_data.get("total_upload_bps", 0)),
                        total_download_bps=int(speed_data.get("total_download_bps", 0)),
                        avg_upload_bps=avg_upload_bps,
                        avg_download_bps=avg_download_bps,
                        active_queues=active_devices,  # Repurposed: now shows active devices (hotspot hosts + arp)
                        active_sessions=len(active_sessions.get("data", [])),
                        interface_rx_bytes=total_rx,
                        interface_tx_bytes=total_tx,
                        recorded_at=now
                    )
                    
                    db.add(snapshot)
                    
                    # Update user bandwidth usage from queues for this router
                    queues = raw.get("queues", {})
                    if queues.get("success") and queues.get("data"):
                        for q in queues["data"]:
                            # Extract MAC from comment
                            comment = q.get("comment", "")
                            mac = ""
                            if "MAC:" in comment:
                                mac = comment.split("MAC:")[1].split("|")[0].strip()
                            
                            if not mac:
                                continue
                            
                            # Parse bytes
                            bytes_str = q.get("bytes", "0/0")
                            bytes_parts = bytes_str.split("/")
                            upload_bytes = int(bytes_parts[0]) if len(bytes_parts) > 0 and bytes_parts[0].isdigit() else 0
                            download_bytes = int(bytes_parts[1]) if len(bytes_parts) > 1 and bytes_parts[1].isdigit() else 0
                            
                            # Find customer by MAC
                            cust_result = await db.execute(
                                select(Customer).where(Customer.mac_address.ilike(f"%{mac}%"))
                            )
                            customer = cust_result.scalar_one_or_none()
                            
                            # Upsert usage record
                            existing = await db.execute(
                                select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == mac)
                            )
                            usage = existing.scalar_one_or_none()
                            
                            if usage:
                                usage.upload_bytes = upload_bytes
                                usage.download_bytes = download_bytes
                                usage.max_limit = q.get("max-limit", "")
                                usage.last_updated = now
                                if customer:
                                    usage.customer_id = customer.id
                            else:
                                usage = UserBandwidthUsage(
                                    mac_address=mac,
                                    customer_id=customer.id if customer else None,
                                    queue_name=q.get("name", ""),
                                    target_ip=q.get("target", ""),
                                    upload_bytes=upload_bytes,
                                    download_bytes=download_bytes,
                                    max_limit=q.get("max-limit", ""),
                                    last_updated=now
                                )
                                db.add(usage)
                    
                    logger.debug(f"Collected bandwidth snapshot for router {router.name} (ID: {router_id})")
                    
                except Exception as router_error:
                    logger.error(f"Error collecting bandwidth from router {router.name}: {router_error}")
                    continue
            
            # Cleanup: delete records older than 1 day (for all routers)
            cutoff = now - timedelta(days=1)
            await db.execute(delete(BandwidthSnapshot).where(BandwidthSnapshot.recorded_at < cutoff))
            
            await db.commit()
            break
        
        logger.info(f"📊 Bandwidth snapshot collected for {len(routers)} router(s)")
    except Exception as e:
        logger.error(f"Error collecting bandwidth snapshot: {e}")


# ========================================
# ADS ENDPOINTS
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


@app.post("/api/advertisers")
async def create_advertiser(
    request: AdvertiserCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new advertiser."""
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


@app.get("/api/advertisers")
async def get_advertisers(
    db: AsyncSession = Depends(get_db)
):
    """List all advertisers."""
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


@app.post("/api/ads")
async def create_ad(
    request: AdCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new ad."""
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


@app.delete("/api/ads/{ad_id}")
async def delete_ad(
    ad_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete an ad by ID (cascades to clicks and impressions)."""
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


@app.put("/api/ads/{ad_id}")
async def update_ad(
    ad_id: int,
    request: AdUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update an ad by ID."""
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


@app.get("/api/ads")
async def get_ads(
    page: int = 1,
    per_page: int = 20,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Fetch active ads for captive portal display.
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
        
        from sqlalchemy import func
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


@app.post("/api/ads/click")
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


@app.post("/api/ads/impression")
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


@app.get("/api/ads/{ad_id}/clicks")
async def get_ad_clicks(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    click_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get click records for a specific ad."""
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
        from sqlalchemy import func
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


@app.get("/api/ads/{ad_id}/impressions")
async def get_ad_impressions(
    ad_id: int,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """Get impression records that include this ad."""
    try:
        # Verify ad exists
        ad_result = await db.execute(select(Ad).where(Ad.id == ad_id))
        ad = ad_result.scalar_one_or_none()
        if not ad:
            raise HTTPException(status_code=404, detail="Ad not found")
        
        # Query impressions where ad_id is in the ad_ids JSON array
        from sqlalchemy import cast, String
        query = select(AdImpression).where(
            AdImpression.ad_ids.contains([ad_id])
        ).order_by(AdImpression.created_at.desc())
        
        # Count
        from sqlalchemy import func
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


@app.get("/api/ads/analytics")
async def get_ads_analytics(
    days: int = 30,
    db: AsyncSession = Depends(get_db)
):
    """Get aggregated analytics for all ads."""
    try:
        from sqlalchemy import func
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


# Startup event - Start background scheduler
@app.on_event("startup")
async def startup_event():
    """Start the background cleanup scheduler when the app starts"""
    # Use prime-number intervals to prevent jobs from ever running simultaneously
    # LCM of primes = product, so overlap won't happen for ~43 days
    scheduler.add_job(
        cleanup_expired_users_background,
        trigger=IntervalTrigger(seconds=67),  # ~1 min (prime)
        id='cleanup_expired_users',
        name='Remove expired hotspot users from MikroTik',
        replace_existing=True,
        max_instances=1
    )
    # Queue sync - ensures bandwidth limits apply even if customer IP changes
    # DISABLED: sync_active_user_queues job
    # scheduler.add_job(
    #     sync_active_user_queues,
    #     trigger=IntervalTrigger(seconds=353),  # ~5 min 53s (prime)
    #     id='sync_user_queues',
    #     name='Sync rate limit queues for active users',
    #     replace_existing=True,
    #     max_instances=1
    # )
    scheduler.add_job(
        collect_bandwidth_snapshot,
        trigger=IntervalTrigger(seconds=157),  # ~2 min 37s (prime)
        id='bandwidth_snapshot',
        name='Collect bandwidth statistics',
        replace_existing=True,
        max_instances=1
    )
    scheduler.start()
    logger.info("🔄 Background scheduler started - cleanup every 67s, bandwidth every 157s")
    
    # Warm up plan cache on startup
    async for db in get_db():
        await warm_plan_cache(db)
        break
    logger.info("✅ Plan cache warmed up")

# Shutdown event - Stop background scheduler
@app.on_event("shutdown")
async def shutdown_event():
    """Stop the background scheduler when the app shuts down"""
    scheduler.shutdown()
    logger.info("🛑 Background scheduler stopped")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Router, Customer, Plan, CustomerStatus
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.config import settings

import logging
import time
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


@router.post("/api/admin/cleanup-inactive-users")
async def cleanup_all_inactive_users(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    One-time cleanup: Remove ALL inactive users from MikroTik
    (They're already marked inactive in DB but still in MikroTik)
    """
    try:
        user = await get_current_user(token, db)
        # Find all INACTIVE customers with MAC addresses
        stmt = select(Customer).where(
            Customer.status == CustomerStatus.INACTIVE,
            Customer.mac_address.isnot(None),
            Customer.user_id == user.id
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
            settings.MIKROTIK_PORT,
            timeout=15,
            connect_timeout=5  # Fast fail if router unreachable
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


@router.get("/api/admin/orphaned-customers")
async def get_orphaned_customers(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Find customers without a router assigned (orphaned from migration).
    These customers cannot be cleaned up by the cron job because they have no router.
    
    Returns list of orphaned customers for review before deletion.
    """
    try:
        user = await get_current_user(token, db)
        # Find customers with no router_id OR router_id pointing to deleted router
        stmt = select(Customer).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).where(
            Customer.user_id == user.id,
            or_(
                Customer.router_id == None,
                Customer.router == None  # router_id exists but router was deleted
            )
        )
        
        result = await db.execute(stmt)
        orphaned_customers = result.scalars().all()
        
        # Categorize by status
        active_orphans = []
        inactive_orphans = []
        expired_orphans = []
        
        now = datetime.utcnow()
        
        for c in orphaned_customers:
            customer_data = {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "status": c.status.value if c.status else "unknown",
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "router_id": c.router_id,  # Shows if they had a router_id (deleted router)
                "plan_name": c.plan.name if c.plan else "No plan",
                "created_at": c.created_at.isoformat() if c.created_at else None
            }
            
            if c.status == CustomerStatus.ACTIVE:
                if c.expiry and c.expiry <= now:
                    expired_orphans.append(customer_data)
                else:
                    active_orphans.append(customer_data)
            else:
                inactive_orphans.append(customer_data)
        
        return {
            "total_orphaned": len(orphaned_customers),
            "summary": {
                "active_not_expired": len(active_orphans),
                "active_but_expired": len(expired_orphans),
                "inactive": len(inactive_orphans)
            },
            "active_not_expired": active_orphans,
            "active_but_expired": expired_orphans,
            "inactive": inactive_orphans,
            "recommendation": "Use DELETE /api/admin/orphaned-customers to remove these. Safe to delete: inactive and expired customers."
        }
        
    except Exception as e:
        logger.error(f"[ORPHANED] Error finding orphaned customers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/admin/orphaned-customers")
async def delete_orphaned_customers(
    include_expired: bool = True,
    include_inactive: bool = True,
    include_active: bool = False,  # Safety: don't delete active by default
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Delete orphaned customers (those without router assignments).
    
    Query params:
    - include_expired: Delete active customers whose subscription has expired (default: True)
    - include_inactive: Delete inactive customers (default: True)  
    - include_active: Delete active customers with valid subscriptions (default: False - DANGEROUS)
    
    These are legacy customers from before migration who cannot be processed by the cron job.
    """
    try:
        user = await get_current_user(token, db)
        now = datetime.utcnow()
        
        # Find orphaned customers
        stmt = select(Customer).where(
            Customer.user_id == user.id,
            or_(
                Customer.router_id == None,
                Customer.router == None
            )
        )
        
        result = await db.execute(stmt)
        orphaned_customers = result.scalars().all()
        
        deleted = []
        skipped = []
        
        for c in orphaned_customers:
            should_delete = False
            reason = ""
            
            if c.status == CustomerStatus.INACTIVE and include_inactive:
                should_delete = True
                reason = "inactive"
            elif c.status == CustomerStatus.ACTIVE:
                if c.expiry and c.expiry <= now and include_expired:
                    should_delete = True
                    reason = "expired"
                elif include_active:
                    should_delete = True
                    reason = "active (forced)"
                else:
                    skipped.append({
                        "id": c.id,
                        "name": c.name,
                        "reason": "active with valid subscription - use include_active=true to force"
                    })
            else:
                # PENDING or other status
                if include_inactive:
                    should_delete = True
                    reason = c.status.value if c.status else "unknown"
            
            if should_delete:
                deleted.append({
                    "id": c.id,
                    "name": c.name,
                    "mac_address": c.mac_address,
                    "status": c.status.value if c.status else "unknown",
                    "reason": reason
                })
                await db.delete(c)
        
        await db.commit()
        
        logger.info(f"[ORPHANED] Deleted {len(deleted)} orphaned customers, skipped {len(skipped)}")
        
        return {
            "success": True,
            "message": f"Deleted {len(deleted)} orphaned customers",
            "deleted_count": len(deleted),
            "skipped_count": len(skipped),
            "deleted": deleted,
            "skipped": skipped
        }
        
    except Exception as e:
        logger.error(f"[ORPHANED] Error deleting orphaned customers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _cleanup_recently_expired_sync(customers_data: list, delay_ms: int = 200) -> dict:
    """
    Synchronous function to remove recently expired users from MikroTik.
    Runs in thread pool to avoid blocking. Fetches data once, then processes.
    
    Args:
        customers_data: List of {id, name, mac_address, status, expiry}
        delay_ms: Delay between removal operations in milliseconds
    """
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
        settings.MIKROTIK_PORT,
        timeout=15,
        connect_timeout=5  # Fast fail if router unreachable
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


@router.post("/api/admin/cleanup-recently-expired")
async def cleanup_recently_expired_users(
    hours: int = 12,
    delay_ms: int = 200,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Remove users expired in the last N hours from MikroTik, regardless of DB status.
    Non-blocking: runs MikroTik operations in thread pool with delays between requests.
    
    Args:
        hours: Look back period (default 12 hours)
        delay_ms: Delay between MikroTik API calls in milliseconds (default 200ms)
    """
    try:
        user = await get_current_user(token, db)
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)
        
        # Find customers expired in the last N hours (ANY status - ACTIVE or INACTIVE)
        stmt = select(Customer).where(
            Customer.expiry.isnot(None),
            Customer.expiry >= cutoff,
            Customer.expiry <= now,
            Customer.mac_address.isnot(None),
            Customer.user_id == user.id
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

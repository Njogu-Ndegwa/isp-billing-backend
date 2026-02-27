"""
MikroTik Background Operations
===============================

All background job functions for MikroTik router management:
- Expired user cleanup (runs every ~67s)
- Queue sync for active users (currently disabled)
- Bandwidth snapshot collection (runs every ~157s)

Also contains shared MikroTik async wrappers and the
remove_user_from_mikrotik function used by multiple router files.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from app.db.database import get_db, async_engine
from app.db.models import Router, Customer, CustomerStatus, BandwidthSnapshot, UserBandwidthUsage
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.core.protected_devices import is_protected_device
from app.config import settings
import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# Shared state for background jobs
mikrotik_lock = asyncio.Lock()
cleanup_running = False
queue_sync_running = False

# Rate limiting constants for queue sync
SYNC_DELAY_BETWEEN_COMMANDS = 0.1
SYNC_DELAY_BETWEEN_CUSTOMERS = 0.05
SYNC_MAX_QUEUE_OPERATIONS_PER_RUN = 50


# =============================================================================
# ASYNC WRAPPERS FOR MIKROTIK OPERATIONS
# =============================================================================

def _run_mikrotik_health_sync(router_info: dict) -> dict:
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
        resources = api.get_system_resources()
        health = api.get_health()
        return {
            "success": True,
            "resources": resources,
            "health": health,
            "router_name": router_info.get("name", "Unknown")
        }
    finally:
        api.disconnect()


async def run_mikrotik_health_async(router_info: dict) -> dict:
    return await asyncio.to_thread(_run_mikrotik_health_sync, router_info)


def _run_mikrotik_operation_sync(router_info: dict, operation: str, **kwargs) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=kwargs.pop("timeout", 15),
        connect_timeout=kwargs.pop("connect_timeout", 5)
    )
    if not api.connect():
        return {"error": "Failed to connect", "router_name": router_info.get("name", "Unknown")}
    try:
        method = getattr(api, operation, None)
        if not method:
            return {"error": f"Unknown operation: {operation}"}
        result = method(**kwargs) if kwargs else method()
        return {"success": True, "data": result, "router_name": router_info.get("name", "Unknown")}
    except Exception as e:
        logger.error(f"MikroTik operation {operation} failed: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


async def run_mikrotik_operation_async(router_info: dict, operation: str, **kwargs) -> dict:
    return await asyncio.to_thread(_run_mikrotik_operation_sync, router_info, operation, **kwargs)


def _run_mikrotik_commands_sync(router_info: dict, commands_func) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=router_info.get("timeout", 15),
        connect_timeout=router_info.get("connect_timeout", 5)
    )
    if not api.connect():
        return {"error": "connection_failed", "message": f"Failed to connect to {router_info.get('name', router_info['ip'])}"}
    try:
        return commands_func(api)
    except Exception as e:
        logger.error(f"MikroTik operation failed on {router_info.get('name', router_info['ip'])}: {e}")
        return {"error": "operation_failed", "message": str(e)}
    finally:
        api.disconnect()


async def run_mikrotik_commands_async(router_info: dict, commands_func) -> dict:
    return await asyncio.to_thread(_run_mikrotik_commands_sync, router_info, commands_func)


# =============================================================================
# SHARED: REMOVE USER FROM MIKROTIK
# =============================================================================

def _remove_user_from_mikrotik_sync(router_info: dict, normalized_mac: str, username: str, original_mac: str) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    if not api.connect():
        logger.error(f"[CLEANUP] Failed to connect to MikroTik for {normalized_mac}")
        return {"error": "connection_failed", "message": "Failed to connect to MikroTik"}
    try:
        removed = {"user": False, "bindings": 0, "queues": 0, "leases": 0, "active_sessions": 0}

        users = api.send_command("/ip/hotspot/user/print")
        if users.get("success") and users.get("data"):
            for u in users["data"]:
                if u.get("name") == username:
                    api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                    removed["user"] = True
                    logger.info(f"[CLEANUP] Removed hotspot user: {username}")
                    break

        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if bindings.get("success") and bindings.get("data"):
            for b in bindings["data"]:
                binding_mac = b.get("mac-address", "").upper()
                binding_name = b.get("name", "").upper()
                if binding_mac == normalized_mac.upper() or binding_name == username.upper():
                    api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                    removed["bindings"] += 1
                    logger.info(f"[CLEANUP] Removed IP binding: {binding_name} ({binding_mac})")

        queues = api.send_command("/queue/simple/print")
        if queues.get("success") and queues.get("data"):
            for q in queues["data"]:
                queue_name = q.get("name", "")
                queue_comment = q.get("comment", "")
                if (queue_name == f"queue_{username}" or
                    normalized_mac.upper() in queue_comment.upper() or
                    original_mac.upper() in queue_comment.upper()):
                    api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                    removed["queues"] += 1
                    logger.info(f"[CLEANUP] Removed queue: {queue_name}")

        leases = api.send_command("/ip/dhcp-server/lease/print")
        if leases.get("success") and leases.get("data"):
            for l in leases["data"]:
                lease_mac = l.get("mac-address", "")
                if lease_mac:
                    lease_mac_clean = lease_mac.replace(":", "").replace("-", "").upper()
                    normalized_mac_clean = normalized_mac.replace(":", "").replace("-", "").upper()
                    if lease_mac_clean == normalized_mac_clean:
                        api.send_command("/ip/dhcp-server/lease/remove", {"numbers": l[".id"]})
                        removed["leases"] += 1
                        logger.info(f"[CLEANUP-DHCP] Removed lease: {lease_mac}")

        active_sessions = api.send_command("/ip/hotspot/active/print")
        if active_sessions.get("success") and active_sessions.get("data"):
            for session in active_sessions["data"]:
                session_user = session.get("user", "").upper()
                session_mac = session.get("mac-address", "").upper()
                if session_user == username.upper() or session_mac == normalized_mac.upper():
                    session_id = session.get(".id")
                    if session_id:
                        api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                        removed["active_sessions"] += 1
                        logger.info(f"[CLEANUP] Disconnected active session: {session_user}")

        logger.info(f"[CLEANUP] Successfully cleaned up {normalized_mac}: {removed}")
        return {"success": True, "removed": removed}
    finally:
        api.disconnect()


async def remove_user_from_mikrotik(mac_address: str, db: AsyncSession) -> dict:
    """
    Remove user from MikroTik router and update database status.
    Used by public_routes and dashboard_routes via import.
    """
    try:
        normalized_mac = normalize_mac_address(mac_address)
        username = normalized_mac.replace(":", "")

        customer_stmt = select(Customer).options(selectinload(Customer.router)).where(Customer.mac_address == normalized_mac)
        customer_result = await db.execute(customer_stmt)
        customer = customer_result.scalar_one_or_none()

        if not customer:
            return {"success": False, "error": "Customer not found in database"}

        customer.status = CustomerStatus.INACTIVE
        await db.commit()
        logger.info(f"[CLEANUP] Customer {customer.id} set to INACTIVE in database")

        if customer.router:
            router = customer.router
            router_info = {
                "ip": router.ip_address,
                "username": router.username,
                "password": router.password,
                "port": router.port,
                "name": router.name
            }
            logger.info(f"[CLEANUP] Will connect to router {router.name} at {router.ip_address}")
        else:
            router_info = {
                "ip": settings.MIKROTIK_HOST,
                "username": settings.MIKROTIK_USERNAME,
                "password": settings.MIKROTIK_PASSWORD,
                "port": settings.MIKROTIK_PORT,
                "name": "Default Router"
            }
            logger.warning(f"[CLEANUP] Customer {customer.id} has no router assigned, using default settings")

        result = await asyncio.to_thread(
            _remove_user_from_mikrotik_sync,
            router_info,
            normalized_mac,
            username,
            mac_address
        )

        if result.get("error"):
            return {"success": False, "error": result.get("message", "MikroTik operation failed")}

        return {
            "success": True,
            "customer_id": customer.id,
            "mac_address": normalized_mac,
            "removed": result.get("removed", {})
        }
    except Exception as e:
        logger.error(f"[CLEANUP] Error removing user {mac_address}: {e}")
        return {"success": False, "error": str(e)}


# =============================================================================
# EXPIRED USER CLEANUP (background job)
# =============================================================================

def _cleanup_customer_from_mikrotik_sync(router_customers_map: dict) -> dict:
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
            router_info["port"],
            timeout=15,
            connect_timeout=5
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
                removed = {"user": False, "binding_removed": False, "hosts": 0, "queues": 0, "leases": 0, "active_sessions": 0}

                client_ip = api.get_client_ip_by_mac(normalized_mac)
                if client_ip:
                    logger.info(f"[CRON] Found client IP: {client_ip} for MAC {normalized_mac}")

                binding_found = False
                binding_fetch_failed = False
                bindings = api.send_command("/ip/hotspot/ip-binding/print")
                if not bindings.get("success"):
                    binding_fetch_failed = True
                    logger.error(f"[CRON] Failed to fetch IP bindings for {normalized_mac}: {bindings.get('error', 'unknown')}")
                elif bindings.get("data"):
                    for b in bindings["data"]:
                        binding_mac = b.get("mac-address", "").upper()
                        binding_comment = b.get("comment", "")
                        binding_id = b.get(".id")
                        mac_match = normalize_mac_address(binding_mac) == normalized_mac if binding_mac else False
                        username_match = f"USER:{username}" in binding_comment.upper()
                        if mac_match or username_match:
                            binding_found = True
                            logger.info(f"[CRON] Found IP binding to remove: id={binding_id}, mac={binding_mac}, type={b.get('type', 'unknown')}")
                            remove_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                            if remove_result.get("success") or "error" not in remove_result:
                                removed["binding_removed"] = True
                                logger.info(f"[CRON] Successfully removed IP binding for {normalized_mac}")
                            else:
                                logger.error(f"[CRON] Failed to remove IP binding: {remove_result.get('error', 'unknown error')}")
                    if not binding_found:
                        logger.info(f"[CRON] No IP binding found for {normalized_mac} (may already be removed)")
                else:
                    logger.info(f"[CRON] No IP bindings on router (empty list)")

                hosts = api.send_command("/ip/hotspot/host/print")
                if hosts.get("success") and hosts.get("data"):
                    for host in hosts["data"]:
                        host_mac = host.get("mac-address", "").upper()
                        host_ip = host.get("address", "")
                        if normalize_mac_address(host_mac) == normalized_mac or host_ip == client_ip:
                            api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
                            removed["hosts"] += 1
                            logger.info(f"[CRON] Removed host entry: {host_mac} / {host_ip}")

                users = api.send_command("/ip/hotspot/user/print")
                if users.get("success") and users.get("data"):
                    user_found = False
                    for u in users["data"]:
                        user_name = u.get("name", "")
                        user_comment = u.get("comment", "")
                        user_id = u.get(".id")
                        name_match = user_name == username
                        mac_in_comment = normalized_mac.upper() in user_comment.upper() or cust['mac_address'].upper() in user_comment.upper()
                        if name_match or mac_in_comment:
                            user_found = True
                            logger.info(f"[CRON] Found hotspot user to remove: id={user_id}, name={user_name}")
                            remove_result = api.send_command("/ip/hotspot/user/remove", {"numbers": user_id})
                            if remove_result.get("success") or "error" not in remove_result:
                                removed["user"] = True
                                logger.info(f"[CRON] Successfully removed hotspot user: {user_name}")
                            else:
                                logger.error(f"[CRON] Failed to remove hotspot user: {remove_result.get('error', 'unknown error')}")
                            break
                    if not user_found:
                        logger.info(f"[CRON] No hotspot user found for {username} (may already be removed)")

                active_sessions = api.send_command("/ip/hotspot/active/print")
                if active_sessions.get("success") and active_sessions.get("data"):
                    for session in active_sessions["data"]:
                        session_mac = session.get("mac-address", "").upper()
                        session_user = session.get("user", "").upper()
                        session_ip = session.get("address", "")
                        session_id = session.get(".id")
                        mac_match = normalize_mac_address(session_mac) == normalized_mac if session_mac else False
                        user_match = session_user == username.upper()
                        if mac_match or user_match:
                            logger.info(f"[CRON] Found active session to disconnect: id={session_id}, user={session_user}, ip={session_ip}")
                            remove_result = api.send_command("/ip/hotspot/active/remove", {"numbers": session_id})
                            if remove_result.get("success") or "error" not in remove_result:
                                removed["active_sessions"] += 1
                                logger.info(f"[CRON] Disconnected active session: {session_user} ({session_ip})")
                            else:
                                logger.error(f"[CRON] Failed to disconnect session: {remove_result.get('error', 'unknown error')}")

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

                leases = api.send_command("/ip/dhcp-server/lease/print")
                if leases.get("success") and leases.get("data"):
                    for lease in leases["data"]:
                        if normalize_mac_address(lease.get("mac-address", "")) == normalized_mac:
                            api.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease[".id"]})
                            removed["leases"] += 1
                            logger.info(f"[CRON] Removed DHCP lease for {normalized_mac}")

                verify_bindings = api.send_command("/ip/hotspot/ip-binding/print")
                if verify_bindings.get("success") and verify_bindings.get("data"):
                    binding_still_exists = False
                    for b in verify_bindings["data"]:
                        if normalize_mac_address(b.get("mac-address", "")) == normalized_mac:
                            binding_still_exists = True
                            logger.error(f"[CRON] VERIFICATION FAILED: IP binding STILL EXISTS for {normalized_mac}!")
                            retry_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                            if retry_result.get("success") or "error" not in retry_result:
                                logger.info(f"[CRON] Retry removal succeeded for {normalized_mac}")
                                removed["binding_removed"] = True
                            else:
                                logger.error(f"[CRON] Retry removal FAILED: {retry_result.get('error', 'unknown')}")
                            break
                    if not binding_still_exists and removed.get("binding_removed"):
                        logger.info(f"[CRON] VERIFICATION: IP binding successfully removed for {normalized_mac}")

                if binding_fetch_failed:
                    results["failed"].append({"id": cust["id"], "error": "Could not fetch IP bindings - user status unknown"})
                    logger.error(f"[CRON] FAILED to check bindings for {cust['name']} - keeping ACTIVE for retry")
                elif removed.get("binding_removed"):
                    results["removed"].append({"id": cust["id"], "details": removed})
                    logger.info(f"[CRON] Expired customer {cust['name']} FULLY removed: {removed}")
                elif not binding_found:
                    results["removed"].append({"id": cust["id"], "details": removed})
                    logger.info(f"[CRON] Expired customer {cust['name']} had no binding (already removed): {removed}")
                else:
                    results["failed"].append({"id": cust["id"], "error": "IP binding removal failed - user may still have access"})
                    logger.error(f"[CRON] FAILED to remove binding for {cust['name']} - keeping ACTIVE for retry")

            except Exception as e:
                results["failed"].append({"id": cust["id"], "error": str(e)})
                logger.error(f"[CRON] Failed to remove customer {cust['id']}: {e}")

        api.disconnect()

    return results


def _cleanup_router_bindings_sync(router_info: dict, active_macs: set) -> int:
    removed = 0
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5
    )
    if not api.connect():
        return 0
    try:
        bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
        if not bindings_result.get("success"):
            return 0
        for binding in bindings_result.get("data", []):
            binding_mac = binding.get("mac-address", "")
            binding_type = binding.get("type", "")
            binding_id = binding.get(".id", "")
            if not binding_mac or binding_type != "bypassed":
                continue
            normalized_mac = normalize_mac_address(binding_mac)
            if normalized_mac not in active_macs:
                remove_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                if remove_result.get("success") or "error" not in remove_result:
                    removed += 1
                    logger.info(f"[SAFETY-NET] Removed orphaned binding for {binding_mac} on {router_info['name']}")
        return removed
    finally:
        api.disconnect()


async def _cleanup_bypassing_for_all_routers(db: AsyncSession) -> int:
    total_removed = 0
    try:
        stmt = select(Router)
        result = await db.execute(stmt)
        routers = result.scalars().all()

        stmt = select(Customer).where(Customer.mac_address.isnot(None))
        result = await db.execute(stmt)
        all_customers = result.scalars().all()

        active_macs = set()
        for c in all_customers:
            normalized = normalize_mac_address(c.mac_address)
            if c.status == CustomerStatus.ACTIVE:
                active_macs.add(normalized)

        for router in routers:
            if getattr(router, 'auth_method', None) == 'RADIUS':
                continue
            try:
                router_info = {
                    "ip": router.ip_address, "username": router.username,
                    "password": router.password, "port": router.port, "name": router.name
                }
                removed = await asyncio.to_thread(_cleanup_router_bindings_sync, router_info, active_macs)
                total_removed += removed
            except Exception as router_err:
                logger.error(f"[SAFETY-NET] Error processing router {router.name}: {router_err}")
                continue
    except Exception as e:
        logger.error(f"[SAFETY-NET] Cleanup failed: {e}")
    return total_removed


async def cleanup_expired_users_background():
    global cleanup_running
    if cleanup_running:
        logger.warning("[CRON] Previous cleanup still running, skipping this run")
        return
    cleanup_running = True
    start_time = datetime.utcnow()
    try:
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

            router_customers_map = {}
            no_router_customers = []
            for c in expired_customers:
                if not c.mac_address:
                    continue
                if c.router and getattr(c.router, 'auth_method', None) == 'RADIUS':
                    c.status = CustomerStatus.INACTIVE
                    continue
                customer_data = {
                    "id": c.id, "name": c.name, "mac_address": c.mac_address,
                    "expiry": c.expiry, "router_id": c.router_id
                }
                if c.router:
                    router_key = f"{c.router.ip_address}:{c.router.port}"
                    if router_key not in router_customers_map:
                        router_customers_map[router_key] = {
                            "router": {
                                "ip": c.router.ip_address, "username": c.router.username,
                                "password": c.router.password, "port": c.router.port, "name": c.router.name
                            },
                            "customers": []
                        }
                    router_customers_map[router_key]["customers"].append(customer_data)
                elif c.router_id:
                    logger.warning(f"[CRON] Customer {c.id} has router_id={c.router_id} but router doesn't exist (deleted?)")
                    no_router_customers.append(customer_data)
                else:
                    no_router_customers.append(customer_data)

            if no_router_customers:
                logger.warning(f"[CRON] Skipping {len(no_router_customers)} customer(s) with no router assigned: {[c['id'] for c in no_router_customers]}")
            logger.info(f"[CRON] Grouped customers across {len(router_customers_map)} router(s)")

            async with mikrotik_lock:
                mikrotik_results = await asyncio.to_thread(_cleanup_customer_from_mikrotik_sync, router_customers_map)

            if mikrotik_results["routers_connected"] > 0:
                successful_ids = [r["id"] for r in mikrotik_results["removed"]]
                failed_ids = [r["id"] for r in mikrotik_results["failed"]]
                for customer in expired_customers:
                    if customer.id in successful_ids:
                        customer.status = CustomerStatus.INACTIVE
                await db.commit()
                if failed_ids:
                    logger.warning(f"[CRON] {len(failed_ids)} customers kept ACTIVE for retry: {failed_ids}")

            duration = (datetime.utcnow() - start_time).total_seconds()
            removed_count = len(mikrotik_results["removed"])
            failed_count = len(mikrotik_results["failed"])
            logger.info(f"[CRON] Cleanup completed in {duration:.2f}s: {removed_count} removed, {failed_count} failed")

            try:
                logger.info(f"[CRON] Running safety net bypass cleanup...")
                async with mikrotik_lock:
                    bypass_cleaned = await _cleanup_bypassing_for_all_routers(db)
                if bypass_cleaned > 0:
                    logger.warning(f"[CRON] Safety net removed {bypass_cleaned} orphaned IP bindings!")
            except Exception as bypass_err:
                logger.error(f"[CRON] Safety net cleanup failed: {bypass_err}")

    except Exception as e:
        logger.error(f"[CRON] Cleanup job failed: {e}")
    finally:
        cleanup_running = False


# =============================================================================
# QUEUE SYNC (background job, currently disabled)
# =============================================================================

def _sync_queues_mikrotik_sync(router_customers_map: dict) -> dict:
    results = {"synced": 0, "errors": 0, "skipped": 0, "routers_connected": 0, "details": []}
    if not router_customers_map:
        logger.info("[SYNC] No routers to process")
        return results

    total_operations = 0

    for router_key, router_data in router_customers_map.items():
        router_info = router_data["router"]
        customers_data = router_data["customers"]
        if not customers_data:
            continue
        if total_operations >= SYNC_MAX_QUEUE_OPERATIONS_PER_RUN:
            logger.info(f"[SYNC] Reached max operations limit ({SYNC_MAX_QUEUE_OPERATIONS_PER_RUN}), will continue next run")
            break

        router_name = router_info["name"]
        router_ip = router_info["ip"]
        logger.info(f"[SYNC] Connecting to {router_name} ({router_ip}) for {len(customers_data)} customers...")

        api = None
        try:
            api = MikroTikAPI(router_info["ip"], router_info["username"], router_info["password"], router_info["port"], timeout=30, connect_timeout=5)
            if not api.connect():
                logger.error(f"[SYNC] Failed to connect to {router_name} ({router_ip})")
                results["errors"] += len(customers_data)
                results["details"].append({"router": router_name, "error": "Connection failed"})
                continue

            results["routers_connected"] += 1
            logger.info(f"[SYNC] Connected to {router_name} successfully")

            def send_with_retry(cmd: str, max_retries: int = 2) -> dict:
                for attempt in range(max_retries + 1):
                    result = api.send_command(cmd)
                    if result.get("error") == "Not connected" and attempt < max_retries:
                        logger.warning(f"[SYNC] Connection lost during {cmd}, reconnecting (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(0.5)
                        if api.connect():
                            logger.info(f"[SYNC] Reconnected successfully, retrying {cmd}")
                            continue
                        else:
                            logger.error(f"[SYNC] Reconnect failed")
                            break
                    return result
                return {"error": "Failed after retries"}

            logger.info(f"[SYNC] Fetching ARP table from {router_name} (optimized)...")
            arp_result = api.get_arp_minimal()
            if arp_result.get("error"):
                if arp_result.get("error") == "Not connected":
                    logger.warning(f"[SYNC] Connection lost, reconnecting...")
                    if api.connect():
                        arp_result = api.get_arp_minimal()
                if arp_result.get("error"):
                    logger.error(f"[SYNC] Failed to fetch ARP table: {arp_result.get('error')}")
                    arp_entries = []
                else:
                    arp_entries = arp_result.get("data", [])
            else:
                arp_entries = arp_result.get("data", [])
            logger.info(f"[SYNC] Got {len(arp_entries)} ARP entries")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

            logger.info(f"[SYNC] Fetching DHCP leases from {router_name} (optimized)...")
            dhcp_result = api.get_dhcp_leases_minimal()
            if dhcp_result.get("error"):
                if dhcp_result.get("error") == "Not connected":
                    logger.warning(f"[SYNC] Connection lost, reconnecting...")
                    if api.connect():
                        dhcp_result = api.get_dhcp_leases_minimal()
                if dhcp_result.get("error"):
                    logger.error(f"[SYNC] Failed to fetch DHCP leases: {dhcp_result.get('error')}")
                    dhcp_leases = []
                else:
                    dhcp_leases = dhcp_result.get("data", [])
            else:
                dhcp_leases = dhcp_result.get("data", [])
            logger.info(f"[SYNC] Got {len(dhcp_leases)} DHCP leases")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

            logger.info(f"[SYNC] Fetching hotspot hosts from {router_name} (optimized)...")
            hosts_result = api.get_hotspot_hosts_minimal()
            if hosts_result.get("error"):
                if hosts_result.get("error") == "Not connected":
                    logger.warning(f"[SYNC] Connection lost, reconnecting...")
                    if api.connect():
                        hosts_result = api.get_hotspot_hosts_minimal()
                if hosts_result.get("error"):
                    logger.error(f"[SYNC] Failed to fetch hotspot hosts: {hosts_result.get('error')}")
                    hotspot_hosts = []
                else:
                    hotspot_hosts = hosts_result.get("data", [])
            else:
                hotspot_hosts = hosts_result.get("data", [])
            logger.info(f"[SYNC] Got {len(hotspot_hosts)} hotspot hosts")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

            logger.info(f"[SYNC] Fetching hotspot active sessions from {router_name} (optimized)...")
            active_result = api.get_hotspot_active_minimal()
            if active_result.get("error"):
                if active_result.get("error") == "Not connected":
                    logger.warning(f"[SYNC] Connection lost, reconnecting...")
                    if api.connect():
                        active_result = api.get_hotspot_active_minimal()
                if active_result.get("error"):
                    logger.error(f"[SYNC] Failed to fetch hotspot active sessions: {active_result.get('error')}")
                    hotspot_active = []
                else:
                    hotspot_active = active_result.get("data", [])
            else:
                hotspot_active = active_result.get("data", [])
            logger.info(f"[SYNC] Got {len(hotspot_active)} hotspot active sessions")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

            logger.info(f"[SYNC] Fetching existing queues from {router_name} (optimized)...")
            queues_result = api.get_simple_queues_minimal()
            if queues_result.get("error"):
                if queues_result.get("error") == "Not connected":
                    logger.warning(f"[SYNC] Connection lost, reconnecting...")
                    if api.connect():
                        queues_result = api.get_simple_queues_minimal()
                if queues_result.get("error"):
                    logger.error(f"[SYNC] Failed to fetch queues: {queues_result.get('error')}")
                    existing_queues = []
                else:
                    existing_queues = queues_result.get("data", [])
            else:
                existing_queues = queues_result.get("data", [])
            logger.info(f"[SYNC] Got {len(existing_queues)} existing queues")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

            mac_to_ip = {}
            for lease in dhcp_leases:
                mac = lease.get("mac-address", "")
                if mac and lease.get("address"):
                    mac_to_ip[normalize_mac_address(mac)] = lease.get("address")
            for entry in arp_entries:
                mac = entry.get("mac-address", "")
                if mac and entry.get("address"):
                    mac_to_ip[normalize_mac_address(mac)] = entry.get("address")
            for host in hotspot_hosts:
                mac = host.get("mac-address", "")
                host_ip = host.get("address") or host.get("to-address")
                if mac and host_ip:
                    mac_to_ip[normalize_mac_address(mac)] = host_ip
            for session in hotspot_active:
                mac = session.get("mac-address", "")
                if mac and session.get("address"):
                    mac_to_ip[normalize_mac_address(mac)] = session.get("address")

            connected_customer_ips = []
            for customer_item in customers_data:
                customer_mac = normalize_mac_address(customer_item["mac_address"])
                customer_ip = mac_to_ip.get(customer_mac)
                if customer_ip:
                    connected_customer_ips.append(customer_ip)

            if connected_customer_ips:
                fasttrack_bypass_result = api.ensure_queue_fasttrack_bypass(connected_customer_ips)
                if fasttrack_bypass_result.get("error"):
                    logger.warning(f"[SYNC] FastTrack bypass setup failed on {router_name}: {fasttrack_bypass_result.get('error')}")
                elif fasttrack_bypass_result.get("fasttrack_enabled"):
                    logger.info(f"[SYNC] FastTrack bypass active on {router_name} (list={fasttrack_bypass_result.get('list_name')}, ips_added={fasttrack_bypass_result.get('ips_added', 0)})")

            queue_by_name = {str(q.get("name", "")).lower(): q for q in existing_queues if q.get("name")}
            queue_by_mac = {}
            for queue in existing_queues:
                queue_comment = str(queue.get("comment", ""))
                comment_upper = queue_comment.upper()
                if "MAC:" not in comment_upper:
                    continue
                try:
                    raw_mac = comment_upper.split("MAC:", 1)[1].split("|", 1)[0].strip().split(" ", 1)[0]
                    if raw_mac:
                        queue_by_mac[normalize_mac_address(raw_mac)] = queue
                except Exception:
                    continue
            logger.info(f"[SYNC] Built IP map with {len(mac_to_ip)} MAC->IP entries")

            synced = 0
            skipped_no_ip = 0
            skipped_already_ok = 0
            errors = 0
            created_queues = []
            updated_queues = []

            logger.info(f"[SYNC] Starting queue processing for {len(customers_data)} customers on {router_name}")

            for cust in customers_data:
                if total_operations >= SYNC_MAX_QUEUE_OPERATIONS_PER_RUN:
                    logger.info(f"[SYNC] Reached max operations limit, stopping customer processing")
                    break
                if not api.connected:
                    logger.warning(f"[SYNC] Connection to {router_name} lost, attempting reconnect...")
                    if not api.connect():
                        logger.error(f"[SYNC] Reconnect failed, aborting sync for {router_name}")
                        errors += len(customers_data) - (synced + skipped_no_ip + skipped_already_ok + errors)
                        break
                    logger.info(f"[SYNC] Reconnected to {router_name}")
                try:
                    if not cust.get("plan_speed"):
                        skipped_already_ok += 1
                        continue
                    normalized_mac = normalize_mac_address(cust["mac_address"])
                    username = normalized_mac.replace(":", "")
                    queue_name = f"plan_{username}"
                    rate_limit = api._parse_speed_to_mikrotik(cust["plan_speed"])
                    client_ip = mac_to_ip.get(normalized_mac)
                    if not client_ip:
                        skipped_no_ip += 1
                        continue
                    existing_queue = queue_by_name.get(queue_name.lower())
                    if not existing_queue:
                        existing_queue = queue_by_name.get(f"queue_{username}".lower())
                    if not existing_queue:
                        existing_queue = queue_by_mac.get(normalized_mac)
                    if existing_queue:
                        current_target = existing_queue.get("target", "")
                        current_limit = existing_queue.get("max-limit", "")
                        current_target_ip = current_target.split("/")[0].strip() if current_target else ""
                        queue_disabled = str(existing_queue.get("disabled", "false")).lower() == "true"
                        needs_update = (current_target_ip != client_ip or rate_limit != current_limit or queue_disabled)
                        if needs_update:
                            queue_id = existing_queue.get(".id")
                            if not queue_id:
                                logger.error(f"[SYNC] Queue {queue_name} has no .id, cannot update")
                                errors += 1
                                continue
                            time.sleep(SYNC_DELAY_BETWEEN_CUSTOMERS)
                            update_payload = {"numbers": queue_id, "target": f"{client_ip}/32", "max-limit": rate_limit}
                            if queue_disabled:
                                update_payload["disabled"] = "no"
                            update_result = api.send_command("/queue/simple/set", update_payload)
                            if update_result.get("error"):
                                logger.error(f"[SYNC] Failed to update queue {queue_name}: {update_result.get('error')}")
                                errors += 1
                            else:
                                logger.info(f"[SYNC] Updated queue {queue_name} -> {client_ip} ({rate_limit})")
                                updated_queues.append({"name": queue_name, "ip": client_ip, "limit": rate_limit})
                                synced += 1
                                total_operations += 1
                        else:
                            skipped_already_ok += 1
                    else:
                        time.sleep(SYNC_DELAY_BETWEEN_CUSTOMERS)
                        add_result = api.send_command("/queue/simple/add", {
                            "name": queue_name, "target": f"{client_ip}/32",
                            "max-limit": rate_limit, "comment": f"MAC:{cust['mac_address']}|Plan rate limit"
                        })
                        if add_result.get("error"):
                            if "already have" in add_result.get("error", "").lower():
                                logger.warning(f"[SYNC] Queue {queue_name} already exists (created elsewhere), reconciling...")
                                reconcile_result = api.get_simple_queues_minimal()
                                duplicate_queue = None
                                if reconcile_result.get("success") and reconcile_result.get("data"):
                                    for queue_item in reconcile_result["data"]:
                                        if str(queue_item.get("name", "")).lower() == queue_name.lower():
                                            duplicate_queue = queue_item
                                            break
                                if duplicate_queue and duplicate_queue.get(".id"):
                                    time.sleep(SYNC_DELAY_BETWEEN_CUSTOMERS)
                                    set_result = api.send_command("/queue/simple/set", {
                                        "numbers": duplicate_queue[".id"], "target": f"{client_ip}/32",
                                        "max-limit": rate_limit, "disabled": "no"
                                    })
                                    if set_result.get("error"):
                                        logger.error(f"[SYNC] Failed to reconcile existing queue {queue_name}: {set_result.get('error')}")
                                        errors += 1
                                    else:
                                        logger.info(f"[SYNC] Reconciled existing queue {queue_name} -> {client_ip} ({rate_limit})")
                                        updated_queues.append({"name": queue_name, "ip": client_ip, "limit": rate_limit})
                                        synced += 1
                                        total_operations += 1
                                else:
                                    skipped_already_ok += 1
                            else:
                                logger.error(f"[SYNC] Failed to create queue {queue_name}: {add_result.get('error')}")
                                errors += 1
                        else:
                            logger.info(f"[SYNC] CREATED queue {queue_name} -> {client_ip} ({rate_limit}) - BANDWIDTH NOW LIMITED")
                            created_queues.append({"name": queue_name, "ip": client_ip, "limit": rate_limit})
                            synced += 1
                            total_operations += 1
                except Exception as e:
                    logger.error(f"[SYNC] Error syncing customer {cust['id']} ({cust['mac_address']}): {e}")
                    errors += 1

            logger.info(f"[SYNC] Router {router_name} Summary:")
            logger.info(f"[SYNC]    - Queues created: {len(created_queues)}")
            logger.info(f"[SYNC]    - Queues updated: {len(updated_queues)}")
            logger.info(f"[SYNC]    - Skipped (no IP): {skipped_no_ip}")
            logger.info(f"[SYNC]    - Skipped (already correct): {skipped_already_ok}")
            logger.info(f"[SYNC]    - Errors: {errors}")
            if created_queues:
                logger.info(f"[SYNC] Created queues: {[q['name'] + '=' + q['limit'] for q in created_queues]}")
            if updated_queues:
                logger.info(f"[SYNC] Updated queues: {[q['name'] + '=' + q['limit'] for q in updated_queues]}")

            results["synced"] += synced
            results["errors"] += errors
            results["skipped"] += skipped_no_ip + skipped_already_ok
            results["details"].append({
                "router": router_name, "synced": synced, "errors": errors,
                "skipped_no_ip": skipped_no_ip, "skipped_already_ok": skipped_already_ok
            })
        except Exception as e:
            logger.error(f"[SYNC] Error processing router {router_name}: {e}")
            results["errors"] += len(customers_data)
            results["details"].append({"router": router_name, "error": str(e)})
        finally:
            if api:
                try:
                    api.disconnect()
                    logger.info(f"[SYNC] Disconnected from {router_name}")
                except Exception as e:
                    logger.warning(f"[SYNC] Error disconnecting from {router_name}: {e}")
            time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

    return results


async def sync_active_user_queues():
    global queue_sync_running
    if queue_sync_running:
        logger.warning("[SYNC] Previous queue sync still running, skipping this run")
        return
    queue_sync_running = True
    start_time = datetime.utcnow()
    logger.info("[SYNC] Starting queue sync job...")
    try:
        async with AsyncSession(async_engine) as db:
            now = datetime.utcnow()
            stmt = select(Customer).where(
                Customer.status == CustomerStatus.ACTIVE,
                Customer.mac_address.isnot(None),
                Customer.expiry > now
            ).options(selectinload(Customer.plan), selectinload(Customer.router))
            result = await db.execute(stmt)
            active_customers = result.scalars().all()
            if not active_customers:
                logger.info("[SYNC] No active customers to sync")
                return
            logger.info(f"[SYNC] Found {len(active_customers)} active customers to check")

            router_customers_map = {}
            no_router_customers = []
            for c in active_customers:
                if not c.plan or not c.plan.speed or not c.mac_address:
                    continue
                if c.router and getattr(c.router, 'auth_method', None) == 'RADIUS':
                    continue
                customer_data = {"id": c.id, "mac_address": c.mac_address, "plan_speed": c.plan.speed}
                if c.router:
                    router_key = f"{c.router.ip_address}:{c.router.port}"
                    if router_key not in router_customers_map:
                        router_customers_map[router_key] = {
                            "router": {
                                "ip": c.router.ip_address, "username": c.router.username,
                                "password": c.router.password, "port": c.router.port, "name": c.router.name
                            },
                            "customers": []
                        }
                    router_customers_map[router_key]["customers"].append(customer_data)
                else:
                    no_router_customers.append(customer_data)

            if no_router_customers:
                logger.warning(f"[SYNC] Skipping {len(no_router_customers)} customer(s) with no router assigned")
            logger.info(f"[SYNC] Grouped customers across {len(router_customers_map)} router(s)")

            async with mikrotik_lock:
                mikrotik_results = await asyncio.to_thread(_sync_queues_mikrotik_sync, router_customers_map)

            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"[SYNC] Job completed in {duration:.2f}s: "
                       f"{mikrotik_results['synced']} synced, "
                       f"{mikrotik_results['errors']} errors, "
                       f"{mikrotik_results['skipped']} skipped, "
                       f"{mikrotik_results['routers_connected']} router(s) connected")
    except Exception as e:
        logger.error(f"[SYNC] Queue sync job failed: {e}", exc_info=True)
    finally:
        queue_sync_running = False


# =============================================================================
# BANDWIDTH COLLECTION (background job)
# =============================================================================

def _parse_speed_value(speed_str: str) -> float:
    speed_str = speed_str.strip().upper()
    try:
        if speed_str.endswith('G'):
            return float(speed_str[:-1]) * 1000
        elif speed_str.endswith('M'):
            return float(speed_str[:-1])
        elif speed_str.endswith('K'):
            return float(speed_str[:-1]) / 1000
        else:
            return float(speed_str)
    except ValueError:
        return 0.0


def _bandwidth_reconnect(api, router_info: dict) -> bool:
    try:
        api.disconnect()
        if api.connect():
            logger.info(f"[BANDWIDTH] Reconnected to router {router_info['id']} at {router_info['ip_address']}")
            return True
    except Exception:
        pass
    logger.warning(f"[BANDWIDTH] Reconnect failed for router {router_info['id']}")
    return False


def _fetch_bandwidth_data_sync_for_router(router_info: dict):
    api = MikroTikAPI(
        router_info["ip_address"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5
    )
    if not api.connect():
        logger.warning(f"[BANDWIDTH] Failed to connect to router ID {router_info['id']} at {router_info['ip_address']}")
        return None

    traffic = api.get_interface_traffic()
    if not traffic.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            traffic = api.get_interface_traffic()

    hotspot_hosts = api.get_hotspot_hosts()
    if not hotspot_hosts.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            hotspot_hosts = api.get_hotspot_hosts()

    arp_entries = api.get_arp_entries()
    if not arp_entries.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            arp_entries = api.get_arp_entries()

    active_sessions = api.get_active_hotspot_users()
    if not active_sessions.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            active_sessions = api.get_active_hotspot_users()

    speed_stats = api.get_queue_speed_stats()
    if not speed_stats.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            speed_stats = api.get_queue_speed_stats()

    queues = api.send_command("/queue/simple/print")
    api.disconnect()

    logger.info(f"[BANDWIDTH] Router {router_info['id']} raw data:")
    logger.info(f"  - Hotspot active sessions: {len(active_sessions.get('data', []))}")
    logger.info(f"  - Hotspot hosts total: {hotspot_hosts.get('total', 0)}, bypassed: {hotspot_hosts.get('bypassed', 0)}")
    logger.info(f"  - ARP entries: {arp_entries.get('count', 0)}")
    logger.info(f"  - Queue stats: active_queues={speed_stats.get('data', {}).get('active_queues', 0)}, total_queues={speed_stats.get('data', {}).get('total_queues', 0)}")

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
    api = MikroTikAPI(
        settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT,
        timeout=15, connect_timeout=5
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
    try:
        now = datetime.utcnow()
        async for db in get_db():
            routers_result = await db.execute(select(Router))
            routers = routers_result.scalars().all()
            if not routers:
                logger.warning("No routers found in database for bandwidth collection")
                return

            for router in routers:
                if getattr(router, 'auth_method', None) == 'RADIUS':
                    continue
                try:
                    router_info = {
                        "id": router.id, "ip_address": router.ip_address,
                        "username": router.username, "password": router.password, "port": router.port
                    }
                    async with mikrotik_lock:
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

                    total_rx = 0
                    total_tx = 0
                    selected_interface = None
                    interfaces = traffic.get("data", [])

                    for iface in interfaces:
                        name = iface.get("name", "").lower()
                        if iface.get("running") and (name == "ether1" or "wan" in name or "gateway" in name):
                            total_rx = iface.get("rx_byte", 0)
                            total_tx = iface.get("tx_byte", 0)
                            selected_interface = iface.get("name")
                            break

                    if not selected_interface:
                        for iface in interfaces:
                            name = iface.get("name", "").lower()
                            if iface.get("running") and ("bridge" in name):
                                total_rx = iface.get("rx_byte", 0)
                                total_tx = iface.get("tx_byte", 0)
                                selected_interface = iface.get("name")
                                break

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

                    prev_result = await db.execute(
                        select(BandwidthSnapshot)
                        .where(BandwidthSnapshot.router_id == router_id)
                        .order_by(BandwidthSnapshot.recorded_at.desc())
                        .limit(1)
                    )
                    prev = prev_result.scalar_one_or_none()

                    interface_fetch_failed = (selected_interface is None and total_rx == 0 and total_tx == 0)
                    if interface_fetch_failed and prev and prev.interface_rx_bytes > 0:
                        logger.warning(f"[BANDWIDTH] Router {router_id}: Interface fetch failed, carrying forward previous byte counters to avoid data gap")
                        total_rx = prev.interface_rx_bytes
                        total_tx = prev.interface_tx_bytes

                    avg_download_bps = 0.0
                    avg_upload_bps = 0.0
                    time_diff = 0
                    if prev and prev.interface_rx_bytes > 0 and not interface_fetch_failed:
                        time_diff = (now - prev.recorded_at).total_seconds()
                        if time_diff > 0:
                            byte_diff_rx = total_rx - prev.interface_rx_bytes
                            byte_diff_tx = total_tx - prev.interface_tx_bytes
                            if byte_diff_rx >= 0 and byte_diff_tx >= 0:
                                if selected_interface and ("ether1" in selected_interface or "wan" in selected_interface.lower()):
                                    avg_download_bps = (byte_diff_rx * 8) / time_diff
                                    avg_upload_bps = (byte_diff_tx * 8) / time_diff
                                else:
                                    avg_download_bps = (byte_diff_tx * 8) / time_diff
                                    avg_upload_bps = (byte_diff_rx * 8) / time_diff
                                logger.info(f"[BANDWIDTH] Router {router_id}: time_diff={time_diff:.1f}s, byte_diff_rx={byte_diff_rx}, byte_diff_tx={byte_diff_tx}")
                                logger.info(f"[BANDWIDTH] Router {router_id}: Using '{selected_interface}' perspective - avg_download={avg_download_bps/1000000:.2f}Mbps, avg_upload={avg_upload_bps/1000000:.2f}Mbps")
                            else:
                                logger.warning(f"[BANDWIDTH] Router {router_id}: Counter reset detected (negative diff), skipping rate calc")
                    elif not interface_fetch_failed:
                        logger.info(f"[BANDWIDTH] Router {router_id}: No previous snapshot or rx_bytes=0, first measurement")

                    hotspot_fetch_ok = hotspot_hosts.get("success", False)
                    if hotspot_fetch_ok:
                        active_devices = hotspot_hosts.get("bypassed", 0) + hotspot_hosts.get("authorized", 0)
                    elif prev:
                        active_devices = prev.active_queues
                        logger.warning(f"[BANDWIDTH] Router {router_id}: Hotspot hosts fetch failed, carrying forward previous active_users={active_devices}")
                    else:
                        active_devices = 0

                    snapshot = BandwidthSnapshot(
                        router_id=router_id,
                        total_upload_bps=int(speed_data.get("total_upload_bps", 0)),
                        total_download_bps=int(speed_data.get("total_download_bps", 0)),
                        avg_upload_bps=avg_upload_bps,
                        avg_download_bps=avg_download_bps,
                        active_queues=active_devices,
                        active_sessions=len(active_sessions.get("data", [])),
                        interface_rx_bytes=total_rx,
                        interface_tx_bytes=total_tx,
                        recorded_at=now
                    )
                    db.add(snapshot)

                    queues = raw.get("queues", {})
                    if queues.get("success") and queues.get("data"):
                        for q in queues["data"]:
                            comment = q.get("comment", "")
                            mac = ""
                            if "MAC:" in comment:
                                mac = comment.split("MAC:")[1].split("|")[0].strip()
                            if not mac:
                                continue
                            bytes_str = q.get("bytes", "0/0")
                            bytes_parts = bytes_str.split("/")
                            upload_bytes = int(bytes_parts[0]) if len(bytes_parts) > 0 and bytes_parts[0].isdigit() else 0
                            download_bytes = int(bytes_parts[1]) if len(bytes_parts) > 1 and bytes_parts[1].isdigit() else 0
                            cust_result = await db.execute(
                                select(Customer).where(Customer.mac_address.ilike(f"%{mac}%"))
                            )
                            customer = cust_result.scalar_one_or_none()
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
                                    mac_address=mac, customer_id=customer.id if customer else None,
                                    queue_name=q.get("name", ""), target_ip=q.get("target", ""),
                                    upload_bytes=upload_bytes, download_bytes=download_bytes,
                                    max_limit=q.get("max-limit", ""), last_updated=now
                                )
                                db.add(usage)

                    logger.debug(f"Collected bandwidth snapshot for router {router.name} (ID: {router_id})")
                except Exception as router_error:
                    logger.error(f"Error collecting bandwidth from router {router.name}: {router_error}")
                    continue

            cutoff = now - timedelta(days=1)
            await db.execute(delete(BandwidthSnapshot).where(BandwidthSnapshot.recorded_at < cutoff))
            await db.commit()
            break

        logger.info(f"Bandwidth snapshot collected for {len(routers)} router(s)")
    except Exception as e:
        logger.error(f"Error collecting bandwidth snapshot: {e}")

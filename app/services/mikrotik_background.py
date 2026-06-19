"""
MikroTik Background Operations
===============================

All background job functions for MikroTik router management:
- Expired user cleanup (runs every ~67s)
- Queue sync for active users (rotating bounded router batch)
- Bandwidth snapshot collection (runs every ~157s)

Also contains shared MikroTik async wrappers and the
remove_user_from_mikrotik function used by multiple router files.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, or_
from sqlalchemy.orm import selectinload
from datetime import datetime, timedelta
from app.db.database import async_session, db_pool_snapshot
from app.db.models import (
    Router,
    Customer,
    CustomerStatus,
    BandwidthSnapshot,
    UserBandwidthUsage,
    CustomerUsagePeriod,
    Plan,
    ConnectionType,
    FupAction,
    RouterAuthMethod,
    AccessCredential,
    AccessCredStatus,
)
from app.services.mikrotik_api import (
    MikroTikAPI,
    is_hotspot_parent_queue_name,
    normalize_mac_address,
)
from app.services.router_availability import (
    ROUTER_OFFLINE_SKIP_PERIOD,
    record_router_availability,
    prune_router_availability_history,
)
from app.services.usage_tracking import record_usage
from app.services.fup import hotspot_throttle_rate_for_plan
from app.core.protected_devices import is_protected_device
from app.config import settings
import asyncio
from contextlib import asynccontextmanager
import logging
import time

logger = logging.getLogger(__name__)

SAFETY_NET_BYPASS_GRACE_PERIOD = timedelta(minutes=5)
BACKGROUND_DB_BUSY_THRESHOLD_PERCENT = 60
ROUTER_OFFLINE_CLEANUP_SKIP_PERIOD = ROUTER_OFFLINE_SKIP_PERIOD  # single source: see router_availability
EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_RUN = 60
EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_ROUTER = 15
SAFETY_NET_CLEANUP_MIN_INTERVAL = timedelta(minutes=10)
ACCESS_CREDENTIAL_REAPER_MIN_INTERVAL = timedelta(minutes=5)
BANDWIDTH_MAX_ROUTERS_PER_RUN = 8
BANDWIDTH_RUN_TIME_BUDGET_SECONDS = 90


class RouterLockManager:
    """Per-router async locks with a global concurrency semaphore.

    Operations on the same router serialize; different routers run concurrently
    up to *max_concurrent* at a time (to avoid exhausting the thread pool).
    """

    def __init__(self, max_concurrent: int = 3):
        self._locks: dict[str, asyncio.Lock] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)

    @asynccontextmanager
    async def acquire(self, router_key: str):
        async with self._semaphore:
            if router_key not in self._locks:
                self._locks[router_key] = asyncio.Lock()
            async with self._locks[router_key]:
                yield


router_locks = RouterLockManager()

# Shared state for background jobs
cleanup_running = False
queue_sync_running = False
_last_safety_net_cleanup_at: datetime | None = None
_last_access_credential_reaper_at: datetime | None = None
_bandwidth_router_cursor = 0
_queue_sync_router_cursor = 0

# Rate limiting constants for queue sync
SYNC_DELAY_BETWEEN_COMMANDS = 0.1
SYNC_DELAY_BETWEEN_CUSTOMERS = 0.05
SYNC_MAX_QUEUE_OPERATIONS_PER_RUN = 50
QUEUE_SYNC_MAX_ROUTERS_PER_RUN = 4


def _router_recently_offline(
    router,
    now: datetime,
    threshold: timedelta = ROUTER_OFFLINE_CLEANUP_SKIP_PERIOD,
) -> bool:
    last_checked = getattr(router, "last_checked_at", None)
    return (
        getattr(router, "last_status", None) is False
        and last_checked is not None
        and (now - last_checked) < threshold
    )


def _background_db_pool_is_busy(job_name: str) -> bool:
    snapshot = db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    if isinstance(checked_out_percent, (int, float)) and checked_out_percent >= BACKGROUND_DB_BUSY_THRESHOLD_PERCENT:
        logger.warning(
            "[%s] Skipping optional background work because DB pool is busy: "
            "checked_out=%s/%s (%.2f%%), status=%s",
            job_name,
            snapshot.get("checked_out"),
            snapshot.get("configured_max_app_connections"),
            checked_out_percent,
            snapshot.get("status"),
        )
        return True
    return False


def _interval_due(last_run_at: datetime | None, now: datetime, interval: timedelta) -> bool:
    return last_run_at is None or (now - last_run_at) >= interval


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

def _cleanup_single_router_hotspot_sync(router_info: dict, customers_data: list) -> dict:
    """Cleanup expired hotspot users on ONE router."""
    results = {"removed": [], "failed": [], "connected": False}
    if not customers_data:
        return results

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
        return results

    results["connected"] = True

    try:
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
    finally:
        api.disconnect()

    return results


def _cleanup_customer_from_mikrotik_sync(router_customers_map: dict) -> dict:
    """Multi-router wrapper (sequential fallback). Prefer per-router calls."""
    merged = {"removed": [], "failed": [], "routers_connected": 0}
    for router_data in router_customers_map.values():
        r = _cleanup_single_router_hotspot_sync(router_data["router"], router_data["customers"])
        merged["removed"].extend(r["removed"])
        merged["failed"].extend(r["failed"])
        if r["connected"]:
            merged["routers_connected"] += 1
    return merged


def _mac_compact_expr(column):
    return func.replace(func.replace(func.upper(column), ":", ""), "-", "")


async def _load_authorized_bypass_macs(
    db: AsyncSession,
    candidate_macs: set[str] | None = None,
    now: datetime | None = None,
) -> set[str]:
    now = now or datetime.utcnow()
    candidate_compacts = {
        mac.replace(":", "").replace("-", "").upper()
        for mac in (candidate_macs or set())
        if mac
    }
    authorized_macs: set[str] = set()

    customer_stmt = select(Customer.mac_address, Customer.status, Customer.expiry).where(
        Customer.mac_address.isnot(None)
    )
    if candidate_compacts:
        customer_stmt = customer_stmt.where(
            _mac_compact_expr(Customer.mac_address).in_(candidate_compacts)
        )

    customer_result = await db.execute(customer_stmt)
    for mac_address, status, expiry in customer_result.all():
        if not mac_address:
            continue
        normalized = normalize_mac_address(mac_address)
        if status in (CustomerStatus.ACTIVE, CustomerStatus.PENDING):
            authorized_macs.add(normalized)
        elif expiry and expiry > (now - SAFETY_NET_BYPASS_GRACE_PERIOD):
            authorized_macs.add(normalized)
            logger.debug("[SAFETY-NET] Grace period: keeping %s (expiry: %s)", normalized, expiry)

    cred_stmt = select(AccessCredential.bound_mac_address).where(
        AccessCredential.bound_mac_address.isnot(None),
        AccessCredential.status == AccessCredStatus.ACTIVE,
    )
    if candidate_compacts:
        cred_stmt = cred_stmt.where(
            _mac_compact_expr(AccessCredential.bound_mac_address).in_(candidate_compacts)
        )

    cred_result = await db.execute(cred_stmt)
    for (bound_mac,) in cred_result.all():
        if bound_mac:
            authorized_macs.add(normalize_mac_address(bound_mac))

    return authorized_macs


async def _filter_current_orphan_bypass_macs(candidate_macs: set[str]) -> set[str]:
    normalized_candidates = {normalize_mac_address(mac) for mac in candidate_macs if mac}
    if not normalized_candidates:
        return set()

    async with async_session() as fresh_db:
        currently_authorized = await _load_authorized_bypass_macs(
            fresh_db,
            candidate_macs=normalized_candidates,
            now=datetime.utcnow(),
        )

    protected = normalized_candidates & currently_authorized
    if protected:
        logger.info(
            "[SAFETY-NET] Skipping %d bypass binding(s) that became active during cleanup: %s",
            len(protected),
            sorted(protected),
        )

    return normalized_candidates - currently_authorized


def _find_router_binding_cleanup_candidates_sync(router_info: dict, active_macs: set) -> set[str]:
    candidates: set[str] = set()
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5
    )
    if not api.connect():
        return set()
    try:
        bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
        if not bindings_result.get("success"):
            return set()
        for binding in bindings_result.get("data", []):
            binding_mac = binding.get("mac-address", "")
            binding_type = binding.get("type", "")
            if not binding_mac or binding_type != "bypassed":
                continue
            normalized_mac = normalize_mac_address(binding_mac)
            if normalized_mac not in active_macs:
                candidates.add(normalized_mac)
        return candidates
    finally:
        api.disconnect()


def _remove_router_bindings_sync(router_info: dict, orphan_macs: set[str]) -> int:
    removed = 0
    normalized_orphans = {normalize_mac_address(mac) for mac in orphan_macs if mac}
    if not normalized_orphans:
        return 0

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
            if not binding_id:
                logger.warning(
                    "[SAFETY-NET] Skipping orphaned binding without .id for %s on %s",
                    binding_mac,
                    router_info["name"],
                )
                continue
            normalized_mac = normalize_mac_address(binding_mac)
            if normalized_mac in normalized_orphans:
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

        now = datetime.utcnow()
        active_macs = await _load_authorized_bypass_macs(
            db,
            now=now,
        )

        # Router scans below can take many seconds across multiple routers.
        # Release the caller's DB connection until we need to write again.
        await db.commit()

        # Payment callbacks can activate a MAC while this cleanup run is still
        # working. Scan routers first, then re-check all candidate MACs with a
        # single DB session before any removal, avoiding one checkout per
        # concurrent router task.
        async def _find_candidates_task(r):
            rk = f"{r.ip_address}:{r.port}"
            ri = {
                "ip": r.ip_address, "username": r.username,
                "password": r.password, "port": r.port, "name": r.name,
            }
            async with router_locks.acquire(rk):
                candidates = await asyncio.to_thread(
                    _find_router_binding_cleanup_candidates_sync,
                    ri,
                    active_macs,
                )
                return {
                    "router_key": rk,
                    "router_info": ri,
                    "candidates": {normalize_mac_address(mac) for mac in candidates if mac},
                }

        eligible = []
        skipped_offline = 0
        for r in routers:
            if getattr(r, "auth_method", None) == "RADIUS":
                continue
            if _router_recently_offline(r, now):
                skipped_offline += 1
                continue
            eligible.append(r)
        if skipped_offline:
            logger.info("[SAFETY-NET] Skipping %d recently-offline router(s)", skipped_offline)
        candidate_outcomes = await asyncio.gather(
            *[_find_candidates_task(r) for r in eligible],
            return_exceptions=True,
        )
        candidate_groups = []
        all_candidates: set[str] = set()
        for i, outcome in enumerate(candidate_outcomes):
            if isinstance(outcome, Exception):
                logger.error(f"[SAFETY-NET] Error scanning router {eligible[i].name}: {outcome}")
                continue
            candidates = outcome.get("candidates", set())
            if candidates:
                candidate_groups.append(outcome)
                all_candidates.update(candidates)

        if not all_candidates:
            return 0

        confirmed_orphans = await _filter_current_orphan_bypass_macs(all_candidates)
        if not confirmed_orphans:
            return 0

        async def _remove_task(group: dict):
            to_remove = group["candidates"] & confirmed_orphans
            if not to_remove:
                return 0
            async with router_locks.acquire(group["router_key"]):
                return await asyncio.to_thread(
                    _remove_router_bindings_sync,
                    group["router_info"],
                    to_remove,
                )

        removal_outcomes = await asyncio.gather(
            *[_remove_task(group) for group in candidate_groups],
            return_exceptions=True,
        )
        for i, outcome in enumerate(removal_outcomes):
            if isinstance(outcome, Exception):
                logger.error(f"[SAFETY-NET] Error removing bindings on router {candidate_groups[i]['router_info']['name']}: {outcome}")
            else:
                total_removed += outcome
    except Exception as e:
        logger.error(f"[SAFETY-NET] Cleanup failed: {e}")
    return total_removed


def _cleanup_single_router_pppoe_sync(router_info: dict, customers_data: list) -> dict:
    """Cleanup expired PPPoE users on ONE router."""
    results = {"removed": [], "failed": [], "connected": False}
    if not customers_data:
        return results

    logger.info(f"[CRON-PPPoE] Processing {len(customers_data)} PPPoE customers on router {router_info['name']} ({router_info['ip']})")

    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        logger.error(f"[CRON-PPPoE] Failed to connect to router {router_info['name']}")
        for cust in customers_data:
            results["failed"].append({"id": cust["id"], "error": f"Failed to connect to router {router_info['name']}"})
        return results

    results["connected"] = True

    try:
        for cust in customers_data:
            try:
                pppoe_user = cust["pppoe_username"]
                logger.info(f"[CRON-PPPoE] Removing expired PPPoE user: {pppoe_user} (customer {cust['id']})")

                disconnect_result = api.disconnect_pppoe_session(pppoe_user)
                remove_result = api.remove_pppoe_secret(pppoe_user)

                if remove_result.get("error"):
                    results["failed"].append({"id": cust["id"], "error": remove_result["error"]})
                    logger.error(f"[CRON-PPPoE] Failed to remove secret for {pppoe_user}: {remove_result['error']}")
                else:
                    results["removed"].append({
                        "id": cust["id"],
                        "details": {
                            "disconnected": disconnect_result.get("disconnected", 0),
                            "secret_action": remove_result.get("action", "unknown"),
                        }
                    })
                    logger.info(f"[CRON-PPPoE] Removed PPPoE user {pppoe_user}")
            except Exception as e:
                results["failed"].append({"id": cust["id"], "error": str(e)})
                logger.error(f"[CRON-PPPoE] Error removing customer {cust['id']}: {e}")
    finally:
        api.disconnect()

    return results


def _cleanup_pppoe_customers_sync(router_pppoe_map: dict) -> dict:
    """Multi-router wrapper (sequential fallback). Prefer per-router calls."""
    merged = {"removed": [], "failed": [], "routers_connected": 0}
    for router_data in router_pppoe_map.values():
        r = _cleanup_single_router_pppoe_sync(router_data["router"], router_data["customers"])
        merged["removed"].extend(r["removed"])
        merged["failed"].extend(r["failed"])
        if r["connected"]:
            merged["routers_connected"] += 1
    return merged


async def cleanup_expired_users_background():
    global cleanup_running, _last_safety_net_cleanup_at, _last_access_credential_reaper_at
    if cleanup_running:
        logger.warning("[CRON] Previous cleanup still running, skipping this run")
        return
    if _background_db_pool_is_busy("CRON"):
        return
    cleanup_running = True
    start_time = datetime.utcnow()
    try:
        async with async_session() as db:
            now = datetime.utcnow()
            from sqlalchemy import or_

            stmt = select(Customer).options(
                selectinload(Customer.router),
                selectinload(Customer.plan),
            ).where(
                Customer.status == CustomerStatus.ACTIVE,
                Customer.expiry.isnot(None),
                Customer.expiry <= now,
                or_(
                    Customer.mac_address.isnot(None),
                    Customer.pppoe_username.isnot(None),
                )
            )
            result = await db.execute(stmt)
            expired_customers = result.scalars().all()
            if not expired_customers:
                return
            logger.info(f"[CRON] Found {len(expired_customers)} expired ACTIVE customers to cleanup")

            # Do not keep a DB connection checked out while RouterOS cleanup
            # runs. Recheck expiry after releasing the first transaction so a
            # customer renewed during this DB phase is not removed from the
            # router with stale expiry data.
            await db.commit()

            candidate_ids = [customer.id for customer in expired_customers]
            current_state = await db.execute(
                select(Customer.id, Customer.status, Customer.expiry).where(
                    Customer.id.in_(candidate_ids)
                )
            )
            now_before_router_cleanup = datetime.utcnow()
            still_expired_ids: set[int] = set()
            renewed_ids: list[int] = []
            for customer_id, status, expiry in current_state.all():
                if status == CustomerStatus.ACTIVE and expiry and expiry <= now_before_router_cleanup:
                    still_expired_ids.add(customer_id)
                else:
                    renewed_ids.append(customer_id)

            if renewed_ids:
                logger.warning(
                    "[CRON] Skipping %d customer(s) renewed or already deactivated before router cleanup: %s",
                    len(renewed_ids),
                    renewed_ids,
                )

            expired_customers = [
                customer for customer in expired_customers
                if customer.id in still_expired_ids
            ]

            await db.commit()

            if not expired_customers:
                return

            router_customers_map = {}
            router_pppoe_map = {}
            no_router_customers = []
            offline_skipped = []
            batch_deferred = []
            scheduled_router_cleanup_count = 0
            per_router_cleanup_counts: dict[str, int] = {}

            def should_schedule_router_cleanup(customer_id: int, router_key: str) -> bool:
                nonlocal scheduled_router_cleanup_count
                if scheduled_router_cleanup_count >= EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_RUN:
                    batch_deferred.append(customer_id)
                    return False
                current_router_count = per_router_cleanup_counts.get(router_key, 0)
                if current_router_count >= EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_ROUTER:
                    batch_deferred.append(customer_id)
                    return False
                scheduled_router_cleanup_count += 1
                per_router_cleanup_counts[router_key] = current_router_count + 1
                return True

            for c in expired_customers:
                is_pppoe = c.pppoe_username and (
                    not c.mac_address
                    or (c.plan and c.plan.connection_type and c.plan.connection_type.value == "pppoe")
                )

                if is_pppoe:
                    if not c.router:
                        c.status = CustomerStatus.INACTIVE
                        continue
                    if _router_recently_offline(c.router, now):
                        offline_skipped.append(c.id)
                        continue
                    router_key = f"{c.router.ip_address}:{c.router.port}"
                    if not should_schedule_router_cleanup(c.id, router_key):
                        continue
                    if router_key not in router_pppoe_map:
                        router_pppoe_map[router_key] = {
                            "router": {
                                "id": c.router.id,
                                "ip": c.router.ip_address, "username": c.router.username,
                                "password": c.router.password, "port": c.router.port, "name": c.router.name
                            },
                            "customers": []
                        }
                    router_pppoe_map[router_key]["customers"].append({
                        "id": c.id, "name": c.name, "pppoe_username": c.pppoe_username,
                        "expiry": c.expiry, "router_id": c.router_id
                    })
                    continue

                if not c.mac_address:
                    continue
                if c.router and getattr(c.router, 'auth_method', None) == 'RADIUS':
                    c.status = CustomerStatus.INACTIVE
                    continue
                if c.router and _router_recently_offline(c.router, now):
                    offline_skipped.append(c.id)
                    continue
                customer_data = {
                    "id": c.id, "name": c.name, "mac_address": c.mac_address,
                    "expiry": c.expiry, "router_id": c.router_id
                }
                if c.router:
                    router_key = f"{c.router.ip_address}:{c.router.port}"
                    if not should_schedule_router_cleanup(c.id, router_key):
                        continue
                    if router_key not in router_customers_map:
                        router_customers_map[router_key] = {
                            "router": {
                                "id": c.router.id,
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

            if offline_skipped:
                logger.warning(
                    "[CRON] Skipping %d customer(s) on recently-offline routers: %s",
                    len(offline_skipped), offline_skipped,
                )

            if batch_deferred:
                logger.warning(
                    "[CRON] Deferred router cleanup for %d expired customer(s) due to batch limits "
                    "(max_per_run=%d, max_per_router=%d); DB rows remain ACTIVE until router cleanup succeeds: %s",
                    len(batch_deferred),
                    EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_RUN,
                    EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_ROUTER,
                    batch_deferred[:50],
                )

            pppoe_count = sum(len(rd["customers"]) for rd in router_pppoe_map.values())
            hotspot_count = sum(len(rd["customers"]) for rd in router_customers_map.values())
            logger.info(f"[CRON] Grouped: {hotspot_count} hotspot across {len(router_customers_map)} router(s), "
                        f"{pppoe_count} PPPoE across {len(router_pppoe_map)} router(s)")

            # Do not keep a DB connection checked out while RouterOS cleanup
            # runs in worker threads.
            await db.commit()

            # --- Hotspot cleanup (concurrent per-router) ---
            mikrotik_results = {"removed": [], "failed": [], "routers_connected": 0}
            offline_router_ids: set[int] = set()
            if router_customers_map:
                async def _hotspot_task(rk, rd):
                    async with router_locks.acquire(rk):
                        return await asyncio.to_thread(
                            _cleanup_single_router_hotspot_sync, rd["router"], rd["customers"],
                        )

                hotspot_items = list(router_customers_map.items())
                hotspot_outcomes = await asyncio.gather(
                    *[_hotspot_task(rk, rd) for rk, rd in hotspot_items],
                    return_exceptions=True,
                )
                for (_rk, rd), outcome in zip(hotspot_items, hotspot_outcomes):
                    if isinstance(outcome, Exception):
                        logger.error("[CRON] Hotspot cleanup task error: %s", outcome)
                        continue
                    mikrotik_results["removed"].extend(outcome["removed"])
                    mikrotik_results["failed"].extend(outcome["failed"])
                    if outcome["connected"]:
                        mikrotik_results["routers_connected"] += 1
                    elif rd["router"].get("id"):
                        offline_router_ids.add(rd["router"]["id"])

            # --- PPPoE cleanup (concurrent per-router) ---
            pppoe_results = {"removed": [], "failed": [], "routers_connected": 0}
            if router_pppoe_map:
                async def _pppoe_task(rk, rd):
                    async with router_locks.acquire(rk):
                        return await asyncio.to_thread(
                            _cleanup_single_router_pppoe_sync, rd["router"], rd["customers"],
                        )

                pppoe_items = list(router_pppoe_map.items())
                pppoe_outcomes = await asyncio.gather(
                    *[_pppoe_task(rk, rd) for rk, rd in pppoe_items],
                    return_exceptions=True,
                )
                for (_rk, rd), outcome in zip(pppoe_items, pppoe_outcomes):
                    if isinstance(outcome, Exception):
                        logger.error("[CRON] PPPoE cleanup task error: %s", outcome)
                        continue
                    pppoe_results["removed"].extend(outcome["removed"])
                    pppoe_results["failed"].extend(outcome["failed"])
                    if outcome["connected"]:
                        pppoe_results["routers_connected"] += 1
                    elif rd["router"].get("id"):
                        offline_router_ids.add(rd["router"]["id"])

            all_successful_ids = set(
                [r["id"] for r in mikrotik_results["removed"]] +
                [r["id"] for r in pppoe_results["removed"]]
            )
            all_failed_ids = set(
                [r["id"] for r in mikrotik_results["failed"]] +
                [r["id"] for r in pppoe_results["failed"]]
            )

            now_after_cleanup = datetime.utcnow()
            post_cleanup_deactivated_count = 0
            skipped_repaid_count = 0
            for router_id in offline_router_ids:
                try:
                    await record_router_availability(
                        db,
                        router_id,
                        False,
                        "expired_cleanup",
                        checked_at=now_after_cleanup,
                    )
                except Exception as availability_err:
                    logger.warning(
                        "[CRON] Failed to record router %s offline after cleanup failure: %s",
                        router_id,
                        availability_err,
                    )
            for customer in expired_customers:
                if customer.id in all_successful_ids:
                    await db.refresh(customer)
                    if customer.expiry and customer.expiry > now_after_cleanup:
                        logger.warning(
                            "[CRON] Customer %s received new payment during cleanup "
                            "(expiry=%s > now=%s), skipping deactivation",
                            customer.id, customer.expiry, now_after_cleanup,
                        )
                        skipped_repaid_count += 1
                        continue
                    if customer.status != CustomerStatus.INACTIVE:
                        customer.status = CustomerStatus.INACTIVE
                        post_cleanup_deactivated_count += 1
            await db.commit()
            if skipped_repaid_count:
                logger.warning(
                    "[CRON] Skipped %d customer(s) that received new payments during cleanup",
                    skipped_repaid_count,
                )
            if post_cleanup_deactivated_count:
                logger.warning(
                    "[CRON] Marked %d additional expired customer(s) INACTIVE after router cleanup",
                    post_cleanup_deactivated_count,
                )

            if all_failed_ids:
                logger.warning(f"[CRON] {len(all_failed_ids)} customers kept ACTIVE for retry: {list(all_failed_ids)}")

            duration = (datetime.utcnow() - start_time).total_seconds()
            removed_total = len(mikrotik_results["removed"]) + len(pppoe_results["removed"])
            failed_total = len(mikrotik_results["failed"]) + len(pppoe_results["failed"])
            logger.info(f"[CRON] Cleanup completed in {duration:.2f}s: {removed_total} removed "
                        f"(hotspot={len(mikrotik_results['removed'])}, pppoe={len(pppoe_results['removed'])}), "
                        f"{failed_total} failed")

            now_optional = datetime.utcnow()
            if _background_db_pool_is_busy("CRON-SAFETY-NET"):
                logger.warning("[CRON] Skipping safety net and access credential reaper due to DB pool pressure")
                return

            try:
                if _interval_due(_last_safety_net_cleanup_at, now_optional, SAFETY_NET_CLEANUP_MIN_INTERVAL):
                    logger.info("[CRON] Running safety net bypass cleanup...")
                    _last_safety_net_cleanup_at = now_optional
                    bypass_cleaned = await _cleanup_bypassing_for_all_routers(db)
                    if bypass_cleaned > 0:
                        logger.warning(f"[CRON] Safety net removed {bypass_cleaned} orphaned IP bindings!")
                else:
                    logger.debug("[CRON] Safety net cleanup not due yet")
            except Exception as bypass_err:
                logger.error(f"[CRON] Safety net cleanup failed: {bypass_err}")

            try:
                if _interval_due(_last_access_credential_reaper_at, now_optional, ACCESS_CREDENTIAL_REAPER_MIN_INTERVAL):
                    _last_access_credential_reaper_at = now_optional
                    released = await _reap_idle_access_credentials(db)
                    if released:
                        logger.info(f"[CRON] Released {released} idle access credential(s)")
                else:
                    logger.debug("[CRON] Access credential reaper not due yet")
            except Exception as reap_err:
                logger.error(f"[CRON] Access credential reaper failed: {reap_err}")

    except Exception as e:
        from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
        from app.db.database import db_pool_status

        logger.error(f"[CRON] Cleanup job failed: {e}")
        if isinstance(e, SQLAlchemyTimeoutError):
            logger.error("[CRON] DB pool status at cleanup failure: %s", db_pool_status())
    finally:
        cleanup_running = False


# =============================================================================
# Idle access credential reaper
# =============================================================================

def _scan_router_idle_credentials_sync(
    router_info: dict,
    creds: list,
    idle_threshold_seconds: int,
) -> dict:
    """Inspect /ip/hotspot/host once per router and decide which credentials to release.

    A credential is released when its bound MAC is either:
      * absent from /ip/hotspot/host entirely, or
      * present with an idle-time exceeding ``idle_threshold_seconds``.

    Returns ``{"to_release": [{"id": int, "mac": str, "bytes_in": int, "bytes_out": int}, ...],
              "to_update": [{"id": int, "bytes_in": int, "bytes_out": int, "ip": str}, ...]}``.

    No DB writes happen here; the async caller applies the changes.
    """
    from app.services.access_credentials import queue_name_for_credential

    out = {"to_release": [], "to_update": []}
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        logger.warning(f"[REAPER] Could not connect to {router_info.get('name')}, skipping")
        return out

    try:
        hosts_resp = api.send_command("/ip/hotspot/host/print")
        hosts_by_mac = {}
        if hosts_resp.get("success") and hosts_resp.get("data"):
            for h in hosts_resp["data"]:
                hm = h.get("mac-address", "")
                if hm:
                    hosts_by_mac[normalize_mac_address(hm)] = h

        # Pull bindings + queues once so per-cred release is just a lookup + remove.
        bindings_resp = api.send_command("/ip/hotspot/ip-binding/print")
        bindings_by_mac: dict[str, str] = {}
        if bindings_resp.get("success") and bindings_resp.get("data"):
            for b in bindings_resp["data"]:
                bm = b.get("mac-address", "")
                bid = b.get(".id")
                if bm and bid:
                    bindings_by_mac[normalize_mac_address(bm)] = bid

        queues_resp = api.send_command("/queue/simple/print")
        queues_by_name: dict[str, str] = {}
        if queues_resp.get("success") and queues_resp.get("data"):
            for q in queues_resp["data"]:
                qn = q.get("name", "")
                qid = q.get(".id")
                if qn and qid:
                    queues_by_name[qn] = qid

        now_utc = datetime.utcnow()

        for cred in creds:
            mac = cred.get("bound_mac_address")
            if not mac:
                continue
            wanted = normalize_mac_address(mac)
            host = hosts_by_mac.get(wanted)
            should_release = False
            if not host:
                # After a successful login the kick removes the host entry so
                # MikroTik can re-evaluate the device as bypassed. There is a
                # brief window (a few seconds) where the host entry is gone
                # but the device is still active. Treat any credential bound
                # within the last 2 minutes as "recently connected" and skip
                # the absent-host release to avoid kicking live users.
                bound_at_str = cred.get("bound_at")
                recently_bound = False
                if bound_at_str:
                    try:
                        from datetime import timezone
                        bound_at = datetime.fromisoformat(bound_at_str)
                        # Handle both timezone-aware and naive datetimes
                        if bound_at.tzinfo is not None:
                            age_seconds = (now_utc.replace(tzinfo=timezone.utc) - bound_at).total_seconds()
                        else:
                            age_seconds = (now_utc - bound_at).total_seconds()
                        recently_bound = age_seconds < 120
                    except (ValueError, TypeError):
                        pass
                if not recently_bound:
                    should_release = True
            else:
                idle_str = host.get("idle-time", "")
                idle_seconds = _parse_mikrotik_duration(idle_str)
                if idle_seconds >= idle_threshold_seconds:
                    should_release = True

            if should_release:
                binding_id = bindings_by_mac.get(wanted)
                if binding_id:
                    api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                queue_id = queues_by_name.get(queue_name_for_credential(cred["id"]))
                if queue_id:
                    api.send_command("/queue/simple/remove", {"numbers": queue_id})
                out["to_release"].append({
                    "id": cred["id"],
                    "mac": mac,
                    "bytes_in": int(host.get("bytes-in", 0) or 0) if host else 0,
                    "bytes_out": int(host.get("bytes-out", 0) or 0) if host else 0,
                    "ip": (host.get("address") or host.get("to-address")) if host else None,
                })
            else:
                out["to_update"].append({
                    "id": cred["id"],
                    "bytes_in": int(host.get("bytes-in", 0) or 0),
                    "bytes_out": int(host.get("bytes-out", 0) or 0),
                    "ip": host.get("address") or host.get("to-address"),
                })
        return out
    finally:
        api.disconnect()


def _parse_mikrotik_duration(s: str) -> int:
    """Parse MikroTik durations like '1h22m13s', '45s', '2d3h' into total seconds."""
    if not s:
        return 0
    import re
    total = 0
    for value, unit in re.findall(r"(\d+)([wdhms])", s):
        v = int(value)
        if unit == "w":
            total += v * 7 * 86400
        elif unit == "d":
            total += v * 86400
        elif unit == "h":
            total += v * 3600
        elif unit == "m":
            total += v * 60
        elif unit == "s":
            total += v
    return total


async def _reap_idle_access_credentials(db: AsyncSession) -> int:
    """Free credentials whose bound MAC is gone or idle, and refresh usage stats."""
    from app.db.models import AccessCredential, AccessCredStatus, Router as RouterModel
    from app.config import settings as _settings

    threshold_minutes = max(1, int(getattr(_settings, "ACCESS_CRED_IDLE_RELEASE_MINUTES", 15)))
    threshold_seconds = threshold_minutes * 60

    stmt = (
        select(AccessCredential)
        .options(selectinload(AccessCredential.router))
        .where(
            AccessCredential.bound_mac_address.isnot(None),
            AccessCredential.status == AccessCredStatus.ACTIVE,
        )
    )
    result = await db.execute(stmt)
    creds = list(result.scalars().all())
    if not creds:
        return 0

    by_router: dict[int, dict] = {}
    now = datetime.utcnow()
    skipped_offline = 0
    for c in creds:
        if not c.router:
            continue
        # RADIUS routers manage sessions externally; we just trust DB state.
        am = getattr(c.router, "auth_method", None)
        if am is not None and getattr(am, "value", None) == "RADIUS":
            continue
        if _router_recently_offline(c.router, now):
            skipped_offline += 1
            continue
        rid = c.router.id
        if rid not in by_router:
            by_router[rid] = {
                "router_info": {
                    "ip": c.router.ip_address,
                    "username": c.router.username,
                    "password": c.router.password,
                    "port": c.router.port,
                    "name": c.router.name,
                },
                "creds": [],
            }
        by_router[rid]["creds"].append({
            "id": c.id,
            "bound_mac_address": c.bound_mac_address,
            "bound_at": c.bound_at.isoformat() if c.bound_at else None,
        })

    if not by_router:
        if skipped_offline:
            logger.info("[REAPER] Skipping %d credential(s) on recently-offline routers", skipped_offline)
        return 0
    if skipped_offline:
        logger.info("[REAPER] Skipping %d credential(s) on recently-offline routers", skipped_offline)

    await db.commit()

    async def _scan(rid: int, bundle: dict):
        async with router_locks.acquire(f"{bundle['router_info']['ip']}:{bundle['router_info']['port']}"):
            return rid, await asyncio.to_thread(
                _scan_router_idle_credentials_sync,
                bundle["router_info"],
                bundle["creds"],
                threshold_seconds,
            )

    outcomes = await asyncio.gather(
        *[_scan(rid, bundle) for rid, bundle in by_router.items()],
        return_exceptions=True,
    )

    cred_by_id = {c.id: c for c in creds}
    released_count = 0
    now = datetime.utcnow()

    for outcome in outcomes:
        if isinstance(outcome, Exception):
            logger.error(f"[REAPER] Router scan failed: {outcome}")
            continue
        _rid, scan = outcome
        for entry in scan.get("to_release", []):
            cred = cred_by_id.get(entry["id"])
            if not cred:
                continue
            if entry.get("bytes_in"):
                cred.total_bytes_in = (cred.total_bytes_in or 0) + entry["bytes_in"]
            if entry.get("bytes_out"):
                cred.total_bytes_out = (cred.total_bytes_out or 0) + entry["bytes_out"]
            if entry.get("ip"):
                cred.last_seen_ip = entry["ip"]
            cred.last_seen_at = now
            cred.bound_mac_address = None
            cred.bound_at = None
            released_count += 1

        for entry in scan.get("to_update", []):
            cred = cred_by_id.get(entry["id"])
            if not cred:
                continue
            cred.last_seen_at = now
            if entry.get("ip"):
                cred.last_seen_ip = entry["ip"]
            # Note: we don't accumulate bytes here because MikroTik counters
            # are session-cumulative; we only record final totals on release.

    await db.commit()
    return released_count


# =============================================================================
# QUEUE SYNC (background job, rotating bounded router batch)
# =============================================================================

def _sync_single_router_queues_sync(router_info: dict, customers_data: list) -> dict:
    """
    Queue sync for ONE router.

    Isolated on purpose: this is designed to be invoked from `asyncio.to_thread`
    under `router_locks.acquire(router_key)`, so that a slow or broken router
    only delays its own task and never blocks sync for any other router in the
    fleet. Each invocation opens its own `MikroTikAPI` connection, does its
    work, and always disconnects in the `finally` block.

    Returns a dict with per-router counters plus an optional `details` entry
    describing what happened (consumed by the aggregator in
    `sync_active_user_queues`).
    """
    results = {
        "synced": 0,
        "errors": 0,
        "skipped": 0,
        "routers_connected": 0,
        "details": None,
    }
    if not customers_data:
        return results

    router_name = router_info["name"]
    router_ip = router_info["ip"]
    logger.info(f"[SYNC] Connecting to {router_name} ({router_ip}) for {len(customers_data)} customers...")

    # Per-router operation budget. Was a global counter before the
    # parallel refactor; making it per-router means one large router
    # cannot starve the others, and any overflow just rolls over to the
    # next sync tick for that specific router.
    total_operations = 0

    api = None
    try:
        api = MikroTikAPI(router_info["ip"], router_info["username"], router_info["password"], router_info["port"], timeout=30, connect_timeout=5)
        if not api.connect():
            logger.error(f"[SYNC] Failed to connect to {router_name} ({router_ip})")
            results["errors"] = len(customers_data)
            results["details"] = {"router": router_name, "error": "Connection failed"}
            return results

        results["routers_connected"] = 1
        logger.info(f"[SYNC] Connected to {router_name} successfully")

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

        # Remove MikroTik's auto-generated hotspot parent simple queue(s).
        # MikroTik recreates a dynamic "hs-<hotspot-name>" simple queue
        # (target=bridge, max-limit=unlimited/unlimited) whenever the
        # hotspot service restarts. Because simple queues match top-down
        # and it targets the whole bridge, it shadows every per-user
        # plan_<username> queue - net effect: all hotspot users get
        # unlimited speed. Drop any such entry we just fetched and also
        # prune it from the router so subsequent matching works.
        hs_parent_queues = [
            q for q in existing_queues
            if is_hotspot_parent_queue_name(q.get("name", ""))
        ]
        if hs_parent_queues:
            logger.warning(
                "[SYNC] Found %d auto-generated hotspot parent queue(s) on %s: %s",
                len(hs_parent_queues), router_name,
                [q.get("name") for q in hs_parent_queues],
            )
            hs_cleanup = api.remove_hotspot_parent_queues()
            if hs_cleanup.get("removed"):
                logger.warning(
                    "[SYNC] Removed %d stale hotspot parent queue(s) on %s - "
                    "per-user plan queues will now enforce speed limits",
                    hs_cleanup["removed"], router_name,
                )
            existing_queues = [
                q for q in existing_queues
                if not is_hotspot_parent_queue_name(q.get("name", ""))
            ]
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
                logger.info(f"[SYNC] {router_name}: reached per-router max operations limit, will continue next run")
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

        results["synced"] = synced
        results["errors"] = errors
        results["skipped"] = skipped_no_ip + skipped_already_ok
        results["details"] = {
            "router": router_name, "synced": synced, "errors": errors,
            "skipped_no_ip": skipped_no_ip, "skipped_already_ok": skipped_already_ok,
        }
    except Exception as e:
        logger.error(f"[SYNC] Error processing router {router_name}: {e}")
        results["errors"] = len(customers_data)
        results["details"] = {"router": router_name, "error": str(e)}
    finally:
        if api:
            try:
                api.disconnect()
                logger.info(f"[SYNC] Disconnected from {router_name}")
            except Exception as e:
                logger.warning(f"[SYNC] Error disconnecting from {router_name}: {e}")

    return results


def _sync_queues_mikrotik_sync(router_customers_map: dict) -> dict:
    """
    Sequential multi-router wrapper around :func:`_sync_single_router_queues_sync`.

    Kept for any direct callers that still invoke the sync function without
    going through :func:`sync_active_user_queues` (which runs routers in
    parallel via ``asyncio.gather``). Prefer the async path for background
    jobs — one slow router here will still block the others because this
    wrapper iterates sequentially.
    """
    results = {"synced": 0, "errors": 0, "skipped": 0, "routers_connected": 0, "details": []}
    if not router_customers_map:
        logger.info("[SYNC] No routers to process")
        return results

    for router_data in router_customers_map.values():
        if not router_data.get("customers"):
            continue
        per_router = _sync_single_router_queues_sync(router_data["router"], router_data["customers"])
        results["synced"] += per_router["synced"]
        results["errors"] += per_router["errors"]
        results["skipped"] += per_router["skipped"]
        results["routers_connected"] += per_router["routers_connected"]
        if per_router.get("details"):
            results["details"].append(per_router["details"])
        time.sleep(SYNC_DELAY_BETWEEN_COMMANDS)

    return results


async def sync_active_user_queues():
    global queue_sync_running, _queue_sync_router_cursor
    if queue_sync_running:
        logger.warning("[SYNC] Previous queue sync still running, skipping this run")
        return
    queue_sync_running = True
    start_time = datetime.utcnow()
    logger.info("[SYNC] Starting queue sync job...")
    try:
        if _background_db_pool_is_busy("QUEUE-SYNC"):
            return

        pending_router_items = []
        async with async_session() as db:
            now = datetime.utcnow()
            stmt = (
                select(Customer)
                .join(Plan, Customer.plan_id == Plan.id)
                .join(Router, Customer.router_id == Router.id)
                .where(
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.mac_address.isnot(None),
                    Customer.expiry > now,
                    Plan.connection_type == ConnectionType.HOTSPOT,
                    Router.auth_method == RouterAuthMethod.DIRECT_API,
                )
                .options(selectinload(Customer.plan), selectinload(Customer.router))
            )
            result = await db.execute(stmt)
            active_customers = result.scalars().all()
            if not active_customers:
                logger.info("[SYNC] No active customers to sync")
                return
            logger.info(f"[SYNC] Found {len(active_customers)} active customers to check")

            customer_ids = [c.id for c in active_customers]
            fup_periods_by_customer_id = {}
            if customer_ids:
                fup_result = await db.execute(
                    select(CustomerUsagePeriod).where(
                        CustomerUsagePeriod.customer_id.in_(customer_ids),
                        CustomerUsagePeriod.closed_at.is_(None),
                        CustomerUsagePeriod.fup_triggered_at.isnot(None),
                        CustomerUsagePeriod.fup_reverted_at.is_(None),
                    )
                )
                fup_periods_by_customer_id = {
                    period.customer_id: period for period in fup_result.scalars().all()
                }

            router_customers_map = {}
            no_router_customers = 0
            skipped_offline_router_keys = set()
            for c in active_customers:
                if not c.plan or not c.plan.speed or not c.mac_address:
                    continue
                if not c.router:
                    no_router_customers += 1
                    continue

                router_key = f"{c.router.ip_address}:{c.router.port}"
                if _router_recently_offline(c.router, now):
                    skipped_offline_router_keys.add(router_key)
                    continue

                plan_speed = c.plan.speed
                fup_period = fup_periods_by_customer_id.get(c.id)
                fup_action = (
                    fup_period.fup_action_taken
                    or fup_period.fup_action_snapshot
                    or c.plan.fup_action
                    if fup_period
                    else None
                )
                if fup_action == FupAction.THROTTLE:
                    plan_speed = hotspot_throttle_rate_for_plan(c.plan)

                customer_data = {
                    "id": c.id,
                    "mac_address": c.mac_address,
                    "plan_speed": plan_speed,
                    "fup_active": bool(fup_period),
                    "fup_action": fup_action.value if fup_action else None,
                }
                if router_key not in router_customers_map:
                    router_customers_map[router_key] = {
                        "router": {
                            "ip": c.router.ip_address, "username": c.router.username,
                            "password": c.router.password, "port": c.router.port, "name": c.router.name
                        },
                        "customers": []
                    }
                router_customers_map[router_key]["customers"].append(customer_data)

            if no_router_customers:
                logger.warning(f"[SYNC] Skipping {no_router_customers} customer(s) with no router assigned")
            if skipped_offline_router_keys:
                logger.info(
                    "[SYNC] Skipping %d recently-offline router(s)",
                    len(skipped_offline_router_keys),
                )
            logger.info(f"[SYNC] Grouped customers across {len(router_customers_map)} direct API router(s)")

            all_router_items = [
                (rk, rd) for rk, rd in router_customers_map.items() if rd.get("customers")
            ]
            if not all_router_items:
                logger.info("[SYNC] No eligible direct API routers need queue sync this run")
                return

            start_index = _queue_sync_router_cursor % len(all_router_items)
            ordered_router_items = all_router_items[start_index:] + all_router_items[:start_index]
            pending_router_items = ordered_router_items[:QUEUE_SYNC_MAX_ROUTERS_PER_RUN]
            _queue_sync_router_cursor = (start_index + len(pending_router_items)) % len(all_router_items)

            logger.info(
                "[SYNC] Processing %d/%d eligible router(s) this run (cursor=%d)",
                len(pending_router_items),
                len(all_router_items),
                start_index,
            )
            await db.commit()

        if _background_db_pool_is_busy("QUEUE-SYNC"):
            return

        # Fan out per-router sync concurrently. Each router gets its own
        # task running in a thread pool, so one slow or broken router only
        # delays its own task and never blocks the whole fleet. The shared
        # `router_locks` manager serializes concurrent work for the same
        # router and caps overall MikroTik connection load.
        async def _sync_router_task(rk, rd):
            try:
                async with router_locks.acquire(rk):
                    return await asyncio.to_thread(
                        _sync_single_router_queues_sync, rd["router"], rd["customers"],
                    )
            except Exception as exc:
                logger.error("[SYNC] Router task %s crashed: %s", rk, exc)
                return {
                    "synced": 0,
                    "errors": len(rd.get("customers", [])),
                    "skipped": 0,
                    "routers_connected": 0,
                    "details": {"router": rd["router"].get("name", rk), "error": str(exc)},
                }

        mikrotik_results = {
            "synced": 0,
            "errors": 0,
            "skipped": 0,
            "routers_connected": 0,
            "details": [],
        }
        outcomes = await asyncio.gather(
            *[_sync_router_task(rk, rd) for rk, rd in pending_router_items],
            return_exceptions=True,
        )
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                logger.error("[SYNC] Router sync task error: %s", outcome)
                continue
            mikrotik_results["synced"] += outcome.get("synced", 0)
            mikrotik_results["errors"] += outcome.get("errors", 0)
            mikrotik_results["skipped"] += outcome.get("skipped", 0)
            mikrotik_results["routers_connected"] += outcome.get("routers_connected", 0)
            if outcome.get("details"):
                mikrotik_results["details"].append(outcome["details"])

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


def _parse_queue_bytes(bytes_str: str) -> tuple[int, int]:
    parts = str(bytes_str or "0/0").split("/")
    upload = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    download = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return upload, download


def _usage_counter_delta(
    usage: UserBandwidthUsage,
    upload_bytes: int,
    download_bytes: int,
) -> tuple[int, int, bool]:
    """Return reset-safe deltas and whether the router counter reset.

    Older hotspot rows predate ``last_*_bytes`` and have lifetime counters in
    ``upload_bytes``/``download_bytes`` but zero baselines. Treat that state as
    a baseline instead of charging all historical bytes into the first period.
    """
    prev_up = int(usage.last_upload_bytes or 0)
    prev_dn = int(usage.last_download_bytes or 0)
    legacy_baseline = (
        prev_up == 0
        and prev_dn == 0
        and ((usage.upload_bytes or 0) > 0 or (usage.download_bytes or 0) > 0)
    )
    if legacy_baseline:
        return 0, 0, False
    if upload_bytes < prev_up or download_bytes < prev_dn:
        return upload_bytes, download_bytes, True
    return upload_bytes - prev_up, download_bytes - prev_dn, False


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

    pppoe_sessions = api.get_active_pppoe_sessions()
    if not pppoe_sessions.get("success") and not api.connected:
        if _bandwidth_reconnect(api, router_info):
            pppoe_sessions = api.get_active_pppoe_sessions()

    api.disconnect()

    pppoe_count = len(pppoe_sessions.get("data", [])) if pppoe_sessions.get("success") else 0
    interface_count = len(traffic.get("data", [])) if traffic.get("success") else 0
    logger.info(
        "[BANDWIDTH] Router %s summary: hotspot_sessions=%s, pppoe_sessions=%s, "
        "hotspot_hosts=%s, bypassed=%s, arp_entries=%s, active_queues=%s, "
        "total_queues=%s, interfaces=%s",
        router_info["id"],
        len(active_sessions.get("data", [])),
        pppoe_count,
        hotspot_hosts.get("total", 0),
        hotspot_hosts.get("bypassed", 0),
        arp_entries.get("count", 0),
        speed_stats.get("data", {}).get("active_queues", 0),
        speed_stats.get("data", {}).get("total_queues", 0),
        interface_count,
    )

    if traffic.get("success"):
        logger.debug("[BANDWIDTH] Router %s interfaces:", router_info["id"])
        for iface in traffic.get("data", []):
            rx_mb = round(iface.get("rx_byte", 0) / 1048576, 2)
            tx_mb = round(iface.get("tx_byte", 0) / 1048576, 2)
            logger.debug(
                "[BANDWIDTH]   * %s: running=%s, rx=%sMB, tx=%sMB",
                iface.get("name"),
                iface.get("running"),
                rx_mb,
                tx_mb,
            )
    else:
        logger.warning(f"  - Interface traffic fetch failed: {traffic.get('error', 'unknown')}")

    return {
        "router_id": router_info["id"],
        "active_sessions": active_sessions,
        "traffic": traffic,
        "speed_stats": speed_stats,
        "queues": queues,
        "hotspot_hosts": hotspot_hosts,
        "arp_entries": arp_entries,
        "pppoe_sessions": pppoe_sessions,
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
    global _bandwidth_router_cursor
    try:
        if _background_db_pool_is_busy("BANDWIDTH"):
            return
        now = datetime.utcnow()
        run_started = time.monotonic()
        async with async_session() as db:
            routers_result = await db.execute(select(Router))
            routers = routers_result.scalars().all()
            if not routers:
                logger.warning("No routers found in database for bandwidth collection")
                return
            await db.commit()

            eligible_routers = []
            skipped_radius = 0
            skipped_offline = 0
            for router in routers:
                if getattr(router, 'auth_method', None) == 'RADIUS':
                    skipped_radius += 1
                    continue
                if _router_recently_offline(router, now):
                    skipped_offline += 1
                    logger.debug(
                        "[BANDWIDTH] Skipping recently-offline router %s (%s)",
                        router.id,
                        router.ip_address,
                    )
                    continue
                eligible_routers.append(router)

            if not eligible_routers:
                logger.info(
                    "[BANDWIDTH] No eligible routers this run (total=%d, radius=%d, recently_offline=%d)",
                    len(routers),
                    skipped_radius,
                    skipped_offline,
                )
                return

            start_index = _bandwidth_router_cursor % len(eligible_routers)
            ordered_routers = eligible_routers[start_index:] + eligible_routers[:start_index]
            routers_to_process = ordered_routers[:BANDWIDTH_MAX_ROUTERS_PER_RUN]
            processed_count = 0
            logger.info(
                "[BANDWIDTH] Processing %d/%d eligible router(s) this run "
                "(total=%d, radius=%d, recently_offline=%d, cursor=%d)",
                len(routers_to_process),
                len(eligible_routers),
                len(routers),
                skipped_radius,
                skipped_offline,
                start_index,
            )

            for router in routers_to_process:
                if time.monotonic() - run_started >= BANDWIDTH_RUN_TIME_BUDGET_SECONDS:
                    logger.warning(
                        "[BANDWIDTH] Stopping run after %.1fs budget; processed %d router(s)",
                        time.monotonic() - run_started,
                        processed_count,
                    )
                    break
                if _background_db_pool_is_busy("BANDWIDTH"):
                    logger.warning(
                        "[BANDWIDTH] Stopping run due to DB pool pressure after %d router(s)",
                        processed_count,
                    )
                    break
                processed_count += 1
                try:
                    router_info = {
                        "id": router.id, "ip_address": router.ip_address,
                        "username": router.username, "password": router.password, "port": router.port
                    }
                    router_key = f"{router.ip_address}:{router.port}"
                    await db.commit()
                    async with router_locks.acquire(router_key):
                        raw = await asyncio.to_thread(_fetch_bandwidth_data_sync_for_router, router_info)
                    if not raw:
                        logger.warning(f"Failed to connect to router {router.name} ({router.ip_address}) for bandwidth snapshot")
                        await record_router_availability(db, router.id, False, "bandwidth_snapshot", checked_at=now)
                        await db.commit()
                        continue

                    active_sessions = raw["active_sessions"]
                    traffic = raw["traffic"]
                    speed_stats = raw["speed_stats"]
                    router_id = raw["router_id"]
                    hotspot_hosts = raw.get("hotspot_hosts", {})
                    arp_entries = raw.get("arp_entries", {})
                    await record_router_availability(db, router_id, True, "bandwidth_snapshot", checked_at=now)

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

                    # Hotspot host count (authorized + bypassed). We persist this
                    # SEPARATELY from the combined ``active_queues`` total so the
                    # /api/mikrotik/health endpoint can return a stable hotspot
                    # figure without having to subtract a live PPPoE count from a
                    # stale combined total (which produced the impossible
                    # "pppoe > total" symptom users were reporting).
                    hotspot_fetch_ok = hotspot_hosts.get("success", False)
                    if hotspot_fetch_ok:
                        active_hotspot_users = hotspot_hosts.get("bypassed", 0) + hotspot_hosts.get("authorized", 0)
                    elif prev:
                        # Carry forward the hotspot-only count, not active_queues
                        # (which already includes the previous PPPoE sample).
                        active_hotspot_users = getattr(prev, "active_hotspot_users", None)
                        if active_hotspot_users is None:
                            # Backfill for snapshots written before active_hotspot_users existed.
                            active_hotspot_users = max(0, (prev.active_queues or 0) - 0)
                        logger.warning(f"[BANDWIDTH] Router {router_id}: Hotspot hosts fetch failed, carrying forward previous active_hotspot_users={active_hotspot_users}")
                    else:
                        active_hotspot_users = 0

                    pppoe_sessions = raw.get("pppoe_sessions", {})
                    pppoe_active_count = len(pppoe_sessions.get("data", [])) if pppoe_sessions.get("success") else 0

                    # active_queues stays as the COMBINED hotspot+PPPoE count to
                    # preserve the historical contract for graphs and other
                    # consumers (see app/api/mikrotik_routes.py bandwidth-history).
                    active_devices = active_hotspot_users + pppoe_active_count
                    hotspot_delta_upload_bytes = 0
                    hotspot_delta_download_bytes = 0
                    pppoe_delta_upload_bytes = 0
                    pppoe_delta_download_bytes = 0

                    snapshot = BandwidthSnapshot(
                        router_id=router_id,
                        total_upload_bps=int(speed_data.get("total_upload_bps", 0)),
                        total_download_bps=int(speed_data.get("total_download_bps", 0)),
                        avg_upload_bps=avg_upload_bps,
                        avg_download_bps=avg_download_bps,
                        active_queues=active_devices,
                        active_hotspot_users=active_hotspot_users,
                        active_sessions=len(active_sessions.get("data", [])),
                        interface_rx_bytes=total_rx,
                        interface_tx_bytes=total_tx,
                        recorded_at=now
                    )
                    db.add(snapshot)

                    queues = raw.get("queues", {})
                    if queues.get("success") and queues.get("data"):
                        for q in queues["data"]:
                            qname = q.get("name", "")
                            comment = q.get("comment", "")

                            # --- Hotspot queues (MAC-based) ---
                            mac = ""
                            if "MAC:" in comment:
                                mac = comment.split("MAC:")[1].split("|")[0].strip()
                            if mac:
                                try:
                                    normalized_mac = normalize_mac_address(mac)
                                except Exception:
                                    normalized_mac = mac.upper()
                                compact_mac = normalized_mac.replace(":", "")
                                mac_variants = list({mac, normalized_mac, compact_mac})
                                upload_bytes, download_bytes = _parse_queue_bytes(q.get("bytes", "0/0"))
                                cust_result = await db.execute(
                                    select(Customer)
                                    .options(selectinload(Customer.plan))
                                    .where(
                                        Customer.router_id == router_id,
                                        or_(
                                            Customer.mac_address.ilike(f"%{normalized_mac}%"),
                                            Customer.mac_address.ilike(f"%{compact_mac}%"),
                                            Customer.mac_address.ilike(f"%{mac}%"),
                                        ),
                                    )
                                )
                                customer = cust_result.scalars().first()
                                existing = await db.execute(
                                    select(UserBandwidthUsage).where(
                                        UserBandwidthUsage.mac_address.in_(mac_variants)
                                    )
                                )
                                usage = existing.scalar_one_or_none()
                                if usage:
                                    delta_up, delta_dn, reset_detected = _usage_counter_delta(
                                        usage, upload_bytes, download_bytes
                                    )
                                    if reset_detected:
                                        logger.info(
                                            "[USAGE] Hotspot counter reset for %s "
                                            "(prev=%s/%s, now=%s/%s)",
                                            normalized_mac,
                                            usage.last_upload_bytes or 0,
                                            usage.last_download_bytes or 0,
                                            upload_bytes,
                                            download_bytes,
                                        )
                                    usage.mac_address = normalized_mac
                                    usage.upload_bytes = upload_bytes
                                    usage.download_bytes = download_bytes
                                    usage.last_upload_bytes = upload_bytes
                                    usage.last_download_bytes = download_bytes
                                    usage.max_limit = q.get("max-limit", "")
                                    usage.queue_name = qname
                                    usage.target_ip = q.get("target", "")
                                    usage.last_updated = now
                                    if customer:
                                        usage.customer_id = customer.id
                                else:
                                    delta_up = 0
                                    delta_dn = 0
                                    usage = UserBandwidthUsage(
                                        mac_address=normalized_mac, customer_id=customer.id if customer else None,
                                        queue_name=qname, target_ip=q.get("target", ""),
                                        upload_bytes=upload_bytes, download_bytes=download_bytes,
                                        last_upload_bytes=upload_bytes,
                                        last_download_bytes=download_bytes,
                                        max_limit=q.get("max-limit", ""), last_updated=now
                                    )
                                    db.add(usage)

                                hotspot_delta_upload_bytes += delta_up
                                hotspot_delta_download_bytes += delta_dn
                                if customer and customer.plan and customer.plan.connection_type == ConnectionType.HOTSPOT:
                                    try:
                                        period = await record_usage(
                                            db,
                                            customer,
                                            delta_up,
                                            delta_dn,
                                            plan=customer.plan,
                                            now=now,
                                        )
                                        try:
                                            from app.services.fup import evaluate_and_enforce
                                        except ImportError:
                                            evaluate_and_enforce = None
                                        if evaluate_and_enforce is not None:
                                            await evaluate_and_enforce(
                                                db, customer, period, plan=customer.plan, now=now
                                            )
                                    except Exception as usage_err:
                                        logger.error(
                                            "[FUP] Failed to record/enforce hotspot usage for %s: %s",
                                            normalized_mac,
                                            usage_err,
                                        )
                                continue

                            # --- PPPoE dynamic queues (<pppoe-USERNAME>) ---
                            if qname.startswith("<pppoe-") and qname.endswith(">"):
                                pppoe_user = qname[7:-1]
                                upload_bytes, download_bytes = _parse_queue_bytes(q.get("bytes", "0/0"))
                                pppoe_key = f"pppoe:{pppoe_user}"

                                cust_result = await db.execute(
                                    select(Customer)
                                    .options(selectinload(Customer.plan))
                                    .where(
                                        Customer.pppoe_username == pppoe_user,
                                        Customer.router_id == router_id,
                                    )
                                )
                                customer = cust_result.scalars().first()

                                existing = await db.execute(
                                    select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == pppoe_key)
                                )
                                usage = existing.scalar_one_or_none()

                                # --- Reset-safe delta computation ---
                                if usage:
                                    delta_up, delta_dn, reset_detected = _usage_counter_delta(
                                        usage, upload_bytes, download_bytes
                                    )
                                    if reset_detected:
                                        logger.info(
                                            f"[FUP] PPPoE counter reset for {pppoe_user} "
                                            f"(prev={usage.last_upload_bytes or 0}/{usage.last_download_bytes or 0}, "
                                            f"now={upload_bytes}/{download_bytes})"
                                        )
                                    usage.upload_bytes = upload_bytes
                                    usage.download_bytes = download_bytes
                                    usage.last_upload_bytes = upload_bytes
                                    usage.last_download_bytes = download_bytes
                                    usage.max_limit = q.get("max-limit", "")
                                    usage.queue_name = qname
                                    usage.target_ip = q.get("target", "")
                                    usage.last_updated = now
                                    if customer:
                                        usage.customer_id = customer.id
                                else:
                                    # First time we see this user: record the baseline; no delta yet.
                                    delta_up = 0
                                    delta_dn = 0
                                    usage = UserBandwidthUsage(
                                        mac_address=pppoe_key,
                                        customer_id=customer.id if customer else None,
                                        queue_name=qname,
                                        target_ip=q.get("target", ""),
                                        upload_bytes=upload_bytes,
                                        download_bytes=download_bytes,
                                        last_upload_bytes=upload_bytes,
                                        last_download_bytes=download_bytes,
                                        max_limit=q.get("max-limit", ""),
                                        last_updated=now,
                                    )
                                    db.add(usage)

                                pppoe_delta_upload_bytes += delta_up
                                pppoe_delta_download_bytes += delta_dn

                                # --- Roll deltas into the open period (PPPoE only) ---
                                if customer and customer.plan and customer.plan.connection_type == ConnectionType.PPPOE:
                                    try:
                                        period = await record_usage(
                                            db,
                                            customer,
                                            delta_up,
                                            delta_dn,
                                            plan=customer.plan,
                                            now=now,
                                        )
                                        # Lazy FUP enforcement (skipped if module/cap not present)
                                        try:
                                            from app.services.fup import evaluate_and_enforce
                                        except ImportError:
                                            evaluate_and_enforce = None
                                        if evaluate_and_enforce is not None:
                                            await evaluate_and_enforce(
                                                db, customer, period, plan=customer.plan, now=now
                                            )
                                    except Exception as fup_err:
                                        logger.error(
                                            f"[FUP] Failed to record/enforce usage for {pppoe_user}: {fup_err}"
                                        )

                    snapshot.hotspot_upload_bytes = hotspot_delta_upload_bytes
                    snapshot.hotspot_download_bytes = hotspot_delta_download_bytes
                    snapshot.pppoe_upload_bytes = pppoe_delta_upload_bytes
                    snapshot.pppoe_download_bytes = pppoe_delta_download_bytes

                    logger.debug(f"Collected bandwidth snapshot for router {router.name} (ID: {router_id})")
                    await db.commit()
                except Exception as router_error:
                    logger.error(f"Error collecting bandwidth from router {router.name}: {router_error}")
                    # Roll the session back so a single failed query (e.g. a missing
                    # column on plans / user_bandwidth_usage) doesn't leave the
                    # connection in 'aborted-transaction' state and poison every
                    # subsequent query on that pooled asyncpg connection.
                    try:
                        await db.rollback()
                    except Exception as rb_err:
                        logger.error(f"[BANDWIDTH] Rollback after router error failed: {rb_err}")
                    continue

            _bandwidth_router_cursor = (start_index + processed_count) % len(eligible_routers)

            cutoff = now - timedelta(days=1)
            await db.execute(delete(BandwidthSnapshot).where(BandwidthSnapshot.recorded_at < cutoff))
            await prune_router_availability_history(db, now=now)
            await db.commit()

        logger.info(
            "Bandwidth snapshot run processed %d/%d eligible router(s) out of %d total router(s)",
            processed_count,
            len(eligible_routers),
            len(routers),
        )
    except Exception as e:
        from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
        from app.db.database import db_pool_status

        logger.error(f"Error collecting bandwidth snapshot: {e}")
        if isinstance(e, SQLAlchemyTimeoutError):
            logger.error("[BANDWIDTH] DB pool status at failure: %s", db_pool_status())

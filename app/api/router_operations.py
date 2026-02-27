from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Router, Customer, Plan, CustomerStatus, ConnectionType
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI, validate_mac_address, normalize_mac_address
from app.services.router_helpers import get_router_by_id, connect_to_router
from app.core.protected_devices import is_protected_device
from app.config import settings

import logging
import time
import asyncio
import hashlib

logger = logging.getLogger(__name__)

router = APIRouter(tags=["router-operations"])


# ---------------------------------------------------------------------------
# Helper functions (sync, run in thread pool)
# ---------------------------------------------------------------------------

def _get_router_users_sync(router_info: dict) -> dict:
    """Synchronous function to get router users. Runs in thread pool."""
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
        users_result = api.send_command("/ip/hotspot/user/print")
        active_sessions_result = api.send_command("/ip/hotspot/active/print")

        users = []
        active_sessions = {}

        if active_sessions_result.get("success") and active_sessions_result.get("data"):
            for session in active_sessions_result["data"]:
                username = session.get("user")
                if username:
                    active_sessions[username] = session

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
            "success": True,
            "users": users,
            "active_sessions_count": len(active_sessions)
        }
    finally:
        api.disconnect()


def _remove_router_user_sync(router_info: dict, username: str) -> dict:
    """Synchronous function to remove router user. Runs in thread pool."""
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
            for u in users_result["data"]:
                if u.get("name") == username:
                    user_id = u.get(".id")
                    break

        if not user_id:
            return {"error": "user_not_found"}

        remove_result = api.send_command("/ip/hotspot/user/remove", {"numbers": user_id})

        if "error" in remove_result:
            return {"error": "remove_failed", "message": remove_result["error"]}

        # Also remove IP bindings and queues
        if len(username) == 12 and username.isalnum():
            mac_address = ':'.join(username[i:i+2] for i in range(0, 12, 2))

            bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings_result.get("success") and bindings_result.get("data"):
                for binding in bindings_result["data"]:
                    if binding.get("mac-address", "").upper() == mac_address.upper():
                        binding_id = binding.get(".id")
                        if binding_id:
                            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})

            queues_result = api.send_command("/queue/simple/print")
            if queues_result.get("success") and queues_result.get("data"):
                for queue in queues_result["data"]:
                    if queue.get("name") == f"queue_{username}":
                        queue_id = queue.get(".id")
                        if queue_id:
                            api.send_command("/queue/simple/remove", {"numbers": queue_id})

        return {"success": True}
    finally:
        api.disconnect()


def _get_router_stats_sync(router_info: dict) -> dict:
    """Synchronous function to get router stats. Runs in thread pool."""
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
        users_result = api.send_command("/ip/hotspot/user/print")
        total_users = len(users_result.get("data", [])) if users_result.get("success") else 0

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
            "success": True,
            "total_users": total_users,
            "active_sessions": active_sessions,
            "active_users": active_users,
            "system_info": system_info
        }
    finally:
        api.disconnect()


def _sync_router_users_sync(router_info: dict) -> dict:
    """Synchronous function to get router users for sync. Runs in thread pool."""
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
        users_result = api.send_command("/ip/hotspot/user/print")
        router_users = users_result.get("data", []) if users_result.get("success") else []
        return {"success": True, "router_users": router_users}
    finally:
        api.disconnect()


def _get_bandwidth_check_data_sync(router_info: dict) -> dict:
    """Fetch queues, ARP, and DHCP data from router. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed"}
    
    try:
        queues_result = api.send_command("/queue/simple/print")
        all_queues = queues_result.get("data", []) if queues_result.get("success") else []
        
        arp_result = api.send_command("/ip/arp/print")
        dhcp_result = api.send_command("/ip/dhcp-server/lease/print")
        
        arp_entries = arp_result.get("data", []) if arp_result.get("success") else []
        dhcp_leases = dhcp_result.get("data", []) if dhcp_result.get("success") else []
        
        return {
            "all_queues": all_queues,
            "arp_entries": arp_entries,
            "dhcp_leases": dhcp_leases
        }
    finally:
        api.disconnect()


def _get_illegal_connections_data_sync(router_info: dict) -> dict:
    """Fetch ARP, DHCP, hotspot, bindings, and queues data from router. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed"}
    
    try:
        arp_result = api.get_arp_minimal()
        arp_entries = arp_result.get("data", []) if arp_result.get("success") else []
        
        dhcp_result = api.get_dhcp_leases_minimal()
        dhcp_leases = dhcp_result.get("data", []) if dhcp_result.get("success") else []
        
        active_result = api.get_hotspot_active_minimal()
        active_sessions = active_result.get("data", []) if active_result.get("success") else []
        
        bindings_result = api.get_ip_bindings_minimal()
        ip_bindings = bindings_result.get("data", []) if bindings_result.get("success") else []
        
        queues_result = api.get_simple_queues_minimal()
        queues = queues_result.get("data", []) if queues_result.get("success") else []
        
        return {
            "arp_entries": arp_entries,
            "dhcp_leases": dhcp_leases,
            "active_sessions": active_sessions,
            "ip_bindings": ip_bindings,
            "queues": queues
        }
    finally:
        api.disconnect()


def _remove_illegal_user_with_cache(
    api, 
    mac_address: str, 
    cached_data: dict,
    customer_info: dict = None
) -> dict:
    """
    Remove a single illegal/unauthorized user from MikroTik using pre-cached data.
    This is efficient because it doesn't re-fetch data for each user.
    
    Args:
        api: Connected MikroTikAPI instance
        mac_address: MAC address to remove
        cached_data: Dict containing pre-fetched bindings, hosts, users, sessions, queues, leases
        customer_info: Optional dict with customer details if exists in DB
    
    Returns:
        Dict with removal results
    """
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    
    removed = {
        "mac_address": mac_address,
        "binding_removed": False,
        "hosts_removed": 0,
        "user_removed": False,
        "active_sessions_removed": 0,
        "queues_removed": 0,
        "leases_removed": 0
    }
    
    if customer_info:
        removed["customer_id"] = customer_info.get("id")
        removed["customer_name"] = customer_info.get("name")
    
    try:
        # Get client IP from cached ARP data
        client_ip = None
        for arp in cached_data.get("arp", []):
            if normalize_mac_address(arp.get("mac-address", "")) == normalized_mac:
                client_ip = arp.get("address", "")
                break
        
        # STEP 1: Remove IP binding (CRITICAL - bypassed bindings allow access without auth)
        binding_found = False
        for b in cached_data.get("bindings", []):
            binding_mac = b.get("mac-address", "").upper()
            binding_comment = b.get("comment", "")
            binding_id = b.get(".id")
            
            # Match by MAC address OR by username in comment
            mac_match = normalize_mac_address(binding_mac) == normalized_mac if binding_mac else False
            username_match = f"USER:{username}" in binding_comment.upper()
            
            if mac_match or username_match:
                binding_found = True
                logger.info(f"[REMOVE-ILLEGAL] Found IP binding: id={binding_id}, mac={binding_mac}, type={b.get('type', 'unknown')}")
                
                remove_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                
                if remove_result.get("success") or "error" not in remove_result:
                    removed["binding_removed"] = True
                    logger.info(f"[REMOVE-ILLEGAL] ✓ Removed IP binding for {normalized_mac}")
                else:
                    logger.error(f"[REMOVE-ILLEGAL] ✗ Failed to remove IP binding: {remove_result.get('error', 'unknown')}")
                break
        
        if not binding_found:
            logger.info(f"[REMOVE-ILLEGAL] No IP binding found for {normalized_mac} in cached data")
        
        # STEP 2: Remove from hotspot hosts
        for host in cached_data.get("hosts", []):
            host_mac = host.get("mac-address", "").upper()
            host_ip = host.get("address", "")
            if normalize_mac_address(host_mac) == normalized_mac or (client_ip and host_ip == client_ip):
                api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]})
                removed["hosts_removed"] += 1
                logger.info(f"[REMOVE-ILLEGAL] Removed host entry: {host_mac}")
        
        # STEP 3: Remove hotspot user (match by name OR MAC in comment)
        user_found = False
        for u in cached_data.get("users", []):
            user_name = u.get("name", "")
            user_comment = u.get("comment", "")
            user_id = u.get(".id")
            
            # Match by username OR MAC address in comment
            name_match = user_name == username
            mac_in_comment = normalized_mac.upper() in user_comment.upper() or mac_address.upper() in user_comment.upper()
            
            if name_match or mac_in_comment:
                user_found = True
                logger.info(f"[REMOVE-ILLEGAL] Found hotspot user: id={user_id}, name={user_name}")
                
                remove_result = api.send_command("/ip/hotspot/user/remove", {"numbers": user_id})
                
                if remove_result.get("success") or "error" not in remove_result:
                    removed["user_removed"] = True
                    logger.info(f"[REMOVE-ILLEGAL] ✓ Removed hotspot user: {user_name}")
                else:
                    logger.error(f"[REMOVE-ILLEGAL] ✗ Failed to remove user: {remove_result.get('error', 'unknown')}")
                break
        
        if not user_found:
            logger.info(f"[REMOVE-ILLEGAL] No hotspot user found for {username}")
        
        # STEP 4: Disconnect active sessions
        for session in cached_data.get("active_sessions", []):
            session_mac = session.get("mac-address", "").upper()
            session_user = session.get("user", "").upper()
            if normalize_mac_address(session_mac) == normalized_mac or session_user == username.upper():
                api.send_command("/ip/hotspot/active/remove", {"numbers": session[".id"]})
                removed["active_sessions_removed"] += 1
                logger.info(f"[REMOVE-ILLEGAL] Disconnected active session")
        
        # STEP 5: Remove queues
        for q in cached_data.get("queues", []):
            queue_name = q.get("name", "")
            queue_comment = q.get("comment", "")
            if (queue_name == f"queue_{username}" or 
                queue_name == f"plan_{username}" or
                normalized_mac.upper() in queue_comment.upper() or
                f"MAC:{mac_address}" in queue_comment):
                api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                removed["queues_removed"] += 1
                logger.info(f"[REMOVE-ILLEGAL] Removed queue: {queue_name}")
        
        # STEP 6: Remove DHCP lease
        for lease in cached_data.get("leases", []):
            if normalize_mac_address(lease.get("mac-address", "")) == normalized_mac:
                api.send_command("/ip/dhcp-server/lease/remove", {"numbers": lease[".id"]})
                removed["leases_removed"] += 1
                logger.info(f"[REMOVE-ILLEGAL] Removed DHCP lease for {normalized_mac}")
                break  # Only one lease per MAC
        
        # STEP 7: VERIFICATION - Re-check that IP binding was removed (most critical item)
        verify_bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if verify_bindings.get("success") and verify_bindings.get("data"):
            for b in verify_bindings["data"]:
                if normalize_mac_address(b.get("mac-address", "")) == normalized_mac:
                    logger.error(f"[REMOVE-ILLEGAL] ⚠️ VERIFICATION: IP binding STILL EXISTS for {normalized_mac}!")
                    # Try one more time with fresh lookup
                    retry_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                    if retry_result.get("success") or "error" not in retry_result:
                        logger.info(f"[REMOVE-ILLEGAL] ✓ Retry removal succeeded for {normalized_mac}")
                        removed["binding_removed"] = True
                    else:
                        logger.error(f"[REMOVE-ILLEGAL] ✗ Retry removal FAILED!")
                        removed["verification_failed"] = True
                    break
        
        removed["success"] = True
        return removed
        
    except Exception as e:
        logger.error(f"[REMOVE-ILLEGAL] Failed to remove {mac_address}: {e}")
        removed["success"] = False
        removed["error"] = str(e)
        return removed


def _bulk_remove_illegal_users_sync(
    router_info: dict,
    illegal_users: list,
    known_macs: dict,
    delay_ms: int = 150
) -> dict:
    """
    Synchronous function to remove illegal users from MikroTik.
    Runs in thread pool to avoid blocking the event loop.
    Fetches all data ONCE then processes removals with delays.
    
    Args:
        router_info: Dict with router connection details
        illegal_users: List of illegal users to remove
        known_macs: Dict of MAC -> customer info
        delay_ms: Delay between each removal (default 150ms)
    
    Returns:
        Dict with results
    """
    results = {"removed": [], "failed": [], "total": len(illegal_users)}
    
    if not illegal_users:
        return results
    
    logger.info(f"[REMOVE-ILLEGAL] Starting bulk removal of {len(illegal_users)} users from {router_info['name']}")
    
    # Connect with reasonable timeouts
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        logger.error(f"[REMOVE-ILLEGAL] Failed to connect to router {router_info['name']}")
        for user in illegal_users:
            results["failed"].append({
                "mac_address": user["mac_address"],
                "error": f"Failed to connect to router"
            })
        return results
    
    try:
        # FETCH ALL DATA ONCE using OPTIMIZED queries (only essential fields)
        # This significantly reduces data transfer and prevents timeouts
        logger.info(f"[REMOVE-ILLEGAL] Caching router data (optimized)...")
        cached_data = {
            "arp": [],
            "bindings": [],
            "hosts": [],
            "users": [],
            "active_sessions": [],
            "queues": [],
            "leases": []
        }
        
        # Fetch with error handling for each - using optimized methods
        arp_result = api.get_arp_minimal()
        if arp_result.get("success"):
            cached_data["arp"] = arp_result.get("data", [])
        
        bindings_result = api.get_ip_bindings_minimal()
        if bindings_result.get("success"):
            cached_data["bindings"] = bindings_result.get("data", [])
        
        # Hosts don't have a minimal version yet - use full fetch (usually small dataset)
        hosts_result = api.send_command("/ip/hotspot/host/print")
        if hosts_result.get("success"):
            cached_data["hosts"] = hosts_result.get("data", [])
        
        users_result = api.get_hotspot_users_minimal()
        if users_result.get("success"):
            cached_data["users"] = users_result.get("data", [])
        
        active_result = api.get_hotspot_active_minimal()
        if active_result.get("success"):
            cached_data["active_sessions"] = active_result.get("data", [])
        
        queues_result = api.get_simple_queues_minimal()
        if queues_result.get("success"):
            cached_data["queues"] = queues_result.get("data", [])
        
        leases_result = api.get_dhcp_leases_minimal()
        if leases_result.get("success"):
            cached_data["leases"] = leases_result.get("data", [])
        
        logger.info(f"[REMOVE-ILLEGAL] Cached: {len(cached_data['bindings'])} bindings, "
                   f"{len(cached_data['hosts'])} hosts, {len(cached_data['users'])} users, "
                   f"{len(cached_data['active_sessions'])} active, {len(cached_data['queues'])} queues, "
                   f"{len(cached_data['leases'])} leases")
        
        # Process each illegal user with delay
        for i, user in enumerate(illegal_users):
            mac_address = user["mac_address"]
            normalized_mac = normalize_mac_address(mac_address)
            customer_info = known_macs.get(normalized_mac)
            
            logger.info(f"[REMOVE-ILLEGAL] Processing {i+1}/{len(illegal_users)}: {mac_address}")
            
            try:
                result = _remove_illegal_user_with_cache(api, mac_address, cached_data, customer_info)
                result["reason"] = user.get("reason", "UNKNOWN")
                result["ip_address"] = user.get("ip_address", "")
                
                if result.get("success"):
                    results["removed"].append(result)
                else:
                    results["failed"].append(result)
                    
            except Exception as e:
                logger.error(f"[REMOVE-ILLEGAL] Error removing {mac_address}: {e}")
                results["failed"].append({
                    "mac_address": mac_address,
                    "error": str(e),
                    "reason": user.get("reason", "UNKNOWN")
                })
            
            # Delay between removals to prevent overwhelming router
            if i < len(illegal_users) - 1:  # No delay after last one
                time.sleep(delay_ms / 1000.0)
        
        api.disconnect()
        logger.info(f"[REMOVE-ILLEGAL] Completed: {len(results['removed'])} removed, {len(results['failed'])} failed")
        
    except Exception as e:
        api.disconnect()
        logger.error(f"[REMOVE-ILLEGAL] Bulk removal error: {e}")
        raise
    
    return results


def _scan_connected_devices_sync(router_info: dict) -> dict:
    """Scan router for connected devices. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed", "connected_devices": {}}
    
    try:
        connected_devices = {}
        
        arp_result = api.send_command("/ip/arp/print")
        for entry in (arp_result.get("data", []) if arp_result.get("success") else []):
            mac = entry.get("mac-address", "")
            ip_addr = entry.get("address", "")
            interface = entry.get("interface", "")
            if mac:
                # Skip protected devices (WireGuard, management, etc.)
                if is_protected_device(ip_address=ip_addr, interface=interface):
                    continue
                normalized_mac = normalize_mac_address(mac)
                connected_devices[normalized_mac] = {"mac_address": mac, "ip_address": ip_addr, "interface": interface}
        
        dhcp_result = api.send_command("/ip/dhcp-server/lease/print")
        for lease in (dhcp_result.get("data", []) if dhcp_result.get("success") else []):
            mac = lease.get("mac-address", "")
            ip_addr = lease.get("address", "")
            server = lease.get("server", "")
            hostname = lease.get("host-name", "")
            if mac:
                # Skip protected devices
                if is_protected_device(ip_address=ip_addr, interface=server, hostname=hostname):
                    continue
                normalized_mac = normalize_mac_address(mac)
                if normalized_mac not in connected_devices:
                    connected_devices[normalized_mac] = {"mac_address": mac, "ip_address": ip_addr, "interface": server}
        
        active_result = api.send_command("/ip/hotspot/active/print")
        for session in (active_result.get("data", []) if active_result.get("success") else []):
            mac = session.get("mac-address", "")
            ip_addr = session.get("address", "")
            if mac:
                # Skip protected devices
                if is_protected_device(ip_address=ip_addr):
                    continue
                normalized_mac = normalize_mac_address(mac)
                if normalized_mac not in connected_devices:
                    connected_devices[normalized_mac] = {"mac_address": mac, "ip_address": ip_addr}
        
        return {"connected_devices": connected_devices}
    finally:
        api.disconnect()


def _force_remove_mac_sync(router_info: dict, normalized_mac: str, username: str) -> dict:
    """Force remove all router entries for a MAC. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed"}
    
    removed = {
        "ip_bindings": 0,
        "hotspot_users": 0,
        "active_sessions": 0,
        "hosts": 0,
        "queues": 0,
        "dhcp_leases": 0
    }
    
    try:
        # Remove ALL IP bindings for this MAC
        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if bindings.get("success"):
            for b in bindings.get("data", []):
                b_mac = normalize_mac_address(b.get("mac-address", "")) if b.get("mac-address") else ""
                b_comment = b.get("comment", "")
                if b_mac == normalized_mac or username in b_comment.upper() or normalized_mac.upper() in b_comment.upper():
                    api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})
                    removed["ip_bindings"] += 1
                    logger.info(f"[FORCE-REMOVE] Removed IP binding: {b['.id']}")
        
        # Remove ALL hotspot users
        users = api.send_command("/ip/hotspot/user/print")
        if users.get("success"):
            for u in users.get("data", []):
                u_name = u.get("name", "")
                u_comment = u.get("comment", "")
                if u_name == username or normalized_mac.upper() in u_comment.upper():
                    api.send_command("/ip/hotspot/user/remove", {"numbers": u[".id"]})
                    removed["hotspot_users"] += 1
                    logger.info(f"[FORCE-REMOVE] Removed hotspot user: {u_name}")
        
        # Disconnect ALL active sessions
        active = api.send_command("/ip/hotspot/active/print")
        if active.get("success"):
            for s in active.get("data", []):
                s_mac = normalize_mac_address(s.get("mac-address", "")) if s.get("mac-address") else ""
                s_user = s.get("user", "").upper()
                if s_mac == normalized_mac or s_user == username.upper():
                    api.send_command("/ip/hotspot/active/remove", {"numbers": s[".id"]})
                    removed["active_sessions"] += 1
                    logger.info(f"[FORCE-REMOVE] Disconnected session: {s_user}")
        
        # Remove hosts
        hosts = api.send_command("/ip/hotspot/host/print")
        if hosts.get("success"):
            for h in hosts.get("data", []):
                h_mac = normalize_mac_address(h.get("mac-address", "")) if h.get("mac-address") else ""
                if h_mac == normalized_mac:
                    api.send_command("/ip/hotspot/host/remove", {"numbers": h[".id"]})
                    removed["hosts"] += 1
        
        # Remove queues
        queues = api.send_command("/queue/simple/print")
        if queues.get("success"):
            for q in queues.get("data", []):
                q_name = q.get("name", "")
                q_comment = q.get("comment", "")
                if username in q_name or normalized_mac.upper() in q_comment.upper():
                    api.send_command("/queue/simple/remove", {"numbers": q[".id"]})
                    removed["queues"] += 1
        
        # Remove DHCP leases
        leases = api.send_command("/ip/dhcp-server/lease/print")
        if leases.get("success"):
            for l in leases.get("data", []):
                l_mac = normalize_mac_address(l.get("mac-address", "")) if l.get("mac-address") else ""
                if l_mac == normalized_mac:
                    api.send_command("/ip/dhcp-server/lease/remove", {"numbers": l[".id"]})
                    removed["dhcp_leases"] += 1
        
        return {"removed": removed}
    finally:
        api.disconnect()


def _cleanup_bypassing_sync(router_info: dict, active_macs: set, customer_by_mac: dict, dry_run: bool) -> dict:
    """Cleanup bypassing users on router. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed"}
    
    try:
        # Get all IP bindings
        bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
        all_bindings = bindings_result.get("data", []) if bindings_result.get("success") else []
        
        # Also get active hotspot sessions for reference
        active_result = api.send_command("/ip/hotspot/active/print")
        active_sessions = active_result.get("data", []) if active_result.get("success") else []
        active_session_macs = set()
        for s in active_sessions:
            mac = s.get("mac-address", "")
            if mac:
                active_session_macs.add(normalize_mac_address(mac))
        
        # Analyze each binding
        to_remove = []
        kept = []
        
        for binding in all_bindings:
            binding_mac = binding.get("mac-address", "")
            binding_type = binding.get("type", "")
            binding_id = binding.get(".id", "")
            binding_address = binding.get("address", "")
            binding_comment = binding.get("comment", "")
            
            if not binding_mac:
                continue
            
            normalized_mac = normalize_mac_address(binding_mac)
            customer_info = customer_by_mac.get(normalized_mac)
            
            # Determine if this binding should be removed
            should_remove = False
            reason = ""
            
            if binding_type != "bypassed":
                # Only care about bypassed bindings (those give internet access)
                kept.append({
                    "mac": binding_mac,
                    "type": binding_type,
                    "reason": "Not a bypassed binding"
                })
                continue
            
            if normalized_mac in active_macs:
                # Customer is ACTIVE - keep the binding
                kept.append({
                    "mac": binding_mac,
                    "type": binding_type,
                    "customer": customer_info,
                    "reason": "Customer is active"
                })
                continue
            
            # If we get here, it's a bypassed binding for non-active customer
            if customer_info:
                # Known customer but not active
                should_remove = True
                reason = f"Customer {customer_info['name']} is {customer_info['status']} (expired: {customer_info['expiry']})"
            else:
                # Unknown MAC - not in database at all
                should_remove = True
                reason = "MAC not found in customer database"
            
            if should_remove:
                entry = {
                    "binding_id": binding_id,
                    "mac_address": binding_mac,
                    "ip_address": binding_address,
                    "type": binding_type,
                    "comment": binding_comment,
                    "customer": customer_info,
                    "reason": reason,
                    "has_active_session": normalized_mac in active_session_macs
                }
                
                if not dry_run:
                    # Actually remove it
                    remove_result = api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": binding_id})
                    entry["removed"] = remove_result.get("success", True)  # MikroTik returns empty on success
                    logger.info(f"[CLEANUP-BYPASS] Removed binding for {binding_mac}: {reason}")
                    
                    # Also remove active session if exists
                    if normalized_mac in active_session_macs:
                        for s in active_sessions:
                            if normalize_mac_address(s.get("mac-address", "")) == normalized_mac:
                                api.send_command("/ip/hotspot/active/remove", {"numbers": s[".id"]})
                                entry["session_removed"] = True
                                logger.info(f"[CLEANUP-BYPASS] Disconnected active session for {binding_mac}")
                                break
                
                to_remove.append(entry)
        
        return {
            "all_bindings": all_bindings,
            "to_remove": to_remove,
            "kept": kept
        }
    finally:
        api.disconnect()


def _remove_single_illegal_user_sync(router_info: dict, mac_address: str, normalized_mac: str, customer_info: dict) -> dict:
    """Remove a single illegal user from router. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5
    )
    
    if not api.connect():
        return {"error": "connect_failed"}
    
    try:
        # Fetch all data once for efficient removal (7 API calls)
        cached_data = {
            "arp": [],
            "bindings": [],
            "hosts": [],
            "users": [],
            "active_sessions": [],
            "queues": [],
            "leases": []
        }
        
        arp_result = api.send_command("/ip/arp/print")
        if arp_result.get("success"):
            cached_data["arp"] = arp_result.get("data", [])
            
            # PROTECTION CHECK: Verify this MAC is not a protected device
            for arp_entry in cached_data["arp"]:
                if normalize_mac_address(arp_entry.get("mac-address", "")) == normalized_mac:
                    arp_ip = arp_entry.get("address", "")
                    arp_interface = arp_entry.get("interface", "")
                    if is_protected_device(ip_address=arp_ip, interface=arp_interface):
                        logger.warning(f"[REMOVE-ILLEGAL] Blocked attempt to remove protected device: {mac_address} ({arp_ip} on {arp_interface})")
                        return {
                            "error": "protected_device",
                            "detail": f"Cannot remove protected device. IP {arp_ip} on interface {arp_interface} is in the protected list (WireGuard/management/infrastructure)."
                        }
                    break
        
        bindings_result = api.send_command("/ip/hotspot/ip-binding/print")
        if bindings_result.get("success"):
            cached_data["bindings"] = bindings_result.get("data", [])
        
        hosts_result = api.send_command("/ip/hotspot/host/print")
        if hosts_result.get("success"):
            cached_data["hosts"] = hosts_result.get("data", [])
        
        users_result = api.send_command("/ip/hotspot/user/print")
        if users_result.get("success"):
            cached_data["users"] = users_result.get("data", [])
        
        active_result = api.send_command("/ip/hotspot/active/print")
        if active_result.get("success"):
            cached_data["active_sessions"] = active_result.get("data", [])
        
        queues_result = api.send_command("/queue/simple/print")
        if queues_result.get("success"):
            cached_data["queues"] = queues_result.get("data", [])
        
        leases_result = api.send_command("/ip/dhcp-server/lease/print")
        if leases_result.get("success"):
            cached_data["leases"] = leases_result.get("data", [])
        
        # Remove the user using cached data
        removal_result = _remove_illegal_user_with_cache(api, mac_address, cached_data, customer_info)
        
        return {"removal_result": removal_result}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/routers/{router_id}/users")
async def get_router_users(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all hotspot users for a specific router. Runs in thread pool."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_get_router_users_sync, router_info)
    
    if result.get("error"):
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "users": result["users"],
        "total_users": len(result["users"]),
        "active_sessions": result["active_sessions_count"]
    }


@router.delete("/api/routers/{router_id}/users/{username}")
async def remove_router_user(
    router_id: int,
    username: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Remove a hotspot user from router. Runs in thread pool."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_remove_router_user_sync, router_info, username)
    
    if result.get("error") == "connection_failed":
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")
    elif result.get("error") == "user_not_found":
        raise HTTPException(status_code=404, detail="User not found")
    elif result.get("error") == "remove_failed":
        raise HTTPException(status_code=400, detail=result.get("message", "Remove failed"))

    return {
        "success": True,
        "message": f"User {username} removed successfully",
        "username": username,
        "router_id": router_id
    }


@router.get("/api/router_stats/{router_id}")
async def get_router_stats(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get router statistics and active users. Runs in thread pool."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    result = await asyncio.to_thread(_get_router_stats_sync, router_info)
    
    if result.get("error"):
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "total_users": result["total_users"],
        "active_sessions": result["active_sessions"],
        "active_users": result["active_users"],
        "system_info": result["system_info"],
        "last_updated": datetime.utcnow().isoformat()
    }


@router.post("/api/routers/{router_id}/sync")
async def sync_router_users_with_database(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Sync router users with database customers. Runs in thread pool."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name
    }
    
    # Run MikroTik operations in thread pool (non-blocking!)
    mikrotik_result = await asyncio.to_thread(_sync_router_users_sync, router_info)
    
    if mikrotik_result.get("error"):
        logger.error(f"Failed to connect to router {router_obj.name} at {router_obj.ip_address}")
        raise HTTPException(status_code=500, detail="Failed to connect to router")

    router_users = mikrotik_result.get("router_users", [])

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


@router.post("/api/routers/{router_id}/cleanup-expired")
async def cleanup_expired_customers_for_router(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Manually trigger cleanup of expired customers for a specific router.
    Removes expired users from MikroTik and marks them as INACTIVE in database.
    """
    try:
        current_user = await get_current_user(token, db)
        # Verify router exists and belongs to user
        router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        
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
                "router_name": router_obj.name,
                "cleaned_up": 0
            }
        
        # Prepare data for sync cleanup
        router_customers_map = {
            f"{router_obj.ip_address}:{router_obj.port}": {
                "router": {
                    "ip": router_obj.ip_address,
                    "username": router_obj.username,
                    "password": router_obj.password,
                    "port": router_obj.port,
                    "name": router_obj.name
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
        
        from app.services.mikrotik_background import mikrotik_lock, _cleanup_customer_from_mikrotik_sync
        
        # Run cleanup in thread pool
        async with mikrotik_lock:
            mikrotik_results = await asyncio.to_thread(_cleanup_customer_from_mikrotik_sync, router_customers_map)
        
        # Update database
        successful_ids = [r["id"] for r in mikrotik_results["removed"]]
        for customer in expired_customers:
            if customer.id in successful_ids:
                customer.status = CustomerStatus.INACTIVE
        
        await db.commit()
        
        return {
            "success": True,
            "message": f"Cleanup completed for router {router_obj.name}",
            "router_id": router_id,
            "router_name": router_obj.name,
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


@router.get("/api/routers/{router_id}/bandwidth-check")
async def check_bandwidth_limits(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Check which active customers have bandwidth queues applied on the router.
    Helps identify users who might be using unlimited bandwidth.
    
    Returns:
    - customers_with_queues: Customers who have bandwidth limits applied
    - customers_without_queues: Customers who are MISSING bandwidth limits (potential issue!)
    - unknown_queues: Queues on router that don't match any customer
    """
    try:
        current_user = await get_current_user(token, db)
        # Get router
        router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        
        # Get all active customers for this router
        stmt = select(Customer).options(selectinload(Customer.plan)).where(
            Customer.router_id == router_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.mac_address.isnot(None)
        )
        result = await db.execute(stmt)
        active_customers = result.scalars().all()
        
        if not active_customers:
            return {
                "router_id": router_id,
                "router_name": router_obj.name,
                "message": "No active customers found for this router",
                "customers_with_queues": [],
                "customers_without_queues": [],
                "unknown_queues": []
            }
        
        # Get router data in thread pool (non-blocking)
        router_info = {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port
        }
        router_data = await asyncio.to_thread(_get_bandwidth_check_data_sync, router_info)
        
        if router_data.get("error") == "connect_failed":
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
        
        all_queues = router_data["all_queues"]
        arp_entries = router_data["arp_entries"]
        dhcp_leases = router_data["dhcp_leases"]
        
        # Build MAC to IP map
        mac_to_ip = {}
        for entry in arp_entries:
            mac = entry.get("mac-address", "")
            if mac:
                mac_to_ip[normalize_mac_address(mac)] = entry.get("address")
        for lease in dhcp_leases:
            mac = lease.get("mac-address", "")
            if mac and lease.get("address"):
                mac_to_ip[normalize_mac_address(mac)] = lease.get("address")
            
            # Build queue lookup by target IP
            queue_by_ip = {}
            queue_by_name = {}
            for q in all_queues:
                target = q.get("target", "")
                # Extract IP from target (e.g., "192.168.1.100/32" -> "192.168.1.100")
                if "/" in target:
                    ip = target.split("/")[0]
                    queue_by_ip[ip] = q
                queue_by_name[q.get("name", "")] = q
            
            customers_with_queues = []
            customers_without_queues = []
            customer_macs = set()
            
            for customer in active_customers:
                normalized_mac = normalize_mac_address(customer.mac_address)
                customer_macs.add(normalized_mac)
                username = normalized_mac.replace(":", "")
                queue_name = f"plan_{username}"
                
                client_ip = mac_to_ip.get(normalized_mac)
                has_queue = False
                queue_info = None
                
                # Check by queue name or by IP
                if queue_name in queue_by_name:
                    has_queue = True
                    queue_info = queue_by_name[queue_name]
                elif client_ip and client_ip in queue_by_ip:
                    has_queue = True
                    queue_info = queue_by_ip[client_ip]
                
                customer_data = {
                    "id": customer.id,
                    "name": customer.name,
                    "mac_address": customer.mac_address,
                    "current_ip": client_ip,
                    "is_connected": client_ip is not None,
                    "plan_name": customer.plan.name if customer.plan else None,
                    "plan_speed": customer.plan.speed if customer.plan else None,
                    "expiry": customer.expiry.isoformat() if customer.expiry else None
                }
                
                if has_queue:
                    customer_data["queue_name"] = queue_info.get("name")
                    customer_data["queue_limit"] = queue_info.get("max-limit")
                    customer_data["queue_target"] = queue_info.get("target")
                    customers_with_queues.append(customer_data)
                else:
                    customer_data["issue"] = "NO BANDWIDTH LIMIT - USER HAS UNLIMITED SPEED!" if client_ip else "Not connected"
                    customers_without_queues.append(customer_data)
            
            # Find queues that don't belong to any known customer
            unknown_queues = []
            for q in all_queues:
                queue_name = q.get("name", "")
                # Skip if it's a known customer queue
                if queue_name.startswith("plan_"):
                    username = queue_name.replace("plan_", "")
                    # Convert username back to MAC format
                    if len(username) == 12:
                        reconstructed_mac = ":".join(username[i:i+2] for i in range(0, 12, 2))
                        if reconstructed_mac not in customer_macs:
                            unknown_queues.append({
                                "name": queue_name,
                                "target": q.get("target"),
                                "limit": q.get("max-limit"),
                                "comment": q.get("comment", "")
                            })
        
        return {
            "router_id": router_id,
            "router_name": router_obj.name,
            "total_active_customers": len(active_customers),
            "customers_with_queues": len(customers_with_queues),
            "customers_without_queues_count": len(customers_without_queues),
            "has_unlimited_users": any(c.get("is_connected") for c in customers_without_queues),
            "customers_with_limits": customers_with_queues,
            "customers_WITHOUT_limits": customers_without_queues,
            "unknown_queues": unknown_queues
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking bandwidth limits for router {router_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Check failed: {str(e)}")


@router.get("/api/routers/{router_id}/illegal-connections")
async def check_illegal_connections(
    router_id: int,
    only_bypassing: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Find devices currently using internet that are NOT active paying customers.
    
    Query params:
    - only_bypassing: If True, only show devices that are ACTUALLY using internet
                      (have hotspot session or bypassed IP binding). 
                      If False (default), show ALL devices in ARP table.
                      
    NOTE: Devices in ARP table that don't have hotspot sessions are usually
    BLOCKED by the captive portal - they're connected to WiFi but can't browse.
    
    Compares:
    - Devices currently connected on MikroTik (ARP + DHCP + active sessions)
    - vs Active customers in the database
    
    Detects:
    1. Unknown devices (MAC not in database at all) - UNAUTHORIZED
    2. Expired/inactive customers still connected - SHOULD BE DISCONNECTED
    
    Returns list of illegal connections with details for removal.
    """
    try:
        current_user = await get_current_user(token, db)
        # Get router
        router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        
        # Get ALL customers with MAC addresses for this router (to check status)
        # Use selectinload to eagerly load plan to avoid lazy loading errors
        stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(
            Customer.router_id == router_id,
            Customer.mac_address.isnot(None)
        )
        result = await db.execute(stmt)
        all_customers = result.scalars().all()
        
        # Build lookup of known customer MACs with their status
        known_macs = {}
        active_macs = set()
        for c in all_customers:
            normalized = normalize_mac_address(c.mac_address)
            known_macs[normalized] = {
                "id": c.id,
                "name": c.name,
                "status": c.status.value if c.status else "unknown",
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "plan_name": c.plan.name if c.plan else "No plan"
            }
            if c.status == CustomerStatus.ACTIVE:
                active_macs.add(normalized)
        
        # Get router data in thread pool (non-blocking)
        router_info = {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port
        }
        router_data = await asyncio.to_thread(_get_illegal_connections_data_sync, router_info)
        
        if router_data.get("error") == "connect_failed":
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
        
        arp_entries = router_data["arp_entries"]
        dhcp_leases = router_data["dhcp_leases"]
        active_sessions = router_data["active_sessions"]
        ip_bindings = router_data["ip_bindings"]
        queues = router_data["queues"]
        
        # Collect all currently connected devices from multiple sources
        connected_devices = {}  # MAC -> device info
        
        # SOURCE 1: ARP table - devices that have communicated recently
        for entry in arp_entries:
            mac = entry.get("mac-address", "")
            if mac:
                normalized_mac = normalize_mac_address(mac)
                if normalized_mac not in connected_devices:
                    connected_devices[normalized_mac] = {
                        "mac_address": mac,
                        "ip_address": entry.get("address", "N/A"),
                        "interface": entry.get("interface", ""),
                        "source": "ARP",
                        "is_complete": entry.get("complete", "") == "true"
                    }
        
        # SOURCE 2: DHCP leases - devices that got an IP address
        for lease in dhcp_leases:
            mac = lease.get("mac-address", "")
            if mac:
                normalized_mac = normalize_mac_address(mac)
                lease_status = lease.get("status", "")
                
                if normalized_mac in connected_devices:
                    # Update existing entry with DHCP info
                    connected_devices[normalized_mac]["dhcp_status"] = lease_status
                    connected_devices[normalized_mac]["dhcp_hostname"] = lease.get("host-name", "")
                    connected_devices[normalized_mac]["source"] += "+DHCP"
                else:
                    connected_devices[normalized_mac] = {
                        "mac_address": mac,
                        "ip_address": lease.get("address", "N/A"),
                        "interface": lease.get("server", ""),
                        "source": "DHCP",
                        "dhcp_status": lease_status,
                        "dhcp_hostname": lease.get("host-name", "")
                    }
        
        # SOURCE 3: Hotspot active sessions - currently authenticated users
        for session in active_sessions:
            mac = session.get("mac-address", "")
            if mac:
                normalized_mac = normalize_mac_address(mac)
                bytes_in = int(session.get("bytes-in", 0) or 0)
                bytes_out = int(session.get("bytes-out", 0) or 0)
                
                if normalized_mac in connected_devices:
                    connected_devices[normalized_mac]["hotspot_active"] = True
                    connected_devices[normalized_mac]["uptime"] = session.get("uptime", "")
                    connected_devices[normalized_mac]["bytes_in"] = bytes_in
                    connected_devices[normalized_mac]["bytes_out"] = bytes_out
                    connected_devices[normalized_mac]["source"] += "+HOTSPOT"
                else:
                    connected_devices[normalized_mac] = {
                        "mac_address": mac,
                        "ip_address": session.get("address", "N/A"),
                        "source": "HOTSPOT",
                        "hotspot_active": True,
                        "uptime": session.get("uptime", ""),
                        "bytes_in": bytes_in,
                        "bytes_out": bytes_out
                    }
        
        # SOURCE 4: IP Bindings - shows who has bypassed access (can use internet without login)
        # Build a set of MACs that have bypassed bindings
        bypassed_macs = set()
        for binding in ip_bindings:
            if binding.get("type") == "bypassed":
                mac = binding.get("mac-address", "")
                if mac:
                    bypassed_macs.add(normalize_mac_address(mac))
                    # Also mark in connected_devices
                    normalized_mac = normalize_mac_address(mac)
                    if normalized_mac in connected_devices:
                        connected_devices[normalized_mac]["has_bypass"] = True
                        connected_devices[normalized_mac]["source"] += "+BYPASSED"
        
        # SOURCE 5: Simple queues with recent traffic - indicates active usage
        for queue in queues:
            comment = queue.get("comment", "")
            # Extract MAC from queue comment (format: "MAC:XX:XX:XX:XX:XX:XX")
            if "MAC:" in comment:
                mac_match = comment.split("MAC:")[1].split()[0] if "MAC:" in comment else ""
                if mac_match:
                    normalized_mac = normalize_mac_address(mac_match)
                    if normalized_mac in connected_devices:
                        connected_devices[normalized_mac]["has_queue"] = True
                        connected_devices[normalized_mac]["queue_name"] = queue.get("name", "")
            
            # Build set of MACs that are actually using internet (hotspot active or bypassed)
            actually_using_internet = set()
            for mac, device_info in connected_devices.items():
                if device_info.get("hotspot_active") or device_info.get("has_bypass"):
                    actually_using_internet.add(mac)
            
            # Now compare: connected devices vs active customers
            unauthorized_devices = []
            expired_still_connected = []
            skipped_protected = []
            skipped_not_bypassing = 0  # Count of ARP-only devices (blocked by captive portal)
            
            for mac, device_info in connected_devices.items():
                # PROTECTION CHECK: Skip system/infrastructure devices
                ip_addr = device_info.get("ip_address", "")
                interface = device_info.get("interface", "")
                hostname = device_info.get("dhcp_hostname", "")
                
                if is_protected_device(ip_address=ip_addr, interface=interface, hostname=hostname):
                    skipped_protected.append({
                        "mac_address": device_info["mac_address"],
                        "ip_address": ip_addr,
                        "interface": interface,
                        "hostname": hostname,
                        "reason": "Protected system/infrastructure device"
                    })
                    logger.debug(f"[ILLEGAL-CHECK] Skipping protected device: {ip_addr} on {interface}")
                    continue
                
                # If only_bypassing is True, skip devices that are just in ARP
                # (they're connected to WiFi but blocked by captive portal)
                is_actually_using = mac in actually_using_internet
                if only_bypassing and not is_actually_using:
                    skipped_not_bypassing += 1
                    continue
                
                customer_info = known_macs.get(mac)
                
                if not customer_info:
                    # MAC not in database at all - UNAUTHORIZED
                    bytes_total = device_info.get("bytes_in", 0) + device_info.get("bytes_out", 0)
                    severity = "CRITICAL" if is_actually_using else "LOW"  # Lower severity if just in ARP
                    if bytes_total > 1000000:
                        severity = "CRITICAL"
                    elif is_actually_using:
                        severity = "HIGH"
                    
                    unauthorized_devices.append({
                        "type": "UNAUTHORIZED",
                        "severity": severity,
                        "mac_address": device_info["mac_address"],
                        "ip_address": device_info["ip_address"],
                        "source": device_info["source"],
                        "interface": device_info.get("interface", ""),
                        "hostname": device_info.get("dhcp_hostname", ""),
                        "uptime": device_info.get("uptime", ""),
                        "is_bypassing": is_actually_using,  # True = actually using internet
                        "bytes_downloaded": device_info.get("bytes_in", 0),
                        "bytes_uploaded": device_info.get("bytes_out", 0),
                        "bytes_total_mb": round(bytes_total / 1048576, 2),
                        "has_queue": device_info.get("has_queue", False),
                        "issue": "Device using internet but NOT registered in customer database!"
                    })
                elif customer_info["status"] != "active":
                    # Customer exists but is NOT ACTIVE - should not have access
                    bytes_total = device_info.get("bytes_in", 0) + device_info.get("bytes_out", 0)
                    severity = "CRITICAL" if is_actually_using else "MEDIUM"
                    expired_still_connected.append({
                        "type": "EXPIRED_CONNECTED",
                        "severity": severity,
                        "mac_address": device_info["mac_address"],
                        "ip_address": device_info["ip_address"],
                        "source": device_info["source"],
                        "customer_id": customer_info["id"],
                        "customer_name": customer_info["name"],
                        "customer_status": customer_info["status"],
                        "expiry": customer_info["expiry"],
                        "plan_name": customer_info.get("plan_name", ""),
                        "uptime": device_info.get("uptime", ""),
                        "is_bypassing": is_actually_using,  # True = actually using internet
                        "bytes_downloaded": device_info.get("bytes_in", 0),
                        "bytes_uploaded": device_info.get("bytes_out", 0),
                        "bytes_total_mb": round(bytes_total / 1048576, 2),
                        "has_queue": device_info.get("has_queue", False),
                        "issue": f"Customer is {customer_info['status']} but still {'USING INTERNET!' if is_actually_using else 'in ARP table'}"
                    })
            
            # Combine all issues
            all_issues = unauthorized_devices + expired_still_connected
            
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            all_issues.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 99))
            
            # Count how many are actually bypassing vs just in ARP
            bypassing_unauthorized = len([i for i in unauthorized_devices if i.get("is_bypassing")])
            bypassing_expired = len([i for i in expired_still_connected if i.get("is_bypassing")])
            
            return {
                "router_id": router_id,
                "router_name": router_obj.name,
                "scan_time": datetime.utcnow().isoformat(),
                "filter_mode": "only_bypassing" if only_bypassing else "all_devices",
                "summary": {
                    "total_connected_devices": len(connected_devices),
                    "actually_using_internet": len(actually_using_internet),  # Hotspot active or bypassed
                    "active_customers": len(active_macs),
                    "total_issues": len(all_issues),
                    "critical": len([i for i in all_issues if i.get("severity") == "CRITICAL"]),
                    "high": len([i for i in all_issues if i.get("severity") == "HIGH"]),
                    "unauthorized_devices": len(unauthorized_devices),
                    "unauthorized_bypassing": bypassing_unauthorized,  # Actually using internet!
                    "expired_still_connected": len(expired_still_connected),
                    "expired_bypassing": bypassing_expired,  # Actually using internet!
                    "skipped_protected": len(skipped_protected),
                    "skipped_not_bypassing": skipped_not_bypassing if only_bypassing else 0
                },
                "issues": all_issues,
                "protected_devices": skipped_protected,
                "note": "Devices with is_bypassing=true are ACTUALLY using internet. Others are just in ARP (blocked by captive portal).",
                "recommendation": f"Focus on {bypassing_unauthorized + bypassing_expired} devices with is_bypassing=true - these are actively using internet without paying!" if (bypassing_unauthorized + bypassing_expired) > 0 else ("Use POST /api/routers/{router_id}/remove-illegal-users to remove all" if all_issues else "No illegal connections found")
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking illegal connections for router {router_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Check failed: {str(e)}")


@router.post("/api/routers/{router_id}/remove-illegal-users")
async def remove_all_illegal_users(
    router_id: int,
    limit: int = 50,
    delay_ms: int = 150,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Remove illegal/unauthorized users from MikroTik router efficiently.
    
    Optimized for performance:
    - Fetches all router data ONCE (not per-user)
    - Adds configurable delay between removals to prevent router overload
    - Runs in thread pool to not block the server
    - Limits users per request (default 50)
    
    Query params:
    - limit: Max users to remove in one request (default 50, max 100)
    - delay_ms: Delay between each removal in milliseconds (default 150ms)
    
    Returns detailed results for each removed user.
    """
    # Validate parameters
    if limit > 100:
        limit = 100
    if limit < 1:
        limit = 1
    if delay_ms < 50:
        delay_ms = 50  # Minimum 50ms delay to protect router
    if delay_ms > 1000:
        delay_ms = 1000
    
    try:
        current_user = await get_current_user(token, db)
        # Get router
        router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        
        # Get all customers with MAC addresses for this router
        stmt = select(Customer).where(
            Customer.router_id == router_id,
            Customer.mac_address.isnot(None)
        )
        result = await db.execute(stmt)
        all_customers = result.scalars().all()
        
        # Build lookup of known customer MACs with their status
        known_macs = {}
        active_macs = set()
        for c in all_customers:
            normalized = normalize_mac_address(c.mac_address)
            known_macs[normalized] = {
                "id": c.id,
                "name": c.name,
                "status": c.status.value if c.status else "unknown"
            }
            if c.status == CustomerStatus.ACTIVE:
                active_macs.add(normalized)
        
        # Quick scan to find illegal users in thread pool (non-blocking)
        router_info = {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port,
            "name": router_obj.name
        }
        scan_result = await asyncio.to_thread(_scan_connected_devices_sync, router_info)
        
        if scan_result.get("error") == "connect_failed":
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
        
        connected_devices = scan_result["connected_devices"]
        
        # Find illegal users
        illegal_users = []
        skipped_protected_count = 0
        for mac, device_info in connected_devices.items():
            ip_addr = device_info.get("ip_address", "")
            interface = device_info.get("interface", "")
            
            # Double-check protection (in case device info was incomplete earlier)
            if is_protected_device(ip_address=ip_addr, interface=interface):
                skipped_protected_count += 1
                continue
                
            customer_info = known_macs.get(mac)
            if not customer_info:
                illegal_users.append({
                    "mac_address": device_info["mac_address"],
                    "ip_address": ip_addr,
                    "reason": "UNAUTHORIZED"
                })
            elif customer_info["status"] != "active":
                illegal_users.append({
                    "mac_address": device_info["mac_address"],
                    "ip_address": ip_addr,
                    "reason": "EXPIRED"
                })
        
        if skipped_protected_count > 0:
            logger.info(f"[REMOVE-ILLEGAL] Skipped {skipped_protected_count} protected devices")
        
        if not illegal_users:
            return {
                "success": True,
                "router_id": router_id,
                "router_name": router_obj.name,
                "message": "No illegal users found",
                "removed_count": 0,
                "failed_count": 0,
                "total_found": 0,
                "details": []
            }
        
        total_found = len(illegal_users)
        
        # Apply limit
        if len(illegal_users) > limit:
            logger.info(f"[REMOVE-ILLEGAL] Found {len(illegal_users)} illegal users, limiting to {limit}")
            illegal_users = illegal_users[:limit]
        
        logger.info(f"[REMOVE-ILLEGAL] Processing {len(illegal_users)} illegal users (of {total_found} found)")
        
        # Prepare router info for thread
        router_info = {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port,
            "name": router_obj.name
        }
        
        # Run bulk removal in thread pool (non-blocking)
        loop = asyncio.get_event_loop()
        removal_results = await loop.run_in_executor(
            None,
            _bulk_remove_illegal_users_sync,
            router_info,
            illegal_users,
            known_macs,
            delay_ms
        )
        
        return {
            "success": True,
            "router_id": router_id,
            "router_name": router_obj.name,
            "message": f"Removed {len(removal_results['removed'])} illegal users, {len(removal_results['failed'])} failed",
            "removed_count": len(removal_results["removed"]),
            "failed_count": len(removal_results["failed"]),
            "total_found": total_found,
            "processed": len(illegal_users),
            "remaining": total_found - len(illegal_users) if total_found > limit else 0,
            "details": removal_results["removed"] + removal_results["failed"]
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing illegal users from router {router_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Removal failed: {str(e)}")


@router.get("/api/routers/{router_id}/diagnose/{mac_address}")
async def diagnose_mac_address(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Diagnose a MAC address - shows EXACTLY what the router has for this device.
    
    Useful for debugging why a customer can still access internet after expiry.
    Returns all router entries for this MAC: IP bindings, hotspot users, active sessions, etc.
    """
    current_user = await get_current_user(token, db)
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    
    router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")
    
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    
    # Check database first
    stmt = select(Customer).where(Customer.mac_address.isnot(None))
    result = await db.execute(stmt)
    all_customers = result.scalars().all()
    
    db_info = None
    for c in all_customers:
        if normalize_mac_address(c.mac_address) == normalized_mac:
            db_info = {
                "customer_id": c.id,
                "name": c.name,
                "status": c.status.value if c.status else "unknown",
                "router_id": c.router_id,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "is_expired": c.expiry < datetime.utcnow() if c.expiry else False
            }
            break
    
    # Sync helper for diagnosis - runs in thread pool
    def _diagnose_mac_sync(router_info: dict, normalized_mac: str, username: str) -> dict:
        api = MikroTikAPI(
            router_info["ip"],
            router_info["username"],
            router_info["password"],
            router_info["port"],
            timeout=15,
            connect_timeout=5
        )
        
        if not api.connect():
            return {"error": "connect_failed"}
        
        try:
            router_entries = {
                "ip_bindings": [],
                "hotspot_users": [],
                "active_sessions": [],
                "arp_entries": [],
                "dhcp_leases": [],
                "queues": [],
                "hosts": []
            }
            can_access_internet = False
            diagnosis = []
            
            # Check IP bindings (CRITICAL - bypassed = free internet)
            bindings = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings.get("success"):
                for b in bindings.get("data", []):
                    b_mac = normalize_mac_address(b.get("mac-address", "")) if b.get("mac-address") else ""
                    b_comment = b.get("comment", "")
                    if b_mac == normalized_mac or username in b_comment.upper():
                        router_entries["ip_bindings"].append(b)
                        if b.get("type") == "bypassed":
                            can_access_internet = True
                            diagnosis.append(f"⚠️ BYPASSED IP BINDING FOUND - user can access internet without login!")
            
            # Check hotspot users
            users = api.send_command("/ip/hotspot/user/print")
            if users.get("success"):
                for u in users.get("data", []):
                    u_name = u.get("name", "")
                    u_comment = u.get("comment", "")
                    if u_name == username or normalized_mac.upper() in u_comment.upper():
                        router_entries["hotspot_users"].append(u)
            
            # Check active sessions
            active = api.send_command("/ip/hotspot/active/print")
            if active.get("success"):
                for s in active.get("data", []):
                    s_mac = normalize_mac_address(s.get("mac-address", "")) if s.get("mac-address") else ""
                    s_user = s.get("user", "").upper()
                    if s_mac == normalized_mac or s_user == username.upper():
                        router_entries["active_sessions"].append(s)
                        can_access_internet = True
                        diagnosis.append(f"⚠️ ACTIVE HOTSPOT SESSION - user is currently online!")
            
            # Check ARP table
            arp = api.send_command("/ip/arp/print")
            if arp.get("success"):
                for a in arp.get("data", []):
                    a_mac = normalize_mac_address(a.get("mac-address", "")) if a.get("mac-address") else ""
                    if a_mac == normalized_mac:
                        router_entries["arp_entries"].append(a)
            
            # Check DHCP leases
            leases = api.send_command("/ip/dhcp-server/lease/print")
            if leases.get("success"):
                for l in leases.get("data", []):
                    l_mac = normalize_mac_address(l.get("mac-address", "")) if l.get("mac-address") else ""
                    if l_mac == normalized_mac:
                        router_entries["dhcp_leases"].append(l)
            
            # Check queues
            queues = api.send_command("/queue/simple/print")
            if queues.get("success"):
                for q in queues.get("data", []):
                    q_name = q.get("name", "")
                    q_comment = q.get("comment", "")
                    if username in q_name or normalized_mac.upper() in q_comment.upper():
                        router_entries["queues"].append(q)
            
            # Check hosts
            hosts = api.send_command("/ip/hotspot/host/print")
            if hosts.get("success"):
                for h in hosts.get("data", []):
                    h_mac = normalize_mac_address(h.get("mac-address", "")) if h.get("mac-address") else ""
                    if h_mac == normalized_mac:
                        router_entries["hosts"].append(h)
            
            return {
                "router_entries": router_entries,
                "can_access_internet": can_access_internet,
                "diagnosis": diagnosis
            }
        finally:
            api.disconnect()
    
    # Run diagnosis in thread pool (non-blocking)
    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port
    }
    diag_result = await asyncio.to_thread(_diagnose_mac_sync, router_info, normalized_mac, username)
    
    if diag_result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router")
    
    findings = {
        "mac_address": mac_address,
        "normalized": normalized_mac,
        "username_format": username,
        "database_info": db_info,
        "router_entries": diag_result["router_entries"],
        "diagnosis": diag_result["diagnosis"],
        "can_access_internet": diag_result["can_access_internet"]
    }
    
    # Build diagnosis summary
    if db_info and db_info.get("is_expired") and findings["can_access_internet"]:
        findings["diagnosis"].insert(0, "🚨 CRITICAL: Customer is EXPIRED but CAN STILL ACCESS INTERNET!")
    
    if not findings["router_entries"]["ip_bindings"] and not findings["router_entries"]["active_sessions"]:
        findings["diagnosis"].append("✅ No bypass or active session - hotspot should be blocking this device")
    
    # Count entries
    total_entries = sum(len(v) for v in findings["router_entries"].values())
    findings["total_router_entries"] = total_entries
    
    return findings


@router.delete("/api/routers/{router_id}/force-remove/{mac_address}")
async def force_remove_mac_address(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    FORCE remove ALL router entries for a MAC address.
    
    Removes everything:
    - All IP bindings with this MAC
    - All hotspot users matching this MAC
    - All active sessions  
    - All hosts entries
    - All queues
    - All DHCP leases
    
    Use this when normal removal isn't working.
    """
    current_user = await get_current_user(token, db)
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    
    router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")
    
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    
    # Run force removal in thread pool (non-blocking)
    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port
    }
    result = await asyncio.to_thread(_force_remove_mac_sync, router_info, normalized_mac, username)
    
    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router")
    
    removed = result["removed"]
    total_removed = sum(removed.values())
    
    return {
        "success": True,
        "mac_address": mac_address,
        "total_removed": total_removed,
        "details": removed,
        "message": f"Force removed {total_removed} entries for {mac_address}"
    }


@router.post("/api/routers/{router_id}/cleanup-bypassing")
async def cleanup_all_bypassing_users(
    router_id: int,
    dry_run: bool = True,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Find and remove ALL IP bindings that belong to expired/unauthorized users.
    
    This is the preventative cleanup endpoint - it scans the router's IP bindings
    and removes any that don't belong to active paying customers.
    
    Args:
        router_id: Router to clean up
        dry_run: If True (default), only report what would be removed. 
                 Set to False to actually remove.
    
    Returns:
        List of removed (or would-be-removed) bindings with customer info.
    """
    current_user = await get_current_user(token, db)
    logger.info(f"[CLEANUP-BYPASS] Starting cleanup for router {router_id}, dry_run={dry_run}")
    
    router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")
    
    # Get ALL customers with MAC addresses (any router, for cross-reference)
    stmt = select(Customer).where(Customer.mac_address.isnot(None))
    result = await db.execute(stmt)
    all_customers = result.scalars().all()
    
    # Build lookup: MAC -> customer info
    customer_by_mac = {}
    active_macs = set()
    for c in all_customers:
        normalized = normalize_mac_address(c.mac_address)
        customer_by_mac[normalized] = {
            "id": c.id,
            "name": c.name,
            "status": c.status.value if c.status else "unknown",
            "expiry": c.expiry.isoformat() if c.expiry else None,
            "router_id": c.router_id
        }
        if c.status == CustomerStatus.ACTIVE:
            active_macs.add(normalized)
    
    # Run cleanup in thread pool (non-blocking)
    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port
    }
    cleanup_result = await asyncio.to_thread(_cleanup_bypassing_sync, router_info, active_macs, customer_by_mac, dry_run)
    
    if cleanup_result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router")
    
    all_bindings = cleanup_result["all_bindings"]
    to_remove = cleanup_result["to_remove"]
    kept = cleanup_result["kept"]
    
    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "dry_run": dry_run,
        "summary": {
            "total_bindings_scanned": len(all_bindings),
            "active_customers": len(active_macs),
            "bindings_to_remove": len(to_remove),
            "bindings_kept": len(kept)
        },
        "to_remove": to_remove,
        "message": f"{'Would remove' if dry_run else 'Removed'} {len(to_remove)} unauthorized IP bindings" if to_remove else "No unauthorized bindings found",
        "next_step": f"Run with dry_run=false to actually remove these {len(to_remove)} bindings" if dry_run and to_remove else None
    }


@router.delete("/api/routers/{router_id}/remove-illegal-user/{mac_address}")
async def remove_single_illegal_user(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Remove a single illegal/unauthorized user from MikroTik router by MAC address.
    
    Uses the same comprehensive removal algorithm as the expired user cron job:
    - Removes IP binding
    - Removes hotspot host entry
    - Removes hotspot user
    - Disconnects active sessions
    - Removes simple queues
    - Removes DHCP leases
    
    If the MAC belongs to a customer in the database, their status is updated to INACTIVE.
    """
    current_user = await get_current_user(token, db)
    logger.info(f"[REMOVE-ILLEGAL] Single removal request: router_id={router_id}, mac={mac_address}")
    
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    
    # Get router
    router_obj = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")
    
    # First, check if this is a protected device by looking up its IP
    # We'll do a quick ARP lookup to get the IP for this MAC
    normalized_mac = normalize_mac_address(mac_address)
    stmt = select(Customer).where(
        Customer.router_id == router_id,
        Customer.mac_address.isnot(None)
    )
    result = await db.execute(stmt)
    all_customers = result.scalars().all()
    
    customer_info = None
    customer_to_update = None
    for c in all_customers:
        if normalize_mac_address(c.mac_address) == normalized_mac:
            customer_info = {"id": c.id, "name": c.name, "status": c.status.value if c.status else "unknown"}
            customer_to_update = c
            break
    
    # Run removal in thread pool (non-blocking)
    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port
    }
    result = await asyncio.to_thread(_remove_single_illegal_user_sync, router_info, mac_address, normalized_mac, customer_info)
    
    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    
    if result.get("error") == "protected_device":
        raise HTTPException(status_code=403, detail=result.get("detail"))
    
    removal_result = result.get("removal_result", {})
    
    if not removal_result.get("success"):
        raise HTTPException(status_code=500, detail=removal_result.get("error", "Failed to remove user"))
    
    # Update customer status to INACTIVE if they exist in database
    if customer_to_update:
        customer_to_update.status = CustomerStatus.INACTIVE
        await db.commit()
        removal_result["customer_status_updated"] = True
        logger.info(f"[REMOVE-ILLEGAL] Updated customer {customer_to_update.id} status to INACTIVE")
    
    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_obj.name,
        "message": f"Successfully removed user with MAC {mac_address}",
        "removed": removal_result
    }

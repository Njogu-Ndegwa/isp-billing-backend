from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from sqlalchemy.orm import selectinload
from typing import Optional, List
from datetime import datetime, timedelta
from dataclasses import asdict
from pathlib import Path

from app.db.database import get_db
from app.db.models import Router, Customer, Plan, CustomerStatus, ConnectionType, ProvisioningToken
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import (
    MikroTikAPI,
    is_hotspot_parent_queue_name,
    normalize_mac_address,
    validate_mac_address,
)
from app.services.router_helpers import get_router_by_id, get_router_by_identity, connect_to_router
from app.core.protected_devices import is_protected_device
from app.services.router_availability import record_router_availability
from app.services.router_concurrency import run_with_guard
from app.services.provisioning import provision_base_url_for_vpn, fetch_certificate_flag_for_url
from app.services.pppoe_customer_import import (
    read_pppoe_workbook,
    normalize_workbook_rows,
    import_pppoe_customers,
)
from app.config import settings

import logging
import time
import asyncio
import hashlib
import json
import os
import tempfile

logger = logging.getLogger(__name__)

router = APIRouter(tags=["router-operations"])


async def _run_locked_router_thread(router_obj: Router, sync_func, *args, **kwargs) -> dict:
    """Run one live router mutation at a time per router."""
    from app.services.mikrotik_background import router_locks

    router_key = f"{router_obj.ip_address}:{router_obj.port}"
    async with router_locks.acquire(router_key):
        return await asyncio.to_thread(sync_func, *args, **kwargs)


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
    await db.commit()
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
    await db.commit()
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
    await db.commit()
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
    await db.commit()
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
        
        current_state = await db.execute(
            select(Customer.id, Customer.status, Customer.expiry).where(
                Customer.id.in_([customer.id for customer in expired_customers])
            )
        )
        now_before_router_cleanup = datetime.utcnow()
        still_expired_ids = set()
        for customer_id, status, expiry in current_state.all():
            if status == CustomerStatus.ACTIVE and expiry and expiry <= now_before_router_cleanup:
                still_expired_ids.add(customer_id)

        expired_customers = [
            customer for customer in expired_customers
            if customer.id in still_expired_ids
        ]

        await db.commit()

        if not expired_customers:
            return {
                "success": True,
                "message": "Expired customers were renewed before router cleanup",
                "router_id": router_id,
                "router_name": router_obj.name,
                "cleaned_up": 0,
                "deactivated": 0
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
        
        from app.services.mikrotik_background import router_locks, _cleanup_single_router_hotspot_sync
        
        router_key = f"{router_obj.ip_address}:{router_obj.port}"
        async with router_locks.acquire(router_key):
            mikrotik_results = await asyncio.to_thread(
                _cleanup_single_router_hotspot_sync,
                router_customers_map[router_key]["router"],
                router_customers_map[router_key]["customers"],
            )

        successful_ids = {r["id"] for r in mikrotik_results["removed"]}
        deactivated_count = 0
        now_after_cleanup = datetime.utcnow()
        for customer in expired_customers:
            if customer.id in successful_ids:
                await db.refresh(customer)
                if customer.expiry and customer.expiry > now_after_cleanup:
                    logger.warning(
                        "[ROUTER-CLEANUP] Customer %s renewed during cleanup; skipping deactivation",
                        customer.id,
                    )
                    continue
                customer.status = CustomerStatus.INACTIVE
                deactivated_count += 1

        await db.commit()
        
        return {
            "success": True,
            "message": f"Cleanup completed for router {router_obj.name}",
            "router_id": router_id,
            "router_name": router_obj.name,
            "expired_found": len(expired_customers),
            "deactivated": deactivated_count,
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
        await db.commit()
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

        # Build queue lookup by target IP/name once. Hotspot parent queues are
        # reported separately because they can shadow otherwise-correct plan
        # queues and make every hotspot customer effectively unlimited.
        queue_by_ip = {}
        queue_by_name = {}
        hotspot_parent_queues = []
        for q in all_queues:
            queue_name = q.get("name", "")
            if is_hotspot_parent_queue_name(queue_name):
                hotspot_parent_queues.append({
                    "name": queue_name,
                    "target": q.get("target"),
                    "limit": q.get("max-limit"),
                    "disabled": q.get("disabled", "false"),
                })
                continue
            target = q.get("target", "")
            # Extract IP from target (e.g., "192.168.1.100/32" -> "192.168.1.100")
            if "/" in target:
                ip = target.split("/")[0]
                queue_by_ip[ip] = q
            queue_by_name[queue_name] = q

        parent_queue_shadowing = any(
            str(q.get("disabled", "false")).lower() != "true"
            for q in hotspot_parent_queues
        )

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
                if parent_queue_shadowing:
                    customer_data["issue"] = "HOTSPOT PARENT QUEUE MAY SHADOW PLAN QUEUE"
                    customers_without_queues.append(customer_data)
                else:
                    customers_with_queues.append(customer_data)
            else:
                customer_data["issue"] = "NO BANDWIDTH LIMIT - USER HAS UNLIMITED SPEED!" if client_ip else "Not connected"
                customers_without_queues.append(customer_data)

        # Find queues that don't belong to any known customer
        unknown_queues = []
        for q in all_queues:
            queue_name = q.get("name", "")
            if is_hotspot_parent_queue_name(queue_name):
                continue
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
            "has_unlimited_users": parent_queue_shadowing or any(c.get("is_connected") for c in customers_without_queues),
            "has_hotspot_parent_queues": bool(hotspot_parent_queues),
            "has_shadowing_hotspot_parent_queues": parent_queue_shadowing,
            "hotspot_parent_queues": hotspot_parent_queues,
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
        await db.commit()
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
        await db.commit()
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
        await db.commit()
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
            infrastructure = {}

            # =================================================================
            # INFRASTRUCTURE CHECKS (new -- prepended before device checks)
            # =================================================================
            infra_issues = []

            # Hotspot server status
            hs_servers = api.get_hotspot_server_status()
            hs_list = hs_servers.get("data", []) if hs_servers.get("success") else []
            hs_enabled = [s for s in hs_list if not s["disabled"]]
            infrastructure["hotspot_server"] = {
                "running": len(hs_enabled) > 0,
                "servers": hs_list,
            }
            if not hs_enabled:
                infra_issues.append({
                    "severity": "critical",
                    "check": "hotspot_server",
                    "message": "Hotspot server is not running or disabled",
                    "recommendation": "Enable the hotspot server on the router",
                })

            hs_interface = hs_enabled[0].get("interface", "bridge") if hs_enabled else "bridge"

            # Bridge & ports
            bridge_data = api.get_bridge_ports_status()
            bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
            bridge_ports_list = bridge_data.get("ports", []) if bridge_data.get("success") else []
            port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports_list}

            hs_bridge = bridges.get(hs_interface)
            infrastructure["hotspot_bridge"] = {
                "name": hs_interface,
                "exists": hs_bridge is not None,
                "running": hs_bridge.get("running", False) if hs_bridge else False,
            }
            if not hs_bridge or not hs_bridge.get("running", False):
                infra_issues.append({
                    "severity": "critical",
                    "check": "hotspot_bridge",
                    "message": f"Hotspot bridge '{hs_interface}' is missing or not running",
                    "recommendation": "Check bridge configuration on the router",
                })

            ifaces_data = api.get_all_interfaces_detail()
            ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}
            any_hs_port_up = False
            for port_name, iface in ifaces.items():
                if iface.get("type") != "ether" or port_name == "ether1":
                    continue
                if port_bridge_map.get(port_name) == hs_interface and iface.get("running", False):
                    any_hs_port_up = True
                    break
            infrastructure["any_hotspot_port_up"] = any_hs_port_up
            if not any_hs_port_up:
                infra_issues.append({
                    "severity": "warning",
                    "check": "hotspot_ports",
                    "message": "No hotspot bridge port has link up",
                    "recommendation": "Check physical cable connections to hotspot ports",
                })

            # DHCP server
            dhcp_data = api.get_dhcp_server_status()
            dhcp_servers = dhcp_data.get("data", []) if dhcp_data.get("success") else []
            active_dhcp = [d for d in dhcp_servers if not d["disabled"]]
            infrastructure["dhcp_server"] = {
                "running": len(active_dhcp) > 0,
                "servers": dhcp_servers,
            }
            if not active_dhcp:
                infra_issues.append({
                    "severity": "critical",
                    "check": "dhcp_server",
                    "message": "DHCP server is not running -- devices cannot get an IP address",
                    "recommendation": "Enable the DHCP server on the hotspot bridge",
                })

            # DHCP pool
            dhcp_pool_name = active_dhcp[0].get("address_pool", "") if active_dhcp else ""
            if dhcp_pool_name:
                pool_data = api.get_ip_pool_status(dhcp_pool_name)
                pools = pool_data.get("pools", []) if pool_data.get("success") else []
                infrastructure["dhcp_pool"] = pools
                if pools and any(p.get("exhausted") for p in pools):
                    infra_issues.append({
                        "severity": "critical",
                        "check": "dhcp_pool",
                        "message": f"DHCP pool '{dhcp_pool_name}' is exhausted",
                        "recommendation": "Expand pool range or clean stale DHCP leases",
                    })

            # Walled garden
            wg = api.get_walled_garden()
            wg_count = len(wg.get("domain_entries", [])) + len(wg.get("ip_entries", []))
            infrastructure["walled_garden_entries"] = wg_count
            if wg_count == 0:
                infra_issues.append({
                    "severity": "warning",
                    "check": "walled_garden",
                    "message": "No walled garden entries -- captive portal may not load for unauthenticated users",
                    "recommendation": "Add walled garden entries for your payment/portal domains",
                })

            # =================================================================
            # DEVICE-LEVEL CHECKS (existing logic, preserved)
            # =================================================================

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
                            diagnosis.append("BYPASSED IP BINDING FOUND - user can access internet without login!")
                        elif b.get("type") == "blocked":
                            diagnosis.append("IP BINDING is BLOCKED - user is deliberately blocked from internet")
            
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
                        diagnosis.append("ACTIVE HOTSPOT SESSION - user is currently online!")
            
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

            # =================================================================
            # SMART RECOMMENDATIONS (new -- after device checks)
            # =================================================================
            recommendations = []

            if not router_entries["arp_entries"]:
                recommendations.append({
                    "severity": "warning",
                    "message": "Device MAC not found in ARP table -- device may not be physically connected to this router",
                })

            if router_entries["arp_entries"] and not router_entries["dhcp_leases"]:
                recommendations.append({
                    "severity": "warning",
                    "message": "Device is in ARP but has no DHCP lease -- may have a static IP or DHCP is not working",
                })

            if router_entries["dhcp_leases"] and not router_entries["hosts"]:
                recommendations.append({
                    "severity": "info",
                    "message": "Device has DHCP lease but no hotspot host entry -- device may not be on the hotspot interface",
                })

            if router_entries["hosts"] and not router_entries["active_sessions"] and not router_entries["ip_bindings"]:
                recommendations.append({
                    "severity": "info",
                    "message": "Hotspot sees the device but there is no active session or binding -- captive portal should be showing",
                })

            if router_entries["ip_bindings"] and not router_entries["queues"]:
                for binding in router_entries["ip_bindings"]:
                    if binding.get("type") == "bypassed":
                        recommendations.append({
                            "severity": "warning",
                            "message": "User is bypassed but has no bandwidth queue -- user may have unlimited speed",
                        })
                        break

            return {
                "router_entries": router_entries,
                "can_access_internet": can_access_internet,
                "diagnosis": diagnosis,
                "infrastructure": infrastructure,
                "infrastructure_issues": infra_issues,
                "recommendations": recommendations,
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
    await db.commit()
    diag_result = await asyncio.to_thread(_diagnose_mac_sync, router_info, normalized_mac, username)
    
    if diag_result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router")
    
    findings = {
        "mac_address": mac_address,
        "normalized": normalized_mac,
        "username_format": username,
        "database_info": db_info,
        "infrastructure": diag_result.get("infrastructure", {}),
        "infrastructure_issues": diag_result.get("infrastructure_issues", []),
        "router_entries": diag_result["router_entries"],
        "diagnosis": diag_result["diagnosis"],
        "recommendations": diag_result.get("recommendations", []),
        "can_access_internet": diag_result["can_access_internet"]
    }
    
    # Build diagnosis summary
    if db_info and db_info.get("is_expired") and findings["can_access_internet"]:
        findings["diagnosis"].insert(0, "CRITICAL: Customer is EXPIRED but CAN STILL ACCESS INTERNET!")
    
    if not findings["router_entries"]["ip_bindings"] and not findings["router_entries"]["active_sessions"]:
        findings["diagnosis"].append("No bypass or active session - hotspot should be blocking this device")
    
    # Count entries
    total_entries = sum(len(v) for v in findings["router_entries"].values())
    findings["total_router_entries"] = total_entries
    findings["total_issues"] = len(findings["infrastructure_issues"]) + len(findings["recommendations"])
    
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
    await db.commit()
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
    await db.commit()
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
    await db.commit()
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


# =========================================================================
# PORT STATUS & DIAGNOSTICS
# =========================================================================

_port_status_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_PORT_CACHE_TTL = 30  # 30 seconds -- port status changes infrequently


def _get_port_status_sync(router_info: dict) -> dict:
    """Get all ethernet port statuses with bridge assignments. Runs in thread pool."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        bridge_data = api.get_bridge_ports_status()
        bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
        bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []
        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports}
        access_state = api.get_pppoe_access_state()
        pppoe_ports = set(access_state.get("ports", [])) if access_state.get("success") else set()
        has_dual = access_state.get("has_dual", False) if access_state.get("success") else False
        has_hotspot_bridge_pppoe = (
            access_state.get("has_hotspot_bridge_pppoe", False)
            if access_state.get("success") else False
        )
        attachment_map = access_state.get("attachment_map", {}) if access_state.get("success") else {}
        configured_dual_ports = set(router_info.get("dual_ports") or [])
        has_dual = bool(has_dual or (has_hotspot_bridge_pppoe and configured_dual_ports))

        ifaces_data = api.get_all_interfaces_detail()
        ifaces_list = ifaces_data.get("data", []) if ifaces_data.get("success") else []

        ports = []
        for iface in ifaces_list:
            if iface.get("type") != "ether" or iface.get("name") == "ether1":
                continue
            name = iface["name"]
            bridge = port_bridge_map.get(name)
            attachment = attachment_map.get(name, {})
            attachment_mode = attachment.get("mode")
            shared_bridge_dual = (
                name in configured_dual_ports
                and bridge == "bridge"
                and has_hotspot_bridge_pppoe
            )
            if attachment_mode == "dual" or shared_bridge_dual:
                service = "dual"
            elif name in pppoe_ports:
                service = "pppoe"
            elif bridge == "bridge-plain":
                service = "plain"
            elif bridge:
                service = "hotspot"
            else:
                service = "unassigned"

            ports.append({
                "port": name,
                "bridge": bridge or "(none)",
                "service": service,
                "pppoe_attachment_mode": (
                    "shared_hotspot_bridge" if shared_bridge_dual else attachment.get("mode")
                ),
                "pppoe_server_interface": (
                    "bridge" if shared_bridge_dual else attachment.get("server_interface")
                ),
                "link_up": iface.get("running", False),
                "disabled": iface.get("disabled", False),
                "rx_byte": iface.get("rx_byte", 0),
                "tx_byte": iface.get("tx_byte", 0),
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
                "rx_drop": iface.get("rx_drop", 0),
                "tx_drop": iface.get("tx_drop", 0),
                "link_downs": iface.get("link_downs", 0),
                "last_link_up_time": iface.get("last_link_up_time", ""),
                "actual_mtu": iface.get("actual_mtu", 0),
            })

        bridge_info = []
        for bname, bdata in bridges.items():
            bridge_info.append({
                "name": bname,
                "running": bdata.get("running", False),
                "disabled": bdata.get("disabled", False),
                "port_count": sum(1 for p in bridge_ports if p["bridge"] == bname),
            })

        return {
            "success": True,
            "ports": ports,
            "bridges": bridge_info,
            "has_dual": has_dual,
            "has_hotspot_bridge_pppoe": has_hotspot_bridge_pppoe,
        }
    except Exception as e:
        logger.error(f"Error getting port status: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


@router.get("/api/routers/{router_id}/ports")
async def get_router_port_status(
    router_id: int,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Show every ethernet port with bridge assignment, service mode
    (hotspot/pppoe/plain/dual/unassigned), link status, speed, and error counters.
    Cached for 30s unless ?refresh=true.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    if not refresh and router_id in _port_status_cache:
        cached = _port_status_cache[router_id]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _PORT_CACHE_TTL:
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "dual_ports": router_obj.dual_ports or [],
    }
    await db.commit()
    result = await asyncio.to_thread(_get_port_status_sync, router_info)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "router_ports")
        if router_id in _port_status_cache:
            stale = _port_status_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "router_ports")

    # Auto-correct DB to match the router reality so retries start clean
    actual_pppoe = sorted(p["port"] for p in result["ports"] if p["service"] == "pppoe")
    actual_plain = sorted(p["port"] for p in result["ports"] if p["service"] == "plain")
    actual_dual = sorted(p["port"] for p in result["ports"] if p["service"] == "dual")
    db_pppoe = sorted(router_obj.pppoe_ports or [])
    db_plain = sorted(router_obj.plain_ports or [])
    db_dual = sorted(router_obj.dual_ports or [])
    db_corrected = False
    corrections = []
    if actual_pppoe != db_pppoe:
        router_obj.pppoe_ports = actual_pppoe if actual_pppoe else None
        db_corrected = True
        corrections.append(f"pppoe_ports: {db_pppoe} -> {actual_pppoe}")
    if actual_plain != db_plain:
        router_obj.plain_ports = actual_plain if actual_plain else None
        db_corrected = True
        corrections.append(f"plain_ports: {db_plain} -> {actual_plain}")
    if actual_dual != db_dual:
        router_obj.dual_ports = actual_dual if actual_dual else None
        db_corrected = True
        corrections.append(f"dual_ports: {db_dual} -> {actual_dual}")
    if db_corrected:
        await db.commit()
        logger.warning(
            f"Router {router_id}: corrected port config to match router reality: "
            + "; ".join(corrections)
        )

    response = {
        "router_id": router_id,
        "router_name": router_obj.name,
        "pppoe_ports": actual_pppoe,
        "plain_ports": actual_plain,
        "dual_ports": actual_dual,
        "generated_at": datetime.utcnow().isoformat(),
        "cached": False,
        "ports": result["ports"],
        "bridges": result["bridges"],
        "has_hotspot_bridge_pppoe": result.get("has_hotspot_bridge_pppoe", False),
    }

    if db_corrected:
        response["db_corrected"] = True
        response["correction_detail"] = (
            f"Database was out of sync with router. Corrections: {'; '.join(corrections)}"
        )

    _port_status_cache[router_id] = {
        "data": response,
        "timestamp": datetime.utcnow(),
    }

    return response


# =========================================================================
# PPPoE PORT CONFIGURATION
# =========================================================================

def _get_ethernet_interfaces_sync(router_info: dict) -> dict:
    """Fetch ethernet interfaces from the router (sync, runs in thread pool)."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        return api.get_ethernet_interfaces()
    finally:
        api.disconnect()


@router.get("/api/routers/{router_id}/interfaces")
async def get_router_interfaces(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get available ethernet interfaces from the router (excludes ether1/WAN)."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(_get_ethernet_interfaces_sync, router_info)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "router_interfaces")
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "router_interfaces")

    return {
        "interfaces": result.get("data", []),
        "pppoe_ports": router_obj.pppoe_ports or [],
        "plain_ports": router_obj.plain_ports or [],
        "dual_ports": router_obj.dual_ports or [],
    }


class ApplyAccessDefaultsRequest(BaseModel):
    pppoe: bool = True
    hotspot: bool = True


class RebootRouterRequest(BaseModel):
    confirm: bool = False
    reason: Optional[str] = None


def _apply_access_defaults_sync(
    router_info: dict,
    include_pppoe: bool = True,
    include_hotspot: bool = True,
) -> dict:
    """Apply reconnect-safe defaults to existing access services on one router."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=20,
        connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connect_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        return api.apply_access_reconnect_defaults(
            include_pppoe=include_pppoe,
            include_hotspot=include_hotspot,
        )
    finally:
        api.disconnect()


def _reboot_router_sync(router_info: dict) -> dict:
    """Send a remote reboot command to a router."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=8,
        connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connect_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        return api.reboot_router()
    finally:
        api.disconnect()


@router.post("/api/routers/{router_id}/apply-access-defaults")
async def apply_access_defaults(
    router_id: int,
    request: Optional[ApplyAccessDefaultsRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Apply safe PPPoE/hotspot reconnect defaults without changing ports/users."""
    request = request or ApplyAccessDefaultsRequest()
    if not request.pppoe and not request.hotspot:
        raise HTTPException(status_code=400, detail="At least one of pppoe or hotspot must be true")

    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()

    result = await run_with_guard(
        router_id,
        _apply_access_defaults_sync,
        router_info,
        request.pppoe,
        request.hotspot,
        timeout_seconds=35,
    )

    if result.get("error") == "busy":
        raise HTTPException(status_code=429, detail=result.get("detail", "Router operation slots are busy"))
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "apply_access_defaults")
        raise HTTPException(status_code=504, detail=result.get("detail", "Router operation timed out"))
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "apply_access_defaults")
        raise HTTPException(
            status_code=503,
            detail=result.get("message", f"Failed to connect to router: {router_obj.name}"),
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "apply_access_defaults")
    _port_status_cache.pop(router_id, None)

    return {
        "success": bool(result.get("success", True)),
        "router_id": router_id,
        "router_name": router_obj.name,
        "applied": {
            "pppoe": request.pppoe,
            "hotspot": request.hotspot,
        },
        "result": result,
        "message": "Access defaults applied to router",
    }


@router.post("/api/routers/{router_id}/reboot")
async def reboot_router(
    router_id: int,
    request: Optional[RebootRouterRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Remotely reboot an owned MikroTik router."""
    request = request or RebootRouterRequest()
    if not request.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to reboot this router")

    reason = (request.reason or "").strip() or None
    if reason and len(reason) > 500:
        raise HTTPException(status_code=400, detail="Reason must be 500 characters or less")

    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()

    result = await run_with_guard(
        router_id,
        _reboot_router_sync,
        router_info,
        acquire_timeout_seconds=5,
        timeout_seconds=20,
    )

    if result.get("error") == "busy":
        raise HTTPException(status_code=429, detail=result.get("detail", "Router operation slots are busy"))
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "router_reboot")
        raise HTTPException(status_code=504, detail=result.get("detail", "Router reboot timed out"))
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "router_reboot")
        raise HTTPException(
            status_code=503,
            detail=result.get("message", f"Failed to connect to router: {router_obj.name}"),
        )
    if result.get("error") == "command_failed":
        await record_router_availability(db, router_id, True, "router_reboot")
        raise HTTPException(
            status_code=502,
            detail=result.get("message", "Router rejected reboot command"),
        )
    if result.get("error"):
        await record_router_availability(db, router_id, False, "router_reboot")
        raise HTTPException(status_code=500, detail=result.get("message") or result["error"])

    await record_router_availability(db, router_id, True, "router_reboot")

    logger.info(
        "Remote reboot sent for router %s (id=%s) by user_id=%s%s",
        router_obj.name,
        router_id,
        user.id,
        f"; reason={reason}" if reason else "",
    )

    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_obj.name,
        "status": result.get("status", "accepted"),
        "command_sent": bool(result.get("command_sent", True)),
        "connection_closed": bool(result.get("connection_closed", False)),
        "message": result.get("message", "Reboot command sent to router"),
        "reason": reason,
        "requested_at": datetime.utcnow().isoformat(),
    }


class SetPPPoEPortsRequest(BaseModel):
    ports: List[str]


def _apply_pppoe_ports_sync(
    router_info: dict,
    new_ports: list,
    old_ports: list,
    plain_ports_to_remove: list = None,
    current_plain_ports: list = None,
    dual_ports_to_remove: list = None,
    current_dual_ports: list = None,
) -> dict:
    """Apply PPPoE port configuration to the live router (sync, runs in thread pool).
    When plain_ports_to_remove is provided, tears down those plain ports first
    within the same connection to avoid a second connect/disconnect cycle."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=30,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        target_ports = list(dict.fromkeys(new_ports or []))
        remaining_dual_after_request = [
            p for p in (current_dual_ports or [])
            if p not in (dual_ports_to_remove or [])
        ]

        # Cross-mode migration: tear down plain on overlapping ports first.
        if plain_ports_to_remove:
            remaining_plain = [p for p in (current_plain_ports or []) if p not in plain_ports_to_remove]
            restore_result = api.restore_ports_from_plain(plain_ports_to_remove, hotspot_bridge="bridge")
            if restore_result.get("error"):
                return {"error": f"Failed to remove plain before PPPoE setup: {restore_result['error']}"}
            if not remaining_plain:
                api.teardown_plain_infrastructure(ports_to_restore=[])

        # Cross-mode migration: restore overlapping dual ports before direct PPPoE setup.
        if dual_ports_to_remove:
            remaining_dual = [p for p in (current_dual_ports or []) if p not in dual_ports_to_remove]
            restore_result = api.restore_ports_from_dual(dual_ports_to_remove, hotspot_bridge="bridge")
            if restore_result.get("error"):
                return {"error": f"Failed to remove dual before PPPoE setup: {restore_result['error']}"}
            if not remaining_dual:
                dual_teardown = api.teardown_dual_infrastructure(
                    hotspot_bridge="bridge",
                    ports_to_restore=[],
                )
                if dual_teardown.get("error"):
                    return {"error": f"Failed to tear down dual infrastructure: {dual_teardown['error']}"}

        current_state = api.get_pppoe_access_state()
        if current_state.get("error"):
            return {
                "error": (
                    f"Failed to read current PPPoE access state before applying "
                    f"changes: {current_state['error']}"
                ),
                "current_ports": old_ports,
            }

        current_ports = set(current_state.get("ports", []))
        current_ports.update(current_state.get("legacy_bridge_members", []))
        current_ports = sorted(current_ports)
        ports_to_restore = [p for p in current_ports if p not in target_ports]

        # Clearing PPPoE entirely: restore actual current PPPoE ports and remove infra.
        if not target_ports:
            if current_ports:
                teardown = api.teardown_pppoe_infrastructure(
                    ports_to_restore=current_ports,
                    remove_shared_resources=not bool(remaining_dual_after_request),
                )
                if teardown.get("error"):
                    teardown["current_ports"] = current_ports
                    return teardown

                verify = api.verify_port_bridges(
                    {p: "bridge" for p in current_ports}, retries=3, delay=0.3,
                )
                if verify.get("error"):
                    return {
                        "error": (
                            f"PPPoE teardown commands ran but ports may not have restored: "
                            f"{verify['error']}"
                        ),
                        "failed_ports": verify.get("failed_ports", []),
                        "current_ports": current_ports,
                    }

            return {
                "success": True,
                "message": "PPPoE ports cleared, all ports restored to hotspot bridge",
                "current_ports": current_ports,
                "plain_migrated": bool(plain_ports_to_remove),
            }

        # Restore ports no longer requested without tearing down the shared PPPoE infra.
        restore_result = api.restore_ports_from_pppoe(
            ports_to_restore,
            hotspot_bridge="bridge",
            current_state=current_state,
        )
        if restore_result.get("error"):
            return {
                "error": restore_result["error"],
                "current_ports": current_ports,
            }

        # Set up or migrate the requested ports to the direct-interface PPPoE layout.
        setup_result = api.setup_pppoe_infrastructure(
            pppoe_ports=target_ports,
            current_state=current_state,
        )
        if setup_result.get("error"):
            setup_result["current_ports"] = current_ports
            return setup_result

        setup_mode = setup_result.get("mode", "direct")

        if setup_mode == "legacy_bridge":
            expected_bridges = {p: "bridge-pppoe" for p in target_ports}
            expected_bridges.update({p: "bridge" for p in ports_to_restore})
            verify = api.verify_port_bridges(expected_bridges, retries=3, delay=0.3)
            if verify.get("error"):
                failed = verify.get("failed_ports", [])
                details = "; ".join(
                    f"{f['port']} is still in '{f['actual_bridge']}' (expected '{f['expected_bridge']}')"
                    for f in failed
                ) if failed else verify["error"]
                return {
                    "error": (
                        f"The router accepted the commands but the final bridge layout "
                        f"does not match the requested PPPoE configuration. {details}. "
                        f"This may indicate the router applied the change slowly or partially."
                    ),
                    "failed_ports": failed,
                    "current_ports": current_ports,
                }
        else:
            final_state = setup_result.get("access_state") or api.get_pppoe_access_state()
            if final_state.get("error"):
                return {
                    "error": (
                        f"The router accepted the commands but the final PPPoE access "
                        f"state could not be verified. {final_state['error']}"
                    ),
                    "current_ports": current_ports,
                }

            final_direct_ports = set(final_state.get("direct_ports", []))
            final_all_ports = set(final_state.get("ports", []))
            final_bridge_map = final_state.get("bridge_map", {})
            failed = []
            for port in target_ports:
                if port not in final_direct_ports:
                    attachment = final_state.get("attachment_map", {}).get(port, {})
                    failed.append({
                        "port": port,
                        "expected_mode": "direct",
                        "actual_mode": attachment.get("mode", "none"),
                        "server_interface": attachment.get("server_interface", ""),
                    })
                actual_bridge = final_bridge_map.get(port)
                if actual_bridge:
                    failed.append({
                        "port": port,
                        "expected_mode": "direct_unbridged",
                        "actual_mode": f"bridge:{actual_bridge}",
                        "server_interface": final_state.get("attachment_map", {}).get(port, {}).get("server_interface", ""),
                    })
            for port in ports_to_restore:
                if port in final_all_ports:
                    attachment = final_state.get("attachment_map", {}).get(port, {})
                    failed.append({
                        "port": port,
                        "expected_mode": "restored_to_bridge",
                        "actual_mode": attachment.get("mode", "pppoe"),
                        "server_interface": attachment.get("server_interface", ""),
                    })

            bridge_verify = (
                api.verify_port_bridges({p: "bridge" for p in ports_to_restore}, retries=3, delay=0.3)
                if ports_to_restore else {"success": True}
            )
            if failed or bridge_verify.get("error"):
                bridge_failed = bridge_verify.get("failed_ports", [])
                if bridge_failed:
                    failed.extend(bridge_failed)
                details = "; ".join(
                    f"{f['port']} did not reach expected state"
                    for f in failed
                ) if failed else bridge_verify.get("error", "verification failed")
                return {
                    "error": (
                        f"The router accepted the commands but the final PPPoE/direct-port "
                        f"layout does not match the requested configuration. {details}. "
                        f"This may indicate the router applied the change slowly or partially."
                    ),
                    "failed_ports": failed,
                    "current_ports": current_ports,
                }

        setup_result["current_ports"] = current_ports
        setup_result["plain_migrated"] = bool(plain_ports_to_remove)
        setup_result["dual_migrated"] = bool(dual_ports_to_remove)
        return setup_result
    finally:
        api.disconnect()


@router.put("/api/routers/{router_id}/pppoe-ports")
async def set_pppoe_ports(
    router_id: int,
    request: SetPPPoEPortsRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Configure which ethernet ports are dedicated to PPPoE.
    Removes selected ports from the hotspot bridge and binds PPPoE directly to
    those interfaces while keeping the frontend contract unchanged.
    Pass an empty list to remove PPPoE and restore all ports to hotspot.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    # Validate: ether1 cannot be assigned to PPPoE
    for port in request.ports:
        if port == "ether1":
            raise HTTPException(status_code=400, detail="ether1 is the WAN port and cannot be used for PPPoE")

    # Detect plain overlap so we can auto-migrate in a single connection
    current_plain = list(router_obj.plain_ports or [])
    plain_overlap = set(current_plain).intersection(request.ports)
    plain_ports_to_remove = sorted(plain_overlap) if plain_overlap else None

    # Detect dual overlap — ports move from dual to dedicated PPPoE
    current_dual = list(router_obj.dual_ports or [])
    dual_overlap = set(current_dual).intersection(request.ports)

    old_ports = router_obj.pppoe_ports or []
    new_ports = request.ports

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    started_at = time.perf_counter()
    await db.commit()
    result = await _run_locked_router_thread(
        router_obj,
        _apply_pppoe_ports_sync,
        router_info,
        new_ports,
        old_ports,
        plain_ports_to_remove=plain_ports_to_remove,
        current_plain_ports=current_plain,
        dual_ports_to_remove=sorted(dual_overlap) if dual_overlap else None,
        current_dual_ports=current_dual,
    )
    logger.info(
        "PPPoE port sync for router %s completed in %.2fs (requested=%s)",
        router_id,
        time.perf_counter() - started_at,
        ",".join(new_ports) if new_ports else "(none)",
    )

    # Update plain_ports in DB if cross-migration happened
    updated_plain = None
    if plain_overlap and not result.get("error"):
        remaining_plain = [p for p in current_plain if p not in plain_overlap]
        updated_plain = remaining_plain if remaining_plain else None
        router_obj.plain_ports = updated_plain
        logger.info(
            "Router %s: auto-migrated ports %s from plain to PPPoE",
            router_id, sorted(plain_overlap),
        )

    # Update dual_ports in DB if cross-migration happened
    if dual_overlap and not result.get("error"):
        remaining_dual = [p for p in current_dual if p not in dual_overlap]
        router_obj.dual_ports = remaining_dual if remaining_dual else None
        logger.info(
            "Router %s: auto-migrated ports %s from dual to dedicated PPPoE",
            router_id, sorted(dual_overlap),
        )

    # Invalidate port status cache so the next GET reflects reality
    _port_status_cache.pop(router_id, None)

    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    if result.get("error"):
        failed_ports = result.get("failed_ports", [])
        detail = {
            "message": result["error"],
            "failed_ports": failed_ports,
            "pppoe_ports_unchanged": result.get("current_ports", old_ports),
        }
        if result.get("partial_errors"):
            detail["partial_errors"] = result.get("partial_errors", [])
        raise HTTPException(status_code=500, detail=detail)

    # Only persist to DB after the router confirmed the change
    router_obj.pppoe_ports = new_ports if new_ports else None
    await db.commit()

    resp = {
        "success": True,
        "router_id": router_id,
        "pppoe_ports": new_ports,
        "warnings": result.get("warnings", []),
        "message": f"PPPoE ports configured: {', '.join(new_ports)}" if new_ports else "PPPoE ports cleared",
    }
    if plain_overlap:
        resp["migrated_from_plain"] = sorted(plain_overlap)
        resp["plain_ports"] = updated_plain
    if dual_overlap:
        resp["migrated_from_dual"] = sorted(dual_overlap)
        resp["dual_ports"] = router_obj.dual_ports
    return resp


# =========================================================================
# PLAIN (NO-AUTH) PORT CONFIGURATION
# =========================================================================

class SetPlainPortsRequest(BaseModel):
    ports: List[str]


def _apply_plain_ports_sync(
    router_info: dict,
    new_ports: list,
    old_ports: list,
    pppoe_ports_to_remove: list = None,
    current_pppoe_ports: list = None,
    dual_ports_to_remove: list = None,
    current_dual_ports: list = None,
) -> dict:
    """Apply plain port configuration to the live router (sync, runs in thread pool).
    When pppoe_ports_to_remove is provided, tears down those PPPoE ports first
    within the same connection to avoid a second connect/disconnect cycle."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=30,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        target_ports = list(dict.fromkeys(new_ports or []))

        # Cross-mode migration: tear down PPPoE on overlapping ports first.
        if pppoe_ports_to_remove:
            remaining_pppoe = [p for p in (current_pppoe_ports or []) if p not in pppoe_ports_to_remove]
            remaining_dual = [
                p for p in (current_dual_ports or [])
                if p not in (dual_ports_to_remove or [])
            ]
            current_state = api.get_pppoe_access_state()
            if not current_state.get("error"):
                restore = api.restore_ports_from_pppoe(
                    pppoe_ports_to_remove, hotspot_bridge="bridge", current_state=current_state,
                )
                if restore.get("error"):
                    return {"error": f"Failed to remove PPPoE before plain setup: {restore['error']}"}
                if not remaining_pppoe:
                    api.teardown_pppoe_infrastructure(
                        ports_to_restore=[],
                        remove_shared_resources=not bool(remaining_dual),
                    )
            else:
                return {"error": f"Failed to read PPPoE state: {current_state['error']}"}

        # Cross-mode migration: restore overlapping dual ports before plain setup.
        if dual_ports_to_remove:
            remaining_dual = [p for p in (current_dual_ports or []) if p not in dual_ports_to_remove]
            restore_result = api.restore_ports_from_dual(dual_ports_to_remove, hotspot_bridge="bridge")
            if restore_result.get("error"):
                return {"error": f"Failed to remove dual before plain setup: {restore_result['error']}"}
            if not remaining_dual:
                dual_teardown = api.teardown_dual_infrastructure(
                    hotspot_bridge="bridge",
                    ports_to_restore=[],
                )
                if dual_teardown.get("error"):
                    return {"error": f"Failed to tear down dual infrastructure: {dual_teardown['error']}"}

        # Clearing plain ports entirely: restore and tear down infra.
        if not target_ports:
            if old_ports:
                teardown = api.teardown_plain_infrastructure(ports_to_restore=old_ports)
                if teardown.get("error"):
                    teardown["current_ports"] = old_ports
                    return teardown

                verify = api.verify_port_bridges(
                    {p: "bridge" for p in old_ports}, retries=3, delay=0.3,
                )
                if verify.get("error"):
                    return {
                        "error": (
                            f"Plain teardown commands ran but ports may not have restored: "
                            f"{verify['error']}"
                        ),
                        "failed_ports": verify.get("failed_ports", []),
                        "current_ports": old_ports,
                    }

            return {
                "success": True,
                "message": "Plain ports cleared, all ports restored to hotspot bridge",
                "current_ports": old_ports,
                "pppoe_migrated": bool(pppoe_ports_to_remove),
            }

        # Restore ports no longer requested back to hotspot bridge.
        ports_to_restore = [p for p in (old_ports or []) if p not in target_ports]
        if ports_to_restore:
            restore_result = api.restore_ports_from_plain(ports_to_restore, hotspot_bridge="bridge")
            if restore_result.get("error"):
                return {"error": restore_result["error"], "current_ports": old_ports}

        # Set up or extend plain infrastructure for the requested ports.
        setup_result = api.setup_plain_infrastructure(plain_ports=target_ports)
        if setup_result.get("error"):
            setup_result["current_ports"] = old_ports
            return setup_result

        # Verify ports landed in the correct bridge.
        expected = {p: "bridge-plain" for p in target_ports}
        if ports_to_restore:
            expected.update({p: "bridge" for p in ports_to_restore})
        verify = api.verify_port_bridges(expected, retries=3, delay=0.3)
        if verify.get("error"):
            failed = verify.get("failed_ports", [])
            details = "; ".join(
                f"{f['port']} is in '{f['actual_bridge']}' (expected '{f['expected_bridge']}')"
                for f in failed
            ) if failed else verify["error"]
            return {
                "error": (
                    f"Plain port commands ran but bridge layout doesn't match: {details}. "
                    f"The router may have applied the change slowly or partially."
                ),
                "failed_ports": failed,
                "current_ports": old_ports,
            }

        return {
            "success": True,
            "message": f"Plain ports configured: {', '.join(target_ports)}",
            "current_ports": target_ports,
            "warnings": setup_result.get("warnings", []),
            "pppoe_migrated": bool(pppoe_ports_to_remove),
            "dual_migrated": bool(dual_ports_to_remove),
        }
    finally:
        api.disconnect()


@router.put("/api/routers/{router_id}/plain-ports")
async def set_plain_ports(
    router_id: int,
    request: SetPlainPortsRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Configure which ethernet ports run in plain (no-auth) mode.
    Ports are moved to a dedicated bridge with DHCP and NAT but no hotspot
    or PPPoE, so clients get internet immediately without authentication.
    Pass an empty list to remove plain mode and restore all ports to hotspot.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    for port in request.ports:
        if port == "ether1":
            raise HTTPException(status_code=400, detail="ether1 is the WAN port and cannot be used for plain mode")

    # Detect PPPoE overlap so we can auto-migrate in a single connection
    current_pppoe = list(router_obj.pppoe_ports or [])
    pppoe_overlap = set(current_pppoe).intersection(request.ports)
    pppoe_ports_to_remove = sorted(pppoe_overlap) if pppoe_overlap else None

    # Detect dual overlap — ports move from dual to plain
    current_dual = list(router_obj.dual_ports or [])
    dual_overlap = set(current_dual).intersection(request.ports)

    old_ports = router_obj.plain_ports or []
    new_ports = request.ports

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    started_at = time.perf_counter()
    await db.commit()
    result = await _run_locked_router_thread(
        router_obj,
        _apply_plain_ports_sync,
        router_info,
        new_ports,
        old_ports,
        pppoe_ports_to_remove=pppoe_ports_to_remove,
        current_pppoe_ports=current_pppoe,
        dual_ports_to_remove=sorted(dual_overlap) if dual_overlap else None,
        current_dual_ports=current_dual,
    )
    logger.info(
        "Plain port sync for router %s completed in %.2fs (requested=%s)",
        router_id,
        time.perf_counter() - started_at,
        ",".join(new_ports) if new_ports else "(none)",
    )

    # Update PPPoE in DB if cross-migration happened
    updated_pppoe = None
    if pppoe_overlap and not result.get("error"):
        remaining_pppoe = [p for p in current_pppoe if p not in pppoe_overlap]
        updated_pppoe = remaining_pppoe if remaining_pppoe else None
        router_obj.pppoe_ports = updated_pppoe
        logger.info(
            "Router %s: auto-migrated ports %s from PPPoE to plain",
            router_id, sorted(pppoe_overlap),
        )

    # Update dual_ports in DB if cross-migration happened
    if dual_overlap and not result.get("error"):
        remaining_dual = [p for p in current_dual if p not in dual_overlap]
        router_obj.dual_ports = remaining_dual if remaining_dual else None
        logger.info(
            "Router %s: auto-migrated ports %s from dual to plain",
            router_id, sorted(dual_overlap),
        )

    _port_status_cache.pop(router_id, None)

    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    if result.get("error"):
        failed_ports = result.get("failed_ports", [])
        detail = {
            "message": result["error"],
            "failed_ports": failed_ports,
            "plain_ports_unchanged": result.get("current_ports", old_ports),
        }
        if result.get("partial_errors"):
            detail["partial_errors"] = result.get("partial_errors", [])
        raise HTTPException(status_code=500, detail=detail)

    router_obj.plain_ports = new_ports if new_ports else None
    await db.commit()

    resp = {
        "success": True,
        "router_id": router_id,
        "plain_ports": new_ports,
        "warnings": result.get("warnings", []),
        "message": f"Plain ports configured: {', '.join(new_ports)}" if new_ports else "Plain ports cleared",
    }
    if pppoe_overlap:
        resp["migrated_from_pppoe"] = sorted(pppoe_overlap)
        resp["pppoe_ports"] = updated_pppoe
    if dual_overlap:
        resp["migrated_from_dual"] = sorted(dual_overlap)
        resp["dual_ports"] = router_obj.dual_ports
    return resp


# =========================================================================
# DUAL-MODE (PPPoE + HOTSPOT) PORT CONFIGURATION
# =========================================================================

class SetDualPortsRequest(BaseModel):
    ports: List[str]
    repair_hotspot: Optional[bool] = None


class HealDualModeRequest(BaseModel):
    ports: Optional[List[str]] = None
    apply_access_defaults: bool = True


async def _router_login_fetch_options(db: AsyncSession, router_id: int) -> dict:
    """Build the RouterOS /tool fetch options for this router's login page."""
    pt_result = await db.execute(
        select(ProvisioningToken)
        .where(ProvisioningToken.router_id == router_id)
        .order_by(ProvisioningToken.created_at.desc())
    )
    token_obj = pt_result.scalars().first()
    if not token_obj:
        return {
            "login_page_url": None,
            "fetch_check_certificate": False,
            "provisioning_token_found": False,
        }

    base_url = provision_base_url_for_vpn(token_obj.vpn_type)
    login_page_url = f"{base_url}/api/provision/{token_obj.token}/login-page"
    cert_flag = fetch_certificate_flag_for_url(login_page_url, token_obj.vpn_type)
    return {
        "login_page_url": login_page_url,
        "fetch_check_certificate": "check-certificate=no" in cert_flag,
        "provisioning_token_found": True,
    }


def _apply_dual_ports_sync(
    router_info: dict,
    new_ports: list,
    old_ports: list,
    pppoe_ports_to_remove: list = None,
    current_pppoe_ports: list = None,
    plain_ports_to_remove: list = None,
    current_plain_ports: list = None,
    repair_hotspot: bool = True,
) -> dict:
    """Apply dual-mode port configuration to the live router (sync, runs in thread pool).

    Dual-mode keeps selected ports on the normal hotspot bridge and runs a
    PPPoE server on that same bridge. Cross-mode migrations from PPPoE or plain
    are handled within the same connection to avoid extra connect/disconnect cycles.
    """
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=30,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        target_ports = list(dict.fromkeys(new_ports or []))

        # Cross-mode: tear down dedicated PPPoE on overlapping ports first.
        if pppoe_ports_to_remove:
            remaining_pppoe = [p for p in (current_pppoe_ports or []) if p not in pppoe_ports_to_remove]
            current_state = api.get_pppoe_access_state()
            if not current_state.get("error"):
                restore = api.restore_ports_from_pppoe(
                    pppoe_ports_to_remove, hotspot_bridge="bridge", current_state=current_state,
                )
                if restore.get("error"):
                    return {"error": f"Failed to remove PPPoE before dual setup: {restore['error']}"}
                if not remaining_pppoe:
                    api.teardown_pppoe_infrastructure(
                        ports_to_restore=[],
                        remove_shared_resources=not bool(target_ports),
                    )
            else:
                return {"error": f"Failed to read PPPoE state: {current_state['error']}"}

        # Cross-mode: tear down plain on overlapping ports first.
        if plain_ports_to_remove:
            remaining_plain = [p for p in (current_plain_ports or []) if p not in plain_ports_to_remove]
            restore_result = api.restore_ports_from_plain(plain_ports_to_remove, hotspot_bridge="bridge")
            if restore_result.get("error"):
                return {"error": f"Failed to remove plain before dual setup: {restore_result['error']}"}
            if not remaining_plain:
                api.teardown_plain_infrastructure(ports_to_restore=[])

        # Clearing dual ports entirely: remove the PPPoE server from the bridge.
        if not target_ports:
            if old_ports:
                teardown = api.teardown_dual_infrastructure(
                    hotspot_bridge="bridge",
                    ports_to_restore=old_ports,
                )
                if teardown.get("error"):
                    return {"error": teardown["error"], "current_ports": old_ports}

            return {
                "success": True,
                "message": "Dual ports cleared, all ports reverted to hotspot-only",
                "current_ports": old_ports,
                "pppoe_migrated": bool(pppoe_ports_to_remove),
                "plain_migrated": bool(plain_ports_to_remove),
            }

        # Set up or ensure the dual-mode PPPoE server on the hotspot bridge.
        setup_result = api.setup_dual_infrastructure(
            dual_ports=target_ports,
            login_page_url=router_info.get("login_page_url"),
            fetch_check_certificate=bool(router_info.get("fetch_check_certificate")),
            repair_hotspot=repair_hotspot,
        )
        if setup_result.get("error"):
            setup_result["current_ports"] = old_ports
            return setup_result

        setup_result["current_ports"] = target_ports
        setup_result["pppoe_migrated"] = bool(pppoe_ports_to_remove)
        setup_result["plain_migrated"] = bool(plain_ports_to_remove)
        return setup_result
    finally:
        api.disconnect()


@router.put("/api/routers/{router_id}/dual-ports")
async def set_dual_ports(
    router_id: int,
    request: SetDualPortsRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Configure which ethernet ports run in dual mode (PPPoE + Hotspot).
    Selected ports stay on the normal hotspot bridge while a PPPoE server is
    enabled on that same bridge, so PPPoE clients get a PPP session and
    non-PPPoE clients hit the hotspot captive portal.
    Pass an empty list to remove dual mode and revert to hotspot-only.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    for port in request.ports:
        if port == "ether1":
            raise HTTPException(
                status_code=400,
                detail="ether1 is the WAN port and cannot be used for dual mode",
            )

    # Detect PPPoE overlap so we can auto-migrate in a single connection
    current_pppoe = list(router_obj.pppoe_ports or [])
    pppoe_overlap = set(current_pppoe).intersection(request.ports)
    pppoe_ports_to_remove = sorted(pppoe_overlap) if pppoe_overlap else None

    # Detect plain overlap
    current_plain = list(router_obj.plain_ports or [])
    plain_overlap = set(current_plain).intersection(request.ports)
    plain_ports_to_remove = sorted(plain_overlap) if plain_overlap else None

    old_ports = router_obj.dual_ports or []
    new_ports = request.ports

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    router_info.update(await _router_login_fetch_options(db, router_id))
    repair_hotspot = (
        request.repair_hotspot
        if request.repair_hotspot is not None
        else bool(not old_ports or pppoe_overlap or plain_overlap)
    )
    started_at = time.perf_counter()
    await db.commit()
    result = await _run_locked_router_thread(
        router_obj,
        _apply_dual_ports_sync,
        router_info,
        new_ports,
        old_ports,
        pppoe_ports_to_remove=pppoe_ports_to_remove,
        current_pppoe_ports=current_pppoe,
        plain_ports_to_remove=plain_ports_to_remove,
        current_plain_ports=current_plain,
        repair_hotspot=repair_hotspot,
    )
    logger.info(
        "Dual port sync for router %s completed in %.2fs (requested=%s)",
        router_id,
        time.perf_counter() - started_at,
        ",".join(new_ports) if new_ports else "(none)",
    )

    # Update PPPoE in DB if cross-migration happened
    if pppoe_overlap and not result.get("error"):
        remaining_pppoe = [p for p in current_pppoe if p not in pppoe_overlap]
        router_obj.pppoe_ports = remaining_pppoe if remaining_pppoe else None
        logger.info(
            "Router %s: auto-migrated ports %s from PPPoE to dual",
            router_id, sorted(pppoe_overlap),
        )

    # Update plain in DB if cross-migration happened
    if plain_overlap and not result.get("error"):
        remaining_plain = [p for p in current_plain if p not in plain_overlap]
        router_obj.plain_ports = remaining_plain if remaining_plain else None
        logger.info(
            "Router %s: auto-migrated ports %s from plain to dual",
            router_id, sorted(plain_overlap),
        )

    _port_status_cache.pop(router_id, None)

    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_obj.name}")
    if result.get("error"):
        detail = {
            "message": result["error"],
            "dual_ports_unchanged": result.get("current_ports", old_ports),
        }
        if result.get("partial_errors"):
            detail["partial_errors"] = result.get("partial_errors", [])
        raise HTTPException(status_code=500, detail=detail)

    router_obj.dual_ports = new_ports if new_ports else None
    await db.commit()

    resp = {
        "success": True,
        "router_id": router_id,
        "dual_ports": new_ports,
        "warnings": result.get("warnings", []),
        "message": (
            f"Dual ports configured: {', '.join(new_ports)}"
            if new_ports
            else "Dual ports cleared"
        ),
    }
    if pppoe_overlap:
        resp["migrated_from_pppoe"] = sorted(pppoe_overlap)
        resp["pppoe_ports"] = router_obj.pppoe_ports
    if plain_overlap:
        resp["migrated_from_plain"] = sorted(plain_overlap)
        resp["plain_ports"] = router_obj.plain_ports
    return resp


def _heal_dual_mode_sync(
    router_info: dict,
    requested_ports: Optional[list] = None,
    apply_defaults: bool = True,
) -> dict:
    """Repair legacy dual-mode layout in one MikroTik API session."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=35,
        connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connect_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }

    try:
        bridge_data = api.get_bridge_ports_status()
        if bridge_data.get("error"):
            return {"error": f"Could not read bridge ports: {bridge_data['error']}"}

        bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []
        bridge_map = {
            port.get("interface", ""): port.get("bridge", "")
            for port in bridge_ports
        }
        legacy_bridge_dual_ports = sorted(
            port for port, bridge in bridge_map.items()
            if bridge == "bridge-dual"
        )

        if requested_ports is None:
            target_ports = list(dict.fromkeys(
                list(router_info.get("dual_ports") or []) + legacy_bridge_dual_ports
            ))
        else:
            target_ports = list(dict.fromkeys(requested_ports or []))

        if not target_ports:
            access_state = api.get_pppoe_access_state()
            return {
                "success": True,
                "target_ports": [],
                "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
                "has_hotspot_bridge_pppoe": bool(
                    access_state.get("has_hotspot_bridge_pppoe")
                    if access_state.get("success") else False
                ),
                "message": "No dual ports found to heal",
            }

        setup_result = api.setup_dual_infrastructure(
            dual_ports=target_ports,
            login_page_url=router_info.get("login_page_url"),
            fetch_check_certificate=bool(router_info.get("fetch_check_certificate")),
        )
        if setup_result.get("error"):
            setup_result["target_ports"] = target_ports
            setup_result["legacy_bridge_dual_ports"] = legacy_bridge_dual_ports
            return setup_result

        warnings = list(setup_result.get("warnings") or [])
        defaults_result = None
        if apply_defaults:
            defaults_result = api.apply_access_reconnect_defaults(
                include_pppoe=True,
                include_hotspot=True,
            )
            if defaults_result.get("error"):
                warnings.append(f"Access defaults: {defaults_result['error']}")

        final_bridge_data = api.get_bridge_ports_status()
        if final_bridge_data.get("error"):
            return {
                "error": f"Could not verify healed bridge ports: {final_bridge_data['error']}",
                "target_ports": target_ports,
                "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
                "partial_errors": warnings,
            }

        final_bridge_ports = (
            final_bridge_data.get("ports", [])
            if final_bridge_data.get("success") else []
        )
        final_bridge_map = {
            port.get("interface", ""): port.get("bridge", "")
            for port in final_bridge_ports
        }

        failed_ports = []
        for port in target_ports:
            actual_bridge = final_bridge_map.get(port)
            if actual_bridge != "bridge":
                failed_ports.append({
                    "port": port,
                    "expected_bridge": "bridge",
                    "actual_bridge": actual_bridge or "(none)",
                })

        final_access_state = api.get_pppoe_access_state()
        if final_access_state.get("error"):
            return {
                "error": f"Could not verify healed PPPoE state: {final_access_state['error']}",
                "target_ports": target_ports,
                "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
                "failed_ports": failed_ports,
                "partial_errors": warnings,
            }

        if not final_access_state.get("has_hotspot_bridge_pppoe"):
            return {
                "error": "PPPoE server is not active on the hotspot bridge after heal",
                "target_ports": target_ports,
                "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
                "failed_ports": failed_ports,
                "partial_errors": warnings,
            }

        if failed_ports:
            return {
                "error": "One or more dual ports did not return to the hotspot bridge",
                "target_ports": target_ports,
                "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
                "failed_ports": failed_ports,
                "partial_errors": warnings,
            }

        bridge_counts = {}
        for bridge in final_bridge_map.values():
            if bridge:
                bridge_counts[bridge] = bridge_counts.get(bridge, 0) + 1

        return {
            "success": True,
            "target_ports": target_ports,
            "legacy_bridge_dual_ports": legacy_bridge_dual_ports,
            "mode": "shared_hotspot_bridge",
            "has_hotspot_bridge_pppoe": True,
            "warnings": warnings,
            "setup_result": setup_result,
            "defaults_result": defaults_result,
            "bridge_counts": bridge_counts,
        }
    finally:
        api.disconnect()


@router.post("/api/routers/{router_id}/heal-dual-mode")
async def heal_dual_mode(
    router_id: int,
    request: Optional[HealDualModeRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Heal PPPoE + Hotspot dual-mode access without changing billing or passwords.

    This repairs the legacy state where access ports were moved to
    ``bridge-dual``. Healed ports are returned to the normal hotspot ``bridge``
    while PPPoE is enabled on that same bridge.
    """
    request = request or HealDualModeRequest()
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    requested_ports = request.ports
    if requested_ports is not None:
        requested_ports = list(dict.fromkeys(requested_ports))
        for port in requested_ports:
            if port == "ether1":
                raise HTTPException(
                    status_code=400,
                    detail="ether1 is the WAN port and cannot be used for dual mode",
                )

    current_pppoe = list(router_obj.pppoe_ports or [])
    current_plain = list(router_obj.plain_ports or [])
    current_dual = list(router_obj.dual_ports or [])
    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "dual_ports": current_dual,
    }
    router_info.update(await _router_login_fetch_options(db, router_id))

    await db.commit()
    result = await run_with_guard(
        router_id,
        _heal_dual_mode_sync,
        router_info,
        requested_ports,
        request.apply_access_defaults,
        timeout_seconds=55,
    )

    _port_status_cache.pop(router_id, None)

    if result.get("error") == "busy":
        raise HTTPException(status_code=429, detail=result.get("detail", "Router operation slots are busy"))
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "heal_dual_mode")
        raise HTTPException(status_code=504, detail=result.get("detail", "Router operation timed out"))
    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "heal_dual_mode")
        raise HTTPException(
            status_code=503,
            detail=result.get("message", f"Failed to connect to router: {router_obj.name}"),
        )
    if result.get("error"):
        await record_router_availability(db, router_id, False, "heal_dual_mode")
        detail = {
            "message": result["error"],
            "target_ports": result.get("target_ports", []),
            "legacy_bridge_dual_ports": result.get("legacy_bridge_dual_ports", []),
            "failed_ports": result.get("failed_ports", []),
        }
        if result.get("partial_errors"):
            detail["partial_errors"] = result["partial_errors"]
        raise HTTPException(status_code=500, detail=detail)

    healed_ports = list(result.get("target_ports") or [])
    if healed_ports:
        healed_set = set(healed_ports)
        router_obj.dual_ports = healed_ports
        router_obj.pppoe_ports = [p for p in current_pppoe if p not in healed_set] or None
        router_obj.plain_ports = [p for p in current_plain if p not in healed_set] or None
        await db.commit()

    await record_router_availability(db, router_id, True, "heal_dual_mode")

    return {
        "success": True,
        "router_id": router_id,
        "router_name": router_obj.name,
        "dual_ports": healed_ports if healed_ports else current_dual,
        "legacy_bridge_dual_ports": result.get("legacy_bridge_dual_ports", []),
        "mode": result.get("mode"),
        "has_hotspot_bridge_pppoe": result.get("has_hotspot_bridge_pppoe", False),
        "bridge_counts": result.get("bridge_counts", {}),
        "warnings": result.get("warnings", []),
        "defaults_applied": bool(request.apply_access_defaults),
        "message": (
            "Dual mode healed: ports are on hotspot bridge and PPPoE is active on that bridge"
            if healed_ports
            else result.get("message", "No dual ports found to heal")
        ),
    }


# =========================================================================
# PPPoE CUSTOMER WORKBOOK IMPORT
# =========================================================================

def _pppoe_import_report_payload(report, *, success: Optional[bool] = None) -> dict:
    payload = asdict(report)
    payload["success"] = (not report.errors) if success is None else success
    payload["has_errors"] = bool(report.errors)
    return payload


def _parse_package_plan_mapping(package_plan_json: Optional[str]) -> Optional[dict]:
    if not package_plan_json:
        return None
    try:
        raw = json.loads(package_plan_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"package_plan_json must be valid JSON: {exc.msg}",
        ) from exc
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="package_plan_json must be an object")

    out = {}
    for package, plan_id in raw.items():
        try:
            out[str(package)] = int(plan_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid plan id for package '{package}': {plan_id}",
            ) from exc
    return out


@router.post("/api/routers/{router_id}/pppoe-customers/import")
async def import_router_pppoe_customers(
    router_id: int,
    file: UploadFile = File(...),
    sheet: str = Form("Items"),
    apply_changes: bool = Form(False, alias="apply"),
    source_timezone: str = Form("Africa/Nairobi"),
    create_missing_plans: bool = Form(False),
    default_plan_price: int = Form(0),
    reassign_existing: bool = Form(False),
    package_plan_json: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Preview or import PPPoE customers from an exported .xlsx workbook."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    if create_missing_plans and default_plan_price <= 0:
        raise HTTPException(
            status_code=400,
            detail="create_missing_plans requires default_plan_price greater than 0",
        )

    filename = Path(file.filename or "pppoe_customers.xlsx").name
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="Upload an .xlsx workbook")

    package_plan_ids = _parse_package_plan_mapping(package_plan_json)
    await db.commit()

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
            temp_path = tmp.name
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)

        if not temp_path or os.path.getsize(temp_path) == 0:
            raise HTTPException(status_code=400, detail="Uploaded workbook is empty")

        try:
            records = await asyncio.to_thread(read_pppoe_workbook, temp_path, sheet_name=sheet)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Could not read workbook: {type(exc).__name__}: {exc}",
            ) from exc

        rows, parse_report = normalize_workbook_rows(
            records,
            source_timezone=source_timezone,
        )
        if parse_report.errors:
            return {
                "success": False,
                "stage": "parse",
                "router_id": router_id,
                "router_name": router_obj.name,
                "source_file": filename,
                "dry_run": not apply_changes,
                "parse_report": _pppoe_import_report_payload(parse_report, success=False),
            }

        report = await import_pppoe_customers(
            db,
            rows,
            reseller_id=router_obj.user_id,
            router_id=router_id,
            source_file=filename,
            dry_run=not apply_changes,
            create_missing_plans=create_missing_plans,
            default_plan_price=default_plan_price,
            reassign_existing=reassign_existing,
            package_plan_ids=package_plan_ids,
        )

        return {
            "success": not report.errors,
            "stage": "import",
            "router_id": router_id,
            "router_name": router_obj.name,
            "reseller_id": router_obj.user_id,
            "source_file": filename,
            "dry_run": report.dry_run,
            "report": _pppoe_import_report_payload(report),
        }
    finally:
        await file.close()
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning("Could not delete temporary PPPoE import workbook %s", temp_path)


# =========================================================================
# DUAL-PORT HOTSPOT DIAGNOSTIC
# =========================================================================

class DiagnoseDualPortRequest(BaseModel):
    port: Optional[str] = None
    mac_address: Optional[str] = None
    customer_id: Optional[int] = None


def _run_dual_diagnostic_sync(
    router_info: dict,
    port: Optional[str],
    mac_address: Optional[str],
    customer: Optional[dict],
) -> dict:
    """Connect to the router and run the layered hotspot diagnostic."""
    from app.services.dual_port_diagnostic import diagnose_dual_port

    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=20,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        return diagnose_dual_port(api, port=port, mac_address=mac_address, customer=customer)
    except Exception as e:
        logger.exception("Dual-port diagnostic failed: %s", e)
        return {"error": str(e)}
    finally:
        api.disconnect()


@router.post("/api/routers/{router_id}/diagnose/dual-port")
async def diagnose_dual_port_endpoint(
    router_id: int,
    request: DiagnoseDualPortRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Admin diagnostic for a dual-mode (PPPoE + Hotspot) port.

    Walks the dual-bridge stack (bridge, address, DHCP, hotspot profile/server,
    NAT, PPPoE, WAN, port link) and — when a MAC or customer_id is supplied —
    inspects ARP, DHCP lease, hotspot host, ip-binding, active session, queues
    and customer billing state. Every check the BILLING SYSTEM itself causes
    is tagged `system_block: true`, surfaced under `system_blocks`, so you can
    instantly see whether you are blocking the customer's hotspot.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    if request.mac_address and not validate_mac_address(request.mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address")

    customer_payload: Optional[dict] = None
    mac_address = request.mac_address

    if request.customer_id:
        cstmt = (
            select(Customer)
            .where(Customer.id == request.customer_id)
            .options(selectinload(Customer.plan))
        )
        if getattr(user, "role", None) and user.role.value != "admin":
            cstmt = cstmt.where(Customer.user_id == user.id)
        cres = await db.execute(cstmt)
        cust = cres.scalar_one_or_none()
        if not cust:
            raise HTTPException(status_code=404, detail="Customer not found")
        customer_payload = {
            "id": cust.id,
            "name": cust.name,
            "phone": cust.phone,
            "mac_address": cust.mac_address,
            "status": cust.status.value if cust.status else None,
            "expiry": cust.expiry,
            "router_id": cust.router_id,
            "plan": (
                {
                    "id": cust.plan.id,
                    "name": cust.plan.name,
                    "speed": cust.plan.speed,
                    "connection_type": cust.plan.connection_type.value if cust.plan.connection_type else None,
                }
                if cust.plan
                else None
            ),
        }
        if not mac_address and cust.mac_address:
            mac_address = cust.mac_address

    port_warning: Optional[str] = None
    if request.port:
        configured = router_obj.dual_ports or []
        if request.port not in configured:
            port_warning = (
                f"{request.port} is not currently registered as a dual port in our DB "
                f"({configured or 'none'}). Diagnostic will still run against the live router."
            )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(
        _run_dual_diagnostic_sync,
        router_info,
        request.port,
        mac_address,
        customer_payload,
    )

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "diagnose_dual_port")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router: {router_obj.name}",
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "diagnose_dual_port")

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "port": request.port,
        "mac_address": normalize_mac_address(mac_address) if mac_address else None,
        "customer": customer_payload,
        "port_warning": port_warning,
        "configured_dual_ports": router_obj.dual_ports or [],
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


# ---------------------------------------------------------------------------
# Hotspot diagnostics — for investigating "free internet" / captive-portal
# bypass complaints. Returns raw output of the relevant /ip/hotspot/* tables
# plus a `findings` block that flags the usual suspects.
# ---------------------------------------------------------------------------

def _get_hotspot_diagnostics_sync(router_info: dict) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=20,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}

    def _rows(resp):
        if not resp or resp.get("error"):
            return {"error": resp.get("error") if resp else "no response"}
        return resp.get("data", []) or []

    try:
        identity_resp = api.send_command("/system/identity/print")
        hotspot_servers = api.send_command("/ip/hotspot/print")
        server_profiles = api.send_command("/ip/hotspot/profile/print")
        user_profiles = api.send_command("/ip/hotspot/user/profile/print")
        users = api.send_command("/ip/hotspot/user/print")
        ip_bindings = api.send_command("/ip/hotspot/ip-binding/print")
        walled_garden = api.send_command("/ip/hotspot/walled-garden/print")
        walled_garden_ip = api.send_command("/ip/hotspot/walled-garden/ip/print")
        active = api.send_command("/ip/hotspot/active/print")
        hosts = api.send_command("/ip/hotspot/host/print")

        # Limit firewall + NAT to relevant chains to keep payload small
        fw_filter = api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[".id", "chain", "action", "protocol", "dst-port",
                      "src-address", "dst-address", "in-interface",
                      "out-interface", "comment", "disabled", "place-before"],
        )
        fw_nat = api.send_command_optimized(
            "/ip/firewall/nat/print",
            proplist=[".id", "chain", "action", "protocol", "dst-port",
                      "src-address", "dst-address", "to-addresses",
                      "to-ports", "in-interface", "out-interface",
                      "comment", "disabled"],
        )

        # Last hotspot-topic log entries (server-side filtered)
        hotspot_logs = api.send_command_optimized(
            "/log/print",
            proplist=["time", "topics", "message"],
            query="?topics~hotspot",
        )

        identity = ""
        if identity_resp.get("success") and identity_resp.get("data"):
            identity = identity_resp["data"][0].get("name", "")

        servers_rows = _rows(hotspot_servers)
        server_profiles_rows = _rows(server_profiles)
        user_profiles_rows = _rows(user_profiles)
        users_rows = _rows(users)
        bindings_rows = _rows(ip_bindings)
        wg_rows = _rows(walled_garden)
        wg_ip_rows = _rows(walled_garden_ip)
        active_rows = _rows(active)
        hosts_rows = _rows(hosts)
        fw_filter_rows = _rows(fw_filter)
        fw_nat_rows = _rows(fw_nat)
        log_rows = _rows(hotspot_logs)

        # ---- Findings -----------------------------------------------------
        findings = []

        # 1. Hotspot servers: any disabled? bound to a bridge that includes WAN?
        if isinstance(servers_rows, list):
            if not servers_rows:
                findings.append({
                    "severity": "critical",
                    "code": "no_hotspot_server",
                    "message": "No /ip/hotspot server configured — captive portal not running at all.",
                })
            for s in servers_rows:
                if s.get("disabled") == "true" or s.get("invalid") == "true":
                    findings.append({
                        "severity": "critical",
                        "code": "hotspot_server_disabled_or_invalid",
                        "message": f"Hotspot server '{s.get('name','?')}' on interface "
                                   f"'{s.get('interface','?')}' is disabled/invalid.",
                        "row": s,
                    })

        # 2. IP bindings with type=bypassed — these MACs get free internet
        bypassed = [b for b in bindings_rows if isinstance(b, dict) and b.get("type") == "bypassed"]
        if bypassed:
            findings.append({
                "severity": "high",
                "code": "ip_bindings_bypassed",
                "message": f"{len(bypassed)} ip-binding entries with type=bypassed — "
                           f"these MAC/IP combos skip the captive portal entirely.",
                "rows": bypassed[:50],
            })

        # 3. Walled-garden IP rules that whitelist the whole internet
        broad_wg = []
        for r in wg_ip_rows if isinstance(wg_ip_rows, list) else []:
            dst = r.get("dst-address", "")
            action = r.get("action", "")
            if action == "accept" and dst in ("0.0.0.0/0", "", "0.0.0.0/0,::/0"):
                broad_wg.append(r)
        if broad_wg:
            findings.append({
                "severity": "critical",
                "code": "walled_garden_ip_too_broad",
                "message": f"{len(broad_wg)} walled-garden IP rule(s) accept traffic to "
                           f"0.0.0.0/0 — clients can reach anything on those ports without auth.",
                "rows": broad_wg,
            })

        # 4. User profile trial settings that grant generous free access
        loose_trials = []
        for p in user_profiles_rows if isinstance(user_profiles_rows, list) else []:
            uptime = (p.get("trial-uptime-limit") or "").strip()
            if uptime and uptime not in ("0s", "0", ""):
                loose_trials.append(p)
        if loose_trials:
            findings.append({
                "severity": "medium",
                "code": "trial_enabled",
                "message": f"{len(loose_trials)} user-profile(s) have a non-zero trial-uptime-limit "
                           f"— trial users get internet without paying.",
                "rows": loose_trials,
            })

        # 5. Active vs host ratio — many hosts but few authenticated = bypass
        active_count = len(active_rows) if isinstance(active_rows, list) else 0
        host_count = len(hosts_rows) if isinstance(hosts_rows, list) else 0
        unauth_hosts = []
        if isinstance(hosts_rows, list):
            for h in hosts_rows:
                if h.get("authorized") != "true" and h.get("bypassed") != "true":
                    # Unauthenticated hosts that are still passing traffic
                    bytes_in = h.get("bytes-in") or "0"
                    try:
                        if int(bytes_in) > 0:
                            unauth_hosts.append(h)
                    except (TypeError, ValueError):
                        pass
        if unauth_hosts:
            findings.append({
                "severity": "high",
                "code": "unauthenticated_hosts_using_data",
                "message": f"{len(unauth_hosts)} hotspot host(s) are not authorized but have "
                           f"non-zero bytes-in. Traffic is leaking past the portal.",
                "rows": unauth_hosts[:30],
            })

        # 6. Firewall: accept rules in forward chain on auth-required interfaces
        suspicious_fw = []
        for r in fw_filter_rows if isinstance(fw_filter_rows, list) else []:
            if r.get("chain") == "forward" and r.get("action") == "accept" and r.get("disabled") != "true":
                # Anything matching dst-port 443 or with no constraint is suspect
                suspicious_fw.append(r)
        if suspicious_fw:
            findings.append({
                "severity": "info",
                "code": "forward_accept_rules_present",
                "message": f"{len(suspicious_fw)} accept rule(s) in chain=forward — review whether "
                           f"any of them allow client traffic before hotspot's hs-unauth chain runs.",
                "rows": suspicious_fw[:30],
            })

        # Identity mismatch sanity check
        if identity and router_info.get("expected_identity") and identity != router_info["expected_identity"]:
            findings.append({
                "severity": "info",
                "code": "identity_mismatch",
                "message": f"Connected router reports identity '{identity}' but lookup expected "
                           f"'{router_info['expected_identity']}'. Are credentials for the right router?",
            })

        return {
            "success": True,
            "router_identity_live": identity,
            "summary": {
                "hotspot_servers": len(servers_rows) if isinstance(servers_rows, list) else 0,
                "user_profiles": len(user_profiles_rows) if isinstance(user_profiles_rows, list) else 0,
                "hotspot_users": len(users_rows) if isinstance(users_rows, list) else 0,
                "ip_bindings_total": len(bindings_rows) if isinstance(bindings_rows, list) else 0,
                "ip_bindings_bypassed": len(bypassed),
                "walled_garden_domain_rules": len(wg_rows) if isinstance(wg_rows, list) else 0,
                "walled_garden_ip_rules": len(wg_ip_rows) if isinstance(wg_ip_rows, list) else 0,
                "active_sessions": active_count,
                "hosts_total": host_count,
                "hosts_unauth_with_traffic": len(unauth_hosts),
                "forward_accept_rules": len(suspicious_fw),
            },
            "findings": findings,
            "raw": {
                "hotspot_servers": servers_rows,
                "server_profiles": server_profiles_rows,
                "user_profiles": user_profiles_rows,
                "hotspot_users": users_rows,
                "ip_bindings": bindings_rows,
                "walled_garden": wg_rows,
                "walled_garden_ip": wg_ip_rows,
                "active": active_rows,
                "hosts": hosts_rows[:200] if isinstance(hosts_rows, list) else hosts_rows,
                "firewall_filter": fw_filter_rows,
                "firewall_nat": fw_nat_rows,
                "hotspot_log_tail": log_rows[-100:] if isinstance(log_rows, list) else log_rows,
            },
        }
    finally:
        api.disconnect()


@router.get("/api/routers/by-identity/{identity}/hotspot-diagnostics")
async def get_hotspot_diagnostics_by_identity(
    identity: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Investigate a hotspot router by its MikroTik `identity` (e.g. "Router-0305").

    Returns hotspot config + a `findings` block highlighting the likely causes
    of "users get free internet / no transactions" — broad walled-garden IP
    rules, bypassed ip-bindings, trial profiles, unauthorized hosts using
    bandwidth, suspicious forward-chain accept rules, etc.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(
            status_code=404,
            detail=f"No router found for identity/name '{identity}'",
        )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
        "name": router_obj.name,
        "expected_identity": router_obj.identity or router_obj.name,
    }

    await db.commit()
    result = await asyncio.to_thread(_get_hotspot_diagnostics_sync, router_info)

    if result.get("error") == "connection_failed":
        await record_router_availability(
            db, router_obj.id, False, "hotspot_diagnostics"
        )
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {result.get('reason') or 'unknown'}",
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(
        db, router_obj.id, True, "hotspot_diagnostics"
    )

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_identity_db": router_obj.identity,
        "router_ip": router_obj.ip_address,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


# ---------------------------------------------------------------------------
# Device-mode management — RouterOS 7.13+ gates features like `hotspot` and
# `container` behind a configurable device-mode. Changes to a more permissive
# mode require physical confirmation at the router (reset button press or
# power cycle within ~5 min). We can initiate remotely and poll for the
# result; someone on site must finish the physical step.
# ---------------------------------------------------------------------------

ALLOWED_DEVICE_MODES = {"home", "enterprise", "basic"}

# Per-feature flags accepted by /system/device-mode/update on RouterOS 7.13+.
# We keep an allowlist so a bad key doesn't get passed straight through to
# the router; values are expected to be "yes" / "no" (RouterOS booleans).
ALLOWED_DEVICE_MODE_FLAGS = {
    "scheduler", "socks", "fetch", "pptp", "l2tp", "bandwidth-test",
    "traffic-gen", "sniffer", "ipsec", "romon", "proxy", "hotspot", "smb",
    "email", "zerotier", "container", "install-any-version", "partitions",
    "routerboard",
}


class DeviceModeUpdateRequest(BaseModel):
    # Use either `mode` (a preset like "enterprise") OR `flags` (per-feature
    # toggles, e.g. {"hotspot": "yes"}). Newer RouterOS builds only accept
    # the flags form — the response message tells you which one this device
    # expects.
    mode: Optional[str] = None
    flags: Optional[dict] = None


def _get_device_mode_sync(router_info: dict) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=10,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}
    try:
        resp = api.send_command("/system/device-mode/print")
        if resp.get("error"):
            return {"error": "command_failed", "reason": resp["error"]}
        data = (resp.get("data") or [{}])[0]
        return {"success": True, "device_mode": data}
    finally:
        api.disconnect()


def _update_device_mode_sync(
    router_info: dict,
    mode: Optional[str] = None,
    flags: Optional[dict] = None,
) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}
    try:
        before_resp = api.send_command("/system/device-mode/print")
        before = (before_resp.get("data") or [{}])[0] if before_resp.get("success") else {}
        current_mode = before.get("mode", "")

        # If the caller asked for a preset that's already active and didn't
        # also pass per-feature flags, there's nothing to do.
        if mode and current_mode == mode and not flags:
            return {
                "success": True,
                "status": "already_in_mode",
                "message": f"Router is already in device-mode '{mode}'. Nothing to do.",
                "device_mode_before": before,
                "device_mode_after": before,
            }

        # Build the command arguments. `mode` takes precedence as a preset;
        # `flags` switches the router into the per-feature ("flagged") form
        # and toggles individual capabilities.
        args: dict = {}
        if mode:
            args["mode"] = mode
        if flags:
            args["flagged"] = "yes"
            for key, value in flags.items():
                args[key] = str(value)

        update_resp = api.send_command(
            "/system/device-mode/update",
            args,
        )

        # NOTE: RouterOS device-mode/update is special. The expected response
        # is a !trap whose message tells you how to physically confirm. We
        # don't classify any non-success as an HTTP error — we relay
        # whatever the router said so the caller can react. The endpoint
        # itself only fails when we cannot even reach the router.
        raw_router_message = update_resp.get("error") or ""
        raw_router_message_lower = raw_router_message.lower()

        pending_markers = ("confirm", "reset button", "reboot", "cold reboot",
                           "physical", "press", "5 minutes", "timer")
        denial_markers = ("not allowed", "denied", "permission", "policy")
        no_command_markers = ("no such command", "unknown command",
                              "syntax error", "expected end of command")

        if any(m in raw_router_message_lower for m in pending_markers):
            status = "pending_physical_confirmation"
            human_message = (
                "RouterOS accepted the update and is waiting for physical "
                "confirmation. Someone at the site must briefly press the reset "
                "button OR power-cycle the router within ~5 minutes. Poll GET "
                "/device-mode to verify the flip."
            )
        elif any(m in raw_router_message_lower for m in denial_markers):
            status = "denied_by_router"
            human_message = (
                "RouterOS rejected the update. Common causes: the API user's "
                "group lacks the 'policy' permission required for "
                "/system/device-mode/update, or the requested feature set is "
                "blocked. Try with an API user in the 'full' group."
            )
        elif any(m in raw_router_message_lower for m in no_command_markers):
            status = "command_not_supported"
            human_message = (
                "RouterOS did not recognise /system/device-mode/update. This "
                "feature was added in RouterOS 7.13; older versions don't have "
                "device-mode at all (and won't have the hotspot-blocking issue "
                "either)."
            )
        elif "does not match any value of mode" in raw_router_message_lower:
            status = "mode_value_rejected"
            human_message = (
                "This RouterOS build does not accept a preset for `mode` — it "
                "expects per-feature flags. Retry with body "
                "{\"flags\": {\"hotspot\": \"yes\"}} (add other features as "
                "needed). That puts the router into `flagged` device-mode and "
                "enables only what you list."
            )
        elif update_resp.get("success") and not raw_router_message:
            status = "applied"
            human_message = f"Device-mode changed to '{mode}' without requiring confirmation."
        else:
            status = "router_responded_unrecognised"
            human_message = (
                "RouterOS responded but we don't know how to classify it. See "
                "router_response_message for the raw text and decide manually."
            )

        # Re-read state. The connection may have been closed by the router
        # after a successful confirmation request, so handle that gracefully.
        try:
            after_resp = api.send_command("/system/device-mode/print")
            after = (after_resp.get("data") or [{}])[0] if after_resp.get("success") else {}
        except Exception:
            after = {}

        return {
            "success": True,
            "status": status,
            "message": human_message,
            "router_response_message": raw_router_message or None,
            "router_response_raw": update_resp,
            "device_mode_before": before,
            "device_mode_after": after,
        }
    finally:
        api.disconnect()


@router.get("/api/routers/by-identity/{identity}/device-mode")
async def get_device_mode(
    identity: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Return the router's current /system/device-mode print output."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(
            status_code=404,
            detail=f"No router found for identity/name '{identity}'",
        )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(_get_device_mode_sync, router_info)

    if result.get("error") == "connection_failed":
        await record_router_availability(db, router_obj.id, False, "device_mode_get")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {result.get('reason') or 'unknown'}",
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result.get("reason") or result["error"])

    await record_router_availability(db, router_obj.id, True, "device_mode_get")

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_identity_db": router_obj.identity,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


@router.post("/api/routers/by-identity/{identity}/device-mode")
async def update_device_mode(
    identity: str,
    request: DeviceModeUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Initiate a /system/device-mode change. RouterOS will require someone
    at the site to press the reset button briefly or power-cycle the router
    within ~5 minutes to physically confirm the change. Poll the GET
    endpoint afterwards to see whether the mode flipped.
    """
    mode = (request.mode or "").strip().lower() or None
    flags = request.flags or None

    if not mode and not flags:
        raise HTTPException(
            status_code=400,
            detail="Provide either `mode` (preset) or `flags` (per-feature toggles).",
        )
    if mode and mode not in ALLOWED_DEVICE_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode '{request.mode}'. Allowed: {sorted(ALLOWED_DEVICE_MODES)}",
        )
    if flags:
        bad_keys = [k for k in flags.keys() if k not in ALLOWED_DEVICE_MODE_FLAGS]
        if bad_keys:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown flag(s): {bad_keys}. "
                       f"Allowed: {sorted(ALLOWED_DEVICE_MODE_FLAGS)}",
            )

    user = await get_current_user(token, db)
    router_obj = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(
            status_code=404,
            detail=f"No router found for identity/name '{identity}'",
        )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(_update_device_mode_sync, router_info, mode, flags)

    if result.get("error") == "connection_failed":
        await record_router_availability(db, router_obj.id, False, "device_mode_update")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {result.get('reason') or 'unknown'}",
        )

    # Any other helper outcome — including RouterOS rejecting the change —
    # is returned as 200 so the caller can see the raw router message and
    # decide what to do. Cloudflare/origin layers will not swap our payload
    # for a generic 5xx page.
    await record_router_availability(db, router_obj.id, True, "device_mode_update")

    logger.info(
        f"Device-mode update for router {router_obj.name} (id={router_obj.id}) "
        f"to '{mode}': status={result.get('status')}"
    )

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_identity_db": router_obj.identity,
        "requested_mode": mode,
        "requested_flags": flags,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


# ---------------------------------------------------------------------------
# File listing — confirms whether hotspot HTML pages (login.html etc.) are
# actually present on the router. A hotspot can be fully configured and
# active but silently fail to redirect if the login page file is missing.
# ---------------------------------------------------------------------------

def _list_router_files_sync(router_info: dict, path_prefix: Optional[str]) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}
    try:
        resp = api.send_command_optimized(
            "/file/print",
            proplist=[".id", "name", "type", "size", "creation-time"],
        )
        if resp.get("error"):
            return {"error": "command_failed", "reason": resp["error"]}

        files = resp.get("data") or []
        if path_prefix:
            files = [f for f in files if (f.get("name") or "").startswith(path_prefix)]

        # Sort by name for predictable output
        files.sort(key=lambda f: f.get("name") or "")

        # Common red flags worth surfacing
        hotspot_files = [f for f in files if (f.get("name") or "").startswith("hotspot/")]
        login_html = next(
            (f for f in hotspot_files if (f.get("name") or "").lower() == "hotspot/login.html"),
            None,
        )
        findings = []
        if path_prefix in (None, "hotspot/", "hotspot"):
            if not hotspot_files:
                findings.append({
                    "severity": "critical",
                    "code": "hotspot_directory_empty",
                    "message": "No files found under hotspot/. The captive portal "
                               "redirect will hit an empty proxy and never show a "
                               "login page. Re-upload the hotspot HTML pages.",
                })
            elif not login_html:
                findings.append({
                    "severity": "critical",
                    "code": "login_html_missing",
                    "message": "hotspot/login.html is missing. The portal redirect "
                               "fires but there is no page to serve, so phones "
                               "never recognise the network as a captive portal.",
                })
            elif login_html.get("size") in ("0", 0, None, ""):
                findings.append({
                    "severity": "high",
                    "code": "login_html_empty",
                    "message": "hotspot/login.html exists but is 0 bytes. "
                               "Re-upload the redirect page.",
                    "row": login_html,
                })

        return {
            "success": True,
            "summary": {
                "total_files": len(files),
                "hotspot_files": len(hotspot_files),
                "login_html_present": login_html is not None,
                "login_html_size": login_html.get("size") if login_html else None,
            },
            "findings": findings,
            "files": files,
        }
    finally:
        api.disconnect()


@router.get("/api/routers/by-identity/{identity}/files")
async def list_router_files(
    identity: str,
    path_prefix: Optional[str] = "hotspot/",
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    List files on the router (`/file/print`). Defaults to filtering by
    `hotspot/` so the response is small and focused on captive-portal
    assets. Pass `?path_prefix=` (empty) to see everything.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(
            status_code=404,
            detail=f"No router found for identity/name '{identity}'",
        )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(
        _list_router_files_sync, router_info, path_prefix or None
    )

    if result.get("error") == "connection_failed":
        await record_router_availability(db, router_obj.id, False, "files_list")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {result.get('reason') or 'unknown'}",
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result.get("reason") or result["error"])

    await record_router_availability(db, router_obj.id, True, "files_list")

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_identity_db": router_obj.identity,
        "path_prefix": path_prefix,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


# ---------------------------------------------------------------------------
# Winbox-over-WireGuard toggle — temporarily opens the Winbox service to
# the WG management network so an operator can connect with Winbox for
# visual exploration that's awkward to do via the API. Call again with
# {"enable": false} when done.
# ---------------------------------------------------------------------------

_WINBOX_FW_COMMENT = "API-managed: Allow Winbox from WG"


class WinboxAccessRequest(BaseModel):
    enable: bool
    wg_source: str = "10.0.0.1/32"  # AWS server's WG address by default


def _toggle_winbox_access_sync(
    router_info: dict, enable: bool, wg_source: str
) -> dict:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}
    try:
        steps: list = []

        # 1. Find the input filter rule we own (by comment), if any.
        existing_fw = api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[".id", "chain", "comment"],
            query=f"?comment={_WINBOX_FW_COMMENT}",
        )
        existing_rules = existing_fw.get("data") or []

        # 2. Find the Winbox service entry.
        svc_resp = api.send_command(
            "/ip/service/print",
            {"?name": "winbox"},
        )
        winbox_svc = (svc_resp.get("data") or [{}])[0]
        winbox_id = winbox_svc.get(".id")

        if enable:
            # Add firewall rule if missing. Place it before any defconf
            # drop rule so it actually has an effect.
            if not existing_rules:
                # Locate the "drop all not coming from LAN" rule to place before it
                defconf = api.send_command_optimized(
                    "/ip/firewall/filter/print",
                    proplist=[".id", "chain", "action", "comment"],
                    query="?comment=defconf: drop all not coming from LAN",
                )
                defconf_rules = defconf.get("data") or []
                add_args = {
                    "chain": "input",
                    "protocol": "tcp",
                    "dst-port": "8291",
                    "src-address": wg_source,
                    "action": "accept",
                    "comment": _WINBOX_FW_COMMENT,
                }
                if defconf_rules:
                    add_args["place-before"] = defconf_rules[0][".id"]
                add_resp = api.send_command(
                    "/ip/firewall/filter/add",
                    add_args,
                )
                steps.append({"step": "add_firewall_rule", "result": add_resp})
            else:
                steps.append({
                    "step": "firewall_rule_exists",
                    "result": {"existing_count": len(existing_rules)},
                })

            # Enable Winbox service restricted to the WG source.
            if winbox_id:
                set_resp = api.send_command(
                    "/ip/service/set",
                    {
                        "numbers": winbox_id,
                        "address": wg_source,
                        "disabled": "no",
                    },
                )
                steps.append({"step": "enable_winbox_service", "result": set_resp})
            else:
                steps.append({
                    "step": "enable_winbox_service",
                    "result": {"error": "Winbox service entry not found"},
                })

            human = (
                f"Winbox now reachable on the router at port 8291 from {wg_source}. "
                f"From the AWS server (10.0.0.1) on the WG mesh you can connect: "
                f"`winbox {router_info['ip']}:8291`. Remember to call this endpoint "
                f"with {{\"enable\": false}} when done."
            )
        else:
            # Disable: remove our firewall rule(s) and turn the service off.
            for rule in existing_rules:
                rule_id = rule.get(".id")
                if rule_id:
                    rm = api.send_command(
                        "/ip/firewall/filter/remove",
                        {"numbers": rule_id},
                    )
                    steps.append({"step": "remove_firewall_rule",
                                  "rule_id": rule_id, "result": rm})

            if winbox_id:
                set_resp = api.send_command(
                    "/ip/service/set",
                    {"numbers": winbox_id, "disabled": "yes"},
                )
                steps.append({"step": "disable_winbox_service", "result": set_resp})

            human = "Winbox service disabled and our firewall rule removed."

        # Re-read state for confirmation.
        after_svc = api.send_command("/ip/service/print", {"?name": "winbox"})
        after_winbox = (after_svc.get("data") or [{}])[0]
        after_fw = api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[".id", "chain", "action", "protocol", "dst-port",
                      "src-address", "comment", "disabled"],
            query=f"?comment={_WINBOX_FW_COMMENT}",
        )

        return {
            "success": True,
            "message": human,
            "steps": steps,
            "winbox_service_after": after_winbox,
            "firewall_rules_after": after_fw.get("data") or [],
        }
    finally:
        api.disconnect()


@router.post("/api/routers/by-identity/{identity}/winbox-access")
async def toggle_winbox_access(
    identity: str,
    request: WinboxAccessRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Enable or disable Winbox access from the WireGuard management network.

    On enable: adds a firewall input-chain accept rule for TCP 8291 from the
    given WG source (default 10.0.0.1/32) and unblocks the Winbox service
    restricted to that source. Connect with Winbox from your AWS host
    (which lives at 10.0.0.1 on the WG mesh).

    On disable: removes our firewall rule and re-disables the service.

    The firewall rule is tagged with a known comment so it can be cleanly
    reversed.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(
            status_code=404,
            detail=f"No router found for identity/name '{identity}'",
        )

    router_info = {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }
    await db.commit()
    result = await asyncio.to_thread(
        _toggle_winbox_access_sync, router_info, request.enable, request.wg_source
    )

    if result.get("error") == "connection_failed":
        await record_router_availability(db, router_obj.id, False, "winbox_toggle")
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router '{router_obj.name}' "
                   f"({router_obj.ip_address}): {result.get('reason') or 'unknown'}",
        )
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result.get("reason") or result["error"])

    await record_router_availability(db, router_obj.id, True, "winbox_toggle")

    logger.info(
        f"Winbox access {'enabled' if request.enable else 'disabled'} for "
        f"router {router_obj.name} (id={router_obj.id}) from {request.wg_source}"
    )

    return {
        "router_id": router_obj.id,
        "router_name": router_obj.name,
        "router_identity_db": router_obj.identity,
        "enabled": request.enable,
        "wg_source": request.wg_source,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


# ---------------------------------------------------------------------------
# Hotspot files sync — fallback for routers where the built-in
# /ip/hotspot/profile/reset-html-directory command is unavailable (returns
# "no such command" on some RouterOS builds, so the standard captive-portal
# HTML scaffolding never gets installed). Pulls every text file under
# hotspot/ from a known-working router and writes them to the destination.
# Skips binary files (favicon.ico, etc.) — those aren't required for the
# captive-portal redirect to function.
# ---------------------------------------------------------------------------

class SyncHotspotFilesRequest(BaseModel):
    from_identity: str
    # Default False to preserve a freshly-fetched custom login.html on the
    # destination. Set True to overwrite everything under hotspot/.
    overwrite_existing: bool = False


def _sync_hotspot_files_sync(
    src_router_info: dict,
    dst_router_info: dict,
    overwrite_existing: bool,
) -> dict:
    src_api = MikroTikAPI(
        src_router_info["ip"], src_router_info["username"],
        src_router_info["password"], src_router_info["port"],
        timeout=20, connect_timeout=5,
    )
    if not src_api.connect():
        return {"error": "src_connection_failed", "reason": src_api.last_connect_error}

    try:
        dst_api = MikroTikAPI(
            dst_router_info["ip"], dst_router_info["username"],
            dst_router_info["password"], dst_router_info["port"],
            timeout=20, connect_timeout=5,
        )
        if not dst_api.connect():
            return {"error": "dst_connection_failed", "reason": dst_api.last_connect_error}

        try:
            src_resp = src_api.send_command_optimized(
                "/file/print",
                proplist=[".id", "name", "type", "size", "contents"],
            )
            if src_resp.get("error"):
                return {"error": "src_list_failed", "reason": src_resp["error"]}

            hotspot_src = [
                f for f in (src_resp.get("data") or [])
                if (f.get("name") or "").startswith("hotspot/")
            ]
            files_to_copy = [f for f in hotspot_src if f.get("type") != "directory"]
            if not files_to_copy:
                return {"error": "no_source_files",
                        "reason": "Source has nothing under hotspot/."}

            # Order by depth so parent paths are created first.
            files_to_copy.sort(key=lambda f: (f.get("name") or "").count("/"))

            created: list = []
            updated: list = []
            preserved: list = []
            skipped: list = []

            for src_file in files_to_copy:
                name = src_file.get("name") or ""
                contents = src_file.get("contents")
                size = src_file.get("size", "")

                if contents is None:
                    # RouterOS /file/print contents only returns the body for
                    # files smaller than ~4 KB. Larger text files (md5.js,
                    # WISPr xsd, etc.) come back with contents=None and we
                    # can't transfer them via this protocol — they need
                    # Winbox/FTP. Genuinely binary files (favicon.ico) also
                    # land here. Neither category is required for the basic
                    # captive-portal redirect flow.
                    skipped.append({"file": name, "size": size,
                                    "reason": "no contents (size > ~4KB API "
                                              "cap, or binary file)"})
                    continue

                # NOTE: query attributes must be sent as bare words
                # (`?name=...`), NOT as `=?name=...` (the latter is parsed
                # as an attribute with a literal `?name` key and the filter
                # gets ignored). Use send_command_optimized which appends
                # the query word verbatim.
                check = dst_api.send_command_optimized(
                    "/file/print",
                    proplist=[".id", "name"],
                    query=f"?name={name}",
                )
                existing = check.get("data") or []

                if existing and not overwrite_existing:
                    preserved.append({"file": name, "size": size,
                                      "reason": "already present, overwrite_existing=false"})
                    continue

                if existing:
                    resp = dst_api.send_command("/file/set", {
                        "numbers": existing[0][".id"], "contents": contents,
                    })
                    if resp.get("error"):
                        skipped.append({"file": name, "size": size,
                                        "reason": f"set failed: {resp['error']}"})
                    else:
                        updated.append({"file": name, "size": size})
                else:
                    resp = dst_api.send_command("/file/add", {
                        "name": name, "contents": contents,
                    })
                    if resp.get("error"):
                        skipped.append({"file": name, "size": size,
                                        "reason": f"add failed: {resp['error']}"})
                    else:
                        created.append({"file": name, "size": size})

            verify = dst_api.send_command_optimized(
                "/file/print",
                proplist=[".id", "name", "type", "size"],
            )
            dst_after = [
                f for f in (verify.get("data") or [])
                if (f.get("name") or "").startswith("hotspot/")
            ]

            return {
                "success": True,
                "summary": {
                    "source_hotspot_files": len(hotspot_src),
                    "source_copyable": len(files_to_copy),
                    "created": len(created),
                    "updated": len(updated),
                    "preserved": len(preserved),
                    "skipped": len(skipped),
                    "destination_hotspot_files_after": len(dst_after),
                },
                "created_files": created,
                "updated_files": updated,
                "preserved_files": preserved,
                "skipped_files": skipped,
                "destination_files_after": dst_after,
            }
        finally:
            dst_api.disconnect()
    finally:
        src_api.disconnect()


@router.post("/api/routers/by-identity/{identity}/sync-hotspot-files")
async def sync_hotspot_files(
    identity: str,
    request: SyncHotspotFilesRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Copy text files under hotspot/ from `from_identity` to this router.
    Use when /ip/hotspot/profile/reset-html-directory is unavailable on
    the destination (returns "no such command") and the standard
    captive-portal HTML scaffolding is missing.

    Default behaviour preserves any file already present on the destination
    (so a freshly-fetched custom login.html survives). Pass
    `overwrite_existing: true` to mirror the source exactly.
    """
    if request.from_identity == identity:
        raise HTTPException(status_code=400,
                            detail="from_identity must differ from destination.")

    user = await get_current_user(token, db)
    dst_router = await get_router_by_identity(db, identity, user.id, user.role.value)
    if not dst_router:
        raise HTTPException(status_code=404,
                            detail=f"Destination router '{identity}' not found.")
    src_router = await get_router_by_identity(
        db, request.from_identity, user.id, user.role.value
    )
    if not src_router:
        raise HTTPException(status_code=404,
                            detail=f"Source router '{request.from_identity}' not found.")

    src_info = {"ip": src_router.ip_address, "username": src_router.username,
                "password": src_router.password, "port": src_router.port}
    dst_info = {"ip": dst_router.ip_address, "username": dst_router.username,
                "password": dst_router.password, "port": dst_router.port}

    await db.commit()
    result = await asyncio.to_thread(
        _sync_hotspot_files_sync, src_info, dst_info, request.overwrite_existing
    )

    if result.get("error") == "src_connection_failed":
        raise HTTPException(status_code=503,
                            detail=f"Source '{src_router.name}' unreachable: "
                                   f"{result.get('reason') or 'unknown'}")
    if result.get("error") == "dst_connection_failed":
        raise HTTPException(status_code=503,
                            detail=f"Destination '{dst_router.name}' unreachable: "
                                   f"{result.get('reason') or 'unknown'}")
    if result.get("error"):
        raise HTTPException(status_code=500,
                            detail=result.get("reason") or result["error"])

    logger.info(
        f"Hotspot files synced from '{src_router.name}' to '{dst_router.name}': "
        f"{result.get('summary')}"
    )

    return {
        "from_router": {"id": src_router.id, "name": src_router.name,
                        "identity": src_router.identity},
        "to_router": {"id": dst_router.id, "name": dst_router.name,
                      "identity": dst_router.identity},
        "overwrite_existing": request.overwrite_existing,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }

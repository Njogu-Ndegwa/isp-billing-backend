from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_helpers import get_router_by_id
from app.services.log_persistence import persist_notable_logs
from app.services.router_concurrency import run_with_guard

import asyncio
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["hotspot-monitor"])

_hotspot_overview_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_OVERVIEW_CACHE_TTL = 60  # 60 seconds


# ---------------------------------------------------------------------------
# Sync helpers (run in thread pool)
# ---------------------------------------------------------------------------

def _hotspot_overview_sync(router_info: dict, db_pppoe_ports: list) -> dict:
    """Gather all hotspot infrastructure data in one connection."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        checks = []

        hs_servers = api.get_hotspot_server_status()
        servers = hs_servers.get("data", []) if hs_servers.get("success") else []
        enabled_servers = [s for s in servers if not s["disabled"]]
        checks.append({
            "check": "hotspot_server",
            "description": "Hotspot server running",
            "passed": len(enabled_servers) > 0,
            "detail": enabled_servers if enabled_servers else "No hotspot server found or all disabled",
        })

        hs_interface = enabled_servers[0].get("interface", "bridge") if enabled_servers else "bridge"

        bridge_data = api.get_bridge_ports_status()
        bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
        bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []

        hotspot_bridge = bridges.get(hs_interface)
        checks.append({
            "check": "hotspot_bridge",
            "description": f"Hotspot bridge '{hs_interface}' exists and running",
            "passed": hotspot_bridge is not None and hotspot_bridge.get("running", False),
            "detail": hotspot_bridge if hotspot_bridge else f"Bridge '{hs_interface}' not found",
        })

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports}
        pppoe_port_set = set(db_pppoe_ports or [])
        hotspot_ports = []
        any_port_up = False
        for port_name, iface in ifaces.items():
            if iface.get("type") != "ether" or port_name == "ether1":
                continue
            if port_name in pppoe_port_set:
                continue
            actual_bridge = port_bridge_map.get(port_name)
            link_up = iface.get("running", False)
            if link_up and actual_bridge == hs_interface:
                any_port_up = True
            hotspot_ports.append({
                "port": port_name,
                "bridge": actual_bridge or "(none)",
                "in_hotspot_bridge": actual_bridge == hs_interface,
                "link_up": link_up,
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
            })
        checks.append({
            "check": "hotspot_ports",
            "description": "Hotspot ports in correct bridge with link up",
            "passed": any_port_up,
            "detail": hotspot_ports if hotspot_ports else "No hotspot ports found (all may be assigned to PPPoE)",
        })

        dhcp_data = api.get_dhcp_server_status()
        dhcp_servers = dhcp_data.get("data", []) if dhcp_data.get("success") else []
        active_dhcp = [d for d in dhcp_servers if not d["disabled"]]
        checks.append({
            "check": "dhcp_server",
            "description": "DHCP server running",
            "passed": len(active_dhcp) > 0,
            "detail": active_dhcp if active_dhcp else "No DHCP server found or all disabled",
        })

        dhcp_pool_name = active_dhcp[0].get("address_pool", "") if active_dhcp else ""
        if dhcp_pool_name:
            pool_data = api.get_ip_pool_status(dhcp_pool_name)
            pools = pool_data.get("pools", []) if pool_data.get("success") else []
            pool_ok = len(pools) > 0 and not any(p.get("exhausted") for p in pools)
            checks.append({
                "check": "dhcp_pool",
                "description": f"DHCP pool '{dhcp_pool_name}' not exhausted",
                "passed": pool_ok,
                "detail": pools if pools else f"Pool '{dhcp_pool_name}' not found",
            })
        else:
            checks.append({
                "check": "dhcp_pool",
                "description": "DHCP pool configured",
                "passed": False,
                "detail": "Could not determine DHCP pool name",
            })

        nat_data = api.get_nat_rules()
        nat_rules = nat_data.get("data", []) if nat_data.get("success") else []
        masquerade_exists = any(
            r["action"] == "masquerade" and not r["disabled"]
            for r in nat_rules
        )
        checks.append({
            "check": "nat_masquerade",
            "description": "NAT masquerade rule exists",
            "passed": masquerade_exists,
            "detail": [r for r in nat_rules if r["action"] == "masquerade"],
        })

        walled_garden = api.get_walled_garden()
        wg_domain = walled_garden.get("domain_entries", []) if walled_garden.get("success") else []
        wg_ip = walled_garden.get("ip_entries", []) if walled_garden.get("success") else []
        checks.append({
            "check": "walled_garden",
            "description": "Walled garden configured (required for captive portal)",
            "passed": len(wg_domain) > 0 or len(wg_ip) > 0,
            "detail": {
                "domain_entries": len(wg_domain),
                "ip_entries": len(wg_ip),
            },
        })

        hs_profiles = api.get_hotspot_profiles_detail()
        profiles = hs_profiles.get("data", []) if hs_profiles.get("success") else []
        has_login = any(p.get("html_directory") for p in profiles)
        checks.append({
            "check": "hotspot_profile",
            "description": "Hotspot profile with login page configured",
            "passed": has_login or len(profiles) > 0,
            "detail": profiles,
        })

        active_data = api.get_active_hotspot_users()
        session_count = len(active_data.get("data", [])) if active_data.get("success") else 0

        all_passed = all(c["passed"] for c in checks)
        return {
            "success": True,
            "healthy": all_passed,
            "active_sessions": session_count,
            "checks": checks,
        }
    except Exception as e:
        logger.error(f"Hotspot overview error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _hotspot_logs_sync(router_info: dict, search: str = "", limit: int = 50) -> dict:
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        logs = api.get_router_logs(topics="hotspot,dhcp", limit=200)
        entries = logs.get("data", []) if logs.get("success") else []
        if search:
            search_lower = search.lower()
            entries = [e for e in entries if search_lower in e.get("message", "").lower()]
        return {"success": True, "data": entries[-limit:], "count": len(entries[-limit:])}
    except Exception as e:
        logger.error(f"Hotspot logs error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/hotspot/{router_id}/overview")
async def hotspot_overview(
    router_id: int,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Hotspot infrastructure health check for a router. Cached for 60s unless ?refresh=true."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    # Check cache first (skip if explicit refresh requested)
    if not refresh and router_id in _hotspot_overview_cache:
        cached = _hotspot_overview_cache[router_id]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _OVERVIEW_CACHE_TTL:
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(
        router_id, _hotspot_overview_sync, router_info, router_obj.pppoe_ports or [],
    )

    if result.get("error") == "connect_failed":
        if router_id in _hotspot_overview_cache:
            stale = _hotspot_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            stale["cache_age_seconds"] = (datetime.utcnow() - _hotspot_overview_cache[router_id]["timestamp"]).total_seconds()
            return stale
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        if router_id in _hotspot_overview_cache:
            stale = _hotspot_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    response = {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        "cached": False,
        **result,
    }

    _hotspot_overview_cache[router_id] = {
        "data": response,
        "timestamp": datetime.utcnow(),
    }

    return response


@router.get("/api/hotspot/{router_id}/logs")
async def hotspot_logs(
    router_id: int,
    search: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get hotspot/DHCP-related log entries from the router."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(router_id, _hotspot_logs_sync, router_info, search or "", limit)

    if result.get("error") == "connect_failed":
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    entries = result.get("data", [])
    persisted = await persist_notable_logs(db, router_id, entries, topic_filter="hotspot,dhcp")

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "filter_search": search,
        "generated_at": datetime.utcnow().isoformat(),
        "notable_entries_persisted": persisted,
        **result,
    }

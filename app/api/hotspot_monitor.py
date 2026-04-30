from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime


from app.db.database import get_db
from app.db.models import Customer
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.services.router_helpers import get_router_by_id
from app.services.log_persistence import persist_notable_logs
from app.services.router_concurrency import run_with_guard
from app.services.router_availability import record_router_availability

import asyncio
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["hotspot-monitor"])

_hotspot_overview_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_OVERVIEW_CACHE_TTL = 60  # 60 seconds

_hotspot_users_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_USERS_CACHE_TTL = 30  # 30 seconds -- live bandwidth changes fast


# ---------------------------------------------------------------------------
# Sync helpers (run in thread pool)
# ---------------------------------------------------------------------------

def _hotspot_overview_sync(
    router_info: dict,
    db_pppoe_ports: list,
    db_plain_ports: list = None,
    db_dual_ports: list = None,
) -> dict:
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

        hotspot_interfaces = {
            s.get("interface", "")
            for s in enabled_servers
            if s.get("interface")
        }

        bridge_data = api.get_bridge_ports_status()
        bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
        bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []

        checks.append({
            "check": "hotspot_bridge",
            "description": "Hotspot bridge interfaces exist and are running",
            "passed": bool(hotspot_interfaces) and all(
                bridges.get(name) is not None and bridges[name].get("running", False)
                for name in hotspot_interfaces
            ),
            "detail": {
                name: bridges.get(name) or {"missing": True}
                for name in sorted(hotspot_interfaces)
            } if hotspot_interfaces else "No enabled hotspot interface found",
        })

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports}
        excluded_ports = set(db_pppoe_ports or []) | set(db_plain_ports or [])
        dual_set = set(db_dual_ports or [])
        hotspot_ports = []
        any_port_up = False
        for port_name, iface in ifaces.items():
            if iface.get("type") != "ether" or port_name == "ether1":
                continue
            if port_name in excluded_ports:
                continue
            actual_bridge = port_bridge_map.get(port_name)
            link_up = iface.get("running", False)
            if link_up and actual_bridge in hotspot_interfaces:
                any_port_up = True
            hotspot_ports.append({
                "port": port_name,
                "bridge": actual_bridge or "(none)",
                "hotspot_interface": actual_bridge if actual_bridge in hotspot_interfaces else "",
                "in_hotspot_bridge": actual_bridge in hotspot_interfaces,
                "dual_mode": port_name in dual_set,
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
        active_dhcp = [
            d for d in dhcp_servers
            if not d["disabled"] and d.get("interface") in hotspot_interfaces
        ]
        dhcp_interfaces = {d.get("interface", "") for d in active_dhcp}
        missing_dhcp = sorted(i for i in hotspot_interfaces if i not in dhcp_interfaces)
        checks.append({
            "check": "dhcp_server",
            "description": "DHCP server running on each hotspot interface",
            "passed": bool(hotspot_interfaces) and not missing_dhcp,
            "detail": {
                "servers": active_dhcp,
                "missing_interfaces": missing_dhcp,
            } if active_dhcp or missing_dhcp else "No DHCP server found or all disabled",
        })

        dhcp_pool_checks = []
        for dhcp_server in active_dhcp:
            dhcp_pool_name = dhcp_server.get("address_pool", "")
            if not dhcp_pool_name:
                dhcp_pool_checks.append({
                    "interface": dhcp_server.get("interface", ""),
                    "pool": "",
                    "ok": False,
                    "detail": "No address pool configured",
                })
                continue
            pool_data = api.get_ip_pool_status(dhcp_pool_name)
            pools = pool_data.get("pools", []) if pool_data.get("success") else []
            pool_ok = len(pools) > 0 and not any(p.get("exhausted") for p in pools)
            dhcp_pool_checks.append({
                "interface": dhcp_server.get("interface", ""),
                "pool": dhcp_pool_name,
                "ok": pool_ok,
                "detail": pools if pools else f"Pool '{dhcp_pool_name}' not found",
            })
        if dhcp_pool_checks:
            checks.append({
                "check": "dhcp_pool",
                "description": "DHCP pools for hotspot interfaces are configured and not exhausted",
                "passed": all(item["ok"] for item in dhcp_pool_checks),
                "detail": dhcp_pool_checks,
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


def _hotspot_users_sync(router_info: dict) -> dict:
    """Gather all hotspot users (configured + bypassed) with bandwidth and online state."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        return api.get_hotspot_users_with_bandwidth()
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
        router_id, _hotspot_overview_sync, router_info,
        router_obj.pppoe_ports or [], router_obj.plain_ports or [],
        getattr(router_obj, "dual_ports", None) or [],
    )

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "hotspot_overview")
        if router_id in _hotspot_overview_cache:
            stale = _hotspot_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            stale["cache_age_seconds"] = (datetime.utcnow() - _hotspot_overview_cache[router_id]["timestamp"]).total_seconds()
            return stale
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "hotspot_overview")
        if router_id in _hotspot_overview_cache:
            stale = _hotspot_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "hotspot_overview")

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
        await record_router_availability(db, router_id, False, "hotspot_logs")
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "hotspot_logs")
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "hotspot_logs")

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


@router.get("/api/hotspot/{router_id}/users")
async def hotspot_users(
    router_id: int,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """All hotspot clients for a router with online/offline status and live bandwidth.

    The hotspot equivalent of ``GET /api/pppoe/{router_id}/users`` -- it returns
    every configured hotspot user *and* every IP-binding (typically the bypassed
    ISP-billed customers) on the router, enriched with:

    - ``online`` flag (active session OR a hotspot host entry that is
      authorized/bypassed). ``online_source`` tells you which signal won
      (``"active"`` for portal sessions, ``"host"`` for bypassed customers).
    - Live ``upload_rate`` / ``download_rate`` in bps, from the per-user
      ``plan_<username>`` simple queue (same trick PPPoE uses).
    - Cumulative session ``upload_bytes`` / ``download_bytes`` -- preferring
      the active session counters and falling back to the queue's running
      totals for bypassed clients that never touch the captive portal.
    - ``mac_address``, ``address`` (IP), ``uptime``, ``idle_time``, ``login_by``
      and ``binding_type`` (``bypassed`` / ``regular`` / ``blocked``).
    - DB customer cross-reference (matched by MAC) with name, phone, plan,
      and subscription status / expiry.

    Cached for 30s per router unless ``?refresh=true``.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    if not refresh and router_id in _hotspot_users_cache:
        cached = _hotspot_users_cache[router_id]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _USERS_CACHE_TTL:
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(router_id, _hotspot_users_sync, router_info)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "hotspot_users")
        if router_id in _hotspot_users_cache:
            stale = _hotspot_users_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            stale["cache_age_seconds"] = (
                datetime.utcnow() - _hotspot_users_cache[router_id]["timestamp"]
            ).total_seconds()
            return stale
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "hotspot_users")
        if router_id in _hotspot_users_cache:
            stale = _hotspot_users_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=504, detail=result.get("detail", "Operation timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "hotspot_users")

    # Cross-reference DB customers by MAC. Hotspot customers in this app are
    # keyed on `Customer.mac_address`, normalized to colon-separated upper-case.
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.router_id == router_id,
            Customer.mac_address.isnot(None),
        )
    )
    db_result = await db.execute(stmt)
    customers = db_result.scalars().all()
    customer_map: dict = {}
    for c in customers:
        mac = c.mac_address or ""
        if not mac:
            continue
        try:
            customer_map[normalize_mac_address(mac)] = c
        except Exception:
            customer_map[mac.upper()] = c

    for u in result.get("users", []):
        mac = u.get("mac_address") or ""
        cust = customer_map.get(mac) if mac else None
        if cust:
            u["customer"] = {
                "id": cust.id,
                "name": cust.name,
                "phone": cust.phone,
                "status": cust.status.value if cust.status else "unknown",
                "plan": cust.plan.name if cust.plan else None,
                "plan_speed": cust.plan.speed if cust.plan else None,
                "expiry": cust.expiry.isoformat() if cust.expiry else None,
            }
        else:
            u["customer"] = None

    response = {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        "cached": False,
        **result,
    }

    _hotspot_users_cache[router_id] = {
        "data": response,
        "timestamp": datetime.utcnow(),
    }

    return response

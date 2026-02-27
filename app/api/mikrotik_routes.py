from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from datetime import datetime, timedelta
from app.db.database import get_db
from app.db.models import Router, Customer, BandwidthSnapshot, UserBandwidthUsage
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_helpers import get_router_by_id
from app.config import settings
import logging
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mikrotik"])

# MikroTik health cache per router
_health_cache = {}  # router_id -> {"data": ..., "timestamp": ...}
_health_cache_ttl = 300  # 5 minutes - reduces router connection load significantly

# MikroTik dashboard cache (avoid hammering the router)
_mikrotik_cache = {"data": None, "timestamp": None}
_mikrotik_cache_ttl = 300  # seconds - limit to once per 5 minutes


# =============================================================================
# ASYNC WRAPPERS FOR MIKROTIK OPERATIONS
# =============================================================================

def _run_mikrotik_health_sync(router_info: dict) -> dict:
    """
    Synchronous function to fetch health data from MikroTik.
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
    """
    Async wrapper that runs MikroTik health fetch in a thread pool.
    This prevents blocking the event loop while waiting for router response.
    """
    return await asyncio.to_thread(_run_mikrotik_health_sync, router_info)


def _fetch_mikrotik_data_sync():
    """Synchronous MikroTik fetch - runs in thread pool to not block event loop"""
    api = MikroTikAPI(
        settings.MIKROTIK_HOST,
        settings.MIKROTIK_USERNAME,
        settings.MIKROTIK_PASSWORD,
        settings.MIKROTIK_PORT,
        timeout=15,
        connect_timeout=5  # Fast fail if router unreachable
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


def _get_mikrotik_traffic_sync(router_info: dict, interface: Optional[str]) -> dict:
    """Synchronous function to get interface traffic. Runs in thread pool."""
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
        traffic = api.get_interface_traffic(interface)
        if traffic.get("error"):
            return {"error": traffic["error"]}
        return {"success": True, "data": traffic.get("data", [])}
    finally:
        api.disconnect()


def _get_mikrotik_active_sessions_sync(router_info: dict) -> dict:
    """Synchronous function to get active sessions. Runs in thread pool."""
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
        sessions = api.get_active_hotspot_users()
        if sessions.get("error"):
            return {"error": sessions["error"]}
        return {"success": True, "data": sessions.get("data", [])}
    finally:
        api.disconnect()


# =============================================================================
# MIKROTIK HEALTH AND STATS ENDPOINTS
# =============================================================================

@router.get("/api/mikrotik/health")
async def get_mikrotik_health(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get MikroTik router health metrics (CPU, memory, disk, uptime).
    
    Active users and bandwidth come from background job data (more reliable).
    Cached for 30 seconds per router to prevent overloading MikroTik.
    """
    user = await get_current_user(token, db)
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
            router = await get_router_by_id(db, router_id, user.id, user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            router_info = {
                "ip": router.ip_address,
                "username": router.username,
                "password": router.password,
                "port": router.port,
                "name": router.name
            }
            router_name = router.name
        else:
            router_info = {
                "ip": settings.MIKROTIK_HOST,
                "username": settings.MIKROTIK_USERNAME,
                "password": settings.MIKROTIK_PASSWORD,
                "port": settings.MIKROTIK_PORT,
                "name": "Default Router"
            }
            router_name = "Default Router"
        
        # Run MikroTik operations in thread pool (non-blocking!)
        mikrotik_result = await run_mikrotik_health_async(router_info)
        
        if mikrotik_result.get("error"):
            # Return stale cache if available when router unreachable
            if cache_key in _health_cache:
                result = _health_cache[cache_key]["data"].copy()
                result["cached"] = True
                result["cache_age_seconds"] = (datetime.utcnow() - _health_cache[cache_key]["timestamp"]).total_seconds()
                result["stale"] = True
                return result
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        
        resources = mikrotik_result.get("resources", {})
        health = mikrotik_result.get("health", {})
        
        if resources.get("error"):
            raise HTTPException(status_code=500, detail=resources["error"])
        
        res_data = resources.get("data", {})
        total_mem = res_data.get("total_memory", 1)
        free_mem = res_data.get("free_memory", 0)
        total_hdd = res_data.get("total_hdd_space", 1)
        free_hdd = res_data.get("free_hdd_space", 0)
        
        # Get active users and bandwidth from latest snapshot (collected by background job)
        active_users = 0
        current_download_mbps = 0.0
        current_upload_mbps = 0.0
        snapshot_age = None
        
        snapshot_query = select(BandwidthSnapshot).order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        if router_id:
            snapshot_query = snapshot_query.where(BandwidthSnapshot.router_id == router_id)
        
        snapshot_result = await db.execute(snapshot_query)
        latest_snapshot = snapshot_result.scalar_one_or_none()
        
        if latest_snapshot:
            active_users = latest_snapshot.active_queues  # We store active users here
            current_download_mbps = round(latest_snapshot.avg_download_bps / 1000000, 2)
            current_upload_mbps = round(latest_snapshot.avg_upload_bps / 1000000, 2)
            snapshot_age = (datetime.utcnow() - latest_snapshot.recorded_at).total_seconds()
        
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
            "active_users": active_users,
            "bandwidth": {
                "download_mbps": current_download_mbps,
                "upload_mbps": current_upload_mbps
            },
            "snapshot_age_seconds": round(snapshot_age, 1) if snapshot_age else None,
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Always cache - we're using reliable DB data now
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


# ============================================================================
# WALLED GARDEN MANAGEMENT
# ============================================================================

@router.get("/api/mikrotik/walled-garden")
async def get_walled_garden(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all walled garden entries (domain and IP-based)."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            host, user, pwd, port = router.ip_address, router.username, router.password, router.port
        else:
            host, user, pwd, port = settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT

        def _fetch():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.get_walled_garden()
            finally:
                api.disconnect()

        result = await asyncio.get_event_loop().run_in_executor(None, _fetch)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting walled garden: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/mikrotik/walled-garden/ip")
async def add_walled_garden_ip_entry(
    dst_address: str,
    comment: str = "Added via API",
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Add an IP address to the walled garden (allows hotspot users to reach it before auth)."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            host, user, pwd, port = router.ip_address, router.username, router.password, router.port
        else:
            host, user, pwd, port = settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT

        def _add():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.add_walled_garden_ip(dst_address, comment=comment)
            finally:
                api.disconnect()

        result = await asyncio.get_event_loop().run_in_executor(None, _add)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding walled garden IP: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/mikrotik/walled-garden/domain")
async def add_walled_garden_domain_entry(
    dst_host: str,
    comment: str = "Added via API",
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Add a domain to the walled garden (allows hotspot users to access it before auth)."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            host, user, pwd, port = router.ip_address, router.username, router.password, router.port
        else:
            host, user, pwd, port = settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT

        def _add():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.add_walled_garden_domain(dst_host, comment=comment)
            finally:
                api.disconnect()

        result = await asyncio.get_event_loop().run_in_executor(None, _add)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding walled garden domain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/mikrotik/walled-garden/ip/{entry_id}")
async def remove_walled_garden_ip_entry(
    entry_id: str,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Remove an IP-based walled garden entry."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            host, user, pwd, port = router.ip_address, router.username, router.password, router.port
        else:
            host, user, pwd, port = settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT

        def _remove():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.remove_walled_garden_ip(entry_id)
            finally:
                api.disconnect()

        result = await asyncio.get_event_loop().run_in_executor(None, _remove)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing walled garden IP entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WIREGUARD MANAGEMENT
# ============================================================================

@router.post("/api/mikrotik/wireguard/update-endpoint")
async def update_wireguard_endpoint(
    new_endpoint: str,
    interface_name: str = "wg-aws",
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update WireGuard peer endpoint address (when server IP changes)."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            host, user, pwd, port = router.ip_address, router.username, router.password, router.port
        else:
            host, user, pwd, port = settings.MIKROTIK_HOST, settings.MIKROTIK_USERNAME, settings.MIKROTIK_PASSWORD, settings.MIKROTIK_PORT

        def _update():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.update_wireguard_endpoint(new_endpoint, interface_name)
            finally:
                api.disconnect()

        result = await asyncio.get_event_loop().run_in_executor(None, _update)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating WireGuard endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# DASHBOARD MIKROTIK DATA
# ============================================================================

@router.get("/api/dashboard/mikrotik")
async def get_dashboard_mikrotik(
    token: str = Depends(verify_token)
):
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


# ============================================================================
# TRAFFIC AND SESSIONS
# ============================================================================

@router.get("/api/mikrotik/traffic")
async def get_mikrotik_traffic(
    interface: Optional[str] = None,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get MikroTik interface traffic statistics. Runs in thread pool."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            router_info = {
                "ip": router.ip_address,
                "username": router.username,
                "password": router.password,
                "port": router.port
            }
            router_name = router.name
        else:
            router_info = {
                "ip": settings.MIKROTIK_HOST,
                "username": settings.MIKROTIK_USERNAME,
                "password": settings.MIKROTIK_PASSWORD,
                "port": settings.MIKROTIK_PORT
            }
            router_name = "Default Router"
        
        # Run MikroTik operations in thread pool (non-blocking!)
        result = await asyncio.to_thread(_get_mikrotik_traffic_sync, router_info, interface)
        
        if result.get("error") == "connection_failed":
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        elif result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "interfaces": result.get("data", []),
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching MikroTik traffic: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/mikrotik/active-sessions")
async def get_mikrotik_active_sessions(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get currently active hotspot sessions with traffic data. Runs in thread pool."""
    try:
        current_user = await get_current_user(token, db)
        if router_id:
            router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
            if not router:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            router_info = {
                "ip": router.ip_address,
                "username": router.username,
                "password": router.password,
                "port": router.port
            }
            router_name = router.name
        else:
            router_info = {
                "ip": settings.MIKROTIK_HOST,
                "username": settings.MIKROTIK_USERNAME,
                "password": settings.MIKROTIK_PASSWORD,
                "port": settings.MIKROTIK_PORT
            }
            router_name = "Default Router"
        
        # Run MikroTik operations in thread pool (non-blocking!)
        result = await asyncio.to_thread(_get_mikrotik_active_sessions_sync, router_info)
        
        if result.get("error") == "connection_failed":
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")
        elif result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "sessions": result.get("data", []),
            "total_sessions": len(result.get("data", [])),
            "router_id": router_id,
            "router_name": router_name,
            "generated_at": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching active sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# BANDWIDTH HISTORY AND TOP USERS
# ============================================================================

@router.get("/api/mikrotik/bandwidth-history")
async def get_bandwidth_history(
    hours: int = 24,
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get historical bandwidth data for graphing. Default last 24 hours.
    
    Query params:
    - hours: Number of hours of history (default 24)
    - router_id: Optional router ID to filter bandwidth history for a specific router
    """
    try:
        await get_current_user(token, db)
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


@router.get("/api/mikrotik/top-users")
async def get_top_bandwidth_users(
    limit: int = 10, 
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get top bandwidth users sorted by total download.
    Reads from cached DB data (updated every 2 min by background job).
    
    Query params:
    - limit: Number of top users to return (default 10)
    - router_id: Optional router ID to filter users for a specific router
    """
    try:
        await get_current_user(token, db)
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

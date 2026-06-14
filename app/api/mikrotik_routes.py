from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional
from datetime import datetime, timedelta
from app.db.database import async_session, get_db
from app.db.models import Router, Customer, Plan, BandwidthSnapshot, UserBandwidthUsage
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_helpers import get_router_by_id
from app.services.router_availability import record_router_availability
from app.config import settings
import logging
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mikrotik"])

# MikroTik health cache per router
_health_cache = {}  # router_id -> {"data": ..., "timestamp": ...}
_health_cache_ttl = 60  # Fresh live health TTL. Stale dashboard calls revalidate in background.
_health_cache_stale_ttl = 1800  # Keep last live system details for 30 min instead of showing blanks.
_health_refresh_retry_floor = 20  # Minimum seconds between background live refresh starts per router.
_health_refresh_inflight = set()  # cache keys currently being refreshed after a fast snapshot response
_health_refresh_last_started = {}  # cache_key -> datetime of last live refresh attempt

# MikroTik dashboard cache (avoid hammering the router)
_mikrotik_cache = {"data": None, "timestamp": None}
_mikrotik_cache_ttl = 300  # seconds - limit to once per 5 minutes


def _bytes_to_mb(value: int) -> float:
    return round(int(value or 0) / (1024 * 1024), 2)


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
        timeout=6,
        connect_timeout=3
    )
    
    if not api.connect():
        return {"error": "Failed to connect", "router_name": router_info.get("name", "Unknown")}
    
    try:
        resources = api.get_system_resources()
        if resources.get("error"):
            return {
                "error": resources["error"],
                "router_name": router_info.get("name", "Unknown"),
            }

        health = {"success": True, "data": {}, "skipped": True}
        if api.connected and api.sock:
            original_timeout = api.sock.gettimeout()
            try:
                api.sock.settimeout(2)
                health_result = api.get_health()
                if health_result.get("success"):
                    health = health_result
            except Exception as exc:
                logger.warning(
                    "Skipping optional health sensors for router %s (%s): %s",
                    router_info.get("name", "Unknown"),
                    router_info["ip"],
                    exc,
                )
            finally:
                try:
                    api.sock.settimeout(original_timeout)
                except Exception:
                    pass

        # Keep /api/mikrotik/health fast. Live PPPoE session detail can be
        # slow on old RouterOS builds and has a dedicated drill-down endpoint.
        # The route below derives the count from the latest bandwidth snapshot.
        pppoe_active = {"success": True, "data": [], "count": 0, "skipped": True}
        return {
            "success": True,
            "resources": resources,
            "health": health,
            "pppoe_active": pppoe_active,
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

# Cap on inline session arrays returned from /api/mikrotik/health when the
# caller opts in via include_sessions=true. Beyond this we set
# ``sessions_truncated: true`` and direct callers to the dedicated drill-down
# endpoints (which paginate per-session detail without hitting the health cache).
_HEALTH_MAX_INLINE_SESSIONS = 50


def _shape_health_response(
    full: dict,
    *,
    include_sessions: bool,
    cached: bool,
    cache_age_seconds: Optional[float],
    stale: bool = False,
    refresh_in_progress: bool = False,
    retry_after_seconds: Optional[float] = None,
) -> dict:
    """Project the cached, full health payload into the public response shape.

    Keeping the cache entry "fat" (with the live session arrays) and slicing
    here means a single cache entry can serve both ``include_sessions=false``
    (default, dashboard tile) and ``include_sessions=true`` (drill-down
    fallback) without doubling cache pressure on the router.
    """
    result = {k: v for k, v in full.items() if k != "_full_pppoe_sessions"}
    full_sessions = full.get("_full_pppoe_sessions", []) or []

    if include_sessions:
        capped = full_sessions[:_HEALTH_MAX_INLINE_SESSIONS]
        result["active_pppoe_sessions"] = capped
        result["sessions_truncated"] = len(full_sessions) > _HEALTH_MAX_INLINE_SESSIONS
    else:
        # Default: no per-session payload on the tile endpoint. Frontends that
        # need the table should call /api/mikrotik/{router_id}/pppoe/active and
        # /api/mikrotik/active-sessions?router_id={id}.
        result.pop("active_pppoe_sessions", None)
        result["sessions_truncated"] = False

    result["cached"] = cached
    if cache_age_seconds is not None:
        result["cache_age_seconds"] = round(cache_age_seconds, 1)
    if stale:
        result["stale"] = True
    if refresh_in_progress:
        result["refresh_in_progress"] = True
    if retry_after_seconds is not None:
        result["retry_after_seconds"] = max(1, round(retry_after_seconds, 1))
    return result


def _health_payload_from_snapshot(
    *,
    latest_snapshot: Optional[BandwidthSnapshot],
    router_id: Optional[int],
    router_name: str,
    reason: str,
) -> dict:
    """Build a contract-compatible health payload from the latest snapshot."""
    snapshot_active_queues = 0
    active_hotspot_users = 0
    current_download_mbps = 0.0
    current_upload_mbps = 0.0
    snapshot_age = None

    if latest_snapshot:
        snapshot_active_queues = latest_snapshot.active_queues or 0
        persisted_hotspot = getattr(latest_snapshot, "active_hotspot_users", None)
        active_hotspot_users = (
            max(0, snapshot_active_queues)
            if persisted_hotspot is None
            else max(0, int(persisted_hotspot))
        )
        current_download_mbps = round((latest_snapshot.avg_download_bps or 0) / 1000000, 2)
        current_upload_mbps = round((latest_snapshot.avg_upload_bps or 0) / 1000000, 2)
        snapshot_age = (datetime.utcnow() - latest_snapshot.recorded_at).total_seconds()

    active_pppoe_users = max(0, snapshot_active_queues - active_hotspot_users)
    total_active_users = active_hotspot_users + active_pppoe_users

    return {
        "system": {
            "uptime": "",
            "version": "",
            "platform": "",
            "board_name": "",
            "architecture": "",
            "cpu": "",
            "cpu_count": 1,
            "cpu_frequency_mhz": 0,
        },
        "cpu_load_percent": 0,
        "memory": {
            "total_bytes": 0,
            "free_bytes": 0,
            "used_bytes": 0,
            "used_percent": 0,
        },
        "storage": {
            "total_bytes": 0,
            "free_bytes": 0,
            "used_bytes": 0,
            "used_percent": 0,
        },
        "health_sensors": {},
        "active_users": active_hotspot_users,
        "active_hotspot_users": active_hotspot_users,
        "active_pppoe_users": active_pppoe_users,
        "active_total_users": total_active_users,
        "_full_pppoe_sessions": [],
        "bandwidth": {
            "download_mbps": current_download_mbps,
            "upload_mbps": current_upload_mbps,
        },
        "snapshot_age_seconds": round(snapshot_age, 1) if snapshot_age else None,
        "router_id": router_id,
        "router_name": router_name,
        "generated_at": datetime.utcnow().isoformat(),
        "live": False,
        "fallback_reason": reason,
    }


def _health_payload_from_live_result(
    *,
    mikrotik_result: dict,
    latest_snapshot: Optional[BandwidthSnapshot],
    router_id: Optional[int],
    router_name: str,
) -> dict:
    """Build the public health payload from live RouterOS data plus DB snapshot counters."""
    resources = mikrotik_result.get("resources", {})
    health = mikrotik_result.get("health", {})
    pppoe_active = mikrotik_result.get("pppoe_active", {}) or {}

    if resources.get("error"):
        raise ValueError(resources["error"])

    res_data = resources.get("data", {})
    total_mem = res_data.get("total_memory", 1)
    free_mem = res_data.get("free_memory", 0)
    total_hdd = res_data.get("total_hdd_space", 1)
    free_hdd = res_data.get("free_hdd_space", 0)

    # Active users come from two different clocks:
    #   * Hotspot count   -> persisted on the snapshot (background job, ~min stale)
    #   * PPPoE count     -> live from ``/ppp/active/print`` on this very request
    # We do NOT derive hotspot from ``active_queues - live_pppoe`` anymore: the
    # combined ``active_queues`` is from time T, while live PPPoE is from now,
    # so subtraction can flip negative if PPPoE sessions reconnected in between
    # (that is the "pppoe(16) > total(14)" symptom). Instead we trust the
    # snapshot's persisted hotspot figure and add the live PPPoE on top, which
    # always yields a self-consistent total = hotspot + pppoe.
    snapshot_hotspot_users = 0
    current_download_mbps = 0.0
    current_upload_mbps = 0.0
    snapshot_age = None

    if latest_snapshot:
        persisted_hotspot = getattr(latest_snapshot, "active_hotspot_users", None)
        if persisted_hotspot is None:
            snapshot_hotspot_users = max(0, latest_snapshot.active_queues or 0)
        else:
            snapshot_hotspot_users = max(0, int(persisted_hotspot))
        current_download_mbps = round((latest_snapshot.avg_download_bps or 0) / 1000000, 2)
        current_upload_mbps = round((latest_snapshot.avg_upload_bps or 0) / 1000000, 2)
        snapshot_age = (datetime.utcnow() - latest_snapshot.recorded_at).total_seconds()

    active_hotspot_users = snapshot_hotspot_users
    if pppoe_active.get("skipped") and latest_snapshot:
        active_pppoe_users = max(0, (latest_snapshot.active_queues or 0) - active_hotspot_users)
    else:
        active_pppoe_users = (
            pppoe_active.get("count", len(pppoe_active.get("data", []) or []))
            if not pppoe_active.get("error")
            else 0
        )
    active_pppoe_sessions = (
        pppoe_active.get("data", []) if not pppoe_active.get("error") else []
    )
    total_active_users = active_hotspot_users + active_pppoe_users

    return {
        "system": {
            "uptime": res_data.get("uptime", ""),
            "version": res_data.get("version", ""),
            "platform": res_data.get("platform", ""),
            "board_name": res_data.get("board_name", ""),
            "architecture": res_data.get("architecture_name", ""),
            "cpu": res_data.get("cpu", ""),
            "cpu_count": res_data.get("cpu_count", 1),
            "cpu_frequency_mhz": res_data.get("cpu_frequency", 0),
        },
        "cpu_load_percent": res_data.get("cpu_load", 0),
        "memory": {
            "total_bytes": total_mem,
            "free_bytes": free_mem,
            "used_bytes": total_mem - free_mem,
            "used_percent": round(((total_mem - free_mem) / total_mem) * 100, 1) if total_mem > 0 else 0,
        },
        "storage": {
            "total_bytes": total_hdd,
            "free_bytes": free_hdd,
            "used_bytes": total_hdd - free_hdd,
            "used_percent": round(((total_hdd - free_hdd) / total_hdd) * 100, 1) if total_hdd > 0 else 0,
        },
        "health_sensors": health.get("data", {}),
        "active_users": active_hotspot_users,
        "active_hotspot_users": active_hotspot_users,
        "active_pppoe_users": active_pppoe_users,
        "active_total_users": total_active_users,
        "_full_pppoe_sessions": active_pppoe_sessions,
        "bandwidth": {
            "download_mbps": current_download_mbps,
            "upload_mbps": current_upload_mbps,
        },
        "snapshot_age_seconds": round(snapshot_age, 1) if snapshot_age else None,
        "router_id": router_id,
        "router_name": router_name,
        "generated_at": datetime.utcnow().isoformat(),
        "live": True,
    }


async def _refresh_health_cache_from_router(
    router_id: Optional[int],
    router_info: dict,
    router_name: str,
    cache_key,
) -> None:
    """Refresh a cold dashboard health cache without blocking the response."""
    global _health_cache
    try:
        latest_snapshot = None
        async with async_session() as db:
            snapshot_query = select(BandwidthSnapshot).order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
            if router_id:
                snapshot_query = snapshot_query.where(BandwidthSnapshot.router_id == router_id)
            latest_snapshot = (await db.execute(snapshot_query)).scalar_one_or_none()
            await db.commit()

        try:
            mikrotik_result = await asyncio.wait_for(
                run_mikrotik_health_async(router_info),
                timeout=10,
            )
        except asyncio.TimeoutError:
            if router_id and not latest_snapshot:
                async with async_session() as db:
                    await record_router_availability(db, router_id, False, "mikrotik_health_timeout")
                    await db.commit()
            return

        if mikrotik_result.get("error"):
            if router_id and not latest_snapshot:
                async with async_session() as db:
                    await record_router_availability(db, router_id, False, "mikrotik_health")
                    await db.commit()
            return

        if router_id:
            async with async_session() as db:
                await record_router_availability(db, router_id, True, "mikrotik_health")
                await db.commit()

        result = _health_payload_from_live_result(
            mikrotik_result=mikrotik_result,
            latest_snapshot=latest_snapshot,
            router_id=router_id,
            router_name=router_name,
        )
        _health_cache[cache_key] = {
            "data": result,
            "timestamp": datetime.utcnow(),
        }
    except Exception as exc:
        logger.warning("Background MikroTik health refresh failed for %s: %s", router_name, exc)
    finally:
        _health_refresh_inflight.discard(cache_key)

def _queue_health_cache_refresh(
    background_tasks: BackgroundTasks,
    router_id: Optional[int],
    router_info: dict,
    router_name: str,
    cache_key,
) -> dict:
    if cache_key in _health_refresh_inflight:
        return {"refresh_in_progress": True, "retry_after_seconds": 5}

    last_started = _health_refresh_last_started.get(cache_key)
    if last_started:
        elapsed = (datetime.utcnow() - last_started).total_seconds()
        retry_after = _health_refresh_retry_floor - elapsed
        if retry_after > 0:
            return {
                "refresh_in_progress": False,
                "retry_after_seconds": retry_after,
            }

    _health_refresh_inflight.add(cache_key)
    _health_refresh_last_started[cache_key] = datetime.utcnow()
    background_tasks.add_task(
        _refresh_health_cache_from_router,
        router_id,
        router_info,
        router_name,
        cache_key,
    )
    return {"refresh_in_progress": True, "retry_after_seconds": 5}


@router.get("/api/mikrotik/health")
async def get_mikrotik_health(
    background_tasks: BackgroundTasks,
    router_id: Optional[int] = None,
    include_sessions: bool = False,
    prefer_snapshot: bool = True,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get MikroTik router health metrics (CPU, memory, disk, uptime, user counts).
    
    Returns counts only by default. Per-session arrays are intentionally NOT
    included — they bloat the dashboard tile poll and become stale. Use the
    drill-down endpoints when you need them:
    
        GET /api/mikrotik/{router_id}/pppoe/active   -> live PPPoE sessions
        GET /api/mikrotik/active-sessions?router_id  -> live hotspot sessions
    
    Pass ``include_sessions=true`` to opt back into an inline (capped) PPPoE
    session array on this endpoint for backward compatibility. The array is
    capped at ``_HEALTH_MAX_INLINE_SESSIONS`` entries; ``sessions_truncated``
    indicates when callers should switch to the drill-down endpoint.

    ``prefer_snapshot`` defaults to true so dashboard tiles return immediately.
    If live health cache is only stale, it is served with refresh metadata while
    one throttled RouterOS refresh runs in the background. On a cold cache, the
    latest bandwidth snapshot is returned with the same refresh metadata.
    
    Active users and bandwidth come from background job data (more reliable).
    Fresh live health is cached briefly per router, then served stale while the
    dashboard revalidates in the background to avoid overloading MikroTik.
    """
    user = await get_current_user(token, db)
    global _health_cache
    
    cache_key = router_id if router_id else "default"
    
    # Fresh cache returns immediately. Stale cache is handled below after we
    # know the router credentials, so dashboard calls can revalidate in the
    # background without dropping back to blank snapshot-only system fields.
    cached_entry = _health_cache.get(cache_key)
    cached_age = None
    if cached_entry:
        cached_age = (datetime.utcnow() - cached_entry["timestamp"]).total_seconds()
        if cached_age < _health_cache_ttl:
            return _shape_health_response(
                cached_entry["data"],
                include_sessions=include_sessions,
                cached=True,
                cache_age_seconds=cached_age,
            )
    
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

        snapshot_query = select(BandwidthSnapshot).order_by(BandwidthSnapshot.recorded_at.desc()).limit(1)
        if router_id:
            snapshot_query = snapshot_query.where(BandwidthSnapshot.router_id == router_id)

        snapshot_result = await db.execute(snapshot_query)
        latest_snapshot = snapshot_result.scalar_one_or_none()

        if prefer_snapshot and not include_sessions:
            refresh_meta = _queue_health_cache_refresh(
                background_tasks,
                router_id,
                router_info,
                router_name,
                cache_key,
            )

            if cached_entry and cached_age is not None and cached_age < _health_cache_stale_ttl:
                return _shape_health_response(
                    cached_entry["data"],
                    include_sessions=False,
                    cached=True,
                    cache_age_seconds=cached_age,
                    stale=True,
                    refresh_in_progress=refresh_meta.get("refresh_in_progress", False),
                    retry_after_seconds=refresh_meta.get("retry_after_seconds"),
                )

            if latest_snapshot:
                snapshot_payload = _health_payload_from_snapshot(
                    latest_snapshot=latest_snapshot,
                    router_id=router_id,
                    router_name=router_name,
                    reason="dashboard_fast_snapshot",
                )
                return _shape_health_response(
                    snapshot_payload,
                    include_sessions=False,
                    cached=False,
                    cache_age_seconds=None,
                    stale=True,
                    refresh_in_progress=refresh_meta.get("refresh_in_progress", False),
                    retry_after_seconds=refresh_meta.get("retry_after_seconds"),
                )
        
        # Release the request's DB connection before slow RouterOS I/O. The
        # session can acquire a new connection below only if availability needs
        # to be persisted.
        await db.commit()

        # Run MikroTik operations in thread pool (non-blocking!)
        try:
            mikrotik_result = await asyncio.wait_for(
                run_mikrotik_health_async(router_info),
                timeout=10,
            )
        except asyncio.TimeoutError:
            if router_id and not latest_snapshot:
                await record_router_availability(db, router_id, False, "mikrotik_health_timeout")
            if cache_key in _health_cache:
                cached_entry = _health_cache[cache_key]
                age = (datetime.utcnow() - cached_entry["timestamp"]).total_seconds()
                return _shape_health_response(
                    cached_entry["data"],
                    include_sessions=include_sessions,
                    cached=True,
                    cache_age_seconds=age,
                    stale=True,
                )
            if latest_snapshot:
                fallback = _health_payload_from_snapshot(
                    latest_snapshot=latest_snapshot,
                    router_id=router_id,
                    router_name=router_name,
                    reason="live_health_timeout",
                )
                return _shape_health_response(
                    fallback,
                    include_sessions=include_sessions,
                    cached=False,
                    cache_age_seconds=None,
                    stale=True,
                )
            raise HTTPException(
                status_code=504,
                detail=f"Timed out fetching router health: {router_name}",
            )
        
        if mikrotik_result.get("error"):
            if router_id and not latest_snapshot:
                await record_router_availability(db, router_id, False, "mikrotik_health")
            # Return stale cache if available when router unreachable
            if cache_key in _health_cache:
                cached_entry = _health_cache[cache_key]
                age = (datetime.utcnow() - cached_entry["timestamp"]).total_seconds()
                return _shape_health_response(
                    cached_entry["data"],
                    include_sessions=include_sessions,
                    cached=True,
                    cache_age_seconds=age,
                    stale=True,
                )
            if latest_snapshot:
                fallback = _health_payload_from_snapshot(
                    latest_snapshot=latest_snapshot,
                    router_id=router_id,
                    router_name=router_name,
                    reason=mikrotik_result.get("error") or "live_health_failed",
                )
                return _shape_health_response(
                    fallback,
                    include_sessions=include_sessions,
                    cached=False,
                    cache_age_seconds=None,
                    stale=True,
                )
            raise HTTPException(status_code=503, detail=f"Failed to connect to router: {router_name}")

        if router_id:
            await record_router_availability(db, router_id, True, "mikrotik_health")
        
        try:
            result = _health_payload_from_live_result(
                mikrotik_result=mikrotik_result,
                latest_snapshot=latest_snapshot,
                router_id=router_id,
                router_name=router_name,
            )
        except ValueError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        
        # Always cache - we're using reliable DB data now
        _health_cache[cache_key] = {
            "data": result,
            "timestamp": datetime.utcnow()
        }
        
        return _shape_health_response(
            result,
            include_sessions=include_sessions,
            cached=False,
            cache_age_seconds=None,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching MikroTik health: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WALLED GARDEN MANAGEMENT
# ============================================================================

class WalledGardenIPRequest(BaseModel):
    dst_address: str = Field(..., description="IP address or CIDR, e.g. '203.0.113.10' or '203.0.113.0/24'")
    comment: str = "Added via API"

class WalledGardenDomainRequest(BaseModel):
    dst_host: str = Field(..., description="Domain or wildcard, e.g. 'example.com' or '*.example.com'")
    comment: str = "Added via API"


@router.get("/api/mikrotik/walled-garden")
async def get_walled_garden(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all walled garden entries (domain and IP-based) for a specific router."""
    try:
        current_user = await get_current_user(token, db)
        target_router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not target_router:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        host, user, pwd, port = target_router.ip_address, target_router.username, target_router.password, target_router.port

        def _fetch():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.get_walled_garden()
            finally:
                api.disconnect()

        await db.commit()
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
    router_id: int,
    body: WalledGardenIPRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Add an IP address to the walled garden (allows hotspot users to reach it before auth)."""
    try:
        current_user = await get_current_user(token, db)
        enforce_active_subscription(current_user)
        target_router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not target_router:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        host, user, pwd, port = target_router.ip_address, target_router.username, target_router.password, target_router.port

        def _add():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.add_walled_garden_ip(body.dst_address, comment=body.comment)
            finally:
                api.disconnect()

        await db.commit()
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
    router_id: int,
    body: WalledGardenDomainRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Add a domain to the walled garden (allows hotspot users to access it before auth)."""
    try:
        current_user = await get_current_user(token, db)
        enforce_active_subscription(current_user)
        target_router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not target_router:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        host, user, pwd, port = target_router.ip_address, target_router.username, target_router.password, target_router.port

        def _add():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.add_walled_garden_domain(body.dst_host, comment=body.comment)
            finally:
                api.disconnect()

        await db.commit()
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
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Remove an IP-based walled garden entry."""
    try:
        current_user = await get_current_user(token, db)
        enforce_active_subscription(current_user)
        target_router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not target_router:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        host, user, pwd, port = target_router.ip_address, target_router.username, target_router.password, target_router.port

        def _remove():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.remove_walled_garden_ip(entry_id)
            finally:
                api.disconnect()

        await db.commit()
        result = await asyncio.get_event_loop().run_in_executor(None, _remove)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing walled garden IP entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/mikrotik/walled-garden/domain/{entry_id}")
async def remove_walled_garden_domain_entry(
    entry_id: str,
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Remove a domain-based walled garden entry."""
    try:
        current_user = await get_current_user(token, db)
        enforce_active_subscription(current_user)
        target_router = await get_router_by_id(db, router_id, current_user.id, current_user.role.value)
        if not target_router:
            raise HTTPException(status_code=404, detail="Router not found or not accessible")
        host, user, pwd, port = target_router.ip_address, target_router.username, target_router.password, target_router.port

        def _remove():
            api = MikroTikAPI(host, user, pwd, port)
            if not api.connect():
                return {"error": "Failed to connect to MikroTik"}
            try:
                return api.remove_walled_garden_domain(entry_id)
            finally:
                api.disconnect()

        await db.commit()
        result = await asyncio.get_event_loop().run_in_executor(None, _remove)
        if result.get("error"):
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing walled garden domain entry: {e}")
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
        enforce_active_subscription(current_user)
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

        await db.commit()
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
        await db.commit()
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
        await db.commit()
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
        user = await get_current_user(token, db)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        router_name = None
        if router_id:
            router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
            if not router_obj:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            router_name = router_obj.name
            query = select(BandwidthSnapshot).where(
                BandwidthSnapshot.recorded_at >= since,
                BandwidthSnapshot.router_id == router_id
            )
        else:
            if user.role.value == "admin":
                query = select(BandwidthSnapshot).where(BandwidthSnapshot.recorded_at >= since)
            else:
                owned_router_ids = select(Router.id).where(Router.user_id == user.id)
                query = select(BandwidthSnapshot).where(
                    BandwidthSnapshot.recorded_at >= since,
                    BandwidthSnapshot.router_id.in_(owned_router_ids)
                )
        
        result = await db.execute(query.order_by(BandwidthSnapshot.recorded_at.asc()))
        snapshots = result.scalars().all()
        
        data = []
        for s in snapshots:
            hotspot_upload_mb = _bytes_to_mb(getattr(s, "hotspot_upload_bytes", 0))
            hotspot_download_mb = _bytes_to_mb(getattr(s, "hotspot_download_bytes", 0))
            pppoe_upload_mb = _bytes_to_mb(getattr(s, "pppoe_upload_bytes", 0))
            pppoe_download_mb = _bytes_to_mb(getattr(s, "pppoe_download_bytes", 0))
            active_hotspot = int(getattr(s, "active_hotspot_users", 0) or 0)
            active_pppoe = max(0, int(s.active_queues or 0) - active_hotspot)
            data.append({
                "timestamp": s.recorded_at.isoformat(),
                "routerId": s.router_id,
                "totalUploadMbps": round(s.total_upload_bps / 1000000, 2),
                "totalDownloadMbps": round(s.total_download_bps / 1000000, 2),
                "avgUploadMbps": round(s.avg_upload_bps / 1000000, 2),
                "avgDownloadMbps": round(s.avg_download_bps / 1000000, 2),
                "activeQueues": s.active_queues,
                "activeSessions": s.active_sessions,
                "activeHotspotUsers": active_hotspot,
                "activePppoeUsers": active_pppoe,
                "hotspotUploadMB": hotspot_upload_mb,
                "hotspotDownloadMB": hotspot_download_mb,
                "hotspotTotalMB": round(hotspot_upload_mb + hotspot_download_mb, 2),
                "pppoeUploadMB": pppoe_upload_mb,
                "pppoeDownloadMB": pppoe_download_mb,
                "pppoeTotalMB": round(pppoe_upload_mb + pppoe_download_mb, 2),
                "trackedUploadMB": round(hotspot_upload_mb + pppoe_upload_mb, 2),
                "trackedDownloadMB": round(hotspot_download_mb + pppoe_download_mb, 2),
                "trackedTotalMB": round(
                    hotspot_upload_mb + hotspot_download_mb + pppoe_upload_mb + pppoe_download_mb,
                    2,
                ),
            })
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "history": data,
            "count": len(data),
            "periodHours": hours,
            "generatedAt": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
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
        user = await get_current_user(token, db)
        
        router_name = None
        if router_id:
            router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
            if not router_obj:
                raise HTTPException(status_code=404, detail="Router not found or not accessible")
            router_name = router_obj.name

        if user.role.value == "admin" and not router_id:
            owned_router_filter = None
        else:
            owned_router_ids = select(Router.id).where(Router.user_id == user.id)
            owned_router_filter = Customer.router_id.in_(owned_router_ids)

        base_join = select(
            UserBandwidthUsage,
            Customer,
            Plan.connection_type.label("connection_type"),
        ).join(
            Customer, UserBandwidthUsage.customer_id == Customer.id
        ).outerjoin(Plan, Customer.plan_id == Plan.id)

        if router_id:
            query = base_join.where(
                Customer.router_id == router_id
            ).order_by(UserBandwidthUsage.download_bytes.desc()).limit(limit)
        elif owned_router_filter is not None:
            query = base_join.where(
                owned_router_filter
            ).order_by(UserBandwidthUsage.download_bytes.desc()).limit(limit)
        else:
            query = base_join.order_by(
                UserBandwidthUsage.download_bytes.desc()
            ).limit(limit)
        
        result = await db.execute(query)
        usage_records = result.all()
        
        users = []
        for u, customer, connection_type in usage_records:
            total_bytes = u.upload_bytes + u.download_bytes
            connection_value = (
                connection_type.value
                if hasattr(connection_type, "value")
                else connection_type
            )
            if not connection_value:
                connection_value = "pppoe" if str(u.mac_address or "").startswith("pppoe:") else "hotspot"
            identifier = (
                customer.pppoe_username
                if connection_value == "pppoe"
                else customer.mac_address
            )
            
            users.append({
                "mac": u.mac_address,
                "target": u.target_ip,
                "queueName": u.queue_name,
                "connectionType": connection_value,
                "serviceLabel": "PPPoE" if connection_value == "pppoe" else "Hotspot",
                "identifier": identifier,
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
                "customerName": customer.name,
                "customerPhone": customer.phone,
                "routerId": customer.router_id
            })
        
        if router_id:
            count_query = select(func.count()).select_from(UserBandwidthUsage).join(
                Customer, UserBandwidthUsage.customer_id == Customer.id
            ).where(Customer.router_id == router_id)
        elif owned_router_filter is not None:
            count_query = select(func.count()).select_from(UserBandwidthUsage).join(
                Customer, UserBandwidthUsage.customer_id == Customer.id
            ).where(owned_router_filter)
        else:
            count_query = select(func.count()).select_from(UserBandwidthUsage).join(
                Customer, UserBandwidthUsage.customer_id == Customer.id
            )
        count_result = await db.execute(count_query)
        total_count = count_result.scalar() or 0
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "topUsers": users,
            "totalTracked": total_count,
            "totalQueues": total_count,
            "generatedAt": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching top users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# PPPoE MONITORING
# =============================================================================

def _get_active_pppoe_sync(router_info: dict) -> dict:
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "Failed to connect to router"}
    try:
        return api.get_active_pppoe_sessions()
    finally:
        api.disconnect()


@router.get("/api/mikrotik/{router_id}/pppoe/active")
async def get_active_pppoe_sessions(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get active PPPoE sessions from a router."""
    try:
        user = await get_current_user(token, db)
        router_obj = await get_router_by_id(db, router_id, user.id)
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")

        router_info = {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port,
        }

        router_name = router_obj.name
        await db.commit()
        result = await asyncio.to_thread(_get_active_pppoe_sync, router_info)

        if result.get("error"):
            raise HTTPException(status_code=502, detail=result["error"])

        return {
            "router_id": router_id,
            "router_name": router_name,
            "sessions": result.get("data", []),
            "count": result.get("count", 0),
            "generated_at": datetime.utcnow().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching PPPoE sessions for router {router_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

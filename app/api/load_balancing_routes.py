"""Multi-WAN PCC load-balancing endpoints (hotspot-safe).

Per-router actions over the live MikroTik API, following the repo's canonical
mutation pattern (see router_operations.set_dual_ports): ownership check via
get_router_by_id -> 404, enforce_active_subscription, plain router_info dict,
COMMIT THE DB SESSION BEFORE ANY ROUTER I/O (Database Session Discipline),
per-router lock (router_locks) around a worker thread, and DB state persisted
only AFTER the router accepted the change.

The actual RouterOS logic lives in app/services/mikrotik_lb.py (ported from the
bench-certified setup-dual-wan-lb skill scripts).
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Customer, Router
from app.services import mikrotik_lb
from app.services.auth import get_current_user, verify_token
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_availability import record_router_availability
from app.services.router_helpers import get_router_by_id
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger(__name__)

router = APIRouter(tags=["load-balancing"])

_WAN_PORT_RE = re.compile(r"^(ether|sfp)[0-9]+$")

# Read-only / short operations.
LB_OP_TIMEOUT_SECONDS = 120
# Enable runs preflight + apply (6s settle) + up to 3 port conversions
# (40s DHCP wait + 8s settle each) + seed + verify on one connection.
LB_ENABLE_TIMEOUT_SECONDS = 420


class LBPreflightRequest(BaseModel):
    wan_ports: List[str]


class LBEnableRequest(BaseModel):
    wan_ports: List[str]
    confirm: bool = False


class LBDisableRequest(BaseModel):
    confirm: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_role(user) -> Optional[str]:
    role = getattr(user, "role", None)
    return role.value if hasattr(role, "value") else role


def _validate_wan_ports(wan_ports: List[str], router_obj: Router) -> None:
    if not (mikrotik_lb.MIN_WAN_PORTS <= len(wan_ports) <= mikrotik_lb.MAX_WAN_PORTS):
        raise HTTPException(
            status_code=422,
            detail=(
                f"wan_ports must list between {mikrotik_lb.MIN_WAN_PORTS} and "
                f"{mikrotik_lb.MAX_WAN_PORTS} ports"
            ),
        )
    if len(set(wan_ports)) != len(wan_ports):
        raise HTTPException(status_code=422, detail="wan_ports must be distinct")
    bad = [p for p in wan_ports if not _WAN_PORT_RE.match(p or "")]
    if bad:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid WAN port name(s): {', '.join(bad)} (expected etherN or sfpN)",
        )
    customer_ports = set(router_obj.pppoe_ports or []) \
        | set(router_obj.plain_ports or []) \
        | set(router_obj.dual_ports or [])
    overlap = sorted(customer_ports.intersection(wan_ports))
    if overlap:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Port(s) {', '.join(overlap)} serve customers "
                "(PPPoE/plain/dual mode) and cannot be used as WAN ports"
            ),
        )


def _router_info(router_obj: Router) -> dict:
    return {
        "ip": router_obj.ip_address,
        "username": router_obj.username,
        "password": router_obj.password,
        "port": router_obj.port,
    }


async def _run_locked_router_thread(
    router_obj: Router,
    sync_func,
    *args,
    timeout_seconds: float = LB_OP_TIMEOUT_SECONDS,
) -> dict:
    """One live router mutation at a time per router (mirrors router_operations)."""
    from app.services.mikrotik_background import router_locks

    router_key = f"{router_obj.ip_address}:{router_obj.port}"
    try:
        async with router_locks.acquire(router_key):
            return await asyncio.wait_for(
                asyncio.to_thread(sync_func, *args), timeout=timeout_seconds
            )
    except asyncio.TimeoutError:
        return {"error": "timeout"}


def _raise_for_router_error(result: dict, router_obj: Router) -> None:
    err = result.get("error")
    if not err:
        return
    if err == "connect_failed":
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to router: {router_obj.name}",
        )
    if err == "busy":
        raise HTTPException(
            status_code=429,
            detail=result.get("detail") or "Router is busy; retry shortly",
        )
    if err == "timeout":
        raise HTTPException(status_code=504, detail="Router operation timed out")
    raise HTTPException(
        status_code=502,
        detail={"message": "command_failed", "error": err},
    )


async def _record_availability(router_id: int, result: dict) -> None:
    """Availability telemetry in its own short session (never the caller's)."""
    err = result.get("error")
    if err == "connect_failed":
        await record_router_availability(None, router_id, False, "load_balancing")
    elif err not in ("timeout", "busy"):
        await record_router_availability(None, router_id, True, "load_balancing")


# ---------------------------------------------------------------------------
# Sync workers (run in a thread under the per-router lock)
# ---------------------------------------------------------------------------

def _connect(router_info: dict, timeout: int = 45) -> MikroTikAPI:
    return MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=timeout,
        connect_timeout=8,
    )


def _lb_preflight_sync(router_info: dict, wan_ports: List[str]) -> dict:
    api = _connect(router_info, timeout=30)
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        return mikrotik_lb.lb_preflight(api, wan_ports)
    finally:
        api.disconnect()


def _lb_enable_sync(router_info: dict, wan_ports: List[str],
                    active_customers: List[dict]) -> dict:
    """preflight -> apply -> convert linked secondary ports -> seed -> verify,
    all on one connection."""
    api = _connect(router_info)
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        report: dict = {
            "preflight": None, "apply": None, "convert": {},
            "converted_ports": [], "dormant_ports": [],
            "seed": None, "verify": None,
        }
        pre = mikrotik_lb.lb_preflight(api, wan_ports)
        report["preflight"] = pre
        if pre.get("blockers"):
            report["error"] = "preflight_blocked"
            return report

        apply_report = mikrotik_lb.lb_apply(api, wan_ports)
        report["apply"] = apply_report
        if apply_report.get("aborted") or not apply_report.get("success"):
            report["error"] = apply_report.get("aborted") or "apply reported failed steps"
            return report

        for idx, port in enumerate(wan_ports[1:], start=1):
            port_state = (pre.get("per_port") or {}).get(port) or {}
            if port_state.get("link") == "true":
                conv = mikrotik_lb.lb_convert_port(
                    api, port, idx, wan1_port=wan_ports[0]
                )
                report["convert"][port] = conv
                if conv.get("success") and not conv.get("aborted"):
                    report["converted_ports"].append(port)
                else:
                    report["dormant_ports"].append(port)
            else:
                # No link yet: apply already made its to_wanX table fall back
                # onto the next WAN, so leaving it dormant is safe.
                report["dormant_ports"].append(port)

        report["seed"] = mikrotik_lb.lb_seed_paid(api, active_customers)
        report["verify"] = mikrotik_lb.lb_verify(api)
        report["success"] = True
        return report
    finally:
        api.disconnect()


def _lb_rollback_sync(router_info: dict) -> dict:
    api = _connect(router_info)
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        return mikrotik_lb.lb_rollback(api)
    finally:
        api.disconnect()


def _lb_verify_sync(router_info: dict) -> dict:
    api = _connect(router_info, timeout=30)
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        return mikrotik_lb.lb_verify(api)
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/routers/{router_id}/load-balancing")
async def get_load_balancing_status(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """DB state only — no router I/O; cheap."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, _user_role(user))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    return {
        "success": True,
        "router_id": router_id,
        "enabled": bool(router_obj.lb_enabled),
        "config": router_obj.lb_config,
        "applied_at": (
            router_obj.lb_applied_at.isoformat() if router_obj.lb_applied_at else None
        ),
    }


@router.post("/api/routers/{router_id}/load-balancing/preflight")
async def preflight_load_balancing(
    router_id: int,
    request: LBPreflightRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Read-only readiness check on the live router for the given WAN ports."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await get_router_by_id(db, router_id, user.id, _user_role(user))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    _validate_wan_ports(request.wan_ports, router_obj)

    router_info = _router_info(router_obj)
    await db.commit()  # release the DB before router I/O

    result = await _run_locked_router_thread(
        router_obj, _lb_preflight_sync, router_info, request.wan_ports
    )
    await _record_availability(router_id, result)
    _raise_for_router_error(result, router_obj)

    return {
        "success": not result.get("blockers"),
        "router_id": router_id,
        "wan_ports": request.wan_ports,
        "blockers": result.get("blockers", []),
        "warnings": result.get("warnings", []),
        "verdict": result.get("verdict"),
        "preflight": result,
    }


@router.post("/api/routers/{router_id}/load-balancing/enable")
async def enable_load_balancing(
    router_id: int,
    request: LBEnableRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """preflight -> apply -> convert secondary ports with link -> seed LB_PAID
    -> verify. DB state is persisted only after the router accepted the setup."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await get_router_by_id(db, router_id, user.id, _user_role(user))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    if not request.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to enable load balancing on this router",
        )
    _validate_wan_ports(request.wan_ports, router_obj)

    router_info = _router_info(router_obj)
    # Active paid customers for LB_PAID seeding — loaded in the SHORT session
    # before any router I/O (Database Session Discipline).
    rows = (
        await db.execute(
            select(Customer).where(
                Customer.router_id == router_id,
                Customer.expiry.isnot(None),
                Customer.expiry > datetime.utcnow(),
                Customer.mac_address.isnot(None),
            )
        )
    ).scalars().all()
    active_customers = [
        {"mac": (c.mac_address or "").upper(), "expiry": c.expiry}
        for c in rows
        if c.mac_address
    ]
    await db.commit()  # release the DB before router I/O

    result = await _run_locked_router_thread(
        router_obj,
        _lb_enable_sync,
        router_info,
        request.wan_ports,
        active_customers,
        timeout_seconds=LB_ENABLE_TIMEOUT_SECONDS,
    )
    await _record_availability(router_id, result)

    if result.get("error") == "preflight_blocked":
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Preflight found blockers; nothing was changed on the router",
                "blockers": (result.get("preflight") or {}).get("blockers", []),
                "preflight": result.get("preflight"),
            },
        )
    _raise_for_router_error(result, router_obj)

    # Persist only now that the router accepted the configuration.
    applied_at = datetime.utcnow()
    router_obj.lb_enabled = True
    router_obj.lb_config = {
        "wan_ports": list(request.wan_ports),
        "applied_at": applied_at.isoformat(),
    }
    router_obj.lb_applied_at = applied_at
    await db.commit()

    verify_report = result.get("verify") or {}
    preflight_report = result.get("preflight") or {}
    warnings = list(preflight_report.get("warnings", [])) + list(
        verify_report.get("warnings", [])
    )
    converted = result.get("converted_ports", [])
    dormant = result.get("dormant_ports", [])
    return {
        "success": True,
        "router_id": router_id,
        "enabled": True,
        "wan_ports": request.wan_ports,
        "converted_ports": converted,
        "dormant_ports": dormant,
        "applied_at": applied_at.isoformat(),
        "warnings": warnings,
        "preflight": preflight_report,
        "apply": result.get("apply"),
        "convert": result.get("convert", {}),
        "seed": result.get("seed"),
        "verify": verify_report,
        "message": (
            f"Load balancing enabled on {', '.join(request.wan_ports)}"
            + (f"; converted: {', '.join(converted)}" if converted else "")
            + (
                f"; dormant (no link yet, will fall back to WAN1): {', '.join(dormant)}"
                if dormant
                else ""
            )
        ),
    }


@router.post("/api/routers/{router_id}/load-balancing/disable")
async def disable_load_balancing(
    router_id: int,
    request: LBDisableRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Rollback in the safe order (marks first, guard last), restore fasttrack,
    remove LB routes/lists/tables. Keeps lb_config for easy re-enable."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await get_router_by_id(db, router_id, user.id, _user_role(user))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")
    if not request.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to disable load balancing on this router",
        )

    router_info = _router_info(router_obj)
    await db.commit()  # release the DB before router I/O

    result = await _run_locked_router_thread(
        router_obj, _lb_rollback_sync, router_info
    )
    await _record_availability(router_id, result)
    _raise_for_router_error(result, router_obj)

    router_obj.lb_enabled = False
    router_obj.lb_applied_at = None  # KEEP lb_config for easy re-enable
    await db.commit()

    return {
        "success": True,
        "router_id": router_id,
        "enabled": False,
        "config": router_obj.lb_config,
        "rollback": result,
        "message": "Load balancing disabled; router back on plain WAN1",
    }


@router.post("/api/routers/{router_id}/load-balancing/verify")
async def verify_load_balancing(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Live verification (counters, flow attribution, LB_PAID safety) + DB state."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    router_obj = await get_router_by_id(db, router_id, user.id, _user_role(user))
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    router_info = _router_info(router_obj)
    enabled = bool(router_obj.lb_enabled)
    config = router_obj.lb_config
    applied_at = (
        router_obj.lb_applied_at.isoformat() if router_obj.lb_applied_at else None
    )
    await db.commit()  # release the DB before router I/O

    result = await _run_locked_router_thread(
        router_obj, _lb_verify_sync, router_info
    )
    await _record_availability(router_id, result)
    _raise_for_router_error(result, router_obj)

    return {
        "success": bool(result.get("success")),
        "router_id": router_id,
        "enabled": enabled,
        "config": config,
        "applied_at": applied_at,
        "verify": result,
    }

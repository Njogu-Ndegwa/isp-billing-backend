"""Turn on a saved load-balancing WAN by itself once its line works.

A reseller can save a load-balancing setup before the extra line's cable
works; that port is left dormant (no routes, its traffic falls back to the
working line). Before this job it only joined when someone pressed "Finish
setup" in the dashboard. Router 542 (2026-11-18) was enabled with ether5
dormant and stayed that way after the line came up.

Every LB_AUTO_ACTIVATE_INTERVAL_SECONDS this job does a light read-only check
of each load-balanced router that has dormant WAN ports. A port becomes a
candidate only after LB_AUTO_ACTIVATE_STABLE_CHECKS consecutive checks with
the link up, no new link drops, and (once it has a DHCP client) a bound lease.
Then it runs the exact dashboard enable path (_lb_enable_sync: preflight with
blockers, apply, dead-man-protected convert, per-line internet probe, LB_PAID
seed, rule-order verify) and persists the result in the same step, so no
second code path can drift from the reviewed one. A line that converts but has
no internet stays staged (enable leaves it dormant) and is not retried for
LB_AUTO_ACTIVATE_RETRY_BACKOFF, so the job never flaps a port.

Going the other way needs nothing from here: a working line that dies is
dropped by the routes' check-gateway, and traffic moves to the other lines.

Locks: the per-router lock only (acquire_router_only, which still yields to a
waiting dashboard user), never the shared fleet slots. DB sessions are short
and closed before any RouterOS I/O (Database Session Discipline).
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select

logger = logging.getLogger(__name__)

LB_AUTO_ACTIVATE_INTERVAL_SECONDS = 120
LB_AUTO_ACTIVATE_STABLE_CHECKS = 3
LB_AUTO_ACTIVATE_RETRY_BACKOFF = timedelta(minutes=30)
LB_AUTO_ACTIVATE_MAX_ROUTERS_PER_RUN = 10
LB_AUTO_ACTIVATE_ENABLE_TIMEOUT_SECONDS = 420
LOCK_HOLDER = "load-balancing auto-activation"

_running = False
# (router_id, port) -> {"ok": consecutive stable checks, "link_downs": last count}
_stability: Dict[Tuple[int, str], dict] = {}
# router_id -> when an activation last ran (success or not)
_last_attempt: Dict[int, datetime] = {}


def reset_state() -> None:
    """Forget in-memory stability counters (tests)."""
    global _running
    _running = False
    _stability.clear()
    _last_attempt.clear()


# ---------------------------------------------------------------------------
# RouterOS side (sync, worker thread)
# ---------------------------------------------------------------------------

def _port_has_routes(routes: List[dict], port: str, wan_index: int) -> bool:
    """True when the port already carries managed routes (converted, live)."""
    from app.services import mikrotik_lb

    probe = mikrotik_lb._probe_comment(port)
    own_table = mikrotik_lb._table_route_comment(wan_index)
    for r in routes:
        comment = r.get("comment") or ""
        if comment == probe:
            return True
        if comment == own_table and (r.get("gateway") or "").endswith("%" + port):
            return True  # RouterOS 6 direct mode
    return False


def _dormant_check_sync(router_info: dict, wan_ports: List[str]) -> dict:
    """Read-only: the state of every secondary WAN port."""
    from app.services import mikrotik_lb
    from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"],
        router_info["port"], timeout=20, connect_timeout=5, lane=LANE_BACKGROUND,
    )
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        rd = mikrotik_lb._rd
        ifs = {i.get("name"): i for i in rd(api, "/interface/print",
                                            ["name", "running", "link-downs"])}
        bridged = {p.get("interface") for p in rd(api, "/interface/bridge/port/print",
                                                  ["interface", "bridge"])}
        dhcp = {d.get("interface"): d for d in rd(api, "/ip/dhcp-client/print")}
        routes = rd(api, "/ip/route/print", ["comment", "gateway"])
        ports = {}
        for idx, port in enumerate(wan_ports[1:], start=1):
            iface = ifs.get(port) or {}
            client = dhcp.get(port)
            ports[port] = {
                "running": iface.get("running") == "true",
                "link_downs": mikrotik_lb._int_or_none(iface.get("link-downs")),
                "in_bridge": port in bridged,
                "dhcp_status": (client or {}).get("status") if client else None,
                "has_routes": _port_has_routes(routes, port, idx),
            }
        return {"ports": ports}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Decision (pure)
# ---------------------------------------------------------------------------

def update_stability(router_id: int, ports: Dict[str, dict]) -> List[str]:
    """Record one check; return the dormant ports that are now stable enough."""
    ready = []
    for port, st in ports.items():
        key = (router_id, port)
        if st.get("has_routes"):
            _stability.pop(key, None)  # live (or check-gateway handles it)
            continue
        prev = _stability.get(key) or {"ok": 0, "link_downs": None}
        stable = bool(st.get("running"))
        if stable and prev["link_downs"] is not None and st.get("link_downs") is not None:
            stable = st["link_downs"] == prev["link_downs"]
        if stable and st.get("dhcp_status") is not None:
            # Already out of the LAN with a DHCP client: the modem must hand out a lease.
            stable = st["dhcp_status"] == "bound"
        ok = prev["ok"] + 1 if stable else 0
        _stability[key] = {"ok": ok, "link_downs": st.get("link_downs")}
        if ok >= LB_AUTO_ACTIVATE_STABLE_CHECKS:
            ready.append(port)
    return ready


def dormant_ports(ports: Dict[str, dict]) -> List[str]:
    return [p for p, st in ports.items() if not st.get("has_routes")]


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

async def _load_active_customers(db, router_id: int) -> List[dict]:
    """Same seed list the dashboard enable builds."""
    from app.db.models import Customer
    from app.services.customer_grace import access_prefilter, effective_expiry, has_access_time

    now = datetime.utcnow()
    rows = (await db.execute(
        select(Customer).where(
            Customer.router_id == router_id,
            Customer.expiry.isnot(None),
            access_prefilter(now),
            Customer.mac_address.isnot(None),
        )
    )).scalars().all()
    return [{"mac": (c.mac_address or "").upper(), "expiry": effective_expiry(c)}
            for c in rows if c.mac_address and has_access_time(c, now)]


async def _persist(router_id: int, wan_ports: List[str], result: dict) -> None:
    from app.db import database as db_module
    from app.db.models import Router

    async with db_module.async_session() as db:
        router = await db.get(Router, router_id)
        if router is None or not router.lb_enabled:
            return  # disabled meanwhile: the router lock kept us apart; keep its state
        applied_at = datetime.utcnow()
        config = dict(router.lb_config or {})
        config.update({
            "wan_ports": list(wan_ports),
            "applied_at": applied_at.isoformat(),
            "dormant_ports": list(result.get("dormant_ports") or []),
        })
        router.lb_config = config
        router.lb_applied_at = applied_at
        await db.commit()


async def _record_event(router_id: int, user_id: Optional[int], result: dict,
                        ready: List[str]) -> None:
    from app.services.customer_events import record_customer_event

    converted = list(result.get("converted_ports") or [])
    waiting = list(result.get("dormant_ports") or [])
    if result.get("error"):
        severity, event, msg = "warning", "lb_wan_auto_activation_failed", (
            f"Load balancing: tried to switch on {', '.join(ready)} automatically "
            f"but it did not complete ({result.get('error')}); traffic stays on the "
            "working line"
        )
    elif converted:
        severity, event, msg = "info", "lb_wan_auto_activated", (
            f"Load balancing: {', '.join(converted)} came online and was switched on "
            "automatically" + (f"; still waiting for {', '.join(waiting)}" if waiting else "")
        )
    else:
        severity, event, msg = "info", "lb_wan_auto_activation_staged", (
            f"Load balancing: {', '.join(ready)} has a stable link but no working "
            "internet yet; left waiting, traffic stays on the working line"
        )
    await record_customer_event(
        None, event, msg, category="change", severity=severity, source="system",
        user_id=user_id, router_id=router_id,
        details={"ready_ports": ready, "converted_ports": converted,
                 "dormant_ports": waiting, "no_internet_ports": result.get("no_internet_ports"),
                 "error": result.get("error")},
    )


async def _activate(bundle: dict, ready: List[str]) -> dict:
    from app.api.load_balancing_routes import _lb_enable_sync
    from app.db import database as db_module
    from app.services.mikrotik_background import router_locks

    router_id = bundle["id"]
    async with db_module.async_session() as db:
        customers = await _load_active_customers(db, router_id)
        await db.commit()  # release the DB before router I/O
    _last_attempt[router_id] = datetime.utcnow()
    async with router_locks.acquire_router_only(bundle["router_key"], holder=LOCK_HOLDER):
        # Held until the worker finishes, even if the wait below times out:
        # never two writers on one router.
        worker = asyncio.ensure_future(asyncio.to_thread(
            _lb_enable_sync, bundle["router_info"], bundle["wan_ports"], customers,
        ))
        try:
            result = await asyncio.wait_for(asyncio.shield(worker),
                                            LB_AUTO_ACTIVATE_ENABLE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            result = await worker
    for port in ready:
        _stability.pop((router_id, port), None)
    if not result.get("error"):
        await _persist(router_id, bundle["wan_ports"], result)
    await _record_event(router_id, bundle.get("user_id"), result, ready)
    logger.info("[LB-AUTO] Router %s: ready=%s converted=%s dormant=%s error=%s",
                router_id, ready, result.get("converted_ports"),
                result.get("dormant_ports"), result.get("error"))
    return result


async def _check_router(bundle: dict) -> Optional[dict]:
    from app.services.mikrotik_background import router_locks

    async with router_locks.acquire_router_only(bundle["router_key"], holder=LOCK_HOLDER):
        state = await asyncio.wait_for(
            asyncio.to_thread(_dormant_check_sync, bundle["router_info"], bundle["wan_ports"]),
            60,
        )
    if state.get("error"):
        return None
    ports = state["ports"]
    if not dormant_ports(ports):
        await _mark_no_dormant(bundle["id"])
        return None
    ready = update_stability(bundle["id"], ports)
    if not ready:
        return None
    last = _last_attempt.get(bundle["id"])
    if last and datetime.utcnow() - last < LB_AUTO_ACTIVATE_RETRY_BACKOFF:
        return None
    return await _activate(bundle, ready)


async def _mark_no_dormant(router_id: int) -> None:
    """Every configured line is live: later runs skip this router without I/O."""
    from app.db import database as db_module
    from app.db.models import Router

    async with db_module.async_session() as db:
        router = await db.get(Router, router_id)
        if router is None or not router.lb_enabled:
            return
        config = dict(router.lb_config or {})
        if config.get("dormant_ports") == []:
            return
        config["dormant_ports"] = []
        router.lb_config = config
        await db.commit()


async def auto_activate_dormant_wans_background() -> None:
    """APScheduler job."""
    global _running
    if _running:
        return
    from app.db import database as db_module
    from app.db.models import Router
    from app.services.mikrotik_background import (
        _background_db_pool_is_busy,
        _router_recently_offline,
    )

    if _background_db_pool_is_busy("LB-AUTO"):
        return
    _running = True
    try:
        now = datetime.utcnow()
        bundles = []
        async with db_module.async_session() as db:
            routers = (await db.execute(
                select(Router).where(Router.lb_enabled == True)  # noqa: E712
                .order_by(Router.id)
            )).scalars().all()
            for r in routers:
                config = r.lb_config or {}
                wan_ports = list(config.get("wan_ports") or [])
                if len(wan_ports) < 2:
                    continue
                # Saved with every line live: nothing to watch. A missing key
                # (saved before this job existed) means "unknown": check it.
                if config.get("dormant_ports") == []:
                    continue
                if _router_recently_offline(r, now):
                    continue
                bundles.append({
                    "id": r.id,
                    "user_id": r.user_id,
                    "router_key": f"{r.ip_address}:{r.port}",
                    "router_info": {"ip": r.ip_address, "username": r.username,
                                    "password": r.password, "port": r.port},
                    "wan_ports": wan_ports,
                })
                if len(bundles) >= LB_AUTO_ACTIVATE_MAX_ROUTERS_PER_RUN:
                    break
            await db.commit()  # release the DB before router I/O
        for bundle in bundles:  # one router at a time: this job is light by design
            try:
                await _check_router(bundle)
            except Exception as exc:
                logger.warning("[LB-AUTO] Router %s check failed: %s", bundle["id"], exc)
    finally:
        _running = False

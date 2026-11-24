"""Server-side health poll for routers that send no health readings.

About 40 online routers never push health: hAP lite / hAP mini were kept off
the real-time push agent for CPU reasons (realtime_push_installer.py), and
routers without an encrypted management tunnel cannot push at all. Without a
reading they have no CPU/memory graph and are missing from the Router load
ranking. This job reads them from the server every ~5 minutes and stores each
reading through ``router_health.record(..., source='poll')``, so it folds into
router_metric_buckets exactly like a push.

Cost, measured on four live hAP lites (2026-11-24, Dennis agreed the cadence):
login + ``/system/resource`` + ``/interface ?name=<wan>`` takes ~1 s and about
0.2 CPU-seconds, usually invisible in 1 s CPU samples. The default-route read
that finds the WAN port is the expensive part on ROS 6 (up to 1.4 s at 90%
CPU), so the WAN name is resolved once and cached for a day.

Rules:
* Only routers that are online, owner not cut off, and have no push/SNMP
  reading in the last 10 minutes. A router that starts pushing drops out on
  its own.
* Back-off: a router whose last poll read >= 85% CPU waits 15 minutes.
* Repeated failures (unreachable, legacy login) back off for 30 minutes.
* A router whose lock is held (payment provisioning, cleanup) is skipped this
  round, never waited on.
* Event loop only (AsyncNativeAPI): no executor threads, which payments share.
* DB session discipline: targets are read in one short session that is closed
  before any RouterOS I/O; each reading is written by router_health.record in
  its own short session.
* Readings do not feed the CPU overload alerts: 5-15 minute samples cannot
  show "sustained" load the way the 2-minute push does.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import Router, RouterAuthMethod, RouterHealth, User
from app.services import router_health
from app.services.native_router_api import AsyncNativeAPI

logger = logging.getLogger(__name__)

SOURCE_POLL = router_health.SOURCE_POLL

OTHER_SOURCE_FRESH = timedelta(minutes=10)   # a push/SNMP reading this recent wins
MIN_INTERVAL = timedelta(minutes=4)          # never twice inside one 5-min cadence
BUSY_CPU_PERCENT = 85
BUSY_INTERVAL = timedelta(minutes=15) - timedelta(seconds=30)
FAILURES_BEFORE_BACKOFF = 3
FAILURE_BACKOFF = timedelta(minutes=30)
WAN_CACHE_TTL = timedelta(hours=24)

CONCURRENCY = 4
ROUTER_TIMEOUT_SECONDS = 20
RUN_BUDGET_SECONDS = 150

RESOURCE_PROPS = ("cpu-load,free-memory,total-memory,free-hdd-space,total-hdd-space,"
                  "uptime,version,board-name")

# Process memory: a restart only costs one route read per router.
_wan_cache: dict[int, tuple[Optional[str], datetime]] = {}
_failures: dict[int, tuple[int, datetime]] = {}


@dataclass
class Target:
    router_id: int
    ip_address: str
    username: str
    password: str
    port: int


def due(health: Optional[RouterHealth], now: datetime) -> bool:
    """Whether a router should be polled now, given its stored health row. Pure."""
    if health is None or health.sampled_at is None:
        return True
    age = now - health.sampled_at
    if health.source != SOURCE_POLL:
        return age > OTHER_SOURCE_FRESH
    if age < MIN_INTERVAL:
        return False
    if health.cpu_load is not None and health.cpu_load >= BUSY_CPU_PERCENT:
        return age >= BUSY_INTERVAL
    return True


def backing_off(router_id: int, now: datetime) -> bool:
    count, last = _failures.get(router_id, (0, None))
    return count >= FAILURES_BEFORE_BACKOFF and last is not None and now - last < FAILURE_BACKOFF


def note_failure(router_id: int, now: datetime) -> None:
    count, _ = _failures.get(router_id, (0, None))
    _failures[router_id] = (count + 1, now)


def note_success(router_id: int) -> None:
    _failures.pop(router_id, None)


def wan_from_routes(rows: list[dict]) -> Optional[str]:
    """The interface of the active default route, from ``/ip/route/print``. Pure.

    ROS 7 gives ``immediate-gw`` as ``192.168.1.1%ether1``; ROS 6 gives
    ``gateway-status`` as ``192.168.1.1 reachable via  ether1``, or
    ``pppoe-out1 reachable`` when the gateway is an interface. With several
    default routes (dual WAN) the active one with the lowest distance wins.
    """
    def distance(row):
        try:
            return int(row.get("distance") or 1)
        except ValueError:
            return 1

    active = [r for r in rows if r.get("active", "true") == "true"
              and r.get("disabled", "false") != "true"]
    for row in sorted(active, key=distance):
        gw = (row.get("immediate-gw") or "").strip()
        if "%" in gw:
            name = gw.rsplit("%", 1)[1].strip()
            if name:
                return name
        words = (row.get("gateway-status") or "").split()
        if "via" in words and words.index("via") + 1 < len(words):
            return words[words.index("via") + 1]
        if words and len(words) >= 2 and words[1] == "reachable" and not words[0][0].isdigit():
            return words[0]
        gateway = (row.get("gateway") or "").strip()
        if gateway and not gateway[0].isdigit() and "," not in gateway:
            return gateway
    return None


def sample_from(resource: dict, wan_link_downs: Optional[int]) -> router_health.HealthSample:
    """RouterOS ``/system/resource`` row -> HealthSample (sanitized by record). Pure."""
    return router_health.HealthSample(
        cpu_load=resource.get("cpu-load"),
        memory_free_bytes=resource.get("free-memory"),
        memory_total_bytes=resource.get("total-memory"),
        storage_free_bytes=resource.get("free-hdd-space"),
        storage_total_bytes=resource.get("total-hdd-space"),
        uptime_seconds=resource.get("uptime"),
        routeros_version=resource.get("version"),
        board_name=resource.get("board-name"),
        wan_link_downs=wan_link_downs,
    )


async def load_targets(now: datetime) -> list[Target]:
    """One short session, closed before the caller touches any router."""
    from app.services.ops_health import is_owner_cut_off

    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.ip_address, Router.username, Router.password,
                   Router.port, Router.auth_method, User.subscription_status, RouterHealth)
            .join(User, User.id == Router.user_id)
            .outerjoin(RouterHealth, RouterHealth.router_id == Router.id)
            .where(Router.last_status.is_(True), Router.ip_address.isnot(None))
            .order_by(Router.id)
        )).all()
        await db.commit()
    targets = []
    for rid, ip, user, password, port, auth, owner_status, health in rows:
        if auth == RouterAuthMethod.RADIUS or is_owner_cut_off(owner_status):
            continue
        if not user or not due(health, now) or backing_off(rid, now):
            continue
        targets.append(Target(rid, ip, user, password or "", int(port or 8728)))
    return targets


async def _wan_link_downs(api, router_id: int, now: datetime) -> Optional[int]:
    cached = _wan_cache.get(router_id)
    if cached is None or now - cached[1] > WAN_CACHE_TTL:
        routes = (await api.rpc(
            "/ip/route/print",
            {".proplist": "gateway,gateway-status,immediate-gw,active,disabled,distance"},
            query=("?dst-address=0.0.0.0/0",)))["rows"]
        cached = (wan_from_routes(routes), now)
        _wan_cache[router_id] = cached
    wan = cached[0]
    if not wan:
        return None
    rows = (await api.rpc("/interface/print", {".proplist": "name,link-downs"},
                          query=(f"?name={wan}",)))["rows"]
    if not rows:
        _wan_cache.pop(router_id, None)   # renamed or gone: resolve again next time
        return None
    try:
        return int(rows[0].get("link-downs"))
    except (TypeError, ValueError):
        return None


async def read_router(target: Target, now: datetime) -> router_health.HealthSample:
    """RouterOS I/O only; no DB session is open here."""
    api = AsyncNativeAPI(target.ip_address, target.username, target.password, target.port)
    try:
        await api.connect()
        resource = (await api.rpc("/system/resource/print",
                                  {".proplist": RESOURCE_PROPS}))["rows"][0]
        try:
            link_downs = await _wan_link_downs(api, target.router_id, now)
        except Exception:
            link_downs = None   # the resource reading still stands
        return sample_from(resource, link_downs)
    finally:
        await api.close()


def _router_busy(target: Target) -> bool:
    from app.services.mikrotik_background import router_locks
    return router_locks.busy_reason(f"{target.ip_address}:{target.port}") is not None


async def poll_router_health(now: Optional[datetime] = None) -> int:
    """Scheduler entry. Returns how many readings were stored. Never raises."""
    if not settings.ROUTER_HEALTH_POLL_ENABLED:
        return 0
    from app.services.router_status_alerts import _db_pool_too_busy
    if _db_pool_too_busy():
        logger.info("[HEALTH-POLL] skipped: DB pool under pressure")
        return 0
    now = now or datetime.utcnow()
    try:
        targets = await load_targets(now)
    except Exception:
        logger.exception("[HEALTH-POLL] could not list routers")
        return 0
    if not targets:
        return 0

    started = time.monotonic()
    sem = asyncio.Semaphore(CONCURRENCY)
    stored = failed = skipped = 0

    async def one(target: Target) -> None:
        nonlocal stored, failed, skipped
        async with sem:
            if time.monotonic() - started > RUN_BUDGET_SECONDS or _router_busy(target):
                skipped += 1
                return
            try:
                sample = await asyncio.wait_for(read_router(target, now),
                                                ROUTER_TIMEOUT_SECONDS)
            except Exception as exc:
                failed += 1
                note_failure(target.router_id, now)
                logger.debug("[HEALTH-POLL] router %s: %s", target.router_id,
                             type(exc).__name__)
                return
            note_success(target.router_id)
        # Written after the router connection is closed, in its own session.
        await router_health.record(target.router_id, sample, source=SOURCE_POLL, now=now)
        stored += 1

    await asyncio.gather(*(one(t) for t in targets), return_exceptions=True)
    logger.info("[HEALTH-POLL] %d due, %d stored, %d failed, %d skipped in %.1fs",
                len(targets), stored, failed, skipped, time.monotonic() - started)
    return stored

"""Keep every router's online/offline status current with a bare TCP probe.

Router status (``routers.last_status`` / ``last_checked_at`` / ``last_online_at``)
used to be recorded only as a side effect: whenever some job happened to talk to
a router (usage push, health read, provisioning, bandwidth snapshot, ...). A
router nothing was talking to kept a stale timestamp, so the ops dashboard
counted it as "stale" instead of online and the online count read low
("24 of 281" on 2026-09-26, while a direct check found almost all of the
quiet ones up). hAP lites moved back to server polling made it worse.

This job asks every router of a live (not cut-off) owner, every few minutes,
the one question "is the management API port answering?" — a TCP connect that
is closed immediately. No login, no RouterOS command: the router's cost is one
SYN/ACK. Routers already checked by another path in the last few minutes are
skipped, so pushing routers are not probed at all.

Results go through ``record_router_availability`` (its own short session per
router, after all network I/O), which keeps the existing offline debounce: a
router is only marked offline after two failed checks within 5 minutes, and
the reseller "went offline" / "back online" notices keep their own guards.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Awaitable, Callable, Optional

from sqlalchemy import select

from app.db import database
from app.db.models import Router, User
from app.services.ops_health import is_owner_cut_off
from app.services.router_availability import record_router_availability
from app.services.router_overload_alerts import tcp_reachable

logger = logging.getLogger(__name__)

SOURCE = "reachability_probe"
# Under the 5-minute offline-confirmation window, so two failed probes in a row
# confirm an outage.
PROBE_INTERVAL_SECONDS = 240
# A router another path checked this recently is left alone.
FRESH_SKIP_SECONDS = 180
PROBE_CONCURRENCY = 20
PROBE_TIMEOUT_SECONDS = 3.0
RETRY_DELAY_SECONDS = 1.0

Reachable = Callable[[str, int, float], Awaitable[bool]]


async def load_probe_targets(now: datetime) -> list[tuple[int, str, int]]:
    """(router_id, ip, port) of routers to probe. One short DB read."""
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.ip_address, Router.port, Router.last_checked_at,
                   User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
        )).all()
        await db.commit()
    targets = []
    for router_id, ip, port, last_checked, owner_status in rows:
        if not ip or is_owner_cut_off(owner_status):
            continue
        if last_checked is not None and (now - last_checked).total_seconds() < FRESH_SKIP_SECONDS:
            continue
        targets.append((router_id, ip, int(port or 8728)))
    return targets


async def probe_router_reachability(
    now: Optional[datetime] = None,
    *,
    reachable: Reachable = tcp_reachable,
    pool_is_busy: Optional[Callable[[], bool]] = None,
) -> dict:
    """Probe every eligible router once; record the results. Never raises."""
    if pool_is_busy is None:
        from app.services.mikrotik_background import _background_db_pool_is_busy

        pool_is_busy = lambda: _background_db_pool_is_busy("REACHABILITY-PROBE")  # noqa: E731
    if pool_is_busy():
        return {"skipped": "db_busy"}
    now = now or datetime.utcnow()
    try:
        targets = await load_probe_targets(now)
    except Exception:
        logger.exception("[REACHABILITY-PROBE] could not load routers")
        return {"skipped": "load_failed"}

    slots = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def probe(target: tuple[int, str, int]) -> tuple[int, bool]:
        router_id, ip, port = target
        async with slots:
            ok = await reachable(ip, port, PROBE_TIMEOUT_SECONDS)
            if not ok:
                # One lost SYN is not an outage.
                await asyncio.sleep(RETRY_DELAY_SECONDS)
                ok = await reachable(ip, port, PROBE_TIMEOUT_SECONDS)
            return router_id, ok

    # All network I/O first, with no DB session open.
    results = await asyncio.gather(*(probe(t) for t in targets))
    checked_at = datetime.utcnow()
    online = 0
    for router_id, ok in results:
        online += int(ok)
        try:
            await record_router_availability(None, router_id, ok, SOURCE, checked_at)
        except Exception:
            logger.exception("[REACHABILITY-PROBE] could not record router %s", router_id)
    summary = {"probed": len(results), "online": online, "offline": len(results) - online}
    logger.info("[REACHABILITY-PROBE] %s", summary)
    return summary

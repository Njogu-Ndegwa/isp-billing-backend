"""Background reconciler for LB_PAID address lists on load-balanced routers.

Paying hotspot customers are ip-binding BYPASSED, which the mangle guard's
hotspot=!auth matcher does NOT treat as authenticated — so they only balance
while listed in LB_PAID. The provisioning hook adds entries at purchase time
and the expiry cleanup removes them, but both are best-effort; this job closes
the gap (router rebooted and lost dynamic host state, hook failed, entry timed
out early after a renewal, etc.).

Guardrails mirror cleanup_expired_users_background:
  * skips entirely when the DB pool is busy (optional work sheds load first);
  * backs off recently-offline routers instead of re-dialing dead ones;
  * short DB session — creds + active customers loaded, then commit/close
    BEFORE any RouterOS I/O (Database Session Discipline);
  * chunked: at most LB_RECONCILE_MAX_ROUTERS_PER_RUN routers per run, with a
    rotating cursor so a large fleet still gets full coverage over time.

Deliberately imports async_session inside the function (not at module level)
so the test harness's engine swap is always seen.
"""

import asyncio
import logging
from datetime import datetime

from sqlalchemy import select

logger = logging.getLogger(__name__)

LB_RECONCILE_MAX_ROUTERS_PER_RUN = 10

_reconcile_running = False
_router_cursor = 0


def _seed_router_lb_paid_sync(router_info: dict, active_customers: list) -> dict:
    """Connect and seed LB_PAID for one router. Runs in a worker thread."""
    from app.services.mikrotik_api import MikroTikAPI
    from app.services.mikrotik_lb import lb_seed_paid

    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=30,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed", "detail": api.last_connect_error}
    try:
        return lb_seed_paid(api, active_customers)
    finally:
        api.disconnect()


async def reconcile_lb_paid_background():
    """APScheduler job: re-seed LB_PAID on routers with lb_enabled=true."""
    global _reconcile_running, _router_cursor
    if _reconcile_running:
        logger.warning("[LB-RECONCILE] Previous run still in progress, skipping")
        return

    from app.db.database import async_session
    from app.db.models import Customer, Router
    from app.services.mikrotik_background import (
        _background_db_pool_is_busy,
        _router_recently_offline,
        router_locks,
    )

    if _background_db_pool_is_busy("LB-RECONCILE"):
        return

    _reconcile_running = True
    try:
        now = datetime.utcnow()
        bundles = []
        async with async_session() as db:
            routers = (
                (await db.execute(
                    select(Router).where(Router.lb_enabled == True)  # noqa: E712
                    .order_by(Router.id)
                )).scalars().all()
            )
            if not routers:
                return

            if len(routers) > LB_RECONCILE_MAX_ROUTERS_PER_RUN:
                start = _router_cursor % len(routers)
                rotated = routers[start:] + routers[:start]
                routers = rotated[:LB_RECONCILE_MAX_ROUTERS_PER_RUN]
                _router_cursor = (start + LB_RECONCILE_MAX_ROUTERS_PER_RUN) % max(
                    1, len(rotated)
                )

            skipped_offline = []
            for r in routers:
                if _router_recently_offline(r, now):
                    skipped_offline.append(r.id)
                    continue
                customers = (
                    (await db.execute(
                        select(Customer).where(
                            Customer.router_id == r.id,
                            Customer.expiry.isnot(None),
                            Customer.expiry > now,
                            Customer.mac_address.isnot(None),
                        )
                    )).scalars().all()
                )
                bundles.append({
                    "router_key": f"{r.ip_address}:{r.port}",
                    "router_info": {
                        "id": r.id,
                        "name": r.name,
                        "ip": r.ip_address,
                        "username": r.username,
                        "password": r.password,
                        "port": r.port,
                    },
                    "customers": [
                        {"mac": (c.mac_address or "").upper(), "expiry": c.expiry}
                        for c in customers
                        if c.mac_address
                    ],
                })
            # Release the DB before any RouterOS I/O.
            await db.commit()

        if skipped_offline:
            logger.info(
                "[LB-RECONCILE] Skipping %d recently-offline router(s): %s",
                len(skipped_offline), skipped_offline,
            )
        if not bundles:
            return

        async def _seed_task(bundle: dict):
            async with router_locks.acquire(bundle["router_key"]):
                return await asyncio.to_thread(
                    _seed_router_lb_paid_sync,
                    bundle["router_info"],
                    bundle["customers"],
                )

        outcomes = await asyncio.gather(
            *[_seed_task(b) for b in bundles], return_exceptions=True
        )
        for bundle, outcome in zip(bundles, outcomes):
            rid = bundle["router_info"]["id"]
            if isinstance(outcome, Exception):
                logger.error("[LB-RECONCILE] Router %s task error: %s", rid, outcome)
            elif outcome.get("error"):
                logger.warning(
                    "[LB-RECONCILE] Router %s: %s (%s)",
                    rid, outcome.get("error"), outcome.get("detail"),
                )
            else:
                added = len(outcome.get("added", []))
                if added:
                    logger.info(
                        "[LB-RECONCILE] Router %s: added %d LB_PAID entrie(s)",
                        rid, added,
                    )
    except Exception as exc:
        logger.error("[LB-RECONCILE] Job failed: %s", exc)
    finally:
        _reconcile_running = False

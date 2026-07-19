from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import database
from app.db.models import Router, RouterAvailabilityCheck
from app.services.router_status_alerts import (
    send_router_recovery_notification,
    should_consider_recovery_notification,
)


ROUTER_OFFLINE_SKIP_PERIOD = timedelta(minutes=30)
ROUTER_STATUS_STALE_AFTER_SECONDS = 600
ROUTER_AVAILABILITY_RETENTION_DAYS = 30


def router_recently_offline(
    router,
    now: Optional[datetime] = None,
    threshold: timedelta = ROUTER_OFFLINE_SKIP_PERIOD,
) -> bool:
    """True when the router's persisted status is offline and the failure is recent."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    return (
        getattr(router, "last_status", None) is False
        and last_checked is not None
        and (now - last_checked) < threshold
    )


def derive_router_status(
    router: Router,
    now: Optional[datetime] = None,
    stale_after_seconds: int = ROUTER_STATUS_STALE_AFTER_SECONDS,
) -> str:
    """Return online/offline/unknown from the persisted router summary fields."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    last_status = getattr(router, "last_status", None)

    if not last_checked or last_status is None:
        return "unknown"

    age_seconds = (now - last_checked).total_seconds()
    if age_seconds > stale_after_seconds:
        return "unknown"

    return "online" if last_status else "offline"


def build_router_status(router: Router, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Serialize the current persisted router status for API responses."""
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    age_seconds = (now - last_checked).total_seconds() if last_checked else None
    status = derive_router_status(router, now=now)

    return {
        "status": status,
        "status_is_stale": status == "unknown" and last_checked is not None,
        "status_age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
        "status_last_checked_at": last_checked.isoformat() if last_checked else None,
        "last_online_at": router.last_online_at.isoformat() if getattr(router, "last_online_at", None) else None,
        "status_source": getattr(router, "last_status_source", None),
        "availability_checks": int(getattr(router, "availability_checks", 0) or 0),
        "availability_successes": int(getattr(router, "availability_successes", 0) or 0),
    }


async def record_router_availability(
    db: AsyncSession,
    router_id: int,
    is_online: bool,
    source: str,
    checked_at: Optional[datetime] = None,
) -> None:
    """Persist a single availability check and update the router summary columns.

    This telemetry write runs in its OWN short, immediately-committed session and
    deliberately does NOT use the caller's ``db``/transaction. Router availability
    is recorded from ~40 request and background paths, all targeting the same hot
    ``routers`` row. When the write rode the caller's transaction (previous
    behaviour: mutate + ``flush()`` only), any caller that stalled after the flush
    (e.g. while waiting on slow RouterOS I/O, or one that was cancelled mid-flight)
    held the ``routers`` row lock open until it eventually committed. Concurrent
    availability writers then queued behind that lock, each pinning a pooled DB
    connection while it waited — a lock convoy that drained the connection pool
    (see docs/agent-memory/incidents/2026-06-05-db-pool-lock-convoy.md).

    Committing in a dedicated session bounds the row lock to milliseconds. The
    ``db`` parameter is retained for call-site compatibility and is intentionally
    unused.
    """
    checked_at = checked_at or datetime.utcnow()
    notify_transition = False
    offline_since: Optional[datetime] = None
    async with database.async_session() as adb:
        router = await adb.get(Router, router_id)
        if not router:
            return

        if is_online:
            # Capture the offline->online transition BEFORE overwriting the
            # summary columns; the message itself is sent after this commit.
            notify_transition = should_consider_recovery_notification(router, checked_at)
            if notify_transition:
                offline_since = router.last_online_at

        router.last_status = is_online
        router.last_checked_at = checked_at
        router.last_status_source = source
        router.availability_checks = int(router.availability_checks or 0) + 1
        if is_online:
            router.last_online_at = checked_at
            router.availability_successes = int(router.availability_successes or 0) + 1

        adb.add(
            RouterAvailabilityCheck(
                router_id=router_id,
                checked_at=checked_at,
                is_online=is_online,
                source=source,
            )
        )
        await adb.commit()

    if notify_transition:
        # DB-only, own short session, never raises (see router_status_alerts).
        await send_router_recovery_notification(
            router_id, offline_since=offline_since, now=checked_at
        )


async def prune_router_availability_history(
    db: AsyncSession,
    retention_days: int = ROUTER_AVAILABILITY_RETENTION_DAYS,
    now: Optional[datetime] = None,
) -> None:
    """Delete old availability samples so the table stays bounded."""
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=retention_days)
    await db.execute(
        delete(RouterAvailabilityCheck).where(RouterAvailabilityCheck.checked_at < cutoff)
    )

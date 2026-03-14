from datetime import datetime, timedelta
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Router, RouterAvailabilityCheck


ROUTER_STATUS_STALE_AFTER_SECONDS = 600
ROUTER_AVAILABILITY_RETENTION_DAYS = 30


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
    """Persist a single availability check and update the router summary columns."""
    checked_at = checked_at or datetime.utcnow()
    router = await db.get(Router, router_id)
    if not router:
        return

    router.last_status = is_online
    router.last_checked_at = checked_at
    router.last_status_source = source
    router.availability_checks = int(router.availability_checks or 0) + 1
    if is_online:
        router.last_online_at = checked_at
        router.availability_successes = int(router.availability_successes or 0) + 1

    db.add(
        RouterAvailabilityCheck(
            router_id=router_id,
            checked_at=checked_at,
            is_online=is_online,
            source=source,
        )
    )
    await db.flush()


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

"""
Admin dashboard metrics endpoints.

All routes require admin role (same auth as /api/admin/* endpoints).
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import db_pool_snapshot, get_db
from app.db.models import Router, RouterAvailabilityCheck, User, UserRole
from app.services.auth import verify_token, get_current_user
from app.services import admin_metrics as svc
from app.services import ops_health
from app.services.management_tunnel_health import (
    build_management_tunnel_health,
    build_fleet_flap_history,
    build_fleet_tunnel_status,
    fetch_insurance_manager_health,
    fetch_manager_health,
    fleet_counts,
    manager_error_code,
)

router = APIRouter(tags=["admin-metrics"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.get("/api/admin/router-agent/metrics")
async def admin_router_agent_metrics(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Return process-local command-agent load and delivery latency counters."""

    await _require_admin(token, db)
    from app.api.router_agent_routes import router_agent_metrics_snapshot

    return router_agent_metrics_snapshot()


@router.get("/api/admin/checkin-pilot")
async def admin_checkin_pilot_stats(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Process-local counters of the router check-in delivery pilot.

    Shadow mode records here what it WOULD have sent, and how long each paid
    MAC stayed missing from its router before the push (or pull) landed.
    """

    await _require_admin(token, db)
    await db.commit()
    from app.services.checkin_delivery import stats_snapshot

    return stats_snapshot()


@router.get("/api/admin/db-pool")
async def admin_db_pool_status(
    include_activity: bool = Query(
        False,
        description="Include pg_stat_activity summaries. Leave false for the lightest pool-only check.",
    ),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Return lightweight live DB pool and Postgres connection pressure."""
    # Capture pool counters before auth performs its indexed user lookup, so
    # the reported checkout count is not inflated by this diagnostic request.
    pool = db_pool_snapshot()
    await _require_admin(token, db)
    await db.commit()

    activity = {
        "skipped": True,
        "reason": "Pass include_activity=true to query pg_stat_activity.",
    }
    long_running = []

    if include_activity:
        try:
            state_rows = (
                await db.execute(
                    text(
                        """
                        SELECT COALESCE(state, 'unknown') AS state, COUNT(*)::int AS count
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                        GROUP BY COALESCE(state, 'unknown')
                        ORDER BY state
                        """
                    )
                )
            ).mappings().all()

            wait_rows = (
                await db.execute(
                    text(
                        """
                        SELECT
                            COALESCE(wait_event_type, 'none') AS wait_event_type,
                            COALESCE(wait_event, 'none') AS wait_event,
                            COUNT(*)::int AS count
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                        GROUP BY COALESCE(wait_event_type, 'none'), COALESCE(wait_event, 'none')
                        ORDER BY count DESC
                        LIMIT 10
                        """
                    )
                )
            ).mappings().all()

            long_rows = (
                await db.execute(
                    text(
                        """
                        SELECT
                            pid,
                            usename,
                            application_name,
                            client_addr::text AS client_addr,
                            COALESCE(state, 'unknown') AS state,
                            wait_event_type,
                            wait_event,
                            ROUND(EXTRACT(EPOCH FROM (
                                now() - COALESCE(xact_start, query_start, backend_start)
                            )))::int AS age_seconds,
                            LEFT(REGEXP_REPLACE(query, '\\s+', ' ', 'g'), 180) AS query_preview
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid <> pg_backend_pid()
                          AND (
                              state = 'active'
                              OR state = 'idle in transaction'
                              OR now() - COALESCE(xact_start, query_start, backend_start) > INTERVAL '30 seconds'
                          )
                        ORDER BY COALESCE(xact_start, query_start, backend_start) ASC
                        LIMIT 10
                        """
                    )
                )
            ).mappings().all()

            states = [{"state": row["state"], "count": row["count"]} for row in state_rows]
            waits = [
                {
                    "wait_event_type": row["wait_event_type"],
                    "wait_event": row["wait_event"],
                    "count": row["count"],
                }
                for row in wait_rows
            ]
            long_running = [dict(row) for row in long_rows]
            activity = {
                "skipped": False,
                "states": states,
                "wait_events": waits,
                "total_connections": sum(row["count"] for row in state_rows),
            }
            await db.commit()
        except Exception as exc:
            activity = {
                "error": "pg_stat_activity_unavailable",
                "detail": str(exc),
            }

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "pool_snapshot_timing": "before_admin_auth_db_checkout",
        "pool": pool,
        "postgres_activity": activity,
        "long_running_connections": long_running,
    }


@router.get("/api/admin/management-tunnels")
async def admin_management_tunnel_status(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Return platform-level WireGuard and L2TP/IPsec health for superadmins."""
    await _require_admin(token, db)
    router_rows = (
        await db.execute(
            select(
                Router.id,
                Router.name,
                Router.identity,
                Router.ip_address,
                Router.last_status,
                Router.last_checked_at,
                Router.last_status_source,
            )
        )
    ).all()
    fleet = fleet_counts((row.ip_address, row.last_status) for row in router_rows)
    router_ids = [row.id for row in router_rows]
    since = datetime.utcnow() - timedelta(hours=24)
    availability_rows = []
    if router_ids:
        availability_rows = (
            await db.execute(
                select(RouterAvailabilityCheck)
                .where(
                    RouterAvailabilityCheck.router_id.in_(router_ids),
                    RouterAvailabilityCheck.checked_at >= since,
                )
                .order_by(
                    RouterAvailabilityCheck.router_id,
                    RouterAvailabilityCheck.checked_at,
                    RouterAvailabilityCheck.id,
                )
            )
        ).scalars().all()
    flap_history = build_fleet_flap_history(
        [
            {
                "id": row.id,
                "name": row.name,
                "identity": row.identity,
                "ip_address": row.ip_address,
            }
            for row in router_rows
        ],
        availability_rows,
    )
    fleet_status = build_fleet_tunnel_status(
        [
            {
                "id": row.id,
                "name": row.name,
                "identity": row.identity,
                "ip_address": row.ip_address,
                "last_status": row.last_status,
                "last_checked_at": row.last_checked_at,
                "last_status_source": row.last_status_source,
            }
            for row in router_rows
        ],
        availability_rows,
    )

    # Release the DB transaction before the external manager call. A tunnel
    # outage must never pin a pooled DB connection while this request times out.
    await db.commit()

    primary_result, insurance_result = await asyncio.gather(
        fetch_manager_health(),
        fetch_insurance_manager_health(),
        return_exceptions=True,
    )
    primary_error = (
        manager_error_code(primary_result)
        if isinstance(primary_result, Exception)
        else None
    )
    insurance_error = (
        manager_error_code(insurance_result)
        if isinstance(insurance_result, Exception)
        else None
    )
    return build_management_tunnel_health(
        None if isinstance(primary_result, Exception) else primary_result,
        fleet,
        error=primary_error,
        insurance_manager=(
            None if isinstance(insurance_result, Exception) else insurance_result
        ),
        insurance_error=insurance_error,
        flap_history=flap_history,
        fleet_status=fleet_status,
    )


# ---------------------------------------------------------------------------
# Operations health (read-only: serves the latest stored snapshot, never computes)
# ---------------------------------------------------------------------------

@router.get("/api/admin/ops-health")
async def admin_ops_health(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Latest ops-health snapshot + 24h sparkline history. Contract: ops-health spec."""
    await _require_admin(token, db)
    await db.commit()
    now = datetime.utcnow()
    latest = await ops_health.load_latest_snapshot()
    points = await ops_health.load_history_points(now, 24)
    if latest is None:
        return {
            "generated_at": None,
            "snapshot_age_seconds": None,
            "overall_status": "unknown",
            "alerts": [],
            "sections": {},
            "history": {"points": points},
        }
    age = max(0, int((now - latest["generated_at"]).total_seconds()))
    return {
        "generated_at": ops_health._iso(latest["generated_at"]),
        "snapshot_age_seconds": age,
        "overall_status": latest["overall_status"],
        "alerts": latest["alerts"],
        "sections": latest["sections"],
        "history": {"points": points},
    }


@router.get("/api/admin/ops-health/window")
async def admin_ops_health_window(
    start: datetime = Query(..., description="ISO 8601 UTC start of the slice"),
    end: Optional[datetime] = Query(None, description="ISO 8601 UTC end (default: now)"),
    router_id: Optional[int] = Query(None, ge=1),
    owner: Optional[str] = Query(
        None, max_length=200,
        description="Reseller email (case-insensitive) or numeric user id: scope to all their routers",
    ),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Live look-back report for an arbitrary time slice.

    Scope it to one reseller with ``owner`` (the primary way in), or to one
    router with ``router_id``. Computed from provisioning_attempts /
    provisioning_logs / mpesa_transactions for that slice only (max 14 days),
    so incident days elsewhere in history do not pollute it. Payments are
    fleet-wide when unscoped, otherwise those of the scoped routers' customers.
    """
    await _require_admin(token, db)
    from app.services.ops_health_window import build_window_report, resolve_owner

    owner_id: Optional[int] = None
    if owner is not None and owner.strip():
        resolved = await resolve_owner(db, owner)
        if resolved is None:
            await db.commit()
            raise HTTPException(status_code=404, detail=f"No reseller matches {owner.strip()!r}")
        owner_id = resolved["user_id"]
    await db.commit()

    start = start.replace(tzinfo=None) if start.tzinfo else start
    end_value = end.replace(tzinfo=None) if (end and end.tzinfo) else (end or datetime.utcnow())
    return await build_window_report(start, end_value, router_id=router_id, owner_id=owner_id)


@router.get("/api/admin/ops-health/history")
async def admin_ops_health_history(
    hours: int = Query(24, ge=1, le=ops_health.HISTORY_MAX_HOURS),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    await db.commit()
    return {"points": await ops_health.load_history_points(datetime.utcnow(), hours)}


# ---------------------------------------------------------------------------
# 1. MRR
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/mrr")
async def admin_mrr(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_mrr(db)


# ---------------------------------------------------------------------------
# 2. Churn
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/churn")
async def admin_churn(
    period: str = Query("month", regex="^(week|month|quarter)$"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_churn(db, period=period)


# ---------------------------------------------------------------------------
# 3. Signups summary
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/signups-summary")
async def admin_signups_summary(
    period: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_signups_summary(db, period=period)


# ---------------------------------------------------------------------------
# 5. Customer signups time series
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/customer-signups")
async def admin_customer_signups(
    period: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    offset: int = Query(0, ge=0, le=svc.MAX_PERIOD_OFFSET),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_customer_signups_timeseries(
        db, period=period, offset=offset,
    )


# ---------------------------------------------------------------------------
# 6. Subscription revenue history
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/subscription-revenue-history")
async def admin_subscription_revenue_history(
    period: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    offset: int = Query(0, ge=0, le=svc.MAX_PERIOD_OFFSET),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_subscription_revenue_history(
        db, period=period, offset=offset,
    )


# ---------------------------------------------------------------------------
# 7. ARPU
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/arpu")
async def admin_arpu(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_arpu(db)


# ---------------------------------------------------------------------------
# 8. Trial conversion
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/trial-conversion")
async def admin_trial_conversion(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_trial_conversion(db)


# ---------------------------------------------------------------------------
# 9. Activation funnel
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/activation-funnel")
async def admin_activation_funnel(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_activation_funnel(db)


# ---------------------------------------------------------------------------
# 10. Revenue concentration
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/revenue-concentration")
async def admin_revenue_concentration(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_revenue_concentration(db)


# ---------------------------------------------------------------------------
# 11. Smart alerts
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/smart-alerts")
async def admin_smart_alerts(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_smart_alerts(db)


# ---------------------------------------------------------------------------
# 12. Revenue forecast
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/revenue-forecast")
async def admin_revenue_forecast(
    period: str = Query("30d", regex="^(7d|30d|90d)$"),
    forecast_days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_revenue_forecast(db, period=period, forecast_days=forecast_days)


# ---------------------------------------------------------------------------
# 13. Growth targets (GET + PUT)
# ---------------------------------------------------------------------------

class GrowthTargetUpdate(BaseModel):
    id: str
    target_value: Optional[float] = None
    period: Optional[str] = None
    label: Optional[str] = None
    unit: Optional[str] = None
    inverse: Optional[bool] = None


class GrowthTargetsPut(BaseModel):
    targets: list[GrowthTargetUpdate]


@router.get("/api/admin/metrics/growth-targets")
async def admin_growth_targets(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.get_growth_targets(db)


@router.put("/api/admin/metrics/growth-targets")
async def admin_update_growth_targets(
    body: GrowthTargetsPut,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    payload = [t.model_dump(exclude_none=True) for t in body.targets]
    for item in payload:
        if "target_value" not in item:
            raise HTTPException(
                status_code=400,
                detail=f"target_value is required for target '{item['id']}'",
            )
    return await svc.upsert_growth_targets(db, payload)


# ---------------------------------------------------------------------------
# 14. Combined earnings (GET) + own reseller accounts (PUT)
# ---------------------------------------------------------------------------

class OwnResellerAccountsPut(BaseModel):
    reseller_ids: list[int]


@router.get("/api/admin/metrics/earnings")
async def admin_earnings(
    period: str = Query(
        "month", regex="^(week|month|quarter|year)$",
        description="Calendar period-to-date, compared against the same point in the previous one.",
    ),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Everything we earn, split by stream: SaaS charges + our own reseller collections."""
    await _require_admin(token, db)
    return await svc.compute_earnings(db, period=period)


@router.put("/api/admin/metrics/earnings/accounts")
async def admin_set_own_reseller_accounts(
    body: OwnResellerAccountsPut,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Choose which reseller accounts count as ours in the earnings view."""
    await _require_admin(token, db)
    saved, rejected = await svc.set_own_reseller_ids(db, body.reseller_ids)
    if rejected:
        # Saving nothing while reporting success is what makes a zero reseller
        # band impossible to explain — fail loudly instead.
        raise HTTPException(
            status_code=400,
            detail=(
                f"Not saved: {len(rejected)} account(s) are not resellers "
                f"(IDs {rejected}). Nothing was changed for them."
            ),
        )
    return {
        "reseller_ids": saved,
        "accounts": await svc.own_reseller_accounts(db, saved),
    }

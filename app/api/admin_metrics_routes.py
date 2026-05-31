"""
Admin dashboard metrics endpoints.

All routes require admin role (same auth as /api/admin/* endpoints).
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import db_pool_snapshot, get_db
from app.db.models import User, UserRole
from app.services.auth import verify_token, get_current_user
from app.services import admin_metrics as svc

router = APIRouter(tags=["admin-metrics"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


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
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_customer_signups_timeseries(db, period=period)


# ---------------------------------------------------------------------------
# 6. Subscription revenue history
# ---------------------------------------------------------------------------

@router.get("/api/admin/metrics/subscription-revenue-history")
async def admin_subscription_revenue_history(
    period: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    return await svc.compute_subscription_revenue_history(db, period=period)


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

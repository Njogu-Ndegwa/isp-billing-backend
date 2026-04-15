"""
Admin dashboard metrics endpoints.

All routes require admin role (same auth as /api/admin/* endpoints).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.database import get_db
from app.db.models import User, UserRole
from app.services.auth import verify_token, get_current_user
from app.services import admin_metrics as svc

router = APIRouter(tags=["admin-metrics"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


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

"""
Business-logic helpers for the admin dashboard metrics endpoints.
Every public function accepts an AsyncSession and returns a plain dict
ready to be serialised as JSON by FastAPI.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, date
from typing import Any

from sqlalchemy import select, func, text, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    User, UserRole, Customer, CustomerPayment,
    Router,
    Subscription, SubscriptionStatus,
    SubscriptionPayment, SubscriptionPaymentStatus,
    GrowthTarget,
)

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _period_range(period: str) -> tuple[datetime, datetime, datetime, datetime]:
    """Return (cur_start, cur_end, prev_start, prev_end) for a named period."""
    now = datetime.utcnow()
    if period == "week":
        cur_start = now - timedelta(days=now.weekday())
        cur_start = cur_start.replace(hour=0, minute=0, second=0, microsecond=0)
        cur_end = now
        prev_start = cur_start - timedelta(weeks=1)
        prev_end = cur_start
    elif period == "quarter":
        q = (now.month - 1) // 3
        cur_start = datetime(now.year, q * 3 + 1, 1)
        cur_end = now
        prev_q_start_month = (q - 1) * 3 + 1 if q > 0 else 10
        prev_q_start_year = now.year if q > 0 else now.year - 1
        prev_start = datetime(prev_q_start_year, prev_q_start_month, 1)
        prev_end = cur_start
    else:  # "month" (default)
        cur_start = datetime(now.year, now.month, 1)
        cur_end = now
        prev_end = cur_start
        if now.month == 1:
            prev_start = datetime(now.year - 1, 12, 1)
        else:
            prev_start = datetime(now.year, now.month - 1, 1)
    return cur_start, cur_end, prev_start, prev_end


def _days_period_range(period: str) -> tuple[datetime, datetime, datetime, datetime]:
    """Return ranges for '7d', '30d', '90d', '1y' style periods."""
    now = datetime.utcnow()
    days_map = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
    days = days_map.get(period, 30)
    cur_start = now - timedelta(days=days)
    cur_end = now
    prev_start = cur_start - timedelta(days=days)
    prev_end = cur_start
    return cur_start, cur_end, prev_start, prev_end


def _pct_change(current: float, previous: float) -> float:
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round((current - previous) / previous * 100, 2)


def _safe_div(num: float, denom: float) -> float:
    return round(num / denom, 2) if denom else 0.0


def _date_label(d: date) -> str:
    return d.strftime("%b %d")


def _trunc_unit_for_days(days: int) -> str:
    if days <= 7:
        return "day"
    if days <= 90:
        return "day"
    return "week"


# ---------------------------------------------------------------------------
# 1. MRR
# ---------------------------------------------------------------------------

async def compute_mrr(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    cur_start = datetime(now.year, now.month, 1)
    if now.month == 1:
        prev_start = datetime(now.year - 1, 12, 1)
    else:
        prev_start = datetime(now.year, now.month - 1, 1)
    prev_end = cur_start

    async def _period_mrr(start: datetime, end: datetime) -> float:
        val = (await db.execute(
            select(func.coalesce(func.sum(SubscriptionPayment.amount), 0))
            .where(
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
                SubscriptionPayment.created_at >= start,
                SubscriptionPayment.created_at < end,
            )
        )).scalar()
        return float(val)

    current = await _period_mrr(cur_start, now)
    previous = await _period_mrr(prev_start, prev_end)

    cur_payers = set((await db.execute(
        select(SubscriptionPayment.user_id)
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= cur_start,
        )
    )).scalars().all())

    prev_payers = set((await db.execute(
        select(SubscriptionPayment.user_id)
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= prev_start,
            SubscriptionPayment.created_at < prev_end,
        )
    )).scalars().all())

    new_payers = cur_payers - prev_payers
    churned_payers = prev_payers - cur_payers

    async def _sum_for_users(user_ids: set, start: datetime, end: datetime) -> float:
        if not user_ids:
            return 0.0
        val = (await db.execute(
            select(func.coalesce(func.sum(SubscriptionPayment.amount), 0))
            .where(
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
                SubscriptionPayment.created_at >= start,
                SubscriptionPayment.created_at < end,
                SubscriptionPayment.user_id.in_(user_ids),
            )
        )).scalar()
        return float(val)

    new_mrr = await _sum_for_users(new_payers, cur_start, now)

    churned_mrr = await _sum_for_users(churned_payers, prev_start, prev_end)

    retained = cur_payers & prev_payers
    expansion_mrr = 0.0
    contraction_mrr = 0.0
    if retained:
        for uid in retained:
            cur_amt = await _sum_for_users({uid}, cur_start, now)
            prev_amt = await _sum_for_users({uid}, prev_start, prev_end)
            diff = cur_amt - prev_amt
            if diff > 0:
                expansion_mrr += diff
            elif diff < 0:
                contraction_mrr += abs(diff)

    by_status = (await db.execute(
        select(
            User.subscription_status,
            func.count(User.id).label("cnt"),
            func.coalesce(func.sum(SubscriptionPayment.amount), 0).label("rev"),
        )
        .outerjoin(
            SubscriptionPayment,
            and_(
                SubscriptionPayment.user_id == User.id,
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
                SubscriptionPayment.created_at >= cur_start,
            ),
        )
        .where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
            ]),
        )
        .group_by(User.subscription_status)
    )).all()

    by_plan = [
        {
            "plan_name": str(row.subscription_status.value).title() if hasattr(row.subscription_status, "value") else str(row.subscription_status).title(),
            "reseller_count": int(row.cnt),
            "mrr": round(float(row.rev), 2),
        }
        for row in by_status
    ]

    return {
        "current_mrr": round(current, 2),
        "previous_period_mrr": round(previous, 2),
        "change_percent": _pct_change(current, previous),
        "currency": "KES",
        "breakdown": {
            "new_mrr": round(new_mrr, 2),
            "churned_mrr": round(churned_mrr, 2),
            "expansion_mrr": round(expansion_mrr, 2),
            "contraction_mrr": round(contraction_mrr, 2),
        },
        "by_plan": by_plan,
        "period": "month",
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 2. Churn
# ---------------------------------------------------------------------------

async def compute_churn(db: AsyncSession, period: str = "month") -> dict[str, Any]:
    now = datetime.utcnow()
    cur_start, cur_end, prev_start, prev_end = _period_range(period)

    active_at_start = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            or_(
                User.subscription_status.in_([
                    SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
                ]),
                and_(
                    User.subscription_status.in_([
                        SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
                    ]),
                    User.subscription_expires_at >= cur_start,
                ),
            ),
        )
    )).scalar() or 0

    churned_q = (
        select(User.id, User.organization_name, User.subscription_expires_at)
        .where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
            ]),
            User.subscription_expires_at >= cur_start,
            User.subscription_expires_at < cur_end,
        )
    )
    churned_rows = (await db.execute(churned_q)).all()
    churned_count = len(churned_rows)

    churn_rate = _safe_div(churned_count * 100, active_at_start)

    prev_active_at_start = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            or_(
                User.subscription_status.in_([
                    SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
                ]),
                and_(
                    User.subscription_status.in_([
                        SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
                    ]),
                    User.subscription_expires_at >= prev_start,
                ),
            ),
        )
    )).scalar() or 0

    prev_churned = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
            ]),
            User.subscription_expires_at >= prev_start,
            User.subscription_expires_at < prev_end,
        )
    )).scalar() or 0

    prev_churn_rate = _safe_div(prev_churned * 100, prev_active_at_start)

    new_resellers = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at >= cur_start,
            User.created_at < cur_end,
        )
    )).scalar() or 0

    net_growth = new_resellers - churned_count

    churned_resellers = [
        {
            "id": row.id,
            "organization_name": row.organization_name,
            "churned_at": row.subscription_expires_at.isoformat() if row.subscription_expires_at else None,
            "reason": "subscription_expired",
        }
        for row in churned_rows
    ]

    return {
        "churn_rate": churn_rate,
        "churned_count": churned_count,
        "total_at_period_start": active_at_start,
        "previous_period_churn_rate": prev_churn_rate,
        "change_percent": round(churn_rate - prev_churn_rate, 2),
        "net_reseller_growth": net_growth,
        "churned_resellers": churned_resellers,
        "period": period,
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 3. Signups summary
# ---------------------------------------------------------------------------

async def compute_signups_summary(db: AsyncSession, period: str = "30d") -> dict[str, Any]:
    now = datetime.utcnow()
    cur_start, cur_end, prev_start, prev_end = _days_period_range(period)
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = datetime(now.year, now.month, 1)

    async def _signup_counts(model, date_col, user_filter=None):
        def _q(since):
            q = select(func.count(model.id)).where(date_col >= since)
            if user_filter is not None:
                q = q.where(user_filter)
            return q

        today = (await db.execute(_q(today_start))).scalar() or 0
        week = (await db.execute(_q(week_start))).scalar() or 0
        month = (await db.execute(_q(month_start))).scalar() or 0
        period_total = (await db.execute(
            _q(cur_start).where(date_col < cur_end)
        )).scalar() or 0
        prev_total = (await db.execute(
            select(func.count(model.id)).where(
                date_col >= prev_start, date_col < prev_end,
                *([user_filter] if user_filter is not None else []),
            )
        )).scalar() or 0
        return {
            "today": today,
            "this_week": week,
            "this_month": month,
            "period_total": period_total,
            "previous_period_total": prev_total,
            "change_percent": _pct_change(period_total, prev_total),
        }

    return {
        "reseller_signups": await _signup_counts(
            User, User.created_at, User.role == UserRole.RESELLER
        ),
        "customer_signups": await _signup_counts(
            Customer, Customer.created_at
        ),
        "period": period,
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 4. Dashboard v2 deltas (called from the existing endpoint)
# ---------------------------------------------------------------------------

async def compute_dashboard_v2_extras(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = datetime(now.year, now.month, 1)
    if now.month == 1:
        prev_month_start = datetime(now.year - 1, 12, 1)
    else:
        prev_month_start = datetime(now.year, now.month - 1, 1)
    prev_month_end = month_start

    cur_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
        .where(CustomerPayment.created_at >= month_start)
    )).scalar())
    prev_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
        .where(
            CustomerPayment.created_at >= prev_month_start,
            CustomerPayment.created_at < prev_month_end,
        )
    )).scalar())

    cur_resellers = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at < now,
        )
    )).scalar() or 0
    prev_resellers = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at < prev_month_end,
        )
    )).scalar() or 0

    cur_customers = (await db.execute(
        select(func.count(Customer.id)).where(Customer.created_at < now)
    )).scalar() or 0
    prev_customers = (await db.execute(
        select(func.count(Customer.id)).where(Customer.created_at < prev_month_end)
    )).scalar() or 0

    signups_today = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at >= today_start,
        )
    )).scalar() or 0
    signups_week = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at >= week_start,
        )
    )).scalar() or 0
    signups_month = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at >= month_start,
        )
    )).scalar() or 0

    return {
        "growth_deltas": {
            "revenue_change_percent": _pct_change(cur_revenue, prev_revenue),
            "resellers_change_percent": _pct_change(cur_resellers, prev_resellers),
            "customers_change_percent": _pct_change(cur_customers, prev_customers),
            "comparison_period": "vs last month",
        },
        "signups_today": signups_today,
        "signups_this_week": signups_week,
        "signups_this_month": signups_month,
    }


# ---------------------------------------------------------------------------
# 5. Customer signups time series
# ---------------------------------------------------------------------------

async def compute_customer_signups_timeseries(
    db: AsyncSession, period: str = "30d",
) -> dict[str, Any]:
    cur_start, cur_end, prev_start, prev_end = _days_period_range(period)

    async def _series(start: datetime, end: datetime):
        rows = (await db.execute(
            select(
                func.date(Customer.created_at).label("d"),
                func.count(Customer.id).label("cnt"),
            )
            .where(Customer.created_at >= start, Customer.created_at < end)
            .group_by(func.date(Customer.created_at))
            .order_by(text("1"))
        )).all()
        return [
            {"date": str(r.d), "label": _date_label(r.d), "count": r.cnt}
            for r in rows
        ]

    return {
        "period": period,
        "customer_signups_over_time": await _series(cur_start, cur_end),
        "previous_period": await _series(prev_start, prev_end),
    }


# ---------------------------------------------------------------------------
# 6. Subscription revenue history
# ---------------------------------------------------------------------------

async def compute_subscription_revenue_history(
    db: AsyncSession, period: str = "30d",
) -> dict[str, Any]:
    cur_start, cur_end, prev_start, prev_end = _days_period_range(period)

    async def _series(start: datetime, end: datetime):
        rows = (await db.execute(
            select(
                func.date(SubscriptionPayment.created_at).label("d"),
                func.coalesce(func.sum(SubscriptionPayment.amount), 0).label("rev"),
            )
            .where(
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
                SubscriptionPayment.created_at >= start,
                SubscriptionPayment.created_at < end,
            )
            .group_by(func.date(SubscriptionPayment.created_at))
            .order_by(text("1"))
        )).all()
        return [
            {"date": str(r.d), "label": _date_label(r.d), "revenue": round(float(r.rev), 2)}
            for r in rows
        ]

    return {
        "period": period,
        "subscription_revenue_over_time": await _series(cur_start, cur_end),
        "previous_period": await _series(prev_start, prev_end),
    }


# ---------------------------------------------------------------------------
# 7. ARPU
# ---------------------------------------------------------------------------

async def compute_arpu(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    if now.month == 1:
        prev_start = datetime(now.year - 1, 12, 1)
    else:
        prev_start = datetime(now.year, now.month - 1, 1)
    prev_end = month_start

    cur_rev = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0))
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= month_start,
        )
    )).scalar())

    prev_rev = float((await db.execute(
        select(func.coalesce(func.sum(SubscriptionPayment.amount), 0))
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= prev_start,
            SubscriptionPayment.created_at < prev_end,
        )
    )).scalar())

    active_resellers = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
            ]),
        )
    )).scalar() or 0

    prev_active = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            or_(
                User.subscription_status.in_([
                    SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
                ]),
                and_(
                    User.subscription_status.in_([
                        SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
                    ]),
                    User.subscription_expires_at >= prev_start,
                ),
            ),
        )
    )).scalar() or 0

    cur_arpu = _safe_div(cur_rev, active_resellers)
    prev_arpu = _safe_div(prev_rev, prev_active)

    return {
        "current_arpu": cur_arpu,
        "previous_period_arpu": prev_arpu,
        "change_percent": _pct_change(cur_arpu, prev_arpu),
        "currency": "KES",
        "active_resellers": active_resellers,
        "total_revenue": round(cur_rev, 2),
        "period": "month",
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 8. Trial conversion
# ---------------------------------------------------------------------------

async def compute_trial_conversion(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    if now.month == 1:
        prev_start = datetime(now.year - 1, 12, 1)
    else:
        prev_start = datetime(now.year, now.month - 1, 1)
    prev_end = month_start

    trials_at_start = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            or_(
                User.subscription_status == SubscriptionStatus.TRIAL,
                and_(
                    User.subscription_status == SubscriptionStatus.ACTIVE,
                    User.created_at < month_start,
                ),
            ),
        )
    )).scalar() or 0

    converted_q = (
        select(User.id, Subscription.created_at.label("sub_created"))
        .outerjoin(Subscription, Subscription.user_id == User.id)
        .where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.ACTIVE,
        )
    )
    converted_rows = (await db.execute(converted_q)).all()

    converted_this_period = []
    for row in converted_rows:
        first_payment = (await db.execute(
            select(func.min(SubscriptionPayment.created_at))
            .where(
                SubscriptionPayment.user_id == row.id,
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            )
        )).scalar()
        if first_payment and first_payment >= month_start:
            converted_this_period.append(row)

    converted_count = len(converted_this_period)

    conversion_rate = _safe_div(converted_count * 100, trials_at_start) if trials_at_start else 0.0

    avg_days_list = []
    for row in converted_this_period:
        first_payment = (await db.execute(
            select(func.min(SubscriptionPayment.created_at))
            .where(
                SubscriptionPayment.user_id == row.id,
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            )
        )).scalar()
        if first_payment and row.sub_created:
            delta = (first_payment - row.sub_created).days
            avg_days_list.append(max(delta, 0))

    avg_days = round(sum(avg_days_list) / len(avg_days_list)) if avg_days_list else 0

    current_trials = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status == SubscriptionStatus.TRIAL,
        )
    )).scalar() or 0

    prev_converted = (await db.execute(
        select(func.count(SubscriptionPayment.user_id.distinct()))
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionPayment.created_at >= prev_start,
            SubscriptionPayment.created_at < prev_end,
        )
    )).scalar() or 0

    prev_trials = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            or_(
                User.subscription_status == SubscriptionStatus.TRIAL,
                and_(
                    User.subscription_status.in_([
                        SubscriptionStatus.ACTIVE,
                        SubscriptionStatus.INACTIVE,
                        SubscriptionStatus.SUSPENDED,
                    ]),
                    User.created_at < prev_end,
                ),
            ),
        )
    )).scalar() or 0

    prev_rate = _safe_div(prev_converted * 100, prev_trials) if prev_trials else 0.0

    return {
        "conversion_rate": conversion_rate,
        "converted_count": converted_count,
        "total_trials_at_start": trials_at_start,
        "current_trials": current_trials,
        "previous_period_rate": prev_rate,
        "change_percent": round(conversion_rate - prev_rate, 2),
        "avg_days_to_convert": avg_days,
        "period": "month",
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 9. Activation funnel
# ---------------------------------------------------------------------------

async def compute_activation_funnel(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()

    signed_up = (await db.execute(
        select(func.count(User.id)).where(User.role == UserRole.RESELLER)
    )).scalar() or 0

    added_router = (await db.execute(
        select(func.count(func.distinct(Router.user_id)))
    )).scalar() or 0

    first_customer = (await db.execute(
        select(func.count(func.distinct(Customer.user_id)))
    )).scalar() or 0

    first_revenue = (await db.execute(
        select(func.count(func.distinct(CustomerPayment.reseller_id)))
    )).scalar() or 0

    def _pct(val):
        return round(val / signed_up * 100, 1) if signed_up else 0

    funnel = [
        {"stage": "signed_up", "label": "Signed Up", "count": signed_up, "percent": 100 if signed_up else 0},
        {"stage": "added_router", "label": "Added Router", "count": added_router, "percent": _pct(added_router)},
        {"stage": "first_customer", "label": "First Customer", "count": first_customer, "percent": _pct(first_customer)},
        {"stage": "first_revenue", "label": "First Revenue", "count": first_revenue, "percent": _pct(first_revenue)},
    ]

    signup_to_router = _safe_div(added_router * 100, signed_up)
    router_to_customer = _safe_div(first_customer * 100, added_router)
    customer_to_revenue = _safe_div(first_revenue * 100, first_customer)
    signup_to_revenue = _safe_div(first_revenue * 100, signed_up)

    return {
        "funnel": funnel,
        "conversion_rates": {
            "signup_to_router": signup_to_router,
            "router_to_customer": router_to_customer,
            "customer_to_revenue": customer_to_revenue,
            "signup_to_revenue": signup_to_revenue,
        },
        "period": "all_time",
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 10. Revenue concentration
# ---------------------------------------------------------------------------

async def compute_revenue_concentration(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    rows = (await db.execute(
        select(
            CustomerPayment.reseller_id,
            User.organization_name,
            func.coalesce(func.sum(CustomerPayment.amount), 0).label("rev"),
        )
        .join(User, User.id == CustomerPayment.reseller_id)
        .where(CustomerPayment.created_at >= month_start)
        .group_by(CustomerPayment.reseller_id, User.organization_name)
        .order_by(func.sum(CustomerPayment.amount).desc())
    )).all()

    total_revenue = sum(float(r.rev) for r in rows)
    total_with_rev = len(rows)

    top_contributors = []
    running = 0.0
    top5_share = 0.0
    top10_share = 0.0
    for i, r in enumerate(rows):
        rev = float(r.rev)
        share = _safe_div(rev * 100, total_revenue)
        running += rev
        if i < 10:
            top_contributors.append({
                "id": r.reseller_id,
                "organization_name": r.organization_name,
                "revenue": round(rev, 2),
                "share_percent": share,
            })
        if i == 4:
            top5_share = _safe_div(running * 100, total_revenue)
        if i == 9:
            top10_share = _safe_div(running * 100, total_revenue)

    if len(rows) < 5:
        top5_share = _safe_div(running * 100, total_revenue) if rows else 0
    if len(rows) < 10:
        top10_share = _safe_div(sum(float(r.rev) for r in rows) * 100, total_revenue) if rows else 0

    return {
        "top_5_share_percent": top5_share,
        "top_10_share_percent": top10_share,
        "total_revenue": round(total_revenue, 2),
        "total_resellers_with_revenue": total_with_rev,
        "top_contributors": top_contributors[:10],
        "period": "this_month",
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 11. Smart alerts
# ---------------------------------------------------------------------------

_REVENUE_MILESTONES = [5_000_000, 2_000_000, 1_000_000, 500_000, 100_000]

async def compute_smart_alerts(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    alerts: list[dict] = []

    month_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
        .where(CustomerPayment.created_at >= month_start)
    )).scalar())

    for milestone in _REVENUE_MILESTONES:
        if month_revenue >= milestone:
            alerts.append({
                "id": f"milestone_rev_{milestone}",
                "type": "milestone",
                "severity": "success",
                "title": "Revenue Milestone",
                "message": f"Platform revenue crossed KES {milestone:,.0f} this month!",
                "timestamp": now.isoformat(),
                "dismissed": False,
            })
            break

    seven_days_ago = now - timedelta(days=7)
    active_resellers_q = (
        select(User.id, User.organization_name)
        .where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
            ]),
        )
    )
    active_resellers = (await db.execute(active_resellers_q)).all()

    for r in active_resellers:
        last_tx = (await db.execute(
            select(func.max(CustomerPayment.created_at))
            .where(CustomerPayment.reseller_id == r.id)
        )).scalar()
        if last_tx and last_tx < seven_days_ago:
            alerts.append({
                "id": f"warning_inactive_{r.id}",
                "type": "warning",
                "severity": "warning",
                "title": "Inactive Reseller",
                "message": f"{r.organization_name} has had no transactions for 7+ days",
                "timestamp": now.isoformat(),
                "dismissed": False,
                "action_url": f"/admin/resellers/{r.id}",
            })
        if len(alerts) >= 20:
            break

    today_start = datetime(now.year, now.month, now.day)
    today_signups = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.created_at >= today_start,
        )
    )).scalar() or 0

    max_daily = (await db.execute(
        select(func.count(User.id).label("cnt"))
        .where(User.role == UserRole.RESELLER)
        .group_by(func.date(User.created_at))
        .order_by(text("cnt DESC"))
        .limit(1)
    )).scalar() or 0

    if today_signups > 0 and today_signups >= max_daily:
        alerts.append({
            "id": "record_signups_today",
            "type": "record",
            "severity": "info",
            "title": "New Daily Record",
            "message": f"{today_signups} new signups today — highest ever!",
            "timestamp": now.isoformat(),
            "dismissed": False,
        })

    expiring_soon = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.subscription_status.in_([
                SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
            ]),
            User.subscription_expires_at.isnot(None),
            User.subscription_expires_at <= now + timedelta(days=3),
            User.subscription_expires_at > now,
        )
    )).scalar() or 0

    if expiring_soon > 0:
        alerts.append({
            "id": "warning_expiring_soon",
            "type": "warning",
            "severity": "danger",
            "title": "Subscriptions Expiring Soon",
            "message": f"{expiring_soon} reseller(s) have subscriptions expiring within 3 days",
            "timestamp": now.isoformat(),
            "dismissed": False,
            "action_url": "/admin/subscriptions/expiring-soon",
        })

    return {
        "alerts": alerts,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 12. Revenue forecast (pure-Python linear regression)
# ---------------------------------------------------------------------------

def _linear_regression(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Return (slope, intercept) for simple OLS."""
    n = len(xs)
    if n < 2:
        return (0.0, ys[0] if ys else 0.0)
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return (0.0, sy / n)
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return (slope, intercept)


async def compute_revenue_forecast(
    db: AsyncSession, period: str = "30d", forecast_days: int = 30,
) -> dict[str, Any]:
    now = datetime.utcnow()
    days_map = {"7d": 7, "30d": 30, "90d": 90}
    based_on = days_map.get(period, 30)
    hist_start = now - timedelta(days=based_on)

    rows = (await db.execute(
        select(
            func.date(CustomerPayment.created_at).label("d"),
            func.coalesce(func.sum(CustomerPayment.amount), 0).label("rev"),
        )
        .where(CustomerPayment.created_at >= hist_start)
        .group_by(func.date(CustomerPayment.created_at))
        .order_by(text("1"))
    )).all()

    if not rows:
        return {
            "forecast": [],
            "projected_period_end_total": 0,
            "growth_rate_percent": 0,
            "confidence": "low",
            "based_on_days": based_on,
            "calculated_at": now.isoformat(),
        }

    xs = list(range(len(rows)))
    ys = [float(r.rev) for r in rows]
    slope, intercept = _linear_regression(xs, ys)

    mean_y = sum(ys) / len(ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

    if r_squared > 0.7:
        confidence = "high"
    elif r_squared > 0.4:
        confidence = "medium"
    else:
        confidence = "low"

    residuals = [y - (slope * x + intercept) for x, y in zip(xs, ys)]
    std_err = math.sqrt(sum(r * r for r in residuals) / max(len(residuals) - 2, 1))
    margin = 1.96 * std_err

    forecast = []
    total_projected = sum(ys)
    base_x = len(xs)
    for i in range(1, forecast_days + 1):
        proj = max(slope * (base_x + i) + intercept, 0)
        total_projected += proj
        d = now + timedelta(days=i)
        forecast.append({
            "date": d.strftime("%Y-%m-%d"),
            "label": _date_label(d.date()),
            "projected_revenue": round(proj, 2),
            "lower_bound": round(max(proj - margin, 0), 2),
            "upper_bound": round(proj + margin, 2),
        })

    first_val = ys[0] if ys[0] else 1
    last_val = ys[-1]
    growth_rate = _pct_change(last_val, first_val)

    return {
        "forecast": forecast,
        "projected_period_end_total": round(total_projected, 2),
        "growth_rate_percent": growth_rate,
        "confidence": confidence,
        "based_on_days": based_on,
        "calculated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 13. Growth targets
# ---------------------------------------------------------------------------

async def get_growth_targets(db: AsyncSession) -> dict[str, Any]:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    targets_rows = (await db.execute(
        select(GrowthTarget).order_by(GrowthTarget.created_at)
    )).scalars().all()

    if not targets_rows:
        targets_rows = await _seed_default_targets(db)

    result_targets = []
    for t in targets_rows:
        current_value = await _compute_target_current(db, t.target_id)
        if t.inverse:
            progress = _safe_div((t.target_value / current_value) * 100, 1) if current_value else 100
        else:
            progress = _safe_div(current_value * 100, t.target_value)
        progress = min(progress, 100)

        result_targets.append({
            "id": t.target_id,
            "label": t.label,
            "current_value": round(current_value, 2),
            "target_value": t.target_value,
            "progress_percent": round(progress, 1),
            "unit": t.unit,
            "period": t.period,
            **({"inverse": True} if t.inverse else {}),
        })

    latest_update = max(
        (t.updated_at for t in targets_rows if t.updated_at), default=now
    )

    return {
        "targets": result_targets,
        "updated_at": latest_update.isoformat(),
    }


async def upsert_growth_targets(
    db: AsyncSession, payload: list[dict],
) -> dict[str, Any]:
    for item in payload:
        existing = (await db.execute(
            select(GrowthTarget).where(GrowthTarget.target_id == item["id"])
        )).scalar_one_or_none()
        if existing:
            if "target_value" in item:
                existing.target_value = item["target_value"]
            if "period" in item:
                existing.period = item["period"]
            if "label" in item:
                existing.label = item["label"]
            if "unit" in item:
                existing.unit = item["unit"]
            existing.updated_at = datetime.utcnow()
        else:
            db.add(GrowthTarget(
                target_id=item["id"],
                label=item.get("label", item["id"]),
                target_value=item["target_value"],
                unit=item.get("unit", ""),
                period=item.get("period", ""),
                inverse=item.get("inverse", False),
            ))
    await db.commit()
    return await get_growth_targets(db)


async def _seed_default_targets(db: AsyncSession) -> list[GrowthTarget]:
    now = datetime.utcnow()
    q_label = f"Q{(now.month - 1) // 3 + 1} {now.year}"
    defaults = [
        GrowthTarget(target_id="mrr_target", label="MRR Target",
                     target_value=60000, unit="KES", period=q_label),
        GrowthTarget(target_id="reseller_target", label="Reseller Count",
                     target_value=100, unit="resellers", period=q_label),
        GrowthTarget(target_id="churn_target", label="Churn Rate",
                     target_value=2.0, unit="%", period=q_label, inverse=True),
    ]
    for d in defaults:
        db.add(d)
    await db.commit()
    return defaults


async def _compute_target_current(db: AsyncSession, target_id: str) -> float:
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    if target_id == "mrr_target":
        val = (await db.execute(
            select(func.coalesce(func.sum(SubscriptionPayment.amount), 0))
            .where(
                SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
                SubscriptionPayment.created_at >= month_start,
            )
        )).scalar()
        return float(val)

    if target_id == "reseller_target":
        val = (await db.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.RESELLER,
                User.subscription_status.in_([
                    SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
                ]),
            )
        )).scalar()
        return float(val or 0)

    if target_id == "churn_target":
        total_active = (await db.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.RESELLER,
                User.subscription_status.in_([
                    SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL,
                ]),
            )
        )).scalar() or 0
        churned = (await db.execute(
            select(func.count(User.id)).where(
                User.role == UserRole.RESELLER,
                User.subscription_status.in_([
                    SubscriptionStatus.INACTIVE, SubscriptionStatus.SUSPENDED,
                ]),
                User.subscription_expires_at >= month_start,
                User.subscription_expires_at < now,
            )
        )).scalar() or 0
        return _safe_div(churned * 100, total_active + churned) if (total_active + churned) else 0.0

    return 0.0

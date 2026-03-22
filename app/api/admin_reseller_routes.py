from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import (
    User, UserRole, Router, Customer, CustomerStatus,
    CustomerPayment, Plan, ResellerFinancials, ResellerPayout,
)
from app.services.auth import verify_token, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-resellers"])


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def _get_reseller_or_404(db: AsyncSession, reseller_id: int) -> User:
    result = await db.execute(
        select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER)
    )
    reseller = result.scalar_one_or_none()
    if not reseller:
        raise HTTPException(status_code=404, detail="Reseller not found")
    return reseller


async def _unpaid_balance(db: AsyncSession, reseller_id: int, total_revenue: float) -> float:
    payout_stmt = select(func.coalesce(func.sum(ResellerPayout.amount), 0)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    total_paid = float((await db.execute(payout_stmt)).scalar())
    return round(total_revenue - total_paid, 2)


# ---------------------------------------------------------------------------
# 1. GET /api/admin/resellers -- List All Resellers
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers")
async def list_resellers(
    sort_by: Optional[str] = Query(None, regex="^(revenue|customers|created_at|last_login)$"),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)

    stmt = select(User).where(User.role == UserRole.RESELLER)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            User.email.ilike(pattern) | User.organization_name.ilike(pattern)
        )
    stmt = stmt.order_by(User.created_at.desc())
    result = await db.execute(stmt)
    resellers = result.scalars().all()

    items = []
    for r in resellers:
        fin_result = await db.execute(
            select(ResellerFinancials).where(ResellerFinancials.user_id == r.id)
        )
        fin = fin_result.scalar_one_or_none()

        router_count = (await db.execute(
            select(func.count(Router.id)).where(Router.user_id == r.id)
        )).scalar() or 0

        total_revenue = float(fin.total_revenue) if fin else 0.0
        balance = await _unpaid_balance(db, r.id, total_revenue)

        items.append({
            "id": r.id,
            "email": r.email,
            "organization_name": r.organization_name,
            "business_name": r.business_name,
            "support_phone": r.support_phone,
            "mpesa_shortcode": r.mpesa_shortcode,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
            "total_revenue": total_revenue,
            "total_customers": fin.total_customers if fin else 0,
            "active_customers": fin.active_customers if fin else 0,
            "last_payment_date": fin.last_payment_date.isoformat() if fin and fin.last_payment_date else None,
            "router_count": router_count,
            "unpaid_balance": balance,
        })

    if sort_by == "revenue":
        items.sort(key=lambda x: x["total_revenue"], reverse=True)
    elif sort_by == "customers":
        items.sort(key=lambda x: x["active_customers"], reverse=True)
    elif sort_by == "last_login":
        items.sort(key=lambda x: x["last_login_at"] or "", reverse=True)

    return {"total": len(items), "resellers": items}


# ---------------------------------------------------------------------------
# 2. GET /api/admin/resellers/{reseller_id} -- Reseller Detail
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}")
async def get_reseller_detail(
    reseller_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    r = await _get_reseller_or_404(db, reseller_id)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = datetime(now.year, now.month, 1)

    async def _revenue_since(since: datetime) -> float:
        s = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
            CustomerPayment.reseller_id == reseller_id,
            CustomerPayment.created_at >= since,
        )
        return float((await db.execute(s)).scalar())

    all_time_stmt = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
        CustomerPayment.reseller_id == reseller_id
    )
    all_time_revenue = float((await db.execute(all_time_stmt)).scalar())

    revenue = {
        "today": await _revenue_since(today_start),
        "this_week": await _revenue_since(week_start),
        "this_month": await _revenue_since(month_start),
        "all_time": all_time_revenue,
    }

    # Customer counts by status
    cust_stmt = select(
        Customer.status, func.count(Customer.id)
    ).where(Customer.user_id == reseller_id).group_by(Customer.status)
    cust_result = await db.execute(cust_stmt)
    status_counts = {row[0].value: row[1] for row in cust_result}

    # Routers with online status
    routers_result = await db.execute(
        select(Router).where(Router.user_id == reseller_id)
    )
    routers = [
        {
            "id": rt.id,
            "name": rt.name,
            "identity": rt.identity,
            "ip_address": rt.ip_address,
            "is_online": rt.last_status,
            "last_checked_at": rt.last_checked_at.isoformat() if rt.last_checked_at else None,
        }
        for rt in routers_result.scalars().all()
    ]

    # Recent 10 payments
    recent_stmt = (
        select(CustomerPayment, Customer, Plan)
        .join(Customer, CustomerPayment.customer_id == Customer.id)
        .outerjoin(Plan, Customer.plan_id == Plan.id)
        .where(CustomerPayment.reseller_id == reseller_id)
        .order_by(CustomerPayment.created_at.desc())
        .limit(10)
    )
    recent_result = await db.execute(recent_stmt)
    recent_payments = [
        {
            "id": p.id,
            "amount": float(p.amount),
            "payment_method": p.payment_method.value,
            "customer_name": c.name,
            "customer_phone": c.phone,
            "plan_name": pl.name if pl else None,
            "created_at": p.created_at.isoformat(),
        }
        for p, c, pl in recent_result
    ]

    # Payout summary
    total_paid_stmt = select(func.coalesce(func.sum(ResellerPayout.amount), 0)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    total_paid = float((await db.execute(total_paid_stmt)).scalar())

    last_payout_stmt = select(func.max(ResellerPayout.created_at)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    last_payout_date = (await db.execute(last_payout_stmt)).scalar()

    return {
        "id": r.id,
        "email": r.email,
        "organization_name": r.organization_name,
        "business_name": r.business_name,
        "support_phone": r.support_phone,
        "mpesa_shortcode": r.mpesa_shortcode,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
        "revenue": revenue,
        "customers": {
            "active": status_counts.get("active", 0),
            "inactive": status_counts.get("inactive", 0),
            "pending": status_counts.get("pending", 0),
            "total": sum(status_counts.values()),
        },
        "routers": routers,
        "recent_payments": recent_payments,
        "payouts": {
            "total_paid": total_paid,
            "last_payout_date": last_payout_date.isoformat() if last_payout_date else None,
            "unpaid_balance": round(all_time_revenue - total_paid, 2),
        },
    }


# ---------------------------------------------------------------------------
# 3. GET /api/admin/resellers/{reseller_id}/payments -- Customer Payments
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}/payments")
async def get_reseller_payments(
    reseller_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    base_filter = [CustomerPayment.reseller_id == reseller_id]

    if date:
        try:
            d = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")
        base_filter.append(CustomerPayment.created_at >= d)
        base_filter.append(CustomerPayment.created_at < d + timedelta(days=1))
    else:
        if start_date:
            try:
                base_filter.append(CustomerPayment.created_at >= datetime.strptime(start_date, "%Y-%m-%d"))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format")
        if end_date:
            try:
                base_filter.append(
                    CustomerPayment.created_at < datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
                )
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format")

    # Summary
    summary_stmt = select(
        func.count(CustomerPayment.id),
        func.coalesce(func.sum(CustomerPayment.amount), 0),
    ).where(*base_filter)
    summary = (await db.execute(summary_stmt)).one()
    total_count, total_amount = int(summary[0]), float(summary[1])

    # Paginated results
    offset = (page - 1) * per_page
    payments_stmt = (
        select(CustomerPayment, Customer, Plan)
        .join(Customer, CustomerPayment.customer_id == Customer.id)
        .outerjoin(Plan, Customer.plan_id == Plan.id)
        .where(*base_filter)
        .order_by(CustomerPayment.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(payments_stmt)

    payments = [
        {
            "id": p.id,
            "amount": float(p.amount),
            "payment_method": p.payment_method.value,
            "payment_reference": p.payment_reference,
            "customer_name": c.name,
            "customer_phone": c.phone,
            "plan_name": pl.name if pl else None,
            "created_at": p.created_at.isoformat(),
        }
        for p, c, pl in result
    ]

    return {
        "reseller_id": reseller_id,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": (total_count + per_page - 1) // per_page,
        "summary": {
            "total_transactions": total_count,
            "total_amount": round(total_amount, 2),
        },
        "payments": payments,
    }


# ---------------------------------------------------------------------------
# 4. GET /api/admin/resellers/{reseller_id}/routers -- Reseller's Routers
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}/routers")
async def get_reseller_routers(
    reseller_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    routers_result = await db.execute(
        select(Router).where(Router.user_id == reseller_id)
    )
    routers = routers_result.scalars().all()

    items = []
    for rt in routers:
        cust_count = (await db.execute(
            select(func.count(Customer.id)).where(Customer.router_id == rt.id)
        )).scalar() or 0

        revenue = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0))
            .join(Customer, CustomerPayment.customer_id == Customer.id)
            .where(Customer.router_id == rt.id, CustomerPayment.reseller_id == reseller_id)
        )).scalar())

        items.append({
            "id": rt.id,
            "name": rt.name,
            "identity": rt.identity,
            "ip_address": rt.ip_address,
            "auth_method": rt.auth_method.value if rt.auth_method else None,
            "is_online": rt.last_status,
            "last_checked_at": rt.last_checked_at.isoformat() if rt.last_checked_at else None,
            "customer_count": cust_count,
            "total_revenue": round(revenue, 2),
        })

    return {"reseller_id": reseller_id, "total": len(items), "routers": items}


# ---------------------------------------------------------------------------
# 5. GET /api/admin/dashboard -- Aggregate Admin Dashboard
# ---------------------------------------------------------------------------
@router.get("/api/admin/dashboard")
async def admin_dashboard(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = datetime(now.year, now.month, 1)
    active_threshold = now - timedelta(days=30)

    # Reseller counts
    total_resellers = (await db.execute(
        select(func.count(User.id)).where(User.role == UserRole.RESELLER)
    )).scalar() or 0

    active_resellers = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.RESELLER,
            User.last_login_at >= active_threshold,
        )
    )).scalar() or 0

    # Revenue across all resellers
    async def _total_revenue_since(since: datetime) -> float:
        s = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
            CustomerPayment.created_at >= since
        )
        return float((await db.execute(s)).scalar())

    all_time_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
    )).scalar())

    # Customer counts
    total_customers = (await db.execute(select(func.count(Customer.id)))).scalar() or 0
    active_customers = (await db.execute(
        select(func.count(Customer.id)).where(Customer.status == CustomerStatus.ACTIVE)
    )).scalar() or 0

    # Router counts
    total_routers = (await db.execute(select(func.count(Router.id)))).scalar() or 0
    online_routers = (await db.execute(
        select(func.count(Router.id)).where(Router.last_status == True)
    )).scalar() or 0

    # Top 10 resellers by revenue this month
    top_stmt = (
        select(
            User.id,
            User.email,
            User.organization_name,
            func.coalesce(func.sum(CustomerPayment.amount), 0).label("month_revenue"),
        )
        .join(CustomerPayment, CustomerPayment.reseller_id == User.id)
        .where(User.role == UserRole.RESELLER, CustomerPayment.created_at >= month_start)
        .group_by(User.id, User.email, User.organization_name)
        .order_by(func.sum(CustomerPayment.amount).desc())
        .limit(10)
    )
    top_result = await db.execute(top_stmt)
    top_resellers = [
        {
            "id": row.id,
            "email": row.email,
            "organization_name": row.organization_name,
            "month_revenue": round(float(row.month_revenue), 2),
        }
        for row in top_result
    ]

    # Payout totals
    total_payouts = float((await db.execute(
        select(func.coalesce(func.sum(ResellerPayout.amount), 0))
    )).scalar())

    total_unpaid = round(all_time_revenue - total_payouts, 2)

    # Recent 10 reseller sign-ups
    recent_stmt = (
        select(User)
        .where(User.role == UserRole.RESELLER)
        .order_by(User.created_at.desc())
        .limit(10)
    )
    recent_result = await db.execute(recent_stmt)
    recent_signups = [
        {
            "id": u.id,
            "email": u.email,
            "organization_name": u.organization_name,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in recent_result.scalars().all()
    ]

    return {
        "resellers": {
            "total": total_resellers,
            "active_last_30_days": active_resellers,
        },
        "revenue": {
            "today": await _total_revenue_since(today_start),
            "this_week": await _total_revenue_since(week_start),
            "this_month": await _total_revenue_since(month_start),
            "all_time": all_time_revenue,
        },
        "customers": {
            "total": total_customers,
            "active": active_customers,
            "inactive": total_customers - active_customers,
        },
        "routers": {
            "total": total_routers,
            "online": online_routers,
            "offline": total_routers - online_routers,
        },
        "top_resellers_this_month": top_resellers,
        "payouts": {
            "total_paid": total_payouts,
            "total_unpaid": total_unpaid,
        },
        "recent_signups": recent_signups,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# 6. POST /api/admin/resellers/{reseller_id}/payouts -- Record a Payout
# ---------------------------------------------------------------------------
class PayoutRequest(BaseModel):
    amount: float
    payment_method: str
    reference: Optional[str] = None
    notes: Optional[str] = None
    period_start: Optional[str] = None
    period_end: Optional[str] = None


@router.post("/api/admin/resellers/{reseller_id}/payouts")
async def record_payout(
    reseller_id: int,
    request: PayoutRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    period_start = None
    period_end = None
    if request.period_start:
        try:
            period_start = datetime.strptime(request.period_start, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid period_start format")
    if request.period_end:
        try:
            period_end = datetime.strptime(request.period_end, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid period_end format")

    payout = ResellerPayout(
        reseller_id=reseller_id,
        amount=request.amount,
        payment_method=request.payment_method,
        reference=request.reference,
        notes=request.notes,
        period_start=period_start,
        period_end=period_end,
    )
    db.add(payout)
    await db.commit()
    await db.refresh(payout)

    # Compute updated unpaid balance
    total_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
            CustomerPayment.reseller_id == reseller_id
        )
    )).scalar())
    balance = await _unpaid_balance(db, reseller_id, total_revenue)

    return {
        "payout": {
            "id": payout.id,
            "reseller_id": payout.reseller_id,
            "amount": payout.amount,
            "payment_method": payout.payment_method,
            "reference": payout.reference,
            "notes": payout.notes,
            "period_start": payout.period_start.isoformat() if payout.period_start else None,
            "period_end": payout.period_end.isoformat() if payout.period_end else None,
            "created_at": payout.created_at.isoformat(),
        },
        "unpaid_balance": balance,
    }


# ---------------------------------------------------------------------------
# 7. GET /api/admin/resellers/{reseller_id}/payouts -- Payout History
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}/payouts")
async def get_payout_history(
    reseller_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    filters = [ResellerPayout.reseller_id == reseller_id]
    if start_date:
        try:
            filters.append(ResellerPayout.created_at >= datetime.strptime(start_date, "%Y-%m-%d"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format")
    if end_date:
        try:
            filters.append(
                ResellerPayout.created_at < datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format")

    # Summary
    summary_stmt = select(
        func.count(ResellerPayout.id),
        func.coalesce(func.sum(ResellerPayout.amount), 0),
    ).where(*filters)
    summary = (await db.execute(summary_stmt)).one()
    total_count, total_amount = int(summary[0]), float(summary[1])

    # Paginated results
    offset = (page - 1) * per_page
    payouts_stmt = (
        select(ResellerPayout)
        .where(*filters)
        .order_by(ResellerPayout.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(payouts_stmt)

    payouts = [
        {
            "id": p.id,
            "amount": p.amount,
            "payment_method": p.payment_method,
            "reference": p.reference,
            "notes": p.notes,
            "period_start": p.period_start.isoformat() if p.period_start else None,
            "period_end": p.period_end.isoformat() if p.period_end else None,
            "created_at": p.created_at.isoformat(),
        }
        for p in result.scalars().all()
    ]

    return {
        "reseller_id": reseller_id,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": (total_count + per_page - 1) // per_page,
        "summary": {
            "total_payouts": total_count,
            "total_amount": round(total_amount, 2),
        },
        "payouts": payouts,
    }

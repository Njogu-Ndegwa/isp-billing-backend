from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text, delete, update
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import (
    User, UserRole, Router, Customer, CustomerStatus,
    CustomerPayment, Plan, ResellerFinancials, ResellerPayout,
    ResellerTransactionCharge,
    PaymentMethod, Payment, ProvisioningToken, Voucher,
    Subscription, CustomerRating, UserBandwidthUsage,
    MpesaTransaction, ProvisioningLog, BandwidthSnapshot,
    RouterLogEntry, RouterAvailabilityCheck,
)
from app.services.auth import verify_token, get_current_user
from app.services.provisioning import remove_wireguard_peer, remove_l2tp_peer

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin-resellers"])

# Only mobile_money payments flow through the admin's M-Pesa shortcode.
# Cash and voucher payments are collected directly by the reseller.
MPESA_FILTER = CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY


def _parse_date(value: str, param_name: str = "date") -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name} format, use YYYY-MM-DD")


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


async def _total_payouts(db: AsyncSession, reseller_id: int) -> float:
    stmt = select(func.coalesce(func.sum(ResellerPayout.amount), 0)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    return float((await db.execute(stmt)).scalar())


async def _total_transaction_charges(db: AsyncSession, reseller_id: int) -> float:
    stmt = select(func.coalesce(func.sum(ResellerTransactionCharge.amount), 0)).where(
        ResellerTransactionCharge.reseller_id == reseller_id
    )
    return float((await db.execute(stmt)).scalar())


async def _mpesa_revenue(db: AsyncSession, reseller_id: int) -> float:
    """Revenue that landed in admin's M-Pesa (excludes cash/voucher)."""
    stmt = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
        CustomerPayment.reseller_id == reseller_id, MPESA_FILTER
    )
    return float((await db.execute(stmt)).scalar())


# ---------------------------------------------------------------------------
# 1. GET /api/admin/resellers -- List All Resellers
# ---------------------------------------------------------------------------
VALID_SORT_FIELDS = {
    "revenue", "mpesa_revenue", "customers", "created_at",
    "last_login", "unpaid_balance", "router_count",
}
VALID_FILTERS = {
    "unpaid",       # unpaid_balance > 0
    "paid_up",      # unpaid_balance <= 0
    "active",       # logged in within 30 days
    "inactive",     # never logged in or >30 days ago
    "has_routers",  # owns at least 1 router
    "no_routers",   # owns 0 routers
    "has_revenue",  # has revenue in the selected period
    "no_revenue",   # zero revenue in the selected period
}


@router.get("/api/admin/resellers")
async def list_resellers(
    sort_by: Optional[str] = Query(None, description="Sort field: revenue, mpesa_revenue, customers, created_at, last_login, unpaid_balance, router_count"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    filter: Optional[str] = Query(None, description="Filter: unpaid, paid_up, active, inactive, has_routers, no_routers, has_revenue, no_revenue"),
    search: Optional[str] = None,
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    List all resellers with summary stats.

    Filtering:
      ?filter=unpaid            -- only resellers you owe money to
      ?filter=paid_up           -- fully paid resellers
      ?filter=active            -- logged in within last 30 days
      ?filter=inactive          -- not logged in for 30+ days
      ?filter=has_routers       -- has at least one router
      ?filter=no_routers        -- no routers yet
      ?filter=has_revenue       -- has revenue in selected period
      ?filter=no_revenue        -- zero revenue in selected period

    Sorting:
      ?sort_by=unpaid_balance&sort_order=desc  -- who you owe the most
      ?sort_by=revenue&sort_order=desc         -- top earners
      ?sort_by=mpesa_revenue                   -- by M-Pesa revenue
      ?sort_by=customers                       -- by active customer count
      ?sort_by=router_count                    -- by number of routers
      ?sort_by=created_at&sort_order=asc       -- oldest first
      ?sort_by=last_login                      -- most recent login first

    Date filtering for revenue figures:
      ?date=2026-03-22           -- single day
      ?start_date=...&end_date=  -- range
    """
    await _require_admin(token, db)

    if sort_by and sort_by not in VALID_SORT_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by. Choose from: {', '.join(sorted(VALID_SORT_FIELDS))}"
        )
    if filter and filter not in VALID_FILTERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid filter. Choose from: {', '.join(sorted(VALID_FILTERS))}"
        )

    descending = sort_order != "asc"

    # Build optional date window for revenue queries
    date_filters = []
    if date:
        d = _parse_date(date)
        date_filters = [CustomerPayment.created_at >= d, CustomerPayment.created_at < d + timedelta(days=1)]
    else:
        if start_date:
            date_filters.append(CustomerPayment.created_at >= _parse_date(start_date, "start_date"))
        if end_date:
            date_filters.append(CustomerPayment.created_at < _parse_date(end_date, "end_date") + timedelta(days=1))

    stmt = select(User).where(User.role == UserRole.RESELLER)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            User.email.ilike(pattern) | User.organization_name.ilike(pattern)
        )

    # Pre-filter at DB level for login-based filters
    now = datetime.utcnow()
    active_cutoff = now - timedelta(days=30)
    if filter == "active":
        stmt = stmt.where(User.last_login_at >= active_cutoff)
    elif filter == "inactive":
        stmt = stmt.where((User.last_login_at == None) | (User.last_login_at < active_cutoff))

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

        # Revenue in the requested period (all methods)
        rev_filters = [CustomerPayment.reseller_id == r.id] + date_filters
        total_revenue = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*rev_filters)
        )).scalar())

        # M-Pesa-only revenue in the requested period (what admin collected)
        mpesa_rev = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*rev_filters, MPESA_FILTER)
        )).scalar())

        # Unpaid balance = all-time M-Pesa revenue minus payouts minus transaction charges
        all_time_mpesa = await _mpesa_revenue(db, r.id)
        paid = await _total_payouts(db, r.id)
        charges = await _total_transaction_charges(db, r.id)
        unpaid = round(all_time_mpesa - paid - charges, 2)

        item = {
            "id": r.id,
            "email": r.email,
            "organization_name": r.organization_name,
            "business_name": r.business_name,
            "support_phone": r.support_phone,
            "mpesa_shortcode": r.mpesa_shortcode,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
            "total_revenue": total_revenue,
            "mpesa_revenue": mpesa_rev,
            "total_customers": fin.total_customers if fin else 0,
            "active_customers": fin.active_customers if fin else 0,
            "last_payment_date": fin.last_payment_date.isoformat() if fin and fin.last_payment_date else None,
            "router_count": router_count,
            "unpaid_balance": unpaid,
            "total_transaction_charges": charges,
        }

        # Apply post-query filters that depend on computed values
        if filter == "unpaid" and unpaid <= 0:
            continue
        if filter == "paid_up" and unpaid > 0:
            continue
        if filter == "has_routers" and router_count == 0:
            continue
        if filter == "no_routers" and router_count > 0:
            continue
        if filter == "has_revenue" and total_revenue == 0:
            continue
        if filter == "no_revenue" and total_revenue > 0:
            continue

        items.append(item)

    # Sort
    sort_key_map = {
        "revenue": lambda x: x["total_revenue"],
        "mpesa_revenue": lambda x: x["mpesa_revenue"],
        "customers": lambda x: x["active_customers"],
        "created_at": lambda x: x["created_at"] or "",
        "last_login": lambda x: x["last_login_at"] or "",
        "unpaid_balance": lambda x: x["unpaid_balance"],
        "router_count": lambda x: x["router_count"],
    }
    if sort_by and sort_by in sort_key_map:
        items.sort(key=sort_key_map[sort_by], reverse=descending)

    return {
        "total": len(items),
        "filters_applied": {"sort_by": sort_by, "sort_order": sort_order, "filter": filter, "search": search},
        "resellers": items,
    }


# ---------------------------------------------------------------------------
# 2. GET /api/admin/resellers/{reseller_id} -- Reseller Detail
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}")
async def get_reseller_detail(
    reseller_id: int,
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Reseller detail with revenue breakdown.
    Optional ?date=YYYY-MM-DD or ?start_date=&end_date= to see a specific period.
    Without date params you get the standard today/week/month/all_time breakdown.
    """
    await _require_admin(token, db)
    r = await _get_reseller_or_404(db, reseller_id)

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = datetime(now.year, now.month, 1)

    base = [CustomerPayment.reseller_id == reseller_id]

    async def _rev(extra_filters=None) -> dict:
        """Return {total, mpesa} revenue for given filters."""
        f = base + (extra_filters or [])
        total = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*f)
        )).scalar())
        mpesa = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*f, MPESA_FILTER)
        )).scalar())
        return {"total": total, "mpesa": mpesa}

    # If a specific date/range is requested, return that instead of the standard breakdown
    if date or start_date or end_date:
        date_filters = []
        if date:
            d = _parse_date(date)
            date_filters = [CustomerPayment.created_at >= d, CustomerPayment.created_at < d + timedelta(days=1)]
        else:
            if start_date:
                date_filters.append(CustomerPayment.created_at >= _parse_date(start_date, "start_date"))
            if end_date:
                date_filters.append(CustomerPayment.created_at < _parse_date(end_date, "end_date") + timedelta(days=1))
        period_rev = await _rev(date_filters)
        revenue = {"period": period_rev["total"], "period_mpesa": period_rev["mpesa"]}
    else:
        today_rev = await _rev([CustomerPayment.created_at >= today_start])
        week_rev = await _rev([CustomerPayment.created_at >= week_start])
        month_rev = await _rev([CustomerPayment.created_at >= month_start])
        all_rev = await _rev()
        revenue = {
            "today": today_rev["total"],
            "today_mpesa": today_rev["mpesa"],
            "this_week": week_rev["total"],
            "this_week_mpesa": week_rev["mpesa"],
            "this_month": month_rev["total"],
            "this_month_mpesa": month_rev["mpesa"],
            "all_time": all_rev["total"],
            "all_time_mpesa": all_rev["mpesa"],
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

    # Payout summary (always all-time, based on M-Pesa revenue only)
    all_time_mpesa = await _mpesa_revenue(db, reseller_id)
    total_paid = await _total_payouts(db, reseller_id)
    total_charges = await _total_transaction_charges(db, reseller_id)

    last_payout_stmt = select(func.max(ResellerPayout.created_at)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    last_payout_date = (await db.execute(last_payout_stmt)).scalar()

    # Recent transaction charges
    recent_charges_stmt = (
        select(ResellerTransactionCharge)
        .where(ResellerTransactionCharge.reseller_id == reseller_id)
        .order_by(ResellerTransactionCharge.created_at.desc())
        .limit(5)
    )
    recent_charges = [
        {
            "id": c.id,
            "amount": c.amount,
            "description": c.description,
            "reference": c.reference,
            "created_at": c.created_at.isoformat(),
        }
        for c in (await db.execute(recent_charges_stmt)).scalars().all()
    ]

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
            "total_transaction_charges": total_charges,
            "last_payout_date": last_payout_date.isoformat() if last_payout_date else None,
            "unpaid_balance": round(all_time_mpesa - total_paid - total_charges, 2),
        },
        "recent_transaction_charges": recent_charges,
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

    # M-Pesa only total (what admin collected, excludes cash/voucher)
    mpesa_amount = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*base_filter, MPESA_FILTER)
    )).scalar())

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
            "mpesa_amount": round(mpesa_amount, 2),
        },
        "payments": payments,
    }


# ---------------------------------------------------------------------------
# 4. GET /api/admin/resellers/{reseller_id}/routers -- Reseller's Routers
# ---------------------------------------------------------------------------
ROUTER_SORT_FIELDS = {
    "revenue", "mpesa_revenue", "customers", "active_customers",
    "name", "created_at", "last_checked", "uptime",
}
ROUTER_FILTERS = {
    "online",          # currently reachable
    "offline",         # not reachable or never checked
    "has_customers",   # at least 1 customer
    "no_customers",    # zero customers
    "active_customers",  # at least 1 active (non-expired) customer
    "has_revenue",     # revenue > 0 in period
    "no_revenue",      # zero revenue in period
    "emergency",       # emergency mode is on
}


@router.get("/api/admin/resellers/{reseller_id}/routers")
async def get_reseller_routers(
    reseller_id: int,
    sort_by: Optional[str] = Query(None, description="Sort field: revenue, mpesa_revenue, customers, active_customers, name, created_at, last_checked, uptime"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    filter: Optional[str] = Query(None, description="Filter: online, offline, has_customers, no_customers, active_customers, has_revenue, no_revenue, emergency"),
    search: Optional[str] = Query(None, description="Search by router name, identity, or IP"),
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    List routers for a reseller with rich detail for troubleshooting.

    Filtering:
      ?filter=online             -- only routers currently reachable
      ?filter=offline            -- routers that are down or never checked
      ?filter=has_customers      -- routers with at least 1 customer
      ?filter=no_customers       -- routers with 0 customers
      ?filter=active_customers   -- routers with at least 1 active customer
      ?filter=has_revenue        -- routers with revenue in selected period
      ?filter=no_revenue         -- routers with zero revenue in period
      ?filter=emergency          -- routers in emergency mode

    Sorting:
      ?sort_by=revenue&sort_order=desc
      ?sort_by=customers
      ?sort_by=uptime

    Date filtering (for revenue figures):
      ?date=2026-03-22
      ?start_date=...&end_date=...
    """
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    if sort_by and sort_by not in ROUTER_SORT_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by. Choose from: {', '.join(sorted(ROUTER_SORT_FIELDS))}"
        )
    if filter and filter not in ROUTER_FILTERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid filter. Choose from: {', '.join(sorted(ROUTER_FILTERS))}"
        )

    descending = sort_order != "asc"

    date_filters: list = []
    if date:
        d = _parse_date(date)
        date_filters = [CustomerPayment.created_at >= d, CustomerPayment.created_at < d + timedelta(days=1)]
    else:
        if start_date:
            date_filters.append(CustomerPayment.created_at >= _parse_date(start_date, "start_date"))
        if end_date:
            date_filters.append(CustomerPayment.created_at < _parse_date(end_date, "end_date") + timedelta(days=1))

    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)

    stmt = select(Router).where(Router.user_id == reseller_id)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            Router.name.ilike(pattern)
            | Router.identity.ilike(pattern)
            | Router.ip_address.ilike(pattern)
        )
    if filter == "online":
        stmt = stmt.where(Router.last_status == True)
    elif filter == "offline":
        stmt = stmt.where((Router.last_status == False) | (Router.last_status == None))
    elif filter == "emergency":
        stmt = stmt.where(Router.emergency_active == True)

    stmt = stmt.order_by(Router.created_at.desc())
    routers = (await db.execute(stmt)).scalars().all()

    items = []
    for rt in routers:
        total_customers = (await db.execute(
            select(func.count(Customer.id)).where(Customer.router_id == rt.id)
        )).scalar() or 0

        active_count = (await db.execute(
            select(func.count(Customer.id)).where(
                Customer.router_id == rt.id,
                Customer.status == CustomerStatus.ACTIVE,
            )
        )).scalar() or 0

        # Period revenue (all methods)
        rev_base = [
            CustomerPayment.reseller_id == reseller_id,
            Customer.router_id == rt.id,
        ]
        rev_join = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).join(
            Customer, CustomerPayment.customer_id == Customer.id
        )
        period_revenue = float((await db.execute(
            rev_join.where(*rev_base, *date_filters)
        )).scalar())

        # Period M-Pesa revenue
        period_mpesa = float((await db.execute(
            rev_join.where(*rev_base, *date_filters, MPESA_FILTER)
        )).scalar())

        # Today's revenue
        today_revenue = float((await db.execute(
            rev_join.where(*rev_base, CustomerPayment.created_at >= today_start)
        )).scalar())

        # All-time revenue
        alltime_revenue = float((await db.execute(
            rev_join.where(*rev_base)
        )).scalar())

        # Uptime percentage from availability fields on the router
        uptime_pct = None
        if rt.availability_checks and rt.availability_checks > 0:
            uptime_pct = round((rt.availability_successes / rt.availability_checks) * 100, 1)

        item = {
            "id": rt.id,
            "name": rt.name,
            "identity": rt.identity,
            "ip_address": rt.ip_address,
            "port": rt.port,
            "auth_method": rt.auth_method.value if rt.auth_method else None,
            "payment_methods": rt.payment_methods,
            "is_online": rt.last_status,
            "last_checked_at": rt.last_checked_at.isoformat() if rt.last_checked_at else None,
            "last_online_at": rt.last_online_at.isoformat() if rt.last_online_at else None,
            "uptime_pct": uptime_pct,
            "emergency_active": rt.emergency_active,
            "emergency_message": rt.emergency_message,
            "created_at": rt.created_at.isoformat() if rt.created_at else None,
            "total_customers": total_customers,
            "active_customers": active_count,
            "revenue": {
                "today": round(today_revenue, 2),
                "period": round(period_revenue, 2),
                "period_mpesa": round(period_mpesa, 2),
                "all_time": round(alltime_revenue, 2),
            },
        }

        # Post-query filters on computed values
        if filter == "has_customers" and total_customers == 0:
            continue
        if filter == "no_customers" and total_customers > 0:
            continue
        if filter == "active_customers" and active_count == 0:
            continue
        if filter == "has_revenue" and period_revenue == 0:
            continue
        if filter == "no_revenue" and period_revenue > 0:
            continue

        items.append(item)

    # Sort
    router_sort_map = {
        "revenue": lambda x: x["revenue"]["period"],
        "mpesa_revenue": lambda x: x["revenue"]["period_mpesa"],
        "customers": lambda x: x["total_customers"],
        "active_customers": lambda x: x["active_customers"],
        "name": lambda x: (x["name"] or "").lower(),
        "created_at": lambda x: x["created_at"] or "",
        "last_checked": lambda x: x["last_checked_at"] or "",
        "uptime": lambda x: x["uptime_pct"] if x["uptime_pct"] is not None else -1,
    }
    if sort_by and sort_by in router_sort_map:
        items.sort(key=router_sort_map[sort_by], reverse=descending)

    summary = {
        "total": len(items),
        "online": sum(1 for i in items if i["is_online"]),
        "offline": sum(1 for i in items if not i["is_online"]),
        "with_active_customers": sum(1 for i in items if i["active_customers"] > 0),
    }

    return {
        "reseller_id": reseller_id,
        "summary": summary,
        "filters_applied": {"sort_by": sort_by, "sort_order": sort_order, "filter": filter, "search": search},
        "routers": items,
    }


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
    async def _total_revenue_since(since: datetime) -> dict:
        f = [CustomerPayment.created_at >= since]
        total = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*f)
        )).scalar())
        mpesa = float((await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(*f, MPESA_FILTER)
        )).scalar())
        return {"total": total, "mpesa": mpesa}

    all_time_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0))
    )).scalar())
    all_time_mpesa_revenue = float((await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(MPESA_FILTER)
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

    total_charges = float((await db.execute(
        select(func.coalesce(func.sum(ResellerTransactionCharge.amount), 0))
    )).scalar())

    total_unpaid = round(all_time_mpesa_revenue - total_payouts - total_charges, 2)

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

    today_rev = await _total_revenue_since(today_start)
    week_rev = await _total_revenue_since(week_start)
    month_rev = await _total_revenue_since(month_start)

    return {
        "resellers": {
            "total": total_resellers,
            "active_last_30_days": active_resellers,
        },
        "revenue": {
            "today": today_rev["total"],
            "today_mpesa": today_rev["mpesa"],
            "this_week": week_rev["total"],
            "this_week_mpesa": week_rev["mpesa"],
            "this_month": month_rev["total"],
            "this_month_mpesa": month_rev["mpesa"],
            "all_time": all_time_revenue,
            "all_time_mpesa": all_time_mpesa_revenue,
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
            "total_transaction_charges": total_charges,
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

    # Compute updated unpaid balance (M-Pesa revenue minus payouts minus charges)
    mpesa_rev = await _mpesa_revenue(db, reseller_id)
    paid = await _total_payouts(db, reseller_id)
    charges = await _total_transaction_charges(db, reseller_id)
    balance = round(mpesa_rev - paid - charges, 2)

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


# ---------------------------------------------------------------------------
# 8. DELETE /api/admin/resellers/{reseller_id} -- Delete Reseller
# ---------------------------------------------------------------------------
async def _reseller_deletion_summary(db: AsyncSession, reseller_id: int) -> dict:
    """Collect counts of everything that would be deleted for a reseller."""
    customer_ids_stmt = select(Customer.id).where(Customer.user_id == reseller_id)
    router_ids_stmt = select(Router.id).where(Router.user_id == reseller_id)

    async def _count(model, col, sub):
        return (await db.execute(select(func.count(model.id)).where(col.in_(sub)))).scalar() or 0

    customers = (await db.execute(
        select(func.count(Customer.id)).where(Customer.user_id == reseller_id)
    )).scalar() or 0
    routers = (await db.execute(
        select(func.count(Router.id)).where(Router.user_id == reseller_id)
    )).scalar() or 0
    plans = (await db.execute(
        select(func.count(Plan.id)).where(Plan.user_id == reseller_id)
    )).scalar() or 0
    vouchers = (await db.execute(
        select(func.count(Voucher.id)).where(Voucher.user_id == reseller_id)
    )).scalar() or 0
    customer_payments = (await db.execute(
        select(func.count(CustomerPayment.id)).where(CustomerPayment.reseller_id == reseller_id)
    )).scalar() or 0
    provisioning_tokens = (await db.execute(
        select(func.count(ProvisioningToken.id)).where(ProvisioningToken.user_id == reseller_id)
    )).scalar() or 0
    payouts = (await db.execute(
        select(func.count(ResellerPayout.id)).where(ResellerPayout.reseller_id == reseller_id)
    )).scalar() or 0
    transaction_charges = (await db.execute(
        select(func.count(ResellerTransactionCharge.id)).where(ResellerTransactionCharge.reseller_id == reseller_id)
    )).scalar() or 0

    payments = await _count(Payment, Payment.customer_id, customer_ids_stmt)
    mpesa_transactions = await _count(MpesaTransaction, MpesaTransaction.customer_id, customer_ids_stmt)
    provisioning_logs_c = await _count(ProvisioningLog, ProvisioningLog.customer_id, customer_ids_stmt)
    provisioning_logs_r = await _count(ProvisioningLog, ProvisioningLog.router_id, router_ids_stmt)
    customer_ratings = await _count(CustomerRating, CustomerRating.customer_id, customer_ids_stmt)
    bandwidth_usage = await _count(UserBandwidthUsage, UserBandwidthUsage.customer_id, customer_ids_stmt)
    bandwidth_snapshots = await _count(BandwidthSnapshot, BandwidthSnapshot.router_id, router_ids_stmt)
    router_logs = await _count(RouterLogEntry, RouterLogEntry.router_id, router_ids_stmt)
    availability_checks = await _count(RouterAvailabilityCheck, RouterAvailabilityCheck.router_id, router_ids_stmt)

    # WG peers to remove
    wg_tokens = (await db.execute(
        select(func.count(ProvisioningToken.id)).where(
            ProvisioningToken.user_id == reseller_id,
            ProvisioningToken.wg_public_key.isnot(None),
        )
    )).scalar() or 0

    return {
        "customers": customers,
        "routers": routers,
        "plans": plans,
        "vouchers": vouchers,
        "customer_payments": customer_payments,
        "payments": payments,
        "mpesa_transactions": mpesa_transactions,
        "provisioning_tokens": provisioning_tokens,
        "provisioning_logs": provisioning_logs_c + provisioning_logs_r,
        "customer_ratings": customer_ratings,
        "bandwidth_usage": bandwidth_usage,
        "bandwidth_snapshots": bandwidth_snapshots,
        "router_logs": router_logs,
        "availability_checks": availability_checks,
        "reseller_payouts": payouts,
        "reseller_transaction_charges": transaction_charges,
        "wireguard_peers": wg_tokens,
    }


@router.delete("/api/admin/resellers/{reseller_id}")
async def delete_reseller(
    reseller_id: int,
    confirm: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Delete a reseller and ALL associated data.

    Without ?confirm=true, returns a dry-run summary of what would be deleted.
    With ?confirm=true, performs the actual deletion.
    """
    await _require_admin(token, db)
    reseller = await _get_reseller_or_404(db, reseller_id)

    summary = await _reseller_deletion_summary(db, reseller_id)

    if not confirm:
        return {
            "dry_run": True,
            "reseller": {
                "id": reseller.id,
                "email": reseller.email,
                "organization_name": reseller.organization_name,
            },
            "will_delete": summary,
            "message": "Add ?confirm=true to actually delete this reseller and all associated data.",
        }

    # ── Phase 1: WireGuard cleanup (best-effort) ──
    wg_failures = []
    tokens_result = await db.execute(
        select(ProvisioningToken).where(
            ProvisioningToken.user_id == reseller_id,
            ProvisioningToken.wg_public_key.isnot(None),
        )
    )
    for tk in tokens_result.scalars().all():
        try:
            if tk.vpn_type == "l2tp" and tk.l2tp_username:
                await remove_l2tp_peer(tk.l2tp_username)
            elif tk.wg_public_key:
                await remove_wireguard_peer(tk.wg_public_key)
        except Exception as e:
            wg_failures.append({"token_id": tk.id, "error": str(e)})
            logger.warning(f"[DELETE-RESELLER] VPN peer removal failed for token {tk.id}: {e}")

    # ── Phase 2: DB cascade deletion (bottom-up) ──
    customer_ids = select(Customer.id).where(Customer.user_id == reseller_id)
    router_ids = select(Router.id).where(Router.user_id == reseller_id)

    # 1. Null out vouchers.redeemed_by pointing to this reseller's customers
    await db.execute(
        update(Voucher).where(Voucher.redeemed_by.in_(customer_ids)).values(redeemed_by=None)
    )

    # 2-3. RADIUS tables (raw SQL since no ORM models)
    await db.execute(text(
        "DELETE FROM radius_check WHERE customer_id IN (SELECT id FROM customers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))
    await db.execute(text(
        "DELETE FROM radius_reply WHERE customer_id IN (SELECT id FROM customers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))

    # 4. Customer ratings
    await db.execute(delete(CustomerRating).where(CustomerRating.customer_id.in_(customer_ids)))

    # 5. User bandwidth usage
    await db.execute(delete(UserBandwidthUsage).where(UserBandwidthUsage.customer_id.in_(customer_ids)))

    # 6. Provisioning logs (customer-side + router-side)
    await db.execute(delete(ProvisioningLog).where(ProvisioningLog.customer_id.in_(customer_ids)))
    await db.execute(delete(ProvisioningLog).where(ProvisioningLog.router_id.in_(router_ids)))

    # 7. M-Pesa transactions
    await db.execute(delete(MpesaTransaction).where(MpesaTransaction.customer_id.in_(customer_ids)))

    # 8. Payments (old table)
    await db.execute(delete(Payment).where(Payment.customer_id.in_(customer_ids)))

    # 9. Customer payments
    await db.execute(delete(CustomerPayment).where(CustomerPayment.reseller_id == reseller_id))

    # 10. Customers
    await db.execute(delete(Customer).where(Customer.user_id == reseller_id))

    # 11. Bandwidth snapshots
    await db.execute(delete(BandwidthSnapshot).where(BandwidthSnapshot.router_id.in_(router_ids)))

    # 12. Router log entries
    await db.execute(delete(RouterLogEntry).where(RouterLogEntry.router_id.in_(router_ids)))

    # 13. Router availability checks
    await db.execute(delete(RouterAvailabilityCheck).where(RouterAvailabilityCheck.router_id.in_(router_ids)))

    # 14. RADIUS NAS (raw SQL, no ORM model)
    await db.execute(text(
        "DELETE FROM radius_nas WHERE router_id IN (SELECT id FROM routers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))

    # 15. Provisioning tokens (unlink router_id first, then delete)
    await db.execute(
        update(ProvisioningToken)
        .where(ProvisioningToken.router_id.in_(router_ids))
        .values(router_id=None)
    )
    await db.execute(delete(ProvisioningToken).where(ProvisioningToken.user_id == reseller_id))

    # 16. Vouchers
    await db.execute(delete(Voucher).where(Voucher.user_id == reseller_id))

    # 17. Routers
    await db.execute(delete(Router).where(Router.user_id == reseller_id))

    # 18. Plans
    await db.execute(delete(Plan).where(Plan.user_id == reseller_id))

    # 19. Reseller financials
    await db.execute(delete(ResellerFinancials).where(ResellerFinancials.user_id == reseller_id))

    # 20. Reseller payouts
    await db.execute(delete(ResellerPayout).where(ResellerPayout.reseller_id == reseller_id))

    # 20b. Reseller transaction charges
    await db.execute(delete(ResellerTransactionCharge).where(ResellerTransactionCharge.reseller_id == reseller_id))

    # 21. Subscriptions
    await db.execute(delete(Subscription).where(Subscription.user_id == reseller_id))

    # 22. Null out created_by references from other users
    await db.execute(update(User).where(User.created_by == reseller_id).values(created_by=None))

    # 23. Delete the user row
    await db.execute(delete(User).where(User.id == reseller_id))

    await db.commit()

    logger.info(f"[DELETE-RESELLER] Deleted reseller {reseller_id} ({reseller.email}): {summary}")

    return {
        "dry_run": False,
        "reseller": {
            "id": reseller.id,
            "email": reseller.email,
            "organization_name": reseller.organization_name,
        },
        "deleted": summary,
        "wireguard_failures": wg_failures,
        "message": "Reseller and all associated data deleted successfully.",
    }


# ---------------------------------------------------------------------------
# 9. POST /api/admin/resellers/{reseller_id}/transaction-charges
# ---------------------------------------------------------------------------
class TransactionChargeRequest(BaseModel):
    amount: float
    description: str
    reference: Optional[str] = None


@router.post("/api/admin/resellers/{reseller_id}/transaction-charges")
async def add_transaction_charge(
    reseller_id: int,
    request: TransactionChargeRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Record a transaction charge (deduction) against a reseller's balance.

    Use this for bank fees, M-Pesa withdrawal charges, or any other
    cost the admin wants to deduct before paying the reseller.
    """
    admin = await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Description is required")

    charge = ResellerTransactionCharge(
        reseller_id=reseller_id,
        amount=request.amount,
        description=request.description.strip(),
        reference=request.reference,
        created_by=admin.id,
    )
    db.add(charge)
    await db.commit()
    await db.refresh(charge)

    mpesa_rev = await _mpesa_revenue(db, reseller_id)
    paid = await _total_payouts(db, reseller_id)
    charges = await _total_transaction_charges(db, reseller_id)
    balance = round(mpesa_rev - paid - charges, 2)

    return {
        "charge": {
            "id": charge.id,
            "reseller_id": charge.reseller_id,
            "amount": charge.amount,
            "description": charge.description,
            "reference": charge.reference,
            "created_by": charge.created_by,
            "created_at": charge.created_at.isoformat(),
        },
        "unpaid_balance": balance,
    }


# ---------------------------------------------------------------------------
# 10. GET /api/admin/resellers/{reseller_id}/transaction-charges
# ---------------------------------------------------------------------------
@router.get("/api/admin/resellers/{reseller_id}/transaction-charges")
async def get_transaction_charges(
    reseller_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all transaction charges for a reseller (paginated)."""
    await _require_admin(token, db)
    await _get_reseller_or_404(db, reseller_id)

    filters = [ResellerTransactionCharge.reseller_id == reseller_id]
    if start_date:
        filters.append(ResellerTransactionCharge.created_at >= _parse_date(start_date, "start_date"))
    if end_date:
        filters.append(
            ResellerTransactionCharge.created_at < _parse_date(end_date, "end_date") + timedelta(days=1)
        )

    summary_stmt = select(
        func.count(ResellerTransactionCharge.id),
        func.coalesce(func.sum(ResellerTransactionCharge.amount), 0),
    ).where(*filters)
    summary = (await db.execute(summary_stmt)).one()
    total_count, total_amount = int(summary[0]), float(summary[1])

    offset = (page - 1) * per_page
    charges_stmt = (
        select(ResellerTransactionCharge)
        .where(*filters)
        .order_by(ResellerTransactionCharge.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(charges_stmt)

    charges = [
        {
            "id": c.id,
            "amount": c.amount,
            "description": c.description,
            "reference": c.reference,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat(),
        }
        for c in result.scalars().all()
    ]

    return {
        "reseller_id": reseller_id,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": (total_count + per_page - 1) // per_page,
        "summary": {
            "total_charges": total_count,
            "total_amount": round(total_amount, 2),
        },
        "charges": charges,
    }

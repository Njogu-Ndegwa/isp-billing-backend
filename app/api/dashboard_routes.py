from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, extract, case, distinct
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime, timedelta, date
from collections import defaultdict

from app.db.database import get_db
from app.db.models import (
    Router, Customer, Plan, CustomerStatus, CustomerPayment,
    MpesaTransaction, MpesaTransactionStatus,
)
from app.services.auth import verify_token, get_current_user
from app.services.router_helpers import get_router_by_id
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address, validate_mac_address

import logging
import asyncio

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])


@router.get("/")
def read_root():
    return {"message": "ISP Billing SaaS API", "version": "1.0.0", "updated": "2025-11-02-v2"}


@router.get("/api/test-remove/{router_id}/{mac_address}")
def test_remove_endpoint(router_id: int, mac_address: str):
    """Test endpoint to verify routing works"""
    return {
        "endpoint_hit": True,
        "router_id": router_id,
        "mac_address": mac_address,
        "message": "Endpoint is working! Route parameters received correctly."
    }


@router.api_route("/api/remove-user/{router_id}/{mac_address}", methods=["GET", "POST", "DELETE"])
async def remove_user_all_methods(
    router_id: int,
    mac_address: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Remove expired user from MikroTik and update database status to INACTIVE
    Supports GET, POST, DELETE methods
    """
    from app.services.mikrotik_background import remove_user_from_mikrotik

    logger.info(f"[REMOVE-USER] Endpoint hit! router_id={router_id}, mac={mac_address}")
    
    if not validate_mac_address(mac_address):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")

    router_obj = await get_router_by_id(db, router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    result = await remove_user_from_mikrotik(mac_address, db)
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to remove user"))
    
    return {
        "success": True,
        "message": f"User with MAC {result['mac_address']} removed from MikroTik and set to INACTIVE",
        "customer_id": result.get("customer_id"),
        "mac_address": result["mac_address"],
        "router_id": router_id,
        "removed_items": result.get("removed", {})
    }


# Dashboard Overview Endpoint
@router.get("/api/dashboard/overview")
async def get_dashboard_overview(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get dashboard overview with key business metrics
    
    Query params:
    - router_id: Optional router ID to filter metrics for a specific router
    
    Returns:
    - Total revenue (today, this week, this month, all time)
    - Active guests count
    - Total guests count
    - Revenue by router (or single router if router_id specified)
    - Revenue by plan
    - Recent transactions
    """
    try:
        user = await get_current_user(token, db)
        user_id = user.id
        
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_start = today_start - timedelta(days=now.weekday())
        month_start = datetime(now.year, now.month, 1)
        
        # Get all customers for this user (optionally filtered by router)
        customers_stmt = select(Customer).where(Customer.user_id == user_id)
        if router_id:
            customers_stmt = customers_stmt.where(Customer.router_id == router_id)
        customers_result = await db.execute(customers_stmt)
        all_customers = customers_result.scalars().all()
        
        total_customers = len(all_customers)
        active_customers = sum(1 for c in all_customers if c.status == CustomerStatus.ACTIVE)
        
        # Get revenue from customer_payments
        # Build base filter conditions for payments (joins through Customer for router filtering)
        if router_id:
            # When router_id is specified, join with Customer to filter by router
            # Total revenue all time
            total_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id
            )
            total_revenue_result = await db.execute(total_revenue_stmt)
            total_revenue = float(total_revenue_result.scalar() or 0)
            
            # Today's revenue
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue_result = await db.execute(today_revenue_stmt)
            today_revenue = float(today_revenue_result.scalar() or 0)
            
            # This week's revenue
            week_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= week_start
            )
            week_revenue_result = await db.execute(week_revenue_stmt)
            week_revenue = float(week_revenue_result.scalar() or 0)
            
            # This month's revenue
            month_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                Customer.router_id == router_id,
                CustomerPayment.created_at >= month_start
            )
            month_revenue_result = await db.execute(month_revenue_stmt)
            month_revenue = float(month_revenue_result.scalar() or 0)
        else:
            # No router filter - original behavior
            # Total revenue all time
            total_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id
            )
            total_revenue_result = await db.execute(total_revenue_stmt)
            total_revenue = float(total_revenue_result.scalar() or 0)
            
            # Today's revenue
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue_result = await db.execute(today_revenue_stmt)
            today_revenue = float(today_revenue_result.scalar() or 0)
            
            # This week's revenue
            week_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= week_start
            )
            week_revenue_result = await db.execute(week_revenue_stmt)
            week_revenue = float(week_revenue_result.scalar() or 0)
            
            # This month's revenue
            month_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= month_start
            )
            month_revenue_result = await db.execute(month_revenue_stmt)
            month_revenue = float(month_revenue_result.scalar() or 0)
        
        # Revenue by router
        router_revenue_stmt = select(
            Router.id,
            Router.name,
            func.count(CustomerPayment.id).label('transaction_count'),
            func.sum(CustomerPayment.amount).label('revenue')
        ).join(
            Customer, Customer.router_id == Router.id
        ).join(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Router.user_id == user_id
        )
        if router_id:
            router_revenue_stmt = router_revenue_stmt.where(Router.id == router_id)
        router_revenue_stmt = router_revenue_stmt.group_by(Router.id, Router.name)
        
        router_revenue_result = await db.execute(router_revenue_stmt)
        router_revenue = [
            {
                "router_id": row.id,
                "router_name": row.name,
                "transaction_count": row.transaction_count,
                "revenue": float(row.revenue or 0)
            }
            for row in router_revenue_result
        ]
        
        # Revenue by plan (filtered by router if specified)
        plan_revenue_stmt = select(
            Plan.id,
            Plan.name,
            Plan.price,
            func.count(CustomerPayment.id).label('sales_count'),
            func.sum(CustomerPayment.amount).label('revenue')
        ).join(
            Customer, Customer.plan_id == Plan.id
        ).join(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Plan.user_id == user_id
        )
        if router_id:
            plan_revenue_stmt = plan_revenue_stmt.where(Customer.router_id == router_id)
        plan_revenue_stmt = plan_revenue_stmt.group_by(Plan.id, Plan.name, Plan.price)
        
        plan_revenue_result = await db.execute(plan_revenue_stmt)
        plan_revenue = [
            {
                "plan_id": row.id,
                "plan_name": row.name,
                "plan_price": row.price,
                "sales_count": row.sales_count,
                "revenue": float(row.revenue or 0)
            }
            for row in plan_revenue_result
        ]
        
        # Recent transactions (last 10)
        recent_txn_stmt = select(CustomerPayment, Customer, Plan).join(
            Customer, CustomerPayment.customer_id == Customer.id
        ).join(
            Plan, Customer.plan_id == Plan.id, isouter=True
        ).where(
            CustomerPayment.reseller_id == user_id
        )
        if router_id:
            recent_txn_stmt = recent_txn_stmt.where(Customer.router_id == router_id)
        recent_txn_stmt = recent_txn_stmt.order_by(CustomerPayment.created_at.desc()).limit(10)
        
        recent_txn_result = await db.execute(recent_txn_stmt)
        recent_transactions = [
            {
                "payment_id": payment.id,
                "amount": float(payment.amount),
                "customer_name": customer.name,
                "customer_phone": customer.phone,
                "plan_name": plan.name if plan else None,
                "payment_date": payment.created_at.isoformat(),
                "payment_method": payment.payment_method.value
            }
            for payment, customer, plan in recent_txn_result
        ]
        
        # Expiring soon (next 24 hours)
        expiring_soon_date = now + timedelta(hours=24)
        expiring_stmt = select(Customer).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry.isnot(None),
            Customer.expiry <= expiring_soon_date,
            Customer.expiry > now
        )
        if router_id:
            expiring_stmt = expiring_stmt.where(Customer.router_id == router_id)
        expiring_stmt = expiring_stmt.order_by(Customer.expiry)
        
        expiring_result = await db.execute(expiring_stmt)
        expiring_soon = [
            {
                "customer_id": c.id,
                "customer_name": c.name,
                "customer_phone": c.phone,
                "mac_address": c.mac_address,
                "expiry": c.expiry.isoformat(),
                "hours_remaining": (c.expiry - now).total_seconds() / 3600
            }
            for c in expiring_result.scalars().all()
        ]
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "revenue": {
                "today": today_revenue,
                "this_week": week_revenue,
                "this_month": month_revenue,
                "all_time": total_revenue
            },
            "customers": {
                "total": total_customers,
                "active": active_customers,
                "inactive": total_customers - active_customers
            },
            "revenue_by_router": router_revenue,
            "revenue_by_plan": plan_revenue,
            "recent_transactions": recent_transactions,
            "expiring_soon": expiring_soon,
            "generated_at": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching dashboard overview: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch dashboard: {str(e)}")


@router.get("/api/dashboard/analytics")
async def get_dashboard_analytics(
    router_id: Optional[int] = None,
    days: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    preset: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Comprehensive analytics endpoint with flexible filtering.
    
    Query params (priority: start_date/end_date > preset > days):
    - router_id: Optional router ID to filter analytics for a specific router
    - start_date: YYYY-MM-DD (inclusive)
    - end_date: YYYY-MM-DD (inclusive, defaults to today)
    - preset: today, yesterday, this_week, last_week, this_month, last_month, 
              this_year, last_7_days, last_30_days, last_90_days, all_time
    - days: Number of days back from today (default 7, kept for backward compatibility)
    """
    try:
        user = await get_current_user(token, db)
        user_id = user.id
        
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        today_end = today_start + timedelta(days=1)
        
        # Determine date range based on params (priority: dates > preset > days)
        if start_date or end_date:
            try:
                filter_start = datetime.strptime(start_date, "%Y-%m-%d") if start_date else today_start
                filter_end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) if end_date else today_end
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
            period_label = f"{start_date or 'start'} to {end_date or 'today'}"
            period_days = (filter_end - filter_start).days
        elif preset:
            presets = {
                "today": (today_start, today_end),
                "yesterday": (today_start - timedelta(days=1), today_start),
                "this_week": (today_start - timedelta(days=today_start.weekday()), today_end),
                "last_week": (
                    today_start - timedelta(days=today_start.weekday() + 7),
                    today_start - timedelta(days=today_start.weekday())
                ),
                "this_month": (datetime(now.year, now.month, 1), today_end),
                "last_month": (
                    datetime(now.year, now.month, 1) - timedelta(days=1),
                    datetime(now.year, now.month, 1)
                ),
                "this_year": (datetime(now.year, 1, 1), today_end),
                "last_7_days": (today_start - timedelta(days=6), today_end),
                "last_30_days": (today_start - timedelta(days=29), today_end),
                "last_90_days": (today_start - timedelta(days=89), today_end),
                "all_time": (datetime(2020, 1, 1), today_end),
            }
            # Fix last_month to get correct range
            if preset == "last_month":
                first_of_this_month = datetime(now.year, now.month, 1)
                last_month_end = first_of_this_month
                if now.month == 1:
                    last_month_start = datetime(now.year - 1, 12, 1)
                else:
                    last_month_start = datetime(now.year, now.month - 1, 1)
                presets["last_month"] = (last_month_start, last_month_end)
            
            if preset not in presets:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid preset. Choose from: {', '.join(presets.keys())}"
                )
            filter_start, filter_end = presets[preset]
            period_label = preset.replace("_", " ").title()
            period_days = (filter_end - filter_start).days
        else:
            # Default: use days param (default 7)
            days = days or 7
            filter_start = today_start - timedelta(days=days - 1)  # Include today
            filter_end = today_end
            period_label = f"Last {days} days"
            period_days = days
        
        # Build both DB queries
        payments_stmt = select(
            CustomerPayment, Customer, Plan
        ).join(
            Customer, CustomerPayment.customer_id == Customer.id
        ).outerjoin(
            Plan, Customer.plan_id == Plan.id
        ).where(
            CustomerPayment.reseller_id == user_id,
            CustomerPayment.created_at >= filter_start,
            CustomerPayment.created_at < filter_end
        )
        if router_id:
            payments_stmt = payments_stmt.where(Customer.router_id == router_id)
        payments_stmt = payments_stmt.order_by(CustomerPayment.created_at.desc())
        
        active_customers_stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        if router_id:
            active_customers_stmt = active_customers_stmt.where(Customer.router_id == router_id)
        
        # Execute DB queries sequentially (AsyncSession doesn't support concurrent operations)
        payments_result = await db.execute(payments_stmt)
        active_result = await db.execute(active_customers_stmt)
        
        all_payments = payments_result.all()
        active_customers = active_result.scalars().all()
        
        # Process payments data
        daily_data = defaultdict(lambda: {
            "transactions": [],
            "phones": set(),
            "hourly_activity": defaultdict(int),
            "hourly_revenue": defaultdict(float),
            "plan_counts": defaultdict(int),
            "plan_revenue": defaultdict(float),
            "hourly_by_plan": defaultdict(lambda: defaultdict(int)),
            "phone_totals": defaultdict(float)
        })
        
        plan_colors = {
            0: "#ef4444", 1: "#f97316", 2: "#eab308", 3: "#22c55e",
            4: "#3b82f6", 5: "#a855f7", 6: "#ec4899", 7: "#14b8a6"
        }
        
        unique_customers_set = set()
        
        for payment, customer, plan in all_payments:
            date_key = payment.created_at.strftime("%Y-%m-%d")
            hour = payment.created_at.hour
            amount = float(payment.amount)
            phone = customer.phone[-4:] if customer.phone else "unknown"
            plan_name = plan.name if plan else "Unknown"
            unique_customers_set.add(customer.id)
            
            day = daily_data[date_key]
            day["transactions"].append({
                "time": payment.created_at.strftime("%H:%M:%S"),
                "amount": amount,
                "phone": phone,
                "plan": plan_name
            })
            day["phones"].add(customer.phone)
            day["hourly_activity"][hour] += 1
            day["hourly_revenue"][hour] += amount
            day["plan_counts"][plan_name] += 1
            day["plan_revenue"][plan_name] += amount
            day["hourly_by_plan"][plan_name][hour] += 1
            day["phone_totals"][customer.phone] += amount
        
        # Build response for each day
        days_output = {}
        for date_key in sorted(daily_data.keys(), reverse=True):
            day = daily_data[date_key]
            date_obj = datetime.strptime(date_key, "%Y-%m-%d")
            
            phone_counts = defaultdict(int)
            for tx in day["transactions"]:
                phone_counts[tx["phone"]] += 1
            repeat_customers = sum(1 for c in phone_counts.values() if c > 1)
            
            purchase_counts = {"1_purchase": 0, "2_purchases": 0, "3_purchases": 0, "4plus_purchases": 0}
            for count in phone_counts.values():
                if count == 1:
                    purchase_counts["1_purchase"] += 1
                elif count == 2:
                    purchase_counts["2_purchases"] += 1
                elif count == 3:
                    purchase_counts["3_purchases"] += 1
                else:
                    purchase_counts["4plus_purchases"] += 1
            
            top_spenders = sorted(
                [{"phone": p[-4:], "amount": a} for p, a in day["phone_totals"].items()],
                key=lambda x: x["amount"],
                reverse=True
            )[:5]
            
            plans_list = []
            for idx, (plan_name, count) in enumerate(sorted(day["plan_counts"].items(), key=lambda x: x[1], reverse=True)):
                plans_list.append({
                    "name": plan_name,
                    "count": count,
                    "revenue": day["plan_revenue"][plan_name],
                    "color": plan_colors.get(idx % 8, "#6b7280")
                })
            
            total_revenue = sum(day["plan_revenue"].values())
            unique_users = len(day["phones"])
            
            cumulative_rev = 0.0
            cumulative_txn = 0
            hourly_cumulative = []
            for h in range(24):
                rev = day["hourly_revenue"].get(h, 0.0)
                txn = day["hourly_activity"].get(h, 0)
                cumulative_rev += rev
                cumulative_txn += txn
                hourly_cumulative.append({
                    "hour": h,
                    "hourLabel": f"{h:02d}:00",
                    "revenue": round(rev, 2),
                    "transactions": txn,
                    "cumulativeRevenue": round(cumulative_rev, 2),
                    "cumulativeTransactions": cumulative_txn
                })
            
            days_output[date_key] = {
                "date": date_key,
                "dateLabel": date_obj.strftime("%B %d, %Y"),
                "totalTransactions": len(day["transactions"]),
                "totalRevenue": total_revenue,
                "uniqueUsers": unique_users,
                "avgDailySpendPerUser": round(total_revenue / unique_users, 2) if unique_users > 0 else 0,
                "repeatCustomers": repeat_customers,
                "repeatCustomerPercent": round((repeat_customers / unique_users) * 100, 1) if unique_users > 0 else 0,
                "plans": plans_list,
                "hourlyActivity": dict(day["hourly_activity"]),
                "hourlyRevenue": {k: round(v, 2) for k, v in day["hourly_revenue"].items()},
                "hourlyCumulative": hourly_cumulative,
                "hourlyByPlan": {k: dict(v) for k, v in day["hourly_by_plan"].items()},
                "topSpenders": top_spenders,
                "firstTransaction": day["transactions"][-1]["time"] if day["transactions"] else None,
                "lastTransaction": day["transactions"][0]["time"] if day["transactions"] else None,
                "userPurchaseCounts": purchase_counts
            }
        
        # Calculate summary
        total_txns = sum(d["totalTransactions"] for d in days_output.values())
        total_rev = sum(d["totalRevenue"] for d in days_output.values())
        total_users = sum(d["uniqueUsers"] for d in days_output.values())
        unique_customers_count = len(unique_customers_set)
        
        daily_trend = [
            {
                "date": d["date"],
                "label": d["dateLabel"],
                "transactions": d["totalTransactions"],
                "revenue": d["totalRevenue"],
                "users": d["uniqueUsers"]
            }
            for d in sorted(days_output.values(), key=lambda x: x["date"])
        ]
        
        hourly_totals = defaultdict(lambda: {"transactions": 0, "revenue": 0.0})
        for day in days_output.values():
            for hour, count in day["hourlyActivity"].items():
                hourly_totals[hour]["transactions"] += count
            for hour, rev in day["hourlyRevenue"].items():
                hourly_totals[hour]["revenue"] += rev
        
        hourly_pattern = [
            {"hour": h, "transactions": hourly_totals[h]["transactions"], "revenue": round(hourly_totals[h]["revenue"], 2)}
            for h in range(24)
        ]
        
        plan_totals = defaultdict(lambda: {"count": 0, "revenue": 0.0})
        for day in days_output.values():
            for plan in day["plans"]:
                plan_totals[plan["name"]]["count"] += plan["count"]
                plan_totals[plan["name"]]["revenue"] += plan["revenue"]
        
        plan_performance = [
            {"name": name, "count": data["count"], "revenue": round(data["revenue"], 2)}
            for name, data in sorted(plan_totals.items(), key=lambda x: x[1]["revenue"], reverse=True)
        ]
        
        today_key = today_start.strftime("%Y-%m-%d")
        today_data = days_output.get(today_key, {})
        today_revenue = today_data.get("totalRevenue", 0)
        today_transactions = today_data.get("totalTransactions", 0)
        
        days_with_data = len(days_output) if days_output else 1
        avg_daily_revenue = round(total_rev / period_days, 2) if period_days > 0 else 0
        avg_daily_transactions = round(total_txns / period_days, 2) if period_days > 0 else 0
        avg_transaction_value = round(total_rev / total_txns, 2) if total_txns > 0 else 0
        avg_revenue_per_customer = round(total_rev / unique_customers_count, 2) if unique_customers_count > 0 else 0
        
        # Calculate speed averages from already-fetched active_customers
        total_download = 0.0
        total_upload = 0.0
        speed_count = 0
        
        for customer in active_customers:
            if customer.plan and customer.plan.speed:
                speed = customer.plan.speed
                if "/" in speed:
                    parts = speed.split("/")
                    download = _parse_speed_value(parts[0])
                    upload = _parse_speed_value(parts[1]) if len(parts) > 1 else download
                    total_download += download
                    total_upload += upload
                    speed_count += 1
        
        avg_download_mbps = round(total_download / speed_count, 2) if speed_count > 0 else 0
        avg_upload_mbps = round(total_upload / speed_count, 2) if speed_count > 0 else 0
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "extractedAt": now.isoformat(),
            "period": {
                "label": period_label,
                "days": period_days,
                "startDate": filter_start.strftime("%Y-%m-%d"),
                "endDate": (filter_end - timedelta(days=1)).strftime("%Y-%m-%d"),
            },
            "summary": {
                "totalTransactions": total_txns,
                "totalRevenue": round(total_rev, 2),
                "totalUniqueUsers": total_users,
                "uniqueCustomers": unique_customers_count,
                "avgRevenuePerDay": round(total_rev / days_with_data, 2) if days_with_data else 0,
                "avgTransactionsPerDay": round(total_txns / days_with_data, 2) if days_with_data else 0
            },
            "today": {
                "date": today_key,
                "revenue": round(today_revenue, 2),
                "transactions": today_transactions,
                "hourlyCumulative": today_data.get("hourlyCumulative", [])
            },
            "averages": {
                "dailyRevenue": avg_daily_revenue,
                "dailyTransactions": avg_daily_transactions,
                "transactionValue": avg_transaction_value,
                "revenuePerCustomer": avg_revenue_per_customer,
                "downloadSpeedMbps": avg_download_mbps,
                "uploadSpeedMbps": avg_upload_mbps
            },
            "activeCustomers": len(active_customers),
            "dailyTrend": daily_trend,
            "hourlyPattern": hourly_pattern,
            "planPerformance": plan_performance,
            "days": days_output
        }
        
    except Exception as e:
        logger.error(f"Error fetching analytics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch analytics: {str(e)}")


@router.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@router.get("/api/dashboard/daily-revenue")
async def get_daily_revenue_metrics(
    router_id: Optional[int] = None,
    date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get hourly cumulative revenue for a specific day.
    Returns data suitable for plotting revenue accumulation throughout the day.
    
    Query params:
    - router_id: Optional router ID to filter revenue for a specific router
    - date: YYYY-MM-DD format (defaults to today)
    """
    try:
        user = await get_current_user(token, db)
        user_id = user.id
        
        # Parse date or use today
        if date:
            try:
                target_date = datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
        else:
            target_date = datetime.utcnow()
        
        day_start = datetime(target_date.year, target_date.month, target_date.day)
        day_end = day_start + timedelta(days=1)
        
        # Get all payments for the day ordered by time
        if router_id:
            payments_stmt = select(
                CustomerPayment.amount,
                CustomerPayment.created_at
            ).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= day_start,
                CustomerPayment.created_at < day_end,
                Customer.router_id == router_id
            ).order_by(CustomerPayment.created_at)
        else:
            payments_stmt = select(
                CustomerPayment.amount,
                CustomerPayment.created_at
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= day_start,
                CustomerPayment.created_at < day_end
            ).order_by(CustomerPayment.created_at)
        
        result = await db.execute(payments_stmt)
        payments = result.all()
        
        # Build hourly breakdown with cumulative totals
        hourly_data = {}
        cumulative = 0.0
        transaction_count = 0
        
        for hour in range(24):
            hourly_data[hour] = {
                "hour": hour,
                "hour_label": f"{hour:02d}:00",
                "revenue": 0.0,
                "transactions": 0,
                "cumulative_revenue": 0.0,
                "cumulative_transactions": 0
            }
        
        for payment in payments:
            hour = payment.created_at.hour
            amount = float(payment.amount)
            hourly_data[hour]["revenue"] += amount
            hourly_data[hour]["transactions"] += 1
        
        # Calculate cumulative values
        for hour in range(24):
            cumulative += hourly_data[hour]["revenue"]
            transaction_count += hourly_data[hour]["transactions"]
            hourly_data[hour]["cumulative_revenue"] = round(cumulative, 2)
            hourly_data[hour]["cumulative_transactions"] = transaction_count
        
        # Convert to list sorted by hour
        hourly_list = [hourly_data[h] for h in range(24)]
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "date": day_start.strftime("%Y-%m-%d"),
            "date_label": day_start.strftime("%B %d, %Y"),
            "total_revenue": round(cumulative, 2),
            "total_transactions": transaction_count,
            "hourly": hourly_list,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching daily revenue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/dashboard/stats")
async def get_dashboard_stats(
    router_id: Optional[int] = None,
    period: int = 30,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get dashboard statistics with proper averages based on period.
    
    Query params:
    - router_id: Optional router ID to filter stats for a specific router
    - period: Number of days to calculate stats for (7, 30, 90, etc.)
    
    Returns averages calculated over the specified period.
    """
    try:
        user = await get_current_user(token, db)
        user_id = user.id
        
        now = datetime.utcnow()
        period_start = now - timedelta(days=period)
        today_start = datetime(now.year, now.month, now.day)
        
        # Build queries with optional router filtering
        if router_id:
            # Total revenue in period (with router filter)
            period_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_revenue = float((await db.execute(period_revenue_stmt)).scalar() or 0)
            
            # Total transactions in period
            period_txn_stmt = select(func.count(CustomerPayment.id)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_transactions = (await db.execute(period_txn_stmt)).scalar() or 0
            
            # Unique customers in period
            period_customers_stmt = select(func.count(func.distinct(CustomerPayment.customer_id))).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start,
                Customer.router_id == router_id
            )
            period_unique_customers = (await db.execute(period_customers_stmt)).scalar() or 0
            
            # Today's stats
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start,
                Customer.router_id == router_id
            )
            today_revenue = float((await db.execute(today_revenue_stmt)).scalar() or 0)
            
            today_txn_stmt = select(func.count(CustomerPayment.id)).join(
                Customer, CustomerPayment.customer_id == Customer.id
            ).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start,
                Customer.router_id == router_id
            )
            today_transactions = (await db.execute(today_txn_stmt)).scalar() or 0
        else:
            # Original queries without router filter
            # Total revenue in period
            period_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_revenue = float((await db.execute(period_revenue_stmt)).scalar() or 0)
            
            # Total transactions in period
            period_txn_stmt = select(func.count(CustomerPayment.id)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_transactions = (await db.execute(period_txn_stmt)).scalar() or 0
            
            # Unique customers in period
            period_customers_stmt = select(func.count(func.distinct(CustomerPayment.customer_id))).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= period_start
            )
            period_unique_customers = (await db.execute(period_customers_stmt)).scalar() or 0
            
            # Today's stats
            today_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_revenue = float((await db.execute(today_revenue_stmt)).scalar() or 0)
            
            today_txn_stmt = select(func.count(CustomerPayment.id)).where(
                CustomerPayment.reseller_id == user_id,
                CustomerPayment.created_at >= today_start
            )
            today_transactions = (await db.execute(today_txn_stmt)).scalar() or 0
        
        # Calculate averages for the period
        avg_daily_revenue = round(period_revenue / period, 2) if period > 0 else 0
        avg_daily_transactions = round(period_transactions / period, 2) if period > 0 else 0
        avg_transaction_value = round(period_revenue / period_transactions, 2) if period_transactions > 0 else 0
        avg_revenue_per_customer = round(period_revenue / period_unique_customers, 2) if period_unique_customers > 0 else 0
        
        # Get plan speed averages (from active customers)
        active_customers_stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(
            Customer.user_id == user_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        if router_id:
            active_customers_stmt = active_customers_stmt.where(Customer.router_id == router_id)
        active_result = await db.execute(active_customers_stmt)
        active_customers = active_result.scalars().all()
        
        total_download = 0.0
        total_upload = 0.0
        speed_count = 0
        
        for customer in active_customers:
            if customer.plan and customer.plan.speed:
                speed = customer.plan.speed
                if "/" in speed:
                    parts = speed.split("/")
                    download = _parse_speed_value(parts[0])
                    upload = _parse_speed_value(parts[1]) if len(parts) > 1 else download
                    total_download += download
                    total_upload += upload
                    speed_count += 1
        
        avg_download_speed = round(total_download / speed_count, 2) if speed_count > 0 else 0
        avg_upload_speed = round(total_upload / speed_count, 2) if speed_count > 0 else 0
        
        # Get router name if filtered
        router_name = None
        if router_id:
            router_result = await db.execute(select(Router).where(Router.id == router_id))
            router_obj = router_result.scalar_one_or_none()
            router_name = router_obj.name if router_obj else None
        
        return {
            "router_id": router_id,
            "router_name": router_name,
            "period_days": period,
            "period_start": period_start.isoformat(),
            "today": {
                "revenue": today_revenue,
                "transactions": today_transactions
            },
            "period_totals": {
                "revenue": round(period_revenue, 2),
                "transactions": period_transactions,
                "unique_customers": period_unique_customers
            },
            "averages": {
                "daily_revenue": avg_daily_revenue,
                "daily_transactions": avg_daily_transactions,
                "transaction_value": avg_transaction_value,
                "revenue_per_customer": avg_revenue_per_customer,
                "download_speed_mbps": avg_download_speed,
                "upload_speed_mbps": avg_upload_speed
            },
            "active_customers": len(active_customers),
            "generated_at": now.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _parse_speed_value(speed_str: str) -> float:
    """Parse speed string like '5M', '10', '512K' into Mbps float"""
    speed_str = speed_str.strip().upper()
    try:
        if speed_str.endswith('G'):
            return float(speed_str[:-1]) * 1000
        elif speed_str.endswith('M'):
            return float(speed_str[:-1])
        elif speed_str.endswith('K'):
            return float(speed_str[:-1]) / 1000
        else:
            return float(speed_str)
    except ValueError:
        return 0.0

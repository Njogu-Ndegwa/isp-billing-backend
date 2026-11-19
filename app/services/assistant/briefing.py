"""Live figures for the assistant's home screen (GET /api/assistant/briefing).

One short DB session of aggregate queries: no customer list is loaded, and
there is no router or network I/O. The result is kept for a minute per person.

It never fails as a whole. Each section is gated by the dashboard route that
shows the same figures (``Catalog.allowed``), so staff permissions and View-as
follow the rules the guards already apply; a section the caller may not see,
or whose query failed, is left out and named in ``unavailable`` (the ones that
are a matter of access are also in ``not_allowed``).

"Today" and revenue follow GET /api/dashboard/analytics: days are UTC days,
payments are counted by ``created_at``, and only ``counts_as_revenue``
payments add to revenue (a comp voucher is a payment, not revenue).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import and_, case, func, select

from app.db import database as db_module
from app.db.models import (
    C2BTransaction, C2BTransactionStatus, Customer, CustomerPayment, CustomerStatus,
    MpesaTransaction, MpesaTransactionStatus, Plan, ResellerPaymentMethod, Router,
    SmsCreditAccount, UnmatchedC2BPayment, User,
)
from app.services.assistant.caller import Caller
from app.services.assistant.catalog import Catalog

logger = logging.getLogger(__name__)

TTL_SECONDS = 60.0
MAX_CACHED = 1000
DAYS = 14
LIST_LIMIT = 5
EXPIRING_LIST_DAYS = 7     # the "next to expire" list looks this far ahead

# section -> the dashboard route(s) whose access decides it (any one is enough)
GATES: dict[str, tuple[tuple[str, str], ...]] = {
    "money": (("GET", "/api/dashboard/analytics"),),
    "customers": (("GET", "/api/customers"),),
    "routers": (("GET", "/api/routers"),),
    "plans": (("GET", "/api/plans/performance"),),   # revenue per plan, so not the plain plan list's rule
    "sms_credits": (("GET", "/api/messaging/credits"),),
    "subscription": (("GET", "/api/subscription"),),
    "unmatched_payments": (("GET", "/api/c2b/unmatched"),),
    "failed_payments_24h": (("GET", "/api/mpesa/transactions/failed"),),
    "setup_plans": (("GET", "/api/plans"),),
    "setup_payment_methods": (("GET", "/api/payment-methods"),),
}

_cache: dict[tuple, tuple[float, dict]] = {}


def reset_cache() -> None:
    _cache.clear()


def _may(catalog: Catalog, caller: Caller, section: str) -> bool:
    for method, template in GATES[section]:
        action = catalog.get(method, template)
        if action is not None and catalog.allowed(action, caller):
            return True
    return False


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value else None


def _revenue():
    return func.coalesce(func.sum(case((CustomerPayment.counts_as_revenue.is_(True), CustomerPayment.amount),
                                       else_=0)), 0)


def _count_if(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


# -- sections (each: a few statements on the shared session) -------------------

async def _money(db, user_id: int, now: datetime) -> dict:
    today = datetime(now.year, now.month, now.day)
    first = today - timedelta(days=DAYS - 1)
    day = func.date(CustomerPayment.created_at)
    rows = (await db.execute(
        select(day, _revenue(), func.count(CustomerPayment.id))
        .where(CustomerPayment.reseller_id == user_id,
               CustomerPayment.created_at >= first,
               CustomerPayment.created_at < today + timedelta(days=1))
        .group_by(day)
    )).all()
    by_day = {str(d)[:10]: (float(revenue or 0), int(payments or 0)) for d, revenue, payments in rows}
    daily = []
    for i in range(DAYS):
        key = (first + timedelta(days=i)).strftime("%Y-%m-%d")
        revenue, payments = by_day.get(key, (0.0, 0))
        daily.append({"day": key, "revenue": round(revenue, 2), "payments": payments,
                      "partial": i == DAYS - 1})
    month = float((await db.execute(
        select(_revenue()).where(CustomerPayment.reseller_id == user_id,
                                 CustomerPayment.created_at >= datetime(now.year, now.month, 1),
                                 CustomerPayment.created_at < today + timedelta(days=1))
    )).scalar() or 0)
    total = lambda part: round(sum(d["revenue"] for d in part), 2)  # noqa: E731
    return {
        "today": daily[-1]["revenue"],
        "yesterday": daily[-2]["revenue"],
        "last7": total(daily[-7:]),       # today and the six days before, as the dashboard's "last 7 days"
        "prev7": total(daily[-14:-7]),
        "month": round(month, 2),
        "payments_today": daily[-1]["payments"],
        "daily": daily,
    }


async def _customers(db, user_id: int, now: datetime) -> dict:
    today_end = datetime(now.year, now.month, now.day) + timedelta(days=1)
    active = Customer.status == CustomerStatus.ACTIVE
    row = (await db.execute(
        select(
            func.count(Customer.id),
            _count_if(active),
            _count_if(and_(active, Customer.expiry >= now, Customer.expiry < today_end)),
            _count_if(and_(active, Customer.expiry >= now, Customer.expiry < now + timedelta(days=3))),
            # a renewal moves expiry forward, so an expiry in the last week means "ran out and
            # has not renewed"; a paused customer's expiry is frozen and is not an expiry
            _count_if(and_(Customer.expiry >= now - timedelta(days=7), Customer.expiry < now,
                           Customer.paused_at.is_(None))),
            _count_if(Customer.created_at >= now - timedelta(days=7)),
        ).where(Customer.user_id == user_id)
    )).one()
    soon = (await db.execute(
        select(Customer.id, Customer.name, Customer.phone, Customer.expiry, Plan.name)
        .outerjoin(Plan, Plan.id == Customer.plan_id)
        .where(Customer.user_id == user_id, active, Customer.expiry >= now,
               Customer.expiry < now + timedelta(days=EXPIRING_LIST_DAYS))
        .order_by(Customer.expiry.asc(), Customer.id.asc())
        .limit(LIST_LIMIT)
    )).all()
    return {
        "total": int(row[0] or 0), "active": int(row[1] or 0),
        "expiring_today": int(row[2] or 0), "expiring_3d": int(row[3] or 0),
        "expired_7d": int(row[4] or 0), "new_7d": int(row[5] or 0),
        "expiring": [{"id": cid, "name": name, "phone": phone, "expiry": _iso(expiry), "plan": plan}
                     for cid, name, phone, expiry, plan in soon],
    }


async def _routers(db, user_id: int, now: datetime) -> dict:
    from app.services.router_availability import derive_router_status

    rows = (await db.execute(
        select(Router.id, Router.name, Router.last_status, Router.last_checked_at, Router.last_online_at)
        .where(Router.user_id == user_id).order_by(Router.id).limit(1000)
    )).all()
    counts = {"online": 0, "offline": 0, "unknown": 0}
    down = []
    for rid, name, last_status, last_checked_at, last_online_at in rows:
        status = derive_router_status(
            SimpleNamespace(last_status=last_status, last_checked_at=last_checked_at), now=now)
        counts[status] = counts.get(status, 0) + 1
        if status == "offline":
            down.append((last_online_at or datetime.min, rid, name, last_online_at))
    down.sort(key=lambda item: item[0], reverse=True)  # the most recent outage first
    return {
        "total": len(rows), **counts,
        "down": [{"id": rid, "name": name, "last_online_at": _iso(last_online_at)}
                 for _, rid, name, last_online_at in down[:LIST_LIMIT]],
    }


async def _plans(db, user_id: int, now: datetime) -> list:
    from app.services.payment_plan import payment_plan_id

    today = datetime(now.year, now.month, now.day)
    revenue = _revenue()
    rows = (await db.execute(
        select(Plan.name, revenue, func.count(CustomerPayment.id))
        .select_from(CustomerPayment)
        .outerjoin(Customer, CustomerPayment.customer_id == Customer.id)
        .join(Plan, Plan.id == payment_plan_id())
        .where(CustomerPayment.reseller_id == user_id,
               CustomerPayment.created_at >= today - timedelta(days=6),
               CustomerPayment.created_at < today + timedelta(days=1))
        .group_by(Plan.id, Plan.name)
        .order_by(revenue.desc(), Plan.name.asc())
        .limit(LIST_LIMIT)
    )).all()
    return [{"name": name, "revenue": round(float(total or 0), 2), "sales": int(sales or 0)}
            for name, total, sales in rows]


async def _failed_payments(db, user_id: int, now: datetime) -> int:
    return int((await db.execute(
        select(func.count(MpesaTransaction.id))
        .join(Customer, MpesaTransaction.customer_id == Customer.id)
        .where(Customer.user_id == user_id,
               MpesaTransaction.status.in_([MpesaTransactionStatus.failed, MpesaTransactionStatus.expired]),
               MpesaTransaction.created_at >= now - timedelta(hours=24))
    )).scalar() or 0)


async def _unmatched_payments(db, user_id: int, now: datetime) -> int:
    return int((await db.execute(
        select(func.count(UnmatchedC2BPayment.id))
        .where(UnmatchedC2BPayment.assigned_reseller_id == user_id,
               UnmatchedC2BPayment.resolved_at.is_(None),
               ~UnmatchedC2BPayment.c2b_transaction.has(
                   C2BTransaction.status == C2BTransactionStatus.STK_ECHO))
    )).scalar() or 0)


async def _sms_credits(db, user_id: int, now: datetime) -> int:
    return int((await db.execute(
        select(SmsCreditAccount.balance).where(SmsCreditAccount.user_id == user_id)
    )).scalar() or 0)


async def _subscription(db, account: Optional[SimpleNamespace]) -> Optional[dict]:
    from app.services.subscription import get_invoice_amount_paid, get_pending_invoice

    if account is None:
        return None
    invoice = await get_pending_invoice(db, account.id)
    amount_due = None
    if invoice is not None:
        charge = float(invoice.final_charge or 0)
        paid = await get_invoice_amount_paid(db, invoice.id)
        amount_due = round(max(charge - paid, 0.0), 2)
    return {"status": account.subscription_status, "expires_at": _iso(account.subscription_expires_at),
            "amount_due": amount_due}


async def _count(db, model, user_id: int) -> int:
    return int((await db.execute(
        select(func.count(model.id)).where(model.user_id == user_id))).scalar() or 0)


# -- the briefing -----------------------------------------------------------------

async def build(catalog: Catalog, caller: Caller) -> dict:
    """The briefing for this caller, at most a minute old."""
    key = (caller.user_id, caller.staff_id, caller.role, caller.viewer_sid is not None)
    hit = _cache.get(key)
    if hit is not None and hit[0] > time.monotonic():
        return hit[1]
    payload = await _build(catalog, caller)
    if len(_cache) >= MAX_CACHED:
        now = time.monotonic()
        for k in [k for k, (expires, _) in _cache.items() if expires <= now] or list(_cache)[:MAX_CACHED // 4]:
            _cache.pop(k, None)
    _cache[key] = (time.monotonic() + TTL_SECONDS, payload)
    return payload


async def _build(catalog: Catalog, caller: Caller) -> dict:
    now = datetime.utcnow()
    if caller.is_admin:
        # Platform figures come from the admin dashboard's own endpoint.
        return {"as_of": _iso(now), "audience": "admin", "name": caller.organization or None,
                "unavailable": []}

    user_id = caller.user_id
    out: dict[str, Any] = {
        "as_of": _iso(now), "audience": "reseller",
        "name": caller.staff_name or caller.organization or None, "currency": "KES",
    }
    unavailable: list[str] = []
    not_allowed: list[str] = []
    may = {section: _may(catalog, caller, section) for section in GATES}

    try:
        async with db_module.async_session() as db:

            async def section(name: str, gate: str, work: Callable[[], Awaitable[Any]], default=None):
                """One figure or card: None when the caller may not see it or the query failed."""
                if not may[gate]:
                    not_allowed.append(name)
                    unavailable.append(name)
                    return default
                try:
                    return await work()
                except Exception:
                    logger.exception("[assistant] briefing section %s failed for user %s", name, user_id)
                    await db.rollback()  # a failed statement must not poison the next section
                    unavailable.append(name)
                    return default

            # Plain values, not the ORM row: a rollback after a failed section expires loaded
            # objects, and touching one afterwards would mean another (lazy) query.
            account = None
            try:
                user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
                if user is not None:
                    from app.services.markets import reseller_market

                    out["currency"] = reseller_market(user).currency
                    if not caller.staff_name:
                        out["name"] = user.organization_name or out["name"]
                    account = SimpleNamespace(
                        id=user.id,
                        subscription_status=getattr(user.subscription_status, "value", user.subscription_status),
                        subscription_expires_at=user.subscription_expires_at,
                    )
            except Exception:
                logger.exception("[assistant] briefing account read failed for user %s", user_id)
                await db.rollback()

            for name, work in (("money", _money), ("customers", _customers),
                               ("routers", _routers), ("plans", _plans)):
                value = await section(name, name, lambda work=work: work(db, user_id, now))
                if value is not None:
                    out[name] = value

            out["attention"] = {
                "failed_payments_24h": await section(
                    "failed_payments_24h", "failed_payments_24h", lambda: _failed_payments(db, user_id, now)),
                "unmatched_payments": await section(
                    "unmatched_payments", "unmatched_payments", lambda: _unmatched_payments(db, user_id, now)),
                "sms_credits": await section(
                    "sms_credits", "sms_credits", lambda: _sms_credits(db, user_id, now)),
                "subscription": await section(
                    "subscription", "subscription", lambda: _subscription(db, account)),
            }

            routers = out.get("routers")
            customers = out.get("customers")
            setup_names = len(unavailable)
            out["setup"] = {
                "routers": routers["total"] if routers else None,
                "plans": await section("setup_plans", "setup_plans", lambda: _count(db, Plan, user_id)),
                "payment_methods": await section(
                    "setup_payment_methods", "setup_payment_methods",
                    lambda: _count(db, ResellerPaymentMethod, user_id)),
                "customers": customers["total"] if customers else None,
            }
            # the setup counts are not sections of their own on the page
            del unavailable[setup_names:]
            not_allowed[:] = [n for n in not_allowed if not n.startswith("setup_")]
            await db.commit()
    except Exception:
        # Could not even open a session: say everything is unavailable, never 500.
        logger.exception("[assistant] briefing failed for user %s", user_id)
        for name in ("money", "customers", "routers", "plans", "failed_payments_24h",
                     "unmatched_payments", "sms_credits", "subscription"):
            if name not in unavailable and name not in out:
                unavailable.append(name)
        out.setdefault("attention", {"failed_payments_24h": None, "unmatched_payments": None,
                                     "sms_credits": None, "subscription": None})
        out.setdefault("setup", {"routers": None, "plans": None, "payment_methods": None, "customers": None})

    out["unavailable"] = unavailable
    out["not_allowed"] = not_allowed
    return out

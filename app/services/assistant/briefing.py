"""Live figures for the assistant's home screen (GET /api/assistant/briefing).

One short DB session of aggregate queries: no customer list is loaded, and
there is no router or network I/O. The result is kept for a minute per person.

It never fails as a whole. Each section is gated by the dashboard route that
shows the same figures (``Catalog.allowed``), so staff permissions and View-as
follow the rules the guards already apply; a section the caller may not see,
or whose query failed, is left out and named in ``unavailable`` (the ones that
are a matter of access are also in ``not_allowed``).

"Today" and revenue follow GET /api/dashboard/analytics and the assistant's own
GET /api/mpesa/transactions/summary: days, weeks and months are the account's
own calendar (``local_day``; midnight in Nairobi is 21:00 UTC), payments are
the money section adds up the very rows the summary does
(``payment_routes.summary_rows``: STK prompts by prompt time, paybill by
receipt time, other ledger entries by ``created_at``), only completed payments
count, and only ``counts_as_revenue`` payments add to revenue (a comp voucher is
a payment, not revenue). Reported 2026-11-27: at 21:23 EAT the home screen said KES 683 from
57 payments while the chat, asked the same thing, said KES 707 from 59; the two
payments made between local midnight and 03:00 were missing from the home
screen because its "today" began at UTC midnight.
"""
from __future__ import annotations

import logging
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import and_, case, func, or_, select

from app.db import database as db_module
from app.db.models import (
    C2BTransaction, C2BTransactionStatus, Customer, CustomerPayment, CustomerStatus, PaymentStatus,
    MpesaTransaction, MpesaTransactionStatus, Plan, ResellerPaymentMethod, Router,
    SmsCreditAccount, UnmatchedC2BPayment, User,
)
from app.services import local_day
from app.services.money_time import moment_between
from app.services.assistant.caller import Caller
from app.services.assistant.catalog import Catalog

logger = logging.getLogger(__name__)

TTL_SECONDS = 60.0
MAX_CACHED = 1000
DAYS = 14
LIST_LIMIT = 5
EXPIRING_LIST_DAYS = 7     # the "next to expire" list looks this far ahead
NETWORK_LIMIT = 12         # routers drawn one by one on the home screen (trouble first)
LIVE_MAX_AGE_SECONDS = 600  # a router's own report older than this is not "live"
WIRED_PORT = re.compile(r"^(ether|sfp|combo|qsfp)", re.IGNORECASE)  # the sockets on the router's front

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


def _utcnow() -> datetime:
    return datetime.utcnow()


@dataclass(frozen=True)
class Clock:
    """Now, and the account's calendar: every bound is naive UTC, as stored."""
    now: datetime                 # naive UTC
    today: date                   # the account's date now
    zone_user: Any                # anything with market_code, for local_day

    def start_of(self, day: date) -> datetime:
        """Local midnight starting ``day``, as naive UTC."""
        return local_day.from_wall_clock(datetime(day.year, day.month, day.day), self.zone_user)

    @property
    def today_start(self) -> datetime:
        return self.start_of(self.today)

    @property
    def tomorrow_start(self) -> datetime:
        return self.start_of(self.today + timedelta(days=1))

    def local_date(self, utc_naive: datetime) -> date:
        return local_day.wall_clock(utc_naive, self.zone_user).date()


def make_clock(zone_user, now: Optional[datetime] = None) -> Clock:
    now = now or _utcnow()
    return Clock(now=now, today=local_day.today(zone_user, now), zone_user=zone_user)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value else None


def _revenue():
    return func.coalesce(func.sum(case((CustomerPayment.counts_as_revenue.is_(True), CustomerPayment.amount),
                                       else_=0)), 0)


def _completed():
    """A pending, failed or refunded payment is not money made (the summary agrees)."""
    return or_(CustomerPayment.status.is_(None), CustomerPayment.status == PaymentStatus.COMPLETED)


def _count_if(condition):
    return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)


# -- sections (each: a few statements on the shared session) -------------------

async def _money(db, user_id: int, clock: Clock) -> dict:
    # The same rows the transactions summary adds up (what the chat says), so the
    # home screen and the chat cannot disagree; each payment goes in the day it
    # was made on the account's clock.
    from app.api.payment_routes import summary_rows

    first_day = clock.today - timedelta(days=DAYS - 1)
    month_start = clock.today.replace(day=1)
    since = min(first_day, month_start)
    rows = await summary_rows(db, user_id, date_start=clock.start_of(since),
                              date_end=clock.tomorrow_start - timedelta(microseconds=1))
    by_day: dict[date, list] = {}
    for row in rows:
        if row["status"] != "completed":
            continue      # a failed, expired or pending attempt is not money made
        bucket = by_day.setdefault(clock.local_date(row["at"]), [0.0, 0])
        if row["counts_as_revenue"]:
            bucket[0] += row["amount"]
        bucket[1] += 1    # a comp is a payment, just not revenue
    daily = []
    for i in range(DAYS):
        day = first_day + timedelta(days=i)
        revenue, payments = by_day.get(day, (0.0, 0))
        daily.append({"day": day.strftime("%Y-%m-%d"), "revenue": round(revenue, 2), "payments": payments,
                      "partial": i == DAYS - 1})
    month = sum(revenue for day, (revenue, _) in by_day.items() if day >= month_start)
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


async def _customers(db, user_id: int, clock: Clock) -> dict:
    now, today_end = clock.now, clock.tomorrow_start   # "expiring today": before the account's midnight
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
        select(Router.id, Router.name, Router.identity, Router.last_status, Router.last_checked_at,
               Router.last_online_at, Router.availability_checks, Router.availability_successes,
               Router.pppoe_ports, Router.dual_ports, Router.plain_ports, Router.lb_enabled, Router.lb_config)
        .where(Router.user_id == user_id).order_by(Router.id).limit(1000)
    )).all()
    counts = {"online": 0, "offline": 0, "unknown": 0}
    down = []
    network = []
    for (rid, name, identity, last_status, last_checked_at, last_online_at, checks, successes,
         pppoe_ports, dual_ports, plain_ports, lb_enabled, lb_config) in rows:
        status = derive_router_status(
            SimpleNamespace(last_status=last_status, last_checked_at=last_checked_at), now=now)
        counts[status] = counts.get(status, 0) + 1
        if status == "offline":
            down.append((last_online_at or datetime.min, rid, name, last_online_at))
        setup = port_setup(pppoe_ports, dual_ports, plain_ports, lb_enabled, lb_config)
        network.append({
            "id": rid, "name": name, "identity": identity, "status": status,
            "last_online_at": _iso(last_online_at),
            "reachable_pct": round(successes * 100 / checks, 1) if checks else None,
            "active_customers": None,   # filled in when the caller may see customers
            "live": _live(rid, now),
            "port_setup": setup,
            "ports": _ports(rid, now, setup) if status != "offline" else None,
        })
    down.sort(key=lambda item: item[0], reverse=True)  # the most recent outage first
    network.sort(key=lambda r: (r["status"] != "offline", r["live"] is None, r["id"]))  # trouble first
    return {
        "total": len(rows), **counts,
        "down": [{"id": rid, "name": name, "last_online_at": _iso(last_online_at)}
                 for _, rid, name, last_online_at in down[:LIST_LIMIT]],
        "list": network[:NETWORK_LIMIT],
    }


def _live(router_id: int, now: datetime) -> Optional[dict]:
    """What the router itself last reported (CPU, memory, people online, WAN traffic).

    Read from memory: the usage-push report the router sends on its own. Nothing here
    contacts the router. None when the router does not report or its report is old.
    """
    try:
        from app.services import realtime_state

        state = realtime_state.get_router_live(router_id)
        if state is None:
            return None
        age = (now - state.received_at).total_seconds()
        if age > LIVE_MAX_AGE_SECONDS:
            return None
        total, free = state.total_memory, state.free_memory
        return {
            "cpu": state.cpu_load,
            "memory_pct": round((total - free) * 100 / total) if total and free is not None else None,
            "uptime": state.uptime or None,
            "version": state.version or None,
            "board": state.board or None,
            "down_bps": state.wan_rx_bps,
            "up_bps": state.wan_tx_bps,
            "hotspot_online": state.hotspot_active,
            "pppoe_online": state.pppoe_active,
            "age_seconds": round(max(0.0, age)),
        }
    except Exception:
        logger.exception("[assistant] live report read failed for router %s", router_id)
        return None


def _names(value: Any) -> list:
    return sorted({str(p) for p in value if p}) if isinstance(value, (list, tuple)) else []


def port_setup(pppoe_ports: Any, dual_ports: Any, plain_ports: Any, lb_enabled: Any, lb_config: Any) -> dict:
    """What each port was set up for in Bitwave, from the router's saved settings.

    internet: the WAN ports (the load-balanced ones when load balancing is on, else
    ether1, the convention every other port setting refuses to touch); pppoe, both
    (hotspot and PPPoE on one port) and free (internet with no login) are the ports
    moved off the hotspot. Every other port in the LAN bridge is hotspot.
    """
    wan = _names((lb_config or {}).get("wan_ports")) if lb_enabled and isinstance(lb_config, dict) else []
    return {
        "internet": wan or ["ether1"],
        "pppoe": _names(pppoe_ports),
        "both": _names(dual_ports),
        "free": _names(plain_ports),
    }


def port_role(name: str, setup: dict, bridge_of: Optional[dict]) -> str:
    """internet | both | pppoe | free | hotspot | unused, for one port.

    ``bridge_of`` maps a port to its bridge (None when the router did not say): a
    port in no bridge and set up for nothing carries no customers ("unused").
    """
    bridged = None if bridge_of is None else bool(bridge_of.get(name))
    if name in setup["internet"] and not bridged:
        return "internet"
    for role in ("both", "pppoe", "free"):
        if name in setup[role]:
            return role
    return "unused" if bridged is False else "hotspot"


def _ports(router_id: int, now: datetime, setup: dict) -> Optional[list]:
    """Each socket on the router: what it is set up for, whether it has a link, how
    many devices sit behind it. From the router's own report, as ``_live``: nothing
    here contacts the router. None when it does not report ports or the report is old.

    ``lost_link``: no link now, but it had one since the router started, so something
    that was plugged in and working (an access point, a switch, the internet line)
    went dark. A socket that never had a link is just empty.
    """
    try:
        from app.services import realtime_state

        state = realtime_state.get_router_live(router_id)
        if state is None or not state.ports or (now - state.received_at).total_seconds() > LIVE_MAX_AGE_SECONDS:
            return None
        bridge_of = ({bp.get("interface"): bp.get("bridge") for bp in state.bridge_ports}
                     if state.bridge_ports is not None else None)
        devices = Counter(state.bridge_hosts.values()) if state.bridge_hosts is not None else None
        out = []
        for p in state.ports:
            name = str(p.get("name") or "")
            if not WIRED_PORT.match(name):
                continue
            role = port_role(name, setup, bridge_of)
            disabled = bool(p.get("disabled"))
            up = bool(p.get("running")) and not disabled
            out.append({
                "name": name, "role": role, "up": up, "disabled": disabled,
                "lost_link": not up and not disabled and role != "unused" and bool(p.get("last_link_up")),
                "link_downs": int(p.get("link_downs") or 0),
                "devices": devices.get(name, 0) if devices is not None and role != "internet" else None,
            })
        # in the order printed on the router: ether2 before ether10
        out.sort(key=lambda x: [int(s) if s.isdigit() else s for s in re.split(r"(\d+)", x["name"].lower())])
        return out or None
    except Exception:
        logger.exception("[assistant] port report read failed for router %s", router_id)
        return None


async def _active_by_router(db, user_id: int, now: datetime) -> dict:
    """Customers with paid time left, per router (one grouped count)."""
    rows = (await db.execute(
        select(Customer.router_id, func.count(Customer.id))
        .where(Customer.user_id == user_id, Customer.status == CustomerStatus.ACTIVE, Customer.expiry >= now)
        .group_by(Customer.router_id)
    )).all()
    return {router_id: int(count) for router_id, count in rows if router_id is not None}


async def _plans(db, user_id: int, clock: Clock) -> list:
    from app.services.payment_plan import payment_plan_id

    revenue = _revenue()
    rows = (await db.execute(
        select(Plan.name, revenue, func.count(CustomerPayment.id))
        .select_from(CustomerPayment)
        .outerjoin(Customer, CustomerPayment.customer_id == Customer.id)
        .join(Plan, Plan.id == payment_plan_id())
        .where(CustomerPayment.reseller_id == user_id,
               _completed(),
               moment_between(clock.start_of(clock.today - timedelta(days=6)), clock.tomorrow_start))
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
    now = _utcnow()
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
            zone_user = SimpleNamespace(market_code=None)   # Kenya when the account is unknown
            try:
                user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
                if user is not None:
                    from app.services.markets import reseller_market

                    out["currency"] = reseller_market(user).currency
                    zone_user = SimpleNamespace(market_code=user.market_code)
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

            clock = make_clock(zone_user, now)
            for name, work, when in (("money", _money, clock), ("customers", _customers, clock),
                                     ("routers", _routers, now), ("plans", _plans, clock)):
                value = await section(name, name, lambda work=work, when=when: work(db, user_id, when))
                if value is not None:
                    out[name] = value

            # how many paying customers sit on each router: only for someone who may see customers
            if out.get("routers") and out["routers"]["list"] and may["customers"]:
                try:
                    per_router = await _active_by_router(db, user_id, now)
                    for item in out["routers"]["list"]:
                        item["active_customers"] = per_router.get(item["id"], 0)
                except Exception:
                    logger.exception("[assistant] briefing customers-per-router failed for user %s", user_id)
                    await db.rollback()

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

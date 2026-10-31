"""Bitwave's own earnings next to the transaction volume it processes.

The admin dashboard used to call every customer payment "revenue". Almost all
of that money belongs to resellers: it is transaction volume (GMV). What
Bitwave itself earns is much smaller and comes from these streams:

* Subscription invoices paid by resellers (``subscription_payments`` joined to
  ``subscription_invoices``). Each invoice is built in
  ``app/services/subscription.py::calculate_reseller_charges`` from:
    - the hotspot commission: ``hotspot_rate`` (3% in Kenya) of the reseller's
      hotspot takings for the billing period, whatever the settlement mode.
      It is invoiced monthly, never deducted at source: direct-settlement
      money goes straight to the reseller and platform-collected money is
      paid out in full by B2B (``mpesa_b2b.PAYOUT_REVENUE_FILTERS``);
    - the per-user fee for every active PPPoE / static-IP customer;
    - the minimum-charge top-up (``final_charge - hotspot - per-user``), which
      is also the whole charge in flat-fee markets.
  A payment is split across those three lines in proportion to its invoice,
  so a half-paid invoice contributes half of each line. A payment with no
  invoice (or a zero-charge invoice) is reported as "unattributed".
  Card payments are counted net of the assumed Paystack fee, as MRR is.
* SMS credit sales (``sms_credit_orders`` with status completed). Credits an
  admin grants and credits refunded for failed sends are ledger moves, not
  sales, so they are not counted.

"Collected" is cash received in the window. "Invoiced" is what the invoices
issued in the window billed (waived invoices excluded and shown on their own),
with how much of it has been paid so far. Both are reported because they
answer different questions and drift apart whenever resellers pay late.

Not counted as earnings, but reported so nothing is hidden:
* hardware shop sales (``shop_orders`` paid): gross product sales with a cost
  of goods behind them, a different business from the platform fee;
* reseller transaction charges (``reseller_transaction_charges``): mostly the
  M-Pesa B2B fee passed back to the reseller, which recovers a cost Bitwave
  already paid Safaricom.

Subscription and SMS payments made by the reseller accounts the admin runs
personally (``admin_own_reseller_ids``) are excluded, as in the Earnings page:
paying ourselves is not income. Their customer payments still count towards
transaction volume, because that money really did flow through the platform.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import cache
from app.db.models import (
    CollectionMode,
    CustomerPayment,
    InvoiceStatus,
    PaymentMethod,
    PaymentStatus,
    ResellerTransactionCharge,
    ShopOrder,
    ShopOrderPaymentStatus,
    SmsCreditOrder,
    SmsCreditOrderStatus,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    User,
)
from app.services import admin_metrics as metrics
from app.services.markets import REPORTING_CURRENCY, sql_kes_by_currency, sql_kes_by_market

PLATFORM_EARNINGS_CACHE_PREFIX = "admin_platform_earnings:"
PLATFORM_EARNINGS_CACHE_TTL = 90

# The dashboard's range chips send 7d/30d/90d/1y; the Earnings page sends the
# calendar names. Both mean the same calendar period-to-date.
PERIOD_ALIASES = {"7d": "week", "30d": "month", "90d": "quarter", "1y": "year"}

# Ordered as the breakdown lists them.
EARNING_STREAMS: list[dict[str, str]] = [
    {"key": "subscription_hotspot", "label": "Hotspot commission", "group": "subscriptions"},
    {"key": "subscription_per_user", "label": "PPPoE / static per-user fees", "group": "subscriptions"},
    {"key": "subscription_minimum", "label": "Minimum / flat subscription fee", "group": "subscriptions"},
    {"key": "subscription_unattributed", "label": "Subscription payments without an invoice", "group": "subscriptions"},
    {"key": "sms_credits", "label": "SMS credit sales", "group": "sms"},
]
_SUBSCRIPTION_KEYS = tuple(s["key"] for s in EARNING_STREAMS if s["group"] == "subscriptions")


@dataclass(frozen=True)
class Windows:
    cur_start: datetime
    cur_end: datetime
    prev_start: datetime
    prev_end: datetime


def normalize_period(period: str | None) -> str:
    period = PERIOD_ALIASES.get(period or "", period or "month")
    return period if period in metrics.EARNINGS_PERIODS else "month"


def windows_for(period: str) -> Windows:
    prev_start, prev_end, cur_start, cur_end = metrics._earnings_windows(period)

    def at(d: date) -> datetime:
        return datetime.combine(d, time.min)

    return Windows(at(cur_start), at(cur_end), at(prev_start), at(prev_end))


def _in_window(ts, start: datetime, end: datetime):
    return and_(ts >= start, ts < end)


def _sum_in(amount, condition):
    return func.coalesce(func.sum(case((condition, amount), else_=0.0)), 0.0)


def _excluding(column, own_ids: list[int]):
    return [column.notin_(own_ids)] if own_ids else []


def _invoice_shares():
    """(hotspot, per-user, minimum) share of an invoice, each 0..1.

    Valid only where ``final_charge > 0``; callers guard on that."""
    final = SubscriptionInvoice.final_charge
    hotspot = func.coalesce(SubscriptionInvoice.hotspot_charge, 0.0)
    per_user = func.coalesce(SubscriptionInvoice.pppoe_charge, 0.0)
    rest = final - hotspot - per_user
    minimum = case((rest > 0, rest), else_=0.0)
    return hotspot / final, per_user / final, minimum / final


async def _transaction_volume(db: AsyncSession, w: Windows) -> dict[str, Any]:
    ts = CustomerPayment.created_at
    amount = sql_kes_by_market(CustomerPayment.amount, User.market_code)
    current = _in_window(ts, w.cur_start, w.cur_end)
    mpesa = CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY
    direct = CustomerPayment.collection_mode == CollectionMode.DIRECT

    row = (await db.execute(
        select(
            _sum_in(amount, current).label("cur"),
            _sum_in(amount, _in_window(ts, w.prev_start, w.prev_end)).label("prev"),
            _sum_in(amount, and_(current, mpesa, or_(
                CustomerPayment.collection_mode.is_(None), ~direct,
            ))).label("collected"),
            _sum_in(amount, and_(current, mpesa, direct)).label("direct"),
            _sum_in(amount, and_(current, ~mpesa)).label("recorded"),
            func.count(case((current, CustomerPayment.id))).label("payments"),
        )
        .select_from(CustomerPayment)
        .outerjoin(User, User.id == CustomerPayment.reseller_id)
        .where(
            ts >= w.prev_start,
            ts < w.cur_end,
            # Free trials, compensation and "activate without payment" record
            # KES 0 with counts_as_revenue=False; refunded payments never
            # reached anyone.
            CustomerPayment.counts_as_revenue == True,  # noqa: E712
            or_(
                CustomerPayment.status.is_(None),
                CustomerPayment.status == PaymentStatus.COMPLETED,
            ),
        )
    )).one()

    total = round(float(row.cur or 0), 2)
    previous = round(float(row.prev or 0), 2)
    return {
        "total": total,
        "previous_total": previous,
        "change_percent": metrics._pct_change(total, previous),
        "payments": int(row.payments or 0),
        "mpesa_platform_collected": round(float(row.collected or 0), 2),
        "mpesa_direct_settled": round(float(row.direct or 0), 2),
        "recorded_manually": round(float(row.recorded or 0), 2),
    }


async def _collected_subscriptions(
    db: AsyncSession, w: Windows, own_ids: list[int],
) -> tuple[dict[str, float], dict[str, float]]:
    ts = SubscriptionPayment.created_at
    net = metrics._sub_kes()
    hot, per_user, minimum = _invoice_shares()
    has_invoice = and_(
        SubscriptionInvoice.id.is_not(None), SubscriptionInvoice.final_charge > 0,
    )
    parts = {
        "subscription_hotspot": case((has_invoice, net * hot), else_=0.0),
        "subscription_per_user": case((has_invoice, net * per_user), else_=0.0),
        "subscription_minimum": case((has_invoice, net * minimum), else_=0.0),
        "subscription_unattributed": case((has_invoice, 0.0), else_=net),
    }
    current = _in_window(ts, w.cur_start, w.cur_end)
    previous = _in_window(ts, w.prev_start, w.prev_end)
    columns = []
    for key, expr in parts.items():
        columns.append(_sum_in(expr, current).label(f"cur_{key}"))
        columns.append(_sum_in(expr, previous).label(f"prev_{key}"))

    row = (await db.execute(
        select(*columns)
        .select_from(SubscriptionPayment)
        .outerjoin(SubscriptionInvoice, SubscriptionPayment.invoice_id == SubscriptionInvoice.id)
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            ts >= w.prev_start,
            ts < w.cur_end,
            *_excluding(SubscriptionPayment.user_id, own_ids),
        )
    )).one()
    cur = {k: float(getattr(row, f"cur_{k}") or 0) for k in parts}
    prev = {k: float(getattr(row, f"prev_{k}") or 0) for k in parts}
    return cur, prev


async def _collected_sms(
    db: AsyncSession, w: Windows, own_ids: list[int],
) -> tuple[float, float, int]:
    ts = SmsCreditOrder.created_at
    current = _in_window(ts, w.cur_start, w.cur_end)
    row = (await db.execute(
        select(
            _sum_in(SmsCreditOrder.amount, current).label("cur"),
            _sum_in(SmsCreditOrder.amount, _in_window(ts, w.prev_start, w.prev_end)).label("prev"),
            func.count(case((current, SmsCreditOrder.id))).label("orders"),
        ).where(
            SmsCreditOrder.status == SmsCreditOrderStatus.COMPLETED,
            ts >= w.prev_start,
            ts < w.cur_end,
            *_excluding(SmsCreditOrder.user_id, own_ids),
        )
    )).one()
    return float(row.cur or 0), float(row.prev or 0), int(row.orders or 0)


async def _invoiced(db: AsyncSession, w: Windows, own_ids: list[int]) -> dict[str, Any]:
    """What the invoices issued in the current window billed."""
    final_kes = sql_kes_by_currency(SubscriptionInvoice.final_charge, SubscriptionInvoice.currency)
    hot, per_user, minimum = _invoice_shares()
    billable = and_(
        SubscriptionInvoice.status != InvoiceStatus.WAIVED,
        SubscriptionInvoice.final_charge > 0,
    )
    waived = SubscriptionInvoice.status == InvoiceStatus.WAIVED
    scope = [
        _in_window(SubscriptionInvoice.created_at, w.cur_start, w.cur_end),
        *_excluding(SubscriptionInvoice.user_id, own_ids),
    ]

    row = (await db.execute(
        select(
            _sum_in(final_kes, billable).label("total"),
            _sum_in(final_kes * hot, billable).label("hotspot"),
            _sum_in(final_kes * per_user, billable).label("per_user"),
            _sum_in(final_kes * minimum, billable).label("minimum"),
            func.count(case((billable, SubscriptionInvoice.id))).label("count"),
            _sum_in(final_kes, waived).label("waived"),
            func.count(case((waived, SubscriptionInvoice.id))).label("waived_count"),
        ).where(*scope)
    )).one()

    # Paid so far against those same invoices, whenever the money arrived.
    paid = float((await db.execute(
        select(func.coalesce(func.sum(metrics._sub_kes()), 0.0))
        .select_from(SubscriptionPayment)
        .join(SubscriptionInvoice, SubscriptionPayment.invoice_id == SubscriptionInvoice.id)
        .where(
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
            SubscriptionInvoice.status != InvoiceStatus.WAIVED,
            *scope,
        )
    )).scalar() or 0)

    total = round(float(row.total or 0), 2)
    paid = round(min(paid, total), 2)
    return {
        "total": total,
        "subscription_hotspot": round(float(row.hotspot or 0), 2),
        "subscription_per_user": round(float(row.per_user or 0), 2),
        "subscription_minimum": round(float(row.minimum or 0), 2),
        "invoices": int(row.count or 0),
        "paid_so_far": paid,
        "outstanding": round(total - paid, 2),
        "waived": round(float(row.waived or 0), 2),
        "waived_invoices": int(row.waived_count or 0),
    }


async def _not_counted(db: AsyncSession, w: Windows) -> dict[str, float]:
    shop = float((await db.execute(
        select(func.coalesce(func.sum(ShopOrder.total_amount), 0)).where(
            ShopOrder.payment_status == ShopOrderPaymentStatus.PAID,
            _in_window(ShopOrder.created_at, w.cur_start, w.cur_end),
        )
    )).scalar() or 0)
    charges = float((await db.execute(
        select(func.coalesce(func.sum(
            sql_kes_by_market(ResellerTransactionCharge.amount, User.market_code)
        ), 0))
        .select_from(ResellerTransactionCharge)
        .outerjoin(User, User.id == ResellerTransactionCharge.reseller_id)
        .where(_in_window(ResellerTransactionCharge.created_at, w.cur_start, w.cur_end))
    )).scalar() or 0)
    return {"shop_sales": round(shop, 2), "reseller_transaction_charges": round(charges, 2)}


def _cache_key(period: str, own_ids: list[int]) -> str:
    # Account list in the key for the same reason as the Earnings cache: the
    # in-process cache is not shared between workers.
    accounts = ",".join(str(i) for i in own_ids) or "none"
    return f"{PLATFORM_EARNINGS_CACHE_PREFIX}{period}:{accounts}"


async def compute_platform_earnings(db: AsyncSession, period: str = "month") -> dict[str, Any]:
    """Transaction volume vs Bitwave's own earnings for a calendar period-to-date.

    Seven aggregate queries on a cache miss, each one row, none per reseller.
    """
    period = normalize_period(period)
    own_ids = await metrics.get_own_reseller_ids(db)
    key = _cache_key(period, own_ids)
    cached = await cache.get(key)
    if cached is not None:
        await db.commit()
        return cached

    w = windows_for(period)
    volume = await _transaction_volume(db, w)
    subs_cur, subs_prev = await _collected_subscriptions(db, w, own_ids)
    sms_cur, sms_prev, sms_orders = await _collected_sms(db, w, own_ids)
    invoiced = await _invoiced(db, w, own_ids)
    not_counted = await _not_counted(db, w)
    accounts = await metrics.own_reseller_accounts(db, own_ids)
    # Every read is done; don't sit idle in transaction while serialising.
    await db.commit()

    current = {**subs_cur, "sms_credits": sms_cur}
    previous = {**subs_prev, "sms_credits": sms_prev}
    total = round(sum(current.values()), 2)
    previous_total = round(sum(previous.values()), 2)
    subscriptions = round(sum(current[k] for k in _SUBSCRIPTION_KEYS), 2)

    streams = [
        {
            **stream,
            "total": round(current[stream["key"]], 2),
            "previous_total": round(previous[stream["key"]], 2),
        }
        for stream in EARNING_STREAMS
        # An empty "unattributed" line is noise; every other line is a real
        # price component and stays visible at zero.
        if stream["key"] != "subscription_unattributed" or current[stream["key"]] > 0
    ]

    take_rate = (
        round(total / volume["total"] * 100, 2) if volume["total"] > 0 else None
    )

    payload = {
        "period": period,
        "start_date": w.cur_start.date().isoformat(),
        "end_date": (w.cur_end - timedelta(days=1)).date().isoformat(),
        "days": (w.cur_end - w.cur_start).days,
        "comparison_label": metrics._EARNINGS_COMPARISON_LABEL[period],
        "currency": REPORTING_CURRENCY,
        **metrics._fx_meta(),
        "transaction_volume": volume,
        "earnings": {
            "basis": "collected",
            "total": total,
            "previous_total": previous_total,
            "change_percent": metrics._pct_change(total, previous_total),
            "subscriptions": subscriptions,
            "sms_credits": round(sms_cur, 2),
            "sms_orders": sms_orders,
            "streams": streams,
        },
        "invoiced": invoiced,
        "take_rate_percent": take_rate,
        "not_counted": not_counted,
        "excluded_own_accounts": accounts,
    }
    await cache.set(key, payload, PLATFORM_EARNINGS_CACHE_TTL)
    return payload

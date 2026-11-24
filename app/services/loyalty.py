"""Loyalty points: earn on gateway-confirmed hotspot payments, spend on a whole plan.

Design: agentic-bitwave/chat-review/designs/loyalty-v1.md (board post 5).

* A balance belongs to (reseller user_id, phone key = last 9 digits of the
  phone). It never crosses resellers. Hotspot plans only.
* Off by default; only payments made after loyalty was switched on earn.
* Earning is found by a short sweep over recent ``customer_payments`` (the
  receipt-SMS pattern in customer_notifications.py), exactly once per payment
  through the unique ``loyalty_ledger.customer_payment_id``. The receipt SMS
  and the portal's payment-status poll call the same ``ensure_awards`` so the
  points can be shown before the next sweep tick.
* Rows that add points carry ``remaining`` / ``expires_at``: spending and
  expiry take the oldest points first, and the balance is the sum of
  ``remaining`` over rows that have not expired.
* A redemption is a zero-amount, non-revenue payment (reference ``LOYALTY-``),
  copied from free_trial.claim_free_trial, delivered under its own
  provisioning entrypoint.

Database Session Discipline: every function reads and writes in a short
session and commits before any router or SMS-provider I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as app_settings
from app.db import database
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    LoyaltyCode,
    LoyaltyLedger,
    LoyaltySettings,
    MessagingSettings,
    PaymentMethod,
    PaymentStatus,
    Plan,
    ProvisioningAttemptEntrypoint,
    Router,
    RouterAuthMethod,
    User,
)
from app.services.free_trial import _owner_can_sell, _phone_match_key
from app.services.markets import reseller_market
from app.services.mikrotik_api import normalize_mac_address
from app.services.plan_cache import plan_model_allows_router

logger = logging.getLogger(__name__)

KIND_EARN = "earn"
KIND_REDEEM = "redeem"
KIND_EXPIRE = "expire"
KIND_ADJUST = "adjust"

EARN_MODES = ("per_kes", "per_purchase")
MAX_REWARDS = 3
REFERENCE_PREFIX = "LOYALTY-"
# References of payments that are never real money, whatever their method.
NON_EARNING_PREFIXES = ("LOYALTY-", "FREE-TRIAL-", "VOUCHER-", "NO-PAYMENT-", "PAID-UNTIL-")

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "earn_mode": "per_kes",
    "kes_per_point": 10,
    "points_per_purchase": 1,
    "plan_points": {},
    "rewards": [],
    "expiry_days": 90,
    "min_paid_amount": 0.0,
    "max_redemptions_per_day": 1,
}

# Sweep: how far back it looks. Long enough to ride out a restart or a
# DB-pressure pause; the unique index keeps it exactly-once.
AWARD_LOOKBACK = timedelta(hours=2)
AWARD_SWEEP_SECONDS = 20

CODE_TTL = timedelta(minutes=10)
CODE_MAX_ATTEMPTS = 5
CODES_PER_PHONE = 3            # per CODE_RATE_WINDOW, counted in the database
CODES_PER_DEVICE = 5           # per CODE_RATE_WINDOW, process memory
CODES_PER_ROUTER = 60          # per hour, process memory
CODE_RATE_WINDOW = timedelta(minutes=30)

phone_key = _phone_match_key


def _utcnow() -> datetime:
    return datetime.utcnow()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def settings_values(row: Optional[LoyaltySettings]) -> dict[str, Any]:
    """The effective settings, defaults filled in, from a row or None."""
    if row is None:
        return dict(DEFAULTS, enabled_at=None)
    return {
        "enabled": bool(row.enabled),
        "enabled_at": row.enabled_at,
        "earn_mode": row.earn_mode if row.earn_mode in EARN_MODES else "per_kes",
        "kes_per_point": int(row.kes_per_point or DEFAULTS["kes_per_point"]),
        "points_per_purchase": int(
            row.points_per_purchase
            if row.points_per_purchase is not None
            else DEFAULTS["points_per_purchase"]
        ),
        "plan_points": _clean_plan_points(row.plan_points),
        "rewards": _clean_rewards(row.rewards),
        "expiry_days": int(row.expiry_days if row.expiry_days is not None else 90),
        "min_paid_amount": float(row.min_paid_amount or 0),
        "max_redemptions_per_day": int(row.max_redemptions_per_day or 1),
    }


def _clean_plan_points(raw) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key, value in raw.items():
        try:
            out[str(int(key))] = max(0, int(value))
        except (TypeError, ValueError):
            continue
    return out


def _clean_rewards(raw) -> list[dict[str, int]]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        try:
            out.append({"plan_id": int(item["plan_id"]), "points_cost": int(item["points_cost"])})
        except (KeyError, TypeError, ValueError):
            continue
    return out[:MAX_REWARDS]


def value_percent(price: float | int | None, points_cost: int, cfg: dict) -> Optional[float]:
    """Share of spend given back by a reward, per_kes only.

    A customer spends points_cost x kes_per_point to earn the points that buy
    a plan worth ``price``.
    """
    if cfg["earn_mode"] != "per_kes" or not price or not points_cost:
        return None
    spend = points_cost * cfg["kes_per_point"]
    return round(float(price) / spend * 100, 2) if spend else None


# ---------------------------------------------------------------------------
# Earning rules (pure)
# ---------------------------------------------------------------------------

def points_for(cfg: dict, *, plan_id: Optional[int], amount: float) -> int:
    """Points one qualifying payment earns under ``cfg``."""
    if amount is None or float(amount) <= 0:
        return 0
    if float(amount) < cfg["min_paid_amount"]:
        return 0
    override = cfg["plan_points"].get(str(plan_id)) if plan_id is not None else None
    if override is not None:
        return max(0, int(override))
    if cfg["earn_mode"] == "per_purchase":
        return max(0, int(cfg["points_per_purchase"]))
    per = cfg["kes_per_point"] or 1
    return int(float(amount) // per)


def payment_earns(row, cfg: dict) -> tuple[int, Optional[str]]:
    """(points, phone key) a payment earns, or (0, None).

    ``row`` carries the payment, its customer and its plan's connection type
    (see _payment_rows).
    """
    if not cfg["enabled"] or cfg["enabled_at"] is None:
        return 0, None
    if row.status != PaymentStatus.COMPLETED or not row.counts_as_revenue:
        return 0, None
    # Gateway-confirmed money only: M-Pesa STK, C2B, ZenoPay, MTN MoMo and
    # Fapshi all record MOBILE_MONEY. Never CASH (sale vouchers, pairing
    # vouchers, the dashboard's cash entries).
    if row.payment_method != PaymentMethod.MOBILE_MONEY:
        return 0, None
    reference = (row.payment_reference or "").upper()
    if reference.startswith(NON_EARNING_PREFIXES):
        return 0, None
    if row.customer_owner_id != row.reseller_id or row.subscription_owner_id is not None:
        return 0, None
    if row.connection_type != ConnectionType.HOTSPOT:
        return 0, None
    if row.created_at is None or row.created_at < cfg["enabled_at"]:
        return 0, None
    key = phone_key(row.phone)
    if not key:
        return 0, None
    return points_for(cfg, plan_id=row.plan_id, amount=row.amount), key


def _payment_rows_query(payment_ids):
    return (
        select(
            CustomerPayment.id,
            CustomerPayment.reseller_id,
            CustomerPayment.amount,
            CustomerPayment.payment_method,
            CustomerPayment.status,
            CustomerPayment.counts_as_revenue,
            CustomerPayment.created_at,
            CustomerPayment.plan_id,
            CustomerPayment.customer_id,
            CustomerPayment.payment_reference,
            Customer.phone,
            Customer.user_id.label("customer_owner_id"),
            Customer.subscription_owner_id,
            Plan.connection_type,
        )
        .join(Customer, Customer.id == CustomerPayment.customer_id)
        .outerjoin(Plan, Plan.id == CustomerPayment.plan_id)
        .where(CustomerPayment.id.in_(list(payment_ids)))
        .order_by(CustomerPayment.id)
    )


# ---------------------------------------------------------------------------
# Balances
# ---------------------------------------------------------------------------

def _live_rows_clause(user_id: int, key: str, now: datetime):
    return (
        LoyaltyLedger.user_id == user_id,
        LoyaltyLedger.phone_key == key,
        LoyaltyLedger.remaining > 0,
        or_(LoyaltyLedger.expires_at.is_(None), LoyaltyLedger.expires_at > now),
    )


async def current_balance(db: AsyncSession, user_id: int, key: str, now: Optional[datetime] = None) -> int:
    now = now or _utcnow()
    value = await db.scalar(
        select(func.coalesce(func.sum(LoyaltyLedger.remaining), 0)).where(
            *_live_rows_clause(user_id, key, now)
        )
    )
    return int(value or 0)


def _local_date(moment: datetime, tz_name: Optional[str]) -> str:
    aware = moment.replace(tzinfo=timezone.utc)
    try:
        return aware.astimezone(ZoneInfo(tz_name or "Africa/Nairobi")).date().isoformat()
    except ZoneInfoNotFoundError:
        return aware.date().isoformat()


async def next_expiry(
    db: AsyncSession, user_id: int, key: str, tz_name: Optional[str], now: Optional[datetime] = None
) -> Optional[dict]:
    """{points, on}: the points that expire first and the local date they do."""
    now = now or _utcnow()
    rows = (
        await db.execute(
            select(LoyaltyLedger.remaining, LoyaltyLedger.expires_at)
            .where(*_live_rows_clause(user_id, key, now), LoyaltyLedger.expires_at.is_not(None))
            .order_by(LoyaltyLedger.expires_at)
        )
    ).all()
    if not rows:
        return None
    first_day = _local_date(rows[0].expires_at, tz_name)
    points = sum(r.remaining for r in rows if _local_date(r.expires_at, tz_name) == first_day)
    return {"points": int(points), "on": first_day}


async def _consume(db: AsyncSession, user_id: int, key: str, amount: int, now: datetime) -> int:
    """Take ``amount`` points, oldest first. Returns how many were taken."""
    rows = (
        await db.execute(
            select(LoyaltyLedger)
            .where(*_live_rows_clause(user_id, key, now))
            .order_by(LoyaltyLedger.id)
        )
    ).scalars().all()
    left = amount
    for row in rows:
        if left <= 0:
            break
        take = min(row.remaining, left)
        row.remaining -= take
        left -= take
    return amount - left


async def _lock_settings(db: AsyncSession, user_id: int, *, create: bool = False) -> Optional[LoyaltySettings]:
    """The reseller's settings row, locked: spending, adjustments and expiry
    for one reseller take turns, so a balance cannot be spent twice."""
    row = (
        await db.execute(
            select(LoyaltySettings).where(LoyaltySettings.user_id == user_id).with_for_update()
        )
    ).scalar_one_or_none()
    if row is None and create:
        row = LoyaltySettings(user_id=user_id)
        db.add(row)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return await _lock_settings(db, user_id)
    return row


def _expiry_for(cfg: dict, now: datetime) -> Optional[datetime]:
    days = cfg["expiry_days"]
    return now + timedelta(days=days) if days and days > 0 else None


# ---------------------------------------------------------------------------
# Awards (exactly once per payment)
# ---------------------------------------------------------------------------

async def ensure_awards(
    payment_ids,
    *,
    session_factory: Callable | None = None,
    now: Optional[datetime] = None,
) -> dict[int, dict]:
    """Award points for these payments if they earn and have none yet.

    Returns {payment_id: {"earned", "balance"}} for every payment that has an
    award, new or old. Safe to call from several places at once: the unique
    customer_payment_id makes the second insert fail, and that one is read back.
    """
    ids = sorted({int(p) for p in payment_ids or [] if p})
    if not ids:
        return {}
    factory = session_factory or database.async_session
    now = now or _utcnow()
    async with factory() as db:
        existing = {
            row.customer_payment_id: row
            for row in (
                await db.execute(
                    select(
                        LoyaltyLedger.customer_payment_id,
                        LoyaltyLedger.user_id,
                        LoyaltyLedger.phone_key,
                        LoyaltyLedger.points,
                    ).where(
                        LoyaltyLedger.customer_payment_id.in_(ids),
                        LoyaltyLedger.kind == KIND_EARN,
                    )
                )
            ).all()
        }
        awarded: dict[int, tuple[int, str, int]] = {
            pid: (row.user_id, row.phone_key, row.points) for pid, row in existing.items()
        }
        todo = [pid for pid in ids if pid not in existing]
        if todo:
            rows = (await db.execute(_payment_rows_query(todo))).all()
            reseller_ids = {row.reseller_id for row in rows}
            configs = {
                s.user_id: settings_values(s)
                for s in (
                    await db.execute(
                        select(LoyaltySettings).where(
                            LoyaltySettings.user_id.in_(reseller_ids),
                            LoyaltySettings.enabled.is_(True),
                        )
                    )
                ).scalars().all()
            } if reseller_ids else {}
            for row in rows:
                cfg = configs.get(row.reseller_id)
                if cfg is None:
                    continue
                points, key = payment_earns(row, cfg)
                if points <= 0:
                    continue
                if row.payment_reference and await _reference_already_awarded(db, row):
                    # The same money recorded twice (an STK receipt and its C2B
                    # copy): award it once.
                    continue
                db.add(LoyaltyLedger(
                    user_id=row.reseller_id,
                    phone_key=key,
                    kind=KIND_EARN,
                    points=points,
                    remaining=points,
                    expires_at=_expiry_for(cfg, now),
                    customer_payment_id=row.id,
                    customer_id=row.customer_id,
                    plan_id=row.plan_id,
                    created_at=now,
                ))
                try:
                    await db.commit()
                    awarded[row.id] = (row.reseller_id, key, points)
                except IntegrityError:
                    await db.rollback()
                    again = (
                        await db.execute(
                            select(LoyaltyLedger.user_id, LoyaltyLedger.phone_key, LoyaltyLedger.points)
                            .where(LoyaltyLedger.customer_payment_id == row.id)
                        )
                    ).first()
                    if again is not None:
                        awarded[row.id] = (again.user_id, again.phone_key, again.points)

        balances: dict[tuple[int, str], int] = {}
        out: dict[int, dict] = {}
        for pid, (user_id, key, points) in awarded.items():
            if (user_id, key) not in balances:
                balances[(user_id, key)] = await current_balance(db, user_id, key, now)
            out[pid] = {"earned": int(points), "balance": balances[(user_id, key)]}
        await db.commit()
    return out


async def _reference_already_awarded(db: AsyncSession, row) -> bool:
    hit = await db.scalar(
        select(LoyaltyLedger.id)
        .join(CustomerPayment, CustomerPayment.id == LoyaltyLedger.customer_payment_id)
        .where(
            LoyaltyLedger.user_id == row.reseller_id,
            LoyaltyLedger.kind == KIND_EARN,
            CustomerPayment.payment_reference == row.payment_reference,
            CustomerPayment.id != row.id,
        )
        .limit(1)
    )
    return hit is not None


async def collect_due_awards(*, session_factory: Callable, now: datetime) -> list[int]:
    """Recent payment ids of resellers with loyalty on that have no award yet."""
    async with session_factory() as db:
        enabled = (
            await db.execute(
                select(LoyaltySettings.user_id, LoyaltySettings.enabled_at).where(
                    LoyaltySettings.enabled.is_(True),
                    LoyaltySettings.enabled_at.is_not(None),
                )
            )
        ).all()
        if not enabled:
            return []
        since = max(now - AWARD_LOOKBACK, min(row.enabled_at for row in enabled))
        already = select(LoyaltyLedger.id).where(
            LoyaltyLedger.customer_payment_id == CustomerPayment.id
        ).exists()
        ids = (
            await db.execute(
                select(CustomerPayment.id)
                .join(Customer, Customer.id == CustomerPayment.customer_id)
                .join(Plan, Plan.id == CustomerPayment.plan_id)
                .where(
                    CustomerPayment.created_at >= since,
                    CustomerPayment.reseller_id.in_([row.user_id for row in enabled]),
                    CustomerPayment.amount > 0,
                    CustomerPayment.status == PaymentStatus.COMPLETED,
                    CustomerPayment.counts_as_revenue.is_(True),
                    CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY,
                    Customer.user_id == CustomerPayment.reseller_id,
                    Customer.subscription_owner_id.is_(None),
                    Plan.connection_type == ConnectionType.HOTSPOT,
                    ~already,
                )
                .order_by(CustomerPayment.id)
                .limit(1000)
            )
        ).scalars().all()
    return list(ids)


async def award_recent_payments(
    *, session_factory: Callable | None = None, now: Optional[datetime] = None
) -> int:
    factory = session_factory or database.async_session
    now = now or _utcnow()
    due = await collect_due_awards(session_factory=factory, now=now)
    if not due:
        return 0
    awards = await ensure_awards(due, session_factory=factory, now=now)
    return sum(1 for pid in due if pid in awards)


_sweep_running = False


def _pool_is_busy() -> bool:
    try:
        level = (database.db_pool_snapshot().get("pressure") or {}).get("level")
    except Exception:
        return False
    return level in {"warning", "critical"}


async def award_points_background() -> int:
    """APScheduler entrypoint: award points for recent qualifying payments."""
    global _sweep_running
    if _sweep_running or _pool_is_busy():
        return 0
    _sweep_running = True
    try:
        count = await award_recent_payments()
        if count:
            logger.info("Loyalty sweep awarded points for %s payment(s)", count)
        return count
    except Exception as exc:
        logger.error("Loyalty award sweep failed: %s", exc, exc_info=True)
        return 0
    finally:
        _sweep_running = False


async def award_for_latest_payment(customer: Customer) -> Optional[dict]:
    """{earned, balance} for this customer's newest payment, awarding it now if due.

    Used by the portal's payment-status poll, so the success screen does not
    wait for the sweep. One primary-key read when the reseller has loyalty off.
    """
    if customer.user_id is None:
        return None
    async with database.async_session() as db:
        row = await db.get(LoyaltySettings, customer.user_id)
        if row is None or not row.enabled:
            return None
        payment_id = await db.scalar(
            select(CustomerPayment.id)
            .where(CustomerPayment.customer_id == customer.id)
            .order_by(CustomerPayment.id.desc())
            .limit(1)
        )
    if payment_id is None:
        return None
    return (await ensure_awards([payment_id])).get(payment_id)


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

async def expire_points(*, session_factory: Callable | None = None, now: Optional[datetime] = None) -> int:
    """Write an ``expire`` row per phone for points past their expiry."""
    factory = session_factory or database.async_session
    now = now or _utcnow()
    async with factory() as db:
        user_ids = (
            await db.execute(
                select(LoyaltyLedger.user_id)
                .where(LoyaltyLedger.remaining > 0, LoyaltyLedger.expires_at <= now)
                .distinct()
            )
        ).scalars().all()
    expired_total = 0
    for user_id in user_ids:
        # One short transaction per reseller.
        async with factory() as db:
            await _lock_settings(db, user_id, create=True)
            rows = (
                await db.execute(
                    select(LoyaltyLedger)
                    .where(
                        LoyaltyLedger.user_id == user_id,
                        LoyaltyLedger.remaining > 0,
                        LoyaltyLedger.expires_at <= now,
                    )
                    .order_by(LoyaltyLedger.id)
                )
            ).scalars().all()
            by_phone: dict[str, int] = {}
            for row in rows:
                by_phone[row.phone_key] = by_phone.get(row.phone_key, 0) + row.remaining
                row.remaining = 0
            for key, points in by_phone.items():
                db.add(LoyaltyLedger(
                    user_id=user_id, phone_key=key, kind=KIND_EXPIRE,
                    points=-points, note="Points expired", created_at=now,
                ))
                expired_total += points
            await db.commit()
    return expired_total


async def expire_points_background() -> int:
    try:
        expired = await expire_points()
        if expired:
            logger.info("Loyalty expiry removed %s point(s)", expired)
        return expired
    except Exception as exc:
        logger.error("Loyalty expiry failed: %s", exc, exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# Public portal
# ---------------------------------------------------------------------------

async def _reward_plans(db: AsyncSession, user_id: int, cfg: dict, router_id: Optional[int]) -> list[tuple[dict, Plan]]:
    """Rewards whose plan still exists, belongs to the reseller, is hotspot
    and is offered on this router."""
    plan_ids = [r["plan_id"] for r in cfg["rewards"]]
    if not plan_ids:
        return []
    plans = {
        p.id: p
        for p in (await db.execute(select(Plan).where(Plan.id.in_(plan_ids)))).scalars().all()
    }
    out = []
    for reward in cfg["rewards"]:
        plan = plans.get(reward["plan_id"])
        if (
            plan is None
            or plan.user_id != user_id
            or plan.connection_type != ConnectionType.HOTSPOT
            or (router_id is not None and not plan_model_allows_router(plan, router_id))
        ):
            continue
        out.append((reward, plan))
    return out


def _reward_public(reward: dict, plan: Plan) -> dict:
    return {
        "plan_id": plan.id,
        "points_cost": reward["points_cost"],
        # Extra to the contract's {plan_id, points_cost}: a reward plan may be
        # hidden from the plan list, so the portal needs something to show.
        "name": plan.name,
        "price": plan.price,
        "duration_value": plan.duration_value,
        "duration_unit": plan.duration_unit.value if plan.duration_unit else None,
        "speed": plan.speed,
    }


async def public_payload(db: AsyncSession, user_id: int, router_id: Optional[int]) -> Optional[dict]:
    """The ``loyalty`` block of the public portal payload; None when off."""
    row = await db.get(LoyaltySettings, user_id)
    cfg = settings_values(row)
    if not cfg["enabled"]:
        return None
    rewards = await _reward_plans(db, user_id, cfg, router_id)
    return {
        "enabled": True,
        "earn_mode": cfg["earn_mode"],
        "kes_per_point": cfg["kes_per_point"],
        "points_per_purchase": cfg["points_per_purchase"],
        "plan_points": cfg["plan_points"],
        "rewards": [_reward_public(reward, plan) for reward, plan in rewards],
        "expiry_days": cfg["expiry_days"],
    }


async def device_check(db: AsyncSession, user_id: int, key: str, mac: str) -> bool:
    """The device you usually pay with: this MAC is a customer of this reseller
    with the same phone, and that customer has at least one earning payment."""
    customer = (
        await db.execute(
            select(Customer.id, Customer.phone).where(
                Customer.mac_address == normalize_mac_address(mac),
                Customer.user_id == user_id,
            )
        )
    ).first()
    if customer is None or phone_key(customer.phone) != key:
        return False
    earned = await db.scalar(
        select(LoyaltyLedger.id).where(
            LoyaltyLedger.user_id == user_id,
            LoyaltyLedger.phone_key == key,
            LoyaltyLedger.customer_id == customer.id,
            LoyaltyLedger.kind == KIND_EARN,
        ).limit(1)
    )
    return earned is not None


def _code_hash(user_id: int, key: str, mac: str, code: str) -> str:
    message = f"{user_id}:{key}:{mac}:{code}".encode()
    return hmac.new(app_settings.SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()


async def check_code(
    db: AsyncSession, user_id: int, key: str, mac: str, code: Optional[str], now: datetime
) -> tuple[bool, Optional[LoyaltyCode]]:
    """(valid, row). A wrong code uses up one of the row's tries (committed)."""
    digits = "".join(ch for ch in (code or "") if ch.isdigit())
    row = (
        await db.execute(
            select(LoyaltyCode)
            .where(
                LoyaltyCode.user_id == user_id,
                LoyaltyCode.phone_key == key,
                LoyaltyCode.mac == mac,
                LoyaltyCode.used_at.is_(None),
                LoyaltyCode.expires_at > now,
            )
            .order_by(LoyaltyCode.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or row.attempts >= CODE_MAX_ATTEMPTS:
        return False, None
    if len(digits) == 6 and hmac.compare_digest(row.code_hash, _code_hash(user_id, key, mac, digits)):
        return True, row
    row.attempts += 1
    await db.commit()
    return False, None


async def balance_view(
    db: AsyncSession, user_id: int, key: str, cfg: dict, router_id: int, tz_name: Optional[str]
) -> dict:
    now = _utcnow()
    balance = await current_balance(db, user_id, key, now)
    rewards = await _reward_plans(db, user_id, cfg, router_id)
    return {
        "ok": True,
        "balance": balance,
        "rewards": [
            dict(_reward_public(reward, plan), affordable=balance >= reward["points_cost"])
            for reward, plan in rewards
        ],
        "expiring": await next_expiry(db, user_id, key, tz_name, now),
    }


# Send-code limits kept in process memory (the app runs one worker), on top
# of the per-phone count in the database.
_send_events: dict[tuple, deque] = {}


def _recent_sends(key: tuple, window: float, now: float) -> deque:
    bucket = _send_events.setdefault(key, deque())
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    return bucket


def reset_send_limiter() -> None:
    """Test hook."""
    _send_events.clear()


def _send_allowed(router_id: int, mac: str) -> bool:
    now = time.monotonic()
    device = _recent_sends(("device", router_id, mac), CODE_RATE_WINDOW.total_seconds(), now)
    router = _recent_sends(("router", router_id), 3600, now)
    if len(device) >= CODES_PER_DEVICE or len(router) >= CODES_PER_ROUTER:
        return False
    device.append(now)
    router.append(now)
    return True


async def _code_recipient(db: AsyncSession, user_id: int, key: str) -> tuple[Optional[int], Optional[str]]:
    """(customer_id, phone) to text: the member's latest paying customer."""
    from app.services.customer_expiry_notifications import is_textable_phone

    customer = (
        await db.execute(
            select(Customer.id, Customer.phone)
            .join(LoyaltyLedger, LoyaltyLedger.customer_id == Customer.id)
            .where(
                LoyaltyLedger.user_id == user_id,
                LoyaltyLedger.phone_key == key,
                LoyaltyLedger.kind == KIND_EARN,
                Customer.user_id == user_id,
            )
            .order_by(LoyaltyLedger.id.desc())
            .limit(1)
        )
    ).first()
    if customer is None or phone_key(customer.phone) != key or not is_textable_phone(customer.phone):
        return None, None
    return customer.id, "".join(ch for ch in customer.phone if ch.isdigit())


async def send_code(db: AsyncSession, router: Router, phone: str, mac: str) -> dict:
    """Text a one-time code to the member's phone, paid from the reseller's SMS credits."""
    from app.services.customer_expiry_notifications import (
        create_customer_campaign,
        spawn_expiry_campaign_dispatch,
    )
    from app.services.customer_sms_templates import brand_name

    user_id = router.user_id
    cfg = settings_values(await db.get(LoyaltySettings, user_id))
    if not cfg["enabled"]:
        return {"ok": False, "code": "loyalty_off"}
    key = phone_key(phone)
    mac = normalize_mac_address(mac)
    now = _utcnow()

    recent = await db.scalar(
        select(func.count(LoyaltyCode.id)).where(
            LoyaltyCode.user_id == user_id,
            LoyaltyCode.phone_key == key,
            LoyaltyCode.created_at > now - CODE_RATE_WINDOW,
        )
    )
    if (recent or 0) >= CODES_PER_PHONE or not _send_allowed(router.id, mac):
        return {"ok": False, "code": "rate_limited"}

    customer_id, recipient = await _code_recipient(db, user_id, key)
    if recipient is None:
        # Not a member here (or no number we can text): spend no credit and
        # do not reveal whether this phone has bought on this hotspot.
        return {"ok": True}

    messaging = await db.get(MessagingSettings, 1)
    if not app_settings.SMS_DISPATCH_ENABLED or (messaging is not None and not messaging.enabled):
        return {"ok": False, "code": "use_paying_device"}

    reseller = await db.get(User, user_id)
    code = f"{secrets.randbelow(1_000_000):06d}"
    row = LoyaltyCode(
        user_id=user_id, phone_key=key, mac=mac,
        code_hash=_code_hash(user_id, key, mac, code),
        expires_at=now + CODE_TTL, created_at=now,
    )
    db.add(row)
    await db.flush()
    body = (
        f"{code} is your {brand_name(reseller)} points code. "
        "It works for 10 minutes. Do not share it."
    )
    campaign_id = await create_customer_campaign(
        db,
        reseller_id=user_id,
        recipients=[(customer_id, recipient, f"loyalty_code:{row.id}", body)],
        # The campaign history shows this, not the code.
        body="Loyalty points code",
        settings_row=messaging,
        credit_note="Loyalty points code",
    )
    if campaign_id is None:
        # No SMS credits: the code row was rolled back with the campaign.
        return {"ok": False, "code": "use_paying_device"}
    spawn_expiry_campaign_dispatch([campaign_id])
    return {"ok": True}


def _day_start_utc(now: datetime, tz_name: Optional[str]) -> datetime:
    try:
        tz = ZoneInfo(tz_name or "Africa/Nairobi")
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    local = now.replace(tzinfo=timezone.utc).astimezone(tz)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone(timezone.utc).replace(tzinfo=None)


async def redeem(
    db: AsyncSession,
    router: Router,
    phone: str,
    mac: str,
    plan_id: int,
    code: Optional[str] = None,
) -> dict:
    """Spend points on a reward plan and provision it, like a free trial."""
    user_id = router.user_id
    key = phone_key(phone)
    mac = normalize_mac_address(mac)
    now = _utcnow()

    cfg = settings_values(await db.get(LoyaltySettings, user_id))
    if not cfg["enabled"]:
        return {"ok": False, "code": "loyalty_off"}
    reward = next((r for r in cfg["rewards"] if r["plan_id"] == plan_id), None)
    rewards = await _reward_plans(db, user_id, cfg, router.id) if reward else []
    match = next(((r, p) for r, p in rewards if r["plan_id"] == plan_id), None)
    if match is None:
        return {"ok": False, "code": "not_a_reward"}
    reward, plan = match

    code_row = None
    if not await device_check(db, user_id, key, mac):
        if not code:
            return {"ok": False, "code": "needs_code"}
        valid, code_row = await check_code(db, user_id, key, mac, code, now)
        if not valid:
            return {"ok": False, "code": "bad_code"}

    if not await _owner_can_sell(db, user_id):
        return {
            "ok": False,
            "code": "unavailable",
            "message": "This service is temporarily unavailable. Please contact your ISP.",
            "status_code": 503,
        }

    reseller = await db.get(User, user_id)
    tz_name = reseller_market(reseller).timezone if reseller else None

    # Spend: the settings row lock makes concurrent redemptions take turns.
    settings_row = await _lock_settings(db, user_id)
    cfg = settings_values(settings_row)
    # Refusals below have written nothing; commit only releases the lock
    # (a rollback would expire the caller's objects).
    if not cfg["enabled"]:
        await db.commit()
        return {"ok": False, "code": "loyalty_off"}
    today = await db.scalar(
        select(func.count(LoyaltyLedger.id)).where(
            LoyaltyLedger.user_id == user_id,
            LoyaltyLedger.phone_key == key,
            LoyaltyLedger.kind == KIND_REDEEM,
            LoyaltyLedger.created_at >= _day_start_utc(now, tz_name),
        )
    )
    if (today or 0) >= cfg["max_redemptions_per_day"]:
        await db.commit()
        return {"ok": False, "code": "limit_reached"}
    cost = reward["points_cost"]
    if await current_balance(db, user_id, key, now) < cost:
        await db.commit()
        return {"ok": False, "code": "not_enough_points"}

    from app.services.subscription_sharing import (
        apply_voucher_plan_if_plan_ended,
        smaller_voucher_refusal,
    )
    from sqlalchemy.orm import selectinload

    customer = (
        await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan))
            .where(Customer.mac_address == mac, Customer.user_id == user_id)
        )
    ).scalar_one_or_none()
    # Same rule as a voucher: a reward must not shrink a live shared plan.
    refusal = await smaller_voucher_refusal(db, customer=customer, new_plan=plan)
    if refusal:
        await db.commit()
        return {"ok": False, "code": "plan_conflict", "message": refusal, "status_code": 400}

    await _consume(db, user_id, key, cost, now)
    ledger_row = LoyaltyLedger(
        user_id=user_id, phone_key=key, kind=KIND_REDEEM, points=-cost,
        plan_id=plan.id, note=f"Redeemed for {plan.name}"[:255], created_at=now,
    )
    db.add(ledger_row)
    if code_row is not None:
        code_row.used_at = now

    phone_digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if customer:
        apply_voucher_plan_if_plan_ended(customer, plan, now)
        customer.plan_id = plan.id
        customer.router_id = router.id
        if phone_digits and not customer.phone:
            customer.phone = phone_digits
    else:
        customer = Customer(
            name="Loyalty reward",
            phone=phone_digits,
            mac_address=mac,
            status=CustomerStatus.INACTIVE,
            plan=plan,
            user_id=user_id,
            router_id=router.id,
        )
        db.add(customer)
    await db.flush()
    ledger_row.customer_id = customer.id

    from app.services.reseller_payments import record_customer_payment
    from app.services.voucher_service import _duration_to_days

    # Commits the points spend, the code use and the payment together.
    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=user_id,
        amount=0.0,
        # Same method free trials record; the zero amount and the
        # counts_as_revenue flag keep it out of revenue, payouts, commission
        # and the subscription charge, and it can never earn points.
        payment_method=PaymentMethod.CASH,
        days_paid_for=_duration_to_days(plan.duration_value, plan.duration_unit.value),
        payment_reference=f"{REFERENCE_PREFIX}{ledger_row.id}",
        notes=f"Loyalty reward: {plan.name} for {cost} points",
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
        counts_as_revenue=False,
    )
    ledger_row.customer_payment_id = payment.id
    await db.commit()
    await db.refresh(customer)
    balance = await current_balance(db, user_id, key, _utcnow())
    await db.commit()

    logger.info(
        "[LOYALTY] plan=%s router=%s customer=%s redeemed %s points",
        plan.id, router.id, customer.id, cost,
    )

    from app.services.voucher_service import _provision_direct_api, _provision_radius

    if getattr(router, "auth_method", None) == RouterAuthMethod.RADIUS:
        result = await _provision_radius(
            db, customer, plan, router,
            fixed_expiry=customer.expiry,
            message="Reward started. Use credentials to login.",
        )
    else:
        result = await _provision_direct_api(
            db, customer, plan, router,
            code=f"{REFERENCE_PREFIX}{ledger_row.id}",
            payment_id=payment.id,
            entrypoint=ProvisioningAttemptEntrypoint.LOYALTY_REDEMPTION,
            comment=f"Loyalty reward {plan.name} for {mac}",
            event_label=f"loyalty reward {plan.name}",
            message="Reward started. Internet access is being provisioned.",
        )
    response = {k: v for k, v in result.items() if k not in ("success", "error")}
    if not result.get("success"):
        response["delivery_error"] = result.get("error")
    response.update({"ok": True, "customer_id": customer.id, "balance": balance})
    return response


# ---------------------------------------------------------------------------
# Reseller side
# ---------------------------------------------------------------------------

def mask_phone_key(key: str) -> str:
    return "******" + key[-3:]


async def adjust(
    db: AsyncSession, user_id: int, phone: str, points: int, note: str, created_by: Optional[int]
) -> dict:
    """Add or remove points for a phone. The balance never goes below 0."""
    key = phone_key(phone)
    now = _utcnow()
    row = await _lock_settings(db, user_id, create=True)
    cfg = settings_values(row)
    balance = await current_balance(db, user_id, key, now)
    if points > 0:
        applied = points
        db.add(LoyaltyLedger(
            user_id=user_id, phone_key=key, kind=KIND_ADJUST, points=applied,
            remaining=applied, expires_at=_expiry_for(cfg, now),
            note=note[:255], created_by=created_by, created_at=now,
        ))
    else:
        applied = -min(-points, balance)
        if applied == 0:
            await db.commit()
            return {"applied": 0, "balance": balance}
        await _consume(db, user_id, key, -applied, now)
        db.add(LoyaltyLedger(
            user_id=user_id, phone_key=key, kind=KIND_ADJUST, points=applied,
            note=note[:255], created_by=created_by, created_at=now,
        ))
    await db.commit()
    return {"applied": applied, "balance": balance + applied}


async def members(db: AsyncSession, user_id: int, limit: int) -> list[dict]:
    now = _utcnow()
    # Only unexpired remaining points count toward the balance.
    live = func.coalesce(func.sum(case(
        (
            and_(
                LoyaltyLedger.remaining > 0,
                or_(LoyaltyLedger.expires_at.is_(None), LoyaltyLedger.expires_at > now),
            ),
            LoyaltyLedger.remaining,
        ),
        else_=0,
    )), 0)
    earned = func.coalesce(func.sum(case(
        (LoyaltyLedger.kind == KIND_EARN, LoyaltyLedger.points), else_=0,
    )), 0)
    rows = (
        await db.execute(
            select(
                LoyaltyLedger.phone_key,
                live.label("balance"),
                earned.label("earned"),
                func.max(LoyaltyLedger.created_at).label("last_activity"),
                func.max(LoyaltyLedger.customer_id).label("customer_id"),
            )
            .where(LoyaltyLedger.user_id == user_id)
            .group_by(LoyaltyLedger.phone_key)
            .order_by(live.desc(), func.max(LoyaltyLedger.created_at).desc())
            .limit(limit)
        )
    ).all()
    names = {}
    customer_ids = {r.customer_id for r in rows if r.customer_id}
    if customer_ids:
        names = dict(
            (await db.execute(
                select(Customer.id, Customer.name).where(
                    Customer.id.in_(customer_ids), Customer.user_id == user_id
                )
            )).all()
        )
    return [
        {
            "phone": mask_phone_key(r.phone_key),
            "balance": int(r.balance or 0),
            "earned_total": int(r.earned or 0),
            "last_activity": r.last_activity.isoformat() if r.last_activity else None,
            "customer_id": r.customer_id if r.customer_id in names else None,
            "customer_name": names.get(r.customer_id),
        }
        for r in rows
    ]


def ledger_entry(row: LoyaltyLedger) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "points": row.points,
        "remaining": row.remaining,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "customer_payment_id": row.customer_payment_id,
        "customer_id": row.customer_id,
        "plan_id": row.plan_id,
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def member_detail(db: AsyncSession, user_id: int, phone: str, limit: int, tz_name: Optional[str]) -> dict:
    key = phone_key(phone)
    now = _utcnow()
    rows = (
        await db.execute(
            select(LoyaltyLedger)
            .where(LoyaltyLedger.user_id == user_id, LoyaltyLedger.phone_key == key)
            .order_by(LoyaltyLedger.id.desc())
            .limit(limit)
        )
    ).scalars().all()
    return {
        "phone": "".join(ch for ch in phone if ch.isdigit()),
        "balance": await current_balance(db, user_id, key, now),
        "expiring": await next_expiry(db, user_id, key, tz_name, now),
        "recent": [ledger_entry(r) for r in rows],
    }


async def summary(db: AsyncSession, user_id: int) -> dict:
    now = _utcnow()
    since = now - timedelta(days=30)
    base = LoyaltyLedger.user_id == user_id
    members_count = await db.scalar(
        select(func.count(func.distinct(LoyaltyLedger.phone_key))).where(base)
    )
    outstanding = await db.scalar(
        select(func.coalesce(func.sum(LoyaltyLedger.remaining), 0)).where(
            base,
            LoyaltyLedger.remaining > 0,
            or_(LoyaltyLedger.expires_at.is_(None), LoyaltyLedger.expires_at > now),
        )
    )
    earned = await db.scalar(
        select(func.coalesce(func.sum(LoyaltyLedger.points), 0)).where(
            base, LoyaltyLedger.kind == KIND_EARN, LoyaltyLedger.created_at >= since
        )
    )
    redeemed = await db.scalar(
        select(func.coalesce(func.sum(LoyaltyLedger.points), 0)).where(
            base, LoyaltyLedger.kind == KIND_REDEEM, LoyaltyLedger.created_at >= since
        )
    )
    redemptions = await db.scalar(
        select(func.count(LoyaltyLedger.id)).where(
            base, LoyaltyLedger.kind == KIND_REDEEM, LoyaltyLedger.created_at >= since
        )
    )
    row = await db.get(LoyaltySettings, user_id)
    return {
        "enabled": bool(row and row.enabled),
        "members": int(members_count or 0),
        "points_outstanding": int(outstanding or 0),
        "points_earned_30d": int(earned or 0),
        "points_redeemed_30d": -int(redeemed or 0),
        "redemptions_30d": int(redemptions or 0),
    }

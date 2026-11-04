"""Withdrawals ledger for the platform admin's earnings, from 1 Oct 2026.

The admin takes money out of what Bitwave earned (by M-Pesa, bank or cash,
outside this app) and records it here so the dashboard can show, per bucket
and in total:

    collected since 1 Oct 2026  -  withdrawn  =  available to withdraw

This module only RECORDS withdrawals. It never moves money, never calls
M-Pesa B2C or any other payment provider, and nothing else in the app reads
these rows to decide a payout.

Buckets (``PlatformWithdrawal.bucket``):
  * ``platform``: platform earnings, i.e. the Hotspot, PPPoE / Static and SMS
    groups of the Bitwave earnings card (reseller subscription payments and
    SMS credit sales, the admin's own accounts excluded);
  * ``reseller_business``: the customer payments taken by the admin's own
    reseller accounts ("My reseller business");
  * ``all``: taken from the combined pot without saying which. It reduces
    the total only; each bucket's "available" is then capped at the total.

Collected uses the same rules as the card (``platform_earnings``): cash
received, completed payments only, card payments net of the Paystack fee.

Rows are never edited or deleted. A mistake is voided, which keeps the row
(with who voided it, when and why) and drops it from "withdrawn". Every
create and void also appends a ``PlatformWithdrawalEvent``.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import PlatformWithdrawal, PlatformWithdrawalEvent, User
from app.services import admin_metrics as metrics
from app.services import platform_earnings as earnings

LEDGER_START = date(2026, 10, 1)
BUCKETS = ("platform", "reseller_business", "all")
SPECIFIC_BUCKETS = ("platform", "reseller_business")
METHODS = ("mpesa", "bank", "cash")
# Kenya time, for "a withdrawal can't be dated in the future".
_EAT = timedelta(hours=3)
# One key for every ledger write, so two records can't both pass the
# "not more than available" check against the same balance.
_LEDGER_LOCK_KEY = 728_301_026
_LIST_LIMIT = 200


class WithdrawalError(Exception):
    """A request the ledger refuses; ``status`` is the HTTP code to answer."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def _today_eat() -> date:
    return (datetime.utcnow() + _EAT).date()


def _money(value: Any) -> float:
    return round(float(value or 0), 2)


async def collected_since_start(db: AsyncSession) -> dict[str, float]:
    """Cash collected per bucket from LEDGER_START until now."""
    own_ids = await metrics.get_own_reseller_ids(db)
    start = datetime.combine(LEDGER_START, datetime.min.time())
    end = datetime.utcnow() + timedelta(days=1)
    # The earnings helpers read a current and a previous window in one query;
    # an empty previous window (start..start) makes them read just this one.
    w = earnings.Windows(start, end, start, start)
    subs, _ = await earnings._collected_subscriptions(db, w, own_ids)
    sms, _, _ = await earnings._collected_sms(db, w, own_ids)
    business, _, _ = await earnings._reseller_business(db, w, own_ids)
    return {
        "platform": _money(sum(subs.values()) + sms),
        "reseller_business": _money(business),
    }


async def _withdrawn_by_bucket(db: AsyncSession) -> dict[str, float]:
    rows = (await db.execute(
        select(PlatformWithdrawal.bucket, func.coalesce(func.sum(PlatformWithdrawal.amount), 0))
        .where(PlatformWithdrawal.voided == False)  # noqa: E712
        .group_by(PlatformWithdrawal.bucket)
    )).all()
    out = {bucket: 0.0 for bucket in BUCKETS}
    for bucket, amount in rows:
        out[bucket] = _money(amount)
    return out


def _summarise(collected: dict[str, float], withdrawn: dict[str, float]) -> dict[str, Any]:
    total_collected = _money(sum(collected[b] for b in SPECIFIC_BUCKETS))
    total_withdrawn = _money(sum(withdrawn.values()))
    total_available = _money(total_collected - total_withdrawn)
    buckets = {}
    for bucket in SPECIFIC_BUCKETS:
        own_available = _money(collected[bucket] - withdrawn[bucket])
        buckets[bucket] = {
            "collected": collected[bucket],
            "withdrawn": withdrawn[bucket],
            # Withdrawals from "all" are not assigned to a bucket, so a bucket
            # can never show more than what is left in total.
            "available": max(0.0, min(own_available, total_available)),
        }
    return {
        "start_date": LEDGER_START.isoformat(),
        "currency": "KES",
        "buckets": buckets,
        "withdrawn_from_all": withdrawn["all"],
        "total": {
            "collected": total_collected,
            "withdrawn": total_withdrawn,
            "available": max(0.0, total_available),
        },
    }


async def ledger_summary(db: AsyncSession) -> dict[str, Any]:
    collected = await collected_since_start(db)
    withdrawn = await _withdrawn_by_bucket(db)
    return _summarise(collected, withdrawn)


def _serialise(row: PlatformWithdrawal, names: dict[int, str]) -> dict[str, Any]:
    return {
        "id": row.id,
        "amount": _money(row.amount),
        "currency": row.currency or "KES",
        "date": row.withdrawn_on.isoformat(),
        "method": row.method,
        "reference": row.reference,
        "note": row.note,
        "bucket": row.bucket,
        "created_by": row.created_by,
        "created_by_name": names.get(row.created_by) if row.created_by else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "voided": bool(row.voided),
        "voided_at": row.voided_at.isoformat() if row.voided_at else None,
        "voided_by": row.voided_by,
        "voided_by_name": names.get(row.voided_by) if row.voided_by else None,
        "void_reason": row.void_reason,
    }


async def _user_names(db: AsyncSession, ids: set[int]) -> dict[int, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = (await db.execute(
        select(User.id, User.organization_name, User.email).where(User.id.in_(ids))
    )).all()
    return {r.id: (r.organization_name or r.email or f"User {r.id}") for r in rows}


async def list_withdrawals(db: AsyncSession) -> dict[str, Any]:
    """Ledger summary plus the most recent withdrawals, voided ones included."""
    summary = await ledger_summary(db)
    rows = (await db.execute(
        select(PlatformWithdrawal)
        .order_by(PlatformWithdrawal.withdrawn_on.desc(), PlatformWithdrawal.id.desc())
        .limit(_LIST_LIMIT)
    )).scalars().all()
    names = await _user_names(db, {r.created_by for r in rows} | {r.voided_by for r in rows})
    await db.commit()
    return {
        **summary,
        "records_only": True,
        "withdrawals": [_serialise(r, names) for r in rows],
    }


def _clean_amount(value: Any) -> Decimal:
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError):
        raise WithdrawalError("Amount must be a number")
    if not amount.is_finite() or amount <= 0:
        raise WithdrawalError("Amount must be more than zero")
    if amount >= Decimal("10000000000"):
        raise WithdrawalError("Amount is too large")
    return amount


def _clean_text(value: str | None, limit: int, field: str) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) > limit:
        raise WithdrawalError(f"{field} must be at most {limit} characters")
    return value or None


async def _lock_ledger(db: AsyncSession) -> None:
    if (await db.connection()).dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LEDGER_LOCK_KEY})


async def create_withdrawal(
    db: AsyncSession,
    *,
    actor: User,
    amount: Any,
    withdrawn_on: date,
    method: str,
    bucket: str,
    reference: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Record a withdrawal. Refuses one that would take more than is available."""
    value = _clean_amount(amount)
    if method not in METHODS:
        raise WithdrawalError(f"Method must be one of: {', '.join(METHODS)}")
    if bucket not in BUCKETS:
        raise WithdrawalError(f"Bucket must be one of: {', '.join(BUCKETS)}")
    if withdrawn_on < LEDGER_START:
        raise WithdrawalError(
            f"The ledger starts on {LEDGER_START.isoformat()}; earlier withdrawals can't be recorded"
        )
    if withdrawn_on > _today_eat():
        raise WithdrawalError("The withdrawal date can't be in the future")
    reference = _clean_text(reference, 100, "Reference")
    note = _clean_text(note, 500, "Note")

    await _lock_ledger(db)
    summary = await ledger_summary(db)
    available = (
        summary["total"]["available"] if bucket == "all"
        else summary["buckets"][bucket]["available"]
    )
    if float(value) > available + 0.005:
        raise WithdrawalError(
            f"Amount KES {float(value):,.2f} is more than the KES {available:,.2f} available to withdraw",
            status=422,
        )

    row = PlatformWithdrawal(
        amount=value, currency="KES", withdrawn_on=withdrawn_on, method=method,
        reference=reference, note=note, bucket=bucket, created_by=actor.id,
        created_at=datetime.utcnow(),
    )
    db.add(row)
    await db.flush()
    db.add(PlatformWithdrawalEvent(
        withdrawal_id=row.id, action="created", actor_id=actor.id,
        details={
            "amount": float(value), "date": withdrawn_on.isoformat(), "method": method,
            "bucket": bucket, "reference": reference, "note": note,
            "available_before": available,
        },
        created_at=datetime.utcnow(),
    ))
    await db.commit()
    await db.refresh(row)
    names = await _user_names(db, {actor.id})
    await db.commit()
    return _serialise(row, names)


async def void_withdrawal(
    db: AsyncSession, *, actor: User, withdrawal_id: int, reason: str,
) -> dict[str, Any]:
    """Void a withdrawal recorded by mistake. The row stays, marked voided."""
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise WithdrawalError("Say why this withdrawal is being voided")
    if len(reason) > 300:
        raise WithdrawalError("Reason must be at most 300 characters")

    await _lock_ledger(db)
    row = await db.get(PlatformWithdrawal, withdrawal_id)
    if row is None:
        raise WithdrawalError("Withdrawal not found", status=404)
    if row.voided:
        raise WithdrawalError("This withdrawal is already voided", status=409)
    row.voided = True
    row.voided_at = datetime.utcnow()
    row.voided_by = actor.id
    row.void_reason = reason
    db.add(PlatformWithdrawalEvent(
        withdrawal_id=row.id, action="voided", actor_id=actor.id,
        details={"reason": reason, "amount": _money(row.amount), "bucket": row.bucket},
        created_at=datetime.utcnow(),
    ))
    await db.commit()
    await db.refresh(row)
    names = await _user_names(db, {row.created_by, actor.id})
    await db.commit()
    return _serialise(row, names)


async def audit_trail(db: AsyncSession, withdrawal_id: int) -> list[dict[str, Any]]:
    rows = (await db.execute(
        select(PlatformWithdrawalEvent)
        .where(PlatformWithdrawalEvent.withdrawal_id == withdrawal_id)
        .order_by(PlatformWithdrawalEvent.id)
    )).scalars().all()
    names = await _user_names(db, {r.actor_id for r in rows})
    await db.commit()
    return [
        {
            "id": r.id,
            "action": r.action,
            "actor_id": r.actor_id,
            "actor_name": names.get(r.actor_id) if r.actor_id else None,
            "details": r.details,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]

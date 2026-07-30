"""Bulk power-outage compensation.

A reseller (or the admin) picks the window a power cut lasted and which
routers it hit; every customer whose paid time overlapped that window gets
their expiry pushed forward by the downtime, so nobody pays for hours the
network was dark.

Design constraints (see AGENTS.md):

* Pure DB work — expiry enforcement is server-driven (the MikroTik cleanup
  cron removes users only once ``Customer.expiry`` passes), so pushing the
  DB expiry forward is sufficient and no router I/O happens here. That also
  means the whole run can share one short transaction.
* Only currently-active customers (``expiry > now``) are credited. A customer
  whose expiry already passed has likely been removed from the router by the
  cleanup cron; silently extending them in the DB would desync router state.
  They are reported in ``skipped_expired`` so the reseller can renew them
  through the normal (re-provisioning) flows instead.
* No ``CustomerPayment`` is written — the credit is free time, not money, so
  revenue/commission aggregates are untouched by design. The audit trail
  lives in ``outage_compensations`` / ``outage_compensation_items``.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.models import (
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    OutageCompensation,
    OutageCompensationItem,
    Router,
)

import logging

logger = logging.getLogger(__name__)


class OutageCompensationError(ValueError):
    """Validation failure with a message safe to surface to the client."""


class OutageOverlapError(OutageCompensationError):
    """A previous run already covers (part of) this window — needs explicit override."""


def _to_naive_utc(dt: datetime) -> datetime:
    """DB stores naive UTC; accept tz-aware input (frontend sends local+offset)."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _validate_window(outage_start: datetime, outage_end: datetime, now: datetime):
    if outage_end <= outage_start:
        raise OutageCompensationError("Outage end must be after outage start")
    # Small tolerance for client/server clock skew on "just ended" outages.
    if outage_end > now + timedelta(minutes=2):
        raise OutageCompensationError(
            "Outage end is in the future — you can only compensate an outage that has ended"
        )
    max_hours = settings.OUTAGE_COMPENSATION_MAX_HOURS
    if outage_end - outage_start > timedelta(hours=max_hours):
        raise OutageCompensationError(
            f"Outage window is longer than the {max_hours}h maximum. "
            "Run separate compensations if the outage really lasted longer."
        )


async def _resolve_routers(
    db: AsyncSession, reseller_id: int, router_ids: Optional[Sequence[int]]
) -> list[Router]:
    stmt = select(Router).where(Router.user_id == reseller_id)
    if router_ids:
        stmt = stmt.where(Router.id.in_(list(router_ids)))
    routers = (await db.execute(stmt)).scalars().all()
    if router_ids:
        missing = set(router_ids) - {r.id for r in routers}
        if missing:
            raise OutageCompensationError(
                f"Router(s) not found or not yours: {sorted(missing)}"
            )
    if not routers:
        raise OutageCompensationError("No routers to compensate")
    return routers


def _credit_seconds(customer: Customer, outage_start: datetime, outage_end: datetime) -> int:
    """Downtime this customer is owed: the outage window, clamped to when the
    customer first existed (someone registered mid-outage only lost the tail)."""
    start = outage_start
    if customer.created_at and customer.created_at > start:
        start = customer.created_at
    return max(0, int((outage_end - start).total_seconds()))


async def _collect(
    db: AsyncSession,
    reseller_id: int,
    router_id_list: list[int],
    outage_start: datetime,
    outage_end: datetime,
    now: datetime,
    exclude_customer_ids: Optional[Sequence[int]] = None,
):
    """Load affected (credit-eligible) and skipped-expired customers."""
    excluded = set(exclude_customer_ids or [])

    base = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.user_id == reseller_id,
            Customer.router_id.in_(router_id_list),
            # Companion devices mirror their owner's expiry; credited via the owner.
            Customer.subscription_owner_id.is_(None),
            Customer.expiry.isnot(None),
        )
    )

    affected = (
        (
            await db.execute(
                base.where(
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry > now,
                    # Bought after the power came back -> not affected.
                    Customer.created_at < outage_end,
                ).order_by(Customer.id)
            )
        )
        .scalars()
        .all()
    )
    affected = [c for c in affected if c.id not in excluded]

    skipped_expired = (
        (
            await db.execute(
                base.where(
                    Customer.expiry > outage_start,
                    Customer.expiry <= now,
                    Customer.created_at < outage_end,
                ).order_by(Customer.id)
            )
        )
        .scalars()
        .all()
    )
    return affected, skipped_expired


async def _overlapping_runs(
    db: AsyncSession,
    reseller_id: int,
    router_id_list: list[int],
    outage_start: datetime,
    outage_end: datetime,
) -> list[OutageCompensation]:
    """Previous compensation runs whose window AND router set overlap this one
    (the double-apply / double-click guard)."""
    rows = (
        (
            await db.execute(
                select(OutageCompensation).where(
                    OutageCompensation.user_id == reseller_id,
                    OutageCompensation.outage_start < outage_end,
                    OutageCompensation.outage_end > outage_start,
                )
            )
        )
        .scalars()
        .all()
    )
    wanted = set(router_id_list)
    return [r for r in rows if wanted & set(r.router_ids or [])]


def _customer_row(c: Customer, credit: int) -> dict:
    return {
        "customer_id": c.id,
        "name": c.name,
        "phone": c.phone,
        "router_id": c.router_id,
        "plan_name": c.plan.name if c.plan else None,
        "connection_type": (
            c.plan.connection_type.value if c.plan and c.plan.connection_type else None
        ),
        "expiry": c.expiry.isoformat() if c.expiry else None,
        "credited_seconds": credit,
        "new_expiry": (c.expiry + timedelta(seconds=credit)).isoformat()
        if c.expiry
        else None,
    }


def _skipped_row(c: Customer) -> dict:
    return {
        "customer_id": c.id,
        "name": c.name,
        "phone": c.phone,
        "router_id": c.router_id,
        "expiry": c.expiry.isoformat() if c.expiry else None,
    }


async def preview_outage_compensation(
    db: AsyncSession,
    *,
    reseller_id: int,
    outage_start: datetime,
    outage_end: datetime,
    router_ids: Optional[Sequence[int]] = None,
    exclude_customer_ids: Optional[Sequence[int]] = None,
) -> dict:
    """Dry run: who would be credited and by how much. No writes."""
    now = datetime.utcnow()
    outage_start = _to_naive_utc(outage_start)
    outage_end = _to_naive_utc(outage_end)
    _validate_window(outage_start, outage_end, now)

    routers = await _resolve_routers(db, reseller_id, router_ids)
    router_id_list = [r.id for r in routers]

    affected, skipped_expired = await _collect(
        db, reseller_id, router_id_list, outage_start, outage_end, now,
        exclude_customer_ids,
    )
    overlaps = await _overlapping_runs(
        db, reseller_id, router_id_list, outage_start, outage_end
    )

    customers = [
        _customer_row(c, _credit_seconds(c, outage_start, outage_end)) for c in affected
    ]
    return {
        "outage_start": outage_start.isoformat(),
        "outage_end": outage_end.isoformat(),
        "outage_seconds": int((outage_end - outage_start).total_seconds()),
        "routers": [{"id": r.id, "name": r.name} for r in routers],
        "customers": customers,
        "total_customers": len(customers),
        "total_seconds_credited": sum(c["credited_seconds"] for c in customers),
        "skipped_expired": [_skipped_row(c) for c in skipped_expired],
        "already_compensated": [
            {
                "id": r.id,
                "outage_start": r.outage_start.isoformat(),
                "outage_end": r.outage_end.isoformat(),
                "customers_credited": r.customers_credited,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in overlaps
        ],
    }


async def apply_outage_compensation(
    db: AsyncSession,
    *,
    reseller_id: int,
    outage_start: datetime,
    outage_end: datetime,
    router_ids: Optional[Sequence[int]] = None,
    exclude_customer_ids: Optional[Sequence[int]] = None,
    note: Optional[str] = None,
    allow_duplicate: bool = False,
) -> dict:
    """Credit every affected customer with the downtime. One transaction,
    committed here; pure DB work throughout (see module docstring)."""
    now = datetime.utcnow()
    outage_start = _to_naive_utc(outage_start)
    outage_end = _to_naive_utc(outage_end)
    _validate_window(outage_start, outage_end, now)

    routers = await _resolve_routers(db, reseller_id, router_ids)
    router_id_list = [r.id for r in routers]

    overlaps = await _overlapping_runs(
        db, reseller_id, router_id_list, outage_start, outage_end
    )
    if overlaps and not allow_duplicate:
        first = overlaps[0]
        raise OutageOverlapError(
            "An overlapping compensation was already applied on "
            f"{first.created_at:%Y-%m-%d %H:%M} UTC for "
            f"{first.outage_start:%Y-%m-%d %H:%M}–{first.outage_end:%H:%M} "
            f"({first.customers_credited} customers). "
            "Pass allow_duplicate=true to apply anyway."
        )

    affected, skipped_expired = await _collect(
        db, reseller_id, router_id_list, outage_start, outage_end, now,
        exclude_customer_ids,
    )

    run = OutageCompensation(
        user_id=reseller_id,
        router_ids=router_id_list,
        outage_start=outage_start,
        outage_end=outage_end,
        note=note,
    )
    db.add(run)
    await db.flush()

    credited_rows: list[dict] = []
    total_seconds = 0
    owner_new_expiry: dict[int, datetime] = {}

    for customer in affected:
        credit = _credit_seconds(customer, outage_start, outage_end)
        if credit <= 0:
            continue
        expiry_before = customer.expiry
        customer.expiry = customer.expiry + timedelta(seconds=credit)
        owner_new_expiry[customer.id] = customer.expiry
        total_seconds += credit
        db.add(
            OutageCompensationItem(
                compensation_id=run.id,
                customer_id=customer.id,
                customer_name=customer.name,
                router_id=customer.router_id,
                seconds_credited=credit,
                expiry_before=expiry_before,
                expiry_after=customer.expiry,
            )
        )
        credited_rows.append(_customer_row(customer, credit))

    owner_ids = list(owner_new_expiry.keys())
    companions_updated = 0
    if owner_ids:
        # Companion devices share the owner's subscription — mirror the new
        # expiry onto their Customer rows and active share pairings so the
        # cleanup cron and pairing checks agree with the owner.
        companions = (
            (
                await db.execute(
                    select(Customer).where(
                        Customer.subscription_owner_id.in_(owner_ids),
                        Customer.status == CustomerStatus.ACTIVE,
                    )
                )
            )
            .scalars()
            .all()
        )
        for comp in companions:
            comp.expiry = owner_new_expiry[comp.subscription_owner_id]
            companions_updated += 1

        pairings = (
            (
                await db.execute(
                    select(DevicePairing).where(
                        DevicePairing.subscription_owner_customer_id.in_(owner_ids),
                        DevicePairing.is_subscription_share == True,  # noqa: E712
                        DevicePairing.is_active == True,  # noqa: E712
                    )
                )
            )
            .scalars()
            .all()
        )
        for pairing in pairings:
            pairing.expires_at = owner_new_expiry[pairing.subscription_owner_customer_id]

        # Usage periods are anchored to expiry — shift the open period's end by
        # the same credit so data-cap accounting stays aligned with the cycle.
        open_periods = (
            (
                await db.execute(
                    select(CustomerUsagePeriod).where(
                        CustomerUsagePeriod.customer_id.in_(owner_ids),
                        CustomerUsagePeriod.closed_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        for period in open_periods:
            period.period_end = owner_new_expiry[period.customer_id]

    run.customers_credited = len(credited_rows)
    run.total_seconds_credited = total_seconds
    await db.commit()

    logger.info(
        "[OUTAGE-COMP] Reseller %s credited %s customer(s) %ss total for outage "
        "%s..%s on routers %s (run %s)",
        reseller_id,
        len(credited_rows),
        total_seconds,
        outage_start.isoformat(),
        outage_end.isoformat(),
        router_id_list,
        run.id,
    )

    return {
        "compensation_id": run.id,
        "outage_start": outage_start.isoformat(),
        "outage_end": outage_end.isoformat(),
        "routers": [{"id": r.id, "name": r.name} for r in routers],
        "customers_credited": len(credited_rows),
        "total_seconds_credited": total_seconds,
        "companion_devices_updated": companions_updated,
        "customers": credited_rows,
        "skipped_expired": [_skipped_row(c) for c in skipped_expired],
    }


async def list_outage_compensations(
    db: AsyncSession, *, reseller_id: int, limit: int = 50
) -> list[dict]:
    """Recent compensation runs for this reseller, newest first."""
    runs = (
        (
            await db.execute(
                select(OutageCompensation)
                .where(OutageCompensation.user_id == reseller_id)
                .order_by(OutageCompensation.created_at.desc(), OutageCompensation.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "outage_start": r.outage_start.isoformat(),
            "outage_end": r.outage_end.isoformat(),
            "router_ids": r.router_ids,
            "customers_credited": r.customers_credited,
            "total_seconds_credited": r.total_seconds_credited,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in runs
    ]

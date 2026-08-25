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

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.services.outage_reprovision import (
    REPROVISION_FAILED,
    REPROVISION_PENDING,
    REPROVISION_ROUTER_OFFLINE,
    schedule_reprovision,
)
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
    """Downtime this customer is owed: the outage window, clamped at both ends
    to the time they were actually paying for.

    Start clamp: someone registered mid-outage only lost the tail.
    End clamp: someone whose subscription ran out *during* the outage only lost
    the hours up to their expiry -- they were not paying for the rest of the
    dark window, so crediting it would be a gift, not a refund.
    """
    start = outage_start
    if customer.created_at and customer.created_at > start:
        start = customer.created_at
    end = outage_end
    if customer.expiry and customer.expiry < end:
        end = customer.expiry
    return max(0, int((end - start).total_seconds()))


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

    # NULL created_at (some imported customers) must not silently exclude a
    # row — treat unknown creation time as "existed before the outage ended".
    existed_before_end = or_(
        Customer.created_at.is_(None), Customer.created_at < outage_end
    )

    affected = (
        (
            await db.execute(
                base.where(
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.expiry > now,
                    # Bought after the power came back -> not affected.
                    existed_before_end,
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
                    existed_before_end,
                ).order_by(Customer.id)
            )
        )
        .scalars()
        .all()
    )
    # The exclusion list has to reach this group too: now that expired
    # customers can be revived, unticking one in the preview must actually
    # keep them out of the run rather than being silently ignored.
    skipped_expired = [c for c in skipped_expired if c.id not in excluded]
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


def _revival_row(c: Customer, credit: int, now: datetime) -> dict:
    """An expired customer's row.

    Note the different expiry arithmetic: adding the credit to an expiry that
    is already in the past would hand them time that has itself already
    elapsed -- a "compensation" worth nothing. Their lost hours are instead
    granted from now, which is what restores what the outage actually took.
    """
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
        "new_expiry": (now + timedelta(seconds=credit)).isoformat(),
        "was_expired": True,
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
    include_expired: bool = False,
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

    # Expired customers are shown either way so the reseller can see who the
    # outage stranded; include_expired decides whether they are acted on.
    expired_rows = [
        _revival_row(c, _credit_seconds(c, outage_start, outage_end), now)
        for c in skipped_expired
    ]
    expired_rows = [r for r in expired_rows if r["credited_seconds"] > 0]

    # Counts and totals are computed over everyone; only the rows sent for
    # display are capped. A town-wide outage on a large reseller would
    # otherwise ship thousands of rows to a phone browser, which is where this
    # actually hurts -- the server side of building them is cheap.
    total_customers = len(customers)
    total_expired = len(expired_rows)
    total_seconds = sum(c["credited_seconds"] for c in customers)
    cap = settings.OUTAGE_COMPENSATION_PREVIEW_ROWS
    customers_truncated = total_customers > cap
    expired_truncated = total_expired > cap

    return {
        "outage_start": outage_start.isoformat(),
        "outage_end": outage_end.isoformat(),
        "outage_seconds": int((outage_end - outage_start).total_seconds()),
        "routers": [{"id": r.id, "name": r.name} for r in routers],
        "customers": customers[:cap],
        "total_customers": total_customers,
        "customers_truncated": customers_truncated,
        "total_seconds_credited": total_seconds,
        "include_expired": include_expired,
        "expired_customers": expired_rows[:cap],
        "total_expired": total_expired,
        "expired_truncated": expired_truncated,
        "preview_row_cap": cap,
        # Backwards-compatible view: with include_expired these are no longer
        # skipped, so the list is empty rather than misleading.
        "skipped_expired": (
            [] if include_expired else [_skipped_row(c) for c in skipped_expired]
        ),
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
    include_expired: bool = False,
) -> dict:
    """Credit every affected customer with the downtime.

    All DB work happens in one short transaction which is committed here. When
    ``include_expired`` revives customers the cleanup cron already removed from
    their router, the router writes needed to actually restore their internet
    are handed to ``outage_reprovision`` *after* that commit -- never inline,
    so no pooled connection is held across RouterOS I/O.
    """
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
        include_expired=include_expired,
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

    # --- revive customers the outage stranded -------------------------------
    # Their expiry is in the past, so unlike an active customer the credit is
    # granted from now (see _revival_row). They also need putting back on the
    # router, which is queued after the commit below.
    revived_rows: list[dict] = []
    reprovision_item_ids: list[int] = []
    new_items: list[OutageCompensationItem] = []
    if include_expired:
        for customer in skipped_expired:
            credit = _credit_seconds(customer, outage_start, outage_end)
            if credit <= 0:
                continue
            expiry_before = customer.expiry
            customer.expiry = now + timedelta(seconds=credit)
            customer.status = CustomerStatus.ACTIVE
            owner_new_expiry[customer.id] = customer.expiry
            total_seconds += credit
            item = OutageCompensationItem(
                compensation_id=run.id,
                customer_id=customer.id,
                customer_name=customer.name,
                router_id=customer.router_id,
                seconds_credited=credit,
                expiry_before=expiry_before,
                expiry_after=customer.expiry,
                was_expired=True,
                reprovision_state=REPROVISION_PENDING,
            )
            db.add(item)
            new_items.append(item)
            revived_rows.append(_revival_row(customer, credit, now))

    # One round trip for the whole group. Flushing per customer inside the
    # loop cost a DB round trip each, which on a big outage is the difference
    # between one short transaction and a long one holding a pooled
    # connection while it chats.
    if new_items:
        await db.flush()
        reprovision_item_ids = [i.id for i in new_items]

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

    run.customers_credited = len(credited_rows) + len(revived_rows)
    run.customers_reactivated = len(revived_rows)
    run.total_seconds_credited = total_seconds
    await db.commit()

    # --- transaction is closed: only now do we touch routers ----------------
    # Detached, so the reseller's request does not wait on hardware that may
    # still be dark. Each customer's outcome lands on its item row.
    if reprovision_item_ids:
        schedule_reprovision(reprovision_item_ids)

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
        "customers_credited": len(credited_rows) + len(revived_rows),
        "total_seconds_credited": total_seconds,
        "companion_devices_updated": companions_updated,
        "customers": credited_rows,
        "include_expired": include_expired,
        "customers_reactivated": len(revived_rows),
        "reactivated": revived_rows,
        # Revived customers are queued for re-provisioning; until that
        # finishes they have paid time but are not yet back on the router.
        "reprovisioning_queued": len(reprovision_item_ids),
        "skipped_expired": (
            [] if include_expired else [_skipped_row(c) for c in skipped_expired]
        ),
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


async def get_outage_compensation(
    db: AsyncSession, *, reseller_id: int, compensation_id: int
) -> Optional[dict]:
    """One run plus its per-customer rows, or None if it isn't this reseller's.

    The re-provisioning outcome is per customer on purpose: after a power cut
    some routers are back and some are not, so "the run succeeded" is rarely
    true of everybody in it.
    """
    run = (
        await db.execute(
            select(OutageCompensation).where(
                OutageCompensation.id == compensation_id,
                OutageCompensation.user_id == reseller_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        return None

    items = (
        (
            await db.execute(
                select(OutageCompensationItem)
                .where(OutageCompensationItem.compensation_id == run.id)
                .order_by(OutageCompensationItem.id)
            )
        )
        .scalars()
        .all()
    )

    return {
        "id": run.id,
        "outage_start": run.outage_start.isoformat(),
        "outage_end": run.outage_end.isoformat(),
        "router_ids": run.router_ids,
        "customers_credited": run.customers_credited,
        "customers_reactivated": run.customers_reactivated,
        "include_expired": run.include_expired,
        "total_seconds_credited": run.total_seconds_credited,
        "note": run.note,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "items": [
            {
                "id": i.id,
                "customer_id": i.customer_id,
                "customer_name": i.customer_name,
                "router_id": i.router_id,
                "seconds_credited": i.seconds_credited,
                "expiry_before": i.expiry_before.isoformat() if i.expiry_before else None,
                "expiry_after": i.expiry_after.isoformat() if i.expiry_after else None,
                "was_expired": bool(i.was_expired),
                "reprovision_state": i.reprovision_state,
                "reprovision_error": i.reprovision_error,
                "reprovision_attempted_at": (
                    i.reprovision_attempted_at.isoformat()
                    if i.reprovision_attempted_at
                    else None
                ),
            }
            for i in items
        ],
    }


async def list_retryable_items(
    db: AsyncSession, *, reseller_id: int, compensation_id: int
) -> Optional[list[int]]:
    """Item ids whose router write still needs doing.

    Returns None when the run isn't this reseller's. Only revived customers who
    did not get back online qualify -- a success is never re-pushed, and the
    time credit is never re-applied by this path.
    """
    run = (
        await db.execute(
            select(OutageCompensation).where(
                OutageCompensation.id == compensation_id,
                OutageCompensation.user_id == reseller_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        return None

    rows = (
        (
            await db.execute(
                select(OutageCompensationItem.id).where(
                    OutageCompensationItem.compensation_id == run.id,
                    OutageCompensationItem.was_expired == True,  # noqa: E712
                    OutageCompensationItem.customer_id.isnot(None),
                    OutageCompensationItem.reprovision_state.in_(
                        [
                            REPROVISION_PENDING,
                            REPROVISION_FAILED,
                            REPROVISION_ROUTER_OFFLINE,
                        ]
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)

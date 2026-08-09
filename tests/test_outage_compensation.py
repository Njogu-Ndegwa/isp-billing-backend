"""Bulk power-outage compensation: preview math, apply, guards, audit trail.

DB-only behavior — the feature deliberately does no router I/O (expiry
enforcement is server-driven), so these tests are the full story.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.models import (
    Customer,
    CustomerPayment,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    OutageCompensation,
    OutageCompensationItem,
)
from app.services.outage_compensation import (
    OutageCompensationError,
    OutageOverlapError,
    apply_outage_compensation,
    list_outage_compensations,
    preview_outage_compensation,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _window(hours_ago_start=4, hours_ago_end=2):
    now = datetime.utcnow()
    return now - timedelta(hours=hours_ago_start), now - timedelta(hours=hours_ago_end)


async def _active_customer(db, reseller, plan, router, *, days_left=10, **overrides):
    return await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=days_left),
        created_at=datetime.utcnow() - timedelta(days=5),
        **overrides,
    )


# ---------------------------------------------------------------- preview ----

async def test_preview_credits_active_customer_full_outage(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await _active_customer(db, reseller, plan, router)
    start, end = _window()

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    assert result["total_customers"] == 1
    row = result["customers"][0]
    assert row["customer_id"] == customer.id
    assert row["credited_seconds"] == int((end - start).total_seconds())
    expected_new = customer.expiry + (end - start)
    assert row["new_expiry"] == expected_new.isoformat()
    assert result["skipped_expired"] == []
    assert result["already_compensated"] == []


async def test_preview_accepts_tz_aware_datetimes(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router)
    start, end = _window()
    start_aware = start.replace(tzinfo=timezone.utc)
    # Same instants expressed in Nairobi time (UTC+3), as the frontend sends.
    nairobi = timezone(timedelta(hours=3))
    end_aware = end.replace(tzinfo=timezone.utc).astimezone(nairobi)

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start_aware, outage_end=end_aware
    )
    assert result["total_customers"] == 1
    assert result["customers"][0]["credited_seconds"] == int((end - start).total_seconds())


async def test_customer_created_mid_outage_gets_clamped_credit(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window(hours_ago_start=4, hours_ago_end=1)
    created = start + timedelta(hours=1)
    await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
        created_at=created,
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )
    assert result["total_customers"] == 1
    assert result["customers"][0]["credited_seconds"] == int((end - created).total_seconds())


async def test_customer_created_after_outage_not_credited(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window(hours_ago_start=6, hours_ago_end=4)
    await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
        created_at=end + timedelta(minutes=30),
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )
    assert result["total_customers"] == 0


async def test_null_created_at_customer_still_credited(db):
    """Imported customers can lack created_at — unknown creation time must not
    silently exclude them from the credit."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
    )
    # The column default stamps created_at on insert; imported rows have NULL.
    customer.created_at = None
    await db.commit()
    start, end = _window()

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )
    assert [c["customer_id"] for c in result["customers"]] == [customer.id]
    assert result["customers"][0]["credited_seconds"] == int((end - start).total_seconds())


async def test_expired_customer_reported_not_credited(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window(hours_ago_start=6, hours_ago_end=2)
    # Expired mid-outage: lost time, but already cleaned off the router.
    expired = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=start + timedelta(hours=1),
        created_at=datetime.utcnow() - timedelta(days=30),
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )
    assert result["total_customers"] == 0
    assert [c["customer_id"] for c in result["skipped_expired"]] == [expired.id]


async def test_scoping_other_reseller_other_router_inactive(db):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, reseller)
    other_plan = await make_plan(db, other)
    router = await make_router(db, reseller)
    router2 = await make_router(db, reseller)
    other_router = await make_router(db, other)

    mine = await _active_customer(db, reseller, plan, router)
    await _active_customer(db, reseller, plan, router2)          # other router
    await _active_customer(db, other, other_plan, other_router)  # other reseller
    await make_customer(                                         # inactive
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1),
        created_at=datetime.utcnow() - timedelta(days=5),
    )
    start, end = _window()

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        router_ids=[router.id],
    )
    assert [c["customer_id"] for c in result["customers"]] == [mine.id]


async def test_router_ownership_enforced(db):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    other_router = await make_router(db, other)
    start, end = _window()

    with pytest.raises(OutageCompensationError, match="not found or not yours"):
        await preview_outage_compensation(
            db, reseller_id=reseller.id, outage_start=start, outage_end=end,
            router_ids=[other_router.id],
        )


# ------------------------------------------------------------- validation ----

async def test_window_validation(db):
    reseller = await make_reseller(db)
    await make_router(db, reseller)
    now = datetime.utcnow()

    with pytest.raises(OutageCompensationError, match="after outage start"):
        await preview_outage_compensation(
            db, reseller_id=reseller.id,
            outage_start=now - timedelta(hours=1), outage_end=now - timedelta(hours=2),
        )

    with pytest.raises(OutageCompensationError, match="in the future"):
        await preview_outage_compensation(
            db, reseller_id=reseller.id,
            outage_start=now - timedelta(hours=1), outage_end=now + timedelta(hours=2),
        )

    with pytest.raises(OutageCompensationError, match="maximum"):
        await preview_outage_compensation(
            db, reseller_id=reseller.id,
            outage_start=now - timedelta(days=10), outage_end=now - timedelta(hours=1),
        )


# ------------------------------------------------------------------ apply ----

async def test_apply_extends_expiry_and_writes_audit_trail(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await _active_customer(db, reseller, plan, router)
    expiry_before = customer.expiry
    start, end = _window(hours_ago_start=5, hours_ago_end=2)

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        note="Transformer blew at the market",
    )

    assert result["customers_credited"] == 1
    outage_seconds = int((end - start).total_seconds())
    assert result["total_seconds_credited"] == outage_seconds

    await db.refresh(customer)
    assert customer.expiry == expiry_before + timedelta(seconds=outage_seconds)

    run = (await db.execute(select(OutageCompensation))).scalar_one()
    assert run.user_id == reseller.id
    assert run.customers_credited == 1
    assert run.total_seconds_credited == outage_seconds
    assert run.router_ids == [router.id]
    assert run.note == "Transformer blew at the market"

    item = (await db.execute(select(OutageCompensationItem))).scalar_one()
    assert item.compensation_id == run.id
    assert item.customer_id == customer.id
    assert item.seconds_credited == outage_seconds
    assert item.expiry_before == expiry_before
    assert item.expiry_after == customer.expiry


async def test_apply_writes_no_payment_rows(db):
    """The credit is free time, not money — revenue aggregates must not move."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router)
    start, end = _window()

    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    payments = (await db.execute(select(CustomerPayment))).scalars().all()
    assert payments == []


async def test_apply_overlap_guard_and_override(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router)
    start, end = _window(hours_ago_start=6, hours_ago_end=3)

    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    # Overlapping second run (double-click / re-submit) is rejected...
    with pytest.raises(OutageOverlapError, match="already applied"):
        await apply_outage_compensation(
            db, reseller_id=reseller.id,
            outage_start=start + timedelta(minutes=30), outage_end=end,
        )

    # ...unless explicitly overridden.
    result = await apply_outage_compensation(
        db, reseller_id=reseller.id,
        outage_start=start + timedelta(minutes=30), outage_end=end,
        allow_duplicate=True,
    )
    assert result["customers_credited"] == 1


async def test_apply_disjoint_window_needs_no_override(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router)

    first_start, first_end = _window(hours_ago_start=10, hours_ago_end=8)
    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=first_start, outage_end=first_end
    )
    second_start, second_end = _window(hours_ago_start=4, hours_ago_end=2)
    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=second_start, outage_end=second_end
    )
    assert result["customers_credited"] == 1


async def test_apply_disjoint_routers_needs_no_override(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router_a)
    await _active_customer(db, reseller, plan, router_b)
    start, end = _window()

    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        router_ids=[router_a.id],
    )
    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        router_ids=[router_b.id],
    )
    assert result["customers_credited"] == 1


async def test_exclude_customer_ids(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    keep = await _active_customer(db, reseller, plan, router)
    skip = await _active_customer(db, reseller, plan, router)
    start, end = _window()

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        exclude_customer_ids=[skip.id],
    )
    assert [c["customer_id"] for c in result["customers"]] == [keep.id]


async def test_companion_devices_mirror_owner_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=3)
    router = await make_router(db, reseller)
    owner = await _active_customer(db, reseller, plan, router)
    companion = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=owner.expiry,
        created_at=datetime.utcnow() - timedelta(days=5),
        subscription_owner_id=owner.id,
        name="TV",
    )
    pairing = DevicePairing(
        customer_id=companion.id,
        device_mac=companion.mac_address,
        router_id=router.id,
        plan_id=plan.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=True,
        expires_at=owner.expiry,
    )
    db.add(pairing)
    await db.commit()

    start, end = _window()
    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    # Only the owner is credited (no double credit for the companion)...
    assert [c["customer_id"] for c in result["customers"]] == [owner.id]
    assert result["companion_devices_updated"] == 1

    # ...but the companion's row and its pairing mirror the new expiry.
    await db.refresh(owner)
    await db.refresh(companion)
    await db.refresh(pairing)
    assert companion.expiry == owner.expiry
    assert pairing.expires_at == owner.expiry

    items = (await db.execute(select(OutageCompensationItem))).scalars().all()
    assert [i.customer_id for i in items] == [owner.id]


async def test_open_usage_period_end_shifts_with_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await _active_customer(db, reseller, plan, router)
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=datetime.utcnow() - timedelta(days=20),
        period_end=customer.expiry,
        upload_bytes=0,
        download_bytes=0,
        total_bytes=0,
    )
    db.add(period)
    await db.commit()

    start, end = _window()
    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    await db.refresh(customer)
    await db.refresh(period)
    assert period.period_end == customer.expiry


# ---------------------------------------------------------------- history ----

async def test_history_lists_runs_newest_first(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    await _active_customer(db, reseller, plan, router)

    s1, e1 = _window(hours_ago_start=10, hours_ago_end=9)
    s2, e2 = _window(hours_ago_start=4, hours_ago_end=2)
    first = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=s1, outage_end=e1
    )
    second = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=s2, outage_end=e2
    )

    runs = await list_outage_compensations(db, reseller_id=reseller.id)
    assert [r["id"] for r in runs] == [second["compensation_id"], first["compensation_id"]]
    assert runs[0]["customers_credited"] == 1

    other = await make_reseller(db)
    assert await list_outage_compensations(db, reseller_id=other.id) == []

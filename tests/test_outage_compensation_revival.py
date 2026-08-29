"""Outage compensation for customers who had already expired.

Two separate things are pinned down here:

* the DB effect — credit clamped honestly, expiry granted from *now* (not from
  a stale expiry), status flipped back to ACTIVE;
* the fact that the router work is *queued after commit*, never performed
  inline. That is the whole safety argument for this feature, so it is asserted
  rather than assumed.

Router behaviour itself lives in tests/test_outage_reprovision.py.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    CustomerPayment,
    CustomerStatus,
    OutageCompensationItem,
)
from app.services.outage_compensation import (
    apply_outage_compensation,
    get_outage_compensation,
    list_retryable_items,
    preview_outage_compensation,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _window(hours_ago_start=6, hours_ago_end=4):
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


async def _expired_customer(db, reseller, plan, router, *, expiry, **overrides):
    return await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=expiry,
        created_at=datetime.utcnow() - timedelta(days=30),
        **overrides,
    )


@pytest.fixture
def captured_queue(monkeypatch):
    """Intercept the post-commit hand-off so tests never touch a router."""
    queued: list[list[int]] = []
    monkeypatch.setattr(
        "app.services.outage_compensation.schedule_reprovision",
        lambda ids: queued.append(list(ids)),
    )
    return queued


# ------------------------------------------------------------- credit math ----

async def test_credit_is_clamped_at_the_customers_own_expiry(db):
    """Someone whose time ran out one hour into a long outage lost one hour,
    not the whole window — they were not paying for the rest of the dark time."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window(hours_ago_start=4, hours_ago_end=1)
    expired = await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )

    assert result["total_expired"] == 1
    row = result["expired_customers"][0]
    assert row["customer_id"] == expired.id
    assert row["credited_seconds"] == 3600


async def test_active_customer_credit_is_unaffected_by_the_clamp(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _active_customer(db, reseller, plan, router)

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    assert result["customers"][0]["credited_seconds"] == int(
        (end - start).total_seconds()
    )


# ----------------------------------------------------------------- preview ----

async def test_expired_credit_runs_from_now_not_from_a_stale_expiry(db):
    """Adding the credit to an expiry already in the past would hand back time
    that has itself elapsed — a compensation worth nothing."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    stale_expiry = start + timedelta(hours=1)  # five hours ago, and unusable
    await _expired_customer(db, reseller, plan, router, expiry=stale_expiry)

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )

    row = result["expired_customers"][0]
    new_expiry = datetime.fromisoformat(row["new_expiry"])
    assert new_expiry > datetime.utcnow(), "revived expiry must be usable"
    # The naive arithmetic would land in the past and be worth nothing.
    assert new_expiry != stale_expiry + timedelta(seconds=row["credited_seconds"])
    assert row["was_expired"] is True
    # Nothing is "skipped" when we are acting on them.
    assert result["skipped_expired"] == []


async def test_preview_without_include_expired_only_reports_them(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    expired = await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )

    result = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )

    assert result["include_expired"] is False
    assert [c["customer_id"] for c in result["skipped_expired"]] == [expired.id]
    assert [c["customer_id"] for c in result["expired_customers"]] == [expired.id]


# ------------------------------------------------------------------- apply ----

async def test_apply_revives_expired_customer_and_queues_reprovisioning(
    db, captured_queue
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    expired = await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )
    expiry_before = expired.expiry

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )

    assert result["customers_reactivated"] == 1
    assert result["reprovisioning_queued"] == 1
    assert result["reactivated"][0]["expiry"] == expiry_before.isoformat()

    await db.refresh(expired)
    assert expired.status == CustomerStatus.ACTIVE
    assert expired.expiry > datetime.utcnow()
    assert result["reactivated"][0]["new_expiry"] == expired.expiry.isoformat()

    item = (
        await db.execute(
            select(OutageCompensationItem).where(
                OutageCompensationItem.customer_id == expired.id
            )
        )
    ).scalar_one()
    assert item.was_expired is True
    assert item.reprovision_state == "pending"
    assert item.expiry_before < datetime.utcnow()
    # Queued by item id — so the worker has a row to write its outcome back to.
    assert captured_queue == [[item.id]]


async def test_reviving_still_writes_no_payment_row(db, captured_queue):
    """The revival must stay free time: a payment row would move revenue and
    hotspot commission, which this feature is explicitly not allowed to do."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )

    await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )

    assert (await db.execute(select(CustomerPayment))).scalars().all() == []


async def test_apply_without_include_expired_leaves_expired_untouched(
    db, captured_queue
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    stale_expiry = start + timedelta(hours=1)
    expired = await _expired_customer(db, reseller, plan, router, expiry=stale_expiry)

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
    )

    assert result["customers_reactivated"] == 0
    assert result["reprovisioning_queued"] == 0
    assert captured_queue == []
    await db.refresh(expired)
    assert expired.expiry == stale_expiry


async def test_active_customers_are_never_queued_for_router_work(db, captured_queue):
    """An active customer never left the router, so reviving machinery must not
    touch them even when the run has include_expired on."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _active_customer(db, reseller, plan, router)

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )

    assert result["customers_credited"] == 1
    assert result["customers_reactivated"] == 0
    assert captured_queue == []


# --------------------------------------------------------- detail / retry ----

async def test_detail_and_retry_only_target_stuck_revivals(db, captured_queue):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _active_customer(db, reseller, plan, router)
    await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )

    applied = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )
    run_id = applied["compensation_id"]

    detail = await get_outage_compensation(
        db, reseller_id=reseller.id, compensation_id=run_id
    )
    assert detail["customers_reactivated"] == 1
    assert len(detail["items"]) == 2

    # Only the revived one needs a router write; the active one never left.
    retryable = await list_retryable_items(
        db, reseller_id=reseller.id, compensation_id=run_id
    )
    assert len(retryable) == 1

    # Once it has succeeded there is nothing left to retry — a success is
    # never re-pushed and the time credit is never re-applied by this path.
    item = await db.get(OutageCompensationItem, retryable[0])
    item.reprovision_state = "succeeded"
    await db.commit()
    assert await list_retryable_items(
        db, reseller_id=reseller.id, compensation_id=run_id
    ) == []


async def test_router_offline_rows_stay_retryable(db, captured_queue):
    """A router still dark after the power cut is the expected failure. The
    credit stands; the router write must remain queued for later."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )

    applied = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True,
    )
    run_id = applied["compensation_id"]

    item_id = (
        await list_retryable_items(
            db, reseller_id=reseller.id, compensation_id=run_id
        )
    )[0]
    item = await db.get(OutageCompensationItem, item_id)
    item.reprovision_state = "router_offline"
    await db.commit()

    still_retryable = await list_retryable_items(
        db, reseller_id=reseller.id, compensation_id=run_id
    )
    assert still_retryable == [item_id]


async def test_detail_and_retry_are_scoped_to_the_owning_reseller(db, captured_queue):
    reseller = await make_reseller(db)
    intruder = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    await _active_customer(db, reseller, plan, router)

    applied = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end
    )
    run_id = applied["compensation_id"]

    assert await get_outage_compensation(
        db, reseller_id=intruder.id, compensation_id=run_id
    ) is None
    assert await list_retryable_items(
        db, reseller_id=intruder.id, compensation_id=run_id
    ) is None


async def test_unticking_a_revived_customer_actually_excludes_them(db, captured_queue):
    """The preview lets the reseller untick people in either group. Before
    expired customers could be revived the exclusion list only had to reach the
    active group; now it must reach both, or an untick is silently ignored."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    start, end = _window()
    keep = await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )
    drop = await _expired_customer(
        db, reseller, plan, router, expiry=start + timedelta(hours=1)
    )
    drop_expiry = drop.expiry

    preview = await preview_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True, exclude_customer_ids=[drop.id],
    )
    assert [c["customer_id"] for c in preview["expired_customers"]] == [keep.id]

    result = await apply_outage_compensation(
        db, reseller_id=reseller.id, outage_start=start, outage_end=end,
        include_expired=True, exclude_customer_ids=[drop.id],
    )

    assert result["customers_reactivated"] == 1
    assert [c["customer_id"] for c in result["reactivated"]] == [keep.id]
    await db.refresh(drop)
    assert drop.expiry == drop_expiry, "an unticked customer must not be revived"

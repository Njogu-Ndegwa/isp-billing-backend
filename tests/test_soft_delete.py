"""Core semantics of the system-wide soft delete (docs/SOFT_DELETE_PLAN.md).

Pins down the load-bearing behaviors the rest of the conversion relies on:
the global SELECT filter, the include_deleted escape hatch, Session.get()
coverage, relationship/join filtering, and tombstones not blocking re-use of
unique values (the partial-unique-index conversion).
"""

from datetime import datetime

import pytest
from sqlalchemy import select, func

from app.db.database import soft_delete
from app.db.models import Customer, Plan, User, Voucher, VoucherStatus, VoucherType
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _fresh(db, obj):
    """Read the row again in a way that can't be served by the identity map."""
    cls, pk = type(obj), obj.id  # capture pk BEFORE expunging
    db.expunge_all()
    return await db.get(cls, pk)


async def test_soft_deleted_rows_vanish_from_selects(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    keep = await make_customer(db, reseller, plan, name="keeper")
    gone = await make_customer(db, reseller, plan, name="goner")

    soft_delete(gone, deleted_by=reseller.id)
    await db.commit()

    names = (await db.execute(select(Customer.name))).scalars().all()
    assert names == ["keeper"]

    count = (await db.execute(select(func.count()).select_from(Customer))).scalar()
    assert count == 1

    by_pk = (await db.execute(select(Customer).where(Customer.id == gone.id))).scalar_one_or_none()
    assert by_pk is None
    assert keep.id in [c.id for c in (await db.execute(select(Customer))).scalars()]


async def test_include_deleted_escape_hatch(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    gone = await make_customer(db, reseller, plan)
    soft_delete(gone)
    await db.commit()

    rows = (
        await db.execute(
            select(Customer).execution_options(include_deleted=True)
        )
    ).scalars().all()
    assert [c.id for c in rows] == [gone.id]
    assert rows[0].deleted_at is not None


async def test_session_get_behavior_is_pinned(db):
    """Pin Session.get() semantics the 75 db.get() call sites rely on.

    When get() emits SQL, the soft-delete filter applies and a tombstoned row
    comes back as None. The one exception is the identity map: the session
    that just soft-deleted an object still holds it and get() returns it
    without SQL — acceptable, since that's the deleting code itself. If this
    assertion ever flips on a SQLAlchemy upgrade, the db.get() call sites
    need explicit deleted_at guards instead.
    """
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    cust_id = cust.id
    soft_delete(cust)
    await db.commit()

    # Same session, object still in identity map: returned without SQL.
    assert await db.get(Customer, cust_id) is cust

    # Fresh load (identity map cleared): filter applies, row is invisible.
    assert await _fresh(db, cust) is None


async def test_joins_and_relationships_are_filtered(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    soft_delete(cust)
    await db.commit()
    db.expire_all()

    joined = (
        await db.execute(
            select(Customer).join(Plan, Customer.plan_id == Plan.id)
        )
    ).scalars().all()
    assert joined == []


async def test_tombstone_does_not_block_reusing_unique_values(db):
    """The partial-unique-index conversion: same MAC + reseller can register
    again after the old customer is soft-deleted; same voucher code can be
    re-issued after the old voucher is tombstoned."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    first = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:00:00:01")
    soft_delete(first)
    await db.commit()

    second = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:00:00:01")
    assert second.id != first.id

    v1 = Voucher(code="11112222", plan_id=plan.id, user_id=reseller.id,
                 status=VoucherStatus.AVAILABLE, voucher_type=VoucherType.SALE)
    db.add(v1)
    await db.commit()
    soft_delete(v1)
    await db.commit()

    v2 = Voucher(code="11112222", plan_id=plan.id, user_id=reseller.id,
                 status=VoucherStatus.AVAILABLE, voucher_type=VoucherType.SALE)
    db.add(v2)
    await db.commit()
    assert v2.id != v1.id


async def test_live_unique_values_still_conflict(db):
    """Partial index must still enforce uniqueness among LIVE rows."""
    from sqlalchemy.exc import IntegrityError

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    await make_customer(db, reseller, plan, mac_address="AA:BB:CC:00:00:02")

    with pytest.raises(IntegrityError):
        await make_customer(db, reseller, plan, mac_address="AA:BB:CC:00:00:02")
    await db.rollback()


async def test_no_behavior_change_when_nothing_deleted(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    await make_customer(db, reseller, plan)
    await make_customer(db, reseller, plan)

    assert (await db.execute(select(func.count()).select_from(Customer))).scalar() == 2
    assert (await db.execute(select(func.count()).select_from(User))).scalar() == 1

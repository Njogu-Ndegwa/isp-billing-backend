"""Purge job + restore endpoint semantics (docs/SOFT_DELETE_PLAN.md)."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, func

from app.db.database import soft_delete
from app.db.models import (
    Customer, CustomerPayment, PaymentMethod, Plan, Router, User,
)
from app.services.soft_delete_purge import purge_expired_tombstones
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _count_all(db, model):
    """Count rows INCLUDING tombstones."""
    return (
        await db.execute(
            select(func.count()).select_from(model)
            .execution_options(include_deleted=True)
        )
    ).scalar()


async def test_purge_removes_only_expired_tombstones(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    live = await make_customer(db, reseller, plan, name="live")
    fresh_dead = await make_customer(db, reseller, plan, name="fresh-dead")
    old_dead = await make_customer(db, reseller, plan, name="old-dead")

    soft_delete(fresh_dead)  # now — inside retention
    soft_delete(old_dead, when=datetime.utcnow() - timedelta(days=120))
    await db.commit()

    purged = await purge_expired_tombstones(retention_days=90)

    assert purged.get("customers") == 1
    assert await _count_all(db, Customer) == 2  # live + fresh_dead survive
    names = (
        await db.execute(
            select(Customer.name).execution_options(include_deleted=True)
        )
    ).scalars().all()
    assert sorted(names) == ["fresh-dead", "live"]


async def test_purge_detaches_live_ledger_rows_and_snapshots_name(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan, name="Ledger Customer")
    payment = CustomerPayment(
        customer_id=cust.id,
        reseller_id=reseller.id,
        amount=500,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=30,
    )
    db.add(payment)
    await db.commit()
    payment_id = payment.id

    soft_delete(cust, when=datetime.utcnow() - timedelta(days=120))
    await db.commit()

    purged = await purge_expired_tombstones(retention_days=90)
    assert purged.get("customers") == 1

    db.expunge_all()
    kept = await db.get(CustomerPayment, payment_id)
    assert kept is not None, "ledger row must survive the purge"
    assert kept.customer_id is None
    assert kept.customer_name == "Ledger Customer"


async def test_purge_handles_parent_child_groups(db):
    """A reseller-style group (customer + router + plan + user) purges in one
    run without FK errors thanks to children-first table order."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    cust = await make_customer(db, reseller, plan, router)

    old_ts = datetime.utcnow() - timedelta(days=120)
    # Mirror the cascade: detach cross-refs like the delete flows do, then
    # tombstone everything with one shared timestamp.
    cust.router_id = None
    cust.plan_id = None
    for obj in (cust, router, plan, reseller):
        soft_delete(obj, when=old_ts)
    await db.commit()

    purged = await purge_expired_tombstones(retention_days=90)

    assert purged.get("customers") == 1
    assert purged.get("routers") == 1
    assert purged.get("plans") == 1
    assert purged.get("users") == 1
    assert await _count_all(db, User) == 0


async def test_recent_tombstones_survive_default_retention(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    soft_delete(cust)
    await db.commit()

    purged = await purge_expired_tombstones()  # default 90 days
    assert "customers" not in purged
    assert await _count_all(db, Customer) == 1


async def test_restore_brings_back_whole_group(db):
    from app.api import admin_reseller_routes as arr

    admin = await make_reseller(db, role=__import__("app.db.models", fromlist=["UserRole"]).UserRole.ADMIN)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan, name="restore-me")

    ts = datetime.utcnow()
    soft_delete(cust, when=ts, deleted_by=admin.id)
    soft_delete(plan, when=ts, deleted_by=admin.id)
    await db.commit()
    cust_id, plan_id = cust.id, plan.id
    db.expunge_all()

    async def _fake_require_admin(token, _db):
        return admin
    orig = arr._require_admin
    arr._require_admin = _fake_require_admin
    try:
        listing = await arr.list_soft_deleted("customer", 50, db, "token")
        assert any(i["id"] == cust_id for i in listing["items"])

        result = await arr.restore_soft_deleted("customer", cust_id, db, "token")
    finally:
        arr._require_admin = orig

    assert result["restored"].get("customers") == 1
    assert result["restored"].get("plans") == 1

    db.expunge_all()
    back = await db.get(Customer, cust_id)
    assert back is not None and back.deleted_at is None
    back_plan = await db.get(Plan, plan_id)
    assert back_plan is not None and back_plan.deleted_at is None

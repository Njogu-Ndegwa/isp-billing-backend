"""
Deleting a plan must not be blocked by the history that references it.

Bug (BIG NEBS, plan 2079, 2026-10-11): DELETE /api/plans/{id} returned a 500
for any plan that had ever sold a voucher or paired a device, because
vouchers.plan_id and device_pairings.plan_id had no ON DELETE rule and Postgres
raised a ForeignKeyViolation. Roughly a fifth of all plans were undeletable.

Fix: used vouchers, paired devices and inactive customers are detached
(plan_id -> NULL) and survive the delete; unused vouchers still block it with
a clear 400, because they may already be printed and sold.
"""

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

from app.db.models import (
    CustomerStatus,
    DevicePairing,
    MpesaTransaction,
    MpesaTransactionStatus,
    Plan,
    UserRole,
    Voucher,
    VoucherStatus,
    ZenoPayTransaction,
    ZenoPayTransactionStatus,
)
from tests.conftest import running_on_postgres
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _as_reseller(monkeypatch, module, reseller):
    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(module, "get_current_user", fake_current_user)
    if hasattr(module, "enforce_active_subscription"):
        monkeypatch.setattr(module, "enforce_active_subscription", lambda user: None)


async def _delete_plan(db, monkeypatch, reseller, plan_id):
    from app.api import plan_routes

    _as_reseller(monkeypatch, plan_routes, reseller)
    return await plan_routes.delete_plan(plan_id=plan_id, db=db, token="test-token")


async def _plan_with_history(db):
    """A plan that sold a voucher and paired a TV, the shape that used to 500."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, name="ELIS 1 50GB")
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, status=CustomerStatus.INACTIVE)
    voucher = Voucher(
        code="20790001",
        plan_id=plan.id,
        router_id=router.id,
        user_id=reseller.id,
        status=VoucherStatus.REDEEMED,
        redeemed_by=customer.id,
        redeemed_at=datetime.utcnow(),
    )
    pairing = DevicePairing(
        customer_id=customer.id,
        device_mac="AA:BB:CC:20:79:01",
        router_id=router.id,
        plan_id=plan.id,
    )
    db.add_all([voucher, pairing])
    await db.commit()
    return reseller, plan, router, customer, voucher, pairing


async def test_plan_with_redeemed_voucher_and_pairing_can_be_deleted(db, monkeypatch):
    reseller, plan, _, customer, voucher, pairing = await _plan_with_history(db)
    voucher_id, pairing_id = voucher.id, pairing.id

    result = await _delete_plan(db, monkeypatch, reseller, plan.id)

    assert result["success"] is True
    assert (await db.execute(select(Plan).where(Plan.id == plan.id))).scalar_one_or_none() is None

    # History survives, only the link to the plan is dropped
    db.expire_all()
    kept_voucher = (await db.execute(select(Voucher).where(Voucher.id == voucher_id))).scalar_one()
    kept_pairing = (await db.execute(select(DevicePairing).where(DevicePairing.id == pairing_id))).scalar_one()
    await db.refresh(customer)
    assert kept_voucher.plan_id is None
    assert kept_voucher.status == VoucherStatus.REDEEMED
    assert kept_pairing.plan_id is None
    assert customer.plan_id is None


async def test_unused_vouchers_block_delete_with_clear_message(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    db.add_all([
        Voucher(code="20790011", plan_id=plan.id, user_id=reseller.id, status=VoucherStatus.AVAILABLE),
        Voucher(code="20790012", plan_id=plan.id, user_id=reseller.id, status=VoucherStatus.AVAILABLE),
    ])
    await db.commit()

    with pytest.raises(HTTPException) as exc:
        await _delete_plan(db, monkeypatch, reseller, plan.id)

    assert exc.value.status_code == 400
    assert "2 unused voucher(s)" in exc.value.detail
    assert (await db.execute(select(Plan).where(Plan.id == plan.id))).scalar_one_or_none() is not None


async def test_disabled_vouchers_do_not_block_delete(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    db.add(Voucher(code="20790021", plan_id=plan.id, user_id=reseller.id, status=VoucherStatus.DISABLED))
    await db.commit()

    result = await _delete_plan(db, monkeypatch, reseller, plan.id)

    assert result["success"] is True


async def test_active_customers_still_block_delete(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    await make_customer(db, reseller, plan, status=CustomerStatus.ACTIVE)

    with pytest.raises(HTTPException) as exc:
        await _delete_plan(db, monkeypatch, reseller, plan.id)

    assert exc.value.status_code == 400
    assert "active customer" in exc.value.detail


def _stk(customer, plan_id=None, status=MpesaTransactionStatus.pending, age=timedelta(minutes=1)):
    return MpesaTransaction(
        checkout_request_id=f"ws_CO_{customer.id}_{status.value}_{int(age.total_seconds())}",
        phone_number=customer.phone,
        amount=500,
        reference="hotspot",
        status=status,
        customer_id=customer.id,
        plan_id=plan_id,
        created_at=datetime.utcnow() - age,
    )


async def _assert_blocked_by_payment(db, monkeypatch, reseller, plan):
    with pytest.raises(HTTPException) as exc:
        await _delete_plan(db, monkeypatch, reseller, plan.id)
    assert exc.value.status_code == 400
    assert "still being confirmed" in exc.value.detail
    assert (await db.execute(select(Plan).where(Plan.id == plan.id))).scalar_one_or_none() is not None


async def test_pending_mpesa_payment_blocks_delete(db, monkeypatch):
    """Customer is mid-STK-push for this plan: the callback would find no plan."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, status=CustomerStatus.PENDING)
    db.add(_stk(customer, plan_id=plan.id))
    await db.commit()

    await _assert_blocked_by_payment(db, monkeypatch, reseller, plan)


async def test_pending_plan_switch_payment_blocks_delete(db, monkeypatch):
    """Existing customer paying to switch onto this plan (pending_update_data)."""
    reseller = await make_reseller(db)
    old_plan = await make_plan(db, reseller, name="Old")
    new_plan = await make_plan(db, reseller, name="New")
    customer = await make_customer(
        db, reseller, old_plan, status=CustomerStatus.INACTIVE,
        pending_update_data=json.dumps({"plan_id": new_plan.id}),
    )
    db.add(_stk(customer))
    await db.commit()

    await _assert_blocked_by_payment(db, monkeypatch, reseller, new_plan)

    # The customer is leaving old_plan, so deleting it cannot strand the payment
    result = await _delete_plan(db, monkeypatch, reseller, old_plan.id)
    assert result["success"] is True


async def test_pending_payment_from_other_provider_blocks_delete(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, status=CustomerStatus.PENDING)
    db.add(ZenoPayTransaction(
        order_id="zp-2079", reseller_id=reseller.id, customer_id=customer.id,
        amount=500, status=ZenoPayTransactionStatus.PENDING, buyer_phone=customer.phone,
    ))
    await db.commit()

    await _assert_blocked_by_payment(db, monkeypatch, reseller, plan)


@pytest.mark.parametrize("status, age", [
    (MpesaTransactionStatus.completed, timedelta(minutes=1)),
    (MpesaTransactionStatus.failed, timedelta(minutes=1)),
    (MpesaTransactionStatus.pending, timedelta(hours=3)),  # past reconciliation, will expire
])
async def test_settled_or_stale_payments_do_not_block_delete(db, monkeypatch, status, age):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, status=CustomerStatus.INACTIVE)
    db.add(_stk(customer, plan_id=plan.id, status=status, age=age))
    await db.commit()

    result = await _delete_plan(db, monkeypatch, reseller, plan.id)

    assert result["success"] is True


async def test_voucher_stats_keep_deleted_plan_vouchers(db, monkeypatch):
    from app.api import voucher_routes

    reseller, plan, *_ = await _plan_with_history(db)
    await _delete_plan(db, monkeypatch, reseller, plan.id)

    _as_reseller(monkeypatch, voucher_routes, reseller)
    stats = await voucher_routes.voucher_stats(db=db, token="test-token")

    assert stats["redeemed"] == 1
    assert stats["by_plan"]["Deleted plan"]["redeemed"] == 1


@pytest.mark.skipif(not running_on_postgres(), reason="FK rules and pg_constraint are Postgres-only")
async def test_startup_migration_upgrades_live_schema_and_is_idempotent(engine, monkeypatch):
    """Reproduce the production schema, then prove the startup migration fixes it."""
    import main

    monkeypatch.setattr(main, "async_engine", engine)

    async with engine.begin() as conn:
        for table, constraint in main.PLAN_DELETE_SET_NULL_FKS:
            await conn.execute(text(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}"))
            await conn.execute(text(
                f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
                "FOREIGN KEY (plan_id) REFERENCES plans(id)"
            ))
        await conn.execute(text("ALTER TABLE vouchers ALTER COLUMN plan_id SET NOT NULL"))

    await main.run_plan_delete_migrations()
    await main.run_plan_delete_migrations()

    async with engine.connect() as conn:
        rules = dict((await conn.execute(text("""
            SELECT conname, confdeltype::text FROM pg_constraint
            WHERE confrelid = 'plans'::regclass
        """))).all())
        nullable = (await conn.execute(text("""
            SELECT is_nullable FROM information_schema.columns
            WHERE table_name = 'vouchers' AND column_name = 'plan_id'
        """))).scalar()

    for _, constraint in main.PLAN_DELETE_SET_NULL_FKS:
        assert rules[constraint] == "n", constraint
    assert nullable == "YES"

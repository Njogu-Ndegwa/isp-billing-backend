"""Adversarial soft-delete tests: the surprises Dennis doesn't want on prod.

Each test targets a way the new tombstone semantics or partial unique indexes
could bite in a running server: money math, payment-callback races, restore
conflicts, double deletes, catch-all query leaks, purge under FK pinning, and
true concurrent registration on Postgres.
"""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.db.database import soft_delete
from app.db.models import (
    Customer, CustomerPayment, CustomerStatus, MpesaTransaction,
    MpesaTransactionStatus, PaymentMethod, PaymentStatus, ProvisioningLog,
    ResellerFinancials, Voucher, VoucherStatus, VoucherType,
)
from app.services.soft_deletion import soft_delete_customer_children
from tests.conftest import running_on_postgres
from tests.factories import make_customer, make_plan, make_reseller
from app.api import customer_routes

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def _radius_scratch_tables(db):
    """The delete flows hard-delete radius rows via raw SQL; give them the
    model-less tables (same trick as test_admin_reseller_deletion — conftest
    drops non-model tables between tests)."""
    from sqlalchemy import text
    for ddl in (
        "CREATE TABLE IF NOT EXISTS radius_check (id INTEGER PRIMARY KEY, customer_id INTEGER)",
        "CREATE TABLE IF NOT EXISTS radius_reply (id INTEGER PRIMARY KEY, customer_id INTEGER)",
        "CREATE TABLE IF NOT EXISTS radius_nas (id INTEGER PRIMARY KEY, router_id INTEGER)",
    ):
        await db.execute(text(ddl))
    await db.commit()


def _wire_auth(monkeypatch, user):
    async def _fake(_token, _db):
        return user
    monkeypatch.setattr(customer_routes, "get_current_user", _fake)
    monkeypatch.setattr(customer_routes, "enforce_active_subscription", lambda u: None)


async def _add_payment(db, reseller, cust, amount=500):
    p = CustomerPayment(
        customer_id=cust.id, reseller_id=reseller.id, amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=30,
        status=PaymentStatus.COMPLETED, counts_as_revenue=True,
    )
    db.add(p)
    await db.commit()
    return p


async def test_revenue_survives_customer_deletion(db, monkeypatch):
    """THE money invariant: deleting a customer must not change the reseller's
    revenue, and the ledger row keeps its FK + gets the name snapshotted."""
    from app.services.reseller_payments import update_reseller_financials

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    keep = await make_customer(db, reseller, plan, name="Keeper")
    gone = await make_customer(db, reseller, plan, name="Goner")
    await _add_payment(db, reseller, keep, 300)
    payment = await _add_payment(db, reseller, gone, 700)
    payment_id = payment.id

    await update_reseller_financials(db, reseller.id)
    await db.commit()
    before = (await db.execute(
        select(ResellerFinancials).where(ResellerFinancials.user_id == reseller.id)
    )).scalar_one()
    assert before.total_revenue == 1000
    assert before.total_customers == 2

    _wire_auth(monkeypatch, reseller)
    result = await customer_routes.delete_customer(gone.id, db, "token")
    assert result["success"] is True

    db.expunge_all()
    after = (await db.execute(
        select(ResellerFinancials).where(ResellerFinancials.user_id == reseller.id)
    )).scalar_one()
    assert after.total_revenue == 1000, "revenue must not move on customer delete"
    assert after.total_customers == 1

    ledger = await db.get(CustomerPayment, payment_id)
    assert ledger is not None and ledger.deleted_at is None
    assert ledger.customer_id == gone.id, "FK kept until purge (no IS NULL leak)"
    assert ledger.customer_name == "Goner"


async def test_double_delete_returns_404_not_500(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    _wire_auth(monkeypatch, reseller)

    await customer_routes.delete_customer(cust.id, db, "token")
    db.expunge_all()
    with pytest.raises(HTTPException) as exc:
        await customer_routes.delete_customer(cust.id, db, "token")
    assert exc.value.status_code == 404


async def test_mpesa_reconcile_never_completes_tombstoned_txn(db):
    """Race: sweep reads a pending txn, the customer/reseller gets deleted
    (cascade tombstones the txn), THEN the claim runs. It must not complete
    the tombstoned row and must never reach provisioning."""
    from app.services.mpesa_transactions import _handle_successful_reconciliation

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    txn = MpesaTransaction(
        checkout_request_id="ws_CO_test_tombstone_1",
        phone_number="254700000001", amount=100, reference="test-ref-1",
        status=MpesaTransactionStatus.pending,
        customer_id=cust.id,
    )
    db.add(txn)
    await db.commit()

    soft_delete(txn)  # what the cascade does between read and claim
    await db.commit()

    calls = []
    def _tracker(name):
        async def _f(*a, **k):
            calls.append(name)
        return _f

    await _handle_successful_reconciliation(
        txn, "Processed OK",
        record_customer_payment=_tracker("record_payment"),
        build_hotspot_payload=_tracker("build_hotspot"),
        get_or_create_provisioning_attempt=_tracker("attempt"),
        log_provisioning_event=_tracker("log"),
        provision_hotspot_customer=_tracker("provision"),
        schedule_provisioning_attempt=_tracker("schedule"),
        call_pppoe_provision=_tracker("pppoe"),
        build_pppoe_payload=_tracker("pppoe_payload"),
    )

    assert calls == [], "tombstoned txn must not trigger payment/provisioning"
    db.expunge_all()
    row = (await db.execute(
        select(MpesaTransaction)
        .where(MpesaTransaction.checkout_request_id == "ws_CO_test_tombstone_1")
        .execution_options(include_deleted=True)
    )).scalar_one()
    assert row.status == MpesaTransactionStatus.pending, "status must not flip"


async def test_restore_conflict_is_atomic(db, monkeypatch):
    """Delete a customer, re-register the same MAC, then try to restore the
    old one: 409, and NOTHING from the old group comes back (no partial
    restore of children while the parent stays tombstoned)."""
    from app.api import admin_reseller_routes as arr
    from app.db.models import UserRole
    from tests.factories import make_reseller as _mk

    admin = await _mk(db, role=UserRole.ADMIN)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    old = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:0F:00:01")
    old_id = old.id
    _wire_auth(monkeypatch, reseller)
    await customer_routes.delete_customer(old_id, db, "token")

    # Same phone re-registers with the same MAC — allowed by the partial index.
    replacement = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:0F:00:01")

    async def _fake_admin(token, _db):
        return admin
    monkeypatch.setattr(arr, "_require_admin", _fake_admin)

    with pytest.raises(HTTPException) as exc:
        await arr.restore_soft_deleted("customer", old_id, True, db, "token")
    assert exc.value.status_code == 409

    db.expunge_all()
    still_gone = await db.get(Customer, old_id)
    assert still_gone is None, "conflicting restore must not resurrect the row"
    both = (await db.execute(
        select(func.count()).select_from(Customer)
        .where(Customer.mac_address == "AA:BB:CC:0F:00:01")
    )).scalar()
    assert both == 1, "exactly the replacement remains live"


async def test_is_null_catchall_cannot_leak_deleted_customer_history(db, monkeypatch):
    """The old cross-tenant leak: transaction lists use `customer_id IS NULL`
    as a catch-all visible to everyone. A deleted customer's rows must never
    match it (payments keep the FK; raw event logs are tombstoned)."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    cust = await make_customer(db, reseller, plan)
    await _add_payment(db, reseller, cust)
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_leak_check_1", phone_number="254700000002",
        amount=100, reference="test-ref-2",
        status=MpesaTransactionStatus.completed,
        customer_id=cust.id,
    ))
    await db.commit()

    _wire_auth(monkeypatch, reseller)
    await customer_routes.delete_customer(cust.id, db, "token")
    db.expunge_all()

    orphan_payments = (await db.execute(
        select(func.count()).select_from(CustomerPayment)
        .where(CustomerPayment.customer_id.is_(None))
    )).scalar()
    orphan_txns = (await db.execute(
        select(func.count()).select_from(MpesaTransaction)
        .where(MpesaTransaction.customer_id.is_(None))
    )).scalar()
    assert orphan_payments == 0
    assert orphan_txns == 0


async def test_voucher_of_deleted_reseller_is_unredeemable(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    v = Voucher(code="99990001", plan_id=plan.id, user_id=reseller.id,
                status=VoucherStatus.AVAILABLE, voucher_type=VoucherType.SALE)
    db.add(v)
    await db.commit()
    soft_delete(v)
    await db.commit()
    db.expunge_all()

    found = (await db.execute(
        select(Voucher).where(Voucher.code == "99990001")
    )).scalar_one_or_none()
    assert found is None, "portal code lookup must miss tombstoned vouchers"


async def test_purge_after_rereg_removes_old_group_only(db, monkeypatch):
    """Delete + re-register the same MAC, age the old group past retention,
    purge: old group gone for good, replacement untouched."""
    from app.services.soft_delete_purge import purge_expired_tombstones

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    old = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:0F:00:02")
    old_id = old.id
    _wire_auth(monkeypatch, reseller)
    await customer_routes.delete_customer(old_id, db, "token")

    replacement = await make_customer(db, reseller, plan, mac_address="AA:BB:CC:0F:00:02")
    replacement_id = replacement.id

    # Age the whole old group (shared timestamp -> one UPDATE per table).
    aged = datetime.utcnow() - timedelta(days=120)
    from sqlalchemy import update as sa_update
    from app.db.database import Base
    for table in Base.metadata.tables.values():
        if "deleted_at" in table.c:
            await db.execute(
                sa_update(table)
                .where(table.c.deleted_at.isnot(None))
                .values(deleted_at=aged)
            )
    await db.commit()

    purged = await purge_expired_tombstones(retention_days=90)
    assert purged.get("customers") == 1

    db.expunge_all()
    assert await db.get(
        Customer, old_id,
        execution_options={"include_deleted": True},
    ) is None, "old row must be physically gone"
    fresh = await db.get(Customer, replacement_id)
    assert fresh is not None and fresh.deleted_at is None


@pytest.mark.skipif(not running_on_postgres(), reason="SQLite does not enforce FKs in this harness")
async def test_purge_survives_pinned_row_and_purges_the_rest(db):
    """One tombstoned-and-expired customer is still referenced by a LIVE
    child (crafted without the cascade). The purge must skip it, purge the
    clean one, and not raise."""
    from app.services.soft_delete_purge import purge_expired_tombstones

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    clean = await make_customer(db, reseller, plan, name="clean")
    pinned = await make_customer(db, reseller, plan, name="pinned")
    db.add(ProvisioningLog(customer_id=pinned.id, action="provision", status="ok"))
    await db.commit()

    aged = datetime.utcnow() - timedelta(days=120)
    clean_id, pinned_id = clean.id, pinned.id
    await soft_delete_customer_children(db, clean_id, when=aged)
    soft_delete(clean, when=aged)
    soft_delete(pinned, when=aged)  # deliberately NO child cascade
    await db.commit()

    purged = await purge_expired_tombstones(retention_days=90)
    assert purged.get("customers", 0) >= 1

    db.expunge_all()
    assert await db.get(
        Customer, clean_id, execution_options={"include_deleted": True}
    ) is None
    survivor = await db.get(
        Customer, pinned_id, execution_options={"include_deleted": True}
    )
    assert survivor is not None, "pinned row skipped, not crashed on"


@pytest.mark.skipif(not running_on_postgres(), reason="needs real concurrent transactions")
async def test_concurrent_same_mac_registration_exactly_one_wins(session_factory, db):
    """Two requests race to register the same MAC for the same reseller.
    The partial unique index must let exactly one commit."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)

    async def _register(delay):
        await asyncio.sleep(delay)
        async with session_factory() as s:
            s.add(Customer(
                name=f"racer-{delay}", phone="254700000009",
                mac_address="AA:BB:CC:0F:00:03", status=CustomerStatus.PENDING,
                plan_id=plan.id, user_id=reseller.id,
            ))
            await s.commit()
            return "ok"

    results = await asyncio.wait_for(
        asyncio.gather(_register(0), _register(0.05), return_exceptions=True),
        timeout=30,
    )
    oks = [r for r in results if r == "ok"]
    errs = [r for r in results if isinstance(r, Exception)]
    assert len(oks) == 1 and len(errs) == 1, results

    count = (await db.execute(
        select(func.count()).select_from(Customer)
        .where(Customer.mac_address == "AA:BB:CC:0F:00:03")
    )).scalar()
    assert count == 1

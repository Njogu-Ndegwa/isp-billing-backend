"""Fapshi recovery contracts, with real HTTP and real database boundaries.

Only the provider status URL is replaced with a loopback stand-in. No production
AppModule, provider credentials, RouterOS, or background scheduler is started.
"""
from __future__ import annotations
import asyncio
import json
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import event, func, select, update
from app.db import database
from app.db.models import (Customer, CustomerPayment, CustomerStatus, DurationUnit,
    FapshiTransaction, FapshiTransactionStatus, ProvisioningAttempt,
    ResellerPaymentMethod, ResellerPaymentMethodType)
from app.services import fapshi, fapshi_reconciliation as service
from app.services.payment_gateway import _initiate_fapshi, encrypt_credential
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.conftest import running_on_postgres

pytestmark = pytest.mark.asyncio

async def purchase(db, *, duration=2, unit=DurationUnit.HOURS, **customer_fields):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=500, duration_value=duration, duration_unit=unit)
    customer = await make_customer(db, owner, plan, router, phone="670000001", **customer_fields)
    pm = ResellerPaymentMethod(user_id=owner.id, method_type=ResellerPaymentMethodType.FAPSHI,
        label="test", is_active=True, fapshi_api_user="synthetic-user",
        fapshi_api_key_encrypted=encrypt_credential("synthetic-key"), fapshi_environment="sandbox")
    db.add(pm)
    await db.flush()
    txn = FapshiTransaction(trans_id="test-transaction", external_id="test-external",
        reseller_id=owner.id, customer_id=customer.id, payment_method_id=pm.id,
        amount=500, phone="670000001", environment="sandbox", status=FapshiTransactionStatus.PENDING,
        purchase_snapshot=await service.capture_purchase_snapshot(db, customer, amount=500))
    db.add(txn)
    await db.commit()
    return txn, customer, plan, pm

def remote(txn, status="SUCCESSFUL", **overrides):
    return dict(transId=txn.trans_id, externalId=txn.external_id, amount=500,
        userId=f"customer-{txn.customer_id}", transType="Collection", status=status,
        financialTransId="synthetic-financial", **overrides)

async def due(db, txn):
    await db.execute(update(FapshiTransaction).where(FapshiTransaction.id == txn.id).values(
        next_check_at=datetime.utcnow()-timedelta(seconds=1)))
    await db.commit()

async def assert_no_credit(db, txn):
    await db.refresh(txn)
    assert txn.status == FapshiTransactionStatus.PENDING
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0
    await db.commit()

@pytest.fixture
def delivery(monkeypatch):
    from app.services import hotspot_provisioning
    mocked = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", mocked)
    return mocked

@pytest.fixture
def http_provider(monkeypatch, engine):
    # All real HTTP requests are loopback. Count checked-out DB connections at
    # the instant the provider receives a request, rather than mock the client.
    state = {"responses": [], "requests": [], "checked_out": 0}
    def checkout(*args): state["checked_out"] += 1
    def checkin(*args): state["checked_out"] -= 1
    event.listen(engine.sync_engine, "checkout", checkout)
    event.listen(engine.sync_engine, "checkin", checkin)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append((self.path, state["checked_out"]))
            code, body = state["responses"].pop(0)
            encoded = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setitem(fapshi.FAPSHI_BASE_URLS, "sandbox", f"http://127.0.0.1:{server.server_port}")
    yield state
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    event.remove(engine.sync_engine, "checkout", checkout)
    event.remove(engine.sync_engine, "checkin", checkin)

@pytest.mark.parametrize("unit,value,seconds", [(DurationUnit.MINUTES, 17, 1020), (DurationUnit.HOURS, 2, 7200)])
async def test_browser_closed_job_uses_real_http_and_atomic_ledger(db, http_provider, delivery, unit, value, seconds):
    txn, customer, plan, pm = await purchase(db, duration=value, unit=unit)
    http_provider["responses"] = [(200, remote(txn, "PENDING")), (200, remote(txn))]
    await service.recheck_pending_fapshi_background()
    await assert_no_credit(db, txn)
    await due(db, txn)
    before = datetime.utcnow()
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn); await db.refresh(customer)
    assert txn.status == FapshiTransactionStatus.SUCCESSFUL
    assert txn.provider_status == "SUCCESSFUL"
    assert txn.customer_payment_id and not txn.fulfillment_pending
    assert before+timedelta(seconds=seconds-1) <= customer.expiry <= datetime.utcnow()+timedelta(seconds=seconds+1)
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1
    assert await db.scalar(select(func.count(ProvisioningAttempt.id))) == 1
    assert delivery.await_count == 1
    assert http_provider["requests"] == [("/payment-status/test-transaction", 0)] * 2
    await db.commit()
    await service.recheck_pending_fapshi_background()
    assert len(http_provider["requests"]) == 2

@pytest.mark.parametrize("code", [429, 500])
async def test_http_error_is_durable_no_credit_and_later_retry(db, http_provider, delivery, code):
    txn, customer, plan, pm = await purchase(db)
    http_provider["responses"] = [(code, {"message": "synthetic retry"}), (200, remote(txn))]
    await service.recheck_pending_fapshi_background()
    await assert_no_credit(db, txn)
    assert txn.last_check_error == "provider_or_reconciliation_error"
    assert txn.next_check_at > datetime.utcnow()
    assert not txn.check_lease_token
    await due(db, txn)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.customer_payment_id
    assert delivery.await_count == 1

@pytest.mark.parametrize("change", ["legacy", "voucher", "plan", "owner", "router", "mac"])
async def test_changed_or_legacy_purchase_is_held_without_credit(db, change):
    txn, customer, plan, pm = await purchase(db)
    if change == "legacy": txn.purchase_snapshot = None
    elif change == "voucher": customer.expiry = datetime.utcnow()+timedelta(days=3); customer.status=CustomerStatus.ACTIVE
    elif change == "plan": plan.speed = "20M/20M"
    elif change == "owner": customer.user_id = (await make_reseller(db)).id
    elif change == "router": customer.router_id = (await make_router(db, await make_reseller(db))).id
    elif change == "mac": customer.mac_address = "12:34:56:78:90:AB"
    await db.commit()
    await service.apply_remote_status(db, txn.id, remote(txn))
    await assert_no_credit(db, txn)
    assert txn.provider_status == "SUCCESSFUL" and txn.review_reason
    if change == "voucher":
        await db.refresh(customer)
        assert customer.status == CustomerStatus.ACTIVE

@pytest.mark.parametrize("field,value", [("transId", "wrong"), ("externalId", "wrong"),
    ("amount", 501), ("amount", "NaN"), ("userId", "customer-other"), ("transType", "Disbursement")])
async def test_provider_contract_mismatch_cannot_credit(db, field, value):
    txn, customer, plan, pm = await purchase(db)
    payload = remote(txn); payload[field] = value
    with pytest.raises(ValueError): await service.apply_remote_status(db, txn.id, payload)
    await db.rollback()
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0

@pytest.mark.parametrize("status", ["FAILED", "EXPIRED"])
async def test_failed_old_attempt_preserves_new_access(db, status):
    txn, customer, plan, pm = await purchase(db)
    expiry = datetime.utcnow()+timedelta(days=4)
    customer.expiry=expiry; customer.status=CustomerStatus.ACTIVE
    await db.commit()
    await service.apply_remote_status(db, txn.id, remote(txn, status))
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE and customer.expiry == expiry
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0

async def test_atomic_failure_rolls_back_ledger_expiry_attempt_and_success(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    old_expiry = customer.expiry
    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "schedule_provisioning_attempt", AsyncMock(side_effect=RuntimeError("injected after ledger")))
    with pytest.raises(RuntimeError): await service.apply_remote_status(db, txn.id, remote(txn))
    await db.rollback()
    await db.refresh(txn); await db.refresh(customer)
    assert txn.status == FapshiTransactionStatus.PENDING
    assert customer.expiry == old_expiry
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0
    assert await db.scalar(select(func.count(ProvisioningAttempt.id))) == 0

@pytest.mark.parametrize("change", ["mac", "router", "owner", "speed", "voucher"])
async def test_delivery_revalidates_after_atomic_credit(db, delivery, change):
    txn, customer, plan, pm = await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    if change == "mac": customer.mac_address = "12:34:56:78:90:AB"
    elif change == "router": customer.router_id = (await make_router(db, await make_reseller(db))).id
    elif change == "owner": customer.user_id = (await make_reseller(db)).id
    elif change == "speed": plan.speed = "99M/99M"
    else: customer.expiry = customer.expiry+timedelta(days=4)
    await db.commit()
    await service.deliver_confirmed_payment(txn.id)
    await db.refresh(txn)
    assert txn.review_reason == "entitlement_changed_before_delivery"
    assert txn.fulfillment_pending
    delivery.assert_not_awaited()

async def test_missing_credentials_persists_retry_without_provider_call(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    pm.fapshi_api_key_encrypted = None
    await db.commit()
    provider = AsyncMock()
    monkeypatch.setattr(fapshi, "get_payment_status", provider)
    await service.recheck_pending_fapshi_background()
    await assert_no_credit(db, txn)
    assert txn.last_check_error == "credentials_unavailable"
    provider.assert_not_awaited()

async def test_stale_lease_recovers_and_active_lease_rate_limits(db, delivery, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    provider = AsyncMock(return_value=remote(txn))
    monkeypatch.setattr(fapshi, "get_payment_status", provider)
    txn.check_lease_token="crashed-worker"; txn.check_lease_until=datetime.utcnow()+timedelta(minutes=1)
    await db.commit()
    await service.recheck_pending_fapshi_background()
    provider.assert_not_awaited()
    txn.check_lease_until=datetime.utcnow()-timedelta(seconds=1)
    await db.commit()
    await service.recheck_pending_fapshi_background()
    assert provider.await_count == 1
    await db.refresh(txn)
    assert txn.customer_payment_id and not txn.check_lease_token

async def test_pending_backoff_and_exhaustion_are_observable_not_failed(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    monkeypatch.setattr(fapshi, "get_payment_status", AsyncMock(return_value=remote(txn, "PENDING")))
    txn.check_attempts=20
    await db.commit()
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.next_check_at >= datetime.utcnow()+timedelta(minutes=14)
    assert txn.review_reason is None
    txn.created_at = datetime.utcnow()-timedelta(days=8)
    await due(db, txn)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.review_reason == "reconciliation_window_exhausted"
    assert txn.status == FapshiTransactionStatus.PENDING

async def test_uncertain_initiation_survives_timeout_and_blocks_second_prompt(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await db.delete(txn); await db.commit()
    prompt = AsyncMock(side_effect=httpx.ReadTimeout("synthetic timeout"))
    monkeypatch.setattr(fapshi, "initiate_direct_payment", prompt)
    with pytest.raises(httpx.ReadTimeout):
        await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    held = await db.scalar(select(FapshiTransaction))
    assert held.purchase_snapshot and held.external_id
    assert held.review_reason == "initiation_outcome_unknown" and not held.trans_id
    held.created_at=datetime.utcnow()-timedelta(days=1)
    await db.commit()
    with pytest.raises(ValueError, match="do not pay again"):
        await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert prompt.await_count == 1

async def test_changed_purchase_does_not_reuse_or_send_new_prompt(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    plan.price=700
    await db.commit()
    prompt=AsyncMock()
    monkeypatch.setattr(fapshi, "initiate_direct_payment", prompt)
    with pytest.raises(ValueError, match="different purchase"):
        await _initiate_fapshi(db, pm, customer, customer.phone, 700, "test")
    prompt.assert_not_awaited()

async def test_stale_fulfillment_flags_do_not_block_later_voucher(db):
    txn, customer, plan, pm = await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    customer.expiry=customer.expiry+timedelta(days=5)
    await db.commit()
    from app.api.fapshi_routes import customer_payment_flags
    flags=await customer_payment_flags(db, customer.id)
    assert flags["payment_status"] == "successful"
    assert flags["payment_fulfillment_status"] is None

@pytest.mark.skipif(not running_on_postgres(), reason="real row locks require Postgres")
async def test_postgres_concurrent_authoritative_success_is_exactly_once(db):
    txn, customer, plan, pm = await purchase(db)
    payload=remote(txn)
    async def apply():
        async with database.async_session() as session:
            await service.apply_remote_status(session, txn.id, payload)
    await asyncio.gather(apply(), apply(), apply())
    await db.refresh(txn)
    assert txn.customer_payment_id
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1
    assert await db.scalar(select(func.count(ProvisioningAttempt.id))) == 1

@pytest.mark.skipif(not running_on_postgres(), reason="cross-session lease requires Postgres")
async def test_postgres_portal_webhook_job_share_one_provider_lease(db, monkeypatch, delivery):
    txn, customer, plan, pm=await purchase(db)
    async def provider(**kwargs):
        await asyncio.sleep(.1)
        return remote(txn)
    mock=AsyncMock(side_effect=provider)
    monkeypatch.setattr(fapshi, "get_payment_status", mock)
    from app.api.fapshi_routes import kick_pending_fapshi_check
    await asyncio.gather(service.reconcile_transaction(txn.id), kick_pending_fapshi_check(customer.id),
                         service.recheck_pending_fapshi_background())
    assert mock.await_count == 1
    assert delivery.await_count == 1
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1


async def test_router_retry_is_durable_and_does_not_query_provider_again(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    provider=AsyncMock(return_value=remote(txn))
    monkeypatch.setattr(fapshi, "get_payment_status", provider)
    from app.services import hotspot_provisioning
    deliver=AsyncMock(side_effect=[{"success": False}, {"success": True}])
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", deliver)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.status == FapshiTransactionStatus.SUCCESSFUL and txn.fulfillment_pending
    assert txn.last_check_error == "router_delivery_pending"
    await due(db, txn)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert not txn.fulfillment_pending and provider.await_count == 1 and deliver.await_count == 2
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1

async def test_fapshi_owns_attempt_retry_and_bypasses_checkin_deferral(db):
    txn, customer, plan, pm = await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    from app.services.checkin_delivery import CHECKIN_DEFERRABLE_ENTRYPOINTS
    attempt = await db.scalar(select(ProvisioningAttempt))
    assert attempt.entrypoint.value not in CHECKIN_DEFERRABLE_ENTRYPOINTS
    assert (await db.scalars(select(ProvisioningAttempt).where(service.non_fapshi_attempt_clause()))).all() == []

async def test_router_io_occurs_without_any_checked_out_session(db, engine, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    checked_out=[0]
    def checkout(*args): checked_out[0]+=1
    def checkin(*args): checked_out[0]-=1
    event.listen(engine.sync_engine, "checkout", checkout)
    event.listen(engine.sync_engine, "checkin", checkin)
    async def deliver(**kwargs):
        assert checked_out[0] == 0
        return {"success": True}
    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", deliver)
    try:
        await service.deliver_confirmed_payment(txn.id)
    finally:
        event.remove(engine.sync_engine, "checkout", checkout)
        event.remove(engine.sync_engine, "checkin", checkin)

async def test_atomic_renewal_defers_fup_io_and_propagates_db_error(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    from app.services import fup, usage_tracking
    restore=AsyncMock()
    monkeypatch.setattr(fup, "revert", restore)
    monkeypatch.setattr(usage_tracking, "get_or_open_current_period", AsyncMock(side_effect=RuntimeError("usage write failure")))
    with pytest.raises(RuntimeError, match="usage write failure"):
        await service.apply_remote_status(db, txn.id, remote(txn))
    await db.rollback()
    restore.assert_not_awaited()
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 0

async def test_cosmetic_plan_edit_does_not_change_purchase_contract(db):
    txn, customer, plan, pm = await purchase(db)
    plan.badge_text = "New label"
    plan.is_hidden = True
    await db.commit()
    await service.apply_remote_status(db, txn.id, remote(txn))
    assert txn.customer_payment_id

async def test_static_credit_remains_explicit_review_never_false_delivered(db, monkeypatch):
    from app.db.models import ConnectionType
    txn, customer, plan, pm = await purchase(db)
    plan.connection_type=ConnectionType.STATIC_IP
    await db.flush()
    txn.purchase_snapshot=await service.capture_purchase_snapshot(db, customer, amount=500)
    await db.commit()
    await service.apply_remote_status(db, txn.id, remote(txn))
    from app.services import static_ip
    provision=AsyncMock()
    monkeypatch.setattr(static_ip, "provision_static_customer", provision)
    await service.deliver_confirmed_payment(txn.id)
    await db.refresh(txn)
    assert txn.fulfillment_pending and txn.review_reason == "static_delivery_requires_review"
    provision.assert_not_awaited()

@pytest.mark.skipif(not running_on_postgres(), reason="startup ALTER is PostgreSQL-specific")
async def test_postgres_startup_migrates_legacy_table_twice_without_backfill(db, engine, monkeypatch):
    from sqlalchemy import text
    txn, customer, plan, pm = await purchase(db)
    columns=["purchase_snapshot", "customer_payment_id", "provider_status", "review_reason",
        "next_check_at", "check_attempts", "check_lease_until", "check_lease_token",
        "last_check_error", "fulfillment_pending", "applied_expiry"]
    await db.commit()
    async with engine.begin() as conn:
        for column in columns:
            await conn.execute(text(f'ALTER TABLE fapshi_transactions DROP COLUMN {column} CASCADE'))
    import main
    monkeypatch.setattr(main, "async_engine", engine)
    await main.run_payment_method_migrations()
    await main.run_payment_method_migrations()
    async with engine.connect() as conn:
        row=(await conn.execute(text("SELECT purchase_snapshot, check_attempts, fulfillment_pending FROM fapshi_transactions WHERE id=:id"), {"id": txn.id})).one()
        assert row == (None, 0, False)
        indexes=(await conn.execute(text("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename='fapshi_transactions'"))).scalars().all()
        assert "uq_fapshi_customer_payment" in indexes and "ix_fapshi_confirmation_due" in indexes


async def test_fast_authoritative_callback_then_initiation_timeout_preserves_credit(db, monkeypatch):
    txn, customer, plan, pm = await purchase(db)
    await db.delete(txn); await db.commit()
    async def accepted_then_timeout(**kwargs):
        assert not db.in_transaction()
        async with database.async_session() as callback_db:
            provisional=await callback_db.scalar(select(FapshiTransaction).where(FapshiTransaction.external_id == kwargs["external_id"]))
            payload=remote(provisional)
            payload["transId"]="fast-callback-id"
            await service.apply_remote_status(callback_db, provisional.id, payload, provider_trans_id="fast-callback-id")
        raise httpx.ReadTimeout("response lost after accepted payment")
    monkeypatch.setattr(fapshi, "initiate_direct_payment", accepted_then_timeout)
    result=await _initiate_fapshi(db, pm, customer, customer.phone, 500, "test")
    assert result["trans_id"] == "fast-callback-id"
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    stored=await db.scalar(select(FapshiTransaction))
    assert stored.status == FapshiTransactionStatus.SUCCESSFUL and stored.review_reason is None
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1


async def test_target_change_during_router_io_never_claims_current_delivery(db, monkeypatch):
    txn, customer, plan, pm=await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    async def delivery_and_later_voucher(**kwargs):
        async with database.async_session() as other:
            current=await other.get(Customer, customer.id)
            current.expiry=current.expiry+timedelta(days=5)
            await other.commit()
        return {"success": True}
    from app.services import hotspot_provisioning
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", delivery_and_later_voucher)
    await service.deliver_confirmed_payment(txn.id)
    await db.refresh(txn)
    assert txn.fulfillment_pending and txn.review_reason == "entitlement_changed_during_delivery"
    assert await db.scalar(select(func.count(CustomerPayment.id))) == 1


async def test_delivery_retry_budget_holds_without_revoking_atomic_credit(db, delivery):
    txn, customer, plan, pm=await purchase(db)
    await service.apply_remote_status(db, txn.id, remote(txn))
    txn.check_attempts=service.MAX_ATTEMPTS
    await due(db, txn)
    await service.recheck_pending_fapshi_background()
    await db.refresh(txn)
    assert txn.status == FapshiTransactionStatus.SUCCESSFUL
    assert txn.customer_payment_id and txn.review_reason == "delivery_window_exhausted"
    delivery.assert_not_awaited()

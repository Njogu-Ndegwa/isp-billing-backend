"""On-demand STK Query driven by the portal's payment-status polling.

When a customer is stuck on the portal spinner because Safaricom's callback
got lost, the 3-second status poll itself should rescue them: if their newest
pending M-Pesa transaction is older than ~25s, the endpoint schedules a
background task that asks Safaricom directly and completes/fails the txn.

Guard rails under test: minimum txn age, per-txn rate limit, and a circuit
breaker that backs off Safaricom after an error.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.payment_routes import router as payment_router
from app.db.database import get_db
from app.db.models import CustomerStatus, MpesaTransaction, MpesaTransactionStatus
from app.services import mpesa_transactions as mt
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_ondemand_state():
    """Module-level rate-limit/breaker state must not leak between tests."""
    mt._ondemand_last_query.clear()
    mt._ondemand_cooldown_until = 0.0
    yield
    mt._ondemand_last_query.clear()
    mt._ondemand_cooldown_until = 0.0


@pytest_asyncio.fixture
async def app(session_factory):
    app = FastAPI()
    app.include_router(payment_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _get_db
    return app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _seed_customer(db, *, status=CustomerStatus.PENDING, mac="AA:BB:CC:DD:EE:01"):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, status=status, mac_address=mac)
    return customer


async def _seed_pending_txn(db, customer, *, age_seconds: int, checkout_id: str):
    created = datetime.utcnow() - timedelta(seconds=age_seconds)
    txn = MpesaTransaction(
        checkout_request_id=checkout_id,
        phone_number=customer.phone,
        amount=10.0,
        reference=f"HOTSPOT-{customer.id}",
        customer_id=customer.id,
        status=MpesaTransactionStatus.pending,
        created_at=created,
        updated_at=created,
    )
    db.add(txn)
    await db.commit()
    await db.refresh(txn)
    return txn


def _patch_query(result=None, side_effect=None):
    if side_effect is not None:
        mock = AsyncMock(side_effect=side_effect)
    else:
        mock = AsyncMock(return_value=result)
    return mock, patch("app.services.mpesa.query_stk_push_status", new=mock)


def _patch_provisioning():
    """Stub the network-touching provisioning calls (same as test_reconcile_4999)."""
    return (
        patch(
            "app.services.hotspot_provisioning.provision_hotspot_customer",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "app.services.hotspot_provisioning.schedule_provisioning_attempt",
            new=AsyncMock(return_value=None),
        ),
    )


async def test_old_pending_txn_triggers_query_and_completes(engine, db, session_factory):
    customer = await _seed_customer(db)
    txn = await _seed_pending_txn(db, customer, age_seconds=40, checkout_id="ws_CO_OND_OLD")
    txn_id = txn.id

    query, query_patch = _patch_query({"result_code": 0, "result_desc": "ok"})
    prov_patch, sched_patch = _patch_provisioning()
    with query_patch, prov_patch, sched_patch:
        await mt.kick_pending_payment_check(customer.id)

    assert query.await_count == 1
    query.assert_awaited_once_with("ws_CO_OND_OLD")

    # Fresh session: committed DB state, not a stale identity map
    async with session_factory() as s:
        refreshed = (await s.execute(
            select(MpesaTransaction).where(MpesaTransaction.id == txn_id)
        )).scalar_one()
    assert refreshed.status == MpesaTransactionStatus.completed


async def test_no_pending_txn_is_noop(engine, db):
    """Customer with no pending transaction: the helper must return without
    querying Safaricom."""
    customer = await _seed_customer(db)

    query, query_patch = _patch_query({"result_code": 0, "result_desc": "ok"})
    with query_patch:
        await mt.kick_pending_payment_check(customer.id)

    assert query.await_count == 0


async def test_young_txn_is_left_alone(engine, db):
    """A 5-second-old txn is still inside the normal callback window —
    Safaricom must not be queried."""
    customer = await _seed_customer(db)
    await _seed_pending_txn(db, customer, age_seconds=5, checkout_id="ws_CO_OND_YOUNG")

    query, query_patch = _patch_query({"result_code": 0, "result_desc": "ok"})
    with query_patch:
        await mt.kick_pending_payment_check(customer.id)

    assert query.await_count == 0


async def test_rate_limit_one_query_per_txn_per_window(engine, db):
    """Two back-to-back polls for the same pending txn must produce exactly
    one Safaricom query (the portal polls every 3s; the limit is one per 20s)."""
    customer = await _seed_customer(db)
    await _seed_pending_txn(db, customer, age_seconds=40, checkout_id="ws_CO_OND_RATE")

    query, query_patch = _patch_query(
        {"result_code": 4999, "result_desc": "The transaction is still under processing"}
    )
    with query_patch:
        await mt.kick_pending_payment_check(customer.id)
        await mt.kick_pending_payment_check(customer.id)

    assert query.await_count == 1


async def test_query_error_opens_breaker(engine, db):
    """A Safaricom failure for one customer must open the circuit breaker so
    the very next customer's check does not pile onto a failing API."""
    customer1 = await _seed_customer(db, mac="AA:BB:CC:DD:EE:11")
    customer2 = await _seed_customer(db, mac="AA:BB:CC:DD:EE:22")
    await _seed_pending_txn(db, customer1, age_seconds=40, checkout_id="ws_CO_OND_ERR_1")
    await _seed_pending_txn(db, customer2, age_seconds=40, checkout_id="ws_CO_OND_ERR_2")

    query, query_patch = _patch_query(side_effect=RuntimeError("safaricom down"))
    with query_patch:
        await mt.kick_pending_payment_check(customer1.id)  # fails -> opens breaker
        await mt.kick_pending_payment_check(customer2.id)  # breaker open -> skipped

    assert query.await_count == 1


async def test_4999_leaves_txn_pending(engine, db, session_factory):
    """4999 = still processing at Safaricom: not final, must stay pending."""
    customer = await _seed_customer(db)
    txn = await _seed_pending_txn(db, customer, age_seconds=40, checkout_id="ws_CO_OND_4999")
    txn_id = txn.id

    query, query_patch = _patch_query(
        {"result_code": 4999, "result_desc": "The transaction is still under processing"}
    )
    with query_patch:
        await mt.kick_pending_payment_check(customer.id)

    assert query.await_count == 1
    async with session_factory() as s:
        refreshed = (await s.execute(
            select(MpesaTransaction).where(MpesaTransaction.id == txn_id)
        )).scalar_one()
    assert refreshed.status == MpesaTransactionStatus.pending


async def test_status_poll_schedules_check_for_pending_customer(engine, db, client):
    """End to end: GET payment-status for a PENDING customer with an old
    pending txn must run the on-demand check (ASGITransport executes the
    background task before the client call returns)."""
    customer = await _seed_customer(db, status=CustomerStatus.PENDING)
    await _seed_pending_txn(db, customer, age_seconds=40, checkout_id="ws_CO_OND_POLL")

    query, query_patch = _patch_query(
        {"result_code": 4999, "result_desc": "The transaction is still under processing"}
    )
    with query_patch:
        resp = await client.get(f"/api/hotspot/payment-status/{customer.id}")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["customer_id"] == customer.id
    assert body["status"] == "pending"
    assert query.await_count == 1


async def test_status_poll_for_active_customer_makes_no_query(engine, db, client):
    """Happy-path guarantee: an already-ACTIVE customer's poll must never
    touch Safaricom."""
    customer = await _seed_customer(db, status=CustomerStatus.ACTIVE)
    await _seed_pending_txn(db, customer, age_seconds=40, checkout_id="ws_CO_OND_ACTIVE")

    query, query_patch = _patch_query({"result_code": 0, "result_desc": "ok"})
    with query_patch:
        resp = await client.get(f"/api/hotspot/payment-status/{customer.id}")

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "active"
    assert query.await_count == 0

"""
Regression tests for the M-Pesa STK callback → hotspot provisioning chain.

Exercises POST /api/mpesa/callback end-to-end with:
  - An isolated SQLite test DB (via overridden get_db dependency)
  - MikroTik provisioning patched out and recorded
  - PPPoE provisioning patched out and recorded
  - APScheduler / other startup machinery never loaded (we mount only the
    payment_router on a minimal FastAPI app)

These tests are the safety net: any change that would silently stop a paying
customer from being auto-provisioned will fail one of them.
"""

from datetime import datetime, timedelta
from typing import List, Tuple
from unittest.mock import patch, AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.payment_routes import router as payment_router
from app.db.database import get_db
from app.db.models import (
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    MpesaTransaction,
    MpesaTransactionStatus,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# App + fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app(session_factory):
    """Minimal FastAPI app with only the payment router mounted."""
    app = FastAPI()
    app.include_router(payment_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    return app


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def provision_calls() -> List[Tuple]:
    """List of (label, args, kwargs) every patched provision call appends to."""
    return []


@pytest_asyncio.fixture
async def patched_provisioning(provision_calls):
    """Patch BOTH provision entrypoints used by the callback.

    The callback hands provisioning to BackgroundTasks, which on
    httpx.AsyncClient + ASGITransport executes AFTER the response. Patching at
    the import site (`app.api.payment_routes.<name>`) is what intercepts it.
    """
    async def _record_hotspot(*args, **kwargs):
        provision_calls.append(("hotspot", args, kwargs))

    async def _record_pppoe(*args, **kwargs):
        provision_calls.append(("pppoe", args, kwargs))

    with patch(
        "app.api.payment_routes.provision_hotspot_customer",
        new=AsyncMock(side_effect=_record_hotspot),
    ), patch(
        "app.api.payment_routes.call_pppoe_provision",
        new=AsyncMock(side_effect=_record_pppoe),
    ):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stk_callback_payload(
    checkout_request_id: str,
    *,
    result_code: int = 0,
    amount: float = 500.0,
    phone: str = "254712345678",
    receipt: str = "RJ7T8K9MNP",
) -> dict:
    items = []
    if result_code == 0:
        items = [
            {"Name": "Amount", "Value": amount},
            {"Name": "MpesaReceiptNumber", "Value": receipt},
            {"Name": "PhoneNumber", "Value": phone},
        ]
    return {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "merch-1",
                "CheckoutRequestID": checkout_request_id,
                "ResultCode": result_code,
                "ResultDesc": "The service request is processed successfully." if result_code == 0 else "Cancelled by user",
                **({"CallbackMetadata": {"Item": items}} if items else {}),
            }
        }
    }


async def _seed_pending_hotspot_payment(session_factory):
    """Set up a pending hotspot payment ready for callback. Returns (customer_id, checkout_id)."""
    async with session_factory() as s:
        reseller = await make_reseller(s)
        plan = await make_plan(s, reseller, duration_value=30, duration_unit=DurationUnit.DAYS, price=500)
        router = await make_router(s, reseller)
        customer = await make_customer(
            s, reseller, plan, router,
            status=CustomerStatus.PENDING,
            expiry=None,
            mac_address="AA:BB:CC:DD:EE:01",
        )
        checkout_id = "ws_CO_TEST_001"
        txn = MpesaTransaction(
            checkout_request_id=checkout_id,
            phone_number=customer.phone,
            amount=500.0,
            reference=f"customer-{customer.id}",
            customer_id=customer.id,
            status=MpesaTransactionStatus.pending,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        s.add(txn)
        await s.commit()
        return customer.id, checkout_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_successful_callback_completes_txn_and_provisions(
    session_factory, client, patched_provisioning, provision_calls
):
    customer_id, checkout_id = await _seed_pending_hotspot_payment(session_factory)
    payload = _stk_callback_payload(checkout_id, amount=500.0)

    resp = await client.post("/api/mpesa/callback", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ResultCode"] == 0

    # Read with a FRESH session so we see the route's commits, not stale cached
    # objects from any setup session.
    async with session_factory() as s:
        refreshed_txn = (
            await s.execute(
                select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_id)
            )
        ).scalar_one()
        assert refreshed_txn.status == MpesaTransactionStatus.completed
        assert refreshed_txn.mpesa_receipt_number == "RJ7T8K9MNP"
        assert refreshed_txn.result_code == "0"

        refreshed_customer = (
            await s.execute(select(Customer).where(Customer.id == customer_id))
        ).scalar_one()
        assert refreshed_customer.status == CustomerStatus.ACTIVE
        assert refreshed_customer.expiry is not None
        assert refreshed_customer.expiry > datetime.utcnow() + timedelta(days=29, hours=23)

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))
        ).scalars().all()
        assert len(payments) == 1
        assert payments[0].payment_reference == "RJ7T8K9MNP"
        assert payments[0].amount == 500.0

    # Hotspot provisioning was scheduled and ran via the background task
    hotspot_calls = [c for c in provision_calls if c[0] == "hotspot"]
    assert len(hotspot_calls) == 1, f"Expected one hotspot provision; got {provision_calls!r}"
    args = hotspot_calls[0][1]
    # provision_hotspot_customer(customer_id, router_id, payload, action, attempt_id)
    assert args[0] == customer_id
    assert args[3] == "hotspot_payment"
    payload_arg = args[2]
    assert payload_arg["mac_address"] == "AA:BB:CC:DD:EE:01"


async def test_failed_callback_marks_failed_and_no_provisioning(
    session_factory, client, patched_provisioning, provision_calls
):
    customer_id, checkout_id = await _seed_pending_hotspot_payment(session_factory)
    payload = _stk_callback_payload(checkout_id, result_code=1)

    resp = await client.post("/api/mpesa/callback", json=payload)
    assert resp.status_code == 200

    async with session_factory() as s:
        refreshed_txn = (
            await s.execute(
                select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_id)
            )
        ).scalar_one()
        assert refreshed_txn.status == MpesaTransactionStatus.failed

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))
        ).scalars().all()
        assert payments == []

        refreshed_customer = (
            await s.execute(select(Customer).where(Customer.id == customer_id))
        ).scalar_one()
        assert refreshed_customer.status == CustomerStatus.INACTIVE

    assert provision_calls == []


async def test_duplicate_callback_is_idempotent(
    session_factory, client, patched_provisioning, provision_calls
):
    customer_id, checkout_id = await _seed_pending_hotspot_payment(session_factory)
    payload = _stk_callback_payload(checkout_id, amount=500.0)

    # Fire the same callback twice
    r1 = await client.post("/api/mpesa/callback", json=payload)
    r2 = await client.post("/api/mpesa/callback", json=payload)
    assert r1.status_code == 200
    assert r2.status_code == 200

    async with session_factory() as s:
        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))
        ).scalars().all()
        assert len(payments) == 1, "Duplicate callback created a second CustomerPayment"

    hotspot_calls = [c for c in provision_calls if c[0] == "hotspot"]
    assert len(hotspot_calls) == 1, "Duplicate callback re-triggered provisioning"


async def test_unknown_checkout_id_does_not_crash(
    session_factory, client, patched_provisioning, provision_calls
):
    payload = _stk_callback_payload("ws_CO_UNKNOWN_XYZ", result_code=0)
    resp = await client.post("/api/mpesa/callback", json=payload)
    # Returns 200 even on unknown transaction (graceful — orphan recovery path)
    assert resp.status_code == 200
    assert provision_calls == []

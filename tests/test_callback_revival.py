"""Tests for SUCCESS-callback revival of wrongly-failed/expired M-Pesa transactions.

Production scenario: during Safaricom outages a still-processing transaction can
get marked failed (old reconcile behavior) or expired (>2h pending sweep). When
Safaricom later delivers the SUCCESS callback the money was actually taken — the
callback must revive and process the transaction instead of dropping it.

Guarantees verified here:
  1. SUCCESS callback for a failed txn revives it (status -> completed, receipt
     stored, customer provisioned).
  2. completed stays FINAL: any further callback is ignored.
  3. FAILURE callback for an already-failed txn stays ignored (no double-fail
     churn, no provisioning).
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
    FailureSource,
    MpesaTransaction,
    MpesaTransactionStatus,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# App + fixtures (same approach as tests/test_mpesa_callback_hotspot.py)
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
    """Patch BOTH provision entrypoints used by the callback at the import site."""
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


def _success_payload(checkout_request_id: str) -> dict:
    return {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "mr-1",
                "CheckoutRequestID": checkout_request_id,
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {"Item": [
                    {"Name": "Amount", "Value": 10},
                    {"Name": "MpesaReceiptNumber", "Value": "SGRTEST123"},
                    {"Name": "PhoneNumber", "Value": 254712345678},
                ]},
            }
        }
    }


def _failure_payload(checkout_request_id: str) -> dict:
    return {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "mr-1",
                "CheckoutRequestID": checkout_request_id,
                "ResultCode": 1032,
                "ResultDesc": "Request cancelled by user",
            }
        }
    }


async def _seed_txn(
    session_factory,
    *,
    status: MpesaTransactionStatus,
    failure_source=None,
):
    """Seed a hotspot customer + an MpesaTransaction in the given status.

    Returns (customer_id, checkout_request_id).
    """
    async with session_factory() as s:
        reseller = await make_reseller(s)
        plan = await make_plan(
            s, reseller, duration_value=30, duration_unit=DurationUnit.DAYS, price=10
        )
        router = await make_router(s, reseller)
        customer = await make_customer(
            s, reseller, plan, router,
            status=CustomerStatus.PENDING,
            expiry=None,
            mac_address="AA:BB:CC:DD:EE:02",
        )
        checkout_id = "ws_CO_REVIVE_001"
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        txn = MpesaTransaction(
            checkout_request_id=checkout_id,
            phone_number=customer.phone,
            amount=10.0,
            reference=f"customer-{customer.id}",
            customer_id=customer.id,
            status=status,
            failure_source=failure_source,
            created_at=five_min_ago,
            updated_at=five_min_ago,
        )
        s.add(txn)
        await s.commit()
        return customer.id, checkout_id


async def _fetch_txn(session_factory, checkout_id: str) -> MpesaTransaction:
    async with session_factory() as s:
        return (
            await s.execute(
                select(MpesaTransaction).where(
                    MpesaTransaction.checkout_request_id == checkout_id
                )
            )
        ).scalar_one()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_success_callback_revives_failed_txn(
    session_factory, client, patched_provisioning, provision_calls
):
    """A SUCCESS callback for a wrongly-failed txn must process it normally."""
    customer_id, checkout_id = await _seed_txn(
        session_factory,
        status=MpesaTransactionStatus.failed,
        failure_source=FailureSource.CLIENT,
    )

    resp = await client.post("/api/mpesa/callback", json=_success_payload(checkout_id))
    assert resp.status_code == 200
    assert resp.json()["ResultCode"] == 0

    # Fresh session — see the route's commits, not stale cached objects.
    txn = await _fetch_txn(session_factory, checkout_id)
    assert txn.status == MpesaTransactionStatus.completed
    assert txn.mpesa_receipt_number == "SGRTEST123"
    assert txn.failure_source is None

    async with session_factory() as s:
        refreshed_customer = (
            await s.execute(select(Customer).where(Customer.id == customer_id))
        ).scalar_one()
        assert refreshed_customer.status == CustomerStatus.ACTIVE

        payments = (
            await s.execute(
                select(CustomerPayment).where(CustomerPayment.customer_id == customer_id)
            )
        ).scalars().all()
        assert len(payments) == 1
        assert payments[0].payment_reference == "SGRTEST123"

    # Revived txn must still trigger hotspot provisioning
    hotspot_calls = [c for c in provision_calls if c[0] == "hotspot"]
    assert len(hotspot_calls) == 1, f"Expected one hotspot provision; got {provision_calls!r}"


async def test_callback_for_completed_txn_still_ignored(
    session_factory, client, patched_provisioning, provision_calls
):
    """completed is FINAL — even a SUCCESS callback must be ignored."""
    customer_id, checkout_id = await _seed_txn(
        session_factory, status=MpesaTransactionStatus.completed
    )

    resp = await client.post("/api/mpesa/callback", json=_success_payload(checkout_id))
    assert resp.status_code == 200
    assert resp.json()["ResultDesc"] == "Already processed"

    txn = await _fetch_txn(session_factory, checkout_id)
    assert txn.status == MpesaTransactionStatus.completed

    async with session_factory() as s:
        payments = (
            await s.execute(
                select(CustomerPayment).where(CustomerPayment.customer_id == customer_id)
            )
        ).scalars().all()
        assert payments == []

    assert provision_calls == []


async def test_failed_callback_for_failed_txn_still_ignored(
    session_factory, client, patched_provisioning, provision_calls
):
    """A FAILURE callback for an already-failed txn stays ignored."""
    customer_id, checkout_id = await _seed_txn(
        session_factory,
        status=MpesaTransactionStatus.failed,
        failure_source=FailureSource.CLIENT,
    )

    resp = await client.post("/api/mpesa/callback", json=_failure_payload(checkout_id))
    assert resp.status_code == 200
    assert resp.json()["ResultDesc"] == "Already processed"

    txn = await _fetch_txn(session_factory, checkout_id)
    assert txn.status == MpesaTransactionStatus.failed

    async with session_factory() as s:
        payments = (
            await s.execute(
                select(CustomerPayment).where(CustomerPayment.customer_id == customer_id)
            )
        ).scalars().all()
        assert payments == []

    assert provision_calls == []


async def test_string_result_code_zero_still_processes(
    session_factory, client, patched_provisioning, provision_calls
):
    """ResultCode delivered as string "0" must be treated as success (int 0).

    Safaricom may deliver ResultCode as a JSON string rather than a number.
    The int-cast added to mpesa_direct_callback ensures "0" == 0 comparisons
    work correctly so the transaction is completed and the customer is provisioned.
    """
    customer_id, checkout_id = await _seed_txn(
        session_factory,
        status=MpesaTransactionStatus.pending,
    )

    # Build a success payload but with ResultCode as a string "0".
    payload = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "mr-string-rc",
                "CheckoutRequestID": checkout_id,
                "ResultCode": "0",          # <-- string, not int
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {"Item": [
                    {"Name": "Amount", "Value": 10},
                    {"Name": "MpesaReceiptNumber", "Value": "SGRTEST456"},
                    {"Name": "PhoneNumber", "Value": 254712345678},
                ]},
            }
        }
    }

    resp = await client.post("/api/mpesa/callback", json=payload)
    assert resp.status_code == 200

    # Fresh session — must see completed status.
    txn = await _fetch_txn(session_factory, checkout_id)
    assert txn.status == MpesaTransactionStatus.completed
    assert txn.mpesa_receipt_number == "SGRTEST456"

    async with session_factory() as s:
        refreshed_customer = (
            await s.execute(select(Customer).where(Customer.id == customer_id))
        ).scalar_one()
        assert refreshed_customer.status == CustomerStatus.ACTIVE

        payments = (
            await s.execute(
                select(CustomerPayment).where(CustomerPayment.customer_id == customer_id)
            )
        ).scalars().all()
        assert len(payments) == 1
        assert payments[0].payment_reference == "SGRTEST456"

    hotspot_calls = [c for c in provision_calls if c[0] == "hotspot"]
    assert len(hotspot_calls) == 1, f"Expected one hotspot provision; got {provision_calls!r}"

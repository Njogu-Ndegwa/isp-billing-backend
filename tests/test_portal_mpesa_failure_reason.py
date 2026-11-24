"""The portal's payment-status poll says why an M-Pesa prompt failed.

Feedback board post 3 (MtaaNet): customers whose prompt failed (wrong PIN,
cancelled, phone not reached) waited for the portal to time out and saw a
generic "Payment Failed", then retried without knowing why. When Safaricom has
CONFIRMED the failure with a code we know, the public status response carries
a short customer-facing reason and next step. Anything not confirmed (a
timeout, our own errors, unknown codes) carries none, so the portal keeps
treating it as unconfirmed.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.payment_routes import router as payment_router
from app.db.database import get_db
from app.db.models import (
    CustomerStatus,
    FailureSource,
    MpesaTransaction,
    MpesaTransactionStatus,
)
from app.services import mpesa_results
from app.services import mpesa_transactions as mt
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _no_ondemand_query():
    # A PENDING customer's poll schedules a Safaricom query; keep it off.
    mt._ondemand_cooldown_until = float("inf")
    yield
    mt._ondemand_cooldown_until = 0.0


@pytest_asyncio.fixture
async def client(session_factory):
    app = FastAPI()
    app.include_router(payment_router)

    async def _get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _customer(db, status):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    return await make_customer(db, reseller, plan, router, status=status, mac_address="AA:BB:CC:DD:EE:31")


async def _txn(db, customer, *, status, code=None, desc=None, source=None, age_seconds=30, checkout="ws_CO_FR"):
    created = datetime.utcnow() - timedelta(seconds=age_seconds)
    txn = MpesaTransaction(
        checkout_request_id=checkout,
        phone_number=customer.phone,
        amount=10.0,
        reference=f"HOTSPOT-{customer.id}",
        customer_id=customer.id,
        status=status,
        result_code=code,
        result_desc=desc,
        failure_source=source,
        created_at=created,
        updated_at=created,
    )
    db.add(txn)
    await db.commit()
    return txn


async def test_wrong_pin_failure_is_explained_to_the_customer(engine, db, client):
    customer = await _customer(db, CustomerStatus.INACTIVE)
    await _txn(db, customer, status=MpesaTransactionStatus.failed, code="2001",
               desc="The initiator information is invalid.", source=FailureSource.CLIENT)

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    failure = body["mpesa_failure"]
    assert failure["reason_key"] == "wrong_pin"
    assert "PIN" in failure["reason"]
    assert failure["next_step"]
    # customer-facing: no reseller/internal wording
    text = (failure["reason"] + " " + failure["next_step"]).lower()
    for word in ("customer", "ask them", "bitwave", "reseller", "setup", "2001"):
        assert word not in text


async def test_failure_found_by_status_query_while_customer_still_pending(engine, db, client):
    # The on-demand/reconcile query marks the txn failed but leaves the customer PENDING.
    customer = await _customer(db, CustomerStatus.PENDING)
    await _txn(db, customer, status=MpesaTransactionStatus.failed, code="1032",
               desc="Request cancelled by user", source=FailureSource.CLIENT)

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    assert body["status"] == "pending"
    assert body["mpesa_failure"]["reason_key"] == "cancelled"


@pytest.mark.parametrize("status,code,source", [
    (MpesaTransactionStatus.pending, None, None),                          # still waiting
    (MpesaTransactionStatus.expired, "TIMEOUT", FailureSource.TIMEOUT),     # timeout is not a failure
    (MpesaTransactionStatus.failed, "SERVER_ERROR", FailureSource.SERVER),  # our side; may be paid
    (MpesaTransactionStatus.failed, "2028", FailureSource.CLIENT),          # reseller setup
    (MpesaTransactionStatus.failed, "7777", FailureSource.CLIENT),          # unknown code
])
async def test_unconfirmed_or_internal_results_carry_no_reason(engine, db, client, status, code, source):
    customer = await _customer(db, CustomerStatus.PENDING)
    await _txn(db, customer, status=status, code=code, source=source)

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    assert body["mpesa_failure"] is None


async def test_newest_prompt_decides(engine, db, client):
    customer = await _customer(db, CustomerStatus.PENDING)
    await _txn(db, customer, status=MpesaTransactionStatus.failed, code="2001",
               source=FailureSource.CLIENT, age_seconds=120, checkout="ws_CO_OLD")
    await _txn(db, customer, status=MpesaTransactionStatus.pending, age_seconds=10, checkout="ws_CO_NEW")

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    assert body["mpesa_failure"] is None


async def test_old_failure_is_not_reported(engine, db, client):
    customer = await _customer(db, CustomerStatus.INACTIVE)
    await _txn(db, customer, status=MpesaTransactionStatus.failed, code="2001",
               source=FailureSource.CLIENT, age_seconds=3 * 3600)

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    assert body["mpesa_failure"] is None


async def test_active_customer_gets_no_failure(engine, db, client):
    customer = await _customer(db, CustomerStatus.ACTIVE)
    await _txn(db, customer, status=MpesaTransactionStatus.failed, code="2001", source=FailureSource.CLIENT)

    body = (await client.get(f"/api/hotspot/payment-status/{customer.id}")).json()

    assert body["mpesa_failure"] is None


async def test_customer_reason_never_names_phone_numbers_or_internal_parties():
    for code in ("1", "17", "1001", "1019", "1025", "9999", "1032", "1037", "1038", "2001", "8006"):
        msg = mpesa_results.customer_reason(code)
        assert msg is not None, code
        text = (msg["reason"] + " " + msg["next_step"]).lower()
        assert not any(ch.isdigit() for ch in text.replace("2 minutes", "")), (code, text)
        for word in ("customer", "ask them", "bitwave", "reseller"):
            assert word not in text, (code, word)
    # M-Pesa's words alone are enough when the code is missing
    assert mpesa_results.customer_reason(None, "Request cancelled by user")["reason_key"] == "cancelled"
    for code in ("0", "2028", "TIMEOUT", "SERVER_ERROR", "STK_PUSH_FAILED", "7777", None):
        assert mpesa_results.customer_reason(code) is None, code

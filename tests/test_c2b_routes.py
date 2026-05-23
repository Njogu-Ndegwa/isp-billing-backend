"""
HTTP-level tests for the C2B Paybill routes.

These hit the actual FastAPI endpoints via httpx.AsyncClient + ASGITransport
— the same pattern as tests/test_mpesa_callback_hotspot.py — so we verify
the full chain: request body parsing -> route handler -> service handler ->
DB writes -> background task scheduling -> Safaricom-shaped response.

The unit tests in test_c2b_handler.py prove the handler logic. These prove
the route wiring (BackgroundTasks injection, dependency overrides, response
serialization, idempotency over real HTTP).
"""

from typing import List, Tuple
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.c2b_routes import router as c2b_router
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
)
from app.services.account_numbers import luhn_check_digit
from tests.factories import make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# Fixtures: minimal app, ASGI client, MikroTik stubs, provision recorder
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app(session_factory):
    """Minimal FastAPI app with only the c2b_router mounted."""
    app = FastAPI()
    app.include_router(c2b_router)

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
    return []


@pytest_asyncio.fixture
async def patched_provisioning(provision_calls):
    """Patch call_pppoe_provision at the route's import site so the
    background task records its args instead of opening a TCP connection
    to a fake 10.0.0.2 RouterOS."""
    async def _record(*args, **kwargs):
        provision_calls.append(("pppoe", args, kwargs))

    with patch(
        "app.services.c2b_handler.call_pppoe_provision",
        new=AsyncMock(side_effect=_record),
    ):
        yield


@pytest.fixture(autouse=True)
def _stub_fup(monkeypatch):
    """Same rationale as test_c2b_handler.py: record_customer_payment's
    on_renewal -> fup.revert path tries to hit MikroTik and stalls."""
    async def _noop(*args, **kwargs):
        return {"ok": True}
    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _valid_account(base: str) -> str:
    return base + luhn_check_digit(base)


def _payload(*, trans_id: str, bill_ref: str, amount: float, shortcode: str = None) -> dict:
    return {
        "TransactionType": "Pay Bill",
        "TransID": trans_id,
        "TransTime": "20260523120000",
        "TransAmount": str(amount),
        "BusinessShortCode": shortcode or settings.MPESA_SHORTCODE,
        "BillRefNumber": bill_ref,
        "MSISDN": "254712345678",
        "FirstName": "Sandbox",
        "LastName": "Tester",
    }


async def _seed_pppoe(db, *, account_number=None, wallet=0):
    reseller = await make_reseller(db)
    plan = await make_plan(
        db, reseller,
        price=500, duration_value=30, duration_unit=DurationUnit.DAYS,
        connection_type=ConnectionType.PPPOE,
    )
    router = await make_router(db, reseller)
    acct = account_number or _valid_account("4000004")
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE,
        expiry=None,
        pppoe_username="pppoe_route_test",
        mac_address=None,
        account_number=acct,
        wallet_credit_kes=wallet,
    )
    return customer


# ---------------------------------------------------------------------------
# Confirmation route
# ---------------------------------------------------------------------------


async def test_confirmation_route_activates_customer_end_to_end(
    db, session_factory, client, patched_provisioning, provision_calls
):
    customer = await _seed_pppoe(db)
    body = _payload(trans_id="HTTP001", bill_ref=customer.account_number, amount=500)

    resp = await client.post("/api/c2b/confirmation", json=body)

    assert resp.status_code == 200
    body_resp = resp.json()
    # Safaricom-expected response shape
    assert body_resp == {"ResultCode": 0, "ResultDesc": "Success"}

    # DB state reflects activation
    async with session_factory() as s:
        refreshed = (await s.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.expiry is not None

        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "HTTP001"))).scalar_one()
        assert txn.status == C2BTransactionStatus.PROCESSED
        assert txn.matched_customer_id == customer.id

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))
        ).scalars().all()
        assert len(payments) == 1
        assert payments[0].payment_reference == "HTTP001"

    # Provisioning queued via BackgroundTasks and ran post-response
    pppoe_calls = [c for c in provision_calls if c[0] == "pppoe"]
    assert len(pppoe_calls) == 1, f"Expected one PPPoE provision; got {provision_calls!r}"
    queued_payload = pppoe_calls[0][1][0]
    assert queued_payload["pppoe_username"] == customer.pppoe_username


async def test_confirmation_route_unknown_account_returns_200_buckets_unmatched(
    db, session_factory, client, patched_provisioning, provision_calls
):
    body = _payload(trans_id="HTTP002", bill_ref=_valid_account("9999999"), amount=500)

    resp = await client.post("/api/c2b/confirmation", json=body)

    # Safaricom must always see 200 — never tell them to retry on app errors
    assert resp.status_code == 200
    assert resp.json() == {"ResultCode": 0, "ResultDesc": "Success"}

    async with session_factory() as s:
        txn = (await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "HTTP002"))).scalar_one()
        assert txn.status == C2BTransactionStatus.UNMATCHED

        um = (
            await s.execute(select(UnmatchedC2BPayment).where(UnmatchedC2BPayment.c2b_transaction_id == txn.id))
        ).scalar_one()
        assert um.reason == UnmatchedC2BReason.UNKNOWN_ACCOUNT

    assert provision_calls == []


async def test_confirmation_route_duplicate_is_idempotent_over_http(
    db, session_factory, client, patched_provisioning, provision_calls
):
    customer = await _seed_pppoe(db)
    body = _payload(trans_id="HTTP003", bill_ref=customer.account_number, amount=500)

    r1 = await client.post("/api/c2b/confirmation", json=body)
    r2 = await client.post("/api/c2b/confirmation", json=body)
    assert r1.status_code == r2.status_code == 200

    async with session_factory() as s:
        txns = (
            await s.execute(select(C2BTransaction).where(C2BTransaction.trans_id == "HTTP003"))
        ).scalars().all()
        assert len(txns) == 1

        payments = (
            await s.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))
        ).scalars().all()
        assert len(payments) == 1

    assert len(provision_calls) == 1  # one provision, not two


async def test_confirmation_route_handles_malformed_body(client):
    """Garbage in -> still 200 with Success. Safaricom must never get a 5xx
    for our parsing failures."""
    resp = await client.post(
        "/api/c2b/confirmation",
        content=b"not json at all",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ResultCode": 0, "ResultDesc": "Success"}


# ---------------------------------------------------------------------------
# Validation route
# ---------------------------------------------------------------------------


async def test_validation_route_accepts_known_account(db, client, patched_provisioning):
    customer = await _seed_pppoe(db)
    body = _payload(trans_id="V-HTTP01", bill_ref=customer.account_number, amount=500)

    resp = await client.post("/api/c2b/validation", json=body)

    assert resp.status_code == 200
    assert resp.json() == {"ResultCode": 0, "ResultDesc": "Accepted"}


async def test_validation_route_rejects_invalid_luhn(client):
    body = _payload(trans_id="V-HTTP02", bill_ref="11111111", amount=500)

    resp = await client.post("/api/c2b/validation", json=body)

    assert resp.status_code == 200
    # C2B00012 = Safaricom's "Invalid Account Number" rejection code; the
    # customer's payment is refused at the M-Pesa menu before money moves.
    assert resp.json() == {"ResultCode": "C2B00012", "ResultDesc": "Invalid Account Number"}


async def test_validation_route_rejects_unknown_account(client):
    body = _payload(trans_id="V-HTTP03", bill_ref=_valid_account("8888888"), amount=500)

    resp = await client.post("/api/c2b/validation", json=body)

    assert resp.status_code == 200
    assert resp.json() == {"ResultCode": "C2B00012", "ResultDesc": "Invalid Account Number"}

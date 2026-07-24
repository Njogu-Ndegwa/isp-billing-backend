"""Customer vs. visitor tiering on the customer list endpoints.

Covers:
- has_paid/tier computed correctly (paid via completed payment row, paid via
  future expiry, never-paid -> visitor, non-completed payments don't count)
- ?tier= filter behavior (all | customer | visitor, invalid -> 400)
- no regression on the default response (all rows returned, existing fields
  intact, tier param omitted)
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.customer_routes as cr
from app.api.customer_routes import router as customer_router
from app.db.database import get_db
from app.db.models import (
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
)
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(customer_router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(cr, "get_current_user", _fake)


async def _add_payment(db, customer, reseller, *,
                       status=PaymentStatus.COMPLETED, amount=20.0):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.CASH,
        days_paid_for=1,
        status=status,
    )
    db.add(payment)
    await db.commit()
    return payment


@pytest_asyncio.fixture
async def dataset(db):
    """One reseller with four customers:

    - paid_row:      completed payment, expiry in the past  -> customer
    - future_expiry: no payments, expiry in the future      -> customer
    - never_paid:    no payments, no expiry                 -> visitor
    - failed_only:   only a FAILED payment, expired         -> visitor
    """
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    now = datetime.utcnow()

    paid_row = await make_customer(
        db, reseller, plan, router,
        name="Paid Row", status=CustomerStatus.INACTIVE,
        expiry=now - timedelta(days=3),
    )
    await _add_payment(db, paid_row, reseller)

    future_expiry = await make_customer(
        db, reseller, plan, router,
        name="Future Expiry", status=CustomerStatus.ACTIVE,
        expiry=now + timedelta(hours=6),
    )

    never_paid = await make_customer(
        db, reseller, plan, router,
        name="Never Paid", status=CustomerStatus.INACTIVE, expiry=None,
    )

    failed_only = await make_customer(
        db, reseller, plan, router,
        name="Failed Only", status=CustomerStatus.INACTIVE,
        expiry=now - timedelta(days=1),
    )
    await _add_payment(db, failed_only, reseller, status=PaymentStatus.FAILED)

    return {
        "reseller": reseller,
        "plan": plan,
        "router": router,
        "paid_row": paid_row,
        "future_expiry": future_expiry,
        "never_paid": never_paid,
        "failed_only": failed_only,
    }


def _by_id(items):
    return {item["id"]: item for item in items}


# ---------------------------------------------------------------------------
# Computed fields
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_has_paid_and_tier_computed(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers")
    assert resp.status_code == 200
    items = _by_id(resp.json())
    assert len(items) == 4

    paid = items[dataset["paid_row"].id]
    assert paid["has_paid"] is True
    assert paid["tier"] == "customer"

    future = items[dataset["future_expiry"].id]
    assert future["has_paid"] is True
    assert future["tier"] == "customer"

    never = items[dataset["never_paid"].id]
    assert never["has_paid"] is False
    assert never["tier"] == "visitor"

    # A FAILED payment row must not count as paying.
    failed = items[dataset["failed_only"].id]
    assert failed["has_paid"] is False
    assert failed["tier"] == "visitor"


@pytest.mark.asyncio
async def test_other_customers_payment_does_not_leak(db, client, monkeypatch, dataset):
    """EXISTS is correlated per customer: paid_row's payment must not mark
    the never-paid customer as paying (they share the same reseller)."""
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers")
    items = _by_id(resp.json())
    assert items[dataset["never_paid"].id]["has_paid"] is False
    assert items[dataset["paid_row"].id]["has_paid"] is True


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tier_filter_customer(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers", params={"tier": "customer"})
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert ids == {dataset["paid_row"].id, dataset["future_expiry"].id}
    assert all(item["tier"] == "customer" for item in resp.json())


@pytest.mark.asyncio
async def test_tier_filter_visitor(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers", params={"tier": "visitor"})
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()}
    assert ids == {dataset["never_paid"].id, dataset["failed_only"].id}
    assert all(item["tier"] == "visitor" for item in resp.json())


@pytest.mark.asyncio
async def test_tier_all_matches_default(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])

    default_resp = await client.get("/api/customers")
    all_resp = await client.get("/api/customers", params={"tier": "all"})
    assert default_resp.status_code == 200
    assert all_resp.status_code == 200
    assert _by_id(default_resp.json()).keys() == _by_id(all_resp.json()).keys()
    assert len(default_resp.json()) == 4


@pytest.mark.asyncio
async def test_invalid_tier_rejected(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers", params={"tier": "vip"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_tier_filter_combines_with_router_filter(db, client, monkeypatch, dataset):
    """tier=visitor + router_id must intersect, not override, filters."""
    _auth_as(monkeypatch, dataset["reseller"])
    other_router = await make_router(db, dataset["reseller"])
    lonely = await make_customer(
        db, dataset["reseller"], dataset["plan"], other_router,
        name="Other Router Visitor", status=CustomerStatus.INACTIVE,
    )

    resp = await client.get(
        "/api/customers",
        params={"tier": "visitor", "router_id": other_router.id},
    )
    assert resp.status_code == 200
    assert {item["id"] for item in resp.json()} == {lonely.id}


# ---------------------------------------------------------------------------
# Default-response regression
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_default_response_shape_unchanged(db, client, monkeypatch, dataset):
    """Existing fields still present with correct values; the only additions
    are has_paid and tier; all rows still returned without a tier param."""
    _auth_as(monkeypatch, dataset["reseller"])

    resp = await client.get("/api/customers")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 4

    item = _by_id(items)[dataset["future_expiry"].id]
    for field in (
        "id", "name", "phone", "mac_address", "pppoe_username",
        "pppoe_password", "static_ip", "status", "expiry", "created_at",
        "plan_id", "router_id", "account_number", "wallet_credit_kes",
        "plan", "router",
    ):
        assert field in item, f"missing pre-existing field {field}"
    assert item["name"] == "Future Expiry"
    assert item["status"] == "active"
    assert item["plan"]["id"] == dataset["plan"].id
    assert item["router"]["id"] == dataset["router"].id


# ---------------------------------------------------------------------------
# /api/customers/active
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_active_endpoint_has_tier_fields_and_filter(db, client, monkeypatch, dataset):
    _auth_as(monkeypatch, dataset["reseller"])
    now = datetime.utcnow()

    # ACTIVE status but expiry already past and no payments -> visitor.
    stale_active = await make_customer(
        db, dataset["reseller"], dataset["plan"], dataset["router"],
        name="Stale Active", status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(hours=2),
    )

    resp = await client.get("/api/customers/active")
    assert resp.status_code == 200
    items = _by_id(resp.json())
    # Only ACTIVE customers appear (pre-existing behavior).
    assert set(items.keys()) == {dataset["future_expiry"].id, stale_active.id}
    assert items[dataset["future_expiry"].id]["tier"] == "customer"
    assert items[stale_active.id]["tier"] == "visitor"
    assert items[stale_active.id]["has_paid"] is False
    # Pre-existing computed field still present.
    assert items[dataset["future_expiry"].id]["hours_remaining"] > 0

    filtered = await client.get("/api/customers/active", params={"tier": "customer"})
    assert filtered.status_code == 200
    assert {i["id"] for i in filtered.json()} == {dataset["future_expiry"].id}

    visitors = await client.get("/api/customers/active", params={"tier": "visitor"})
    assert visitors.status_code == 200
    assert {i["id"] for i in visitors.json()} == {stale_active.id}

    bad = await client.get("/api/customers/active", params={"tier": "bogus"})
    assert bad.status_code == 400

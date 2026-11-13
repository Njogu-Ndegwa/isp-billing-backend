"""Customer install location (latitude / longitude) on register, edit and
detail: both-or-neither, ranges, captured-at stamping, clearing, audit log."""

import json
from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import customer_routes
from app.db.models import ConnectionType, Customer, CustomerEvent
from app.services import customer_profile as cp
from tests.factories import make_customer, make_plan, make_reseller, make_router

LAT, LNG = -1.2195, 36.8869  # Kahawa Sukari


def _as(monkeypatch, user):
    async def _get(token, db):
        return user
    monkeypatch.setattr(customer_routes, "get_current_user", _get)


@pytest.fixture(autouse=True)
def _no_welcome_sms(monkeypatch):
    from app.services import customer_notifications
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda _id: None)


async def _seed(db, connection_type=ConnectionType.PPPOE):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=connection_type)
    router = await make_router(db, reseller)
    return reseller, plan, router


def _register(plan, router, **kw):
    base = dict(name="Wanjiru", phone="254712345678", plan_id=plan.id, router_id=router.id)
    base.update(kw)
    return customer_routes.CustomerRegisterRequest(**base)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_clean_location_rounds_and_accepts_strings():
    assert cp.clean_location("-1.21951234567", "36.886912345") == (-1.219512, 36.886912)
    assert cp.clean_location(None, None) is None


@pytest.mark.parametrize("lat, lng", [
    (LAT, None), (None, LNG),               # half a pair
    (91, LNG), (-90.5, LNG),                # latitude range
    (LAT, 180.1), (LAT, -181),              # longitude range
    (0, 0), (0.0, 0.0),                     # failed GPS read
    (float("nan"), LNG), (LAT, float("inf")),
    ("abc", LNG),
])
def test_clean_location_rejects(lat, lng):
    with pytest.raises(HTTPException) as err:
        cp.clean_location(lat, lng)
    assert err.value.status_code == 400


def test_edge_values_are_valid():
    assert cp.clean_location(90, 180) == (90, 180)
    assert cp.clean_location(-90, -180) == (-90, -180)
    assert cp.clean_location(0, 36.8) == (0, 36.8)  # the equator is real


# ---------------------------------------------------------------------------
# Register / edit / detail
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("connection_type", [ConnectionType.PPPOE, ConnectionType.HOTSPOT])
async def test_register_saves_location(db, monkeypatch, connection_type):
    reseller, plan, router = await _seed(db, connection_type)
    _as(monkeypatch, reseller)
    extra = {"mac_address": "AA:BB:CC:DD:EE:02"} if connection_type == ConnectionType.HOTSPOT else {}

    out = await customer_routes.register_customer_api(
        _register(plan, router, latitude=LAT, longitude=LNG, **extra), db, "t")

    row = await db.get(Customer, out["id"])
    assert (row.latitude, row.longitude) == (LAT, LNG)
    assert row.location_captured_at is not None
    assert out["latitude"] == LAT and out["longitude"] == LNG
    assert out["location_captured_at"] == row.location_captured_at.isoformat()


@pytest.mark.asyncio
async def test_register_without_location(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)

    out = await customer_routes.register_customer_api(_register(plan, router), db, "t")

    row = await db.get(Customer, out["id"])
    assert row.latitude is None and row.longitude is None and row.location_captured_at is None
    assert out["latitude"] is None and out["location_captured_at"] is None


@pytest.mark.asyncio
async def test_register_with_half_a_location_creates_nothing(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)

    with pytest.raises(HTTPException) as err:
        await customer_routes.register_customer_api(
            _register(plan, router, latitude=LAT), db, "t")
    assert err.value.status_code == 400
    assert (await db.execute(select(func.count(Customer.id)))).scalar_one() == 0


@pytest.mark.asyncio
async def test_edit_sets_keeps_and_clears_location(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k")

    out = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(latitude=LAT, longitude=LNG), db, "t")
    await db.refresh(customer)
    assert (customer.latitude, customer.longitude) == (LAT, LNG)
    first_capture = customer.location_captured_at
    assert first_capture is not None
    assert out["customer"]["latitude"] == LAT

    # Absent = unchanged.
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(name="Renamed"), db, "t")
    await db.refresh(customer)
    assert (customer.latitude, customer.longitude) == (LAT, LNG)

    # Same pair sent back by the form: captured-at is not bumped.
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(latitude=LAT, longitude=LNG), db, "t")
    await db.refresh(customer)
    assert customer.location_captured_at == first_capture

    # Cleared.
    out = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(clear_location=True), db, "t")
    await db.refresh(customer)
    assert customer.latitude is None and customer.longitude is None
    assert customer.location_captured_at is None
    assert out["customer"]["latitude"] is None


@pytest.mark.asyncio
async def test_edit_with_bad_location_changes_nothing(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k")

    for bad in (dict(latitude=LAT), dict(latitude=100, longitude=LNG),
                dict(latitude=LAT, longitude=LNG, clear_location=True)):
        with pytest.raises(HTTPException) as err:
            await customer_routes.edit_customer(
                customer.id, customer_routes.CustomerEditRequest(name="Renamed", **bad), db, "t")
        assert err.value.status_code == 400
    await db.refresh(customer)
    assert customer.name != "Renamed"
    assert customer.latitude is None


@pytest.mark.asyncio
async def test_edit_audit_log_says_location_changed_not_where(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="w_k")

    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(latitude=LAT, longitude=LNG), db, "t")
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(latitude=-1.3, longitude=36.9), db, "t")
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(clear_location=True), db, "t")

    events = (await db.execute(select(CustomerEvent).order_by(CustomerEvent.id))).scalars().all()
    messages = [e.message for e in events]
    assert any("location set" in m for m in messages)
    assert any("location changed" in m for m in messages)
    assert any("location removed" in m for m in messages)
    dumped = json.dumps(messages + [e.details for e in events], default=str)
    assert "36.88" not in dumped and "1.21" not in dumped


@pytest.mark.asyncio
async def test_detail_returns_location_list_does_not(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    captured = datetime(2026, 11, 11, 9, 30)
    customer = await make_customer(db, reseller, plan, router,
                                   latitude=LAT, longitude=LNG, location_captured_at=captured)

    detail = await customer_routes.get_customer_detail(customer.id, db, "t")
    assert detail["latitude"] == LAT and detail["longitude"] == LNG
    assert detail["location_captured_at"] == "2026-11-11T09:30:00"

    (item,) = await customer_routes.get_customers_api(router_id=None, tier=None, db=db, token="t")
    assert "latitude" not in item and "longitude" not in item


@pytest.mark.asyncio
async def test_location_endpoint_validates(db, monkeypatch):
    reseller, plan, router = await _seed(db)
    _as(monkeypatch, reseller)
    customer = await make_customer(db, reseller, plan, router)

    with pytest.raises(HTTPException) as err:
        await customer_routes.update_customer_location(
            customer.id, customer_routes.UpdateLocationRequest(latitude=0, longitude=0), db, "t")
    assert err.value.status_code == 400

    out = await customer_routes.update_customer_location(
        customer.id, customer_routes.UpdateLocationRequest(latitude=LAT, longitude=LNG), db, "t")
    assert out["latitude"] == LAT and out["location_captured_at"]


@pytest.mark.asyncio
async def test_other_reseller_cannot_set_location(db, monkeypatch):
    owner, plan, router = await _seed(db)
    other = await make_reseller(db)
    customer = await make_customer(db, owner, plan, router)
    _as(monkeypatch, other)

    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id, customer_routes.CustomerEditRequest(latitude=LAT, longitude=LNG), db, "t")
    assert err.value.status_code == 404
    await db.refresh(customer)
    assert customer.latitude is None

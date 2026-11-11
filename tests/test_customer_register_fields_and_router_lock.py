"""Customer register fields (ID number, house, email, install date, notes,
location) and the opt-in PPPoE router lock."""

from datetime import date

import pytest
from fastapi import HTTPException

from app.api import customer_routes, pppoe_router_lock_routes
from app.db.models import ConnectionType, Customer, CustomerStatus
from app.services import pppoe_router_lock
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _user_getter(user):
    async def _get(token, db):
        return user
    return _get


@pytest.fixture(autouse=True)
def _no_side_effects(monkeypatch):
    from app.services import customer_notifications

    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda _id: None)

    async def _no_event(*args, **kwargs):
        return None

    monkeypatch.setattr(customer_routes, "record_customer_event", _no_event)
    monkeypatch.setattr(pppoe_router_lock_routes, "record_customer_event", _no_event)


async def _seed(db, monkeypatch, *, lock=False):
    reseller = await make_reseller(db)
    reseller.pppoe_router_lock_enabled = lock
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)
    await db.commit()
    getter = _user_getter(reseller)
    monkeypatch.setattr(customer_routes, "get_current_user", getter)
    monkeypatch.setattr(pppoe_router_lock_routes, "get_current_user", getter)
    return reseller, plan, router_a, router_b


def _register(plan, router, **kw):
    base = dict(name="Elgy Client", phone="254712345678", plan_id=plan.id, router_id=router.id)
    base.update(kw)
    return customer_routes.CustomerRegisterRequest(**base)


# ---------------------------------------------------------------------------
# Register fields
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_saves_optional_fields(db, monkeypatch):
    _, plan, router, _ = await _seed(db, monkeypatch)
    out = await customer_routes.register_customer_api(_register(
        plan, router,
        id_number=" 12345678 ", house="Block C, Hse 4", email="client@example.com",
        install_date=date(2026, 11, 1), notes="Roof mount, 5m cable",
        location="Kitengela, near Total", latitude=-1.47, longitude=36.96,
    ), db, "t")
    assert out["id_number"] == "12345678"
    assert out["house"] == "Block C, Hse 4"
    assert out["email"] == "client@example.com"
    assert out["install_date"] == "2026-11-01"
    assert out["notes"] == "Roof mount, 5m cable"
    assert out["location"] == "Kitengela, near Total"
    assert (out["latitude"], out["longitude"]) == (-1.47, 36.96)
    row = await db.get(Customer, out["id"])
    assert row.location_captured_at is not None


@pytest.mark.asyncio
async def test_register_without_optional_fields_still_works(db, monkeypatch):
    _, plan, router, _ = await _seed(db, monkeypatch)
    out = await customer_routes.register_customer_api(_register(plan, router), db, "t")
    assert out["id_number"] is None and out["install_date"] is None and out["location"] is None
    assert out["pppoe_locked_router_id"] is None  # lock is off by default


@pytest.mark.asyncio
async def test_register_rejects_bad_email(db, monkeypatch):
    _, plan, router, _ = await _seed(db, monkeypatch)
    with pytest.raises(HTTPException) as exc:
        await customer_routes.register_customer_api(_register(plan, router, email="nope"), db, "t")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_edit_sets_clears_and_keeps_fields(db, monkeypatch):
    reseller, plan, router, _ = await _seed(db, monkeypatch)
    customer = await make_customer(
        db, reseller, plan, router, pppoe_username="pppoe_1", pppoe_password="pw",
        status=CustomerStatus.INACTIVE, id_number="111", notes="old",
    )
    await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(notes="", house="Hse 9", install_date=date(2026, 10, 29)),
        db, "t",
    )
    await db.refresh(customer)
    assert customer.notes is None          # "" clears
    assert customer.house == "Hse 9"
    assert customer.install_date == date(2026, 10, 29)
    assert customer.id_number == "111"     # omitted is kept

    detail = await customer_routes.get_customer_detail(customer.id, db, "t")
    assert detail["house"] == "Hse 9" and detail["id_number"] == "111"
    assert detail["pppoe_router_lock_enabled"] is False


# ---------------------------------------------------------------------------
# PPPoE router lock
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lock_off_by_default_router_move_allowed(db, monkeypatch):
    reseller, plan, router_a, router_b = await _seed(db, monkeypatch)
    customer = await make_customer(
        db, reseller, plan, router_a, pppoe_username="pppoe_2", pppoe_password="pw",
        status=CustomerStatus.INACTIVE,
    )
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(router_id=router_b.id), db, "t",
    )
    await db.refresh(customer)
    assert customer.router_id == router_b.id
    assert customer.pppoe_locked_router_id is None


@pytest.mark.asyncio
async def test_register_with_lock_on_stamps_first_router_and_refuses_move(db, monkeypatch):
    _, plan, router_a, router_b = await _seed(db, monkeypatch, lock=True)
    out = await customer_routes.register_customer_api(_register(plan, router_a), db, "t")
    assert out["pppoe_locked_router_id"] == router_a.id

    with pytest.raises(HTTPException) as exc:
        await customer_routes.edit_customer(
            out["id"], customer_routes.CustomerEditRequest(router_id=router_b.id), db, "t",
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["status"] == "pppoe_router_locked"
    row = await db.get(Customer, out["id"])
    await db.refresh(row)
    assert row.router_id == router_a.id

    # Saving the same router (or other fields) is fine.
    await customer_routes.edit_customer(
        out["id"], customer_routes.CustomerEditRequest(router_id=router_a.id, notes="ok"), db, "t",
    )


@pytest.mark.asyncio
async def test_enabling_lock_stamps_existing_pppoe_customers_only(db, monkeypatch):
    reseller, plan, router_a, router_b = await _seed(db, monkeypatch)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    pppoe = await make_customer(
        db, reseller, plan, router_b, pppoe_username="pppoe_3", pppoe_password="pw",
        status=CustomerStatus.INACTIVE,
    )
    hotspot = await make_customer(db, reseller, hotspot_plan, router_a)

    out = await pppoe_router_lock_routes.set_pppoe_router_lock(
        pppoe_router_lock_routes.RouterLockToggle(enabled=True), db, "t",
    )
    assert out["enabled"] is True and out["newly_locked"] == 1
    await db.refresh(pppoe)
    await db.refresh(hotspot)
    assert pppoe.pppoe_locked_router_id == router_b.id
    assert hotspot.pppoe_locked_router_id is None

    got = await pppoe_router_lock_routes.get_pppoe_router_lock(db, "t")
    assert got == {"enabled": True, "locked_customers": 1}


@pytest.mark.asyncio
async def test_release_allows_one_move_then_relocks(db, monkeypatch):
    reseller, plan, router_a, router_b = await _seed(db, monkeypatch, lock=True)
    customer = await make_customer(
        db, reseller, plan, router_a, pppoe_username="pppoe_4", pppoe_password="pw",
        status=CustomerStatus.INACTIVE, pppoe_locked_router_id=router_a.id,
    )
    released = await pppoe_router_lock_routes.release_pppoe_router_lock(customer.id, db, "t")
    assert released["released_router_id"] == router_a.id

    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(router_id=router_b.id), db, "t",
    )
    await db.refresh(customer)
    assert customer.router_id == router_b.id
    assert customer.pppoe_locked_router_id == router_b.id

    with pytest.raises(HTTPException) as exc:
        await customer_routes.edit_customer(
            customer.id, customer_routes.CustomerEditRequest(router_id=router_a.id), db, "t",
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_lock_turned_off_stops_enforcing(db, monkeypatch):
    reseller, plan, router_a, router_b = await _seed(db, monkeypatch, lock=True)
    customer = await make_customer(
        db, reseller, plan, router_a, pppoe_username="pppoe_5", pppoe_password="pw",
        status=CustomerStatus.INACTIVE, pppoe_locked_router_id=router_a.id,
    )
    await pppoe_router_lock_routes.set_pppoe_router_lock(
        pppoe_router_lock_routes.RouterLockToggle(enabled=False), db, "t",
    )
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(router_id=router_b.id), db, "t",
    )
    await db.refresh(customer)
    assert customer.router_id == router_b.id


def test_check_router_change_ignores_hotspot_customers():
    class Owner:
        pppoe_router_lock_enabled = True

    c = Customer(id=1, pppoe_username=None, router_id=1, pppoe_locked_router_id=1)
    pppoe_router_lock.check_router_change(Owner(), c, 2)  # no raise


@pytest.mark.asyncio
async def test_edit_null_install_date_clears_it(db, monkeypatch):
    reseller, plan, router, _ = await _seed(db, monkeypatch)
    customer = await make_customer(
        db, reseller, plan, router, pppoe_username="pppoe_6", pppoe_password="pw",
        status=CustomerStatus.INACTIVE, install_date=date(2026, 10, 1),
    )
    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(install_date=None), db, "t",
    )
    await db.refresh(customer)
    assert customer.install_date is None

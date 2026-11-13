"""Auto-generated PPPoE usernames and the username-taken checks.

Regression for customer 46072 (Techmid, 2026-10-23): a phone pasted with a
TAB produced the router login ``pppoe_<TAB><digits>``.
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import customer_routes
from app.db.models import ConnectionType, Customer, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _user_getter(user):
    async def _get(token, db):
        return user
    return _get


@pytest.fixture(autouse=True)
def _no_welcome_sms(monkeypatch):
    from app.services import customer_notifications
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda _id: None)


async def _seed(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    return reseller, plan, router


def _register(plan, router, **kw):
    base = dict(name="New", phone="254712345678", plan_id=plan.id, router_id=router.id)
    base.update(kw)
    return customer_routes.CustomerRegisterRequest(**base)


@pytest.mark.parametrize("raw", [
    "\t254712345678",
    "254712345678\t",
    " +254 712 345 678 ",
    "+254-712-345-678",
    "(254) 712345678\n",
    "254 712 345678",
])
def test_generated_username_is_digits_only(raw):
    assert customer_routes._generated_pppoe_username(raw) == "pppoe_254712345678"


def test_generated_username_needs_digits():
    assert customer_routes._generated_pppoe_username("  \t ") is None
    assert customer_routes._generated_pppoe_username("") is None


@pytest.mark.asyncio
async def test_register_with_tab_in_phone_gives_clean_username_and_phone(db, monkeypatch):
    _, plan, router = await _seed(db, monkeypatch)

    out = await customer_routes.register_customer_api(
        _register(plan, router, phone="\t254712345678 "), db, "t")

    row = await db.get(Customer, out["id"])
    assert row.pppoe_username == "pppoe_254712345678"
    assert row.phone == "254712345678"


@pytest.mark.asyncio
async def test_register_without_digits_and_without_username_is_400(db, monkeypatch):
    _, plan, router = await _seed(db, monkeypatch)

    with pytest.raises(HTTPException) as err:
        await customer_routes.register_customer_api(_register(plan, router, phone="\t"), db, "t")
    assert err.value.status_code == 400


@pytest.mark.asyncio
async def test_register_keeps_explicit_username(db, monkeypatch):
    _, plan, router = await _seed(db, monkeypatch)

    out = await customer_routes.register_customer_api(
        _register(plan, router, phone="\t0712", pppoe_username="  mary_k "), db, "t")

    row = await db.get(Customer, out["id"])
    assert row.pppoe_username == "mary_k"


@pytest.mark.asyncio
async def test_register_duplicate_username_is_409_even_when_duplicates_exist(db, monkeypatch):
    reseller, plan, router = await _seed(db, monkeypatch)
    # No unique constraint on the column: two rows can already share a name.
    for _ in range(2):
        await make_customer(db, reseller, plan, router, pppoe_username="pppoe_254712345678",
                            status=CustomerStatus.INACTIVE)

    with pytest.raises(HTTPException) as err:
        await customer_routes.register_customer_api(
            _register(plan, router, phone="\t254712345678"), db, "t")
    assert err.value.status_code == 409
    assert "pppoe_254712345678" in err.value.detail


@pytest.mark.asyncio
async def test_register_username_check_stays_global_across_resellers(db, monkeypatch):
    other = await make_reseller(db)
    other_plan = await make_plan(db, other, connection_type=ConnectionType.PPPOE)
    other_router = await make_router(db, other)
    await make_customer(db, other, other_plan, other_router, pppoe_username="shared_name",
                        status=CustomerStatus.INACTIVE)
    _, plan, router = await _seed(db, monkeypatch)

    with pytest.raises(HTTPException) as err:
        await customer_routes.register_customer_api(
            _register(plan, router, pppoe_username="shared_name"), db, "t")
    assert err.value.status_code == 409


@pytest.mark.asyncio
async def test_edit_duplicate_username_is_409_even_when_duplicates_exist(db, monkeypatch):
    reseller, plan, router = await _seed(db, monkeypatch)
    for _ in range(2):
        await make_customer(db, reseller, plan, router, pppoe_username="taken",
                            status=CustomerStatus.INACTIVE)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="mine",
                                   status=CustomerStatus.INACTIVE)

    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id, customer_routes.CustomerEditRequest(pppoe_username=" taken "), db, "t")
    assert err.value.status_code == 409
    assert "taken" in err.value.detail


@pytest.mark.asyncio
async def test_edit_strips_phone(db, monkeypatch):
    reseller, plan, router = await _seed(db, monkeypatch)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="mine",
                                   status=CustomerStatus.INACTIVE)

    await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(phone="\t254700000001\n"), db, "t")

    row = (await db.execute(select(Customer).where(Customer.id == customer.id))).scalar_one()
    await db.refresh(row)
    assert row.phone == "254700000001"
    # Existing usernames are never rewritten by a phone edit.
    assert row.pppoe_username == "mine"

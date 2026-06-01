from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import customer_routes, pppoe_monitor
from app.db.models import ConnectionType, Customer, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _seed_pppoe_customer(db, *, status=CustomerStatus.INACTIVE):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=status,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address=None,
        pppoe_username="Festo",
        pppoe_password="secret",
        name="Festus",
    )
    return reseller, router, customer


async def test_delete_customer_deprovisions_inactive_pppoe_before_db_delete(db, monkeypatch):
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.INACTIVE)
    calls = []

    async def _cleanup(payload):
        calls.append(payload)
        return {
            "success": True,
            "disconnect_result": {"success": True, "disconnected": 1},
            "remove_result": {"success": True, "action": "removed"},
        }

    monkeypatch.setattr(customer_routes, "call_pppoe_remove", _cleanup)

    response = await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert response["success"] is True
    assert response["pppoe_deprovisioned"] == "ok"
    assert calls == [{
        "pppoe_username": "Festo",
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
    }]

    remaining = (
        await db.execute(select(Customer).where(Customer.id == customer.id))
    ).scalar_one_or_none()
    assert remaining is None


async def test_delete_customer_keeps_db_row_when_pppoe_cleanup_fails(db, monkeypatch):
    reseller, _, customer = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    async def _cleanup(_payload):
        return {"error": "Failed to connect to router"}

    monkeypatch.setattr(customer_routes, "call_pppoe_remove", _cleanup)

    with pytest.raises(HTTPException) as exc:
        await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert exc.value.status_code == 503
    assert "customer was not deleted" in exc.value.detail

    await db.rollback()
    remaining = (
        await db.execute(select(Customer).where(Customer.id == customer.id))
    ).scalar_one_or_none()
    assert remaining is not None


async def test_cleanup_pppoe_user_endpoint_removes_orphan_router_secret(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    calls = []

    async def _cleanup(payload):
        calls.append(payload)
        return {
            "success": True,
            "disconnect_result": {"success": True, "disconnected": 1},
            "remove_result": {"success": True, "action": "removed"},
        }

    monkeypatch.setattr(pppoe_monitor, "call_pppoe_remove", _cleanup)

    response = await pppoe_monitor.cleanup_pppoe_user(
        router.id,
        "Festo",
        False,
        db,
        _token(reseller),
    )

    assert response["success"] is True
    assert response["username"] == "Festo"
    assert response["customer_present"] is False
    assert calls[0]["pppoe_username"] == "Festo"
    assert calls[0]["router_ip"] == router.ip_address


async def test_cleanup_pppoe_user_endpoint_refuses_existing_customer_without_force(db, monkeypatch):
    reseller, router, _ = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    async def _cleanup(_payload):
        raise AssertionError("cleanup should not run for a DB-owned username without force")

    monkeypatch.setattr(pppoe_monitor, "call_pppoe_remove", _cleanup)

    with pytest.raises(HTTPException) as exc:
        await pppoe_monitor.cleanup_pppoe_user(
            router.id,
            "Festo",
            False,
            db,
            _token(reseller),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["customer"]["name"] == "Festus"

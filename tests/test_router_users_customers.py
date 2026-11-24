"""GET /api/routers/{id}/users reads as people: each router hotspot account named after a
device's MAC carries the billing customer with that MAC on the same router."""
from datetime import datetime, timedelta

import pytest

from app.api.router_operations import _attach_router_user_customers
from app.db.models import ConnectionType, CustomerStatus
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest.mark.asyncio
async def test_router_users_carry_their_customer(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    other_router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    expiry = datetime.utcnow() + timedelta(hours=5)
    await make_customer(db, reseller, plan, router, name="Amina", mac_address="02:00:00:00:00:01",
                        status=CustomerStatus.ACTIVE, expiry=expiry)
    await make_customer(db, reseller, plan, other_router, name="Elsewhere", mac_address="02:00:00:00:00:02",
                        status=CustomerStatus.ACTIVE, expiry=expiry)
    users = [
        {"username": "02:00:00:00:00:01", "profile": "plan_5M_5M", "active": True},
        {"username": "02:00:00:00:00:02", "profile": "plan_5M_5M", "active": False},
        {"username": "default-trial", "profile": "default", "active": False},
    ]

    await _attach_router_user_customers(db, router.id, users)

    assert users[0]["customer"]["name"] == "Amina"
    assert users[0]["customer"]["plan"] == plan.name
    assert users[0]["customer"]["status"] == "active"
    assert users[0]["customer"]["expiry"].startswith(expiry.isoformat()[:16])
    # a customer on another router is not this router's account, and a non-MAC account has none
    assert "customer" not in users[1]
    assert "customer" not in users[2]

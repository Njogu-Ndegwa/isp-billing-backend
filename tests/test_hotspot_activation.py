"""A hotspot customer can be given internet without an M-Pesa payment (Dennis, 21 Nov 2026).

PPPoE and static customers could be activated by hand (cash, paid elsewhere, or no
payment); a hotspot customer could only get time by paying on the portal or a
voucher. POST /api/customers/{id}/activate-hotspot closes that gap and lets the
device on through the same provisioning a paid purchase uses.

Through the real app: register, activate, with only the router faked.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import ConnectionType, Customer, CustomerPayment, CustomerStatus, PaymentMethod
from app.services import hotspot_provisioning, staff_access
from app.services.auth import create_access_token
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MAC = "AA:BB:CC:DD:EE:51"


def _bearer(owner):
    return {"Authorization": f"Bearer {create_access_token(login_token_claims(owner), timedelta(hours=1))}"}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No router, no SMS: record what would have been pushed to the router."""
    staff_access.reset_cache()
    pushed = []

    async def _provision(customer_id, router_id, payload, action="hotspot_payment", attempt_id=None, verify_only=False):
        pushed.append({"customer_id": customer_id, "router_id": router_id, "mac": payload.get("mac_address"), "action": action})
        return {"success": True}

    async def _no_alert(*_a, **_k):
        pass

    from app.services import customer_notifications

    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", _provision)
    monkeypatch.setattr(staff_access, "alert_owner", _no_alert)
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda *_a, **_k: None)
    yield pushed
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


async def _register(client, headers, plan, router, mac=MAC):
    r = await client.post("/api/customers/register", headers=headers, json={
        "name": "Mama Mboga", "phone": "0722000222", "plan_id": plan.id, "router_id": router.id, "mac_address": mac})
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def test_a_hotspot_customer_is_activated_without_paying(client, db, offline):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=300, duration_value=7)
    headers = _bearer(owner)
    router_id = router.id
    customer_id = await _register(client, headers, plan, router)

    r = await client.post(f"/api/customers/{customer_id}/activate-hotspot", headers=headers, json={"payment_method": "none"})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["payment_recorded"] is False and body["provision_result"] == "ok"
    db.expire_all()
    customer = await db.get(Customer, customer_id)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry > datetime.utcnow() + timedelta(days=6)
    assert offline[-1]["mac"] == MAC and offline[-1]["router_id"] == router_id
    rows = (await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))).scalars().all()
    assert len(rows) == 1 and rows[0].amount == 0   # the zero, non-revenue row a free activation leaves


async def test_cash_is_recorded_and_the_wrong_kind_of_customer_is_refused(client, db, offline):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=300, duration_value=7)
    headers = _bearer(owner)
    customer_id = await _register(client, headers, plan, router)

    r = await client.post(f"/api/customers/{customer_id}/activate-hotspot", headers=headers, json={"payment_method": "cash"})
    assert r.status_code == 200 and r.json()["payment_recorded"] is True
    [row] = (await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))).scalars().all()
    assert row.amount == 300 and row.payment_method == PaymentMethod.CASH

    pppoe_plan = await make_plan(db, owner, price=1500, connection_type=ConnectionType.PPPOE)
    r = await client.post("/api/customers/register", headers=headers, json={
        "name": "Home", "phone": "0722000333", "plan_id": pppoe_plan.id, "router_id": router.id})
    assert r.status_code == 200, r.text
    refused = await client.post(f"/api/customers/{r.json()['id']}/activate-hotspot", headers=headers, json={"payment_method": "none"})
    assert refused.status_code == 400 and "activate-pppoe" in refused.json()["detail"]

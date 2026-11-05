"""PPPoE free-trial plans (Dennis, 29 Oct 2026).

A free trial used to be hotspot only, so the admin form flipped a PPPoE plan
back to Hotspot as soon as "Free trial" was picked. A PPPoE free trial is a
price-0 plan with a duration and PPPoE speeds: the reseller registers the
customer on it and activates them. There is no portal claim; activating never
records a payment (zero, non-revenue ledger row, like a portal trial claim).

These go through the real app: create the plan, register the customer,
activate them, with only the router and SMS faked.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerEvent,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    PaymentMethod,
    PaymentStatus,
    Plan,
    PlanType,
)
from app.services import pppoe_provisioning, staff_access
from app.services.auth import create_access_token
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MAC = "AA:BB:CC:DD:EE:42"


def _bearer(owner):
    token = create_access_token(login_token_claims(owner), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No router, no SMS: record what would have been pushed to the router."""
    staff_access.reset_cache()
    pushed = []

    async def _provision(payload):
        pushed.append(payload)
        return {"success": True, "profile": "pppoe_10M_10M"}

    async def _no_alert(*_args, **_kwargs):
        pass

    from app.services import customer_notifications

    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", _provision)
    monkeypatch.setattr(staff_access, "alert_owner", _no_alert)
    monkeypatch.setattr(customer_notifications, "spawn_welcome_message", lambda *_a, **_k: None)
    yield pushed
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


def _trial_body(**overrides):
    body = {
        "name": "UNLIMITED SUPPORT PPPoE",
        "speed": "10M/10M",
        "price": 0,
        "duration_value": 90,
        "duration_unit": "DAYS",
        "connection_type": "pppoe",
        "plan_type": "free_trial",
        "max_shared_users": 2,
    }
    body.update(overrides)
    return body


async def test_reseller_can_create_a_pppoe_free_trial_plan(client, db):
    owner = await make_reseller(db)

    response = await client.post("/api/plans/create", headers=_bearer(owner), json=_trial_body())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["plan_type"] == "free_trial"
    assert body["connection_type"] == "pppoe"
    assert body["price"] == 0
    plan = await db.get(Plan, body["id"])
    assert plan.plan_type == PlanType.FREE_TRIAL
    assert plan.connection_type == ConnectionType.PPPOE
    assert plan.duration_value == 90 and plan.duration_unit == DurationUnit.DAYS
    assert plan.speed == "10M/10M"
    assert plan.max_shared_users == 2


@pytest.mark.parametrize(
    "overrides,detail",
    [
        ({"price": 500}, "A free trial plan must have a price of 0"),
        ({"connection_type": "static_ip"}, "Free trial plans are only available for hotspot and PPPoE"),
    ],
)
async def test_pppoe_trial_must_be_free_and_static_ip_has_no_trials(client, db, overrides, detail):
    owner = await make_reseller(db)

    response = await client.post(
        "/api/plans/create", headers=_bearer(owner), json=_trial_body(**overrides),
    )

    assert response.status_code == 400, response.text
    assert response.json()["detail"] == detail


async def test_existing_trial_can_be_switched_between_hotspot_and_pppoe(client, db):
    owner = await make_reseller(db)
    plan = await make_plan(db, owner, price=0, plan_type=PlanType.FREE_TRIAL, name="Trial")

    to_pppoe = await client.put(
        f"/api/plans/{plan.id}", headers=_bearer(owner), json={"connection_type": "pppoe"},
    )
    assert to_pppoe.status_code == 200, to_pppoe.text
    assert to_pppoe.json()["connection_type"] == "pppoe"

    back = await client.put(
        f"/api/plans/{plan.id}", headers=_bearer(owner), json={"connection_type": "hotspot"},
    )
    assert back.status_code == 200, back.text
    assert back.json()["connection_type"] == "hotspot"


@pytest.mark.parametrize("payment_method", ["cash", "none"])
async def test_register_and_activate_a_pppoe_customer_on_a_free_trial(client, db, offline, payment_method):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    headers = _bearer(owner)

    created = await client.post("/api/plans/create", headers=headers, json=_trial_body())
    assert created.status_code == 200, created.text
    plan_id = created.json()["id"]

    registered = await client.post(
        "/api/customers/register",
        headers=headers,
        json={"name": "Support line", "phone": "0712345678", "plan_id": plan_id, "router_id": router.id},
    )
    assert registered.status_code == 200, registered.text
    customer_id = registered.json()["id"]
    assert registered.json()["pppoe_username"]
    assert registered.json()["status"] == "inactive"

    before = datetime.utcnow()
    activated = await client.post(
        f"/api/customers/{customer_id}/activate-pppoe",
        headers=headers,
        json={"payment_method": payment_method},
    )

    assert activated.status_code == 200, activated.text
    body = activated.json()
    assert body["status"] == "active"
    # Whatever the form sent, a free trial never records money.
    assert body["payment_recorded"] is False
    assert body["provision_result"] == "ok"

    db.expire_all()
    customer = await db.get(Customer, customer_id)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry >= before + timedelta(days=90) - timedelta(seconds=5)
    assert customer.expiry <= datetime.utcnow() + timedelta(days=90, seconds=5)

    [row] = (
        await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))
    ).scalars().all()
    assert row.amount == 0
    assert row.counts_as_revenue is False
    assert row.status == PaymentStatus.COMPLETED
    assert row.payment_method == PaymentMethod.OTHER
    assert row.payment_reference == f"FREE-TRIAL-{plan_id}"
    assert row.notes.startswith("Free trial: no payment collected")

    # The secret went to the router with the plan's PPPoE speed and device limit.
    [payload] = offline
    assert payload["pppoe_username"] == customer.pppoe_username
    assert payload["bandwidth_limit"] == "10M/10M"
    assert payload["max_devices"] == 2

    [event] = (
        await db.execute(
            select(CustomerEvent).where(
                CustomerEvent.customer_id == customer_id,
                CustomerEvent.event_type == "pppoe_activated",
            )
        )
    ).scalars().all()
    assert "free trial, no payment" in event.message
    assert event.details["free_trial"] is True and event.details["no_payment"] is True


async def test_paid_pppoe_activation_still_records_cash(client, db):
    """Unchanged: only free-trial plans skip the payment."""
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await make_plan(db, owner, price=1500, connection_type=ConnectionType.PPPOE)
    headers = _bearer(owner)
    registered = await client.post(
        "/api/customers/register",
        headers=headers,
        json={"name": "Paying", "phone": "0722000111", "plan_id": plan.id, "router_id": router.id},
    )
    assert registered.status_code == 200, registered.text

    activated = await client.post(
        f"/api/customers/{registered.json()['id']}/activate-pppoe",
        headers=headers,
        json={"payment_method": "cash"},
    )

    assert activated.status_code == 200, activated.text
    assert activated.json()["payment_recorded"] is True
    [row] = (
        await db.execute(
            select(CustomerPayment).where(CustomerPayment.customer_id == registered.json()["id"])
        )
    ).scalars().all()
    assert row.amount == 1500 and row.payment_method == PaymentMethod.CASH


async def test_pppoe_trial_is_not_offered_or_claimable_on_the_hotspot_portal(db):
    from app.services.free_trial import claim_free_trial, get_trial_eligibility

    owner = await make_reseller(db)
    router = await make_router(db, owner)
    hotspot_trial = await make_plan(db, owner, price=0, plan_type=PlanType.FREE_TRIAL, name="Hotspot trial")
    pppoe_trial = await make_plan(
        db, owner, price=0, plan_type=PlanType.FREE_TRIAL,
        connection_type=ConnectionType.PPPOE, name="PPPoE trial",
    )

    eligibility = await get_trial_eligibility(db, router.id, MAC)
    assert [t["plan_id"] for t in eligibility["trials"]] == [hotspot_trial.id]

    result = await claim_free_trial(db, pppoe_trial.id, MAC, router.id)
    assert result["success"] is False
    assert result["error"] == "Free trials are only available on hotspot"

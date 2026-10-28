"""Activate without payment (Dennis, 28 Oct 2026).

A reseller can switch a PPPoE or static-IP customer on for the plan's period
without recording money: a free month, a comp, or money already recorded
somewhere else. The ledger gets the same zero-amount, non-revenue row the
paid-until activation writes, so revenue, the dashboard and the subscription
charge never see it. The double-renewal guard from #273 still applies.

Most of these go through the real app (auth, staff middleware, handlers).
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import (
    ConnectionType,
    CustomerEvent,
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
    ResellerStaff,
)
from app.api import customer_routes
from app.services import pppoe_provisioning, staff_access
from app.services.auth import create_access_token, pwd_context
from app.services.subscription import calculate_reseller_charges
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


async def _staff_token(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Front desk", email=f"desk{owner.id}@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    return create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No router, no SMS: the provisioning call and owner alerts are faked."""
    staff_access.reset_cache()

    async def _provision(_payload):
        return {"success": True, "profile": "pppoe_5M_5M"}

    async def _static(_customer_id, **_kw):
        return {"success": True}

    async def _no_alert(*_args, **_kwargs):
        pass

    from app.services import fup

    async def _restore(_db, _customer, _plan):
        return {"success": True}

    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", _provision)
    monkeypatch.setattr(customer_routes, "provision_static_customer", _static)
    monkeypatch.setattr(staff_access, "alert_owner", _no_alert)
    monkeypatch.setattr(fup, "restore_normal_profile", _restore)
    yield
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


async def _pppoe_customer(db, *, status=CustomerStatus.INACTIVE, expiry=None, owner=None):
    owner = owner or await make_reseller(db)
    plan = await make_plan(db, owner, price=1500, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=status, expiry=expiry, mac_address=None,
        pppoe_username=f"comp{owner.id}", pppoe_password="secret", name="Comp client",
    )
    return owner, plan, customer


async def _payments(db, customer_id):
    return (
        await db.execute(
            select(CustomerPayment)
            .where(CustomerPayment.customer_id == customer_id)
            .execution_options(populate_existing=True)
        )
    ).scalars().all()


async def _events(db, customer_id, event_type):
    return (
        await db.execute(
            select(CustomerEvent).where(
                CustomerEvent.customer_id == customer_id, CustomerEvent.event_type == event_type,
            )
        )
    ).scalars().all()


def _activate(client, token, customer, kind="pppoe", **body):
    return client.post(
        f"/api/customers/{customer.id}/activate-{kind}",
        headers=_bearer(token),
        json={"payment_method": "none", **body},
    )


# --- the ledger row ----------------------------------------------------------


async def test_activate_without_payment_writes_only_a_zero_non_revenue_row(client, db):
    owner, plan, customer = await _pppoe_customer(db, expiry=datetime.utcnow() - timedelta(days=3))
    days = plan.duration_value
    before = datetime.utcnow()

    response = await _activate(client, _owner_token(owner), customer)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "active"
    assert body["payment_recorded"] is False
    db.expire_all()
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    # The plan's full period, same as a paid activation.
    assert customer.expiry >= before + timedelta(days=days) - timedelta(seconds=5)

    [row] = await _payments(db, customer.id)
    assert row.amount == 0
    assert row.counts_as_revenue is False
    assert row.status == PaymentStatus.COMPLETED
    assert row.payment_method == PaymentMethod.OTHER
    assert row.payment_reference == f"NO-PAYMENT-{customer.id}"
    assert row.days_paid_for == days
    assert "No payment collected" in row.notes

    [event] = await _events(db, customer.id, "pppoe_activated")
    assert "without payment by" in event.message
    assert event.details["no_payment"] is True
    assert event.details["payment_id"] == row.id


async def test_no_payment_row_with_an_amount_is_ever_created(client, db):
    owner, _, customer = await _pppoe_customer(db)

    response = await _activate(client, _owner_token(owner), customer, notes="Free month for referral")

    assert response.status_code == 200, response.text
    rows = await _payments(db, customer.id)
    assert rows and all(row.amount == 0 for row in rows)
    assert "Free month for referral" in rows[0].notes


async def test_payment_method_none_is_case_and_space_insensitive(client, db):
    owner, _, customer = await _pppoe_customer(db)

    response = await _activate(client, _owner_token(owner), customer, payment_method=" None ")

    assert response.status_code == 200, response.text
    [row] = await _payments(db, customer.id)
    assert row.amount == 0 and row.counts_as_revenue is False


# --- revenue ------------------------------------------------------------------


async def test_revenue_and_subscription_charge_are_unchanged(client, db):
    owner, _, customer = await _pppoe_customer(db)
    _, _, paid_customer = await _pppoe_customer(db, owner=owner)
    token = _owner_token(owner)
    period_start = datetime.utcnow() - timedelta(days=1)
    period_end = datetime.utcnow() + timedelta(days=1)

    async def revenue():
        response = await client.get("/api/dashboard/overview", headers=_bearer(token))
        assert response.status_code == 200, response.text
        return response.json()["revenue"]

    async def hotspot_revenue():
        charges = await calculate_reseller_charges(db, owner.id, period_start, period_end)
        return charges["hotspot_revenue"], charges["pricing_rule"]["hotspot_revenue_local"]

    revenue_before = await revenue()
    charge_before = await hotspot_revenue()

    assert (await _activate(client, token, customer)).status_code == 200
    assert await revenue() == revenue_before
    assert await hotspot_revenue() == charge_before

    # Control: a cash activation does move revenue, so the check above is real.
    cash = await _activate(client, token, paid_customer, payment_method="cash")
    assert cash.status_code == 200, cash.text
    assert (await revenue())["all_time"] == revenue_before["all_time"] + 1500


# --- double renewal guard ----------------------------------------------------


async def test_double_renew_guard_still_applies_to_no_payment(client, db):
    expiry = datetime.utcnow() + timedelta(days=12)
    owner, _, customer = await _pppoe_customer(db, status=CustomerStatus.ACTIVE, expiry=expiry)

    response = await _activate(client, _owner_token(owner), customer)

    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "customer_already_active"
    assert "without recording a payment" in detail["message"]
    db.expire_all()
    await db.refresh(customer)
    assert customer.expiry == expiry
    assert await _payments(db, customer.id) == []


async def test_double_click_on_no_payment_is_refused(client, db):
    owner, _, customer = await _pppoe_customer(db, expiry=datetime.utcnow() - timedelta(days=1))
    token = _owner_token(owner)

    assert (await _activate(client, token, customer)).status_code == 200
    second = await _activate(client, token, customer)

    assert second.status_code == 409, second.text
    detail = second.json()["detail"]
    assert detail["code"] == "customer_already_paid"
    assert "was activated without payment" in detail["message"]
    assert len(await _payments(db, customer.id)) == 1


async def test_force_adds_a_no_payment_period_on_top(client, db):
    expiry = datetime.utcnow() + timedelta(days=5)
    owner, plan, customer = await _pppoe_customer(db, status=CustomerStatus.ACTIVE, expiry=expiry)
    days = plan.duration_value

    response = await _activate(client, _owner_token(owner), customer, force=True)

    assert response.status_code == 200, response.text
    db.expire_all()
    await db.refresh(customer)
    assert customer.expiry > expiry + timedelta(days=days - 1)
    [row] = await _payments(db, customer.id)
    assert row.amount == 0 and row.counts_as_revenue is False
    [event] = await _events(db, customer.id, "pppoe_activated")
    assert "confirmed although already active/paid" in event.message


# --- static IP ----------------------------------------------------------------


async def test_static_ip_activate_without_payment(client, db):
    owner = await make_reseller(db)
    plan = await make_plan(db, owner, price=2000, connection_type=ConnectionType.STATIC_IP, speed="10M/10M")
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.INACTIVE, expiry=None,
        static_ip="192.168.2.31",
    )

    response = await _activate(client, _owner_token(owner), customer, kind="static")

    assert response.status_code == 200, response.text
    assert response.json()["payment_recorded"] is False
    [row] = await _payments(db, customer.id)
    assert row.amount == 0 and row.counts_as_revenue is False
    [event] = await _events(db, customer.id, "static_ip_activated")
    assert "without payment by" in event.message


async def test_static_ip_guard_applies_to_no_payment(client, db):
    owner = await make_reseller(db)
    plan = await make_plan(db, owner, connection_type=ConnectionType.STATIC_IP, speed="10M/10M")
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=20), static_ip="192.168.2.32",
    )

    response = await _activate(client, _owner_token(owner), customer, kind="static")

    assert response.status_code == 409, response.text
    assert await _payments(db, customer.id) == []


# --- staff -------------------------------------------------------------------


async def test_staff_with_customers_manage_can_activate_without_payment(client, db):
    owner, _, customer = await _pppoe_customer(db)
    token = await _staff_token(db, owner, ["customers.view", "customers.manage"])

    response = await _activate(client, token, customer)

    assert response.status_code == 200, response.text
    [row] = await _payments(db, customer.id)
    assert row.amount == 0 and row.reseller_id == owner.id
    [event] = await _events(db, customer.id, "pppoe_activated")
    assert "without payment by Front desk (staff)" in event.message


async def test_staff_without_customers_manage_is_refused(client, db):
    owner, _, customer = await _pppoe_customer(db)
    token = await _staff_token(db, owner, ["customers.view"])

    response = await _activate(client, token, customer)

    assert response.status_code == 403, response.text
    assert await _payments(db, customer.id) == []


async def test_staff_of_another_reseller_cannot_activate(client, db):
    owner, _, customer = await _pppoe_customer(db)
    other = await make_reseller(db)
    token = await _staff_token(db, other, ["customers.view", "customers.manage"])

    response = await _activate(client, token, customer)

    assert response.status_code == 404, response.text
    assert await _payments(db, customer.id) == []


# --- existing behaviour kept ----------------------------------------------------


async def test_cash_activation_still_records_the_plan_price(client, db):
    owner, _, customer = await _pppoe_customer(db)

    response = await _activate(client, _owner_token(owner), customer, payment_method="cash")

    assert response.status_code == 200, response.text
    assert response.json()["payment_recorded"] is True
    [row] = await _payments(db, customer.id)
    assert row.amount == 1500 and row.counts_as_revenue is True
    assert row.payment_method == PaymentMethod.CASH


async def test_unknown_method_message_mentions_none(client, db):
    owner, _, customer = await _pppoe_customer(db)

    response = await _activate(client, _owner_token(owner), customer, payment_method="mpesa")

    assert response.status_code == 400
    assert "'none'" in response.json()["detail"]

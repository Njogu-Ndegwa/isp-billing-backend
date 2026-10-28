"""Manual activation must not double-renew, mislabel money, or cross tenants.

Regressions from 27 Oct 2026 (reseller 722, customer 47890): the customer
paid by C2B and was auto-activated; 19 seconds later the reseller pressed
Activate on a stale customer list and the backend added a second 30 days
plus a KES 1,000 CASH revenue row with no money behind it.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import customer_routes, payment_routes
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
)
from app.services import pppoe_provisioning
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


def _as(user):
    async def _get(_token, _db):
        return user
    return _get


async def _seed_pppoe(db, *, status, expiry):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, price=1000, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=status, expiry=expiry, mac_address=None,
        pppoe_username="kenjoe47890", pppoe_password="secret", name="Kenjoe client",
    )
    return reseller, plan, router, customer


async def _payments(db, customer_id):
    return (
        await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer_id))
    ).scalars().all()


@pytest.fixture
def router_ok(monkeypatch):
    async def _provision(payload):
        return {"success": True, "profile": "pppoe_5M_5M"}

    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", _provision)

    # on_renewal reverts FUP on the router; keep these tests off the network.
    from app.services import fup

    async def _restore(_db, _customer, _plan):
        return {"success": True}

    monkeypatch.setattr(fup, "restore_normal_profile", _restore)


async def _add_payment(db, reseller, customer, plan, *, seconds_ago, method=PaymentMethod.MOBILE_MONEY):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        plan_id=plan.id,
        amount=1000.0,
        payment_method=method,
        payment_reference="TJR7C2BXYZ",
        payment_date=datetime.utcnow() - timedelta(seconds=seconds_ago),
        days_paid_for=30,
        status=PaymentStatus.COMPLETED,
    )
    db.add(payment)
    await db.commit()
    return payment


# --- 1. double renewal -------------------------------------------------------


async def test_activate_refuses_customer_who_just_paid_by_c2b(db, monkeypatch, router_ok):
    expiry = datetime.utcnow() + timedelta(days=30)
    reseller, plan, _, customer = await _seed_pppoe(db, status=CustomerStatus.ACTIVE, expiry=expiry)
    await _add_payment(db, reseller, customer, plan, seconds_ago=19)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    with pytest.raises(HTTPException) as exc:
        await customer_routes.activate_pppoe_customer(
            customer.id, customer_routes.ActivatePPPoERequest(payment_method="cash"), db, "t",
        )

    assert exc.value.status_code == 409
    detail = exc.value.detail
    assert detail["code"] == "customer_already_paid"
    assert detail["expiry"] == expiry.isoformat()
    assert detail["last_payment_method"] == "mobile_money"
    assert "already paid" in detail["message"]
    await db.refresh(customer)
    assert customer.expiry == expiry, "expiry must not move on a refused activation"
    assert len(await _payments(db, customer.id)) == 1, "no fake CASH row"


async def test_activate_refuses_customer_with_paid_time_left(db, monkeypatch, router_ok):
    expiry = datetime.utcnow() + timedelta(days=12)
    reseller, _, _, customer = await _seed_pppoe(db, status=CustomerStatus.ACTIVE, expiry=expiry)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    with pytest.raises(HTTPException) as exc:
        await customer_routes.activate_pppoe_customer(
            customer.id, customer_routes.ActivatePPPoERequest(), db, "t",
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "customer_already_active"
    assert exc.value.detail["last_payment_at"] is None
    assert await _payments(db, customer.id) == []


async def test_recent_payment_blocks_even_when_status_is_not_active(db, monkeypatch, router_ok):
    """A double click: the first activation's row is seconds old."""
    reseller, plan, _, customer = await _seed_pppoe(
        db, status=CustomerStatus.INACTIVE, expiry=datetime.utcnow() - timedelta(days=2),
    )
    await _add_payment(db, reseller, customer, plan, seconds_ago=30, method=PaymentMethod.CASH)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    with pytest.raises(HTTPException) as exc:
        await customer_routes.activate_pppoe_customer(
            customer.id, customer_routes.ActivatePPPoERequest(), db, "t",
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "customer_already_paid"


async def test_force_records_a_deliberate_second_payment(db, monkeypatch, router_ok):
    expiry = datetime.utcnow() + timedelta(days=30)
    reseller, plan, _, customer = await _seed_pppoe(db, status=CustomerStatus.ACTIVE, expiry=expiry)
    await _add_payment(db, reseller, customer, plan, seconds_ago=19)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    out = await customer_routes.activate_pppoe_customer(
        customer.id, customer_routes.ActivatePPPoERequest(payment_method="cash", force=True), db, "t",
    )

    assert out["success"] is True
    await db.refresh(customer)
    assert customer.expiry > expiry + timedelta(days=29)
    assert len(await _payments(db, customer.id)) == 2


async def test_old_payment_and_expired_customer_activate_normally(db, monkeypatch, router_ok):
    reseller, plan, _, customer = await _seed_pppoe(
        db, status=CustomerStatus.INACTIVE, expiry=datetime.utcnow() - timedelta(days=1),
    )
    await _add_payment(db, reseller, customer, plan, seconds_ago=31 * 86400)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    out = await customer_routes.activate_pppoe_customer(
        customer.id, customer_routes.ActivatePPPoERequest(), db, "t",
    )

    assert out["success"] is True and out["status"] == "active"
    assert len(await _payments(db, customer.id)) == 2


async def test_customer_in_grace_can_be_activated_without_force(db, monkeypatch, router_ok):
    """Paid time ended, grace still open: they owe, so no confirmation needed."""
    expiry = datetime.utcnow() - timedelta(hours=2)
    reseller, _, _, customer = await _seed_pppoe(db, status=CustomerStatus.ACTIVE, expiry=expiry)
    customer.grace_period_minutes = 24 * 60
    await db.commit()
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    out = await customer_routes.activate_pppoe_customer(
        customer.id, customer_routes.ActivatePPPoERequest(), db, "t",
    )

    assert out["success"] is True
    await db.refresh(customer)
    # Grace keeps the billing date: extended from the paid expiry.
    assert abs((customer.expiry - (expiry + timedelta(days=30))).total_seconds()) < 1


async def test_static_activation_has_the_same_guard(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP, speed="10M/10M")
    router = await make_router(db, reseller)
    expiry = datetime.utcnow() + timedelta(days=20)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=expiry,
        static_ip="192.168.2.24",
    )
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    async def _provision(cid, **kw):
        raise AssertionError("router must not be touched on a refused activation")

    monkeypatch.setattr(customer_routes, "provision_static_customer", _provision)

    with pytest.raises(HTTPException) as exc:
        await customer_routes.activate_static_customer(
            customer.id, customer_routes.ActivatePPPoERequest(), db, "t",
        )
    assert exc.value.status_code == 409
    assert await _payments(db, customer.id) == []


# --- 2. payment-method mapping ----------------------------------------------


@pytest.mark.parametrize("label", ["mpesa", "voucher", "mobile_money", "bitcoin"])
async def test_misleading_payment_methods_are_refused_not_saved_as_cash(
    db, monkeypatch, router_ok, label,
):
    reseller, _, _, customer = await _seed_pppoe(
        db, status=CustomerStatus.INACTIVE, expiry=None,
    )
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    with pytest.raises(HTTPException) as exc:
        await customer_routes.activate_pppoe_customer(
            customer.id, customer_routes.ActivatePPPoERequest(payment_method=label), db, "t",
        )

    assert exc.value.status_code == 400
    assert "manual activation" in exc.value.detail
    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE
    assert await _payments(db, customer.id) == []


@pytest.mark.parametrize("label, stored", [
    ("cash", PaymentMethod.CASH),
    ("Cash", PaymentMethod.CASH),
    ("other", PaymentMethod.OTHER),
])
async def test_honest_payment_methods_are_stored_as_given(db, monkeypatch, router_ok, label, stored):
    reseller, _, _, customer = await _seed_pppoe(db, status=CustomerStatus.INACTIVE, expiry=None)
    monkeypatch.setattr(customer_routes, "get_current_user", _as(reseller))

    await customer_routes.activate_pppoe_customer(
        customer.id, customer_routes.ActivatePPPoERequest(payment_method=label), db, "t",
    )

    [payment] = await _payments(db, customer.id)
    assert payment.payment_method == stored


# --- 3. initiate-payment tenant check ---------------------------------------


def _stk_request(customer):
    return payment_routes.InitiateMpesaPaymentRequest(
        customer_id=customer.id, amount=1000, phone="254712345678",
    )


async def test_initiate_payment_refuses_another_resellers_customer(db, monkeypatch):
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway

    owner = await make_reseller(db)
    intruder = await make_reseller(db)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
    )
    sent = []

    async def _stk(**kwargs):
        sent.append(kwargs)
        return {"checkoutRequestId": "ws_CO_should_not_happen"}

    async def _no_method(_db, _router_id):
        return None

    monkeypatch.setattr(payment_routes, "get_current_user", _as(intruder))
    monkeypatch.setattr(payment_gateway, "resolve_collection_payment_method", _no_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", _stk)

    with pytest.raises(HTTPException) as exc:
        await payment_routes.initiate_mpesa_payment_api(_stk_request(customer), db=db, token="t")

    assert exc.value.status_code == 403
    assert sent == [], "no STK prompt for someone else's customer"
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE


async def test_admin_may_initiate_payment_for_any_customer(db, monkeypatch):
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway

    admin = await make_admin(db)
    owner = await make_reseller(db)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner)
    customer = await make_customer(db, owner, plan, router)

    async def _stk(**_kwargs):
        return {"checkoutRequestId": "ws_CO_admin", "merchantRequestId": "m-admin"}

    async def _no_method(_db, _router_id):
        return None

    monkeypatch.setattr(payment_routes, "get_current_user", _as(admin))
    monkeypatch.setattr(payment_gateway, "resolve_collection_payment_method", _no_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", _stk)

    out = await payment_routes.initiate_mpesa_payment_api(_stk_request(customer), db=db, token="t")
    assert out["checkout_request_id"] == "ws_CO_admin"


async def test_failed_gateway_initiation_leaves_customer_status_alone(db, monkeypatch):
    from app.services import payment_gateway

    owner = await make_reseller(db)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
    )

    async def _method(_db, _router_id):
        return SimpleNamespace(id=1, method_type="mpesa_paybill")

    async def _fail(**_kwargs):
        raise RuntimeError("Safaricom 503")

    monkeypatch.setattr(payment_routes, "get_current_user", _as(owner))
    monkeypatch.setattr(payment_gateway, "resolve_collection_payment_method", _method)
    monkeypatch.setattr(payment_gateway, "initiate_customer_payment", _fail)

    with pytest.raises(HTTPException) as exc:
        await payment_routes.initiate_mpesa_payment_api(_stk_request(customer), db=db, token="t")

    assert exc.value.status_code == 500
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE


# --- 4. staff tokens (#272) ---------------------------------------------------
# A staff JWT carries the owner's user_id, so get_current_user resolves to the
# owner and the ownership check compares against the owner, never staff_id.
# These go through the real app so the staff middleware runs too.


async def _staff_token(db, owner, permissions):
    from app.db.models import ResellerStaff
    from app.services import staff_access
    from app.services.auth import create_access_token, pwd_context

    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Front desk", email=f"desk{owner.id}@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    return create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))


@pytest.fixture
def staff_app(engine, monkeypatch):
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway, staff_access

    staff_access.reset_cache()
    sent = []

    async def _no_alert(*_args, **_kwargs):
        pass

    async def _no_method(_db, _router_id):
        return None

    async def _stk(**kwargs):
        sent.append(kwargs)
        return {"checkoutRequestId": f"ws_CO_staff_{len(sent)}", "merchantRequestId": "m-staff"}

    monkeypatch.setattr(staff_access, "alert_owner", _no_alert)
    monkeypatch.setattr(payment_gateway, "resolve_collection_payment_method", _no_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", _stk)
    yield sent
    staff_access.reset_cache()


async def _post_initiate(token, customer):
    import main
    from httpx import ASGITransport, AsyncClient

    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
        return await client.post(
            "/api/mpesa/initiate-payment",
            headers={"Authorization": f"Bearer {token}"},
            json={"customer_id": customer.id, "amount": 1000, "phone": "254712345678"},
        )


async def test_staff_may_initiate_payment_for_their_owners_customer(db, staff_app):
    owner = await make_reseller(db)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner)
    customer = await make_customer(db, owner, plan, router)
    token = await _staff_token(db, owner, ["customers.view", "customers.manage"])

    response = await _post_initiate(token, customer)

    assert response.status_code == 200, response.text
    assert response.json()["checkout_request_id"] == "ws_CO_staff_1"
    assert len(staff_app) == 1


async def test_staff_of_another_reseller_gets_403_and_no_stk(db, staff_app):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
    )
    token = await _staff_token(db, other, ["customers.view", "customers.manage"])

    response = await _post_initiate(token, customer)

    assert response.status_code == 403, response.text
    # The handler's ownership check, not the staff permission middleware.
    assert "your own customers" in response.json()["detail"]
    assert staff_app == [], "no STK prompt for another reseller's customer"
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE

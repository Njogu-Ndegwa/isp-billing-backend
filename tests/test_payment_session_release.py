"""M-Pesa requests must not pin a pooled DB connection across Daraja I/O."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.db.models import (
    Customer,
    CustomerStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def test_existing_customer_legacy_stk_releases_session(db, monkeypatch):
    from app.api import payment_routes
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    async def current_user(_token, _db):
        return reseller

    async def no_assigned_method(_db, _router_id):
        return None

    async def stk(**_kwargs):
        assert not db.in_transaction(), "DB transaction remained open during STK push"
        return {
            "checkoutRequestId": "ws_CO_existing_release",
            "merchantRequestId": "merchant-existing",
        }

    monkeypatch.setattr(payment_routes, "get_current_user", current_user)
    monkeypatch.setattr(payment_gateway, "resolve_router_payment_method", no_assigned_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", stk)

    response = await payment_routes.initiate_mpesa_payment_api(
        payment_routes.InitiateMpesaPaymentRequest(
            customer_id=customer.id,
            amount=100,
            phone="254712345678",
        ),
        db=db,
        token="test-token",
    )

    assert response["checkout_request_id"] == "ws_CO_existing_release"


async def test_hotspot_legacy_stk_releases_session(db, monkeypatch):
    from app.api import payment_routes
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        mac_address="AA:BB:CC:DD:EE:41",
    )

    async def no_assigned_method(_db, _router_id):
        return None

    async def stk(**_kwargs):
        assert not db.in_transaction(), "DB transaction remained open during STK push"
        return SimpleNamespace(
            checkout_request_id="ws_CO_hotspot_release",
            merchant_request_id="merchant-hotspot",
        )

    monkeypatch.setattr(payment_gateway, "resolve_router_payment_method", no_assigned_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", stk)

    response = await payment_routes.register_hotspot_and_pay_api(
        payment_routes.HotspotPaymentRequest(
            phone="254712345678",
            mac_address=customer.mac_address,
            plan_id=plan.id,
            router_id=router.id,
            payment_method="mobile_money",
        ),
        db=db,
    )

    assert response["status"] == CustomerStatus.PENDING.value


@pytest.mark.parametrize(
    "method_type",
    [
        ResellerPaymentMethodType.MPESA_TILL,
        ResellerPaymentMethodType.MPESA_PAYBILL,
        ResellerPaymentMethodType.BANK_ACCOUNT,
    ],
)
async def test_assigned_system_mpesa_releases_session(
    db, monkeypatch, method_type
):
    from app.services import mpesa as mpesa_service
    from app.services.payment_gateway import initiate_customer_payment

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    payment_method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=method_type,
        label="assigned system collection",
        is_active=True,
    )
    db.add(payment_method)
    await db.commit()
    await db.refresh(payment_method)

    # Re-open a transaction exactly as the route does before dispatch.
    await db.execute(select(Customer.id).where(Customer.id == customer.id))

    async def stk(**_kwargs):
        assert not db.in_transaction(), "DB transaction remained open during STK push"
        return SimpleNamespace(
            checkout_request_id=f"ws_CO_{method_type.value}_release",
            merchant_request_id="merchant-assigned",
        )

    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", stk)

    result = await initiate_customer_payment(
        db=db,
        payment_method=payment_method,
        customer=customer,
        router=router,
        phone="254712345678",
        amount=100,
        reference="PAYMENT-SESSION-RELEASE",
    )

    assert result["gateway"] == "mpesa"


async def test_assigned_reseller_keys_mpesa_releases_session(db, monkeypatch):
    from app.services import mpesa as mpesa_service
    from app.services.payment_gateway import encrypt_credential, initiate_customer_payment

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    payment_method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="assigned reseller collection",
        is_active=True,
        mpesa_shortcode="777777",
        mpesa_passkey_encrypted=encrypt_credential("passkey"),
        mpesa_consumer_key_encrypted=encrypt_credential("consumer-key"),
        mpesa_consumer_secret_encrypted=encrypt_credential("consumer-secret"),
    )
    db.add(payment_method)
    await db.commit()
    await db.refresh(payment_method)

    await db.execute(select(Customer.id).where(Customer.id == customer.id))

    async def stk(**kwargs):
        assert not db.in_transaction(), "DB transaction remained open during STK push"
        assert kwargs["shortcode"] == "777777"
        return SimpleNamespace(
            checkout_request_id="ws_CO_reseller_keys_release",
            merchant_request_id="merchant-reseller-keys",
        )

    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", stk)

    result = await initiate_customer_payment(
        db=db,
        payment_method=payment_method,
        customer=customer,
        router=router,
        phone="254712345678",
        amount=100,
        reference="PAYMENT-SESSION-RELEASE",
    )

    assert result["gateway"] == "mpesa"


async def test_failed_hotspot_stk_restores_existing_customer(db, monkeypatch):
    from app.api import payment_routes
    from app.services import mpesa as mpesa_service
    from app.services import payment_gateway

    reseller = await make_reseller(db)
    old_router = await make_router(db, reseller)
    new_router = await make_router(db, reseller)
    old_plan = await make_plan(db, reseller, name="Current plan")
    new_plan = await make_plan(db, reseller, name="Attempted plan")
    customer = await make_customer(
        db,
        reseller,
        old_plan,
        old_router,
        status=CustomerStatus.ACTIVE,
        mac_address="AA:BB:CC:DD:EE:42",
        phone="254700000001",
        name="Original name",
    )
    customer_id = customer.id
    old_plan_id = old_plan.id
    old_router_id = old_router.id

    async def no_assigned_method(_db, _router_id):
        return None

    async def failed_stk(**_kwargs):
        assert not db.in_transaction(), "DB transaction remained open during failed STK push"
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(payment_gateway, "resolve_router_payment_method", no_assigned_method)
    monkeypatch.setattr(mpesa_service, "initiate_stk_push", failed_stk)

    with pytest.raises(HTTPException) as exc:
        await payment_routes.register_hotspot_and_pay_api(
            payment_routes.HotspotPaymentRequest(
                phone="254700000999",
                name="Changed name",
                mac_address=customer.mac_address,
                plan_id=new_plan.id,
                router_id=new_router.id,
                payment_method="mobile_money",
            ),
            db=db,
        )

    assert exc.value.status_code == 400
    db.expire_all()
    restored = (
        await db.execute(select(Customer).where(Customer.id == customer_id))
    ).scalar_one()
    assert restored.status == CustomerStatus.ACTIVE
    assert restored.plan_id == old_plan_id
    assert restored.router_id == old_router_id
    assert restored.phone == "254700000001"
    assert restored.name == "Original name"

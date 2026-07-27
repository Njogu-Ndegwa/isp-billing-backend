"""Captive-portal collection for MPESA_TILL payment methods (2026-07-22).

MPESA_TILL was added as a B2B payout destination (BusinessBuyGoods), but the
collection dispatcher `initiate_customer_payment` was never taught about it —
every STK push on a router assigned a till method raised
"Unsupported payment method type" and portal payments 400'd for six resellers.

A till method must collect exactly like MPESA_PAYBILL / BANK_ACCOUNT: the
platform shortcode takes the STK push and the reseller is paid by the nightly
B2B payout.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.db.models import (
    CollectionMode,
    MpesaTransaction,
    MpesaTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize(
    "method_type",
    [
        ResellerPaymentMethodType.MPESA_TILL,
        ResellerPaymentMethodType.MPESA_PAYBILL,
        ResellerPaymentMethodType.BANK_ACCOUNT,
    ],
)
async def test_system_collected_types_initiate_stk_push(db, monkeypatch, method_type):
    from app.services import mpesa as mpesa_service
    from app.services.payment_gateway import initiate_customer_payment

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    pm = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=method_type,
        label="collection method",
        is_active=True,
        mpesa_till_number="9285575",
        mpesa_paybill_number="9285575",
    )
    db.add(pm)
    await db.commit()
    await db.refresh(pm)

    stk = AsyncMock(return_value=SimpleNamespace(
        checkout_request_id=f"ws_CO_test_{method_type.value}",
        merchant_request_id="merchant-001",
    ))
    monkeypatch.setattr(mpesa_service, "initiate_stk_push_direct", stk)

    result = await initiate_customer_payment(
        db=db,
        payment_method=pm,
        customer=customer,
        router=router,
        phone="254712345678",
        amount=10.0,
        reference=f"HOTSPOT-{customer.id}-TEST",
    )
    await db.commit()

    assert result["gateway"] == "mpesa"
    assert result["collection_mode"] == CollectionMode.SYSTEM_COLLECTED
    stk.assert_awaited_once()
    # System-collected: the platform shortcode takes the money, so no
    # reseller credentials/shortcode are passed to the STK push.
    assert "shortcode" not in stk.await_args.kwargs

    txn = (await db.execute(
        select(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == f"ws_CO_test_{method_type.value}"
        )
    )).scalar_one()
    assert txn.customer_id == customer.id
    assert txn.status == MpesaTransactionStatus.pending


async def test_every_method_type_has_a_collection_path():
    """Exhaustiveness guard: a ResellerPaymentMethodType with no branch in
    initiate_customer_payment means routers assigned that method 400 on every
    portal payment (how mpesa_till broke six resellers on 2026-07-21). Adding
    an enum value must come with a collection path — or an explicit entry here.
    """
    import inspect

    from app.services import payment_gateway

    source = inspect.getsource(payment_gateway.initiate_customer_payment)
    missing = [
        m.name for m in ResellerPaymentMethodType
        if f"ResellerPaymentMethodType.{m.name}" not in source
    ]
    assert not missing, (
        f"initiate_customer_payment has no dispatch branch for: {missing}. "
        "Every payment method type a router can be assigned must either "
        "collect payments or be explicitly rejected at assignment time."
    )

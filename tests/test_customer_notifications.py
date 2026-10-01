from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.db.models import (
    ConnectionType,
    CustomerExpirySmsSettings,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    MessagingProviderAccount,
    MessagingSettings,
    PaymentMethod,
    PaymentStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    SmsCreditAccount,
    SmsMessage,
)
from app.services import customer_notifications
from tests.factories import (
    make_customer,
    make_plan,
    make_reseller,
    make_router,
    make_sms_account,
)


pytestmark = pytest.mark.asyncio


async def _reseller(db, *, credits=5, **prefs):
    reseller = await make_reseller(db, organization_name="Twork Links")
    await make_sms_account(db, reseller, balance=credits)
    if await db.get(MessagingSettings, 1) is None:
        db.add(MessagingSettings(id=1, enabled=True))
    defaults = dict(
        enabled=False,
        reminder_offsets_minutes=[1440],
        send_at_expiry=True,
        payment_receipt_enabled=True,
        receipt_include_hotspot=False,
        welcome_enabled=True,
    )
    defaults.update(prefs)
    db.add(CustomerExpirySmsSettings(user_id=reseller.id, **defaults))
    await db.commit()
    return reseller


async def _pay(db, reseller, customer, plan, *, amount=1500, reference="QJK3ABCD12",
               created_at=None, counts_as_revenue=True):
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference=reference,
        days_paid_for=30,
        plan_id=plan.id,
        status=PaymentStatus.COMPLETED,
        counts_as_revenue=counts_as_revenue,
        created_at=created_at or datetime.utcnow(),
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    return payment


async def _pppoe_customer(db, reseller, *, router=None, **overrides):
    plan = await make_plan(
        db, reseller, connection_type=ConnectionType.PPPOE, name="Home 10Mbps"
    )
    defaults = dict(
        status=CustomerStatus.ACTIVE,
        # 18:00 UTC is 21:00 in Nairobi.
        expiry=datetime(2030, 10, 8, 18, 0),
        pppoe_username="jane_home",
        pppoe_password="x7Kp2mQa",
        name="Jane Wanjiku",
        phone="254700000001",
        account_number="12345674",
    )
    defaults.update(overrides)
    customer = await make_customer(db, reseller, plan, router, **defaults)
    return plan, customer


async def _messages(db):
    return (await db.execute(select(SmsMessage).order_by(SmsMessage.id))).scalars().all()


async def test_pppoe_payment_gets_receipt_with_amount_reference_and_expiry(
    db, session_factory,
):
    reseller = await _reseller(db)
    plan, customer = await _pppoe_customer(db, reseller)
    payment = await _pay(db, reseller, customer, plan)

    campaigns = await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    )

    [message] = await _messages(db)
    credits = (
        await db.execute(select(SmsCreditAccount).where(SmsCreditAccount.user_id == reseller.id))
    ).scalar_one()
    assert len(campaigns) == 1
    assert message.customer_id == customer.id
    assert message.category == customer_notifications.receipt_category(payment.id)
    assert message.body == (
        "Payment of KES 1,500 received. Your Home 10Mbps is active until "
        "08 Oct, 21:00. Ref QJK3ABCD12. - Twork Links"
    )
    assert credits.balance == 4


async def test_receipt_is_sent_once_per_payment(db, session_factory):
    reseller = await _reseller(db)
    plan, customer = await _pppoe_customer(db, reseller)
    await _pay(db, reseller, customer, plan)

    first = await customer_notifications.queue_payment_receipts(session_factory=session_factory)
    second = await customer_notifications.queue_payment_receipts(session_factory=session_factory)

    assert len(first) == 1
    assert second == []
    assert len(await _messages(db)) == 1


async def test_hotspot_receipts_need_their_own_opt_in(db, session_factory):
    reseller = await _reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT,
                           duration_value=1, duration_unit=DurationUnit.HOURS)
    customer = await make_customer(db, reseller, plan, status=CustomerStatus.ACTIVE,
                                   expiry=datetime.utcnow() + timedelta(hours=1),
                                   phone="254700000002")
    await _pay(db, reseller, customer, plan, amount=20, reference="QHOT123")

    assert await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    ) == []

    preferences = await db.get(CustomerExpirySmsSettings, reseller.id)
    preferences.receipt_include_hotspot = True
    await db.commit()

    assert len(await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    )) == 1
    [message] = await _messages(db)
    assert "KES 20" in message.body
    # Hotspot customers cannot pay by account number, so no paybill line.
    assert "Paybill" not in message.body


@pytest.mark.parametrize(
    "payment_kwargs",
    [
        {"amount": 0},
        {"counts_as_revenue": False},
        {"created_at": datetime.utcnow() - timedelta(hours=1)},
    ],
    ids=["free", "compensation", "too-old"],
)
async def test_non_payments_and_old_payments_get_no_receipt(
    db, session_factory, payment_kwargs,
):
    reseller = await _reseller(db)
    plan, customer = await _pppoe_customer(db, reseller)
    await _pay(db, reseller, customer, plan, **payment_kwargs)

    assert await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    ) == []


async def test_receipts_off_by_default(db, session_factory):
    reseller = await _reseller(db, payment_receipt_enabled=False)
    plan, customer = await _pppoe_customer(db, reseller)
    await _pay(db, reseller, customer, plan)

    assert await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    ) == []


async def test_own_gateway_reseller_without_credits_still_gets_receipts(
    db, session_factory,
):
    reseller = await _reseller(db, credits=0)
    db.add(MessagingProviderAccount(
        user_id=reseller.id, provider="talksasa", label="Own", credentials={},
        sender_id="TWORK", is_default=True, is_active=True,
    ))
    await db.commit()
    plan, customer = await _pppoe_customer(db, reseller)
    await _pay(db, reseller, customer, plan)

    campaigns = await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    )

    [message] = await _messages(db)
    assert len(campaigns) == 1
    assert message.credits_charged == 0


async def test_reseller_template_is_used_for_receipts(db, session_factory):
    reseller = await _reseller(db, custom_templates={
        "payment_receipt": "Hi {name}, we got {amount}. Online till {expiry}. Call {support_phone}",
    })
    reseller.support_phone = "0711000000"
    await db.commit()
    plan, customer = await _pppoe_customer(db, reseller)
    await _pay(db, reseller, customer, plan)

    await customer_notifications.queue_payment_receipts(session_factory=session_factory)

    [message] = await _messages(db)
    assert message.body == "Hi Jane, we got KES 1,500. Online till 08 Oct, 21:00. Call 0711000000"


async def test_welcome_sends_pppoe_login_and_reseller_paybill(db, session_factory):
    reseller = await _reseller(db)
    method = ResellerPaymentMethod(
        user_id=reseller.id,
        method_type=ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS,
        label="Own paybill",
        is_active=True,
        mpesa_shortcode="777888",
        c2b_registered_at=datetime.utcnow(),
    )
    db.add(method)
    await db.commit()
    router = await make_router(db, reseller, payment_method_id=method.id)
    _, customer = await _pppoe_customer(
        db, reseller, router=router, status=CustomerStatus.INACTIVE, expiry=None
    )

    campaign_id = await customer_notifications.queue_welcome_message(
        customer.id, session_factory=session_factory
    )
    again = await customer_notifications.queue_welcome_message(
        customer.id, session_factory=session_factory
    )

    [message] = await _messages(db)
    assert campaign_id is not None
    assert again is None
    assert message.category == customer_notifications.WELCOME_CATEGORY
    assert message.body == (
        "Welcome to Twork Links! Username: jane_home Password: x7Kp2mQa. "
        "Pay via M-Pesa Paybill 777888, Account 12345674 to activate."
    )


async def test_welcome_needs_opt_in(db, session_factory):
    reseller = await _reseller(db, welcome_enabled=False)
    _, customer = await _pppoe_customer(db, reseller)

    assert await customer_notifications.queue_welcome_message(
        customer.id, session_factory=session_factory
    ) is None
    assert (await db.execute(select(func.count(SmsMessage.id)))).scalar_one() == 0


async def test_non_kenyan_reseller_is_never_told_to_use_mpesa(db, session_factory):
    reseller = await _reseller(db)
    reseller.market_code = "TZ"
    await db.commit()
    _, customer = await _pppoe_customer(db, reseller, phone="255700000001")

    await customer_notifications.queue_welcome_message(
        customer.id, session_factory=session_factory
    )

    [message] = await _messages(db)
    assert "M-Pesa" not in message.body
    assert message.body.endswith("Password: x7Kp2mQa.")


async def test_customers_with_placeholder_phones_are_skipped(db, session_factory):
    reseller = await _reseller(db)
    plan, customer = await _pppoe_customer(db, reseller, phone="AA:BB:CC:DD:EE:FF")
    await _pay(db, reseller, customer, plan)

    assert await customer_notifications.queue_payment_receipts(
        session_factory=session_factory
    ) == []

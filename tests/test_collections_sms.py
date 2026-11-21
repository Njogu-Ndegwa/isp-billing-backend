"""SMS credit sales land in the platform paybill, so the Collections page can send them on."""
import pytest

import app.api.subscription_routes as sr
from app.db.models import (
    B2BTransaction, B2BTransactionStatus, SmsCreditOrder, SmsCreditOrderStatus,
    SubscriptionPayment, SubscriptionPaymentStatus,
)
from tests.factories import make_admin, make_reseller


def _sms(user_id: int, amount: int, status=SmsCreditOrderStatus.COMPLETED) -> SmsCreditOrder:
    return SmsCreditOrder(
        user_id=user_id, quantity=amount, unit_price=1, amount=amount,
        phone_number="254700000000", status=status,
    )


@pytest.mark.asyncio
async def test_completed_sms_sales_are_available_to_send(db):
    reseller = await make_reseller(db)
    db.add_all([
        SubscriptionPayment(
            user_id=reseller.id, amount=500.0, payment_method="mpesa",
            status=SubscriptionPaymentStatus.COMPLETED,
        ),
        _sms(reseller.id, 300),
        _sms(reseller.id, 200),
        _sms(reseller.id, 900, SmsCreditOrderStatus.PENDING),
        _sms(reseller.id, 700, SmsCreditOrderStatus.FAILED),
    ])
    await db.commit()

    summary = await sr._subscription_collection_summary(db)

    assert summary["subscription_collected"] == 500.0
    assert summary["sms_collected"] == 500.0
    assert summary["sms_orders"] == 2
    assert summary["paybill_collected"] == 1000.0
    assert summary["total_collected"] == 1000.0
    assert summary["available_to_send"] == 1000.0


@pytest.mark.asyncio
async def test_sent_and_pending_transfers_reduce_sms_money_too(db):
    admin = await make_admin(db)
    reseller = await make_reseller(db)
    db.add_all([
        SubscriptionPayment(
            user_id=reseller.id, amount=400.0, payment_method="mpesa",
            status=SubscriptionPaymentStatus.COMPLETED,
        ),
        _sms(reseller.id, 600),
        B2BTransaction(
            reseller_id=admin.id, amount=700.0, fee=0, net_amount=700.0,
            party_a="000000", party_b="111111",
            status=B2BTransactionStatus.COMPLETED,
            triggered_by=sr.SUBSCRIPTION_OWNER_TRIGGER,
        ),
        B2BTransaction(
            reseller_id=admin.id, amount=100.0, fee=0, net_amount=100.0,
            party_a="000000", party_b="111111",
            status=B2BTransactionStatus.PENDING,
            triggered_by=sr.SUBSCRIPTION_OWNER_TRIGGER,
        ),
    ])
    await db.commit()

    summary = await sr._subscription_collection_summary(db)

    assert summary["completed_sent"] == 700.0
    assert summary["pending_send"] == 100.0
    assert summary["available_to_send"] == 200.0

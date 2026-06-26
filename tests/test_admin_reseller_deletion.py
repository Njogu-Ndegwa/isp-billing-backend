from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select, text

import app.api.admin_reseller_routes as admin_resellers
from app.db.models import (
    AccessCredential,
    C2BTransaction,
    C2BTransactionStatus,
    MessageTemplate,
    PortalSettings,
    ResellerInboxMessage,
    ShopOrder,
    ShopOrderItem,
    ShopOrderTracking,
    ShopProduct,
    SmsCampaign,
    SmsCreditAccount,
    SmsCreditOrder,
    SmsCreditTransaction,
    SmsCreditTxnKind,
    SmsMessage,
    SmsMessageKind,
    SubscriptionShareCode,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
    User,
    UserRole,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _count(db, model):
    return (await db.execute(select(func.count(model.id)))).scalar_one()


async def _create_radius_tables(db):
    await db.execute(text("CREATE TABLE radius_check (id INTEGER PRIMARY KEY, customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE radius_reply (id INTEGER PRIMARY KEY, customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE radius_nas (id INTEGER PRIMARY KEY, router_id INTEGER)"))
    await db.commit()


@pytest.mark.asyncio
async def test_delete_reseller_cleans_messaging_and_related_fk_rows(db, monkeypatch):
    await _create_radius_tables(db)

    admin = await make_reseller(db, role=UserRole.ADMIN, email="admin-delete@example.com")
    reseller = await make_reseller(db, email="delete-me@example.com")
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    async def _fake_current_user(token, session):
        return admin

    async def _no_vpn_cleanup(value):
        return None

    monkeypatch.setattr(admin_resellers, "get_current_user", _fake_current_user)
    monkeypatch.setattr(admin_resellers, "remove_wireguard_peer", _no_vpn_cleanup)
    monkeypatch.setattr(admin_resellers, "remove_l2tp_peer", _no_vpn_cleanup)

    campaign = SmsCampaign(
        user_id=reseller.id,
        body="Service notice",
        recipient_count=1,
        segments_per_message=1,
        total_credits=1,
    )
    product = ShopProduct(user_id=reseller.id, name="Router", price=2500)
    order = ShopOrder(
        order_number="ORD-DEL-1",
        user_id=reseller.id,
        buyer_name="Buyer",
        buyer_phone="254700000000",
        total_amount=2500,
    )
    c2b = C2BTransaction(
        trans_id="C2B-DEL-1",
        trans_amount=100,
        status=C2BTransactionStatus.PROCESSED,
        matched_customer_id=customer.id,
        matched_reseller_id=reseller.id,
    )
    db.add_all([campaign, product, order, c2b])
    await db.flush()

    unmatched = UnmatchedC2BPayment(
        c2b_transaction_id=c2b.id,
        reason=UnmatchedC2BReason.UNKNOWN_ACCOUNT,
        assigned_reseller_id=reseller.id,
        resolved_by_user_id=reseller.id,
        resolution_customer_id=customer.id,
    )
    db.add_all([
        SmsCreditAccount(user_id=reseller.id, balance=5),
        SmsCreditTransaction(
            user_id=reseller.id,
            change=5,
            balance_after=5,
            kind=SmsCreditTxnKind.ADMIN_ADJUSTMENT,
        ),
        SmsCreditOrder(
            user_id=reseller.id,
            quantity=10,
            unit_price=1,
            amount=10,
            phone_number="254700000000",
        ),
        MessageTemplate(user_id=reseller.id, name="Reminder", body="Please pay"),
        SmsMessage(
            campaign_id=campaign.id,
            user_id=reseller.id,
            customer_id=customer.id,
            recipient_phone=customer.phone,
            body="Service notice",
            segments=1,
            credits_charged=1,
            kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
        ),
        ResellerInboxMessage(
            recipient_user_id=reseller.id,
            sender_user_id=admin.id,
            subject="Notice",
            body="Update your account",
        ),
        PortalSettings(user_id=reseller.id),
        ShopOrderItem(
            order_id=order.id,
            product_id=product.id,
            product_name="Router",
            product_price=2500,
            quantity=1,
            subtotal=2500,
        ),
        ShopOrderTracking(
            order_id=order.id,
            status_label="created",
            updated_by_user_id=reseller.id,
        ),
        SubscriptionShareCode(
            code="SHAREDEL1",
            router_id=router.id,
            owner_customer_id=customer.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
        ),
        AccessCredential(
            user_id=reseller.id,
            router_id=router.id,
            username="guest",
            password="secret",
        ),
        unmatched,
    ])
    await db.commit()

    result = await admin_resellers.delete_reseller(reseller.id, True, db, "token")

    assert result["dry_run"] is False
    assert await db.get(User, reseller.id) is None

    for model in (
        SmsMessage,
        SmsCampaign,
        SmsCreditAccount,
        SmsCreditTransaction,
        SmsCreditOrder,
        MessageTemplate,
        ResellerInboxMessage,
        PortalSettings,
        ShopOrderTracking,
        ShopOrderItem,
        ShopOrder,
        ShopProduct,
        SubscriptionShareCode,
        AccessCredential,
    ):
        assert await _count(db, model) == 0

    c2b_after = await db.get(C2BTransaction, c2b.id)
    unmatched_after = await db.get(UnmatchedC2BPayment, unmatched.id)
    assert c2b_after is not None
    assert c2b_after.matched_customer_id is None
    assert c2b_after.matched_reseller_id is None
    assert unmatched_after is not None
    assert unmatched_after.assigned_reseller_id is None
    assert unmatched_after.resolved_by_user_id is None
    assert unmatched_after.resolution_customer_id is None

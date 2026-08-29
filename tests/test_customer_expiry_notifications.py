from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.db.models import (
    ConnectionType,
    CustomerStatus,
    MessagingSettings,
    SmsCampaign,
    SmsCreditAccount,
    SmsMessage,
)
from app.services import customer_expiry_notifications, mikrotik_background
from tests.factories import (
    make_customer,
    make_plan,
    make_reseller,
    make_router,
    make_sms_account,
)


pytestmark = pytest.mark.asyncio


async def _seed_expired_pppoe(db, *, credits=5):
    reseller = await make_reseller(
        db,
        organization_name="Twork Links Limited",
    )
    await make_sms_account(db, reseller, balance=credits)
    db.add(MessagingSettings(id=1, enabled=True))
    await db.commit()
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        price=1500,
        speed="12M/12M",
    )
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=1),
        pppoe_username="Joe",
        mac_address=None,
        name="Joe",
        phone="+254700087474",
    )
    return reseller, router, customer


async def test_queues_expiry_sms_in_campaign_history_and_debits_credit(
    db, session_factory,
):
    reseller, _, customer = await _seed_expired_pppoe(db)

    campaigns = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )

    assert len(campaigns) == 1
    campaign = await db.get(SmsCampaign, campaigns[0])
    message = (
        await db.execute(
            select(SmsMessage).where(SmsMessage.campaign_id == campaign.id)
        )
    ).scalar_one()
    credits = (
        await db.execute(
            select(SmsCreditAccount).where(SmsCreditAccount.user_id == reseller.id)
        )
    ).scalar_one()

    assert campaign.recipient_count == 1
    assert campaign.total_credits == 1
    assert "expired" in campaign.body
    assert "Twork Links Limited" in campaign.body
    assert message.customer_id == customer.id
    assert message.recipient_phone == "+254700087474"
    assert message.category == customer_expiry_notifications.expiry_message_category(
        customer.expiry
    )
    assert credits.balance == 4


async def test_same_customer_period_is_never_queued_twice(db, session_factory):
    _, _, customer = await _seed_expired_pppoe(db)

    first = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )
    second = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )
    count = (
        await db.execute(select(func.count(SmsMessage.id)))
    ).scalar_one()

    assert len(first) == 1
    assert second == []
    assert count == 1


async def test_insufficient_credits_skips_campaign(db, session_factory):
    _, _, customer = await _seed_expired_pppoe(db, credits=0)

    campaigns = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )

    assert campaigns == []
    assert (await db.execute(select(func.count(SmsCampaign.id)))).scalar_one() == 0
    assert (await db.execute(select(func.count(SmsMessage.id)))).scalar_one() == 0


async def test_active_or_renewed_customer_is_not_notified(db, session_factory):
    _, _, customer = await _seed_expired_pppoe(db)
    customer.status = CustomerStatus.ACTIVE
    customer.expiry = datetime.utcnow() + timedelta(days=30)
    await db.commit()

    campaigns = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )

    assert campaigns == []


async def test_pppoe_cleanup_notifies_only_after_router_enforcement(
    db, session_factory, monkeypatch,
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=1),
        pppoe_username="expired-ppp",
        mac_address=None,
    )

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(
        mikrotik_background,
        "_background_db_pool_is_busy",
        lambda _job_name: False,
    )

    async def _zero(*_args, **_kwargs):
        return 0

    async def _none(*_args, **_kwargs):
        return None

    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _none)
    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_pppoe_sync",
        lambda _router, customers: {
            "removed": [{"id": item["id"], "details": {}} for item in customers],
            "failed": [],
            "connected": True,
        },
    )

    notified = []

    async def _queue(ids, **_kwargs):
        notified.extend(ids)
        return [99]

    dispatched = []
    monkeypatch.setattr(
        customer_expiry_notifications,
        "queue_customer_expiry_notifications",
        _queue,
    )
    monkeypatch.setattr(
        customer_expiry_notifications,
        "spawn_expiry_campaign_dispatch",
        lambda ids: dispatched.extend(ids),
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE
    assert notified == [customer.id]
    assert dispatched == [99]

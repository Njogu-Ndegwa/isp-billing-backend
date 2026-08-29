from datetime import datetime, timedelta

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    ConnectionType,
    CustomerExpirySmsSettings,
    CustomerStatus,
    MessagingSettings,
    SmsCampaign,
    SmsCreditAccount,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
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
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id,
        enabled=True,
        reminder_offsets_minutes=[1440],
        send_at_expiry=True,
    ))
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
        account_number="12345674",
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
    assert "Paybill 600980" in campaign.body
    assert "Account [customer account]" in campaign.body
    assert message.customer_id == customer.id
    assert message.recipient_phone == "+254700087474"
    assert "Paybill 600980" in message.body
    assert "Account 12345674" in message.body
    assert message.category == customer_expiry_notifications.expiry_message_category(
        customer.expiry
    )
    assert credits.balance == 4


async def test_reminder_uses_each_customers_unique_payment_account(
    db, session_factory,
):
    now = datetime.utcnow().replace(microsecond=0)
    reseller = await make_reseller(db, organization_name="Payment ISP")
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id,
        enabled=True,
        reminder_offsets_minutes=[120],
        send_at_expiry=False,
    ))
    await db.commit()
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    first = await make_customer(
        db,
        reseller,
        plan,
        status=CustomerStatus.ACTIVE,
        expiry=now + timedelta(minutes=90),
        pppoe_username="first",
        phone="254700000001",
        account_number="12345674",
    )
    second = await make_customer(
        db,
        reseller,
        plan,
        status=CustomerStatus.ACTIVE,
        expiry=now + timedelta(minutes=90),
        pppoe_username="second",
        phone="254700000002",
        account_number="20000028",
    )

    campaign_id = await customer_expiry_notifications._queue_reseller_reminder_campaign(
        reseller.id,
        120,
        [first.id, second.id],
        session_factory=session_factory,
        now=now,
    )

    campaign = await db.get(SmsCampaign, campaign_id)
    messages = (
        await db.execute(
            select(SmsMessage).where(SmsMessage.campaign_id == campaign_id)
            .order_by(SmsMessage.customer_id)
        )
    ).scalars().all()

    assert campaign.recipient_count == 2
    assert campaign.total_credits == 2
    assert "Account [customer account]" in campaign.body
    assert "Account 12345674" in messages[0].body
    assert "Account 20000028" in messages[1].body
    assert all(message.segments == 1 for message in messages)


async def test_hotspot_expiry_does_not_advertise_pppoe_paybill(
    db, session_factory,
):
    reseller = await make_reseller(db, organization_name="Hotspot ISP")
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id,
        enabled=True,
        reminder_offsets_minutes=[1440],
        send_at_expiry=True,
    ))
    await db.commit()
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db,
        reseller,
        plan,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=1),
        phone="254700000003",
        account_number="30000036",
    )

    campaign_ids = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )
    campaign = await db.get(SmsCampaign, campaign_ids[0])
    message = (
        await db.execute(
            select(SmsMessage).where(SmsMessage.campaign_id == campaign.id)
        )
    ).scalar_one()

    assert "Paybill" not in campaign.body
    assert "Paybill" not in message.body
    assert "Please renew" in message.body


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


async def test_database_key_blocks_concurrent_duplicate_reminder(db, session_factory):
    reseller, _, customer = await _seed_expired_pppoe(db)
    await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )
    original = (
        await db.execute(select(SmsMessage).where(SmsMessage.customer_id == customer.id))
    ).scalar_one()
    db.add(SmsMessage(
        campaign_id=original.campaign_id,
        user_id=reseller.id,
        customer_id=customer.id,
        recipient_phone=customer.phone,
        body=original.body,
        segments=original.segments,
        credits_charged=original.credits_charged,
        kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
        status=SmsMessageStatus.QUEUED,
        category=original.category,
    ))

    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


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


async def test_at_expiry_toggle_can_disable_final_message(db, session_factory):
    reseller, _, customer = await _seed_expired_pppoe(db)
    preferences = await db.get(CustomerExpirySmsSettings, reseller.id)
    preferences.send_at_expiry = False
    await db.commit()

    campaigns = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory
    )

    assert campaigns == []


async def test_pre_expiry_scan_honors_offsets_and_deduplicates(
    db, session_factory, monkeypatch,
):
    now = datetime.utcnow().replace(microsecond=0)
    reseller = await make_reseller(db, organization_name="Reminder ISP")
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id,
        enabled=True,
        reminder_offsets_minutes=[120, 30],
        send_at_expiry=False,
    ))
    await db.commit()
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(
        db,
        reseller,
        plan,
        status=CustomerStatus.ACTIVE,
        expiry=now + timedelta(minutes=90),
        pppoe_username="due-soon",
        name="Due Soon",
        phone="254700000099",
    )

    monkeypatch.setattr(
        customer_expiry_notifications.database,
        "async_session",
        session_factory,
    )
    monkeypatch.setattr(
        customer_expiry_notifications.database,
        "db_pool_snapshot",
        lambda: {"pressure": {"level": "healthy"}},
    )
    dispatched = []
    monkeypatch.setattr(
        customer_expiry_notifications,
        "spawn_expiry_campaign_dispatch",
        lambda ids: dispatched.extend(ids),
    )

    first_count = await customer_expiry_notifications.scan_customer_expiry_reminders(
        now=now
    )
    second_count = await customer_expiry_notifications.scan_customer_expiry_reminders(
        now=now + timedelta(minutes=5)
    )
    messages = (
        await db.execute(select(SmsMessage).order_by(SmsMessage.id))
    ).scalars().all()

    assert first_count == 1
    assert second_count == 0
    assert len(dispatched) == 1
    assert len(messages) == 1
    assert messages[0].customer_id == customer.id
    assert messages[0].category == customer_expiry_notifications.reminder_message_category(
        customer.expiry, 120
    )
    assert "expire soon" in messages[0].body


async def test_steady_state_batch_read_is_constant_query_count(
    db, session_factory, engine,
):
    """Adding resellers/offsets must not add polling queries.

    The steady state is exactly: global messaging setting, enabled preferences
    joined to positive credit accounts, and one fleet customer query. There are
    no due customers here, so the optional dedupe query is not needed.
    """
    now = datetime.utcnow().replace(microsecond=0)
    db.add(MessagingSettings(id=1, enabled=True))
    await db.commit()
    offsets = [10080, 4320, 1440, 120, 30]
    for index in range(8):
        reseller = await make_reseller(db)
        await make_sms_account(db, reseller, balance=10)
        db.add(CustomerExpirySmsSettings(
            user_id=reseller.id,
            enabled=True,
            reminder_offsets_minutes=offsets,
            send_at_expiry=True,
        ))
        await db.commit()
        plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
        await make_customer(
            db,
            reseller,
            plan,
            status=CustomerStatus.ACTIVE,
            expiry=now + timedelta(days=8),
            pppoe_username=f"outside-window-{index}",
            phone=f"2547111000{index:02d}",
        )

    selects = []

    def _record_select(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record_select)
    try:
        groups = await customer_expiry_notifications.collect_due_reminder_groups(
            session_factory=session_factory,
            now=now,
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record_select)

    assert groups == {}
    assert len(selects) == 3
    assert sum("FROM customers" in statement for statement in selects) == 1


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

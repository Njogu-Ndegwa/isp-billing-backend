from datetime import datetime, timedelta

import pytest

from app.db.models import (
    Customer, CustomerStatus, SmsCampaign, SmsCampaignStatus,
    SmsMessage, SmsMessageStatus, SmsMessageKind,
)
from app.services import sms_dispatch, sms_credits
from app.services.messaging.base import SendResult
from tests.factories import make_reseller, make_plan, make_customer, make_sms_account


@pytest.mark.asyncio
async def test_resolve_recipients_all_scoped_to_reseller(db):
    r1 = await make_reseller(db)
    r2 = await make_reseller(db)
    p1 = await make_plan(db, r1)
    await make_customer(db, r1, p1, phone="254700000001", status=CustomerStatus.ACTIVE)
    await make_customer(db, r1, p1, phone="254700000002", status=CustomerStatus.ACTIVE)
    p2 = await make_plan(db, r2)
    await make_customer(db, r2, p2, phone="254700000003", status=CustomerStatus.ACTIVE)

    recips = await sms_dispatch.resolve_recipients(db, r1.id, filter="all")
    phones = {c["phone"] for c in recips}
    assert phones == {"254700000001", "254700000002"}


@pytest.mark.asyncio
async def test_dispatch_marks_sent_and_refunds_failures(db, session_factory, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    c1 = await make_customer(db, r, p, phone="254700000001")
    c2 = await make_customer(db, r, p, phone="254700000002")
    await make_sms_account(db, r, balance=10)

    await sms_credits.try_deduct(db, r.id, 2, reference="pending")
    camp = SmsCampaign(user_id=r.id, body="Hi", recipient_count=2,
                       segments_per_message=1, total_credits=2,
                       status=SmsCampaignStatus.QUEUED, sender_id="BRAND")
    db.add(camp)
    await db.flush()
    for cust in (c1, c2):
        db.add(SmsMessage(campaign_id=camp.id, user_id=r.id, customer_id=cust.id,
                          recipient_phone=cust.phone, body="Hi", segments=1,
                          credits_charged=1, kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                          status=SmsMessageStatus.QUEUED))
    await db.commit()
    camp_id = camp.id

    class _FakeProvider:
        name = "fake"
        async def send_bulk(self, recipients, body, sender_id):
            return [
                SendResult(recipient="+254700000001", success=True,
                           provider_message_id="X1", status="Success"),
                SendResult(recipient="254700000002", success=False,
                           status="Failed", error="Failed"),
            ]

    monkeypatch.setattr(sms_dispatch, "get_provider", lambda: _FakeProvider())
    monkeypatch.setattr(sms_dispatch, "async_session", session_factory)

    await sms_dispatch.dispatch_campaign(camp_id)

    async with session_factory() as s:
        camp = await s.get(SmsCampaign, camp_id)
        assert camp.status == SmsCampaignStatus.PARTIAL
        assert camp.sent_count == 1
        assert camp.failed_count == 1
        assert camp.refunded_credits == 1
        acct = await sms_credits.get_or_create_account(s, r.id)
        assert acct.balance == 9      # 10 - 2 reserved + 1 refund


@pytest.mark.asyncio
async def test_dispatch_all_success_marks_completed(db, session_factory, monkeypatch):
    r = await make_reseller(db)
    p = await make_plan(db, r)
    c1 = await make_customer(db, r, p, phone="254700000001")
    await make_sms_account(db, r, balance=10)
    await sms_credits.try_deduct(db, r.id, 1, reference="pending")
    camp = SmsCampaign(user_id=r.id, body="Hi", recipient_count=1,
                       segments_per_message=1, total_credits=1,
                       status=SmsCampaignStatus.QUEUED, sender_id="BRAND")
    db.add(camp)
    await db.flush()
    db.add(SmsMessage(campaign_id=camp.id, user_id=r.id, customer_id=c1.id,
                      recipient_phone=c1.phone, body="Hi", segments=1,
                      credits_charged=1, kind=SmsMessageKind.RESELLER_TO_CUSTOMER,
                      status=SmsMessageStatus.QUEUED))
    await db.commit()
    camp_id = camp.id

    class _FakeProvider:
        name = "fake"
        async def send_bulk(self, recipients, body, sender_id):
            return [SendResult(recipient="254700000001", success=True,
                               provider_message_id="X1", status="Success")]

    monkeypatch.setattr(sms_dispatch, "get_provider", lambda: _FakeProvider())
    monkeypatch.setattr(sms_dispatch, "async_session", session_factory)
    await sms_dispatch.dispatch_campaign(camp_id)

    async with session_factory() as s:
        camp = await s.get(SmsCampaign, camp_id)
        assert camp.status == SmsCampaignStatus.COMPLETED
        assert camp.sent_count == 1
        assert camp.failed_count == 0
        assert camp.refunded_credits == 0


@pytest.mark.asyncio
async def test_dispatch_admin_sms_messages_updates_per_recipient_status(
        db, session_factory, monkeypatch):
    r1 = await make_reseller(db, support_phone="254700000001")
    r2 = await make_reseller(db, support_phone="254700000002")
    m1 = SmsMessage(user_id=r1.id, recipient_phone=r1.support_phone, body="Notice",
                    segments=1, credits_charged=1,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER,
                    status=SmsMessageStatus.QUEUED)
    m2 = SmsMessage(user_id=r2.id, recipient_phone=r2.support_phone, body="Notice",
                    segments=1, credits_charged=1,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER,
                    status=SmsMessageStatus.QUEUED)
    db.add_all([m1, m2])
    await db.commit()
    ids = [m1.id, m2.id]

    class _FakeProvider:
        name = "fake"
        async def send_bulk(self, recipients, body, sender_id):
            assert recipients == ["254700000001", "254700000002"]
            assert body == "Notice"
            assert sender_id == "BRAND"
            return [
                SendResult(recipient="+254700000001", success=True,
                           provider_message_id="ADM1", status="Success"),
                SendResult(recipient="254700000002", success=False,
                           status="Rejected", error="Rejected"),
            ]

    monkeypatch.setattr(sms_dispatch, "get_provider", lambda: _FakeProvider())
    monkeypatch.setattr(sms_dispatch, "async_session", session_factory)

    await sms_dispatch.dispatch_admin_sms_messages(ids, "BRAND")

    async with session_factory() as s:
        row1 = await s.get(SmsMessage, ids[0])
        row2 = await s.get(SmsMessage, ids[1])
        assert row1.status == SmsMessageStatus.SENT
        assert row1.provider == "fake"
        assert row1.provider_message_id == "ADM1"
        assert row1.error is None
        assert row2.status == SmsMessageStatus.FAILED
        assert row2.provider == "fake"
        assert row2.error == "Rejected"

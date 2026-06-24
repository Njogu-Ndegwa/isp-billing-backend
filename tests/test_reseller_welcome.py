import pytest
from sqlalchemy import select

from app.db.models import MessagingSettings, SmsMessage, SmsMessageKind, SmsMessageStatus


@pytest.mark.asyncio
async def test_new_columns_exist_and_default(db):
    db.add(MessagingSettings(id=1))
    await db.commit()
    s = await db.get(MessagingSettings, 1)
    assert s.welcome_enabled is True
    assert s.welcome_subject is None
    assert s.welcome_message_body is None
    assert s.welcome_support_phone is None

    row = SmsMessage(user_id=1, recipient_phone="254700000000", body="hi",
                     segments=1, credits_charged=1,
                     kind=SmsMessageKind.ADMIN_TO_RESELLER,
                     status=SmsMessageStatus.QUEUED, category="reseller_welcome")
    db.add(row)
    await db.commit()
    got = (await db.execute(select(SmsMessage))).scalars().one()
    assert got.category == "reseller_welcome"

"""Pre-expiry subscription reminder tests.

Timing helpers are pure functions and tested directly. The DB-touching paths run
against the in-memory SQLite harness with the SMS provider dispatch patched out —
these must never reach a provider.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    InvoiceStatus, MessagingSettings, ResellerInboxMessage, SmsMessage,
    SmsMessageKind, SmsMessageStatus, SubscriptionExpiryReminder,
    SubscriptionInvoice, SubscriptionStatus, UserRole,
)
from app.services.messaging import count_segments
from app.services.subscription_reminders import (
    REMINDER_CATEGORY, STAGES,
    due_stage, humanize_lead, next_suspension_run_at, reminder_send_at,
    render_reminder_inbox, render_reminder_sms, send_due_subscription_reminders,
    send_expiry_reminder, shift_out_of_quiet_hours,
)
from tests.factories import make_reseller

EAT_OFFSET = timedelta(hours=3)
T72 = timedelta(hours=72)
T24 = timedelta(hours=24)
T2 = timedelta(hours=2)


def eat(year, month, day, hour, minute=0) -> datetime:
    """Build a UTC datetime from an EAT wall-clock time (what resellers see)."""
    return datetime(year, month, day, hour, minute) - EAT_OFFSET


# --------------------------------------------------------------------------
# Quiet hours
# --------------------------------------------------------------------------

def test_daytime_reminder_is_not_shifted():
    when = eat(2026, 7, 26, 14, 30)
    assert shift_out_of_quiet_hours(when) == when


def test_late_evening_reminder_holds_until_next_morning():
    # 23:10 EAT -> 07:00 EAT the following day
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 23, 10)) == eat(2026, 7, 27, 7)


def test_small_hours_reminder_holds_until_same_morning():
    # 02:00 EAT -> 07:00 EAT the same day, not tomorrow
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 2)) == eat(2026, 7, 26, 7)


def test_quiet_window_boundaries():
    # 22:00 EAT is inside the window; 07:00 EAT is already outside it.
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 22)) == eat(2026, 7, 27, 7)
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 7)) == eat(2026, 7, 26, 7)
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 21, 59)) == eat(2026, 7, 26, 21, 59)


def test_reminder_send_at_applies_quiet_hours():
    # Expiry 03:00 EAT -> naive T-2h is 01:00 EAT, held to 07:00 EAT.
    expires = eat(2026, 7, 27, 3)
    assert reminder_send_at(expires, T2) == eat(2026, 7, 27, 7)
    # T-24h for the same expiry is 03:00 EAT the day before -> held to 07:00.
    assert reminder_send_at(expires, T24) == eat(2026, 7, 26, 7)


# --------------------------------------------------------------------------
# Send window
# --------------------------------------------------------------------------

def test_next_suspension_run_is_the_next_0800_utc():
    # check_overdue_invoices runs daily at 08:00 UTC.
    expires = datetime(2026, 7, 26, 14, 0)
    assert next_suspension_run_at(expires) == datetime(2026, 7, 27, 8, 0)
    expires_early = datetime(2026, 7, 26, 3, 0)
    assert next_suspension_run_at(expires_early) == datetime(2026, 7, 26, 8, 0)


def test_no_reminder_before_the_t72_window():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 24, 15), set()) is None


def test_t72_fires_three_days_out():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 25, 15), set()) == "t72"


def test_t24_follows_t72():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 26, 15), {"t72"}) is None
    assert due_stage(expires, eat(2026, 7, 27, 15), {"t72"}) == "t24"


def test_t24_fires_a_day_out():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 27, 15), set()) == "t24"


def test_t2_fires_two_hours_out_after_t24_already_sent():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 28, 13), {"t24"}) == "t2"


def test_t24_is_not_resent_once_recorded():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 27, 16), {"t24"}) is None


def test_nothing_more_after_t2_is_sent():
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 28, 14), {"t24", "t2"}) is None


def test_late_start_sends_only_the_shortest_due_stage():
    """Server down through the t24 window: one accurate text, not two."""
    expires = eat(2026, 7, 28, 15)
    assert due_stage(expires, eat(2026, 7, 28, 14), set()) == "t2"


def test_reminder_still_sent_after_expiry_until_the_suspension_run():
    # Expires 03:00 EAT; the quiet-hours hold releases at 07:00 EAT, which is
    # after expiry but still 4h before the 11:00 EAT suspension run.
    expires = eat(2026, 7, 27, 3)
    assert due_stage(expires, eat(2026, 7, 27, 7, 5), {"t24"}) == "t2"


def test_no_reminder_once_the_suspension_run_has_passed():
    expires = eat(2026, 7, 27, 3)
    assert due_stage(expires, eat(2026, 7, 27, 11, 30), {"t24"}) is None


def test_stage_keys_are_stable():
    # Stage keys are persisted in subscription_expiry_reminders.stage.
    assert [s for s, _ in STAGES] == ["t72", "t24", "t2"]


# --------------------------------------------------------------------------
# Copy
# --------------------------------------------------------------------------

def test_humanize_lead_rounds_sensibly():
    assert humanize_lead(timedelta(hours=2)) == "2 hours"
    assert humanize_lead(timedelta(hours=1)) == "1 hour"
    assert humanize_lead(timedelta(hours=23, minutes=50)) == "24 hours"
    assert humanize_lead(timedelta(minutes=45)) == "45 minutes"
    assert humanize_lead(timedelta(days=2)) == "2 days"
    assert humanize_lead(timedelta(seconds=-30)) == "1 minute"


@pytest.mark.parametrize("amount", [None, 500.0, 1200.0, 12500.0, 125000.0])
@pytest.mark.parametrize("lead", [timedelta(hours=24), timedelta(hours=2),
                                  timedelta(minutes=45), timedelta(hours=-1)])
def test_sms_body_never_costs_more_than_one_segment(amount, lead):
    """These are billed to us per segment — a second segment doubles the cost."""
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - lead, amount)
    assert count_segments(body) == 1, f"{len(body)} chars: {body}"


def test_sms_names_the_amount_when_an_invoice_is_outstanding():
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - T2, 1200.0)
    assert "KES 1,200" in body
    assert "about 2 hours" in body


def test_sms_omits_the_amount_when_there_is_no_invoice():
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - T2, None)
    assert "KES" not in body
    assert "Renew in the app" in body


def test_sms_switches_to_expired_wording_past_expiry():
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires + timedelta(minutes=30), 1200.0)
    assert "has expired" in body
    assert "expires in" not in body


def test_inbox_message_states_the_expiry_in_local_time():
    expires = eat(2026, 7, 27, 15, 30)
    subject, body = render_reminder_inbox(expires, expires - T2, 1200.0)
    assert "2 hours" in subject
    assert "3:30PM EAT" in body
    assert "KES 1,200" in body


# --------------------------------------------------------------------------
# Send path
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_provider_calls(monkeypatch):
    """Guard: these tests must never reach the SMS provider."""
    sent = []

    async def _fake_dispatch(message_ids, sender_id):
        sent.append((list(message_ids), sender_id))
    monkeypatch.setattr(
        "app.services.sms_dispatch.dispatch_admin_sms_messages", _fake_dispatch)
    return sent


async def _reseller_expiring(db, *, hours: float, phone="254700111222",
                             status=SubscriptionStatus.ACTIVE, invoice=1200.0):
    expires = datetime.utcnow() + timedelta(hours=hours)
    reseller = await make_reseller(db, support_phone=phone,
                                   subscription_status=status,
                                   subscription_expires_at=expires)
    if invoice is not None:
        db.add(SubscriptionInvoice(
            user_id=reseller.id,
            period_start=expires - timedelta(days=30),
            period_end=expires,
            hotspot_revenue=0, hotspot_charge=0, pppoe_user_count=0,
            pppoe_charge=0, gross_charge=invoice, final_charge=invoice,
            status=InvoiceStatus.PENDING, due_date=expires,
        ))
        await db.commit()
    return reseller, expires


@pytest.mark.asyncio
async def test_send_creates_sms_inbox_and_dedupe_row(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)

    outcome = await send_expiry_reminder(reseller.id, "t2", expires)
    assert outcome is not None

    sms = (await db.execute(select(SmsMessage))).scalars().all()
    assert len(sms) == 1
    assert sms[0].kind == SmsMessageKind.ADMIN_TO_RESELLER
    assert sms[0].category == REMINDER_CATEGORY
    assert sms[0].status == SmsMessageStatus.QUEUED
    assert sms[0].recipient_phone == "254700111222"
    assert "KES 1,200" in sms[0].body
    assert outcome["sms_id"] == sms[0].id

    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].recipient_user_id == reseller.id

    claims = (await db.execute(select(SubscriptionExpiryReminder))).scalars().all()
    assert len(claims) == 1
    assert (claims[0].stage, claims[0].expires_at) == ("t2", expires)
    assert claims[0].sms_message_id == sms[0].id


@pytest.mark.asyncio
async def test_second_send_for_the_same_stage_is_a_no_op(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)

    assert await send_expiry_reminder(reseller.id, "t2", expires) is not None
    assert await send_expiry_reminder(reseller.id, "t2", expires) is None

    assert len((await db.execute(select(SmsMessage))).scalars().all()) == 1
    assert len((await db.execute(select(SubscriptionExpiryReminder))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_renewing_moves_the_expiry_and_reopens_reminders(db):
    """A new billing cycle must be able to warn again for the new expiry."""
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)
    assert await send_expiry_reminder(reseller.id, "t2", expires) is not None

    new_expires = expires + timedelta(days=30)
    reseller.subscription_expires_at = new_expires
    await db.commit()

    assert await send_expiry_reminder(reseller.id, "t2", new_expires) is not None
    assert len((await db.execute(select(SubscriptionExpiryReminder))).scalars().all()) == 2


@pytest.mark.asyncio
async def test_send_skipped_when_the_expiry_moved_since_the_scan(db):
    """They paid between the scan and the send — don't text a paid-up reseller."""
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)
    reseller.subscription_expires_at = expires + timedelta(days=30)
    await db.commit()

    assert await send_expiry_reminder(reseller.id, "t2", expires) is None
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_send_skipped_for_an_already_suspended_reseller(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(
        db, hours=2, status=SubscriptionStatus.SUSPENDED)

    assert await send_expiry_reminder(reseller.id, "t2", expires) is None
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_no_phone_still_gets_the_inbox_message(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2, phone=None)

    outcome = await send_expiry_reminder(reseller.id, "t2", expires)
    assert outcome == {"sms_id": None}
    assert (await db.execute(select(SmsMessage))).scalars().all() == []
    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert len(inbox) == 1
    assert inbox[0].sent_sms is False


@pytest.mark.asyncio
async def test_messaging_globally_disabled_skips_the_sms(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)
    db.add(MessagingSettings(id=1, enabled=False))
    await db.commit()

    outcome = await send_expiry_reminder(reseller.id, "t2", expires)
    assert outcome == {"sms_id": None}
    assert (await db.execute(select(SmsMessage))).scalars().all() == []


@pytest.mark.asyncio
async def test_scan_sends_and_dispatches(db, no_provider_calls):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, _ = await _reseller_expiring(db, hours=1.5)

    result = await send_due_subscription_reminders()
    assert result["sent"] == 1
    assert result["sms_queued"] == 1

    sms = (await db.execute(select(SmsMessage))).scalars().all()
    assert len(sms) == 1
    assert sms[0].user_id == reseller.id
    assert no_provider_calls and no_provider_calls[0][0] == [sms[0].id]


@pytest.mark.asyncio
async def test_scan_is_idempotent_across_ticks(db, no_provider_calls):
    await make_reseller(db, role=UserRole.ADMIN)
    await _reseller_expiring(db, hours=1.5)

    assert (await send_due_subscription_reminders())["sent"] == 1
    assert (await send_due_subscription_reminders())["sent"] == 0
    assert len((await db.execute(select(SmsMessage))).scalars().all()) == 1
    assert len(no_provider_calls) == 1


@pytest.mark.asyncio
async def test_scan_ignores_resellers_that_are_not_close_to_expiry(db,
                                                                  no_provider_calls):
    await make_reseller(db, role=UserRole.ADMIN)
    await _reseller_expiring(db, hours=100)

    result = await send_due_subscription_reminders()
    assert result["candidates"] == 0
    assert (await db.execute(select(SmsMessage))).scalars().all() == []
    assert no_provider_calls == []


@pytest.mark.asyncio
async def test_scan_respects_the_admin_kill_switch(db, no_provider_calls):
    await make_reseller(db, role=UserRole.ADMIN)
    await _reseller_expiring(db, hours=1.5)
    db.add(MessagingSettings(id=1, subscription_reminders_enabled=False))
    await db.commit()

    result = await send_due_subscription_reminders()
    assert result["sent"] == 0
    assert (await db.execute(select(SmsMessage))).scalars().all() == []
    assert no_provider_calls == []


@pytest.mark.asyncio
async def test_scan_sheds_load_under_db_pool_pressure(db, monkeypatch,
                                                      no_provider_calls):
    await make_reseller(db, role=UserRole.ADMIN)
    await _reseller_expiring(db, hours=1.5)
    monkeypatch.setattr(
        "app.services.subscription_reminders.db_pool_snapshot",
        lambda: {"pressure": {"level": "critical"}})

    result = await send_due_subscription_reminders()
    assert result["skipped"] == 1
    assert (await db.execute(select(SmsMessage))).scalars().all() == []
    assert no_provider_calls == []


@pytest.mark.asyncio
async def test_settings_default_leaves_reminders_on(db):
    db.add(MessagingSettings(id=1))
    await db.commit()
    s = await db.get(MessagingSettings, 1)
    assert s.subscription_reminders_enabled is True

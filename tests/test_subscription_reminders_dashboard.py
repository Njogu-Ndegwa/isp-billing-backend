"""Subscription reminders across markets, trials, and the admin dashboard view.

Companion to tests/test_subscription_reminders.py (timing + send path). These
must never reach an SMS provider either.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_messaging_routes as amr
import app.api.admin_subscription_reminder_routes as asr
from app.db.database import get_db
from app.db.models import (
    InvoiceStatus, MessagingSettings, ResellerInboxMessage, SmsMessage,
    SmsMessageStatus, SubscriptionExpiryReminder, SubscriptionInvoice,
    SubscriptionStatus, UserRole,
)
from app.services import subscription_reminders as sr
from app.services.auth import verify_token
from app.services.messaging import count_segments
from app.services.subscription_reminders import (
    next_planned, reminder_overview, render_reminder_inbox, render_reminder_sms,
    send_expiry_reminder, shift_out_of_quiet_hours,
)
from tests.factories import make_reseller

EAT = timedelta(hours=3)
WAT = timedelta(hours=1)
T72 = timedelta(hours=72)
T24 = timedelta(hours=24)
T2 = timedelta(hours=2)


def eat(year, month, day, hour, minute=0) -> datetime:
    return datetime(year, month, day, hour, minute) - EAT


def wat(year, month, day, hour, minute=0) -> datetime:
    return datetime(year, month, day, hour, minute) - WAT


@pytest.fixture(autouse=True)
def no_provider_calls(monkeypatch):
    sent = []

    async def _fake_dispatch(message_ids, sender_id, owner_user_id=None):
        sent.append(list(message_ids))
    monkeypatch.setattr(
        "app.services.sms_dispatch.dispatch_admin_sms_messages", _fake_dispatch)
    return sent


async def _reseller_expiring(db, *, hours: float, phone="254700111222",
                             status=SubscriptionStatus.ACTIVE, invoice=1200.0,
                             currency="KES", market_code="KE"):
    expires = datetime.utcnow() + timedelta(hours=hours)
    reseller = await make_reseller(db, support_phone=phone, market_code=market_code,
                                   subscription_status=status,
                                   subscription_expires_at=expires)
    if invoice is not None:
        db.add(SubscriptionInvoice(
            user_id=reseller.id, period_start=expires - timedelta(days=30),
            period_end=expires, hotspot_revenue=0, hotspot_charge=0,
            pppoe_user_count=0, pppoe_charge=0, gross_charge=invoice,
            final_charge=invoice, currency=currency,
            status=InvoiceStatus.PENDING, due_date=expires,
        ))
        await db.commit()
    return reseller, expires


# --------------------------------------------------------------------------
# Timezones
# --------------------------------------------------------------------------

def test_quiet_hours_follow_the_resellers_own_timezone():
    # 23:30 in Douala (WAT) is quiet; held to 07:00 WAT, not 07:00 EAT.
    assert shift_out_of_quiet_hours(wat(2026, 7, 26, 23, 30), "Africa/Douala") \
        == wat(2026, 7, 27, 7)
    # 05:00 UTC is 08:00 in Nairobi (fine) but 06:00 in Douala (held to 07:00).
    five_utc = datetime(2026, 7, 27, 5, 0)
    assert shift_out_of_quiet_hours(five_utc, "Africa/Nairobi") == five_utc
    assert shift_out_of_quiet_hours(five_utc, "Africa/Douala") == wat(2026, 7, 27, 7)


def test_missing_tz_database_falls_back_to_the_fixed_offset(monkeypatch):
    """python:slim may lack tzdata; quiet hours must not silently become UTC."""
    def _no_tzdata(name):
        raise sr.ZoneInfoNotFoundError(name)

    monkeypatch.setattr(sr, "ZoneInfo", _no_tzdata)
    assert shift_out_of_quiet_hours(eat(2026, 7, 26, 23, 10), "Africa/Nairobi") \
        == eat(2026, 7, 27, 7)
    assert shift_out_of_quiet_hours(wat(2026, 7, 26, 23, 30), "Africa/Douala") \
        == wat(2026, 7, 27, 7)


# --------------------------------------------------------------------------
# Copy
# --------------------------------------------------------------------------

@pytest.mark.parametrize("trial", [False, True])
@pytest.mark.parametrize("amount,currency", [
    (None, None), (500.0, "KES"), (125000.0, "KES"), (10.0, "USD"),
    (1250.5, "USD"), (1234567.0, "XAF"), (9876543.0, "UGX"),
])
@pytest.mark.parametrize("lead", [T72, T24, T2, timedelta(minutes=45),
                                  timedelta(hours=-1)])
def test_every_sms_variant_fits_one_segment(trial, amount, currency, lead):
    """Billed to us per segment — a second segment doubles the cost."""
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - lead, amount, currency, trial=trial)
    assert count_segments(body) == 1, f"{len(body)} chars: {body}"


def test_sms_uses_the_invoice_currency():
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - T24, 10.0, "USD")
    assert "USD 10.00" in body
    assert "KES" not in body


def test_t72_sms_says_three_days():
    expires = datetime(2026, 7, 27, 12, 0)
    assert "about 3 days" in render_reminder_sms(expires, expires - T72, None)


def test_trial_wording():
    expires = datetime(2026, 7, 27, 12, 0)
    body = render_reminder_sms(expires, expires - T24, None, None, trial=True)
    assert "free trial ends in about 24 hours" in body
    assert "Subscribe in the app" in body
    ended = render_reminder_sms(expires, expires + T2, None, None, trial=True)
    assert "free trial has ended" in ended
    subject, _ = render_reminder_inbox(expires, expires - T24, None, None, trial=True)
    assert subject == "Free trial ends in about 24 hours"


def test_inbox_uses_the_resellers_local_time_and_zone():
    expires = wat(2026, 7, 27, 15, 30)
    _, body = render_reminder_inbox(expires, expires - T2, 10.0, "USD",
                                    tz_name="Africa/Douala")
    assert "3:30PM WAT" in body
    assert "USD 10.00" in body


def test_next_planned_reports_the_upcoming_stage_and_time():
    expires = eat(2026, 7, 28, 15)
    assert next_planned(expires, eat(2026, 7, 24, 15), set()) == ("t72", eat(2026, 7, 25, 15))
    assert next_planned(expires, eat(2026, 7, 26, 9), {"t72"}) == ("t24", eat(2026, 7, 27, 15))
    now = eat(2026, 7, 28, 13, 5)
    assert next_planned(expires, now, {"t72", "t24"}) == ("t2", now)
    assert next_planned(expires, eat(2026, 7, 28, 14), {"t72", "t24", "t2"}) is None


# --------------------------------------------------------------------------
# Send path
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_trial_reseller_gets_trial_copy(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(
        db, hours=2, status=SubscriptionStatus.TRIAL, invoice=None)

    assert await send_expiry_reminder(reseller.id, "t2", expires) is not None
    sms = (await db.execute(select(SmsMessage))).scalars().one()
    assert "free trial" in sms.body


@pytest.mark.asyncio
async def test_international_reseller_is_quoted_in_usd_and_local_time(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(
        db, hours=2, phone="237670000000", invoice=10.0, currency="USD",
        market_code="CM")

    assert await send_expiry_reminder(reseller.id, "t2", expires) is not None
    sms = (await db.execute(select(SmsMessage))).scalars().one()
    assert "USD 10.00" in sms.body
    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().one()
    assert "WAT" in inbox.body


@pytest.mark.asyncio
async def test_reminder_row_records_phone_and_inbox(db):
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)
    await send_expiry_reminder(reseller.id, "t2", expires)
    claim = (await db.execute(select(SubscriptionExpiryReminder))).scalars().one()
    assert claim.phone == "254700111222"
    assert claim.inbox_sent is True


# --------------------------------------------------------------------------
# Admin dashboard
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_overview_lists_upcoming_and_recent(db):
    await make_reseller(db, role=UserRole.ADMIN)
    texted, texted_expiry = await _reseller_expiring(db, hours=2)
    no_phone, _ = await _reseller_expiring(db, hours=50, phone=None)
    await _reseller_expiring(db, hours=24 * 20)  # outside the 7-day view

    await send_expiry_reminder(texted.id, "t2", texted_expiry)
    sms = (await db.execute(select(SmsMessage))).scalars().one()
    sms.status = SmsMessageStatus.FAILED
    sms.error = "Low bulk credits"
    await db.commit()

    out = await reminder_overview(db, days=7)
    assert out["enabled"] is True
    assert [u["reseller_id"] for u in out["upcoming"]] == [texted.id, no_phone.id]
    first, second = out["upcoming"]
    assert [s["stage"] for s in first["stages_sent"]] == ["t2"]
    assert first["next_stage"] is None
    assert second["phone"] is None
    assert second["next_stage"] in {"t72", "t24"}

    assert len(out["recent"]) == 1
    row = out["recent"][0]
    assert (row["reseller_id"], row["stage"]) == (texted.id, "t2")
    assert row["sms_status"] == "failed"
    assert row["sms_error"] == "Low bulk credits"
    assert row["inbox_sent"] is True

    s = out["summary"]
    assert (s["upcoming"], s["upcoming_without_phone"]) == (2, 1)
    assert (s["sent_last_7_days"], s["sms_failed_last_7_days"]) == (1, 1)


@pytest.mark.asyncio
async def test_overview_reports_pruned_sms_as_sent(db):
    """Sent SMS rows are pruned after the retention window; the log must survive."""
    await make_reseller(db, role=UserRole.ADMIN)
    reseller, expires = await _reseller_expiring(db, hours=2)
    await send_expiry_reminder(reseller.id, "t2", expires)
    sms = (await db.execute(select(SmsMessage))).scalars().one()
    await db.delete(sms)
    await db.commit()

    out = await reminder_overview(db)
    assert out["recent"][0]["sms_status"] == "sent"


@pytest.mark.asyncio
async def test_overview_reflects_the_kill_switch(db):
    db.add(MessagingSettings(id=1, subscription_reminders_enabled=False))
    await db.commit()
    assert (await reminder_overview(db))["enabled"] is False


# --------------------------------------------------------------------------
# HTTP: admin only, and the switch round-trips through messaging settings
# --------------------------------------------------------------------------

@pytest.fixture
def http(session_factory):
    application = FastAPI()
    application.include_router(asr.router)
    application.include_router(amr.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(asr, "get_current_user", _fake)
    monkeypatch.setattr(amr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_endpoint_is_admin_only(db, http, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.get("/api/admin/subscription-reminders")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_endpoint_and_switch_for_admin(db, http, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    await _reseller_expiring(db, hours=30)
    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.get("/api/admin/subscription-reminders?days=7")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["enabled"] is True
        assert body["summary"]["upcoming"] == 1
        assert [s["stage"] for s in body["stages"]] == ["t72", "t24", "t2"]

        settings = (await c.get("/api/admin/messaging/settings")).json()
        assert settings["subscription_reminders_enabled"] is True
        put = await c.put("/api/admin/messaging/settings",
                          json={"subscription_reminders_enabled": False})
        assert put.status_code == 200, put.text
        resp = await c.get("/api/admin/subscription-reminders")
        assert resp.json()["enabled"] is False

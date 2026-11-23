"""Router status SMS alerts go to every alert number a reseller lists.

A reseller asked for alerts on his own phone and his field technician's (up to
3 numbers). Rules pinned here:

- every alert event goes to every listed number, de-duplicated after
  normalisation ("0712 345 678" and "+254712345678" are one recipient);
- SMS credit is charged per recipient, in order; when it runs out partway the
  first numbers still get the alert and the rest are skipped;
- the per-router daily budget and the per-reseller daily SMS cap count each
  alert event once, never once per recipient;
- an empty list falls back to ``users.support_phone`` exactly as before;
- the GET/PUT endpoints validate numbers like ``support_phone`` (plus the
  Kenyan-mobile check for Kenyan resellers) and need the "SMS settings"
  staff permission.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.messaging_routes as mr
from app.api.messaging_routes import router as messaging_router
from app.config import settings
from app.db.database import get_db
from app.db.models import ResellerInboxMessage, Router, SmsMessage, User, UserRole
from app.services import alert_contacts, sms_credits
from app.services import router_status_alerts as rsa
from app.services import staff_permissions as perms
from app.services.auth import verify_token
from app.services.router_availability import record_router_availability
from tests.factories import make_reseller, make_router

TECH = "0722000002"
HELPER = "0733000003"


# ─── helpers ────────────────────────────────────────────────────────────────

async def _setup(db, *, support="254700000001", alert_phones=None, credits=10, routers=1):
    await make_reseller(db, role=UserRole.ADMIN,
                        email=f"admin-{datetime.utcnow().timestamp()}@example.com")
    owner = await make_reseller(db, support_phone=support, alert_phones=alert_phones)
    if credits:
        await sms_credits.grant(db, owner.id, credits, reference="test-grant")
        await db.commit()
    made = []
    for i in range(routers):
        made.append(await make_router(
            db, owner, name=f"Site #{i + 1}", status_alerts_enabled=True, last_status=False,
            last_checked_at=datetime.utcnow() - timedelta(minutes=2),
            last_online_at=datetime.utcnow() - timedelta(minutes=20)))
    return owner, made


def _capture_spawn(monkeypatch):
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", True)
    calls = []
    monkeypatch.setattr(rsa, "_spawn_alert_sms_dispatch",
                        lambda ids, sender: calls.append(list(ids)))
    return calls


async def _sms(db, user_id):
    return (await db.execute(select(SmsMessage).where(SmsMessage.user_id == user_id)
                             .order_by(SmsMessage.id))).scalars().all()


async def _inbox(db, user_id):
    return (await db.execute(select(ResellerInboxMessage)
                             .where(ResellerInboxMessage.recipient_user_id == user_id)
                             .order_by(ResellerInboxMessage.id))).scalars().all()


async def _balance(db, user_id):
    acct = await sms_credits.get_or_create_account(db, user_id)
    await db.refresh(acct)
    return acct.balance


async def _go_offline(db, router_id):
    r = await db.get(Router, router_id)
    await db.refresh(r)
    r.last_status = False
    r.last_checked_at = datetime.utcnow() - timedelta(minutes=2)
    r.last_online_at = datetime.utcnow() - timedelta(minutes=20)
    if r.offline_notified_at is not None:
        r.offline_notified_at = r.last_online_at - timedelta(minutes=40)
    if r.online_notified_at is not None:
        r.online_notified_at = r.last_online_at - timedelta(minutes=60)
    await db.commit()


# ─── recipients ─────────────────────────────────────────────────────────────

def test_recipients_fall_back_to_support_phone():
    owner = User(support_phone=" 254700000001 ", alert_phones=None)
    assert alert_contacts.alert_recipients(owner) == ["254700000001"]
    owner.alert_phones = []
    assert alert_contacts.alert_recipients(owner) == ["254700000001"]
    assert alert_contacts.alert_recipients(User(support_phone=None, alert_phones=None)) == []


def test_recipients_are_deduplicated_after_normalisation():
    owner = User(support_phone="254700000001",
                 alert_phones=["0712345678", "+254712345678", "712345678", TECH])
    assert alert_contacts.alert_recipients(owner) == ["0712345678", TECH]


# ─── sending ────────────────────────────────────────────────────────────────

async def test_alert_queues_one_sms_per_number_in_order(db, monkeypatch):
    calls = _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0711000001", TECH, HELPER])

    assert await rsa.scan_and_notify_offline_routers() == 1

    rows = await _sms(db, owner.id)
    assert [r.recipient_phone for r in rows] == ["0711000001", TECH, HELPER]
    assert len({r.body for r in rows}) == 1 and "appears to be offline" in rows[0].body
    assert all(r.category == rsa.ALERT_SMS_CATEGORY for r in rows)
    assert calls == [[r.id for r in rows]]       # one dispatch for the whole event
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and inbox[0].sent_sms is True


async def test_duplicate_spellings_get_one_sms(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0722 000 002", "+254722000002", HELPER])

    await rsa.scan_and_notify_offline_routers()

    rows = await _sms(db, owner.id)
    assert [r.recipient_phone for r in rows] == ["0722 000 002", HELPER]
    assert await _balance(db, owner.id) == 8


async def test_credit_is_charged_per_recipient(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0711000001", TECH, HELPER], credits=10)

    await rsa.scan_and_notify_offline_routers()

    rows = await _sms(db, owner.id)
    assert [r.credits_charged for r in rows] == [1, 1, 1]
    assert await _balance(db, owner.id) == 7


async def test_credit_running_out_sends_to_as_many_as_it_covers_in_order(db, monkeypatch):
    calls = _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0711000001", TECH, HELPER], credits=2)

    await rsa.scan_and_notify_offline_routers()

    rows = await _sms(db, owner.id)
    assert [r.recipient_phone for r in rows] == ["0711000001", TECH]
    assert await _balance(db, owner.id) == 0
    assert calls == [[r.id for r in rows]]
    assert (await _inbox(db, owner.id))[0].sent_sms is True


async def test_no_credit_at_all_is_inbox_only(db, monkeypatch):
    calls = _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0711000001", TECH], credits=0)

    await rsa.scan_and_notify_offline_routers()

    assert await _sms(db, owner.id) == []
    assert calls == []
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and inbox[0].sent_sms is False


async def test_empty_list_falls_back_to_support_phone(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=[])

    await rsa.scan_and_notify_offline_routers()

    rows = await _sms(db, owner.id)
    assert [r.recipient_phone for r in rows] == ["254700000001"]
    assert await _balance(db, owner.id) == 9


async def test_router_daily_budget_counts_each_event_once(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, (router,) = await _setup(db, alert_phones=["0711000001", TECH, HELPER], credits=50)

    for _ in range(5):                         # flapping: five outage/recovery cycles
        await _go_offline(db, router.id)
        await rsa.scan_and_notify_offline_routers()
        await record_router_availability(db, router.id, True, "test")

    r = await db.get(Router, router.id)
    await db.refresh(r)
    assert r.status_alerts_sent_today == rsa.MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 3                     # offline, back online, unstable
    rows = await _sms(db, owner.id)
    assert len(rows) == 3 * 3                  # each of the 3 events to each of 3 numbers


async def test_owner_daily_sms_cap_counts_events_not_recipients(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, routers = await _setup(db, alert_phones=["0711000001", TECH, HELPER],
                                  credits=100, routers=3)
    for r in routers:                          # 3 routers x (offline + back online) = 6 events
        await rsa.scan_and_notify_offline_routers()
        await record_router_availability(db, r.id, True, "test")

    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 6
    assert sum(1 for m in inbox if m.sent_sms) == rsa.MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY
    rows = await _sms(db, owner.id)
    assert len(rows) == rsa.MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY * 3


async def test_deliver_refunds_each_failed_recipient(db, monkeypatch):
    _capture_spawn(monkeypatch)
    owner, _ = await _setup(db, alert_phones=["0711000001", TECH], credits=5)
    await rsa.scan_and_notify_offline_routers()
    rows = await _sms(db, owner.id)
    assert await _balance(db, owner.id) == 3

    async def _fail_second(ids, sender, owner_user_id=None):
        from app.db.models import SmsMessageStatus
        from app.db import database
        async with database.async_session() as s:
            first = await s.get(SmsMessage, ids[0])
            first.status = SmsMessageStatus.SENT
            second = await s.get(SmsMessage, ids[1])
            second.status = SmsMessageStatus.FAILED
            await s.commit()

    monkeypatch.setattr("app.services.sms_dispatch.dispatch_admin_sms_messages", _fail_second)
    await rsa.deliver_alert_sms([r.id for r in rows], "TALKSASA")

    assert await _balance(db, owner.id) == 4


# ─── API ────────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(messaging_router)

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
    async with AsyncClient(transport=ASGITransport(app=application),
                           base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user_id):
    async def _fake(token, db):
        return await db.get(User, user_id)
    monkeypatch.setattr(mr, "get_current_user", _fake)


@pytest.mark.asyncio
async def test_get_defaults_to_support_phone(db, client, monkeypatch):
    owner = await make_reseller(db, support_phone="0700000001")
    _auth_as(monkeypatch, owner.id)

    resp = await client.get("/api/messaging/alert-contacts")

    assert resp.status_code == 200
    body = resp.json()
    assert body["phones"] == []
    assert body["recipients"] == ["0700000001"]
    assert body["using_support_phone"] is True
    assert body["max_phones"] == 3


@pytest.mark.asyncio
async def test_put_cleans_dedupes_and_saves(db, client, monkeypatch):
    owner = await make_reseller(db, support_phone="0700000001")
    _auth_as(monkeypatch, owner.id)

    resp = await client.put("/api/messaging/alert-contacts",
                            json={"phones": ["0722 000-002", "+254722000002", "(0733) 000003", ""]})

    assert resp.status_code == 200, resp.text
    assert resp.json()["phones"] == ["0722000002", "0733000003"]
    assert resp.json()["using_support_phone"] is False
    await db.refresh(owner)
    assert owner.alert_phones == ["0722000002", "0733000003"]

    cleared = await client.put("/api/messaging/alert-contacts", json={"phones": []})
    assert cleared.status_code == 200
    assert cleared.json()["recipients"] == ["0700000001"]
    await db.refresh(owner)
    assert owner.alert_phones is None


@pytest.mark.asyncio
@pytest.mark.parametrize("phones, detail", [
    (["0711000001", "0722000002", "0733000003", "0744000004"], "up to 3"),
    (["not-a-phone"], "Invalid phone number format"),
    (["12345"], "Invalid phone number format"),
    (["+33612345678"], "Kenyan mobile"),
])
async def test_put_rejects_invalid_lists(db, client, monkeypatch, phones, detail):
    owner = await make_reseller(db, support_phone="0700000001")
    _auth_as(monkeypatch, owner.id)

    resp = await client.put("/api/messaging/alert-contacts", json={"phones": phones})

    assert resp.status_code == 400
    assert detail in resp.json()["detail"]
    await db.refresh(owner)
    assert owner.alert_phones is None


@pytest.mark.asyncio
async def test_non_kenyan_reseller_may_save_international_numbers(db, client, monkeypatch):
    owner = await make_reseller(db, market_code="CM")
    _auth_as(monkeypatch, owner.id)

    resp = await client.put("/api/messaging/alert-contacts", json={"phones": ["+237670000001"]})

    assert resp.status_code == 200, resp.text
    assert resp.json()["phones"] == ["+237670000001"]


def test_staff_need_sms_settings_permission():
    for method in ("GET", "PUT"):
        rule, _ = perms.match_rule(method, "/api/messaging/alert-contacts")
        assert rule is not None
        assert rule.allows(frozenset({"messaging.settings"}))
        assert not rule.allows(frozenset({"messaging.send"}))
        assert not rule.allows(frozenset({"routers.manage"}))

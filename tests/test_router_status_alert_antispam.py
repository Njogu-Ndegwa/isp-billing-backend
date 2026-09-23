"""Status alerts must never spam a reseller, even for a flapping router.

Pinned incident (2026-09-24 audit): one reseller received 52 offline/back-online
messages in a single day (25 + 27) and another 14 SMS in a day, because every
outage >= 15 min produced a pair with only a 30-minute cooldown.
"""

from datetime import datetime, timedelta

from sqlalchemy import select

from app.config import settings
from app.core.local_time import local_midnight_utc
from app.db.models import ResellerInboxMessage, Router, SmsMessage, UserRole
from app.services import router_status_alerts as rsa, sms_credits
from app.services.router_availability import record_router_availability
from tests.factories import make_reseller, make_router


async def _inbox(db, user_id):
    rows = (await db.execute(select(ResellerInboxMessage)
                             .where(ResellerInboxMessage.recipient_user_id == user_id)
                             .order_by(ResellerInboxMessage.id))).scalars().all()
    return rows


async def _setup(db, *, phone=None, credits=0, routers=1):
    await make_reseller(db, role=UserRole.ADMIN, email=f"admin-{datetime.utcnow().timestamp()}@x.io")
    owner = await make_reseller(db, support_phone=phone)
    if credits:
        await sms_credits.grant(db, owner.id, credits, reference="t")
        await db.commit()
    made = []
    for i in range(routers):
        made.append(await make_router(
            db, owner, name=f"Flappy #{i + 1}", status_alerts_enabled=True, last_status=False,
            last_checked_at=datetime.utcnow() - timedelta(minutes=2),
            last_online_at=datetime.utcnow() - timedelta(minutes=20)))
    return owner, made


async def _go_offline(db, router_id):
    """Simulate a fresh outage long enough to pass the 15-minute gate."""
    r = await db.get(Router, router_id)
    await db.refresh(r)
    r.last_status = False
    r.last_checked_at = datetime.utcnow() - timedelta(minutes=2)
    r.last_online_at = datetime.utcnow() - timedelta(minutes=20)
    # Age the per-outage/cooldown stamps so ONLY the daily budget can stop us.
    if r.offline_notified_at is not None:
        r.offline_notified_at = r.last_online_at - timedelta(minutes=40)
    if r.online_notified_at is not None:
        r.online_notified_at = r.last_online_at - timedelta(minutes=60)
    await db.commit()


async def test_flapping_router_gets_at_most_three_messages_a_day(db):
    owner, (router,) = await _setup(db)
    for _ in range(10):                       # ten full outage/recovery cycles
        await _go_offline(db, router.id)
        await rsa.scan_and_notify_offline_routers()
        await record_router_availability(db, router.id, True, "test")

    msgs = await _inbox(db, owner.id)
    assert [m.subject.split(":")[0] for m in msgs] == [
        "Router offline", "Router back online", "Router connection unstable"]
    assert "until tomorrow" in msgs[2].body
    r = await db.get(Router, router.id)
    await db.refresh(r)
    assert r.status_alerts_sent_today == rsa.MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY


async def test_budget_resets_the_next_local_day(db):
    owner, (router,) = await _setup(db)
    r = await db.get(Router, router.id)
    r.status_alerts_day = "2000-01-01"          # yesterday's spent budget
    r.status_alerts_sent_today = rsa.MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY
    await db.commit()
    assert await rsa.scan_and_notify_offline_routers() == 1
    msgs = await _inbox(db, owner.id)
    assert len(msgs) == 1 and msgs[0].subject.startswith("Router offline")


async def test_spent_budget_keeps_outage_unannounced_for_tomorrow(db):
    owner, (router,) = await _setup(db)
    r = await db.get(Router, router.id)
    r.status_alerts_day = rsa._local_day(datetime.utcnow())
    r.status_alerts_sent_today = rsa.MAX_STATUS_ALERTS_PER_ROUTER_PER_DAY
    await db.commit()
    assert await rsa.scan_and_notify_offline_routers() == 0
    await db.refresh(r)
    assert r.offline_notified_at is None      # rolled back, so tomorrow can announce it
    assert await _inbox(db, owner.id) == []


async def test_no_back_online_for_an_outage_we_never_announced(db):
    owner, (router,) = await _setup(db)
    await record_router_availability(db, router.id, True, "test")
    assert await _inbox(db, owner.id) == []


def test_decide_daily_kind_rules():
    now = datetime.utcnow()
    today = rsa._local_day(now)
    fresh = Router(status_alerts_day=None, status_alerts_sent_today=0, last_online_at=now)
    assert rsa.decide_daily_kind(fresh, rsa.KIND_OFFLINE, now) == (rsa.KIND_OFFLINE, 1)
    once = Router(status_alerts_day=today, status_alerts_sent_today=1)
    assert rsa.decide_daily_kind(once, rsa.KIND_OFFLINE, now) == (rsa.KIND_UNSTABLE, 3)
    spent = Router(status_alerts_day=today, status_alerts_sent_today=3)
    assert rsa.decide_daily_kind(spent, rsa.KIND_OFFLINE, now) is None
    unannounced = Router(status_alerts_day=today, status_alerts_sent_today=1,
                         offline_notified_at=None, online_notified_at=None)
    assert rsa.decide_daily_kind(unannounced, rsa.KIND_RECOVERY, now) is None
    assert rsa.decide_daily_kind(unannounced, rsa.KIND_RECOVERY, now,
                                 first_ever_online=True) == (rsa.KIND_RECOVERY, 2)
    announced = Router(status_alerts_day=today, status_alerts_sent_today=1,
                       offline_notified_at=now, online_notified_at=now - timedelta(hours=1))
    assert rsa.decide_daily_kind(announced, rsa.KIND_RECOVERY, now) == (rsa.KIND_RECOVERY, 2)


async def test_budget_claim_is_compare_and_swap(db):
    _, (router,) = await _setup(db)
    now = datetime.utcnow()
    stale = await db.get(Router, router.id)
    snapshot = Router(id=stale.id, status_alerts_day=stale.status_alerts_day,
                      status_alerts_sent_today=stale.status_alerts_sent_today or 0)
    assert await rsa._spend_daily_budget(db, snapshot, 1, now) is True
    await db.commit()
    # A second writer holding the same (now stale) view must lose.
    assert await rsa._spend_daily_budget(db, snapshot, 1, now) is False
    await db.rollback()


async def test_owner_sms_capped_across_routers(db, monkeypatch):
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", True)
    monkeypatch.setattr(rsa, "_spawn_alert_sms_dispatch", lambda *a: None)
    owner, routers = await _setup(db, phone="254700000009", credits=50, routers=4)
    for r in routers:                         # 4 routers x (offline + back online)
        await rsa.scan_and_notify_offline_routers()
        await record_router_availability(db, r.id, True, "test")

    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 8                    # inbox still records every event
    sms = (await db.execute(select(SmsMessage).where(
        SmsMessage.user_id == owner.id,
        SmsMessage.created_at >= local_midnight_utc()))).scalars().all()
    assert len(sms) == rsa.MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY
    assert sum(1 for m in inbox if m.sent_sms) == rsa.MAX_STATUS_ALERT_SMS_PER_OWNER_PER_DAY

"""Opt-in router status alerts (app/services/router_status_alerts.py).

Covers both directions:
- recovery ("back online") via the transition hook in record_router_availability
- outage ("went offline") via the debounced scheduler scan

plus the noise-control gates: opt-in flag, minimum outage duration, staleness
window, per-outage stamp, and cooldown claims.
"""

from datetime import datetime, timedelta

from sqlalchemy import select

from app.db.models import ResellerInboxMessage, Router, User, UserRole
from app.services.router_availability import record_router_availability
from app.services.router_status_alerts import (
    MIN_OUTAGE_FOR_ALERTS,
    NOTIFY_COOLDOWN,
    OFFLINE_STATUS_FRESH_WINDOW,
    scan_and_notify_offline_routers,
    should_consider_recovery_notification,
)
from tests.factories import make_reseller, make_router


async def _make_admin(db) -> User:
    return await make_reseller(
        db, role=UserRole.ADMIN, email=f"admin-{datetime.utcnow().timestamp()}@example.com"
    )


async def _setup_offline_router(db, *, alerts=True, offline_for=timedelta(hours=2),
                                checked_ago=timedelta(minutes=3)):
    admin = await _make_admin(db)
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        status_alerts_enabled=alerts,
        last_status=False,
        last_checked_at=datetime.utcnow() - checked_ago,
        last_online_at=datetime.utcnow() - offline_for,
    )
    return admin, reseller, router


async def _inbox_messages(db, recipient_id):
    result = await db.execute(
        select(ResellerInboxMessage).where(
            ResellerInboxMessage.recipient_user_id == recipient_id
        )
    )
    return result.scalars().all()


# ─── Recovery ("back online") direction ─────────────────────────────────────

async def test_offline_to_online_transition_sends_recovery_message(db):
    _, reseller, router = await _setup_offline_router(db)

    await record_router_availability(db, router.id, True, "test")

    messages = await _inbox_messages(db, reseller.id)
    assert len(messages) == 1
    assert router.name in messages[0].subject
    assert "back online" in messages[0].body
    assert "2 hours" in messages[0].body
    assert messages[0].sent_sms is False

    refreshed = await db.get(Router, router.id)
    await db.refresh(refreshed)
    assert refreshed.online_notified_at is not None
    assert refreshed.last_status is True


async def test_no_recovery_message_when_not_opted_in(db):
    _, reseller, router = await _setup_offline_router(db, alerts=False)

    await record_router_availability(db, router.id, True, "test")

    assert await _inbox_messages(db, reseller.id) == []


async def test_short_blip_does_not_send_recovery(db):
    _, reseller, router = await _setup_offline_router(
        db, offline_for=MIN_OUTAGE_FOR_ALERTS - timedelta(minutes=1)
    )

    await record_router_availability(db, router.id, True, "test")

    assert await _inbox_messages(db, reseller.id) == []


async def test_online_to_online_does_not_notify(db):
    await _make_admin(db)
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        status_alerts_enabled=True,
        last_status=True,
        last_checked_at=datetime.utcnow(),
        last_online_at=datetime.utcnow(),
    )

    await record_router_availability(db, router.id, True, "test")

    assert await _inbox_messages(db, reseller.id) == []


async def test_recovery_cooldown_blocks_repeat_notification(db):
    _, reseller, router = await _setup_offline_router(db)

    await record_router_availability(db, router.id, True, "test")
    assert len(await _inbox_messages(db, reseller.id)) == 1

    # Flap: offline long enough to pass the min-outage gate, then online again
    # inside the cooldown window — no second message.
    flap_router = await db.get(Router, router.id)
    await db.refresh(flap_router)  # pick up the service's writes before mutating
    flap_router.last_status = False
    flap_router.last_online_at = datetime.utcnow() - (
        MIN_OUTAGE_FOR_ALERTS + timedelta(minutes=5)
    )
    await db.commit()

    await record_router_availability(db, router.id, True, "test")
    assert len(await _inbox_messages(db, reseller.id)) == 1

    # Once the cooldown has lapsed, the same shape notifies again.
    aged = await db.get(Router, router.id)
    await db.refresh(aged)
    aged.last_status = False
    aged.last_online_at = datetime.utcnow() - (MIN_OUTAGE_FOR_ALERTS + timedelta(minutes=5))
    aged.online_notified_at = datetime.utcnow() - (NOTIFY_COOLDOWN + timedelta(minutes=1))
    await db.commit()

    await record_router_availability(db, router.id, True, "test")
    assert len(await _inbox_messages(db, reseller.id)) == 2


async def test_never_online_router_notifies_on_first_online(db):
    await _make_admin(db)
    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        status_alerts_enabled=True,
        last_status=False,
        last_checked_at=datetime.utcnow() - timedelta(minutes=3),
        last_online_at=None,
    )

    await record_router_availability(db, router.id, True, "test")

    messages = await _inbox_messages(db, reseller.id)
    assert len(messages) == 1
    assert "now online" in messages[0].body


def test_should_consider_requires_offline_previous_status():
    router = Router(
        status_alerts_enabled=True,
        last_status=None,
        name="r",
        ip_address="10.0.0.9",
        username="u",
        password="p",
        user_id=1,
    )
    assert should_consider_recovery_notification(router, datetime.utcnow()) is False


# ─── Outage ("went offline") direction ──────────────────────────────────────

async def test_offline_scan_sends_notice_after_threshold(db):
    _, reseller, router = await _setup_offline_router(
        db, offline_for=MIN_OUTAGE_FOR_ALERTS + timedelta(minutes=5)
    )

    sent = await scan_and_notify_offline_routers()
    assert sent == 1

    messages = await _inbox_messages(db, reseller.id)
    assert len(messages) == 1
    assert "offline" in messages[0].subject.lower()
    assert "appears to be offline" in messages[0].body
    assert "20 minutes" in messages[0].body
    assert messages[0].sent_sms is False

    # Second scan: same outage already announced, nothing new.
    assert await scan_and_notify_offline_routers() == 0
    assert len(await _inbox_messages(db, reseller.id)) == 1


async def test_offline_scan_respects_min_outage_threshold(db):
    _, reseller, _ = await _setup_offline_router(
        db, offline_for=MIN_OUTAGE_FOR_ALERTS - timedelta(minutes=1)
    )

    assert await scan_and_notify_offline_routers() == 0
    assert await _inbox_messages(db, reseller.id) == []


async def test_offline_scan_skips_not_opted_in(db):
    _, reseller, _ = await _setup_offline_router(db, alerts=False)

    assert await scan_and_notify_offline_routers() == 0
    assert await _inbox_messages(db, reseller.id) == []


async def test_offline_scan_skips_never_online_router(db):
    await _make_admin(db)
    reseller = await make_reseller(db)
    await make_router(
        db,
        reseller,
        status_alerts_enabled=True,
        last_status=False,
        last_checked_at=datetime.utcnow() - timedelta(minutes=3),
        last_online_at=None,
    )

    assert await scan_and_notify_offline_routers() == 0
    assert await _inbox_messages(db, reseller.id) == []


async def test_offline_scan_skips_stale_status(db):
    # Nothing has probed the router in a long time: status is "unknown",
    # not a confirmed outage — no alarm.
    _, reseller, _ = await _setup_offline_router(
        db,
        offline_for=timedelta(hours=5),
        checked_ago=OFFLINE_STATUS_FRESH_WINDOW + timedelta(minutes=5),
    )

    assert await scan_and_notify_offline_routers() == 0
    assert await _inbox_messages(db, reseller.id) == []


async def test_full_outage_and_recovery_pair(db):
    _, reseller, router = await _setup_offline_router(db, offline_for=timedelta(minutes=30))

    assert await scan_and_notify_offline_routers() == 1
    await record_router_availability(db, router.id, True, "test")

    messages = await _inbox_messages(db, reseller.id)
    assert len(messages) == 2
    assert "offline" in messages[0].subject.lower()
    assert "back online" in messages[1].subject.lower()

    # A later, separate outage (stamps aged past the cooldown) notifies again.
    aged = await db.get(Router, router.id)
    await db.refresh(aged)
    aged.last_status = False
    aged.last_checked_at = datetime.utcnow() - timedelta(minutes=3)
    aged.last_online_at = datetime.utcnow() - timedelta(minutes=20)
    aged.offline_notified_at = datetime.utcnow() - (NOTIFY_COOLDOWN + timedelta(minutes=1))
    await db.commit()

    assert await scan_and_notify_offline_routers() == 1
    assert len(await _inbox_messages(db, reseller.id)) == 3

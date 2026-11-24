"""BD-8: tell the reseller when the safety net cuts off a device that had
internet without a valid payment. Rides on the existing safety-net scan; no
new router access."""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import ResellerInboxMessage, SubscriptionStatus
from app.services import mikrotik_background, unpaid_device_alerts
from tests.factories import make_admin, make_reseller, make_router


pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _fresh_throttle():
    unpaid_device_alerts._last_sent.clear()
    yield
    unpaid_device_alerts._last_sent.clear()


def _patch_scan(monkeypatch, session_factory, macs_by_ip):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(unpaid_device_alerts.database, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_a: False)

    def fake_find(router_info, active_macs):
        return set(macs_by_ip.get(router_info["ip"], set()))

    async def fake_filter(candidates):
        return set(candidates)

    def fake_remove(router_info, orphan_macs):
        return len(orphan_macs)

    monkeypatch.setattr(mikrotik_background, "_find_router_binding_cleanup_candidates_sync", fake_find)
    monkeypatch.setattr(mikrotik_background, "_filter_current_orphan_bypass_macs", fake_filter)
    monkeypatch.setattr(mikrotik_background, "_remove_router_bindings_sync", fake_remove)


async def _inbox(db, user_id):
    rows = await db.execute(
        select(ResellerInboxMessage).where(ResellerInboxMessage.recipient_user_id == user_id)
    )
    return rows.scalars().all()


async def test_removal_sends_one_message_without_full_mac(db, session_factory, monkeypatch):
    await make_admin(db)
    reseller = await make_reseller(db)
    await make_router(db, reseller, ip_address="10.0.0.40", port=8728, name="OPIC #2")
    _patch_scan(monkeypatch, session_factory, {
        "10.0.0.40": {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"},
    })

    removed = await mikrotik_background._cleanup_bypassing_for_all_routers(db)

    assert removed == 2
    msgs = await _inbox(db, reseller.id)
    assert len(msgs) == 1
    text = f"{msgs[0].subject} {msgs[0].body}"
    assert "OPIC #2" in text
    assert "EE:01" in text and "EE:02" in text
    assert "AA:BB:CC:DD:EE:01" not in text and "AA:BB:CC:DD:EE:02" not in text
    assert "AA:BB" not in text


async def test_second_removal_within_six_hours_sends_nothing(db, session_factory, monkeypatch):
    await make_admin(db)
    reseller = await make_reseller(db)
    await make_router(db, reseller, ip_address="10.0.0.41", port=8728)
    _patch_scan(monkeypatch, session_factory, {"10.0.0.41": {"AA:BB:CC:DD:EE:03"}})

    await mikrotik_background._cleanup_bypassing_for_all_routers(db)
    _patch_scan(monkeypatch, session_factory, {"10.0.0.41": {"AA:BB:CC:DD:EE:04"}})
    await mikrotik_background._cleanup_bypassing_for_all_routers(db)

    assert len(await _inbox(db, reseller.id)) == 1


async def test_throttle_expires_after_six_hours(db, session_factory, monkeypatch):
    await make_admin(db)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    monkeypatch.setattr(unpaid_device_alerts.database, "async_session", session_factory)
    t0 = datetime.utcnow()

    assert await unpaid_device_alerts.notify_unpaid_devices_removed(
        {router.id: {"AA:BB:CC:DD:EE:05"}}, now=t0) == 1
    assert await unpaid_device_alerts.notify_unpaid_devices_removed(
        {router.id: {"AA:BB:CC:DD:EE:06"}}, now=t0 + timedelta(hours=5)) == 0
    assert await unpaid_device_alerts.notify_unpaid_devices_removed(
        {router.id: {"AA:BB:CC:DD:EE:07"}}, now=t0 + timedelta(hours=6, minutes=1)) == 1
    assert len(await _inbox(db, reseller.id)) == 2


@pytest.mark.parametrize("status", ["SUSPENDED", "INACTIVE"])
async def test_cut_off_owner_gets_no_message(db, session_factory, monkeypatch, status):
    await make_admin(db)
    reseller = await make_reseller(db, subscription_status=getattr(SubscriptionStatus, status))
    router = await make_router(db, reseller)
    monkeypatch.setattr(unpaid_device_alerts.database, "async_session", session_factory)

    sent = await unpaid_device_alerts.notify_unpaid_devices_removed(
        {router.id: {"AA:BB:CC:DD:EE:08"}})

    assert sent == 0
    assert await _inbox(db, reseller.id) == []


async def test_admin_owned_router_gets_no_message(db, session_factory, monkeypatch):
    admin = await make_admin(db)
    router = await make_router(db, admin)
    monkeypatch.setattr(unpaid_device_alerts.database, "async_session", session_factory)

    sent = await unpaid_device_alerts.notify_unpaid_devices_removed(
        {router.id: {"AA:BB:CC:DD:EE:09"}})

    assert sent == 0
    assert await _inbox(db, admin.id) == []

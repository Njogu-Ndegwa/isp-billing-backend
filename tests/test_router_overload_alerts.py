"""Router overload alerts to resellers (app/services/router_overload_alerts.py).

Pinned incident: 2026-09-23, router 371 (hAP lite) at 100% CPU every evening;
TCP to its API port connected in 0.3 s but logins took ~100 s, so every paid
customer failed to provision and nobody told the reseller.
"""

from datetime import datetime, timedelta
from itertools import count

import pytest
from sqlalchemy import select

from app.config import settings
from app.core.local_time import local_midnight_utc
from app.db.models import (
    ProvisioningAttempt, ProvisioningAttemptEntrypoint, ProvisioningAttemptSource,
    ProvisioningState, ResellerInboxMessage, Router, SmsMessage, SmsMessageKind,
    SmsMessageStatus, SubscriptionStatus, UserRole,
)
from app.services import router_overload_alerts as oa
from tests.factories import make_customer, make_plan, make_reseller, make_router

_PK = count(80_000)


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_OVERLOAD_ALERTS_ENABLED", True)
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", True)
    monkeypatch.setattr(oa, "_db_pool_too_busy", lambda: False)
    oa._cpu_history.clear()
    yield
    oa._cpu_history.clear()


@pytest.fixture
def sms_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(oa, "_spawn_sms", lambda sms_id, sender: calls.append(sms_id))
    return calls


@pytest.fixture
def reachable(monkeypatch):
    state = {"up": True, "probed": []}

    async def _tcp(host, port, timeout=3.0):
        state["probed"].append(host)
        return state["up"]
    monkeypatch.setattr(oa, "tcp_reachable", _tcp)
    return state


async def _setup(db, *, failures=3, age=timedelta(minutes=5), alerts=True,
                 owner_status=SubscriptionStatus.ACTIVE, phone="254704009555",
                 state=ProvisioningState.RETRY_PENDING):
    await make_reseller(db, role=UserRole.ADMIN, email=f"admin{next(_PK)}@example.com")
    owner = await make_reseller(db, support_phone=phone, subscription_status=owner_status)
    plan = await make_plan(db, owner)
    router = await make_router(db, owner, name="lee net hotspot #1", ip_address="10.0.0.138",
                               status_alerts_enabled=alerts)
    now = datetime.utcnow()
    for _ in range(failures):
        c = await make_customer(db, owner, plan, router)
        db.add(ProvisioningAttempt(
            customer_id=c.id, router_id=router.id, mac_address=c.mac_address,
            source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_PK),
            entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, provisioning_state=state,
            attempt_count=4, last_error="Failed to connect", created_at=now - age,
            last_attempt_at=now - age, updated_at=now - age))
    await db.commit()
    return owner, router


async def _inbox(db, user_id):
    return (await db.execute(select(ResellerInboxMessage)
                             .where(ResellerInboxMessage.recipient_user_id == user_id))).scalars().all()


async def _sms(db, user_id):
    return (await db.execute(select(SmsMessage).where(SmsMessage.user_id == user_id))).scalars().all()


async def test_failing_payments_on_reachable_router_alert_owner_platform_paid(db, sms_calls, reachable):
    owner, router = await _setup(db)

    assert await oa.scan_payment_overload() == 1

    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and "overloaded" in inbox[0].subject
    assert "3 payments" in inbox[0].body and "restart" in inbox[0].body
    sms = await _sms(db, owner.id)
    assert len(sms) == 1
    assert sms[0].credits_charged == 0                      # platform pays
    assert sms[0].category == oa.OVERLOAD_SMS_CATEGORY
    assert sms[0].kind == SmsMessageKind.ADMIN_TO_RESELLER
    assert sms[0].status == SmsMessageStatus.QUEUED
    assert sms_calls == [sms[0].id]
    await db.refresh(router)
    assert router.overload_critical_notified_at is not None


async def test_only_one_alert_per_router_per_local_day(db, sms_calls, reachable):
    owner, router = await _setup(db)
    assert await oa.scan_payment_overload() == 1
    assert await oa.scan_payment_overload() == 0
    assert len(await _inbox(db, owner.id)) == 1

    # Stamp from yesterday (before local midnight) -> allowed again today.
    fresh = await db.get(Router, router.id)
    fresh.overload_critical_notified_at = local_midnight_utc() - timedelta(minutes=1)
    await db.commit()
    assert await oa.scan_payment_overload() == 1


async def test_unreachable_router_is_left_to_offline_alerts(db, sms_calls, reachable):
    reachable["up"] = False
    owner, _ = await _setup(db)
    assert await oa.scan_payment_overload() == 0
    assert await _inbox(db, owner.id) == []
    assert reachable["probed"] == ["10.0.0.138"]


@pytest.mark.parametrize("kwargs", [
    {"failures": 2},                                  # below threshold
    {"age": timedelta(minutes=45)},                   # outside the 20-min window
    {"alerts": False},                                # reseller opted out
    {"state": ProvisioningState.ROUTER_UPDATED},      # delivered, not failing
])
async def test_no_alert_without_the_overload_signal(db, sms_calls, reachable, kwargs):
    owner, _ = await _setup(db, **kwargs)
    assert await oa.scan_payment_overload() == 0
    assert await _inbox(db, owner.id) == []


async def test_suspended_owner_gets_nothing(db, sms_calls, reachable):
    owner, _ = await _setup(db, owner_status=SubscriptionStatus.SUSPENDED)
    assert await oa.scan_payment_overload() == 0
    assert await _inbox(db, owner.id) == []


async def test_inbox_only_when_sms_dispatch_is_off(db, sms_calls, reachable, monkeypatch):
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", False)
    owner, _ = await _setup(db)
    assert await oa.scan_payment_overload() == 1
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and inbox[0].sent_sms is False
    assert await _sms(db, owner.id) == [] and sms_calls == []


async def test_scan_is_skipped_when_disabled_or_db_busy(db, sms_calls, reachable, monkeypatch):
    owner, _ = await _setup(db)
    monkeypatch.setattr(oa, "_db_pool_too_busy", lambda: True)
    assert await oa.scan_payment_overload() == 0
    monkeypatch.setattr(oa, "_db_pool_too_busy", lambda: False)
    monkeypatch.setattr(settings, "ROUTER_OVERLOAD_ALERTS_ENABLED", False)
    assert await oa.scan_payment_overload() == 0
    assert reachable["probed"] == []


async def test_scan_never_raises(db, monkeypatch):
    async def _boom(now):
        raise RuntimeError("db down")
    monkeypatch.setattr(oa, "find_payment_overload_candidates", _boom)
    assert await oa.scan_payment_overload() == 0


async def test_tcp_reachable_is_false_for_closed_port():
    assert await oa.tcp_reachable("127.0.0.1", 1, timeout=1.0) is False


# --- CPU levels ------------------------------------------------------------------------

def _samples(router_id, values, start=None, step=timedelta(minutes=5)):
    t = start or datetime(2026, 9, 23, 17, 0)
    for v in values:
        oa.record_cpu_sample(router_id, v, t)
        t += step


def test_cpu_warning_needs_ten_sustained_minutes():
    _samples(1, [92, 95])
    assert oa.evaluate_cpu_level(1) is None
    _samples(2, [92, 95, 91])
    assert oa.evaluate_cpu_level(2) == oa.LEVEL_WARNING
    _samples(3, [92, 80, 95])
    assert oa.evaluate_cpu_level(3) is None


def test_cpu_critical_needs_two_readings_at_100():
    _samples(4, [100])
    assert oa.evaluate_cpu_level(4) is None
    _samples(5, [100, 100])
    assert oa.evaluate_cpu_level(5) == oa.LEVEL_CRITICAL


def test_gap_between_samples_breaks_sustained():
    _samples(6, [95, 95, 95], step=timedelta(minutes=20))
    assert oa.evaluate_cpu_level(6) is None


async def test_cpu_poll_alerts_owner_and_stores_reading(db, sms_calls, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_SNMP_POLL_ENABLED", True)
    monkeypatch.setattr(settings, "ROUTER_SNMP_COMMUNITY", "bw-ro")
    owner, router = await _setup(db, failures=0)
    r = await db.get(Router, router.id)
    r.snmp_enabled = True
    await db.commit()

    async def _cpu(host, community, timeout=2.0, retries=1):
        assert community == "bw-ro"
        return 100
    monkeypatch.setattr(oa.snmp_cpu, "read_cpu_load", _cpu)

    t0 = datetime.utcnow() - timedelta(minutes=5)
    assert await oa.poll_router_cpu(now=t0) == 1
    assert await _inbox(db, owner.id) == []                 # one reading is not enough
    assert await oa.poll_router_cpu(now=t0 + timedelta(minutes=5)) == 1
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and "100% CPU" in inbox[0].body
    await db.refresh(r)
    assert r.cpu_load == 100 and r.cpu_checked_at is not None


async def test_cpu_poll_is_off_until_configured(db, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_SNMP_POLL_ENABLED", True)
    monkeypatch.setattr(settings, "ROUTER_SNMP_COMMUNITY", "")
    assert await oa.poll_router_cpu() == 0
    monkeypatch.setattr(settings, "ROUTER_SNMP_POLL_ENABLED", False)
    monkeypatch.setattr(settings, "ROUTER_SNMP_COMMUNITY", "bw-ro")
    assert await oa.poll_router_cpu() == 0


async def test_unenrolled_router_is_never_polled(db, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_SNMP_POLL_ENABLED", True)
    monkeypatch.setattr(settings, "ROUTER_SNMP_COMMUNITY", "bw-ro")
    await _setup(db, failures=0)
    polled = []

    async def _cpu(host, community, timeout=2.0, retries=1):
        polled.append(host)
        return 50
    monkeypatch.setattr(oa.snmp_cpu, "read_cpu_load", _cpu)
    assert await oa.poll_router_cpu() == 0 and polled == []


def test_messages_fit_in_two_sms_segments():
    from app.services.messaging import count_segments
    _, body = oa.render_payment_overload("lee net hotspot #1", 12)
    assert count_segments(body) <= 2
    for level in (oa.LEVEL_WARNING, oa.LEVEL_CRITICAL):
        _, body = oa.render_cpu_alert("lee net hotspot #1", level, 97)
        assert count_segments(body) <= 2

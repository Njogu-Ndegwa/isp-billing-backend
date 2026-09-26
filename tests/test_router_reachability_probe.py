"""The reachability probe keeps router status current without logging in.

2026-09-26: the dashboard read "24 of 281 online" because status was only
recorded when some job happened to talk to a router; quiet routers (hAP lites
moved back to polling) looked stale although a direct check found them up.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import Router, RouterAvailabilityCheck, SubscriptionStatus
from app.services import router_reachability_probe as probe
from tests.factories import make_reseller, make_router


def _answering(up_ips):
    calls = []

    async def reachable(ip, port, timeout):
        calls.append(ip)
        return ip in up_ips

    return reachable, calls


async def _router(db, reseller, ip, **kw):
    return await make_router(db, reseller, ip_address=ip, **kw)


@pytest.mark.asyncio
async def test_quiet_routers_are_probed_and_marked_online(db, session_factory):
    reseller = await make_reseller(db)
    quiet = await _router(db, reseller, "10.0.9.1", last_status=True,
                          last_checked_at=datetime.utcnow() - timedelta(hours=3),
                          last_online_at=datetime.utcnow() - timedelta(hours=3))
    await db.commit()
    reachable, calls = _answering({"10.0.9.1"})

    summary = await probe.probe_router_reachability(reachable=reachable, pool_is_busy=lambda: False)

    assert summary == {"probed": 1, "online": 1, "offline": 0}
    async with session_factory() as s:
        r = await s.get(Router, quiet.id)
        assert r.last_status is True
        assert (datetime.utcnow() - r.last_checked_at).total_seconds() < 60
        assert (datetime.utcnow() - r.last_online_at).total_seconds() < 60
        src = (await s.execute(select(RouterAvailabilityCheck.source)
                               .where(RouterAvailabilityCheck.router_id == quiet.id))).scalars().all()
    assert src == ["reachability_probe"]


@pytest.mark.asyncio
async def test_recently_checked_and_cut_off_routers_are_left_alone(db):
    reseller = await make_reseller(db)
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    await _router(db, reseller, "10.0.9.2", last_status=True, last_checked_at=datetime.utcnow())  # pushing
    await _router(db, suspended, "10.0.9.3", last_status=True,
                  last_checked_at=datetime.utcnow() - timedelta(hours=3))
    await db.commit()
    reachable, calls = _answering(set())

    summary = await probe.probe_router_reachability(reachable=reachable, pool_is_busy=lambda: False)

    assert summary["probed"] == 0 and calls == []


@pytest.mark.asyncio
async def test_one_failed_probe_is_retried_and_does_not_flip_status(db, session_factory, monkeypatch):
    # Offline needs two failed checks within 5 min (record_router_availability's
    # debounce); a single probe run must not mark a router down.
    reseller = await make_reseller(db)
    router = await _router(db, reseller, "10.0.9.4", last_status=True,
                           last_checked_at=datetime.utcnow() - timedelta(hours=1),
                           last_online_at=datetime.utcnow() - timedelta(hours=1))
    await db.commit()
    reachable, calls = _answering(set())
    monkeypatch.setattr(probe, "RETRY_DELAY_SECONDS", 0)

    summary = await probe.probe_router_reachability(reachable=reachable, pool_is_busy=lambda: False)

    assert summary == {"probed": 1, "online": 0, "offline": 1}
    assert calls == ["10.0.9.4", "10.0.9.4"]           # retried once
    async with session_factory() as s:
        assert (await s.get(Router, router.id)).last_status is True   # not confirmed yet

    # Second run minutes later: two failures inside the window confirm it.
    await probe.probe_router_reachability(reachable=reachable, pool_is_busy=lambda: False)
    async with session_factory() as s:
        assert (await s.get(Router, router.id)).last_status is False


@pytest.mark.asyncio
async def test_sheds_when_the_db_pool_is_busy(db):
    reachable, calls = _answering(set())
    assert await probe.probe_router_reachability(reachable=reachable, pool_is_busy=lambda: True) == {"skipped": "db_busy"}
    assert calls == []


@pytest.mark.asyncio
async def test_outages_that_began_before_the_probe_are_not_announced(db, session_factory):
    # Dennis 2026-09-26: the probe confirms old, unnoticed outages; their
    # resellers get no late "went offline" message. New outages still do.
    from app.db.models import AppSetting
    from app.services import router_status_alerts as alerts

    went_live = datetime.utcnow() - timedelta(hours=1)
    reseller = await make_reseller(db)
    old = await _router(db, reseller, "10.0.9.5", last_status=False, status_alerts_enabled=True,
                        last_checked_at=datetime.utcnow(), last_online_at=went_live - timedelta(hours=5))
    new = await _router(db, reseller, "10.0.9.6", last_status=False, status_alerts_enabled=True,
                        last_checked_at=datetime.utcnow(), last_online_at=datetime.utcnow() - timedelta(minutes=30))
    await db.commit()
    now = datetime.utcnow()

    async with session_factory() as s:   # no cutoff row: both eligible, as before the probe
        both = set((await s.execute(select(Router.id).where(
            *alerts._offline_candidate_filters(now, await alerts._outage_alerts_from(s))))).scalars())
    assert {old.id, new.id} <= both

    async with session_factory() as s:
        s.add(AppSetting(key=alerts.OUTAGE_ALERTS_FROM_SETTING, value=went_live.strftime("%Y-%m-%dT%H:%M:%S")))
        await s.commit()
    async with session_factory() as s:
        ids = set((await s.execute(select(Router.id).where(
            *alerts._offline_candidate_filters(now, await alerts._outage_alerts_from(s))))).scalars())
    assert new.id in ids and old.id not in ids

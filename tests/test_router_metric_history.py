"""Bounded router health history (router_metric_buckets) behind the CPU/memory
graphs: folding samples, reboots and WAN link drops, reading dense series,
retention, and the endpoint's ownership check."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import usage_routes
from app.db import database
from app.db.models import RouterHealth, RouterMetricBucket
from app.services import router_health as rh
from app.services import router_metric_history as mh
from tests.factories import make_reseller, make_router

MB = 1024 * 1024
T0 = datetime(2026, 11, 23, 10, 1, 30)   # inside the 10:00 five-minute bucket


async def _buckets(db, router_id, step):
    rows = (await db.execute(
        select(RouterMetricBucket)
        .where(RouterMetricBucket.router_id == router_id,
               RouterMetricBucket.step_seconds == step)
        .order_by(RouterMetricBucket.bucket_start)
        .execution_options(populate_existing=True)
    )).scalars().all()
    return rows


# --- pure helpers ---------------------------------------------------------------------

@pytest.mark.parametrize("ts,step,expected", [
    (datetime(2026, 11, 23, 10, 4, 59), 300, datetime(2026, 11, 23, 10, 0)),
    (datetime(2026, 11, 23, 10, 5, 0), 300, datetime(2026, 11, 23, 10, 5)),
    (datetime(2026, 11, 23, 23, 59, 59, 999), 3600, datetime(2026, 11, 23, 23, 0)),
])
def test_bucket_floor(ts, step, expected):
    assert mh.bucket_floor(ts, step) == expected


def test_memory_used_percent():
    assert mh.memory_used_percent(8 * MB, 32 * MB) == 75
    assert mh.memory_used_percent(None, 32 * MB) is None
    assert mh.memory_used_percent(8 * MB, 0) is None


def _prev(uptime, at, source="push", downs=None):
    return mh.PrevReading(uptime_seconds=uptime, wan_link_downs=downs, sampled_at=at, source=source)


def test_no_reboot_when_uptime_keeps_pace():
    prev = _prev(3 * 3600, T0)
    assert mh.detect_reboot(prev, 3 * 3600 + 120, T0 + timedelta(minutes=2)) is None


def test_reboot_when_uptime_goes_backwards():
    now = T0 + timedelta(minutes=10)
    assert mh.detect_reboot(_prev(3 * 3600, T0), 120, now) == now - timedelta(seconds=120)


def test_reboot_during_a_long_outage_is_still_seen():
    # Up 5 minutes, then silent for 3 hours, back with 40 minutes of uptime: the
    # counter did not go backwards, but the boot time moved 2h20m later.
    now = T0 + timedelta(hours=3)
    assert mh.detect_reboot(_prev(300, T0), 2400, now) == now - timedelta(seconds=2400)


def test_boot_time_check_needs_a_push_timestamp():
    # The last writer was SNMP: its sampled_at is not when that uptime was read.
    now = T0 + timedelta(hours=3)
    assert mh.detect_reboot(_prev(300, T0, source="snmp"), 2400, now) is None


def test_first_sample_or_missing_uptime_is_never_a_reboot():
    assert mh.detect_reboot(None, 60, T0) is None
    assert mh.detect_reboot(_prev(None, T0), 60, T0) is None
    assert mh.detect_reboot(_prev(3600, T0), None, T0) is None


@pytest.mark.parametrize("prev,new,rebooted,expected", [
    (4, 7, False, 3),
    (7, 7, False, 0),
    (7, 2, False, 2),       # counter restarted (reboot we could not date)
    (7, 9, True, 9),        # after a reboot the value is the count since boot
    (None, 9, False, 0),    # nothing to compare with
    (0, 10_000, False, 0),  # implausible jump: another interface now
])
def test_link_drop_delta(prev, new, rebooted, expected):
    assert mh.link_drop_delta(prev, new, rebooted) == expected


# --- folding via router_health.record -------------------------------------------------

async def test_samples_fold_into_both_tiers_with_avg_and_peak(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(
        cpu_load=20, memory_free_bytes=16 * MB, memory_total_bytes=32 * MB, uptime_seconds=3600),
        source="push", now=T0)
    await rh.record(router.id, rh.HealthSample(
        cpu_load=90, memory_free_bytes=8 * MB, memory_total_bytes=32 * MB, uptime_seconds=3720),
        source="push", now=T0 + timedelta(minutes=2))
    # SNMP carries CPU only: it counts for CPU, not memory.
    await rh.record(router.id, rh.HealthSample(cpu_load=40), source="snmp",
                    now=T0 + timedelta(minutes=3))

    for step, start in ((300, datetime(2026, 11, 23, 10, 0)), (3600, datetime(2026, 11, 23, 10, 0))):
        [b] = await _buckets(db, router.id, step)
        assert b.bucket_start == start
        assert (b.cpu_samples, b.cpu_sum, b.cpu_max) == (3, 150, 90)
        assert (b.mem_samples, b.mem_sum, b.mem_max) == (2, 50 + 75, 75)
        assert (b.reboots, b.link_drops) == (0, 0)


async def test_reboot_lands_in_the_bucket_it_happened_in(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(cpu_load=10, uptime_seconds=5 * 3600),
                    source="push", now=T0)
    # 10:12:30, uptime 4 min: booted 10:08:30 — the 10:05 bucket.
    await rh.record(router.id, rh.HealthSample(cpu_load=60, uptime_seconds=240),
                    source="push", now=T0 + timedelta(minutes=11))

    fine = {b.bucket_start.strftime("%H:%M"): b for b in await _buckets(db, router.id, 300)}
    assert fine["10:05"].reboots == 1 and fine["10:05"].cpu_samples == 0
    assert fine["10:10"].reboots == 0 and fine["10:10"].cpu_samples == 1
    [hourly] = await _buckets(db, router.id, 3600)
    assert hourly.reboots == 1 and hourly.cpu_samples == 2


async def test_wan_link_drops_are_counted_from_the_counter(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(cpu_load=5, uptime_seconds=3600, wan_link_downs=4),
                    source="push", now=T0)
    await rh.record(router.id, rh.HealthSample(cpu_load=5, uptime_seconds=3720, wan_link_downs=7),
                    source="push", now=T0 + timedelta(minutes=2))
    [b] = await _buckets(db, router.id, 300)
    assert b.link_drops == 3


async def test_history_failure_never_loses_the_latest_reading(db, monkeypatch):
    router = await make_router(db, await make_reseller(db))

    async def broken(*_a, **_k):
        raise RuntimeError("history table missing")

    monkeypatch.setattr(mh, "_bucket", broken)
    await rh.record(router.id, rh.HealthSample(cpu_load=77), source="push", now=T0)
    row = await db.get(RouterHealth, router.id)
    assert row is not None and row.cpu_load == 77
    assert await _buckets(db, router.id, 300) == []


# --- reading ----------------------------------------------------------------------------

async def test_history_is_dense_with_gaps_as_null(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(cpu_load=30, memory_free_bytes=24 * MB,
                                               memory_total_bytes=32 * MB, uptime_seconds=600),
                    source="push", now=T0)
    await rh.record(router.id, rh.HealthSample(cpu_load=50, uptime_seconds=600 + 1200),
                    source="push", now=T0 + timedelta(minutes=20))

    now = T0 + timedelta(minutes=21)
    h = await mh.history(db, router.id, "24h", now=now)
    assert (h["step_seconds"], h["slots"]) == (300, 288)
    assert h["start"] == datetime(2026, 11, 23, 10, 20) - timedelta(minutes=5 * 287)
    assert h["cpu_avg"][-1] == 50.0 and h["cpu_avg"][-5] == 30.0
    assert h["cpu_avg"][-2] is None and h["mem_avg"][-1] is None
    assert h["mem_avg"][-5] == 25.0
    assert h["summary"] == {"cpu_avg": 40.0, "cpu_max": 50, "mem_avg": 25.0, "mem_max": 25,
                            "reboots": 0, "link_drops": 0, "buckets_with_data": 2}

    week = await mh.history(db, router.id, "7d", now=now)
    assert (week["step_seconds"], week["slots"]) == (3600, 168)
    assert week["cpu_avg"][-1] == 40.0 and week["cpu_max"][-1] == 50


async def test_storage_stays_bounded_after_days_of_two_minute_reports(db):
    """Three days of reports every 2 minutes, pruned as the scheduler does:
    never more than one tier-full of rows per router."""
    router = await make_router(db, await make_reseller(db))
    start = T0 - timedelta(days=3)
    # Fold directly (one session) to keep the test fast; record() is covered above.
    t = start
    async with database.async_session() as s:
        while t <= T0:
            await mh.fold(s, router.id, rh.HealthSample(cpu_load=25), None, t)
            t += timedelta(minutes=2)
        await mh.prune(s, T0)
        await s.commit()

    fine = await _buckets(db, router.id, 300)
    hourly = await _buckets(db, router.id, 3600)
    assert len(fine) <= 26 * 12 + 1
    assert len(hourly) == 3 * 24 + 1   # 3 days are inside the 8-day window
    assert fine[0].bucket_start >= T0 - timedelta(hours=26)

    async with database.async_session() as s:
        await mh.prune(s, T0 + timedelta(days=9))
        await s.commit()
    total = (await db.execute(select(func.count()).select_from(RouterMetricBucket))).scalar()
    assert total == 0


# --- endpoint ---------------------------------------------------------------------------

async def test_endpoint_serves_own_router_and_hides_others(db, monkeypatch):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    mine = await make_router(db, owner)
    theirs = await make_router(db, other)
    await rh.record(mine.id, rh.HealthSample(cpu_load=12), source="push")

    async def _current_user(_token, _db):
        return owner

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    out = await usage_routes.get_router_health_history(
        router_id=mine.id, range_key="24h", db=db, token="t")
    assert out["summary"]["cpu_max"] == 12

    with pytest.raises(HTTPException) as exc:
        await usage_routes.get_router_health_history(
            router_id=theirs.id, range_key="24h", db=db, token="t")
    assert exc.value.status_code == 404

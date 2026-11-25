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
from app.services import staff_permissions as perms
from tests.factories import make_admin, make_reseller, make_router

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


def test_reboot_during_a_long_outage_is_seen_on_polled_routers_too():
    # hAP lites have no push agent; the server poll reads their uptime.
    now = T0 + timedelta(hours=3)
    assert mh.detect_reboot(_prev(300, T0, source="poll"), 2400, now) == now - timedelta(seconds=2400)


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
    assert h["summary"] == {
        "cpu_avg": 40.0, "cpu_p95": 50.0, "cpu_p99": 50.0, "cpu_max": 50,
        "mem_avg": 25.0, "mem_p95": 25.0, "mem_p99": 25.0, "mem_max": 25,
        "reboots": 0, "link_drops": 0, "buckets_with_data": 2,
        "last_report_at": T0 + timedelta(minutes=20), "reporting": True,
        "link_drops_reported": False,
    }

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


# --- percentiles, coverage and the fleet ranking ---------------------------------------

def test_percentile_is_nearest_rank_and_never_invents_a_value():
    values = list(range(1, 101))            # 1..100
    assert mh.percentile(values, 95) == 95
    assert mh.percentile(values, 99) == 99
    assert mh.percentile([7], 99) == 7
    assert mh.percentile([], 95) is None
    # Twenty quiet slots and one busy one: p95 stays quiet, p99 finds the busy one.
    assert mh.percentile([10] * 20 + [90], 95) == 10
    assert mh.percentile([10] * 20 + [90], 99) == 90


async def _fill(router_id, cpu_by_minute, start=T0):
    """One push per minute, like the fleet's reporter."""
    async with database.async_session() as s:
        for i, cpu in enumerate(cpu_by_minute):
            await mh.fold(s, router_id, rh.HealthSample(cpu_load=cpu), None, start + timedelta(minutes=i))
        await s.commit()


async def test_p95_and_p99_come_from_five_minute_averages(db):
    router = await make_router(db, await make_reseller(db))
    # 100 five-minute buckets (500 minutes): averages 1..100.
    start = datetime(2026, 11, 23, 0, 0)
    await _fill(router.id, [b + 1 for b in range(100) for _ in range(5)], start=start)
    h = await mh.history(db, router.id, "24h", now=start + timedelta(minutes=500))
    assert h["summary"]["cpu_p95"] == 95.0
    assert h["summary"]["cpu_p99"] == 99.0
    assert h["summary"]["cpu_max"] == 100


async def test_link_drops_say_unknown_until_the_router_reports_the_counter(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(cpu_load=5, uptime_seconds=600), source="push", now=T0)
    h = await mh.history(db, router.id, "24h", now=T0)
    assert h["summary"]["link_drops_reported"] is False
    await rh.record(router.id, rh.HealthSample(cpu_load=5, uptime_seconds=720, wan_link_downs=3),
                    source="push", now=T0 + timedelta(minutes=2))
    h = await mh.history(db, router.id, "24h", now=T0 + timedelta(minutes=2))
    assert h["summary"]["link_drops_reported"] is True


async def test_a_router_that_stopped_reporting_is_flagged(db):
    router = await make_router(db, await make_reseller(db))
    await rh.record(router.id, rh.HealthSample(cpu_load=5), source="push", now=T0)
    h = await mh.history(db, router.id, "24h", now=T0 + timedelta(hours=2))
    assert h["summary"]["reporting"] is False
    assert h["summary"]["last_report_at"] == T0


async def test_ranking_puts_the_busiest_first_and_lists_silent_online_routers(db):
    owner = await make_reseller(db, business_name="Owner Net")
    other = await make_reseller(db)
    calm = await make_router(db, owner, name="calm")
    busy = await make_router(db, owner, name="busy")
    silent = await make_router(db, owner, name="silent", last_status=True)
    theirs = await make_router(db, other, name="theirs")
    await _fill(calm.id, [10] * 30)
    await _fill(busy.id, [20] * 25 + [95] * 5)
    await _fill(theirs.id, [99] * 30)
    now = T0 + timedelta(minutes=30)

    mine = await mh.ranking(db, "24h", owner_id=owner.id, now=now)
    assert [r["name"] for r in mine["routers"]] == ["busy", "calm"]
    top = mine["routers"][0]
    assert (top["cpu_p95"], top["cpu_p99"], top["cpu_max"]) == (95.0, 95.0, 95)
    assert top["owner_name"] == "Owner Net"
    assert [r["name"] for r in mine["not_reporting"]] == ["silent"]

    everyone = await mh.ranking(db, "24h", now=now)
    assert everyone["routers"][0]["name"] == "theirs"
    assert {r["name"] for r in everyone["routers"]} == {"theirs", "busy", "calm"}


async def test_ranking_endpoint_scopes_resellers_and_shows_admins_everything(db, monkeypatch):
    owner = await make_reseller(db)
    other = await make_reseller(db)
    admin = await make_admin(db)
    mine = await make_router(db, owner)
    theirs = await make_router(db, other)
    await rh.record(mine.id, rh.HealthSample(cpu_load=12), source="push")
    await rh.record(theirs.id, rh.HealthSample(cpu_load=34), source="push")

    who = {"user": owner}

    async def _current_user(_token, _db):
        return who["user"]

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    out = await usage_routes.get_router_health_ranking(range_key="24h", db=db, token="t")
    assert [r["router_id"] for r in out["routers"]] == [mine.id]
    who["user"] = admin
    out = await usage_routes.get_router_health_ranking(range_key="24h", db=db, token="t")
    assert {r["router_id"] for r in out["routers"]} == {mine.id, theirs.id}


@pytest.mark.parametrize("path", ["/api/routers/7/health-history", "/api/router-health/ranking"])
def test_staff_who_can_see_routers_or_the_dashboard_can_read_history(path):
    rule, _ = perms.match_rule("GET", path)
    assert rule is not None
    assert rule.allows({"routers.view"}) and rule.allows({"dashboard.view"})
    assert not rule.allows({"customers.view"})


# --- WAN link-down counter from the ports list -------------------------------------------

def _port(name, rx, tx, downs):
    from types import SimpleNamespace
    return SimpleNamespace(name=name, rx_bytes=rx, tx_bytes=tx, link_downs=downs)


GB = 1024 ** 3


def test_wan_counter_is_the_port_whose_bytes_match_the_wan():
    ports = [_port("ether1", 500 * GB, 40 * GB, 7),     # WAN: lots down, little up
             _port("ether2", 38 * GB, 480 * GB, 2),     # LAN: the mirror image
             _port("wlan1", 1 * GB, 9 * GB, 0)]
    # WAN counters read a moment after the ports: a little further on.
    assert rh.wan_link_downs_from_ports(ports, 500 * GB + 30 * MB, 40 * GB + 2 * MB) == 7


def test_wan_on_another_port_is_found_too():
    ports = [_port("ether1", 0, 0, 0), _port("ether2", 80 * GB, 9 * GB, 3)]
    assert rh.wan_link_downs_from_ports(ports, 80 * GB + MB, 9 * GB + MB) == 3


@pytest.mark.parametrize("ports,rx,tx", [
    # WAN is pppoe-out1 on ether1: ether1 carries more than the WAN, so no match.
    ([_port("ether1", 101 * GB, 11 * GB, 4)], 100 * GB, 10 * GB),
    # Fresh router: every counter near zero, so two ports match.
    ([_port("ether1", 0, 0, 0), _port("ether2", 0, 0, 1)], 10 * MB, 10 * MB),
    ([], 5 * GB, 5 * GB),
    ([_port("ether1", 0, 0, 0)], 0, 0),
])
def test_no_counter_unless_exactly_one_port_matches(ports, rx, tx):
    assert rh.wan_link_downs_from_ports(ports, rx, tx) is None

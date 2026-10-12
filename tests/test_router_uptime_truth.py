"""Uptime and outages must match what customers experienced.

2026-10-12, router 564: 91 "offline" samples in 48 h, 82 of them taken while
the router was sending its own usage reports — our RouterOS connection failed,
the router and its customers were fine. Uptime, outage history, the router's
status badge and the "router offline" alerts all counted them.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.api import router_management
from app.db.models import Router
from app.services.router_availability import (
    record_router_availability,
    summarize_router_flaps,
    time_based_uptime,
)
from tests.factories import make_reseller, make_router

T = datetime(2026, 10, 11, 12, 0, 0)


def _c(minutes, up, source):
    return {"checked_at": T + timedelta(minutes=minutes), "is_online": up, "source": source}


def test_failures_between_reports_are_not_outages():
    checks = []
    for m in range(0, 120, 5):
        checks += [_c(m, True, "usage_push"), _c(m + 1.5, False, "reachability_probe"),
                   _c(m + 2, False, "provisioning")]
    s = summarize_router_flaps(checks, now=T + timedelta(minutes=120))
    assert (s["status"], s["outage_count"], s["outages"], s["judged_by"]) == (
        "online", 0, [], "router_reports")


def test_a_real_silence_is_one_outage_dated_by_the_first_failure():
    checks = [_c(m, True, "usage_push") for m in (0, 5, 10)]
    checks += [_c(14, False, "reachability_probe"), _c(19, False, "reachability_probe")]
    checks += [_c(m, True, "usage_push") for m in (32, 37, 42)]
    s = summarize_router_flaps(checks, now=T + timedelta(minutes=45))
    assert s["outage_count"] == 1
    # 14 is within 8 minutes of the 10-minute report, so 19 dates the start.
    assert s["outages"][0]["started_at"] == (T + timedelta(minutes=19)).isoformat()
    assert s["outages"][0]["ended_at"] == (T + timedelta(minutes=32)).isoformat()


def test_a_router_silent_now_is_offline():
    checks = [_c(m, True, "usage_push") for m in (0, 5, 10)]
    s = summarize_router_flaps(checks, now=T + timedelta(minutes=40))
    assert s["status"] == "offline"
    assert s["outages"][-1]["ended_at"] is None


def test_uptime_is_a_share_of_time_not_of_samples():
    outages = [{"started_at": (T + timedelta(hours=1)).isoformat(),
                "ended_at": (T + timedelta(hours=2)).isoformat()}]
    u = time_based_uptime(outages, start=T, end=T + timedelta(hours=10), first_data_at=T)
    assert (u["uptime_percentage"], u["downtime_seconds"], u["outage_count"]) == (90.0, 3600, 1)
    # Only the part of the window with data counts.
    u = time_based_uptime(outages, start=T - timedelta(hours=10), end=T + timedelta(hours=10),
                          first_data_at=T)
    assert u["uptime_percentage"] == 90.0


@pytest.mark.asyncio
async def test_failed_checks_do_not_mark_a_reporting_router_offline(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    await record_router_availability(None, router.id, True, "usage_push",
                                      checked_at=now - timedelta(minutes=3))
    await record_router_availability(None, router.id, False, "reachability_probe",
                                      checked_at=now - timedelta(minutes=1))
    await record_router_availability(None, router.id, False, "provisioning", checked_at=now)
    row = (await db.execute(select(Router).where(Router.id == router.id))).scalar_one()
    await db.refresh(row)
    assert row.last_status is True

    # A router that has not reported for a while is marked offline as before.
    other = await make_router(db, reseller)
    await record_router_availability(None, other.id, True, "usage_push",
                                      checked_at=now - timedelta(minutes=30))
    await record_router_availability(None, other.id, False, "reachability_probe",
                                      checked_at=now - timedelta(minutes=1))
    await record_router_availability(None, other.id, False, "reachability_probe", checked_at=now)
    row = (await db.execute(select(Router).where(Router.id == other.id))).scalar_one()
    await db.refresh(row)
    assert row.last_status is False


@pytest.mark.asyncio
async def test_uptime_endpoint_reports_time_based_uptime(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    start = now - timedelta(hours=2)
    # Reports every 5 min for 2 h with failed probes in between, and one
    # 30-minute silence in which only failures arrive.
    for m in range(0, 120, 5):
        at = start + timedelta(minutes=m)
        if 60 <= m < 90:
            await record_router_availability(None, router.id, False, "reachability_probe", checked_at=at)
            continue
        await record_router_availability(None, router.id, True, "usage_push", checked_at=at)
        await record_router_availability(None, router.id, False, "reachability_probe",
                                          checked_at=at + timedelta(minutes=2))

    out = await router_management.get_router_uptime(
        router.id, hours=24, recent_checks=200, db=db,
        token={"user_id": reseller.id, "role": reseller.role.value})
    assert out["method"] == "time"
    assert out["window"]["outage_count"] == 1
    assert 70 < out["window"]["uptime_percentage"] < 80  # ~28 of ~120 measured minutes down
    failed = [c for c in out["recent_checks"] if not c["is_online"]]
    assert any(c["counted_as_outage"] for c in failed)
    assert any(not c["counted_as_outage"] for c in failed)
    assert {b["status"] for b in out["timeline"]} >= {"up", "no_data"}


@pytest.mark.asyncio
@pytest.mark.parametrize("hours, slices", [(24, 24), (72, 72), (168, 84), (720, 84)])
async def test_each_window_the_panel_offers(db, hours, slices):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    # Reports every 5 min for the last 2 days, with a 1-hour silence 30 h ago:
    # inside the 72 h / 7 d / 30 d windows, outside the 24 h one.
    t = now - timedelta(hours=48)
    while t < now:
        silent = now - timedelta(hours=31) <= t < now - timedelta(hours=30)
        if not silent:
            await record_router_availability(None, router.id, True, "usage_push", checked_at=t)
        t += timedelta(minutes=5)

    out = await router_management.get_router_uptime(
        router.id, hours=hours, recent_checks=50, db=db,
        token={"user_id": reseller.id, "role": reseller.role.value})
    assert out["window"]["hours"] == hours
    assert len(out["timeline"]) == slices
    if hours == 24:
        assert out["window"]["outage_count"] == 0 and out["window"]["uptime_percentage"] == 100.0
    else:
        assert out["window"]["outage_count"] == 1
        assert out["window"]["uptime_percentage"] < 100.0
    # 30-day figure is the same whichever window is picked.
    assert out["overall"]["outage_count"] == 1

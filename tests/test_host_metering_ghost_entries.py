"""Duplicate hotspot host entries must not re-bank a device's whole counter.

Incident 2026-09-29: a phone on mobile data / VPN holds two /ip hotspot host
entries — its real LAN one and a near-empty one for its stray source address.
Keyed by MAC alone, the two counters were diffed against each other on every
push, each drop looked like a reset, and the device's running total was booked
again once a minute (731 GB on a 10 Mbps plan in six hours).
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import ConnectionType, CustomerStatus, CustomerUsagePeriod, UserBandwidthUsage
from app.services import realtime_state, usage_push
from app.services.realtime_state import HostSample
from app.services.usage_counters import (
    line_rate_ceiling_bytes,
    plan_line_rate_bps,
    record_queue_usage_sample,
)
from app.services.usage_push import UsageReport, host_usage_key
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024
MAC = "72:7B:64:EB:A4:72"


async def _setup(db, speed="10M/10M"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT, speed=speed)
    customer = await make_customer(
        db, reseller, plan, router, mac_address=MAC, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return router, plan, customer


def _host(ip, up, down):
    return UsageReport(queue_key=MAC, upload_bytes=up, download_bytes=down, target_ip=ip, source="host")


async def _period_total(session_factory, customer_id):
    async with session_factory() as s:
        period = (await s.execute(
            select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer_id)
        )).scalar_one()
        return period.total_bytes


@pytest.mark.asyncio
async def test_ghost_host_entry_does_not_rebank_the_real_counter(db, session_factory):
    router, _, customer = await _setup(db)
    t0 = datetime.utcnow()
    # Real entry grows 10 MB down per minute; the ghost sits at a few KB.
    for minute in range(6):
        real_dn = (100 + 10 * minute) * MB
        await usage_push.ingest_usage_reports(
            router.id,
            [_host("192.168.88.233", 1 * MB, real_dn), _host("10.47.135.116", 28_000, 0)],
            now=t0 + timedelta(minutes=minute),
            session_factory=session_factory,
            meter_hotspot_by_host=True,
        )

    # Five intervals of real traffic: 50 MB down, nothing else. The old code
    # booked ~100 MB+ per push here (the real entry's whole counter each time).
    assert await _period_total(session_factory, customer.id) == 50 * MB

    async with session_factory() as s:
        keys = sorted(
            (await s.execute(select(UserBandwidthUsage.mac_address)
                             .where(UserBandwidthUsage.customer_id == customer.id))).scalars()
        )
    assert keys == [host_usage_key(MAC, "10.47.135.116"), host_usage_key(MAC, "192.168.88.233")]


@pytest.mark.asyncio
async def test_host_listed_twice_in_one_report_is_counted_once(db, session_factory):
    router, _, customer = await _setup(db)
    t0 = datetime.utcnow()
    for minute, dn in enumerate((10 * MB, 30 * MB)):
        await usage_push.ingest_usage_reports(
            router.id,
            [_host("192.168.88.10", 0, dn), _host("192.168.88.10", 0, dn)],
            now=t0 + timedelta(minutes=minute),
            session_factory=session_factory,
            meter_hotspot_by_host=True,
        )
    assert await _period_total(session_factory, customer.id) == 20 * MB
    async with session_factory() as s:
        rows = (await s.execute(select(UserBandwidthUsage)
                                .where(UserBandwidthUsage.customer_id == customer.id))).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_delta_above_the_plan_line_rate_is_clamped(db, session_factory):
    _, plan, customer = await _setup(db, speed="10M/10M")
    t0 = datetime.utcnow()
    async with session_factory() as s:
        await record_queue_usage_sample(s, customer=customer, plan=plan, queue_key="k",
                                        upload_bytes=0, download_bytes=0, now=t0)
        # 50 GB "in one minute" on a 10 Mbps line is not traffic, it is a bug.
        update = await record_queue_usage_sample(
            s, customer=customer, plan=plan, queue_key="k",
            upload_bytes=0, download_bytes=50_000 * MB, now=t0 + timedelta(minutes=1),
        )
        await s.commit()
    assert update.delta_download_bytes == line_rate_ceiling_bytes(plan, 60)
    assert update.delta_download_bytes < 400 * MB


@pytest.mark.asyncio
async def test_genuine_full_speed_traffic_is_not_clamped(db, session_factory):
    _, plan, customer = await _setup(db, speed="10M/10M")
    t0 = datetime.utcnow()
    full_speed_minute = 10_000_000 // 8 * 60  # exactly line rate for 60 s
    async with session_factory() as s:
        await record_queue_usage_sample(s, customer=customer, plan=plan, queue_key="k",
                                        upload_bytes=0, download_bytes=0, now=t0)
        update = await record_queue_usage_sample(
            s, customer=customer, plan=plan, queue_key="k",
            upload_bytes=0, download_bytes=full_speed_minute, now=t0 + timedelta(minutes=1),
        )
        await s.commit()
    assert update.delta_download_bytes == full_speed_minute


def test_plan_line_rate_parsing():
    class P:
        def __init__(self, speed):
            self.speed = speed

    assert plan_line_rate_bps(P("10M/10M")) == 10_000_000
    assert plan_line_rate_bps(P("5M/20M")) == 20_000_000
    assert plan_line_rate_bps(P("512k/1M 2M/4M")) == 1_000_000
    assert plan_line_rate_bps(P("1G")) == 1_000_000_000
    assert plan_line_rate_bps(P("")) == 0
    assert plan_line_rate_bps(None) == 0
    assert line_rate_ceiling_bytes(P("garbage"), 60) is None


def test_live_view_shows_the_real_entry_not_the_ghost():
    realtime_state.reset_realtime_state()
    now = datetime.utcnow()
    state = realtime_state.record_push(
        5, now=now, interval_seconds=60, queues=[], live_customers={MAC: 1},
        hosts=[HostSample(mac=MAC, ip="192.168.88.233", bytes_in=31 * MB, bytes_out=671 * MB),
               HostSample(mac=MAC, ip="10.47.135.116", bytes_in=28_000, bytes_out=0)],
    )
    assert state.devices[MAC].ip == "192.168.88.233"
    assert state.devices[MAC].bytes_out == 671 * MB
    realtime_state.reset_realtime_state()

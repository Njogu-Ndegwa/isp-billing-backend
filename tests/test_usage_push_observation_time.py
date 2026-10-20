"""Delayed native counters must not look like a fresh counter reset."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db.models import CustomerUsagePeriod, UserBandwidthUsage
from app.services import usage_push
from app.services.usage_push import UsageReport, host_usage_key
from tests.test_usage_push_ingest import _hotspot_setup


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["queue", "host"])
async def test_delayed_observation_cannot_regress_baseline_but_real_reset_works(db, session_factory, source):
    _, router, _, customer = await _hotspot_setup(db)
    key = customer.mac_address
    start = datetime.utcnow() - timedelta(minutes=2)

    async def ingest(up, down, arrived, observed=None):
        return await usage_push.ingest_usage_reports(
            router.id,
            [UsageReport(key, up, down, source=source, target_ip="192.0.2.4", sampled_at=observed)],
            session_factory=session_factory, now=arrived, meter_hotspot_by_host=source == "host",
        )

    await ingest(100, 200, start)
    await ingest(200, 400, start + timedelta(seconds=30))
    await ingest(150, 300, start + timedelta(seconds=40), start + timedelta(seconds=10))
    canonical = host_usage_key(key, "192.0.2.4") if source == "host" else key
    async with session_factory() as session:
        usage = (await session.execute(select(UserBandwidthUsage).where(
            UserBandwidthUsage.customer_id == customer.id,
            UserBandwidthUsage.mac_address == canonical,
        ))).scalar_one()
        period = (await session.execute(select(CustomerUsagePeriod).where(
            CustomerUsagePeriod.customer_id == customer.id,
        ))).scalar_one()
        assert (usage.last_upload_bytes, usage.last_download_bytes) == (200, 400)
        assert period.total_bytes == 300

    # A current, lower counter is a genuine reset and still credits its bytes.
    await ingest(5, 10, start + timedelta(seconds=50), start + timedelta(seconds=49))
    async with session_factory() as session:
        period = (await session.execute(select(CustomerUsagePeriod).where(
            CustomerUsagePeriod.customer_id == customer.id,
        ))).scalar_one()
        assert period.total_bytes == 315


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-361, 1])
async def test_implausible_observation_time_does_not_create_a_baseline(db, session_factory, offset):
    _, router, _, customer = await _hotspot_setup(db)
    now = datetime.utcnow()
    result = await usage_push.ingest_usage_reports(
        router.id, [UsageReport(customer.mac_address, 100, 200, sampled_at=now + timedelta(seconds=offset))],
        session_factory=session_factory, now=now,
    )
    assert result.rejected == 1
    assert result.errors == ["implausible_sample_time"]
    async with session_factory() as session:
        assert (await session.execute(select(UserBandwidthUsage))).scalars().all() == []


@pytest.mark.asyncio
async def test_timezone_observation_normalizes_to_utc(db, session_factory):
    _, router, _, customer = await _hotspot_setup(db)
    now = datetime.utcnow()
    observed = now.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=3)))
    result = await usage_push.ingest_usage_reports(
        router.id, [UsageReport(customer.mac_address, 100, 200, sampled_at=observed)],
        session_factory=session_factory, now=now,
    )
    assert result.accepted == 1
    assert result.rejected == 0

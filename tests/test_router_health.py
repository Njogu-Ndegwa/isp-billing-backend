"""Router health via the push agent (CPU, memory, storage, uptime, version,
board, WAN link drops), stored in router_health and feeding the CPU alerts."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.db.models import ResellerInboxMessage, RouterHealth, UserRole
from app.services import router_health as rh
from app.services import router_overload_alerts as oa
from app.services import usage_push
from app.services.usage_push_auth import derive_router_token
from app.services.usage_push_script import render_usage_push_script
from tests.factories import make_reseller, make_router
from sqlalchemy import select

URL = "https://isp.bitwavetechnologies.net/api/router/usage-push"


# --- parsing and bounds ------------------------------------------------------------

@pytest.mark.parametrize("raw,secs", [
    ("6h43m36s", 6 * 3600 + 43 * 60 + 36),
    ("3w9h40m47s", 3 * 604800 + 9 * 3600 + 40 * 60 + 47),
    ("1d14m56s", 86400 + 14 * 60 + 56),
    ("2d03:04:05", 2 * 86400 + 3 * 3600 + 4 * 60 + 5),
    ("00:00:09", 9),
    (125, 125),
])
def test_parse_uptime_both_routeros_formats(raw, secs):
    assert rh.parse_uptime(raw) == secs


@pytest.mark.parametrize("raw", ["", "abc", "5x", None, -3, "1d; rm"])
def test_parse_uptime_rejects_garbage(raw):
    assert rh.parse_uptime(raw) is None


def test_sanitize_drops_only_the_implausible_fields():
    clean = rh.sanitize(rh.HealthSample(
        cpu_load=140, memory_free_bytes=8_658_944, memory_total_bytes=33_554_432,
        storage_free_bytes=900, storage_total_bytes=100,       # free > total: both dropped
        uptime_seconds="6h43m36s", routeros_version="7.19.6 (stable)\x07",
        board_name="hAP lite", wan_link_downs=-1))
    assert clean.cpu_load is None and clean.wan_link_downs is None
    assert clean.memory_free_bytes == 8_658_944 and clean.memory_total_bytes == 33_554_432
    assert clean.storage_free_bytes is None and clean.storage_total_bytes is None
    assert clean.uptime_seconds == 24216
    assert clean.routeros_version == "7.19.6 (stable)" and clean.board_name == "hAP lite"


# --- storage -----------------------------------------------------------------------------

async def test_record_upserts_and_partial_samples_keep_other_fields(db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    t0 = datetime.utcnow() - timedelta(minutes=4)
    await rh.record(router.id, rh.HealthSample(
        cpu_load=40, memory_free_bytes=10, memory_total_bytes=32, uptime_seconds="1h",
        routeros_version="7.19.6 (stable)", board_name="hAP lite"), source="push", now=t0)
    # An SNMP reading carries CPU only; it must not erase the push's memory figures.
    await rh.record(router.id, rh.HealthSample(cpu_load=66), source="snmp",
                    now=t0 + timedelta(minutes=2))
    row = await db.get(RouterHealth, router.id)
    await db.refresh(row)
    assert (row.cpu_load, row.source) == (66, "snmp")
    assert (row.memory_free_bytes, row.memory_total_bytes, row.uptime_seconds) == (10, 32, 3600)
    assert row.board_name == "hAP lite"
    rows = (await db.execute(select(RouterHealth))).scalars().all()
    assert len(rows) == 1


async def test_empty_or_all_invalid_sample_writes_nothing(db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    await rh.record(router.id, rh.HealthSample(cpu_load=999), source="push")
    assert await db.get(RouterHealth, router.id) is None


# --- alerts from push samples ----------------------------------------------------------------

@pytest.fixture
def spawned(monkeypatch):
    coros = []
    monkeypatch.setattr(rh, "_spawn", lambda coro: coros.append(coro))
    monkeypatch.setattr(settings, "ROUTER_OVERLOAD_ALERTS_ENABLED", True)
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", False)
    oa._cpu_history.clear()
    oa._attempted.clear()
    yield coros
    for c in coros:
        c.close() if hasattr(c, "close") else None
    oa._cpu_history.clear()
    oa._attempted.clear()


async def test_sustained_push_readings_raise_one_warning(db, spawned):
    await make_reseller(db, role=UserRole.ADMIN, email="admin-rh@x.io")
    owner = await make_reseller(db, support_phone="254704009555")
    router = await make_router(db, owner, name="lee net hotspot #1", status_alerts_enabled=True)
    start = datetime.utcnow() - timedelta(minutes=12)
    for i in range(6):                                   # every 2 minutes, 92-96%
        await rh.record_and_evaluate(router.id, rh.HealthSample(cpu_load=92 + i % 5),
                                     source="push", now=start + timedelta(minutes=2 * i))
    assert len(spawned) == 1                             # one alert, not one per push
    await spawned.pop()                                  # deliver it
    inbox = (await db.execute(select(ResellerInboxMessage)
                              .where(ResellerInboxMessage.recipient_user_id == owner.id))).scalars().all()
    assert len(inbox) == 1 and "above 90% CPU" in inbox[0].body


async def test_short_push_spike_does_not_alert(db, spawned):
    owner = await make_reseller(db)
    router = await make_router(db, owner, status_alerts_enabled=True)
    start = datetime.utcnow() - timedelta(minutes=6)
    for i, cpu in enumerate([100, 100, 40]):
        await rh.record_and_evaluate(router.id, rh.HealthSample(cpu_load=cpu),
                                     source="push", now=start + timedelta(minutes=2 * i))
    assert spawned == []


async def test_push_readings_never_alert_when_feature_is_off(db, spawned, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_OVERLOAD_ALERTS_ENABLED", False)
    owner = await make_reseller(db)
    router = await make_router(db, owner, status_alerts_enabled=True)
    start = datetime.utcnow() - timedelta(minutes=12)
    for i in range(6):
        await rh.record_and_evaluate(router.id, rh.HealthSample(cpu_load=100),
                                     source="push", now=start + timedelta(minutes=2 * i))
    assert spawned == []
    assert (await db.get(RouterHealth, router.id)).cpu_load == 100   # still stored


# --- end to end through the push endpoint ------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    monkeypatch.setattr(usage_push, "async_session", session_factory, raising=False)
    import app.api.usage_push_routes as routes
    monkeypatch.setattr(routes, "async_session", session_factory, raising=False)
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    routes.reset_rate_limiter()
    application = FastAPI()
    application.include_router(routes.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _router_block(**extra):
    block = {"iface_rx_bytes": 1000, "iface_tx_bytes": 2000, "hotspot_active": 3,
             "pppoe_active": 0, "queue_count": 5}
    block.update(extra)
    return block


async def test_push_with_health_fields_is_stored(db, client, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_OVERLOAD_ALERTS_ENABLED", False)
    owner = await make_reseller(db)
    router = await make_router(db, owner, identity="Router-0960")
    r = await client.post(
        "/api/router/usage-push",
        json={"identity": "Router-0960", "reports": [], "router": _router_block(
            cpu_load=71, free_memory=8_658_944, total_memory=33_554_432,
            free_hdd=4_000_000, total_hdd=16_777_216, uptime="6h43m36s",
            version="7.19.6 (stable)", board="hAP lite", wan_link_downs=12)},
        headers={"Authorization": f"Bearer {derive_router_token('Router-0960')}"},
    )
    assert r.status_code == 200
    row = await db.get(RouterHealth, router.id)
    assert row is not None
    await db.refresh(row)
    assert (row.source, row.cpu_load, row.board_name, row.wan_link_downs) == ("push", 71, "hAP lite", 12)
    assert row.uptime_seconds == 24216 and row.memory_total_bytes == 33_554_432


async def test_old_script_without_health_fields_still_works(db, client):
    owner = await make_reseller(db)
    router = await make_router(db, owner, identity="Router-0961")
    r = await client.post(
        "/api/router/usage-push",
        json={"identity": "Router-0961", "reports": [], "router": _router_block()},
        headers={"Authorization": f"Bearer {derive_router_token('Router-0961')}"},
    )
    assert r.status_code == 200
    assert await db.get(RouterHealth, router.id) is None


async def test_garbage_health_values_do_not_fail_the_push(db, client):
    owner = await make_reseller(db)
    await make_router(db, owner, identity="Router-0962")
    r = await client.post(
        "/api/router/usage-push",
        json={"identity": "Router-0962", "reports": [], "router": _router_block(
            cpu_load=-5, uptime="nonsense", total_memory=0)},
        headers={"Authorization": f"Bearer {derive_router_token('Router-0962')}"},
    )
    assert r.status_code == 200


# --- the router script itself -------------------------------------------------------------------

def test_script_reads_health_before_walking_queues():
    s = render_usage_push_script(identity="Router-0721", endpoint_url=URL, include_router_metrics=True)
    assert s.index("/system resource get cpu-load") < s.index("/queue simple find")
    for field in ("cpu_load", "free_memory", "total_memory", "free_hdd", "total_hdd",
                  "uptime", "version", "board", "wan_link_downs"):
        assert f'\\"{field}\\"' in s
    assert "link-downs" in s


def test_script_without_metrics_flag_is_unchanged():
    s = render_usage_push_script(identity="Router-0721", endpoint_url=URL)
    assert "/system resource get" not in s


def test_script_has_no_bare_return():
    """RouterOS 7.19+ validates the whole script; a bare :return kills it on every
    run (the 2026-09-23 command-agent failure). Never ship one."""
    import re
    s = render_usage_push_script(identity="Router-0721", endpoint_url=URL, include_router_metrics=True)
    assert not re.search(r"^\s*:return\s*$", s, re.M)

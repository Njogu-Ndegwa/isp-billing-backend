"""Real-time push pilot: per-device metering, live state, self-tuning cadence.

Pilot routers (settings.REALTIME_PILOT_ROUTER_IDS) report every few seconds
with hosts, queue targets and router health. Their hotspot usage is metered
from each device's /ip hotspot host counters, so a stale queue on a reused IP
can no longer turn a paying customer's usage into 0 MB.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.usage_push_routes as routes
from app.api.usage_routes import _live_for
from app.config import settings
from app.db.models import ConnectionType, CustomerStatus, CustomerUsagePeriod
from app.services import realtime_state, usage_push
from app.services.realtime_state import HostSample, QueueSample
from app.services.usage_push_auth import derive_router_token
from app.services.usage_push_script import render_realtime_push_script
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024
MAC = "AA:BB:CC:11:22:33"
OLD_MAC = "AA:BB:CC:99:99:99"
IDENT = "Router-0721"


@pytest.fixture(autouse=True)
def _clean_state():
    realtime_state.reset_realtime_state()
    yield
    realtime_state.reset_realtime_state()


@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    monkeypatch.setattr(usage_push, "async_session", session_factory, raising=False)
    monkeypatch.setattr(routes, "async_session", session_factory, raising=False)
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    monkeypatch.setattr(routes, "PILOT_MIN_SECONDS_BETWEEN_PUSHES", 0)
    routes.reset_rate_limiter()
    application = FastAPI()
    application.include_router(routes.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _setup(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=IDENT)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db, reseller, plan, router, mac_address=MAC, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return router, customer


def _push(host_in, host_out, queue_up, queue_dn, *, shadow=False):
    reports = []
    if shadow:
        # An expired customer's queue left on this device's IP, above its own.
        reports.append({"queue_key": OLD_MAC.replace(":", ""), "upload_bytes": queue_up,
                        "download_bytes": queue_dn, "target_ip": "192.168.88.50/32",
                        "max_limit": "2000000/2000000"})
    reports.append({"queue_key": MAC.replace(":", ""),
                    "upload_bytes": 0 if shadow else queue_up,
                    "download_bytes": 0 if shadow else queue_dn,
                    "target_ip": "192.168.88.50/32", "max_limit": "5000000/5000000"})
    return {
        "identity": IDENT,
        "v": 2,
        "reports": reports,
        "hosts": [{"mac": MAC, "ip": "192.168.88.50", "bytes_in": host_in, "bytes_out": host_out,
                   "bypassed": True, "idle_time": "1s", "uptime": "1h"}],
        "router": {"iface_rx_bytes": 1000, "iface_tx_bytes": 500, "cpu_load": 7,
                   "free_memory": 900, "total_memory": 1024, "uptime": "3w", "version": "7.14",
                   "board": "RB4011iGS+"},
    }


def _auth():
    return {"Authorization": f"Bearer {derive_router_token(IDENT)}"}


async def _period(session_factory, customer_id):
    async with session_factory() as s:
        return (await s.execute(
            select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer_id)
        )).scalar_one_or_none()


@pytest.mark.asyncio
async def test_pilot_meters_hotspot_from_host_counters_not_the_shadowed_queue(
    db, client, session_factory, monkeypatch,
):
    router, customer = await _setup(db)
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", str(router.id))
    repairs = []

    async def fake_repair(router_id):
        repairs.append(router_id)

    monkeypatch.setattr(routes, "_repair", fake_repair)

    r1 = await client.post("/api/router/usage-push", json=_push(1 * MB, 4 * MB, 0, 0, shadow=True),
                           headers=_auth())
    assert r1.status_code == 200
    assert r1.json()["next_push_seconds"] == settings.REALTIME_PUSH_INTERVAL_SECONDS

    # 10 s later the device moved 1 MB up / 16 MB down. Its own queue still
    # reads 0 (shadowed); the stale queue above it caught the traffic.
    r2 = await client.post("/api/router/usage-push",
                           json=_push(2 * MB, 20 * MB, 50 * MB, 900 * MB, shadow=True),
                           headers=_auth())
    assert r2.status_code == 200

    period = await _period(session_factory, customer.id)
    assert period.total_bytes == 17 * MB  # host delta, nothing from either queue

    state = realtime_state.get_router_live(router.id)
    device = state.devices[MAC]
    assert device.online and device.queue_status == realtime_state.QUEUE_SHADOWED
    assert device.limited_by == OLD_MAC and device.max_limit == "2000000/2000000"
    assert device.rate_down_bps and device.rate_down_bps > 0
    assert state.cpu_load == 7 and state.board == "RB4011iGS+"
    assert state.orphan_queues == 1
    assert repairs == [router.id]  # repair kicked off by the report itself


@pytest.mark.asyncio
async def test_non_pilot_router_ignores_hosts_and_keeps_two_minute_cadence(
    db, client, session_factory, monkeypatch,
):
    router, customer = await _setup(db)
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", "")

    r1 = await client.post("/api/router/usage-push", json=_push(0, 0, 0, 0), headers=_auth())
    assert r1.json()["next_push_seconds"] == routes.DEFAULT_PUSH_INTERVAL_SECONDS
    routes.reset_rate_limiter()
    await client.post("/api/router/usage-push", json=_push(5 * MB, 5 * MB, 1 * MB, 2 * MB),
                      headers=_auth())

    period = await _period(session_factory, customer.id)
    assert period.total_bytes == 3 * MB  # queue delta, as before the pilot
    assert realtime_state.get_router_live(router.id) is None


@pytest.mark.asyncio
async def test_customer_usage_carries_live_block_for_pilot_devices(db, client, monkeypatch):
    router, customer = await _setup(db)
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", str(router.id))
    monkeypatch.setattr(routes, "_repair", lambda router_id: _noop())

    await client.post("/api/router/usage-push", json=_push(1 * MB, 1 * MB, 1 * MB, 1 * MB), headers=_auth())

    live = _live_for(customer)
    assert live is not None
    assert live.online and live.ip == "192.168.88.50"
    assert live.queue_status == realtime_state.QUEUE_OK
    assert live.interval_seconds == settings.REALTIME_PUSH_INTERVAL_SECONDS


async def _noop():
    return None


def test_live_state_rates_statuses_and_repair_throttle():
    now = datetime(2026, 9, 25, 10, 0, 0)
    queues = [
        QueueSample(key=OLD_MAC, target_ip="10.0.0.50", max_limit="1M/1M", disabled=False,
                    upload_bytes=0, download_bytes=0),
        QueueSample(key=MAC, target_ip="10.0.0.50", max_limit="5M/5M", disabled=False,
                    upload_bytes=0, download_bytes=0),
    ]
    live = {MAC: 1, "AA:BB:CC:00:00:02": 2}
    host = lambda b_in, b_out: [HostSample(mac=MAC, ip="10.0.0.50", bytes_in=b_in, bytes_out=b_out)]

    s1 = realtime_state.record_push(9, now=now, interval_seconds=10, hosts=host(0, 0),
                                    queues=queues, live_customers=live)
    assert s1.devices[MAC].rate_down_bps is None  # first sighting: no honest rate
    assert s1.devices["AA:BB:CC:00:00:02"].queue_status == realtime_state.QUEUE_OFFLINE
    assert realtime_state.repair_due(s1, now)
    realtime_state.note_repair(9, now, {"status": "running"})

    s2 = realtime_state.record_push(9, now=now + timedelta(seconds=10), interval_seconds=10,
                                    hosts=host(1_000_000, 10_000_000), queues=queues, live_customers=live)
    assert s2.devices[MAC].rate_down_bps == pytest.approx(8_000_000)
    assert s2.devices[MAC].queue_status == realtime_state.QUEUE_SHADOWED
    # Same problem, 10 s after a repair started: not again yet.
    assert not realtime_state.repair_due(s2, now + timedelta(seconds=10))

    fixed = [q for q in queues if q.key == MAC]
    s3 = realtime_state.record_push(9, now=now + timedelta(seconds=20), interval_seconds=10,
                                    hosts=host(500, 500), queues=fixed, live_customers=live)
    assert s3.devices[MAC].queue_status == realtime_state.QUEUE_OK
    assert s3.devices[MAC].rate_down_bps is None  # host counter reset: no rate this window
    assert not realtime_state.repair_due(s3, now + timedelta(seconds=20))


def test_realtime_script_reads_server_cadence_and_reports_hosts():
    script = render_realtime_push_script(
        identity="Router-0721", endpoint_url="https://isp.example.com/api/router/usage-push",
        interval_seconds=10,
    )
    assert "output=user as-value" in script          # v1 used output=none and never retuned
    assert '"\\"next_push_seconds\\":"' in script
    assert "/system scheduler set" in script
    assert "/ip hotspot host find where bypassed" in script
    assert "cpu-load" in script and "interval=10s" in script
    assert all(ord(c) < 128 for c in script)
    with pytest.raises(ValueError):
        render_realtime_push_script(identity="Router-0721", endpoint_url="https://x.y/z", interval_seconds=2)
    with pytest.raises(ValueError):
        render_realtime_push_script(identity='bad"id', endpoint_url="https://x.y/z")


def test_index_prefers_the_live_row_when_a_device_has_several():
    from app.services.usage_push import _index_customers

    class C:
        def __init__(self, cid, status, days):
            self.id, self.status, self.mac_address, self.pppoe_username = cid, status, MAC, None
            self.expiry = datetime.utcnow() + timedelta(days=days)

    live = C(2, CustomerStatus.ACTIVE, 3)
    expired = C(1, CustomerStatus.INACTIVE, -90)
    assert _index_customers([live, expired])[MAC].id == 2
    assert _index_customers([expired, live])[MAC].id == 2


@pytest.mark.asyncio
async def test_router_only_lock_does_not_wait_for_fleet_slots():
    import asyncio

    from app.services.mikrotik_background import RouterLockManager

    locks = RouterLockManager(max_concurrent=1)
    async with locks.acquire("10.0.0.99:8728"):          # the only fleet slot is taken
        async with locks.acquire_router_only("10.0.0.5:8728"):
            pass                                          # ...and this still gets in
        with pytest.raises(asyncio.TimeoutError):
            async def same_router():
                async with locks.acquire_router_only("10.0.0.99:8728"):
                    pass
            await asyncio.wait_for(same_router(), 0.05)   # same router still serializes


@pytest.mark.asyncio
async def test_no_second_repair_while_one_is_running(db, client, monkeypatch):
    router, _ = await _setup(db)
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", str(router.id))
    started = []

    async def slow_repair(router_id):
        started.append(router_id)  # never calls note_repair: stays "running"

    monkeypatch.setattr(routes, "_repair", slow_repair)
    monkeypatch.setattr(realtime_state, "REPAIR_PERSISTENT_PROBLEM_SECONDS", 0)
    monkeypatch.setattr(realtime_state, "REPAIR_COOLDOWN_SECONDS", 0)

    for _ in range(3):
        await client.post("/api/router/usage-push", json=_push(1, 1, 0, 0, shadow=True), headers=_auth())

    assert started == [router.id]


def test_pppoe_sessions_show_live_with_speed_from_their_session_queue():
    now = datetime(2026, 9, 25, 11, 0, 0)
    key = "pppoe:Jeff01"
    q = lambda up, dn: [QueueSample(key=key, target_ip="", max_limit="5400000/5400000",
                                     disabled=False, upload_bytes=up, download_bytes=dn)]
    session = [realtime_state.PppSample(name="Jeff01", address="192.168.89.253", uptime="57m")]

    realtime_state.record_push(9, now=now, interval_seconds=10, hosts=[], queues=q(0, 0),
                               live_customers={}, ppp_sessions=session,
                               live_pppoe_customers={key: 33284, "pppoe:TEST": 13653})
    s2 = realtime_state.record_push(9, now=now + timedelta(seconds=10), interval_seconds=10, hosts=[],
                                    queues=q(125_000, 1_250_000), live_customers={}, ppp_sessions=session,
                                    live_pppoe_customers={key: 33284, "pppoe:TEST": 13653})
    jeff = realtime_state.get_pppoe_live(9, "Jeff01")
    assert jeff.online and jeff.kind == "pppoe" and jeff.ip == "192.168.89.253"
    assert jeff.rate_down_bps == pytest.approx(1_000_000)
    assert jeff.queue_status == realtime_state.QUEUE_OK and jeff.max_limit == "5400000/5400000"
    assert realtime_state.get_pppoe_live(9, "TEST").queue_status == realtime_state.QUEUE_OFFLINE
    assert s2.orphan_queues == 0  # PPPoE queues are never orphans


def test_realtime_script_reports_ppp_sessions():
    script = render_realtime_push_script(identity="Router-1178", endpoint_url="https://isp.example.com/api/router/usage-push")
    assert "/ppp active find" in script and '\\"ppp\\":[' in script


def test_small_routers_start_slower_and_back_off_on_their_own_cpu(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", "10,390")
    monkeypatch.setattr(settings, "REALTIME_PUSH_INTERVAL_SECONDS", 10)
    monkeypatch.setattr(settings, "REALTIME_PUSH_INTERVAL_OVERRIDES", "390:120")
    now = datetime(2026, 9, 25, 12, 0, 0)
    assert realtime_state.pilot_push_interval_seconds(10) == 10
    assert realtime_state.pilot_push_interval_seconds(390) == 120

    for cpu, expected in ((20, 10), (65, 30), (92, 60)):
        realtime_state.record_push(10, now=now, interval_seconds=10, hosts=[], queues=[],
                                   live_customers={}, metrics={"cpu_load": cpu}, has_hosts=True)
        assert realtime_state.pilot_push_interval_seconds(10) == expected


def test_poller_takes_a_pilot_router_back_when_its_push_stops(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", "426")
    now = datetime(2026, 9, 25, 12, 0, 0)
    # Pilot, but never pushed (router unreachable): the poller must keep collecting.
    assert not realtime_state.host_metering_active(426, now)
    realtime_state.record_push(426, now=now, interval_seconds=30, hosts=[], queues=[],
                               live_customers={}, has_hosts=True)
    assert realtime_state.host_metering_active(426, now + timedelta(seconds=60))
    assert realtime_state.host_metered_router_ids(now + timedelta(seconds=60)) == [426]
    # Push stopped: after the freshness window the poller takes it back.
    assert not realtime_state.host_metering_active(426, now + timedelta(minutes=10))


def test_cpu_back_off_is_sticky_so_the_cadence_does_not_flip_flop(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PILOT_ROUTER_IDS", "10")
    monkeypatch.setattr(settings, "REALTIME_PUSH_INTERVAL_SECONDS", 10)
    monkeypatch.setattr(settings, "REALTIME_PUSH_INTERVAL_OVERRIDES", "")
    now = datetime(2026, 9, 25, 12, 0, 0)
    push = lambda t, cpu: realtime_state.record_push(10, now=t, interval_seconds=10, hosts=[], queues=[],
                                                     live_customers={}, metrics={"cpu_load": cpu}, has_hosts=True)
    push(now, 95)
    assert realtime_state.pilot_push_interval_seconds(10) == 60
    push(now + timedelta(seconds=60), 5)       # quiet sample right after: still backed off
    assert realtime_state.pilot_push_interval_seconds(10) == 60
    push(now + timedelta(minutes=11), 5)       # hold expired and CPU is fine
    assert realtime_state.pilot_push_interval_seconds(10) == 10

"""Server-side health poll for routers that send no health readings."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import RouterHealth, RouterMetricBucket, SubscriptionStatus
from app.services import router_health as rh
from app.services import router_health_poll as poll
from app.services.app_settings import set_setting
from tests.factories import make_reseller, make_router

HAP_LITE = {
    "cpu-load": "7", "free-memory": "5705728", "total-memory": "33554432",
    "free-hdd-space": "1200128", "total-hdd-space": "16777216",
    "uptime": "7h54m56s", "version": "6.48.6 (long-term)", "board-name": "hAP lite",
}
ROS6_ROUTES = [{"gateway": "192.168.100.1",
                "gateway-status": "192.168.100.1 reachable via  ether1"}]


def _health(source, minutes_ago, cpu=10, now=None):
    now = now or datetime(2026, 11, 24, 12, 0)
    return RouterHealth(router_id=1, source=source, cpu_load=cpu,
                        sampled_at=now - timedelta(minutes=minutes_ago))


# --- pure rules -------------------------------------------------------------------------

NOW = datetime(2026, 11, 24, 12, 0)


@pytest.mark.parametrize("health,expected", [
    (None, True),                                  # never reported
    (_health("push", 3), False),                   # the router pushes: leave it alone
    (_health("snmp", 9), False),
    (_health("push", 11), True),                   # push stopped: poll takes over
    (_health("poll", 3), False),                   # polled this cadence already
    (_health("poll", 5), True),
    (_health("poll", 5, cpu=90), False),           # busy: back off to ~15 min
    (_health("poll", 15, cpu=90), True),
])
def test_due(health, expected):
    assert poll.due(health, NOW) is expected


@pytest.mark.parametrize("rows,wan", [
    (ROS6_ROUTES, "ether1"),
    ([{"gateway": "192.168.1.1", "immediate-gw": "192.168.1.1%ether2", "active": "true"}], "ether2"),
    ([{"gateway": "pppoe-out1", "gateway-status": "pppoe-out1 reachable"}], "pppoe-out1"),
    ([{"gateway": "pppoe-out1"}], "pppoe-out1"),
    # dual WAN: the inactive route and the higher distance lose
    ([{"gateway-status": "10.0.0.1 reachable via  ether1", "active": "false"},
      {"gateway-status": "10.1.0.1 reachable via  ether3", "distance": "2"},
      {"gateway-status": "10.2.0.1 reachable via  ether2", "distance": "1"}], "ether2"),
    ([{"gateway": "192.168.1.1", "gateway-status": "192.168.1.1 unreachable"}], None),
    ([], None),
])
def test_wan_from_routes(rows, wan):
    assert poll.wan_from_routes(rows) == wan


def test_rollout_allowlist_and_switches():
    nobody = poll.parse_rollout("", None, None)
    assert not nobody.allows(330, "hAP lite")
    canary = poll.parse_rollout("330, 478", "", "")
    assert canary.allows(330, None) and canary.allows(478, "hAP lite")
    assert not canary.allows(439, "hAP lite")
    everyone = poll.parse_rollout("ALL", "174,184", "hap lite, hap mini")
    assert everyone.allows(439, "RB951G-2HnD") and everyone.allows(255, None)
    assert not everyone.allows(174, None)                 # per-router off switch
    assert not everyone.allows(330, "hAP lite")           # per-board off switch
    assert not poll.parse_rollout("yes please", None, None).allows(1, None)


def test_slots_spread_the_fleet_over_five_minutes():
    t = datetime(2026, 11, 24, 12, 0)
    minutes = [t + timedelta(minutes=m) for m in range(10)]
    for rid in (330, 331, 332, 478, 1000):
        hits = [m for m in minutes if poll.in_slot(rid, m)]
        assert len(hits) == 2 and hits[1] - hits[0] == timedelta(minutes=5)
    assert sum(poll.in_slot(rid, t) for rid in range(100)) == 20


def test_timeout_backs_off_at_once():
    poll._failures.clear()
    poll.note_failure(9, NOW, slow=True)
    assert poll.backing_off(9, NOW + timedelta(minutes=1))
    poll._failures.clear()


def test_failure_backoff():
    poll._failures.clear()
    for _ in range(poll.FAILURES_BEFORE_BACKOFF):
        assert not poll.backing_off(5, NOW)
        poll.note_failure(5, NOW)
    assert poll.backing_off(5, NOW + timedelta(minutes=10))
    assert not poll.backing_off(5, NOW + poll.FAILURE_BACKOFF + timedelta(seconds=1))
    poll.note_success(5)
    assert not poll.backing_off(5, NOW)


# --- end to end against the DB, with a fake RouterOS --------------------------------------

class FakeRouterOS:
    """Stands in for AsyncNativeAPI; records calls and checks no DB session is open."""

    calls: list = []
    open_sessions = None
    fail_hosts: set = set()
    routes = ROS6_ROUTES
    link_downs = "4"
    cpu = "7"

    def __init__(self, host, user, password, port=8728):
        self.host = host

    async def connect(self):
        assert FakeRouterOS.open_sessions() == 0, "DB session held across RouterOS I/O"
        if self.host in FakeRouterOS.fail_hosts:
            raise ConnectionResetError()
        FakeRouterOS.calls.append((self.host, "login"))

    async def rpc(self, path, args=None, query=(), timeout=25):
        assert FakeRouterOS.open_sessions() == 0, "DB session held across RouterOS I/O"
        FakeRouterOS.calls.append((self.host, path))
        if path == "/system/resource/print":
            return {"rows": [dict(HAP_LITE, **{"cpu-load": FakeRouterOS.cpu})], "done": {}}
        if path == "/ip/route/print":
            return {"rows": FakeRouterOS.routes, "done": {}}
        if path == "/interface/print":
            assert query == ("?name=ether1",)
            return {"rows": [{"name": "ether1", "link-downs": FakeRouterOS.link_downs}], "done": {}}
        raise AssertionError(path)

    async def close(self):
        pass


@pytest.fixture
def fake_ros(monkeypatch):
    active = {"n": 0}
    real = database.async_session

    @asynccontextmanager
    async def counted():
        active["n"] += 1
        try:
            async with real() as s:
                yield s
        finally:
            active["n"] -= 1

    monkeypatch.setattr(database, "async_session", counted)
    monkeypatch.setattr(poll, "AsyncNativeAPI", FakeRouterOS)
    monkeypatch.setattr(poll, "_router_busy", lambda target: False)
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ENABLED", True)
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ROUTER_IDS", "all")
    monkeypatch.setattr(poll, "SLOTS", 1)          # every minute is every router's slot
    FakeRouterOS.calls = []
    FakeRouterOS.fail_hosts = set()
    FakeRouterOS.link_downs = "4"
    FakeRouterOS.cpu = "7"
    FakeRouterOS.open_sessions = lambda: active["n"]
    poll._wan_cache.clear()
    poll._failures.clear()
    yield FakeRouterOS
    poll._wan_cache.clear()
    poll._failures.clear()


async def test_poll_stores_reading_and_graph_buckets_for_silent_routers_only(db, fake_ros):
    owner = await make_reseller(db)
    cut_off = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    silent = await make_router(db, owner, ip_address="10.0.100.9", last_status=True)
    pushing = await make_router(db, owner, ip_address="10.0.0.20", last_status=True)
    offline = await make_router(db, owner, ip_address="10.0.0.21", last_status=False)
    dead_owner = await make_router(db, cut_off, ip_address="10.0.0.22", last_status=True)
    await rh.record(pushing.id, rh.HealthSample(cpu_load=30), source="push",
                    now=datetime.utcnow() - timedelta(minutes=2))

    assert await poll.poll_router_health() == 1

    hosts = {h for h, _ in fake_ros.calls}
    assert hosts == {"10.0.100.9"}
    row = await db.get(RouterHealth, silent.id)
    await db.refresh(row)
    assert row.source == "poll"
    assert (row.cpu_load, row.memory_free_bytes, row.memory_total_bytes) == (7, 5705728, 33554432)
    assert (row.storage_free_bytes, row.uptime_seconds) == (1200128, 7 * 3600 + 54 * 60 + 56)
    assert (row.board_name, row.wan_link_downs) == ("hAP lite", 4)
    buckets = (await db.execute(select(RouterMetricBucket)
                                .where(RouterMetricBucket.router_id == silent.id))).scalars().all()
    assert buckets and all(b.cpu_samples == 1 for b in buckets)
    assert await db.get(RouterHealth, offline.id) is None
    assert await db.get(RouterHealth, dead_owner.id) is None
    pushed = await db.get(RouterHealth, pushing.id)
    await db.refresh(pushed)
    assert pushed.source == "push"


async def test_next_cadence_reuses_cached_wan_and_counts_link_drops(db, fake_ros):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address="10.0.100.9", last_status=True)
    t0 = datetime.utcnow() - timedelta(minutes=6)
    assert await poll.poll_router_health(now=t0) == 1
    # Same cadence: not due again.
    assert await poll.poll_router_health(now=t0 + timedelta(minutes=1)) == 0

    fake_ros.calls.clear()
    fake_ros.link_downs = "6"                       # the WAN dropped twice
    assert await poll.poll_router_health(now=datetime.utcnow()) == 1
    paths = [p for _, p in fake_ros.calls]
    assert "/ip/route/print" not in paths          # the expensive read happens once a day
    assert paths == ["login", "/system/resource/print", "/interface/print"]
    drops = (await db.execute(select(RouterMetricBucket.link_drops)
                              .where(RouterMetricBucket.router_id == router.id))).scalars().all()
    assert sum(d or 0 for d in drops) >= 2


async def test_unreachable_router_backs_off_and_never_raises(db, fake_ros):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address="10.0.0.65", last_status=True)
    fake_ros.fail_hosts = {"10.0.0.65"}
    for _ in range(poll.FAILURES_BEFORE_BACKOFF):
        assert await poll.poll_router_health() == 0
    assert poll.backing_off(router.id, datetime.utcnow())
    assert await poll.load_targets(datetime.utcnow()) == []


async def test_disabled_does_nothing(db, fake_ros, monkeypatch):
    owner = await make_reseller(db)
    await make_router(db, owner, last_status=True)
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ENABLED", False)
    assert await poll.poll_router_health() == 0
    assert fake_ros.calls == []


async def test_nothing_is_polled_until_allowlisted(db, fake_ros, monkeypatch):
    owner = await make_reseller(db)
    await make_router(db, owner, ip_address="10.0.100.9", last_status=True)
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ROUTER_IDS", "")
    assert await poll.poll_router_health() == 0
    assert fake_ros.calls == []


async def test_canary_allowlist_and_board_switch_from_app_settings(db, fake_ros, monkeypatch):
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ROUTER_IDS", "")
    owner = await make_reseller(db)
    canary = await make_router(db, owner, ip_address="10.0.100.9", last_status=True)
    await make_router(db, owner, ip_address="10.0.100.10", last_status=True)
    await set_setting(db, poll.KEY_ROUTER_IDS, str(canary.id))
    t0 = datetime.utcnow() - timedelta(minutes=10)
    assert await poll.poll_router_health(now=t0) == 1
    assert {h for h, _ in fake_ros.calls} == {"10.0.100.9"}

    # Back out every hAP lite at once: the canary last reported "hAP lite".
    await set_setting(db, poll.KEY_ROUTER_IDS, "all")
    await set_setting(db, poll.KEY_EXCLUDE_BOARDS, "hap lite")
    fake_ros.calls.clear()
    assert await poll.poll_router_health(now=datetime.utcnow()) == 1
    assert {h for h, _ in fake_ros.calls} == {"10.0.100.10"}


async def test_busy_router_is_asked_nothing_more_and_waits_15_minutes(db, fake_ros):
    owner = await make_reseller(db)
    router = await make_router(db, owner, ip_address="10.0.100.9", last_status=True)
    fake_ros.cpu = "92"
    t0 = datetime.utcnow() - timedelta(minutes=16)
    assert await poll.poll_router_health(now=t0) == 1
    assert [p for _, p in fake_ros.calls] == ["login", "/system/resource/print"]
    row = await db.get(RouterHealth, router.id)
    await db.refresh(row)
    assert row.cpu_load == 92 and row.wan_link_downs is None
    fake_ros.calls.clear()
    assert await poll.poll_router_health(now=t0 + timedelta(minutes=5)) == 0
    assert await poll.poll_router_health(now=t0 + timedelta(minutes=10)) == 0
    assert await poll.poll_router_health(now=t0 + timedelta(minutes=15)) == 1

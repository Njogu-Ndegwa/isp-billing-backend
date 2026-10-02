"""Poll-only MAC-login routers must meter usage from <hotspot-MAC> queues.

On MAC-login routers the customer's rate limit lives in a router-managed
dynamic queue named after the hotspot user (the MAC), with no comment. The
bandwidth poller only understood app-made plan_ queues tagged ``MAC:``, so every
poll-only MAC-login router booked 0 MB (router 131, Major1 Net, from
2026-09-29 while its WAN moved 34-98 GB/day).
"""

from collections import deque
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import ConnectionType, CustomerUsagePeriod, UserBandwidthUsage
from app.services import mikrotik_background
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024
MAC = "AA:BB:CC:DD:EE:01"


def _snapshot(router_id, queues):
    return {
        "router_id": router_id,
        "active_sessions": {"success": True, "data": []},
        "traffic": {"success": True, "data": [{"name": "ether1", "running": True, "rx_byte": 1, "tx_byte": 1}]},
        "speed_stats": {"success": True, "data": {"total_upload_bps": 0, "total_download_bps": 0,
                                                   "active_queues": 0, "total_queues": len(queues)}},
        "queues": {"success": True, "data": queues},
        "hotspot_hosts": {"success": True, "authorized": 1, "bypassed": 0, "total": 1},
        "arp_entries": {"success": True, "count": 0, "data": []},
        "pppoe_sessions": {"success": True, "data": []},
    }


def _dyn(name, up, down):
    return {"name": name, "comment": "", "bytes": f"{up}/{down}", "max-limit": "5M/5M",
            "target": "192.168.88.20/32", "dynamic": "true"}


async def _run(db, session_factory, monkeypatch, polls, *, mac_login=True):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT, speed="5M/5M")
    customer = await make_customer(db, reseller, plan, router, mac_address=MAC,
                                   expiry=datetime.utcnow() + timedelta(days=1))
    payloads = deque(_snapshot(router.id, q) for q in polls)

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_a, **_k: False)
    monkeypatch.setattr(mikrotik_background, "_fetch_bandwidth_data_sync_for_router", lambda _i: payloads.popleft())
    monkeypatch.setattr(mikrotik_background, "mac_login_enabled", lambda rid: mac_login)

    async def _noop(*_a, **_k):
        return None

    monkeypatch.setattr(mikrotik_background, "record_router_availability", _noop)
    monkeypatch.setattr(mikrotik_background, "prune_router_availability_history", _noop)
    for _ in polls:
        await mikrotik_background.collect_bandwidth_snapshot()

    async with session_factory() as s:
        period = (await s.execute(select(CustomerUsagePeriod)
                                  .where(CustomerUsagePeriod.customer_id == customer.id))).scalar_one_or_none()
        rows = (await s.execute(select(UserBandwidthUsage)
                                .where(UserBandwidthUsage.customer_id == customer.id))).scalars().all()
    return (period.total_bytes if period else 0), rows


@pytest.mark.asyncio
async def test_mac_login_queue_is_metered_and_each_session_has_its_own_counter(db, session_factory, monkeypatch):
    total, rows = await _run(db, session_factory, monkeypatch, [
        [_dyn(f"<hotspot-{MAC}>", 1 * MB, 10 * MB), _dyn(f"<hotspot-{MAC}-2>", 0, MB // 10)],
        [_dyn(f"<hotspot-{MAC}>", 2 * MB, 30 * MB), _dyn(f"<hotspot-{MAC}-2>", 0, 3 * MB // 10)],
    ])
    # First reading of a session queue is that session's usage; then deltas.
    assert total == (2 * MB + 30 * MB) + 3 * MB // 10
    assert sorted(r.mac_address for r in rows) == [f"hsq:{MAC}", f"hsq:{MAC}-2"]


@pytest.mark.asyncio
async def test_a_new_session_queue_is_credited_from_zero(db, session_factory, monkeypatch):
    total, _ = await _run(db, session_factory, monkeypatch, [
        [_dyn(f"<hotspot-{MAC}>", 0, 40 * MB)],
        [_dyn(f"<hotspot-{MAC}>", 0, 5 * MB)],   # session ended, a new one started
    ])
    assert total == 45 * MB


@pytest.mark.asyncio
async def test_dynamic_queues_are_ignored_when_router_is_not_mac_login(db, session_factory, monkeypatch):
    total, rows = await _run(db, session_factory, monkeypatch, [
        [_dyn(f"<hotspot-{MAC}>", 1 * MB, 10 * MB)],
        [_dyn(f"<hotspot-{MAC}>", 2 * MB, 30 * MB)],
    ], mac_login=False)
    assert total == 0 and rows == []


@pytest.mark.asyncio
async def test_plan_queue_wins_over_a_leftover_mac_login_queue(db, session_factory, monkeypatch):
    plan_q = lambda up, dn: {"name": "plan_AABBCCDDEE01", "comment": f"MAC:{MAC}|Plan",
                             "bytes": f"{up}/{dn}", "max-limit": "5M/5M", "target": "192.168.88.20/32"}
    total, rows = await _run(db, session_factory, monkeypatch, [
        [plan_q(0, 0), _dyn(f"<hotspot-{MAC}>", 0, 50 * MB)],
        [plan_q(0, 10 * MB), _dyn(f"<hotspot-{MAC}>", 0, 60 * MB)],
    ])
    assert total == 10 * MB  # the plan_ queue only; no double count
    assert all(not r.mac_address.startswith("hsq:") for r in rows)


def test_queue_identity_parsing():
    ident = mikrotik_background.mac_login_queue_identity
    assert ident("<hotspot-1a:91:db:40:a4:fd-2>") == ("1A:91:DB:40:A4:FD", "hsq:1A:91:DB:40:A4:FD-2")
    assert ident("<hotspot-E6:EA:6B:26:AC:A6>") == ("E6:EA:6B:26:AC:A6", "hsq:E6:EA:6B:26:AC:A6")
    assert ident("<hotspot-voucher123>") is None
    assert ident("plan_AABBCCDDEEFF") is None
    assert ident("<pppoe-bob>") is None

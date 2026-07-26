"""PPPoE usage attribution in the bandwidth snapshot job (PKT-001).

Reseller-reported defect: a PPPoE customer's card shows "0 MB" on a monthly
plan while hotspot customers accumulate normally.  Production evidence
(2026-07-26, read-only): 39/172 ``pppoe:*`` rows in ``user_bandwidth_usage``
have ``customer_id IS NULL`` and 332 active PPPoE customers hold only 126 open
usage periods — the collection loop samples the dynamic ``<pppoe-USERNAME>``
queue but fails to attribute it to the customer, so the byte baseline advances
while the open ``CustomerUsagePeriod`` stays at 0 forever.

Attribution in ``collect_bandwidth_snapshot`` required an exact, case-sensitive
``pppoe_username`` match scoped to the sampled router row.  Real fleets drift:
resellers hand-recreate secrets in Winbox with different case, and replaced /
re-registered routers leave ``Customer.router_id`` pointing at a stale router
row.  These tests pin the tolerant behavior:

* case-insensitive username match on the sampled router;
* unique global username fallback when the router row doesn't match
  (PPPoE usernames are globally unique app-wide — create/update/import all
  enforce it);
* NO attribution when the case-insensitive fallback is ambiguous.
"""

from collections import deque
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    ConnectionType,
    CustomerUsagePeriod,
    UserBandwidthUsage,
)
from app.services import mikrotik_background
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _raw_snapshot(router_id: int, *, queues: list[dict], rx: int = 10_000, tx: int = 5_000) -> dict:
    return {
        "router_id": router_id,
        "active_sessions": {"success": True, "data": []},
        "traffic": {
            "success": True,
            "data": [{"name": "ether1", "running": True, "rx_byte": rx, "tx_byte": tx}],
        },
        "speed_stats": {
            "success": True,
            "data": {
                "total_upload_bps": 0,
                "total_download_bps": 0,
                "active_queues": 0,
                "total_queues": len(queues),
            },
        },
        "queues": {"success": True, "data": queues},
        "hotspot_hosts": {"success": True, "authorized": 0, "bypassed": 0, "total": 0},
        "arp_entries": {"success": True, "count": 0, "data": []},
        "pppoe_sessions": {"success": True, "data": []},
    }


def _pppoe_queue(username: str, bytes_str: str) -> dict:
    return {
        "name": f"<pppoe-{username}>",
        "comment": "",
        "bytes": bytes_str,
        "max-limit": "10M/10M",
        "target": "10.10.10.2/32",
    }


def _patch_background(monkeypatch, session_factory, payloads_by_router: dict[int, deque]):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_a, **_k: False)
    monkeypatch.setattr(
        mikrotik_background,
        "_fetch_bandwidth_data_sync_for_router",
        lambda info: payloads_by_router[info["id"]].popleft(),
    )

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(mikrotik_background, "record_router_availability", _noop)
    monkeypatch.setattr(mikrotik_background, "prune_router_availability_history", _noop)


async def _open_period_for(session_factory, customer_id: int):
    async with session_factory() as s:
        return (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer_id,
                    CustomerUsagePeriod.closed_at.is_(None),
                )
            )
        ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_pppoe_usage_attributed_when_secret_case_differs(
    db,
    session_factory,
    monkeypatch,
):
    """Router secret recreated by hand as 'brian' while the DB has 'Brian'.

    The dynamic queue is named ``<pppoe-brian>``; usage must still land in
    Brian's open period instead of an orphaned usage row.
    """
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        phone="254700010001",
        pppoe_username="Brian",
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    payloads = {
        router.id: deque(
            [
                _raw_snapshot(router.id, queues=[_pppoe_queue("brian", "500/1500")]),
                _raw_snapshot(router.id, queues=[_pppoe_queue("brian", "900/2500")], rx=20_000, tx=10_000),
            ]
        )
    }
    _patch_background(monkeypatch, session_factory, payloads)

    await mikrotik_background.collect_bandwidth_snapshot()
    await mikrotik_background.collect_bandwidth_snapshot()

    period = await _open_period_for(session_factory, customer.id)
    assert period is not None, "case-drifted PPPoE secret must still accrue a usage period"
    assert period.upload_bytes == 400
    assert period.download_bytes == 1000
    assert period.total_bytes == 1400

    async with session_factory() as s:
        rows = (
            await s.execute(
                select(UserBandwidthUsage).where(
                    UserBandwidthUsage.mac_address.in_(["pppoe:Brian", "pppoe:brian"])
                )
            )
        ).scalars().all()
    assert len(rows) == 1
    # Canonical key comes from the DB username so the cap sampler and the
    # snapshot job share one row.
    assert rows[0].mac_address == "pppoe:Brian"
    assert rows[0].customer_id == customer.id


@pytest.mark.asyncio
async def test_pppoe_usage_attributed_after_router_reregistration(
    db,
    session_factory,
    monkeypatch,
):
    """Customer.router_id points at a stale router row; the live session (and
    its dynamic queue) shows up on the re-registered router.  The globally
    unique username must still attribute the usage."""
    reseller = await make_reseller(db)
    router_old = await make_router(db, reseller)
    router_new = await make_router(db, reseller, ip_address="10.0.0.3")
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router_old,
        phone="254700010002",
        pppoe_username="KevoHome",
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    payloads = {
        router_old.id: deque(
            [
                _raw_snapshot(router_old.id, queues=[]),
                _raw_snapshot(router_old.id, queues=[]),
            ]
        ),
        router_new.id: deque(
            [
                _raw_snapshot(router_new.id, queues=[_pppoe_queue("KevoHome", "500/1500")]),
                _raw_snapshot(router_new.id, queues=[_pppoe_queue("KevoHome", "900/2500")], rx=20_000, tx=10_000),
            ]
        ),
    }
    _patch_background(monkeypatch, session_factory, payloads)

    await mikrotik_background.collect_bandwidth_snapshot()
    await mikrotik_background.collect_bandwidth_snapshot()

    period = await _open_period_for(session_factory, customer.id)
    assert period is not None, "username is globally unique; stale router_id must not orphan usage"
    assert period.upload_bytes == 400
    assert period.download_bytes == 1000

    async with session_factory() as s:
        usage = (
            await s.execute(
                select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == "pppoe:KevoHome")
            )
        ).scalar_one()
    assert usage.customer_id == customer.id


@pytest.mark.asyncio
async def test_pppoe_usage_not_attributed_when_username_ambiguous(
    db,
    session_factory,
    monkeypatch,
):
    """Two customers whose usernames differ only by case, session on a third
    router: the fallback must refuse to guess (no attribution, no period)."""
    reseller_a = await make_reseller(db)
    reseller_b = await make_reseller(db)
    reseller_c = await make_reseller(db)
    router_a = await make_router(db, reseller_a)
    router_b = await make_router(db, reseller_b, ip_address="10.0.0.4")
    router_c = await make_router(db, reseller_c, ip_address="10.0.0.5")
    plan_a = await make_plan(db, reseller_a, connection_type=ConnectionType.PPPOE)
    plan_b = await make_plan(db, reseller_b, connection_type=ConnectionType.PPPOE)
    expiry = datetime.utcnow() + timedelta(days=30)
    customer_a = await make_customer(
        db, reseller_a, plan_a, router_a,
        phone="254700010003", pppoe_username="Wanjiku", expiry=expiry,
    )
    customer_b = await make_customer(
        db, reseller_b, plan_b, router_b,
        phone="254700010004", pppoe_username="wanjiku", expiry=expiry,
    )

    payloads = {
        router_a.id: deque([_raw_snapshot(router_a.id, queues=[])] * 2),
        router_b.id: deque([_raw_snapshot(router_b.id, queues=[])] * 2),
        router_c.id: deque(
            [
                _raw_snapshot(router_c.id, queues=[_pppoe_queue("WANJIKU", "500/1500")]),
                _raw_snapshot(router_c.id, queues=[_pppoe_queue("WANJIKU", "900/2500")]),
            ]
        ),
    }
    _patch_background(monkeypatch, session_factory, payloads)

    await mikrotik_background.collect_bandwidth_snapshot()
    await mikrotik_background.collect_bandwidth_snapshot()

    assert await _open_period_for(session_factory, customer_a.id) is None
    assert await _open_period_for(session_factory, customer_b.id) is None

    async with session_factory() as s:
        usage = (
            await s.execute(
                select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address == "pppoe:WANJIKU")
            )
        ).scalar_one()
    assert usage.customer_id is None

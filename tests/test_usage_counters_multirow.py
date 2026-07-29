"""Regression tests for the 2026-07-29 poller-freeze incident.

PR #20's cross-tenant fix in ``record_queue_usage_sample`` looked a usage row up
BY CUSTOMER FIRST. But a customer legitimately owns several rows — one per
device/queue key they have ever used (randomised phone MACs; one customer in
prod owns 25). For those customers the lookup grabbed an arbitrary row and then
rewrote its ``mac_address`` to the current key, manufacturing DUPLICATE rows for
one key. The bandwidth poller's hotspot lookup (``scalar_one_or_none`` by MAC)
then raised ``Multiple rows were found``, whose cleanup path aborted the whole
run before the rotation cursor advanced — freezing the poller on the same 8
routers and flatlining every other router's dashboard.

These tests pin the corrected contract:

* the helper only ever touches a row for THE KEY BEING SAMPLED — a multi-row
  customer's other rows are never rewritten;
* another customer's row for the same key is never touched (the original
  cross-tenant guarantee, now with the claimed row actually present);
* the poller completes its run and records a snapshot even when duplicate rows
  for one MAC already exist in the table (the incident's direct trigger).
"""

from collections import deque
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    BandwidthSnapshot,
    ConnectionType,
    CustomerStatus,
    UserBandwidthUsage,
)
from app.services import mikrotik_background
from app.services.usage_counters import record_queue_usage_sample
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


async def _customer(db, *, mac="AA:BB:CC:11:22:33"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address=mac, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    return reseller, router, plan, customer


def _row(key, customer_id=None, up=0, dn=0):
    return UserBandwidthUsage(
        mac_address=key, customer_id=customer_id,
        upload_bytes=up, download_bytes=dn,
        last_upload_bytes=up, last_download_bytes=dn,
        last_updated=datetime.utcnow(),
    )


@pytest.mark.asyncio
async def test_multi_row_customer_updates_only_the_sampled_key(db, session_factory):
    """A customer with rows for two device keys: sampling key B must update B's
    row and leave A's row untouched — the incident began with A's row being
    grabbed and its mac rewritten to B."""
    _, _, plan, customer = await _customer(db)
    key_a, key_b = "AA:BB:CC:00:00:0A", "AA:BB:CC:00:00:0B"

    async with session_factory() as s:
        s.add(_row(key_a, customer_id=customer.id, up=1 * MB, dn=9 * MB))
        s.add(_row(key_b, customer_id=customer.id, up=2 * MB, dn=4 * MB))
        await s.commit()

    async with session_factory() as s:
        cust = await s.get(type(customer), customer.id)
        pl = await s.get(type(plan), plan.id)
        update = await record_queue_usage_sample(
            s, customer=cust, plan=pl, queue_key=key_b,
            upload_bytes=3 * MB, download_bytes=6 * MB,
        )
        await s.commit()

    assert update.usage.mac_address == key_b
    assert update.delta_upload_bytes == 1 * MB
    assert update.delta_download_bytes == 2 * MB

    async with session_factory() as s:
        rows = (await s.execute(
            select(UserBandwidthUsage).order_by(UserBandwidthUsage.mac_address)
        )).scalars().all()

    by_key = {r.mac_address: r for r in rows}
    assert set(by_key) == {key_a, key_b}, "a row's key was rewritten"
    assert by_key[key_a].download_bytes == 9 * MB, "the other key's row was touched"
    assert by_key[key_b].download_bytes == 6 * MB


@pytest.mark.asyncio
async def test_never_adopts_another_customers_row_for_the_same_key(db, session_factory):
    """Same key claimed by another customer: create our own row, do not steal."""
    _, _, plan, ours = await _customer(db, mac="AA:BB:CC:00:00:0C")
    _, _, _, other = await _customer(db, mac="AA:BB:CC:00:00:0C")
    key = "AA:BB:CC:00:00:0C"

    async with session_factory() as s:
        s.add(_row(key, customer_id=other.id, up=5 * MB, dn=50 * MB))
        await s.commit()

    async with session_factory() as s:
        cust = await s.get(type(ours), ours.id)
        pl = await s.get(type(plan), plan.id)
        update = await record_queue_usage_sample(
            s, customer=cust, plan=pl, queue_key=key,
            upload_bytes=1 * MB, download_bytes=2 * MB,
        )
        await s.commit()

    assert update.created is True
    async with session_factory() as s:
        rows = (await s.execute(select(UserBandwidthUsage))).scalars().all()
    theirs = [r for r in rows if r.customer_id == other.id]
    assert len(rows) == 2
    assert theirs[0].download_bytes == 50 * MB, "another customer's counters were overwritten"


@pytest.mark.asyncio
async def test_legacy_unclaimed_row_is_still_adopted(db, session_factory):
    _, _, plan, customer = await _customer(db, mac="AA:BB:CC:00:00:0D")
    key = "AA:BB:CC:00:00:0D"

    async with session_factory() as s:
        s.add(_row(key, customer_id=None, up=1 * MB, dn=1 * MB))
        await s.commit()

    async with session_factory() as s:
        cust = await s.get(type(customer), customer.id)
        pl = await s.get(type(plan), plan.id)
        update = await record_queue_usage_sample(
            s, customer=cust, plan=pl, queue_key=key,
            upload_bytes=2 * MB, download_bytes=3 * MB,
        )
        await s.commit()

    assert update.created is False
    assert update.usage.customer_id == customer.id

    async with session_factory() as s:
        rows = (await s.execute(select(UserBandwidthUsage))).scalars().all()
    assert len(rows) == 1


def _poller_payload(router_id, mac_comment_mac, bytes_str):
    return {
        "router_id": router_id,
        "active_sessions": {"success": True, "data": []},
        "traffic": {"success": True, "data": [
            {"name": "ether1", "running": True, "rx_byte": 10_000, "tx_byte": 5_000}]},
        "speed_stats": {"success": True, "data": {
            "total_upload_bps": 0, "total_download_bps": 0,
            "active_queues": 1, "total_queues": 1}},
        "queues": {"success": True, "data": [{
            "name": "plan_" + mac_comment_mac.replace(":", ""),
            "comment": f"MAC:{mac_comment_mac}|Plan rate limit",
            "bytes": bytes_str, "max-limit": "5M/5M",
            "target": "192.168.88.10/32"}]},
        "hotspot_hosts": {"success": True, "authorized": 1, "bypassed": 0, "total": 1},
        "arp_entries": {"success": True, "count": 0, "data": []},
        "pppoe_sessions": {"success": True, "data": []},
    }


@pytest.mark.asyncio
async def test_poller_survives_duplicate_usage_rows_for_one_mac(
    db, session_factory, monkeypatch
):
    """The incident trigger: duplicate rows for one MAC already in the table.

    The hotspot lookup used scalar_one_or_none, raised MultipleResultsFound, the
    run aborted before the rotation cursor advanced, and every other router's
    dashboard froze. The poller must instead complete the run and commit the
    snapshot.
    """
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    mac = "AA:BB:CC:DD:EE:FF"
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address=mac, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
    )

    # The duplicates my helper manufactured in production: one claimed, one not.
    async with session_factory() as s:
        s.add(_row(mac, customer_id=customer.id, up=1 * MB, dn=2 * MB))
        s.add(_row(mac, customer_id=None, up=0, dn=0))
        await s.commit()

    payloads = deque([_poller_payload(router.id, mac, f"{2 * MB}/{5 * MB}")])
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _j: False)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_a, **_k: False)
    monkeypatch.setattr(
        mikrotik_background, "_fetch_bandwidth_data_sync_for_router",
        lambda _info: payloads.popleft(),
    )

    async def _noop(*_a, **_k):
        return None

    monkeypatch.setattr(mikrotik_background, "record_router_availability", _noop)
    monkeypatch.setattr(mikrotik_background, "prune_router_availability_history", _noop)

    await mikrotik_background.collect_bandwidth_snapshot()

    async with session_factory() as s:
        snapshot = (await s.execute(
            select(BandwidthSnapshot).where(BandwidthSnapshot.router_id == router.id)
        )).scalars().all()

    assert len(snapshot) == 1, (
        "poller failed to commit a snapshot when duplicate usage rows exist — "
        "this is the exact 2026-07-29 dashboard-freeze trigger"
    )

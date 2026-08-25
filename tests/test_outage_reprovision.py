"""Re-provisioning revived outage-compensation customers.

This module is the only part of outage compensation that leaves the database,
so what matters here is not "does the router come back" (that is RouterOS's
job) but the safety contract around it:

* no DB session is held across the router call — the rule from **Database
  Session Discipline** in AGENTS.md that this whole design exists to obey;
* one customer's failure never takes the batch down with it;
* a router that is already known to be down is skipped, not retried into a
  timeout — after a power cut that is the *expected* case, not an edge case;
* every outcome, success or not, lands on the item row, so a partial recovery
  is visible instead of being reported as a clean run.
"""

from datetime import datetime, timedelta

import pytest

from app.db import database as db_module
from app.db.models import (
    CustomerStatus,
    OutageCompensation,
    OutageCompensationItem,
)
from app.services import outage_reprovision
from app.services.outage_reprovision import (
    REPROVISION_FAILED,
    REPROVISION_PENDING,
    REPROVISION_ROUTER_OFFLINE,
    REPROVISION_SUCCEEDED,
    REPROVISION_UNSUPPORTED,
    reprovision_items,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def _pending_item(db, *, router_kwargs=None, customer_kwargs=None):
    """A committed compensation run with one revived customer awaiting a router
    write — the exact state apply_outage_compensation leaves behind."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller, **(router_kwargs or {}))
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        created_at=datetime.utcnow() - timedelta(days=30),
        **(customer_kwargs or {}),
    )
    run = OutageCompensation(
        user_id=reseller.id,
        router_ids=[router.id],
        outage_start=datetime.utcnow() - timedelta(hours=6),
        outage_end=datetime.utcnow() - timedelta(hours=4),
        customers_credited=1,
        customers_reactivated=1,
        include_expired=True,
    )
    db.add(run)
    await db.flush()
    item = OutageCompensationItem(
        compensation_id=run.id,
        customer_id=customer.id,
        customer_name=customer.name,
        router_id=router.id,
        seconds_credited=7200,
        expiry_before=datetime.utcnow() - timedelta(hours=5),
        expiry_after=customer.expiry,
        was_expired=True,
        reprovision_state=REPROVISION_PENDING,
    )
    db.add(item)
    await db.commit()
    return item, customer, router


async def _state_of(item_id: int) -> OutageCompensationItem:
    """Read the item back through a fresh session, as the worker wrote it."""
    async with db_module.async_session() as s:
        return await s.get(OutageCompensationItem, item_id)


@pytest.fixture
def fake_hotspot(monkeypatch):
    """Stand in for the RouterOS write and record how it was called."""
    calls = []

    async def _fake(customer_id, router_id, payload, action=None, attempt_id=None):
        calls.append(
            {
                "customer_id": customer_id,
                "router_id": router_id,
                "action": action,
                "payload": payload,
            }
        )
        return {"success": True}

    monkeypatch.setattr(
        "app.services.hotspot_provisioning.provision_hotspot_customer", _fake
    )
    return calls


# ------------------------------------------------------------- happy path ----

async def test_successful_reprovision_is_recorded(db, fake_hotspot):
    item, customer, router = await _pending_item(db)

    summary = await reprovision_items([item.id])

    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    assert (await _state_of(item.id)).reprovision_state == REPROVISION_SUCCEEDED

    assert len(fake_hotspot) == 1
    assert fake_hotspot[0]["customer_id"] == customer.id
    assert fake_hotspot[0]["router_id"] == router.id
    assert fake_hotspot[0]["action"] == "outage_compensation"


async def test_no_db_session_is_held_across_the_router_call(db, monkeypatch):
    """The core safety property. The stand-in provisioning call opens its own
    session and writes — which would block on a row lock (and, in production,
    pin a second pooled connection) if the worker were still holding the item's
    transaction open while awaiting the router."""
    item, customer, _ = await _pending_item(db)
    observed = {}

    async def _fake(customer_id, router_id, payload, action=None, attempt_id=None):
        async with db_module.async_session() as s:
            row = await s.get(OutageCompensationItem, item.id)
            row.customer_name = "touched mid-call"
            await s.commit()
            observed["wrote_during_call"] = True
        return {"success": True}

    monkeypatch.setattr(
        "app.services.hotspot_provisioning.provision_hotspot_customer", _fake
    )

    summary = await reprovision_items([item.id])

    assert observed.get("wrote_during_call") is True
    assert summary["succeeded"] == 1


# ------------------------------------------------------------- failure ----

async def test_offline_router_is_skipped_without_calling_the_router(db, fake_hotspot):
    """After a power cut the router is often still dark. Burning a timeout per
    customer on a device that cannot answer is exactly what we must not do."""
    item, _, _ = await _pending_item(db, router_kwargs={"last_status": False})

    summary = await reprovision_items([item.id])

    assert summary["router_offline"] == 1
    assert fake_hotspot == [], "must not dial a router known to be down"

    state = await _state_of(item.id)
    assert state.reprovision_state == REPROVISION_ROUTER_OFFLINE
    # The reason has to survive: this row is retried once the router is back.
    assert "offline" in (state.reprovision_error or "").lower()


async def test_provisioning_failure_is_recorded_not_swallowed(db, monkeypatch):
    item, _, _ = await _pending_item(db)

    async def _fail(customer_id, router_id, payload, action=None, attempt_id=None):
        return {"success": False, "error": "no such command prefix"}

    monkeypatch.setattr(
        "app.services.hotspot_provisioning.provision_hotspot_customer", _fail
    )

    summary = await reprovision_items([item.id])

    assert summary["failed"] == 1
    state = await _state_of(item.id)
    assert state.reprovision_state == REPROVISION_FAILED
    assert "no such command prefix" in state.reprovision_error


async def test_one_customers_exception_does_not_kill_the_batch(db, monkeypatch):
    """A whole outage's recovery must not hinge on one bad row."""
    first, first_customer, _ = await _pending_item(db)
    second, second_customer, _ = await _pending_item(db)

    async def _explode_for_first(
        customer_id, router_id, payload, action=None, attempt_id=None
    ):
        if customer_id == first_customer.id:
            raise RuntimeError("router exploded")
        return {"success": True}

    monkeypatch.setattr(
        "app.services.hotspot_provisioning.provision_hotspot_customer",
        _explode_for_first,
    )

    summary = await reprovision_items([first.id, second.id])

    assert summary["failed"] == 1
    assert summary["succeeded"] == 1
    assert (await _state_of(first.id)).reprovision_state == REPROVISION_FAILED
    assert (await _state_of(second.id)).reprovision_state == REPROVISION_SUCCEEDED


async def test_customer_without_a_mac_is_marked_unsupported(db, fake_hotspot):
    item, _, _ = await _pending_item(db, customer_kwargs={"mac_address": ""})

    summary = await reprovision_items([item.id])

    assert summary["unsupported"] == 1
    assert fake_hotspot == []
    assert (await _state_of(item.id)).reprovision_state == REPROVISION_UNSUPPORTED


# ------------------------------------------------------------- load shed ----

async def test_work_is_deferred_when_the_db_pool_is_under_pressure(
    db, monkeypatch, fake_hotspot
):
    """Optional background work must yield to paying traffic (AGENTS.md). The
    credit is already committed, so deferring costs nothing but a retry."""
    item, _, _ = await _pending_item(db)
    monkeypatch.setattr(outage_reprovision, "_pool_is_busy", lambda: True)

    summary = await reprovision_items([item.id])

    assert summary["deferred"] == 1
    assert summary["attempted"] == 0
    assert fake_hotspot == []
    # Left pending so a retry can pick it up — never silently dropped.
    assert (await _state_of(item.id)).reprovision_state == REPROVISION_PENDING


async def test_empty_batch_is_a_no_op(db, fake_hotspot):
    assert (await reprovision_items([]))["attempted"] == 0
    assert fake_hotspot == []


# ------------------------------------------------------------- batching ----

async def test_pool_pressure_partway_through_defers_the_rest(db, monkeypatch):
    """A town-wide outage takes minutes to reconnect, so the pool can come
    under pressure *during* the run. Checking only once at the start would
    push on regardless; the remainder must be deferred, not abandoned."""
    items = [(await _pending_item(db))[0].id for _ in range(3)]

    monkeypatch.setattr(outage_reprovision, "_CHUNK_SIZE", 1)
    calls = {"n": 0}

    async def _ok(customer_id, router_id, payload, action=None, attempt_id=None):
        calls["n"] += 1
        return {"success": True}

    monkeypatch.setattr(
        "app.services.hotspot_provisioning.provision_hotspot_customer", _ok
    )
    # Healthy for the first chunk, then under pressure.
    checks = {"n": 0}

    def _busy_after_first():
        checks["n"] += 1
        return checks["n"] > 1

    monkeypatch.setattr(outage_reprovision, "_pool_is_busy", _busy_after_first)

    summary = await reprovision_items(items)

    assert summary["succeeded"] == 1
    assert summary["deferred"] == 2
    assert calls["n"] == 1, "must stop dialling routers once the pool is busy"
    # Deferred rows stay pending so the retry endpoint can pick them up.
    assert (await _state_of(items[1])).reprovision_state == REPROVISION_PENDING


async def test_attempt_is_registered_in_the_same_session_as_the_read(db, fake_hotspot):
    """Read + attempt-create share one short session, halving pool checkouts
    per customer. Both still happen before any router I/O."""
    item, _, _ = await _pending_item(db)

    job = await outage_reprovision._load_job(item.id)

    assert job is not None
    assert job["attempt_id"] is not None
    assert fake_hotspot == [], "loading a job must not touch the router"

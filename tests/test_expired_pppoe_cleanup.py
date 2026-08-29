"""PPPoE expiry enforcement round-trip (mirrors test_expired_hotspot_cleanup.py).

cleanup_expired_users_background splits expired ACTIVE customers into hotspot
vs PPPoE; PPPoE goes through _cleanup_single_router_pppoe_sync (disconnect
session + remove secret). The money-side invariant under test: a customer's DB
row flips to INACTIVE ONLY after the router actually enforced the cutoff —
otherwise the row must stay ACTIVE so the next run retries (an INACTIVE row
with a live session is free internet, invisible to every retry path).
"""

import asyncio
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import ConnectionType, CustomerStatus, ProvisioningLog
from app.services import mikrotik_background
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


def _patch_cleanup_side_effects(monkeypatch, session_factory):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job_name: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _async_none)


async def _async_zero(*_args, **_kwargs):
    return 0


async def _async_none(*_args, **_kwargs):
    return None


async def _make_expired_pppoe_customer(db, *, pppoe_username="pppuser1", minutes_expired=30):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=minutes_expired),
        pppoe_username=pppoe_username,
    )
    return reseller, plan, router, customer


# ---------------------------------------------------------------------------
# Boundary-patched tests (same seam the hotspot suite uses)
# ---------------------------------------------------------------------------

async def test_pppoe_cleanup_keeps_expired_customer_active_when_router_cleanup_fails(
    db, session_factory, monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    _, _, router, customer = await _make_expired_pppoe_customer(db)

    cleanup_calls = []

    def fake_router_cleanup(router_info, customers_data):
        cleanup_calls.append((router_info["ip"], [c["id"] for c in customers_data]))
        return {
            "removed": [],
            "failed": [{"id": c["id"], "error": "router unavailable"} for c in customers_data],
            "connected": False,
        }

    monkeypatch.setattr(
        mikrotik_background, "_cleanup_single_router_pppoe_sync", fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert cleanup_calls == [(router.ip_address, [customer.id])]


async def test_pppoe_cleanup_marks_customer_inactive_after_router_cleanup_succeeds(
    db, session_factory, monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    _, _, router, customer = await _make_expired_pppoe_customer(db)

    cleanup_calls = []

    def fake_router_cleanup(router_info, customers_data):
        cleanup_calls.append(
            (router_info["ip"], [(c["id"], c["pppoe_username"]) for c in customers_data])
        )
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background, "_cleanup_single_router_pppoe_sync", fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE
    assert cleanup_calls == [(router.ip_address, [(customer.id, "pppuser1")])]
    deactivation_log = (
        await db.execute(
            select(ProvisioningLog).where(
                ProvisioningLog.customer_id == customer.id,
                ProvisioningLog.action == "pppoe_deactivation",
                ProvisioningLog.status == "success",
            )
        )
    ).scalar_one()
    assert "Expiry cleanup" in deactivation_log.details


async def test_inactive_pppoe_safety_net_removes_once_and_records_cleanup_proof(
    db, session_factory, monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    monkeypatch.setattr(mikrotik_background, "inactive_pppoe_reconcile_running", False)
    monkeypatch.setattr(mikrotik_background, "_inactive_pppoe_reconcile_cursor", 0)
    _, _, router, customer = await _make_expired_pppoe_customer(db)
    customer.status = CustomerStatus.INACTIVE
    await db.commit()

    cleanup_calls = []

    def fake_router_cleanup(router_info, customers_data):
        cleanup_calls.append((router_info["ip"], [row["id"] for row in customers_data]))
        return {
            "removed": [{"id": row["id"], "details": {}} for row in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_pppoe_sync",
        fake_router_cleanup,
    )

    first = await mikrotik_background.reconcile_inactive_pppoe_access_background()
    second = await mikrotik_background.reconcile_inactive_pppoe_access_background()

    assert first == {"selected": 1, "removed": 1, "failed": 0, "restored": 0}
    assert second == {"selected": 0, "removed": 0, "failed": 0, "restored": 0}
    assert cleanup_calls == [(router.ip_address, [customer.id])]
    cleanup_log = (
        await db.execute(
            select(ProvisioningLog).where(
                ProvisioningLog.customer_id == customer.id,
                ProvisioningLog.action == "pppoe_deactivation",
                ProvisioningLog.status == "success",
            )
        )
    ).scalar_one()
    assert "safety net" in cleanup_log.details


async def test_inactive_pppoe_safety_net_retries_when_router_cleanup_fails(
    db, session_factory, monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    monkeypatch.setattr(mikrotik_background, "inactive_pppoe_reconcile_running", False)
    monkeypatch.setattr(mikrotik_background, "_inactive_pppoe_reconcile_cursor", 0)
    _, _, _, customer = await _make_expired_pppoe_customer(db)
    customer.status = CustomerStatus.INACTIVE
    await db.commit()

    calls = []

    def fake_router_cleanup(_router_info, customers_data):
        calls.append([row["id"] for row in customers_data])
        return {
            "removed": [],
            "failed": [{"id": row["id"], "error": "router unavailable"} for row in customers_data],
            "connected": False,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_pppoe_sync",
        fake_router_cleanup,
    )

    first = await mikrotik_background.reconcile_inactive_pppoe_access_background()
    second = await mikrotik_background.reconcile_inactive_pppoe_access_background()

    assert first["failed"] == 1
    assert second["failed"] == 1
    assert calls == [[customer.id], [customer.id]]
    cleanup_log = (
        await db.execute(
            select(ProvisioningLog).where(
                ProvisioningLog.customer_id == customer.id,
                ProvisioningLog.action == "pppoe_deactivation",
            )
        )
    ).scalar_one_or_none()
    assert cleanup_log is None


async def test_inactive_pppoe_safety_net_sheds_work_when_db_pool_is_busy(monkeypatch):
    monkeypatch.setattr(mikrotik_background, "inactive_pppoe_reconcile_running", False)
    monkeypatch.setattr(
        mikrotik_background,
        "_background_db_pool_is_busy",
        lambda _job_name: True,
    )

    async def _must_not_load():
        raise AssertionError("candidate query must not run under DB-pool pressure")

    monkeypatch.setattr(
        mikrotik_background,
        "_load_inactive_pppoe_reconcile_batch",
        _must_not_load,
    )

    result = await mikrotik_background.reconcile_inactive_pppoe_access_background()

    assert result == {"skipped": "db_pool_busy"}


async def test_inactive_pppoe_safety_net_caps_customers_per_router(
    db, session_factory, monkeypatch,
):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "_inactive_pppoe_reconcile_cursor", 0)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    for index in range(mikrotik_background.INACTIVE_PPPOE_RECONCILE_MAX_PER_ROUTER + 2):
        await make_customer(
            db,
            reseller,
            plan,
            router,
            status=CustomerStatus.INACTIVE,
            expiry=datetime.utcnow() - timedelta(hours=1),
            pppoe_username=f"inactive-{index}",
        )

    batch = await mikrotik_background._load_inactive_pppoe_reconcile_batch()

    assert len(batch) == mikrotik_background.INACTIVE_PPPOE_RECONCILE_MAX_PER_ROUTER
    assert {row["router_id"] for row in batch} == {router.id}


async def test_pppoe_customer_routes_to_pppoe_boundary_not_hotspot(
    db, session_factory, monkeypatch,
):
    """A customer with a MAC on file but a PPPoE plan must go through the PPPoE
    path (secret removal), never the hotspot IP-binding path."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    _, _, _, customer = await _make_expired_pppoe_customer(db)

    pppoe_calls, hotspot_calls = [], []

    def fake_pppoe(_router_info, customers_data):
        pppoe_calls.append([c["id"] for c in customers_data])
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    def fake_hotspot(_router_info, customers_data):
        hotspot_calls.append([c["id"] for c in customers_data])
        return {"removed": [], "failed": [], "connected": True}

    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_pppoe_sync", fake_pppoe)
    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync", fake_hotspot)

    await mikrotik_background.cleanup_expired_users_background()

    assert pppoe_calls == [[customer.id]]
    assert hotspot_calls == []


async def test_pppoe_customer_renewed_during_router_cleanup_stays_active(
    db, session_factory, monkeypatch,
):
    """Renewal race: a payment lands while the router cleanup is in flight.

    The job re-reads expiry after the router work; a renewed customer must NOT
    be deactivated even though the router reported a successful removal (the
    payment path re-provisions the secret independently)."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    _, _, _, customer = await _make_expired_pppoe_customer(db)

    loop = asyncio.get_running_loop()
    new_expiry = datetime.utcnow() + timedelta(days=30)

    async def _renew():
        async with session_factory() as s:
            row = await s.get(type(customer), customer.id)
            row.expiry = new_expiry
            await s.commit()

    def fake_router_cleanup(_router_info, customers_data):
        # Runs in a worker thread while the loop is free: schedule the renewal
        # on the loop and wait for it, exactly like a concurrent payment task.
        asyncio.run_coroutine_threadsafe(_renew(), loop).result(timeout=10)
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background, "_cleanup_single_router_pppoe_sync", fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry == new_expiry


async def test_pppoe_customer_without_router_is_deactivated_without_router_work(
    db, session_factory, monkeypatch,
):
    """Pins existing behavior: no router assigned -> nothing to enforce, the
    row flips INACTIVE directly and no router boundary is invoked."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    customer = await make_customer(
        db, reseller, plan, None,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(hours=1),
        pppoe_username="orphan-ppp",
    )

    def _explode(*_a, **_k):  # pragma: no cover - must not be called
        raise AssertionError("router boundary must not be reached without a router")

    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_pppoe_sync", _explode)
    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync", _explode)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE


# ---------------------------------------------------------------------------
# Real _cleanup_single_router_pppoe_sync with a stubbed RouterOS API
# ---------------------------------------------------------------------------

class _StubMikroTikAPI:
    """Configurable stand-in for MikroTikAPI inside mikrotik_background."""

    connect_ok = True
    disconnect_result = {"success": True, "disconnected": 1}
    remove_result = {"success": True, "action": "removed"}
    log: list = []

    def __init__(self, ip, username, password, port, timeout=None, connect_timeout=None):
        self._ip = ip

    def connect(self):
        type(self).log.append(("connect", self._ip, type(self).connect_ok))
        return type(self).connect_ok

    def disconnect_pppoe_session(self, username):
        type(self).log.append(("disconnect_pppoe_session", username))
        return dict(type(self).disconnect_result)

    def remove_pppoe_secret(self, username):
        type(self).log.append(("remove_pppoe_secret", username))
        return dict(type(self).remove_result)

    def disconnect(self):
        type(self).log.append(("disconnect", self._ip))


@pytest.fixture
def stub_api(monkeypatch):
    _StubMikroTikAPI.connect_ok = True
    _StubMikroTikAPI.disconnect_result = {"success": True, "disconnected": 1}
    _StubMikroTikAPI.remove_result = {"success": True, "action": "removed"}
    _StubMikroTikAPI.log = []
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", _StubMikroTikAPI)
    return _StubMikroTikAPI


async def test_real_pppoe_sync_unreachable_router_keeps_customer_active(
    db, session_factory, monkeypatch, stub_api,
):
    """Router connect failure: the service must report every customer failed and
    the DB row must stay ACTIVE for retry (this is the 'system disconnect
    doesn't cut client internet' failure class at the connect level)."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    stub_api.connect_ok = False
    _, _, _, customer = await _make_expired_pppoe_customer(db)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert ("remove_pppoe_secret", "pppuser1") not in stub_api.log


async def test_real_pppoe_sync_success_removes_secret_and_deactivates(
    db, session_factory, monkeypatch, stub_api,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    _, _, _, customer = await _make_expired_pppoe_customer(db)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE
    assert ("disconnect_pppoe_session", "pppuser1") in stub_api.log
    assert ("remove_pppoe_secret", "pppuser1") in stub_api.log


async def test_real_pppoe_sync_disconnect_error_keeps_customer_active_for_retry(
    db, session_factory, monkeypatch, stub_api,
):
    """Live-bug pin: secret removal succeeded but the session disconnect
    errored. The client keeps surfing on the established PPPoE session, so the
    DB row must stay ACTIVE and the next run must retry the disconnect —
    flipping it INACTIVE here is exactly 'system disconnect doesn't cut client
    internet' (no retry path ever looks at INACTIVE rows)."""
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    stub_api.disconnect_result = {"error": "timeout reading /ppp/active"}
    _, _, _, customer = await _make_expired_pppoe_customer(db)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    # Secret removal is still attempted (blocks re-auth) ...
    assert ("remove_pppoe_secret", "pppuser1") in stub_api.log
    # ... but enforcement is not complete until the live session is dead.
    assert customer.status == CustomerStatus.ACTIVE

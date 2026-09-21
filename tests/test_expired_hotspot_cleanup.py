import asyncio
from datetime import datetime, timedelta

import pytest

from app.api import customer_routes
from app.db.models import CustomerStatus, RouterAvailabilityCheck
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


async def test_cleanup_keeps_expired_customer_active_when_router_cleanup_fails(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(hours=2),
        mac_address="BE:96:9D:22:1B:45",
    )

    cleanup_calls = []

    def fake_router_cleanup(_router_info, customers_data):
        cleanup_calls.append([c["id"] for c in customers_data])
        return {
            "removed": [],
            "failed": [{"id": c["id"], "error": "router unavailable"} for c in customers_data],
            "connected": False,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert cleanup_calls == [[customer.id]]


async def test_cleanup_restores_recent_unreachable_router_backoff_after_restart(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=10),
        mac_address="BE:96:9D:22:1B:46",
    )
    failed_at = datetime.utcnow() - timedelta(minutes=5)
    db.add(
        RouterAvailabilityCheck(
            router_id=router.id,
            checked_at=failed_at,
            is_online=False,
            source="expired_cleanup",
        )
    )
    await db.commit()

    cleanup_calls = []

    def fake_router_cleanup(_router_info, customers_data):
        cleanup_calls.append([c["id"] for c in customers_data])
        return {"removed": [], "failed": [], "connected": True}

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert cleanup_calls == []
    assert mikrotik_background._expiry_cleanup_unreachable_routers[router.id] == failed_at


async def test_cleanup_does_not_restore_backoff_after_newer_online_sample(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=10),
        mac_address="BE:96:9D:22:1B:47",
    )
    now = datetime.utcnow()
    db.add_all(
        [
            RouterAvailabilityCheck(
                router_id=router.id,
                checked_at=now - timedelta(minutes=5),
                is_online=False,
                source="expired_cleanup",
            ),
            RouterAvailabilityCheck(
                router_id=router.id,
                checked_at=now - timedelta(minutes=1),
                is_online=True,
                source="bandwidth_snapshot",
            ),
        ]
    )
    await db.commit()

    cleanup_calls = []

    def fake_router_cleanup(_router_info, customers_data):
        cleanup_calls.append([c["id"] for c in customers_data])
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE
    assert cleanup_calls == [[customer.id]]
    assert router.id not in mikrotik_background._expiry_cleanup_unreachable_routers


async def test_cleanup_quarantines_long_offline_router_until_it_recovers(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    now = datetime.utcnow()
    offline_router = await make_router(
        db,
        reseller,
        last_status=False,
        last_checked_at=now - timedelta(minutes=1),
        last_online_at=now - timedelta(days=8),
    )
    online_router = await make_router(
        db,
        reseller,
        ip_address="10.0.0.3",
        last_status=True,
        last_checked_at=now - timedelta(minutes=1),
        last_online_at=now - timedelta(minutes=1),
    )
    quarantined = await make_customer(
        db,
        reseller,
        plan,
        offline_router,
        status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(days=2),
        mac_address="BE:96:9D:22:1B:48",
    )
    current = await make_customer(
        db,
        reseller,
        plan,
        online_router,
        status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(minutes=5),
        mac_address="BE:96:9D:22:1B:49",
    )

    cleanup_calls = []

    def fake_router_cleanup(router_info, customers_data):
        cleanup_calls.append((router_info["id"], [c["id"] for c in customers_data]))
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(quarantined)
    await db.refresh(current)

    assert cleanup_calls == [(online_router.id, [current.id])]
    assert quarantined.status == CustomerStatus.ACTIVE
    assert current.status == CustomerStatus.INACTIVE

    offline_router.last_status = True
    offline_router.last_checked_at = datetime.utcnow()
    offline_router.last_online_at = datetime.utcnow()
    await db.commit()
    cleanup_calls.clear()

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(quarantined)

    assert cleanup_calls == [(offline_router.id, [quarantined.id])]
    assert quarantined.status == CustomerStatus.INACTIVE


async def test_cleanup_marks_customer_inactive_after_router_cleanup_succeeds(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=30),
        mac_address="8E:B3:63:D7:1D:05",
    )

    cleanup_calls = []

    def fake_router_cleanup(_router_info, customers_data):
        cleanup_calls.append([c["id"] for c in customers_data])
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.INACTIVE
    assert cleanup_calls == [[customer.id]]


async def test_hotspot_customer_renewed_during_cleanup_is_immediately_repaired(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=5),
        mac_address="AA:BB:CC:DD:EE:45",
    )
    loop = asyncio.get_running_loop()
    new_expiry = datetime.utcnow() + timedelta(days=30)
    repairs = []

    async def _renew():
        async with session_factory() as session:
            row = await session.get(type(customer), customer.id)
            row.expiry = new_expiry
            await session.commit()

    def fake_router_cleanup(_router_info, customers_data):
        asyncio.run_coroutine_threadsafe(_renew(), loop).result(timeout=10)
        return {
            "removed": [{"id": row["id"], "details": {}} for row in customers_data],
            "failed": [],
            "connected": True,
        }

    async def fake_repair(**kwargs):
        repairs.append(kwargs)
        return {"success": True}

    import app.services.hotspot_provisioning as hotspot_provisioning

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", fake_repair)

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry == new_expiry
    assert len(repairs) == 1
    assert repairs[0]["customer_id"] == customer.id
    assert repairs[0]["action"] == "expiry_race_repair"


async def test_cleanup_batches_router_removal_and_leaves_deferred_customers_active(
    db,
    session_factory,
    monkeypatch,
):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    monkeypatch.setattr(mikrotik_background, "EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_RUN", 10)
    monkeypatch.setattr(mikrotik_background, "EXPIRED_ROUTER_CLEANUP_MAX_CUSTOMERS_PER_ROUTER", 2)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customers = []
    for idx in range(4):
        customers.append(
            await make_customer(
                db,
                reseller,
                plan,
                router,
                status=CustomerStatus.ACTIVE,
                expiry=datetime.utcnow() - timedelta(minutes=10 + idx),
                mac_address=f"AA:BB:CC:DD:EE:{idx:02X}",
                phone=f"25470000000{idx}",
            )
        )

    cleanup_calls = []

    def fake_router_cleanup(_router_info, customers_data):
        cleanup_calls.append([c["id"] for c in customers_data])
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(
        mikrotik_background,
        "_cleanup_single_router_hotspot_sync",
        fake_router_cleanup,
    )

    await mikrotik_background.cleanup_expired_users_background()
    for customer in customers:
        await db.refresh(customer)

    attempted_ids = set(cleanup_calls[0])
    assert len(attempted_ids) == 2
    for customer in customers:
        expected = CustomerStatus.INACTIVE if customer.id in attempted_ids else CustomerStatus.ACTIVE
        assert customer.status == expected


async def test_active_customers_endpoint_includes_expired_active_rows(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    expired = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=5),
        mac_address="EA:8D:20:82:2A:83",
    )
    current = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
        mac_address="DA:A1:11:F4:23:50",
    )

    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)

    response = await customer_routes.get_active_customers(db=db, token="token")

    assert [item["id"] for item in response] == [expired.id, current.id]
    assert response[0]["hours_remaining"] == 0

from datetime import datetime, timedelta

import pytest

from app.api import customer_routes
from app.db.models import CustomerStatus
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

"""Per-customer grace period: access is cut at expiry + grace, expiry unchanged."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from app.api import customer_routes
from app.api.radius_hotspot import _is_customer_active
from app.db.models import Customer, CustomerStatus
from app.services import customer_grace, mikrotik_background
from app.services.hotspot_provisioning import build_hotspot_payload
from app.services.usage_push import _customer_is_live
from tests.factories import make_customer, make_plan, make_reseller, make_router




async def _async_zero(*_args, **_kwargs):
    return 0


async def _async_none(*_args, **_kwargs):
    return None


def _patch_cleanup_side_effects(monkeypatch, session_factory):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job_name: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _async_none)


def _record_hotspot_cleanup(monkeypatch):
    calls = []

    def fake_router_cleanup(_router_info, customers_data):
        calls.append([c["id"] for c in customers_data])
        return {"removed": [{"id": c["id"]} for c in customers_data], "failed": [], "connected": True}

    monkeypatch.setattr(
        mikrotik_background, "_cleanup_single_router_hotspot_sync", fake_router_cleanup
    )
    return calls


# --- helpers ---------------------------------------------------------------

def test_effective_expiry_adds_grace():
    expiry = datetime(2026, 10, 1, 12, 0)
    c = Customer(expiry=expiry, grace_period_minutes=120)
    assert customer_grace.effective_expiry(c) == datetime(2026, 10, 1, 14, 0)
    assert customer_grace.is_in_grace(c, datetime(2026, 10, 1, 13, 0))
    assert customer_grace.has_access_time(c, datetime(2026, 10, 1, 13, 59))
    assert not customer_grace.has_access_time(c, datetime(2026, 10, 1, 14, 0))
    assert not customer_grace.is_in_grace(c, datetime(2026, 10, 1, 11, 0))


def test_no_grace_is_plain_expiry():
    expiry = datetime(2026, 10, 1, 12, 0)
    for grace in (None, 0, -5, "junk"):
        c = Customer(expiry=expiry, grace_period_minutes=grace)
        assert customer_grace.effective_expiry(c) == expiry
    assert customer_grace.effective_expiry(Customer(expiry=None, grace_period_minutes=60)) is None


def test_grace_is_capped():
    assert customer_grace.normalize_grace_minutes(10**9) == customer_grace.MAX_GRACE_MINUTES


# --- enforcement -----------------------------------------------------------

async def test_cleanup_keeps_customer_inside_grace(db, session_factory, monkeypatch):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    calls = _record_hotspot_cleanup(monkeypatch)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    paid_expiry = datetime.utcnow() - timedelta(hours=2)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=paid_expiry,
        grace_period_minutes=3 * 60,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry == paid_expiry
    assert calls == []


async def test_cleanup_removes_customer_after_grace(db, session_factory, monkeypatch):
    _patch_cleanup_side_effects(monkeypatch, session_factory)
    calls = _record_hotspot_cleanup(monkeypatch)
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(hours=2),
        grace_period_minutes=60,
    )

    await mikrotik_background.cleanup_expired_users_background()
    await db.refresh(customer)

    assert calls == [[customer.id]]
    assert customer.status == CustomerStatus.INACTIVE


async def test_identityless_customer_in_grace_stays_active(db, session_factory, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    now = datetime.utcnow()
    in_grace = await make_customer(
        db, reseller, plan, None, status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(hours=1), mac_address=None, grace_period_minutes=120,
    )
    in_grace.mac_address = None
    past_grace = await make_customer(
        db, reseller, plan, None, status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(hours=3), mac_address=None, grace_period_minutes=120,
    )
    past_grace.mac_address = None
    await db.commit()

    ids = await mikrotik_background._deactivate_expired_identityless_customers(db, now)

    assert ids == [past_grace.id]


async def test_router_deadline_and_liveness_use_effective_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=now - timedelta(minutes=30), grace_period_minutes=24 * 60,
    )

    payload = build_hotspot_payload(customer, plan, router, "test")

    # The reaper EXP tag and LB_PAID timeout come from this deadline.
    assert payload["customer_expiry"] == customer.expiry + timedelta(days=1)
    assert _customer_is_live(customer, now)
    assert _is_customer_active(customer)


# --- reseller endpoint -----------------------------------------------------

def _as_reseller(monkeypatch, reseller):
    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)


async def test_set_grace_keeps_expiry_and_cascades_to_companions(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    paid_expiry = datetime.utcnow() + timedelta(hours=5)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=paid_expiry,
    )
    companion = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=paid_expiry,
        subscription_owner_id=owner.id,
    )
    _as_reseller(monkeypatch, reseller)
    synced = []
    monkeypatch.setattr(
        "app.services.expiry_tag_sync.schedule_expiry_tag_sync",
        lambda ids, reason: synced.append(sorted(ids)),
    )

    response = await customer_routes.set_customer_grace_period(
        owner.id, customer_routes.CustomerGraceRequest(grace_period_minutes=2 * 24 * 60), db, "token",
    )
    await db.refresh(owner)
    await db.refresh(companion)

    assert response["grace_period_minutes"] == 2 * 24 * 60
    assert response["restored"] is False
    assert response["companions_updated"] == 1
    assert owner.expiry == paid_expiry
    assert owner.grace_period_minutes == companion.grace_period_minutes == 2 * 24 * 60
    assert synced == [sorted([owner.id, companion.id])]


async def test_set_grace_restores_customer_already_cut_off(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    paid_expiry = datetime.utcnow() - timedelta(hours=1)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.INACTIVE, expiry=paid_expiry,
    )
    _as_reseller(monkeypatch, reseller)
    monkeypatch.setattr(
        "app.services.expiry_tag_sync.schedule_expiry_tag_sync", lambda ids, reason: None
    )
    restored = []

    async def fake_restore(customer_id):
        restored.append(customer_id)

    monkeypatch.setattr(customer_routes, "_restore_customer_access", fake_restore)

    response = await customer_routes.set_customer_grace_period(
        customer.id, customer_routes.CustomerGraceRequest(grace_period_minutes=24 * 60), db, "token",
    )
    for task in list(customer_routes._grace_restore_tasks):
        await task
    await db.refresh(customer)

    assert response["restored"] is True
    assert response["in_grace"] is True
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry == paid_expiry
    assert restored == [customer.id]


async def test_short_grace_does_not_restore_long_expired_customer(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(days=3),
    )
    _as_reseller(monkeypatch, reseller)
    monkeypatch.setattr(
        "app.services.expiry_tag_sync.schedule_expiry_tag_sync", lambda ids, reason: None
    )

    response = await customer_routes.set_customer_grace_period(
        customer.id, customer_routes.CustomerGraceRequest(grace_period_minutes=24 * 60), db, "token",
    )
    await db.refresh(customer)

    assert response["restored"] is False
    assert customer.status == CustomerStatus.INACTIVE
    assert customer.grace_period_minutes == 24 * 60


async def test_set_grace_rejects_other_resellers_customer(db, monkeypatch):
    owner_reseller = await make_reseller(db)
    other_reseller = await make_reseller(db)
    plan = await make_plan(db, owner_reseller)
    customer = await make_customer(db, owner_reseller, plan, None)
    _as_reseller(monkeypatch, other_reseller)

    with pytest.raises(HTTPException) as exc:
        await customer_routes.set_customer_grace_period(
            customer.id, customer_routes.CustomerGraceRequest(grace_period_minutes=60), db, "token",
        )
    assert exc.value.status_code == 404


def test_grace_request_bounds():
    with pytest.raises(Exception):
        customer_routes.CustomerGraceRequest(grace_period_minutes=-1)
    with pytest.raises(Exception):
        customer_routes.CustomerGraceRequest(
            grace_period_minutes=customer_grace.MAX_GRACE_MINUTES + 1
        )

"""Tests: a plan can be tied to specific routers.

`plans.router_ids` is an allow-list of routers a plan is offered on. NULL (and
defensively, an empty list) means "every router the owner has" — the behaviour
every plan had before the column existed, so nothing pre-existing changes.

Covers the two things that must not diverge:
  * what the captive portal DISPLAYS for a router, and
  * what the payment endpoints ACCEPT for that router — a filtered dropdown is
    not access control, and a hand-rolled POST must be rejected too.

Also covers emergency mode, which used to hide/show plans across the owner's
whole fleet even though it is switched on per router.
"""

from types import SimpleNamespace

import pytest

from app.services.plan_cache import (
    filter_plans_for_router,
    invalidate_plan_cache,
    normalize_router_ids,
    plan_allows_router,
    plan_model_allows_router,
    select_portal_plans,
)
from app.db.models import PlanType
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Scope normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ([], None),
        ("nonsense", None),
        ({}, None),
        ([3, 1, 2], [3, 1, 2]),
        ([1, 1, 2], [1, 2]),
        (["4", 5], [4, 5]),
        ([None, "x", 7], [7]),
    ],
)
async def test_normalize_router_ids(raw, expected):
    assert normalize_router_ids(raw) == expected


async def test_unscoped_plan_is_offered_everywhere():
    """The default. Every plan that existed before this feature has router_ids NULL."""
    assert plan_allows_router({"router_ids": None}, 1) is True
    assert plan_allows_router({"router_ids": None}, 999) is True


async def test_empty_scope_is_treated_as_all_routers():
    """An empty list must never mean "no routers".

    A plan that silently disappears from every portal stops earning money, so
    the ambiguous value resolves to the safe direction.
    """
    assert plan_allows_router({"router_ids": []}, 1) is True


async def test_scoped_plan_only_matches_listed_routers():
    plan = {"router_ids": [10, 11]}
    assert plan_allows_router(plan, 10) is True
    assert plan_allows_router(plan, 11) is True
    assert plan_allows_router(plan, 12) is False


async def test_filter_plans_for_router_partitions_the_catalogue():
    plans = [
        {"id": 1, "router_ids": None},
        {"id": 2, "router_ids": [10]},
        {"id": 3, "router_ids": [11]},
        {"id": 4, "router_ids": [10, 11]},
    ]
    assert [p["id"] for p in filter_plans_for_router(plans, 10)] == [1, 2, 4]
    assert [p["id"] for p in filter_plans_for_router(plans, 11)] == [1, 3, 4]
    # No router in context (reseller dashboard) → nothing is filtered out.
    assert [p["id"] for p in filter_plans_for_router(plans, None)] == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# Portal read path
# ---------------------------------------------------------------------------

async def test_get_plans_cached_scopes_to_router(db):
    reseller = await make_reseller(db)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)

    everywhere = await make_plan(db, reseller, name="Everywhere", price=100)
    only_a = await make_plan(
        db, reseller, name="Only A", price=200, router_ids=[router_a.id]
    )
    await invalidate_plan_cache()

    from app.services.plan_cache import get_plans_cached

    a_plans = await get_plans_cached(db, reseller.id, router_id=router_a.id)
    b_plans = await get_plans_cached(db, reseller.id, router_id=router_b.id)

    assert {p["id"] for p in a_plans} == {everywhere.id, only_a.id}
    assert {p["id"] for p in b_plans} == {everywhere.id}


async def test_scoping_does_not_multiply_cache_entries(db):
    """Per-router filtering happens after the cache read, on purpose.

    Keying the cache by router would cool it down proportionally to fleet size.
    """
    reseller = await make_reseller(db)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)
    await make_plan(db, reseller, name="Shared", price=100)
    await invalidate_plan_cache()

    from app.services import plan_cache

    calls = {"n": 0}
    original = plan_cache._serialize_plan

    def counting_serialize(plan):
        calls["n"] += 1
        return original(plan)

    plan_cache._serialize_plan = counting_serialize
    try:
        await plan_cache.get_plans_cached(db, reseller.id, router_id=router_a.id)
        first = calls["n"]
        await plan_cache.get_plans_cached(db, reseller.id, router_id=router_b.id)
        assert calls["n"] == first, "second router re-read the DB instead of hitting cache"
    finally:
        plan_cache._serialize_plan = original


# ---------------------------------------------------------------------------
# Emergency mode — per router, not per fleet
# ---------------------------------------------------------------------------

def _plan(pid, plan_type="regular", **extra):
    return {"id": pid, "plan_type": plan_type, "valid_until": None, **extra}


async def test_emergency_router_shows_only_emergency_plans():
    visible = [_plan(1), _plan(2)]
    all_plans = visible + [_plan(9, "emergency", is_hidden=True)]

    chosen = select_portal_plans(visible, all_plans, emergency_active=True)

    assert [p["id"] for p in chosen] == [9]


async def test_non_emergency_router_is_unaffected_by_emergency_plans():
    """The bug this fixes: emergency on one router changed every other router."""
    visible = [_plan(1), _plan(2)]
    all_plans = visible + [_plan(9, "emergency", is_hidden=True)]

    chosen = select_portal_plans(visible, all_plans, emergency_active=False)

    assert [p["id"] for p in chosen] == [1, 2]


async def test_emergency_without_emergency_plans_still_sells():
    """A router must never be left with an empty portal."""
    visible = [_plan(1), _plan(2)]

    chosen = select_portal_plans(visible, visible, emergency_active=True)

    assert [p["id"] for p in chosen] == [1, 2]


async def test_expired_emergency_plan_is_not_offered():
    visible = [_plan(1)]
    all_plans = visible + [
        _plan(9, "emergency", valid_until="2020-01-01T00:00:00"),
    ]

    chosen = select_portal_plans(visible, all_plans, emergency_active=True)

    assert [p["id"] for p in chosen] == [1]


async def test_activating_emergency_does_not_touch_other_routers(db, monkeypatch):
    from app.api import plan_routes

    reseller = await make_reseller(db)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)
    regular = await make_plan(db, reseller, name="Daily", price=50)

    async def fake_current_user(token, db_):
        return reseller

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda user: None)

    await plan_routes.activate_emergency_mode(
        plan_routes.EmergencyActivateRequest(router_id=router_a.id, message="Fibre cut"),
        db=db,
        token="t",
    )

    await db.refresh(router_a)
    await db.refresh(router_b)
    await db.refresh(regular)

    assert router_a.emergency_active is True
    assert router_b.emergency_active is False
    # The old implementation set is_hidden=True here, blanking router B's portal.
    assert regular.is_hidden is False


# ---------------------------------------------------------------------------
# Payment-path enforcement
# ---------------------------------------------------------------------------

async def test_plan_model_allows_router_matches_dict_helper():
    unscoped = SimpleNamespace(router_ids=None)
    scoped = SimpleNamespace(router_ids=[10])

    assert plan_model_allows_router(unscoped, 12) is True
    assert plan_model_allows_router(scoped, 10) is True
    assert plan_model_allows_router(scoped, 12) is False


async def test_hotspot_pay_rejects_plan_scoped_to_another_router(db, monkeypatch):
    """A filtered portal dropdown is not access control."""
    from fastapi import HTTPException

    from app.api import payment_routes

    reseller = await make_reseller(db)
    router_a = await make_router(db, reseller)
    router_b = await make_router(db, reseller)
    plan_a = await make_plan(db, reseller, name="A only", router_ids=[router_a.id])

    request = payment_routes.HotspotPaymentRequest(
        mac_address="AA:BB:CC:DD:EE:FF",
        phone="254700000000",
        plan_id=plan_a.id,
        router_id=router_b.id,
        payment_method="mobile_money",
    )

    with pytest.raises(HTTPException) as exc:
        await payment_routes.register_hotspot_and_pay_api(request, db=db)

    assert exc.value.status_code == 400
    assert "not available on this router" in str(exc.value.detail)


async def test_router_scope_validation_rejects_routers_you_do_not_own(db):
    from fastapi import HTTPException

    from app.api.plan_routes import _validate_router_scope

    owner = await make_reseller(db)
    stranger = await make_reseller(db)
    mine = await make_router(db, owner)
    theirs = await make_router(db, stranger)

    assert await _validate_router_scope(db, owner.id, [mine.id]) == [mine.id]
    assert await _validate_router_scope(db, owner.id, None) is None
    assert await _validate_router_scope(db, owner.id, []) is None

    with pytest.raises(HTTPException) as exc:
        await _validate_router_scope(db, owner.id, [mine.id, theirs.id])
    assert exc.value.status_code == 400

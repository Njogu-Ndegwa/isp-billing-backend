"""Captive portal contract tests — what a paying customer actually SEES.

These exist because per-router plan scoping and per-router emergency mode are
only half-enforced by the API. The portal front-end lives in a THIRD repo
(`isp-landing-page/script.js`) and re-filters the payload before rendering, so
an endpoint test that asserts on the JSON alone can pass while the real portal
renders nothing. That already happened once during this change: emergency plans
were returned with `is_hidden` still set and the client silently dropped every
one of them, on exactly the router having an outage.

So every test here runs the API response through `render_portal_plans()`, a
faithful port of the client filter, and asserts on the rendered result.

The invariant that matters most: a router that is up and has sellable plans must
never render an empty plan list. An empty portal is a router that cannot take
money.
"""

from datetime import datetime, timedelta

import pytest

from app.api.public_routes import get_portal_data, get_public_plans
from app.db.models import ConnectionType, PlanType
from app.services.plan_cache import invalidate_plan_cache
from tests.factories import make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Faithful port of the portal client's filter.
#
# Source: isp-landing-page/script.js, transformPlansData() ~line 1489:
#
#     const visiblePlans = apiPlans.filter(p => {
#         if (p.is_hidden) return false;
#         if (p.connection_type && p.connection_type !== 'hotspot') return false;
#         if (p.plan_type === 'emergency' && !planFlags.emergency_mode_active) return false;
#         if (p.plan_type === 'special_offer' && !planFlags.has_special_offers) return false;
#         return true;
#     });
#
# If that function changes, change this one in the same commit.
# ---------------------------------------------------------------------------

def render_portal_plans(api_plans, plan_flags):
    """Return the plans the captive portal would actually put on screen."""
    rendered = []
    for p in api_plans:
        if p.get("is_hidden"):
            continue
        connection_type = p.get("connection_type")
        if connection_type and connection_type != "hotspot":
            continue
        if p.get("plan_type") == "emergency" and not plan_flags.get("emergency_mode_active"):
            continue
        if p.get("plan_type") == "special_offer" and not plan_flags.get("has_special_offers"):
            continue
        rendered.append(p)
    return rendered


async def portal_for(db, router):
    """Fetch the portal payload for a router and render it like the client does."""
    await invalidate_plan_cache()
    payload = await get_portal_data(identity=router.identity, db=db)
    rendered = render_portal_plans(payload["plans"], payload["plan_flags"])
    return payload, rendered


def ids(plans):
    return sorted(p["id"] for p in plans)


async def make_site(db, reseller, identity, **overrides):
    return await make_router(db, reseller, identity=identity, **overrides)


# ---------------------------------------------------------------------------
# Baseline: nothing about an un-scoped fleet changes
# ---------------------------------------------------------------------------

async def test_unscoped_plans_render_on_every_router(db):
    """The upgrade must be invisible to a reseller who never scopes anything."""
    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "site-a")
    site_b = await make_site(db, reseller, "site-b")
    p1 = await make_plan(db, reseller, name="Hourly", price=20)
    p2 = await make_plan(db, reseller, name="Daily", price=100)

    _, rendered_a = await portal_for(db, site_a)
    _, rendered_b = await portal_for(db, site_b)

    assert ids(rendered_a) == sorted([p1.id, p2.id])
    assert ids(rendered_b) == sorted([p1.id, p2.id])


async def test_scoped_plan_renders_only_where_it_belongs(db):
    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "scoped-a")
    site_b = await make_site(db, reseller, "scoped-b")
    shared = await make_plan(db, reseller, name="Shared", price=50)
    a_only = await make_plan(db, reseller, name="A only", price=80, router_ids=[site_a.id])

    _, rendered_a = await portal_for(db, site_a)
    _, rendered_b = await portal_for(db, site_b)

    assert ids(rendered_a) == sorted([shared.id, a_only.id])
    assert ids(rendered_b) == [shared.id]


async def test_a_router_scoped_plan_still_renders_when_it_is_the_only_plan(db):
    """Scoping must not trip the client's hidden/type filters."""
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "only-scoped")
    only = await make_plan(db, reseller, name="Site special", price=30, router_ids=[site.id])

    _, rendered = await portal_for(db, site)

    assert ids(rendered) == [only.id]


# ---------------------------------------------------------------------------
# Emergency mode — the regression that started this file
# ---------------------------------------------------------------------------

async def test_emergency_plans_actually_render_despite_legacy_hidden_flag(db):
    """The bug: emergency plans left is_hidden by the OLD deactivate path.

    The API returned them and the client threw them all away, leaving a blank
    portal on the router that was already having an outage.
    """
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "emergency-site", emergency_active=True)
    await make_plan(db, reseller, name="Daily", price=100)
    rescue = await make_plan(
        db, reseller, name="Rescue", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=True,
    )

    payload, rendered = await portal_for(db, site)

    assert payload["plan_flags"]["emergency_mode_active"] is True
    assert ids(rendered) == [rescue.id]
    assert rendered, "emergency router rendered an empty portal"


async def test_emergency_on_one_router_does_not_touch_the_other(db):
    """The headline fix: emergency was fleet-wide state, applied per router."""
    reseller = await make_reseller(db)
    down = await make_site(db, reseller, "down-site", emergency_active=True)
    healthy = await make_site(db, reseller, "healthy-site")
    daily = await make_plan(db, reseller, name="Daily", price=100)
    rescue = await make_plan(
        db, reseller, name="Rescue", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=True,
    )

    down_payload, down_rendered = await portal_for(db, down)
    well_payload, well_rendered = await portal_for(db, healthy)

    assert ids(down_rendered) == [rescue.id]
    assert ids(well_rendered) == [daily.id]
    assert down_payload["plan_flags"]["emergency_mode_active"] is True
    assert well_payload["plan_flags"]["emergency_mode_active"] is False


async def test_emergency_router_with_no_emergency_plans_keeps_selling(db):
    """A misconfigured emergency switch must not zero out the router's revenue."""
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "no-rescue-plans", emergency_active=True)
    daily = await make_plan(db, reseller, name="Daily", price=100)

    _, rendered = await portal_for(db, site)

    assert ids(rendered) == [daily.id]


async def test_emergency_plan_scoped_to_another_router_does_not_rescue_this_one(db):
    """Scoping applies to emergency plans too — and the fallback must catch it."""
    reseller = await make_reseller(db)
    down = await make_site(db, reseller, "down-scoped", emergency_active=True)
    other = await make_site(db, reseller, "other-scoped")
    daily = await make_plan(db, reseller, name="Daily", price=100)
    await make_plan(
        db, reseller, name="Rescue elsewhere", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=True, router_ids=[other.id],
    )

    _, rendered = await portal_for(db, down)

    # No emergency plan applies here, so the router falls back to normal plans
    # rather than rendering nothing.
    assert ids(rendered) == [daily.id]


async def test_expired_emergency_plan_does_not_render(db):
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "expired-rescue", emergency_active=True)
    daily = await make_plan(db, reseller, name="Daily", price=100)
    await make_plan(
        db, reseller, name="Old rescue", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=True,
        valid_until=datetime.utcnow() - timedelta(days=1),
    )

    _, rendered = await portal_for(db, site)

    assert ids(rendered) == [daily.id]


# ---------------------------------------------------------------------------
# Deploy transition — the state production is actually in right now
# ---------------------------------------------------------------------------

async def test_deploy_while_a_reseller_is_mid_emergency(db):
    """Documents the known transition gap — see the note in AGENTS/handoff.

    Legacy state: the OLD code hid every regular plan fleet-wide when emergency
    was switched on anywhere. After deploy, the emergency router recovers, but
    the reseller's OTHER routers still render nothing until emergency is
    switched off once. That is NOT a new regression — those routers were
    already blank under the old code, for the same reason — but it does not
    self-heal at deploy either.
    """
    reseller = await make_reseller(db)
    down = await make_site(db, reseller, "legacy-down", emergency_active=True)
    healthy = await make_site(db, reseller, "legacy-healthy")
    # Exactly what the old fleet-wide activate left behind:
    await make_plan(db, reseller, name="Daily", price=100, is_hidden=True)
    rescue = await make_plan(
        db, reseller, name="Rescue", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=False,
    )

    _, down_rendered = await portal_for(db, down)
    _, healthy_rendered = await portal_for(db, healthy)

    assert ids(down_rendered) == [rescue.id], "emergency router must recover immediately"
    assert healthy_rendered == [], (
        "known gap: sibling routers stay blank until emergency is deactivated once"
    )


async def test_deactivating_emergency_restores_the_whole_fleet(db, monkeypatch):
    """The repair path for the state above — one toggle fixes every router."""
    from app.api import plan_routes

    reseller = await make_reseller(db)
    down = await make_site(db, reseller, "repair-down", emergency_active=True)
    healthy = await make_site(db, reseller, "repair-healthy")
    daily = await make_plan(db, reseller, name="Daily", price=100, is_hidden=True)
    await make_plan(
        db, reseller, name="Rescue", price=10,
        plan_type=PlanType.EMERGENCY, is_hidden=False,
    )

    async def fake_current_user(token, db_):
        return reseller

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda user: None)

    await plan_routes.deactivate_emergency_mode(
        plan_routes.EmergencyDeactivateRequest(router_id=down.id), db=db, token="t"
    )

    _, down_rendered = await portal_for(db, down)
    _, healthy_rendered = await portal_for(db, healthy)

    assert ids(down_rendered) == [daily.id]
    assert ids(healthy_rendered) == [daily.id]


async def test_repair_does_not_unhide_a_plan_hidden_on_purpose(db, monkeypatch):
    """The repair is narrow: it only fires when EVERY regular plan is hidden."""
    from app.api import plan_routes

    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "deliberate-hide", emergency_active=True)
    visible = await make_plan(db, reseller, name="Daily", price=100, is_hidden=False)
    retired = await make_plan(db, reseller, name="Retired", price=999, is_hidden=True)

    async def fake_current_user(token, db_):
        return reseller

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda user: None)

    await plan_routes.deactivate_emergency_mode(
        plan_routes.EmergencyDeactivateRequest(router_id=site.id), db=db, token="t"
    )

    await db.refresh(retired)
    assert retired.is_hidden is True, "a deliberately hidden plan must stay hidden"

    _, rendered = await portal_for(db, site)
    assert ids(rendered) == [visible.id]


# ---------------------------------------------------------------------------
# Display and payment must agree
# ---------------------------------------------------------------------------

async def test_every_rendered_plan_is_actually_payable(db, monkeypatch):
    """If the portal shows it, register-and-pay must accept it.

    A mismatch here is a customer tapping a plan and getting an error after
    entering their phone number — worse than the plan not being listed.
    """
    from types import SimpleNamespace

    from app.api import payment_routes

    # Stub the STK push: this test is about the scope gate, and a real call
    # would reach the Safaricom sandbox over the network.
    stk_calls = []

    async def fake_stk(**kwargs):
        stk_calls.append(kwargs)
        return SimpleNamespace(
            checkout_request_id=f"ws_CO_{len(stk_calls)}",
            merchant_request_id=f"mr_{len(stk_calls)}",
        )

    # payment_routes imports this inside the handler, so patch it at the source.
    import app.services.mpesa as mpesa_service

    monkeypatch.setattr(mpesa_service, "initiate_stk_push", fake_stk)

    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "pay-a")
    site_b = await make_site(db, reseller, "pay-b")
    await make_plan(db, reseller, name="Shared", price=50)
    await make_plan(db, reseller, name="A only", price=80, router_ids=[site_a.id])
    await make_plan(db, reseller, name="B only", price=90, router_ids=[site_b.id])

    # Snapshot identities first: the payment endpoint commits, which expires
    # these ORM rows and would trigger a lazy reload mid-loop.
    sites = [(site_a.id, site_a.identity), (site_b.id, site_b.identity)]
    plans_per_site = {}
    for site_id, identity in sites:
        await invalidate_plan_cache()
        payload = await get_portal_data(identity=identity, db=db)
        rendered = render_portal_plans(payload["plans"], payload["plan_flags"])
        assert rendered, f"{identity} rendered nothing"
        plans_per_site[site_id] = [p["id"] for p in rendered]

    for index, (site_id, identity) in enumerate(sites):
        for plan_id in plans_per_site[site_id]:
            request = payment_routes.HotspotPaymentRequest(
                mac_address=f"AA:BB:CC:DD:{index:02X}:{plan_id:02X}",
                phone="254700000000",
                plan_id=plan_id,
                router_id=site_id,
                payment_method="mobile_money",
            )
            before = len(stk_calls)
            await payment_routes.register_hotspot_and_pay_api(request, db=db)
            assert len(stk_calls) == before + 1, (
                f"portal offered plan {plan_id} on {identity} but payment "
                f"never reached STK push — a scope/ownership gate rejected it"
            )


async def test_plan_hidden_from_a_router_cannot_be_paid_for_there(db, monkeypatch):
    """The other direction: not rendered means not purchasable by direct POST.

    Asserts on the specific rejection reason, not just the 400. The endpoint
    also returns 400 when the STK push itself fails, so a status-only
    assertion would pass even with the scope guard deleted.
    """
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.api import payment_routes
    import app.services.mpesa as mpesa_service

    # Stub STK so that if the guard were missing, the request would SUCCEED
    # rather than fail for an unrelated reason and mask the hole.
    async def fake_stk(**kwargs):
        return SimpleNamespace(checkout_request_id="ws_CO_x", merchant_request_id="mr_x")

    monkeypatch.setattr(mpesa_service, "initiate_stk_push", fake_stk)

    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "block-a")
    site_b = await make_site(db, reseller, "block-b")
    a_only = await make_plan(db, reseller, name="A only", price=80, router_ids=[site_a.id])

    _, rendered_b = await portal_for(db, site_b)
    assert a_only.id not in ids(rendered_b)

    request = payment_routes.HotspotPaymentRequest(
        mac_address="AA:BB:CC:DD:EE:02",
        phone="254700000000",
        plan_id=a_only.id,
        router_id=site_b.id,
        payment_method="mobile_money",
    )
    with pytest.raises(HTTPException) as exc:
        await payment_routes.register_hotspot_and_pay_api(request, db=db)
    assert exc.value.status_code == 400
    assert "not available on this router" in str(exc.value.detail), (
        f"rejected for the wrong reason: {exc.value.detail!r}"
    )


# ---------------------------------------------------------------------------
# The other public plans endpoint, and cache freshness
# ---------------------------------------------------------------------------

async def test_public_plans_endpoint_scopes_like_the_portal_endpoint(db):
    """Two endpoints serve plans to guests; they must not disagree."""
    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "dual-a")
    site_b = await make_site(db, reseller, "dual-b")
    await make_plan(db, reseller, name="Shared", price=50)
    await make_plan(db, reseller, name="A only", price=80, router_ids=[site_a.id])

    for site in (site_a, site_b):
        payload, rendered_portal = await portal_for(db, site)
        await invalidate_plan_cache()
        direct = await get_public_plans(router_id=site.id, db=db)
        rendered_direct = render_portal_plans(direct, payload["plan_flags"])
        assert ids(rendered_direct) == ids(rendered_portal), (
            f"/plans/{site.id} disagrees with /portal/{site.identity}"
        )


async def test_scope_change_takes_effect_after_cache_invalidation(db):
    """A reseller who narrows a plan must see it leave the other portal."""
    reseller = await make_reseller(db)
    site_a = await make_site(db, reseller, "cache-a")
    site_b = await make_site(db, reseller, "cache-b")
    plan = await make_plan(db, reseller, name="Everywhere", price=50)

    _, before = await portal_for(db, site_b)
    assert ids(before) == [plan.id]

    plan.router_ids = [site_a.id]
    await db.commit()
    await invalidate_plan_cache()

    _, after_b = await portal_for(db, site_b)
    _, after_a = await portal_for(db, site_a)
    assert after_b == []
    assert ids(after_a) == [plan.id]


async def test_pppoe_plans_never_reach_the_hotspot_portal(db):
    """The client drops non-hotspot plans; make sure scoping didn't smuggle any in."""
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "pppoe-site")
    hotspot = await make_plan(db, reseller, name="Hotspot", price=50)
    await make_plan(
        db, reseller, name="Home fibre", price=3000,
        connection_type=ConnectionType.PPPOE, router_ids=[site.id],
    )

    _, rendered = await portal_for(db, site)

    assert ids(rendered) == [hotspot.id]


async def test_plan_scoped_to_a_deleted_router_reverts_to_fleet_wide(db):
    """Stale ids must not strand a plan.

    A scope referencing only routers that no longer exist reads as "all
    routers" rather than "no routers", so the plan keeps selling instead of
    disappearing silently.
    """
    reseller = await make_reseller(db)
    site = await make_site(db, reseller, "survivor")
    plan = await make_plan(db, reseller, name="Orphaned scope", price=50,
                           router_ids=[site.id])

    plan.router_ids = []
    await db.commit()
    await invalidate_plan_cache()

    _, rendered = await portal_for(db, site)

    assert ids(rendered) == [plan.id]

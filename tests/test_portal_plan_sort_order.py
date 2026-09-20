"""Portal package ordering — `portal_settings.plan_sort_order`.

A reseller asked for the opposite of what the portal has always done: list the
smallest package first, not the most expensive. The order is a per-reseller
setting, and it is applied in TWO places that must agree:

  * here, on `GET /api/public/portal/{identity}` and `GET /api/public/plans/{id}`
  * in the portal client (`isp-frontend/script.js`, `transformPlansData()`)

The client is the one that decides what a customer actually sees, so the
integration tests below run the API payload through `client_order()` — a port of
the client's comparator — and assert on that, the same contract style as
`tests/test_captive_portal_contract.py`.

Default stays `default`: the legacy merchandised order (featured/bestseller
pinned, then price high->low). A deploy must not re-order anybody's portal.
"""

import pytest  # noqa: F401  (pytest.ini asyncio_mode=auto)

from app.api.public_routes import get_portal_data, get_public_plans
from app.db.models import DurationUnit, PlanType, PortalSettings
from app.services.plan_cache import (
    DEFAULT_PLAN_SORT_ORDER,
    VALID_PLAN_SORT_ORDERS,
    plan_duration_minutes,
    invalidate_plan_cache,
    sort_portal_plans,
)
from tests.factories import make_plan, make_reseller, make_router

# asyncio_mode = auto (pytest.ini) — the async tests below need no marker, and a
# module-level one would warn on every sync test in this file.


# ---------------------------------------------------------------------------
# Port of the portal client's sort.
#
# Source: isp-frontend/script.js, transformPlansData():
#
#     const typeOrder = { special_offer: 0, emergency: 1 };
#     transformedPlans.sort((a, b) => {
#         ... type group, then bestseller, then popular ...
#         return applySortOrder(a, b);   // price desc under 'default'
#     });
#
# If that comparator changes, change this one in the same commit.
# ---------------------------------------------------------------------------

_TYPE_ORDER = {"special_offer": 0, "emergency": 1}


def client_order(plans, sort_order):
    """Return the plans in the order the portal client would render them."""
    type_rank = lambda p: _TYPE_ORDER.get(p.get("plan_type") or "regular", 2)

    if sort_order in ("price_asc", "price_desc"):
        key, reverse = (lambda p: float(p["price"])), sort_order == "price_desc"
    elif sort_order in ("duration_asc", "duration_desc"):
        key, reverse = plan_duration_minutes, sort_order == "duration_desc"
    else:  # 'default' — legacy merchandised order
        key, reverse = (lambda p: float(p["price"])), True

    by_id = sorted(plans, key=lambda p: p["id"])
    within = sorted(by_id, key=key, reverse=reverse)
    return sorted(within, key=type_rank)


async def set_sort_order(db, reseller, order):
    db.add(PortalSettings(user_id=reseller.id, plan_sort_order=order))
    await db.commit()


async def portal_plans(db, router):
    await invalidate_plan_cache()
    payload = await get_portal_data(identity=router.identity, db=db)
    return payload["plans"], payload["portal_settings"]


def prices(plans):
    return [p["price"] for p in plans]


# ---------------------------------------------------------------------------
# sort_portal_plans — the helper both endpoints call
# ---------------------------------------------------------------------------

def _p(plan_id, price, value=1, unit="DAYS"):
    return {
        "id": plan_id,
        "price": price,
        "duration_value": value,
        "duration_unit": unit,
    }


def test_default_order_is_left_untouched():
    """'default' means "the client decides" — don't reshuffle behind its back."""
    plans = [_p(1, 100), _p(2, 20), _p(3, 50)]
    assert [p["id"] for p in sort_portal_plans(plans, "default")] == [1, 2, 3]
    assert [p["id"] for p in sort_portal_plans(plans, None)] == [1, 2, 3]


def test_price_ascending_lists_the_smallest_package_first():
    plans = [_p(1, 100), _p(2, 20), _p(3, 50)]
    assert prices(sort_portal_plans(plans, "price_asc")) == [20, 50, 100]


def test_price_descending():
    plans = [_p(1, 100), _p(2, 20), _p(3, 50)]
    assert prices(sort_portal_plans(plans, "price_desc")) == [100, 50, 20]


def test_duration_sorts_across_units_not_by_raw_number():
    """180 MINUTES is shorter than 1 DAYS, even though 180 > 1."""
    plans = [_p(1, 100, 1, "DAYS"), _p(2, 30, 180, "MINUTES"), _p(3, 20, 2, "HOURS")]
    ordered = sort_portal_plans(plans, "duration_asc")
    assert [p["id"] for p in ordered] == [3, 2, 1]
    assert [p["id"] for p in sort_portal_plans(plans, "duration_desc")] == [1, 2, 3]


def test_equal_values_keep_a_stable_order_in_both_directions():
    """Two packages at the same price must not swap places between page loads."""
    plans = [_p(3, 50), _p(1, 50), _p(2, 50)]
    assert [p["id"] for p in sort_portal_plans(plans, "price_asc")] == [1, 2, 3]
    assert [p["id"] for p in sort_portal_plans(plans, "price_desc")] == [1, 2, 3]


def test_unknown_sort_order_falls_back_to_default_instead_of_raising():
    plans = [_p(1, 100), _p(2, 20)]
    assert [p["id"] for p in sort_portal_plans(plans, "by_vibes")] == [1, 2]


def test_input_list_is_never_mutated():
    """The list may be a cached object shared with other requests."""
    plans = [_p(1, 100), _p(2, 20)]
    sort_portal_plans(plans, "price_asc")
    assert [p["id"] for p in plans] == [1, 2]


def test_default_is_a_valid_choice():
    assert DEFAULT_PLAN_SORT_ORDER in VALID_PLAN_SORT_ORDERS


# ---------------------------------------------------------------------------
# The invariant that matters most: sorting must never LOSE a package.
#
# An empty portal is a router that cannot take money. Re-ordering is cosmetic;
# dropping a plan is an outage, so every order is checked against the input set.
# ---------------------------------------------------------------------------

def test_no_sort_order_ever_adds_drops_or_duplicates_a_package():
    plans = [
        _p(1, 100, 1, "DAYS"),
        _p(2, 20, 3, "HOURS"),
        _p(3, 50, 1, "WEEKS"),
        _p(4, 20, 30, "MINUTES"),
    ]
    expected = sorted(p["id"] for p in plans)
    for order in VALID_PLAN_SORT_ORDERS:
        got = sort_portal_plans(plans, order)
        assert sorted(p["id"] for p in got) == expected, order
        assert len(got) == len(plans), order


def test_a_plan_missing_price_or_duration_is_kept_not_dropped():
    """Bad data must sort somewhere sane, never vanish from the grid."""
    plans = [_p(1, 100), {"id": 2}, {"id": 3, "price": None, "duration_value": None}]
    for order in VALID_PLAN_SORT_ORDERS:
        assert sorted(p["id"] for p in sort_portal_plans(plans, order)) == [1, 2, 3], order


def test_sorting_an_empty_list_stays_empty_instead_of_raising():
    for order in VALID_PLAN_SORT_ORDERS:
        assert sort_portal_plans([], order) == []


def test_special_offers_lead_whatever_the_chosen_order():
    """The portal renders them as their own group, so the payload must agree."""
    plans = [
        {**_p(1, 500), "plan_type": "regular"},
        {**_p(2, 10), "plan_type": "special_offer"},
        {**_p(3, 20), "plan_type": "regular"},
    ]
    assert [p["id"] for p in sort_portal_plans(plans, "price_desc")] == [2, 1, 3]
    assert [p["id"] for p in sort_portal_plans(plans, "price_asc")] == [2, 3, 1]


# ---------------------------------------------------------------------------
# What the customer actually sees
# ---------------------------------------------------------------------------

async def test_portal_lists_smallest_package_first_when_asked(db):
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-asc")
    await set_sort_order(db, reseller, "price_asc")
    await make_plan(db, reseller, name="Weekly", price=200, duration_value=7)
    await make_plan(db, reseller, name="Hourly", price=10, duration_value=1,
                    duration_unit=DurationUnit.HOURS)
    await make_plan(db, reseller, name="Daily", price=50, duration_value=1)

    plans, settings = await portal_plans(db, site)

    assert settings["plan_sort_order"] == "price_asc"
    assert prices(plans) == [10, 50, 200]
    assert prices(client_order(plans, "price_asc")) == [10, 50, 200]


async def test_reseller_who_never_touched_the_setting_keeps_the_old_order(db):
    """No portal_settings row at all — the portal must behave exactly as before."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-none")
    await make_plan(db, reseller, name="Weekly", price=200, duration_value=7)
    await make_plan(db, reseller, name="Hourly", price=10, duration_value=1,
                    duration_unit=DurationUnit.HOURS)

    plans, settings = await portal_plans(db, site)

    assert settings["plan_sort_order"] == DEFAULT_PLAN_SORT_ORDER
    assert prices(client_order(plans, DEFAULT_PLAN_SORT_ORDER)) == [200, 10]


async def test_shortest_package_first_uses_real_duration(db):
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-duration")
    await set_sort_order(db, reseller, "duration_asc")
    await make_plan(db, reseller, name="Daily", price=50, duration_value=1)
    await make_plan(db, reseller, name="3 Hours", price=20, duration_value=180,
                    duration_unit=DurationUnit.MINUTES)

    plans, _ = await portal_plans(db, site)

    assert [p["name"] for p in plans] == ["3 Hours", "Daily"]


async def test_standalone_plans_endpoint_uses_the_same_order(db):
    """The portal falls back to /api/public/plans/{id} on a reload."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-fallback")
    await set_sort_order(db, reseller, "price_asc")
    await make_plan(db, reseller, name="Weekly", price=200, duration_value=7)
    await make_plan(db, reseller, name="Hourly", price=10, duration_value=1,
                    duration_unit=DurationUnit.HOURS)

    await invalidate_plan_cache()
    plans = await get_public_plans(router_id=site.id, db=db)

    assert prices(plans) == [10, 200]


async def test_one_resellers_order_does_not_leak_into_anothers_portal(db):
    """Plans are cached per owner — the sort must not ride the cache."""
    asc_reseller = await make_reseller(db)
    asc_site = await make_router(db, asc_reseller, identity="tenant-asc")
    await set_sort_order(db, asc_reseller, "price_asc")
    await make_plan(db, asc_reseller, name="Big", price=200, duration_value=7)
    await make_plan(db, asc_reseller, name="Small", price=10, duration_value=1)

    plain_reseller = await make_reseller(db)
    plain_site = await make_router(db, plain_reseller, identity="tenant-default")
    await make_plan(db, plain_reseller, name="Big", price=200, duration_value=7)
    await make_plan(db, plain_reseller, name="Small", price=10, duration_value=1)

    asc_plans, _ = await portal_plans(db, asc_site)
    plain_plans, plain_settings = await portal_plans(db, plain_site)

    assert prices(asc_plans) == [10, 200]
    assert plain_settings["plan_sort_order"] == DEFAULT_PLAN_SORT_ORDER
    assert prices(client_order(plain_plans, DEFAULT_PLAN_SORT_ORDER)) == [200, 10]


async def test_emergency_mode_still_renders_its_plans_under_a_custom_sort(db):
    """The regression this contract file exists for, re-checked with sorting on.

    Emergency plans are conventionally left is_hidden; the portal drops hidden
    plans client-side. Sorting must not reintroduce an empty portal on exactly
    the router having an outage.
    """
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-emergency", emergency_active=True)
    await set_sort_order(db, reseller, "price_asc")
    await make_plan(db, reseller, name="Daily", price=100, duration_value=1)
    await make_plan(db, reseller, name="Rescue Big", price=30, duration_value=1,
                    plan_type=PlanType.EMERGENCY, is_hidden=True)
    await make_plan(db, reseller, name="Rescue Small", price=10, duration_value=1,
                    plan_type=PlanType.EMERGENCY, is_hidden=True)

    plans, _ = await portal_plans(db, site)
    rendered = [p for p in plans if not p["is_hidden"]]

    assert len(rendered) == 2, "emergency portal must not render empty"
    assert prices(rendered) == [10, 30]


async def test_a_sorted_portal_never_comes_back_empty(db):
    """Whatever the setting, a router with sellable plans must list them."""
    for order in sorted(VALID_PLAN_SORT_ORDERS):
        reseller = await make_reseller(db)
        site = await make_router(db, reseller, identity=f"nonempty-{order}")
        await set_sort_order(db, reseller, order)
        await make_plan(db, reseller, name="A", price=50, duration_value=1)
        await make_plan(db, reseller, name="B", price=150, duration_value=7)

        plans, _ = await portal_plans(db, site)

        assert len(plans) == 2, f"{order} rendered {len(plans)} plans"


async def test_a_legacy_row_with_a_null_sort_order_behaves_as_default(db):
    """Belt and braces: the migration backfills 'default', but a NULL must be safe."""
    reseller = await make_reseller(db)
    site = await make_router(db, reseller, identity="sort-null")
    settings = PortalSettings(user_id=reseller.id)
    settings.plan_sort_order = None
    db.add(settings)
    await db.commit()
    await make_plan(db, reseller, name="Weekly", price=200, duration_value=7)
    await make_plan(db, reseller, name="Hourly", price=10, duration_value=1,
                    duration_unit=DurationUnit.HOURS)

    plans, portal_settings = await portal_plans(db, site)

    assert portal_settings["plan_sort_order"] == DEFAULT_PLAN_SORT_ORDER
    assert len(plans) == 2

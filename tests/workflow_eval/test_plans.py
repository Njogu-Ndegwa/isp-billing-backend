"""Workflow evals: plans and pricing (real model, opt-in).

Each scenario is an account in a given state, one reseller message, and checks on what a
GOOD answer must contain. Any reasonable correct path passes (a check names the outcome,
not the exact wording).
"""
from datetime import datetime, timedelta, timezone

import pytest

from tests.assistant_eval_kit import (
    KEY, any_of, ask, build, card_for, customer, evaluate, plan, prefilled, report, says, shows, use_real_model,
)
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

PLAN_FORM = "/api/plans/create"


# -- small local checks -----------------------------------------------------------------

def _values(row, method=None, path_part=""):
    """Form values (prefilled) merged with the raw body, for cards matching method/path."""
    out = {}
    for c in row["cards"]:
        if (method is None or c["method"] == method) and path_part in c["path"]:
            if isinstance(c.get("body"), dict):
                out.update(c["body"])
            out.update(c["prefilled"])
    return out


def value_in(key, accepted, method=None, path_part=""):
    """The card's value for key is one of accepted (compared as lower-case strings)."""
    def check(row):
        got = _values(row, method, path_part).get(key)
        ok = got is not None and str(got).lower() in {str(a).lower() for a in accepted}
        return None if ok else f"{key}={got!r}, wanted one of {list(accepted)}"
    return check


def router_ids_only(wanted_id, other_ids):
    def check(row):
        got = _values(row, None, "/api/plans").get("router_ids")
        ids = {str(i) for i in (got or [])} if isinstance(got, (list, tuple)) else {str(got)} if got else set()
        if str(wanted_id) not in ids or ids & {str(i) for i in other_ids}:
            return f"router_ids={got!r}, wanted only [{wanted_id}]"
        return None
    return check


def no_card_of(method, path_part=""):
    def check(row):
        bad = [c["path"] for c in row["cards"] if c["method"] == method and path_part in c["path"]]
        return None if not bad else f"should not propose {method} {bad}"
    return check


def run(scenario, row, checks):
    problems = evaluate(row, checks)
    report(scenario, row, problems)
    assert not problems, problems


# -- creating plans: the form shows only what applies -----------------------------------

@pytest.mark.asyncio
async def test_create_pppoe_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Create a PPPoE plan called Home 10M, 10 Mbps, 2500 bob per month", monkeypatch)
    run("plans/create-pppoe", row, [
        card_for("POST", PLAN_FORM),
        prefilled(connection_type="pppoe", price=2500),
        shows("name", "speed", "price", never=("trial_once", "fup_")),
    ])


@pytest.mark.asyncio
async def test_create_static_ip_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Home 10M", 2500, days=30, kind="pppoe")])
    use_real_model(monkeypatch)
    row = await ask(client, token, "I want a static IP plan for businesses: Biashara 20M, 5000 KES monthly", monkeypatch)
    run("plans/create-static-ip", row, [
        card_for("POST", PLAN_FORM),
        prefilled(connection_type="static_ip", price=5000),
        shows("name", "price", never=("max_shared_users", "trial_once", "fup_")),
    ])


@pytest.mark.asyncio
async def test_create_free_trial(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Weka free trial ya dakika 30 kwa hotspot, kila simu ipate mara moja tu", monkeypatch)
    run("plans/create-free-trial", row, [
        card_for("POST", PLAN_FORM),
        prefilled(plan_type="free_trial", connection_type="hotspot", price=0),
        shows("trial_once_per_customer", never=("original_price",)),
    ])


@pytest.mark.asyncio
async def test_create_capped_fup_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Create a weekly hotspot plan for 300 with a 10GB cap; after the 10GB slow them down to 1Mbps",
                    monkeypatch)
    run("plans/create-fup-capped", row, [
        card_for("POST", PLAN_FORM),
        value_in("data_cap_mb", [10240, 10000]),
        prefilled(fup_action="throttle", price=300),
        shows("data_cap_mb", "fup_action", "fup_throttle_profile"),
    ])


# -- prerequisites and router scope -------------------------------------------------------

@pytest.mark.asyncio
async def test_create_plan_with_no_router_yet(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller)  # brand-new account: no router, no plans
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nataka kuongeza plan ya hotspot ya 20 bob, masaa mawili", monkeypatch)
    # Good: open the plan form (a plan needs no router to exist) AND say a router must be
    # connected before customers can buy it, or do the router step first. Either way: router.
    run("plans/no-router-yet", row, [
        says("router"),
        any_of(card_for("POST", PLAN_FORM), says("setup", "connect", "unganisha", any_=True)),
    ])


@pytest.mark.asyncio
async def test_new_plan_only_for_one_router(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower", "Kahawa"], plans=[plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Create a hotspot plan Daily 30, 30 bob for 1 day, 3M speed. This plan only for Kahawa",
                    monkeypatch)
    run("plans/new-plan-only-kahawa", row, [
        card_for("POST", PLAN_FORM),
        router_ids_only(made["routers"]["Kahawa"].id, [made["routers"]["Main Tower"].id]),
        shows("max_shared_users", never=("trial_once", "fup_")),
    ])


# -- changing plans customers are on ------------------------------------------------------

@pytest.mark.asyncio
async def test_price_change_on_plan_with_customers_warns(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7)],
                       customers=[customer("Amina", "254711000001", "Weekly 300", hours_left=50),
                                  customer("Brian", "254711000002", "Weekly 300", hours_left=100),
                                  customer("Chero", "254711000003", "Weekly 300", hours_left=20)])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Change the Weekly 300 price to 350", monkeypatch)
    run("plans/price-change-warns", row, [
        card_for("PUT", f"/api/plans/{made['plans']['Weekly 300'].id}"),
        prefilled(price=350),
        says("customer", "wateja", "active", any_=True),
    ])


@pytest.mark.asyncio
async def test_duplicate_plan_with_other_price(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("Home 10M", 2000, days=30, kind="pppoe", speed="10M/10M"), plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Duplicate Home 10M as 'Home 10M Promo' but at 1800, keep everything else the same", monkeypatch)
    run("plans/duplicate-other-price", row, [
        card_for("POST", PLAN_FORM),
        prefilled(price=1800, connection_type="pppoe", speed="10M/10M", duration_value=30),
        no_card_of("PUT", "/api/plans/"),
    ])


@pytest.mark.asyncio
async def test_hide_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7)],
                       customers=[customer("Amina", "254711000001", "Weekly 300", hours_left=50)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Ficha Weekly 300 kwa portal, sitaki wateja wapya waione lakini wale wako nayo waendelee",
                    monkeypatch)
    run("plans/hide-plan", row, [
        card_for("PUT", f"/api/plans/{made['plans']['Weekly 300'].id}"),
        value_in("is_hidden", [True], "PUT", "/api/plans/"),
        no_card_of("DELETE"),
    ])


@pytest.mark.asyncio
async def test_reorder_plans_on_portal(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("Monthly 1500", 1500, days=30), plan("Weekly 300", 300, days=7), plan("Daily 50", 50)])
    use_real_model(monkeypatch)
    row = await ask(client, token, "On my login page I want the cheapest plans to show first", monkeypatch)
    run("plans/reorder-portal", row, [
        card_for("PUT", "/api/portal/settings"),
        prefilled(plan_sort_order="price_asc"),
    ])


@pytest.mark.asyncio
async def test_delete_plan_with_active_customers(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"],
                plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7)],
                customers=[customer("Amina", "254711000001", "Weekly 300", hours_left=50),
                           customer("Brian", "254711000002", "Weekly 300", hours_left=100)])
    use_real_model(monkeypatch)
    row = await ask(client, token, "Delete the Weekly 300 plan, I don't want it anymore", monkeypatch)
    # The API refuses to delete a plan with active customers; a good answer says so and offers hiding.
    run("plans/delete-with-customers", row, [
        says("customer", "wateja", "active", any_=True),
        any_of(says("hide", "hidden", "ficha", any_=True), value_in("is_hidden", [True], "PUT", "/api/plans/")),
        no_card_of("DELETE", "/api/plans/"),
    ])


# -- offers --------------------------------------------------------------------------------

def _next_sunday_dates():
    """Sunday in Kenya, and the Monday after (end of Sunday as midnight is fine too)."""
    today = datetime.now(timezone(timedelta(hours=3))).date()
    sunday = today + timedelta(days=(6 - today.weekday()) % 7)
    return sunday.isoformat(), (sunday + timedelta(days=1)).isoformat()


def offer_ok(regular_plan_id):
    """A special plan at 250 ("was 300") that ends on Sunday; the regular plan is not given an end date,
    since valid_until removes a plan from sale for good once it passes."""
    def check(row):
        put = _values(row, "PUT", f"/api/plans/{regular_plan_id}")
        if put.get("valid_until"):
            return f"set valid_until={put['valid_until']!r} on the regular plan: it would vanish after Sunday"
        new = _values(row, "POST", PLAN_FORM)
        if not new:
            return f"wanted a new special-offer plan, got {[c['method'] + ' ' + c['path'] for c in row['cards']]}"
        problems = []
        if str(new.get("price")) != "250":
            problems.append(f"price={new.get('price')!r}")
        if str(new.get("original_price")) != "300":
            problems.append(f"original_price={new.get('original_price')!r}")
        if not any(d in str(new.get("valid_until") or "") for d in _next_sunday_dates()):
            problems.append(f"valid_until={new.get('valid_until')!r} (wanted {_next_sunday_dates()[0]})")
        return ("offer card wrong: " + ", ".join(problems)) if problems else None
    return check


@pytest.mark.asyncio
async def test_weekend_special_offer(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Daily 50", 50), plan("Weekly 300", 300, days=7)])
    use_real_model(monkeypatch)
    row = await ask(client, token,
                    "Weekend special: Weekly 300 was 300, now 250 till Sunday. Iweke kwa portal", monkeypatch)
    run("plans/weekend-special", row, [offer_ok(made["plans"]["Weekly 300"].id)])

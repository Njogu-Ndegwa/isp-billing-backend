"""PPPoE and static-IP customers, end to end: registering them on the right kind of plan,
noticing what the account lacks first, and the steps after registration (activate after a
cash payment, share the login, change plan, extend, cut off a non-payer, move router,
new password). A reseller in Kenya writes in English or Kiswahili.

Each check states what a good answer must contain; any reasonable correct path passes.
"""
from datetime import datetime, timedelta

import pytest

from tests.assistant_eval_kit import (KEY, any_of, ask, build, card_for, customer, evaluate, no_card,
                                      picker_only, plan, prefilled, report, says, shows, use_real_model)
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

HOTSPOT = [plan("Daily 50", 50), plan("Weekly 300", 300, days=7)]
HOME_10 = plan("Home 10M", 2000, days=30, kind="pppoe", speed="10M/10M")
HOME_20 = plan("Home 20M", 3000, days=30, kind="pppoe", speed="20M/20M")
BIZ_10 = plan("Biz Static 10M", 4000, days=30, kind="static_ip", speed="10M/10M")
BIZ_20 = plan("Biz Static 20M", 6000, days=30, kind="static_ip", speed="20M/20M")


# -- small local checks ----------------------------------------------------------------

def all_of(*checks):
    def check(row):
        bad = [p for p in (c(row) for c in checks) if p]
        return " & ".join(bad) if bad else None
    return check


def no_card_for(path_part):
    def check(row):
        bad = [c["method"] + " " + c["path"] for c in row["cards"] if path_part in c["path"]]
        return f"should not propose {bad}" if bad else None
    return check


def picker_never(field_name, forbidden):
    """If the form has a picker for field_name, it offers none of these (no picker is fine)."""
    def check(row):
        for c in row["cards"]:
            opts = c["pickers"].get(field_name) or []
            wrong = [o for o in opts if any(f.lower() in o.lower() for f in forbidden)]
            if wrong:
                return f"{field_name} picker offers {opts}, should not offer {wrong}"
        return None
    return check


def value_of(row, key, path_part=""):
    for c in row["cards"]:
        if path_part not in c["path"]:
            continue
        if key in c["prefilled"]:
            return c["prefilled"][key]
        if isinstance(c.get("body"), dict) and key in c["body"]:
            return c["body"][key]
    return None


def cash_or_default(row):
    v = value_of(row, "payment_method", "activate-pppoe")
    return None if v in (None, "", "cash") else f"activation records payment_method={v!r}, wanted cash"


def expiry_near(days_from_now, path_part="/api/customers/"):
    def check(row):
        v = value_of(row, "expiry", path_part)
        if not v:
            return "no expiry on the edit"
        try:
            got = datetime.fromisoformat(str(v).replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return f"expiry {v!r} is not a date"
        want = datetime.utcnow() + timedelta(days=days_from_now)
        return None if abs((got - want).total_seconds()) < 36 * 3600 else f"expiry {v} (wanted about {want:%Y-%m-%d %H:%M})"
    return check


def asks_which(*names):
    """Asked which record is meant: no card, and every candidate named."""
    return all_of(no_card, says(*names))


async def run(scenario, client, token, monkeypatch, question, checks, conversation_id=None):
    row = await ask(client, token, question, monkeypatch, conversation_id)
    problems = evaluate(row, checks)
    report(scenario, row, problems)
    return row, problems


# -- registering: account state decides the right move ------------------------------

@pytest.mark.asyncio
async def test_register_pppoe_exactly_one_pppoe_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[*HOTSPOT, plan("Home 5M", 1500, days=30, kind="pppoe")])
    use_real_model(monkeypatch)
    _, problems = await run("register/one-pppoe-plan", client, token, monkeypatch,
                            "Add a PPPoE client Grace Wanjiku 0733444555 on Main Tower", [
        card_for("POST", "/api/customers/register"),
        # only one plan fits: pick it (and the PPPoE fields show), or offer only it
        any_of(all_of(prefilled(plan_id="Home 5M"), shows("pppoe_username", never=("mac_address", "static_ip"))),
               picker_only("plan_id", ["Home 5M"], forbidden=["Daily 50", "Weekly 300"])),
        prefilled(router_id="Main Tower"),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_register_pppoe_without_pppoe_plan_offers_plan_first(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=HOTSPOT)
    use_real_model(monkeypatch)
    _, problems = await run("register/no-pppoe-plan", client, token, monkeypatch,
                            "Nataka kusajili mteja wa PPPoE, James Mwangi 0711222333", [
        no_card_for("/api/customers/register"),     # never on a hotspot plan
        card_for("POST", "/api/plans/create"),
        prefilled(connection_type="pppoe"),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_register_pppoe_without_router(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, plans=[HOME_10])
    use_real_model(monkeypatch)
    _, problems = await run("register/no-router", client, token, monkeypatch,
                            "Register PPPoE customer Mary Achieng 0700111222 on Home 10M", [
        no_card_for("/api/customers/register"),
        says("router"),
        any_of(card_for("POST", "/api/provision"), says("setup", "command", "winbox", any_=True)),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_register_static_ip_customer(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[*HOTSPOT, HOME_10, BIZ_10, BIZ_20])
    use_real_model(monkeypatch)
    _, problems = await run("register/static-ip", client, token, monkeypatch,
                            "Register a static IP customer Acme Hardware 0799000111, give them IP 192.168.88.50", [
        card_for("POST", "/api/customers/register"),
        any_of(picker_only("plan_id", ["Biz Static 10M", "Biz Static 20M"], forbidden=["Daily", "Weekly", "Home"]),
               prefilled(plan_id="Biz Static")),
        picker_never("plan_id", ["Daily", "Weekly", "Home"]),
        prefilled(static_ip="192.168.88.50"),
    ])
    assert not problems, problems


# -- after registration: the next steps ----------------------------------------------

@pytest.mark.asyncio
async def test_activate_pppoe_after_cash(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[*HOTSPOT, HOME_10],
                customers=[customer("John Kamau", "254712345678", "Home 10M", hours_left=None, status="inactive",
                                    pppoe_username="john.kamau")])
    use_real_model(monkeypatch)
    _, problems = await run("next/activate-after-cash", client, token, monkeypatch,
                            "John Kamau amenilipa 2000 cash leo, muwashe", [
        card_for("POST", "/activate-pppoe"),
        cash_or_default,
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_share_login_then_new_password(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[HOME_10],
                customers=[customer("Peter Otieno", "254722111222", "Home 10M", hours_left=200,
                                    pppoe_username="otieno01", pppoe_password="s3cretPw77")])
    use_real_model(monkeypatch)
    row, p1 = await run("next/share-login", client, token, monkeypatch,
                        "Peter Otieno anataka login yake ya PPPoE, nimtumie aje?", [
        says("otieno01"),
        lambda r: None if "s3cretPw77" not in r["said"] else "repeated the password in chat",
        # how he gets the password: the customer page, an SMS, or a new one
        says("/customers/", "sms", "password", "nenosiri", any_=True),
    ])
    _, p2 = await run("next/new-pppoe-password", client, token, monkeypatch,
                      "Ameisahau password, mbadilishie mpya", [
        any_of(card_for("POST", "/regenerate-pppoe-password"),
               all_of(card_for("PUT", "/api/customers/"), shows("pppoe_password"))),
        lambda r: None if "s3cretPw77" not in r["said"] else "repeated the old password in chat",
    ], conversation_id=row["conversation_id"])
    assert not (p1 or p2), p1 + p2


@pytest.mark.asyncio
async def test_change_pppoe_plan(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[*HOTSPOT, HOME_10, HOME_20, BIZ_10],
                customers=[customer("Peter Otieno", "254722111222", "Home 10M", hours_left=200,
                                    pppoe_username="otieno01")])
    use_real_model(monkeypatch)
    _, problems = await run("next/change-plan", client, token, monkeypatch,
                            "Upgrade Peter Otieno to the 20 Mbps package", [
        card_for("PUT", "/api/customers/"),
        prefilled(plan_id="Home 20M"),
        picker_never("plan_id", ["Daily", "Weekly", "Biz Static"]),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_extend_pppoe_free_days(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[HOME_10],
                customers=[customer("Peter Otieno", "254722111222", "Home 10M", hours_left=48,
                                    pppoe_username="otieno01")])
    use_real_model(monkeypatch)
    _, problems = await run("next/extend-7-days", client, token, monkeypatch,
                            "Mwongezee Peter Otieno siku 7 bure, alikosa internet wiki iliyopita", [
        no_card_for("/activate-pppoe"),          # a free week is not a 30-day paid renewal
        card_for("PUT", "/api/customers/"),
        expiry_near(2 + 7),                      # 2 days left + 7
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_cut_off_pppoe_non_payer(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[HOME_10],
                customers=[customer("Faith Njeri", "254733555666", "Home 10M", hours_left=20,
                                    pppoe_username="faith.n")])
    use_real_model(monkeypatch)
    _, problems = await run("next/suspend-non-payer", client, token, monkeypatch,
                            "Faith Njeri hajalipa, mkatie internet sasa hivi", [
        card_for("POST", "/deactivate-pppoe"),
    ])
    assert not problems, problems


@pytest.mark.asyncio
async def test_move_pppoe_customer_to_other_router(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower", "Kahawa AP"], plans=[HOME_10],
                customers=[customer("Peter Otieno", "254722111222", "Home 10M", router="Main Tower",
                                    hours_left=200, pppoe_username="otieno01")])
    use_real_model(monkeypatch)
    _, problems = await run("next/move-router", client, token, monkeypatch,
                            "Move Peter Otieno to the Kahawa AP router", [
        # the edit moves his secret to the new router; the router transfer moves EVERY PPPoE customer
        card_for("PUT", "/api/customers/"),
        prefilled(router_id="Kahawa"),
        no_card_for("/pppoe-customers/transfer"),
    ])
    assert not problems, problems


# -- ambiguity --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_peters_asks_which(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[HOME_10],
                customers=[customer("Peter Otieno", "254722111222", "Home 10M", hours_left=None, status="inactive",
                                    pppoe_username="otieno01"),
                           customer("Peter Odhiambo", "254722333444", "Home 10M", hours_left=None, status="inactive",
                                    pppoe_username="odhiambo01")])
    use_real_model(monkeypatch)
    _, problems = await run("ambiguity/two-peters", client, token, monkeypatch,
                            "Peter amelipa 2000 cash, muwashe", [asks_which("Otieno", "Odhiambo")])
    assert not problems, problems


@pytest.mark.asyncio
async def test_make_hotspot_customer_pppoe(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Main Tower"], plans=[*HOTSPOT, HOME_10],
                customers=[customer("Brian Kiprop", "254711999888", "Daily 50", hours_left=5)])
    use_real_model(monkeypatch)
    _, problems = await run("ambiguity/hotspot-to-pppoe", client, token, monkeypatch,
                            "Make Brian Kiprop PPPoE, nimemwekea router kwa nyumba yake", [
        card_for("PUT", "/api/customers/"),
        prefilled(plan_id="Home 10M"),
        shows("pppoe_username", never=("mac_address",)),
    ])
    assert not problems, problems

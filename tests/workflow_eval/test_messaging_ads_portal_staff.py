"""Workflow scenarios: SMS messaging, ads, the login portal, staff and account settings.

Each scenario is an account in a given state, a reseller's message (English or
Kiswahili) and what a good answer must contain. Several turn on a prerequisite the
account lacks (no SMS credits, no support number, Show ads off): a good answer
notices it and opens the form that fixes it, instead of a form that would fail or
an ad that would never show.
"""
from typing import Optional

import pytest
from sqlalchemy import select

from tests.assistant_eval_kit import (KEY, any_of, ask, build, card_for, customer, evaluate, never_says, plan,
                                      prefilled, report, says, shows, use_real_model)
from tests.test_assistant import auth, client, owner, sse_events  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


# -- small local checks ----------------------------------------------------------------

def _cards(row, method, path_part):
    return [c for c in row["cards"] if c["method"] == method and path_part in c["path"]]


def _value(card, key):
    body = card.get("body") if isinstance(card.get("body"), dict) else {}
    return body.get(key, card["prefilled"].get(key))


def body_has(method, path_part, **expected):
    """A card for this action whose body (or prefilled form) holds these values.
    A value may be a function(value) -> bool, or text that must appear in it."""
    def check(row):
        cards = _cards(row, method, path_part)
        if not cards:
            return f"no {method} ...{path_part} card (got {[c['method'] + ' ' + c['path'] for c in row['cards']]})"
        for c in cards:
            bad = []
            for k, want in expected.items():
                got = _value(c, k)
                ok = want(got) if callable(want) else (got is not None and str(want).lower() in str(got).lower())
                if not ok:
                    bad.append(f"{k}={got!r}")
            if not bad:
                return None
        return f"{path_part} card body wrong: {', '.join(bad)}"
    return check


def no_card_for(method, path_part):
    def check(row):
        return None if not _cards(row, method, path_part) else f"proposed {method} {path_part}, which is the wrong action"
    return check


def _truthy(v) -> bool:
    return v is True or str(v).lower() in ("true", "1", "yes")


async def confirm(client, token, db, conversation_id, path_part, values: Optional[dict] = None) -> dict:  # noqa: F811
    """Tap Confirm on the pending card for path_part, as the person would."""
    from app.db.models import AssistantAction

    db.expire_all()
    action = (await db.execute(select(AssistantAction).where(
        AssistantAction.conversation_id == conversation_id, AssistantAction.status == "pending"))).scalars().all()
    action = next((a for a in action if path_part in (a.path or "")), None)
    assert action is not None, f"no pending {path_part} action to confirm"
    r = await client.post(f"/api/assistant/conversations/{conversation_id}/decide", headers=auth(token), timeout=240,
                          json={"decisions": [{"action_id": action.id, "approve": True, "values": values or {}}]})
    return next((e for e in sse_events(r.text) if e["type"] == "action_result"), {})


def _base_customers():
    # two whose time ends this week, two with weeks left, one already off
    return [customer("Amina Wanjiku", "254711000001", "Weekly 300", hours_left=30),
            customer("Otieno Brian", "254711000002", "Weekly 300", hours_left=96),
            customer("Kamau Peter", "254711000003", "Monthly 1000", hours_left=24 * 20),
            customer("Chebet Joy", "254711000004", "Monthly 1000", hours_left=24 * 25),
            customer("Mwangi Ken", "254711000005", "Weekly 300", hours_left=-48, status="inactive")]


async def _account(db, reseller, **kw):
    return await build(db, reseller, routers=["Main Tower"],
                       plans=[plan("Weekly 300", 300, days=7), plan("Monthly 1000", 1000, days=30)],
                       customers=_base_customers(), payment_methods=["mpesa_paybill"], **kw)


def _run(name, row, checks):
    problems = evaluate(row, checks)
    report(name, row, problems)
    assert not problems, problems


# -- SMS ---------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sms_expiring_this_week_without_credits_buys_first(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, sms_credits=0)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nataka kutuma SMS kwa wateja ambao muda wao unaisha wiki hii, wakumbuke kulipa mapema",
                    monkeypatch)
    _run("sms/expiring-no-credits-buy-first", row, [
        card_for("POST", "/api/messaging/credits/purchase"),
        says("credit", "salio", "sms", any_=True),
        says("0", "hakuna", "no ", "zero", "huna", "none", "insufficient", "hazitosha", any_=True),
    ])


@pytest.mark.asyncio
async def test_sms_expiring_this_week_with_credits_sends(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    made = await _account(db, reseller, sms_credits=500)
    expiring = {made["customers"]["Amina Wanjiku"].id, made["customers"]["Otieno Brian"].id}
    use_real_model(monkeypatch)
    row = await ask(client, token, "Send an SMS to customers whose package ends this week reminding them to renew early",
                    monkeypatch)

    def targets_expiring(r):
        for c in _cards(r, "POST", "/api/messaging/send"):
            f, ids = _value(c, "filter"), _value(c, "customer_ids")
            if f == "expiring" or (isinstance(ids, list) and set(ids) == expiring):
                return None
            return f"send goes to filter={f!r} customer_ids={ids!r}, not the customers ending this week"
        return "no POST /api/messaging/send card"

    _run("sms/expiring-with-credits-send", row, [
        targets_expiring,
        body_has("POST", "/api/messaging/send", body=lambda v: bool(v and len(str(v)) > 15)),
        no_card_for("POST", "/api/messaging/credits/purchase"),
    ])


@pytest.mark.asyncio
async def test_sms_template_saved_then_used(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, sms_credits=300)
    use_real_model(monkeypatch)
    first = await ask(client, token, "Save an SMS template called 'Renew reminder' that says: Habari, kifurushi chako "
                                     "kinaisha karibuni. Lipa mapema uendelee kufurahia internet ya Kwetu WiFi.", monkeypatch)
    problems = evaluate(first, [body_has("POST", "/api/messaging/templates", name="renew reminder", body="lipa mapema"),
                                no_card_for("POST", "/api/messaging/send")])
    report("sms/template-save", first, problems)
    assert not problems, problems

    result = await confirm(client, token, db, first["conversation_id"], "/api/messaging/templates")
    assert result.get("ok"), result
    second = await ask(client, token, "Now send that Renew reminder template to all my active customers", monkeypatch,
                       conversation_id=first["conversation_id"])
    _run("sms/template-use", second, [
        body_has("POST", "/api/messaging/send", filter="active"),
        any_of(body_has("POST", "/api/messaging/send", template_id=lambda v: v not in (None, "")),
               body_has("POST", "/api/messaging/send", body="lipa mapema")),
    ])


@pytest.mark.asyncio
async def test_sms_automatic_expiry_reminders_need_credits(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, sms_credits=0)
    use_real_model(monkeypatch)
    row = await ask(client, token, "I want my customers to get an SMS automatically one day before their package expires",
                    monkeypatch)
    _run("sms/auto-expiry-reminders", row, [
        body_has("PUT", "/api/messaging/expiry-settings", enabled=_truthy,
                 reminder_offsets_minutes=lambda v: isinstance(v, list) and 1440 in [int(x) for x in v]),
        # reminders are skipped without credits: a good answer says so (and may offer the purchase)
        says("credit", any_=True),
    ])


# -- ads -----------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ad_own_wifi_without_support_number_or_show_ads(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, portal={"show_ads": False})
    use_real_model(monkeypatch)
    row = await ask(client, token, "Nataka kuweka tangazo la WiFi yangu kwenye login page: Weekly 300 sasa ni bei poa, "
                                   "nunua leo!", monkeypatch)
    _run("ads/house-promo-prereqs-missing", row, [
        # the promo shows the network's support number, and nothing shows while Show ads is off
        says("support", "msaada", "namba", "number", any_=True),
        says("show ads", "show_ads", "matangazo yamezimwa", "ads are off", "ads off", "turned off", "switched off",
             "imezimwa", "haionyeshi", "zima", "washa", "turn on", "switch on", any_=True),
        any_of(card_for("PUT", "/api/portal/settings"), card_for("PATCH", "/api/profile")),
        no_card_for("POST", "/api/ad-sales"),
    ])


@pytest.mark.asyncio
async def test_ad_sold_to_a_shop(client, owner, db, monkeypatch):  # noqa: F811
    from app.db.models import AppSetting

    reseller, token = owner
    await _account(db, reseller, portal={"show_ads": True, "portal_support_phone": "0711999000"})
    db.add(AppSetting(key="ads_selling_mode", value="everyone"))
    await db.commit()
    use_real_model(monkeypatch)
    row = await ask(client, token, "Mama Njeri's shop wants to advertise on my WiFi for 2 weeks, she will pay 200 a week. "
                                   "Her number is 0722334455", monkeypatch)
    _run("ads/sold-to-shop", row, [
        body_has("POST", "/api/ad-sales", business_phone="722334455"),
        any_of(body_has("POST", "/api/ad-sales", weeks="2", price_per_week="200"),
               body_has("POST", "/api/ad-sales", weeks="2")),
        no_card_for("POST", "/api/ads"),
    ])


# -- portal --------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_portal_theme_and_logo(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller, portal={"color_theme": "slate_gray"})
    use_real_model(monkeypatch)
    row = await ask(client, token, "Change my login page colour to green and put my logo on it", monkeypatch)
    _run("portal/theme-and-logo", row, [
        body_has("PUT", "/api/portal/settings", color_theme="green"),
        shows("company_logo_url"),
    ])


@pytest.mark.asyncio
async def test_portal_maintenance_announcement(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Weka tangazo kwa login page: Jumamosi tutakuwa na maintenance saa nne hadi saa sita "
                                   "asubuhi, internet itakatika kidogo.", monkeypatch)
    _run("portal/maintenance-announcement", row, [
        body_has("PUT", "/api/portal/settings", show_announcement=_truthy, announcement_text="maintenance"),
        shows("announcement_type", "announcement_text"),
    ])


@pytest.mark.asyncio
async def test_portal_support_whatsapp(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Put my support WhatsApp 0712345678 on the login page so customers can reach me",
                    monkeypatch)
    _run("portal/support-whatsapp", row, [
        body_has("PUT", "/api/portal/settings", portal_support_whatsapp="712345678"),
    ])


# -- staff and account -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_staff_who_sees_customers_and_takes_payments(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Add a staff member Grace Achieng, grace@kwetu.co.ke, 0722000111. She should only see "
                                   "customers and take payments, nothing on routers and she can't withdraw money.",
                    monkeypatch)
    forbidden = {"routers.view", "routers.manage", "money.withdraw", "payment_methods.manage", "settlement.manage",
                 "plans.manage", "subscription.manage", "portal.manage"}

    def scoped(r):
        for c in _cards(r, "POST", "/api/staff"):
            perms = _value(c, "permissions") or []
            perms = perms if isinstance(perms, list) else [perms]
            wrong = sorted(set(perms) & forbidden)
            if "customers.view" not in perms:
                return f"permissions {perms} lack customers.view"
            if wrong:
                return f"permissions {perms} include {wrong}"
            if _truthy(_value(c, "is_account_admin")):
                return "made her an account admin"
            if not any(p in perms for p in ("transactions.view", "transactions.manage", "customers.manage")):
                return f"permissions {perms} give no way to take payments"
            return None
        return "no POST /api/staff card"

    _run("staff/customers-and-payments-only", row, [
        scoped,
        prefilled(email="grace@kwetu.co.ke"),
        no_card_for("POST", "/api/access-credentials"),
    ])


@pytest.mark.asyncio
async def test_technician_free_internet_is_an_access_credential(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Fundi wangu Brian anahitaji internet ya bure kwenye router ya Main Tower, asilipe "
                                   "kila siku", monkeypatch)
    _run("staff/technician-free-internet", row, [
        card_for("POST", "/api/access-credentials"),
        no_card_for("POST", "/api/staff"),
        never_says("dashboard login"),
    ])


@pytest.mark.asyncio
async def test_change_my_own_email(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await _account(db, reseller)
    use_real_model(monkeypatch)
    row = await ask(client, token, "Change my email to dennis.kwetu@gmail.com", monkeypatch)
    _run("account/change-email", row, [
        body_has("PATCH", "/api/profile", email="dennis.kwetu@gmail.com"),
        no_card_for("PUT", "/api/staff"),
        no_card_for("POST", "/api/staff"),
    ])

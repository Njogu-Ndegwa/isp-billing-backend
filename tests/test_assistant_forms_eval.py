"""Opt-in check against the real model: do add and edit requests come back as forms?

Skipped unless ASSISTANT_EVAL_KEY holds a model key (the provider is the app's own
setting). Each case is one fresh chat on a throwaway account in the test database,
set up in a given state (brand new, plans but no router, a full account, an existing
customer...). Nothing is confirmed, so nothing runs. Most questions are ones
resellers actually asked, Swahili included. A report is written to
ASSISTANT_EVAL_REPORT if set; ASSISTANT_EVAL_ONLY runs the cases whose question
contains that text.

    ASSISTANT_EVAL_KEY=... python -m pytest tests/test_assistant_forms_eval.py -s -n 0 -p no:warnings
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta

import pytest

from app.config import settings
from app.db.models import ConnectionType, CustomerStatus
from app.services.assistant import agent as agent_mod
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import auth, client, owner, sse_events, visible_text  # noqa: F401  (fixtures)

KEY = os.environ.get("ASSISTANT_EVAL_KEY", "")
pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")


# -- account states ------------------------------------------------------------

async def _fresh(db, reseller):
    """A brand-new account: no router, no plan, no customer."""


async def _plans_only(db, reseller):
    await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)


async def _full(db, reseller):
    await make_router(db, reseller, name="Main Tower")
    await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_plan(db, reseller, name="Diamond", price=2000, duration_value=30,
                    connection_type=ConnectionType.PPPOE, speed="10M/10M")


async def _with_bank(db, reseller):
    """Paid out to a bank account, no till yet."""
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    await _full(db, reseller)
    db.add(ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.BANK_ACCOUNT,
                                 label="Equity Bank", bank_paybill_number="247247",
                                 bank_account_number="0170299999999", is_active=True))


async def _with_till(db, reseller):
    """Paid out to an M-Pesa till already."""
    from app.db.models import ResellerPaymentMethod, ResellerPaymentMethodType

    await _full(db, reseller)
    db.add(ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
                                 label="Shop Till", mpesa_till_number="123456", is_active=True))


async def _with_customer(db, reseller):
    router = await make_router(db, reseller, name="Main Tower")
    plan = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    await make_customer(db, reseller, plan, router, name="Amina Wanjiru", phone="254712345678")


async def _messaging(db, reseller, credits=200):
    from app.db.models import MessageTemplate
    from tests.factories import make_sms_account

    router = await make_router(db, reseller, name="Main Tower")
    weekly = await make_plan(db, reseller, name="Weekly 300", price=300, duration_value=7)
    daily = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    now = datetime.utcnow()
    await make_customer(db, reseller, daily, router, name="Amina Wanjiru", phone="254711000001",
                        status=CustomerStatus.ACTIVE, expiry=now + timedelta(hours=5))
    await make_customer(db, reseller, weekly, router, name="Brian Otieno", phone="254711000002",
                        status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=4))
    await make_customer(db, reseller, weekly, router, name="George Kamau", phone="254711000007",
                        status=CustomerStatus.INACTIVE, expiry=now - timedelta(days=2))
    await make_sms_account(db, reseller, balance=credits)
    db.add(MessageTemplate(user_id=reseller.id, name="Promo", body="Get 10% off Weekly this week!"))


async def _no_credits(db, reseller):
    await _messaging(db, reseller, credits=0)


async def _owing(db, reseller, status, expires_in):
    from app.db.models import InvoiceStatus, SubscriptionInvoice

    await _with_customer(db, reseller)
    now = datetime.utcnow()
    reseller.subscription_status = status
    reseller.subscription_expires_at = now + expires_in
    db.add(SubscriptionInvoice(user_id=reseller.id, period_start=now - timedelta(days=30), period_end=now,
                               final_charge=1500, currency="KES", due_date=now + expires_in,
                               status=InvoiceStatus.OVERDUE if expires_in < timedelta(0) else InvoiceStatus.PENDING))


async def _suspended(db, reseller):
    from app.db.models import SubscriptionStatus
    await _owing(db, reseller, SubscriptionStatus.SUSPENDED, timedelta(days=-2))


async def _ending_soon(db, reseller):
    from app.db.models import SubscriptionStatus
    await _owing(db, reseller, SubscriptionStatus.ACTIVE, timedelta(hours=20))


# -- what counts as right -----------------------------------------------------------

def form_for(path_start: str, **prefilled):
    """A form card for this action, with these values already filled in (... = any value)."""
    def check(row):
        if not (row["form"] and row["path"] and row["path"].split(" ", 1)[1].startswith(path_start)):
            return f"wanted a form for {path_start}"
        for k, want in prefilled.items():
            got = (row["prefilled"] or {}).get(k)
            if got is None or (want is not ... and str(want).lower() not in str(got).lower()):
                return f"{k} should be filled with {want!r}, got {got!r}"
        return None
    return check


def shows_only(*names, never=()):
    """What the person sees on the form (fields of the chosen kind only): these, and none of `never`."""
    def check(row):
        seen = set(row.get("visible") or [])
        missing = [n for n in names if n not in seen]
        wrong = sorted(n for n in seen if any(n.startswith(p) for p in never))
        if missing:
            return f"form should show {', '.join(missing)}"
        return f"form shows fields of another kind: {', '.join(wrong)}" if wrong else None
    return check


def guides_to(*words):
    """No card is the right answer here: say what is needed first (in words that name it)."""
    def check(row):
        said = row["said"].lower()
        return None if any(w in said for w in words) else f"should say {' or '.join(words)} is needed first"
    return check


def delete_card(path_start: str):
    def check(row):
        return None if row["path"] and row["path"].startswith("DELETE " + path_start) else f"wanted a delete card for {path_start}"
    return check


def card_for(method: str, path_part: str):
    """A card (form or plain) for this kind of change on the router."""
    def check(row):
        return None if row["path"] and row["path"].startswith(method + " ") and path_part in row["path"] else f"wanted {method} ...{path_part}"
    return check


def answers_without_a_card(row):
    """A question about the router: answered from reads, nothing proposed, nothing claimed."""
    return None if not row["card"] else f"proposed {row['path']} for a question"


def all_of(*checks):
    def check(row):
        results = [r for r in (c(row) for c in checks) if r]
        return " / ".join(results) or None
    return check


def any_of(*checks):
    def check(row):
        results = [c(row) for c in checks]
        return None if any(r is None for r in results) else " / ".join(r for r in results if r)
    return check


# (state, question, check)
CASES = [
    # plans
    (_full, "Can I add a new plan", form_for("/api/plans/create")),
    (_full, "help me set up a pppoe package 10 mbs at ksh 2000 period 1 month package name Diamond Plus",
     form_for("/api/plans/create", name="Diamond Plus", price=2000, connection_type="pppoe")),
    (_fresh, "Create a hotspot plan called Assistant Test, 1 KES for 1 hour, 1M/1M speed.",
     form_for("/api/plans/create", name="Assistant Test", price=1, duration_unit="HOURS")),
    (_full, "Change the price of my Weekly 300 plan to 350", form_for("/api/plans/", price=350)),
    (_full, "Nataka kuongeza plan mpya ya siku moja", form_for("/api/plans/create")),
    # customers: the account's state decides the right answer
    # no router yet: a customer cannot be put anywhere, and a router comes from the setup command
    (_fresh, "Add a new customer", any_of(form_for("/api/plans/create"), guides_to("router", "setup"))),
    (_plans_only, "Add a new customer", any_of(form_for("/api/customers"), guides_to("router"))),
    (_full, "Add a new customer", form_for("/api/customers")),
    (_full, "Add a customer Amina, phone 0712345678, on the Weekly 300 plan",
     form_for("/api/customers", name="Amina", plan_id=...)),
    (_full, "Nisajilie customer mpya", form_for("/api/customers")),
    (_full, "Register a PPPoE customer John on the Diamond package", form_for("/api/customers", plan_id=...)),
    (_with_customer, "Change Amina's phone number to 0722000111", form_for("/api/customers/", phone="722000111")),
    # vouchers
    (_full, "Generate 10 one-day vouchers", any_of(form_for("/api/vouchers"), form_for("/api/plans/create"))),
    (_fresh, "Generate 10 vouchers", any_of(form_for("/api/plans/create"), guides_to("router", "setup"))),
    # deletes: a plain red confirm, nothing to fill in
    (_full, "Delete the Daily 50 plan", delete_card("/api/plans/")),
    (_with_customer, "Remove the customer Amina Wanjiru", delete_card("/api/customers/")),
    # routers: ports, load balancing, location, names, restarts and questions about them
    (_full, "Set ether3 and ether4 on Main Tower as plain ports", card_for("PUT", "/plain-ports")),
    (_full, "Make ether5 a PPPoE port on Main Tower", card_for("PUT", "/pppoe-ports")),
    (_full, "Use ether2 for both hotspot and PPPoE on Main Tower", card_for("PUT", "/dual-ports")),
    (_full, "Turn on load balancing on Main Tower with ether1 and ether2 as the internet lines",
     any_of(card_for("POST", "/load-balancing/enable"), card_for("POST", "/load-balancing/preflight"))),
    (_full, "Switch off load balancing on Main Tower", card_for("POST", "/load-balancing/disable")),
    (_full, "Set the location of Main Tower to Kahawa West, Nairobi", card_for("PUT", "/api/routers/")),
    (_full, "Rename the router Main Tower to Kahawa Tower", card_for("PUT", "/api/routers/")),
    (_full, "Change the WiFi name on Main Tower to Kwetu WiFi", card_for("PUT", "/wifi/ssid")),
    (_full, "Restart Main Tower", card_for("POST", "/reboot")),
    (_full, "Restart ether3 on Main Tower", card_for("POST", "/interfaces/")),
    (_full, "Tell me when Main Tower goes offline", card_for("PUT", "/status-alerts")),
    (_full, "Remove the router Main Tower", card_for("DELETE", "/api/routers/")),
    (_full, "What is the uptime of Main Tower?", answers_without_a_card),
    (_full, "Router yangu iko na load kiasi gani? CPU na memory", answers_without_a_card),
    (_full, "Which ports on Main Tower are hotspot and which are PPPoE?", answers_without_a_card),
    # account, staff, payments
    (_full, "change my email to sample.owner@example.com", form_for("/api/profile", email="sample.owner@example.com")),
    (_full, "Staff wanafaa kuingia kwa net na username na password gani bila kununua internet? Niongezee mmoja",
     form_for("/api/access-credentials")),
    (_full, "Add a staff member who can only see customers", form_for("/api/staff")),
    (_full, "Add an M-Pesa till for my payments", form_for("/api/payment-methods")),
    # payment methods: one request model, seven kinds; the form must show the chosen kind only
    (_full, "Change my payment method to M-Pesa till 123456",
     all_of(form_for("/api/payment-methods", method_type="mpesa_till"),
            shows_only("mpesa_till_number", never=("bank_", "mtn_", "fapshi_", "zenopay_", "mpesa_shortcode", "mpesa_paybill")))),
    (_with_bank, "I want my customers' money to go to my till 654321 instead of the bank",
     all_of(form_for("/api/payment-methods", method_type="mpesa_till"),
            shows_only("mpesa_till_number", never=("bank_", "mtn_", "fapshi_", "zenopay_")))),
    (_with_till, "Change my till number to 778899",
     all_of(form_for("/api/payment-methods/", mpesa_till_number="778899"),
            shows_only("mpesa_till_number", never=("bank_", "mtn_", "fapshi_", "zenopay_", "mpesa_shortcode")))),
    (_with_bank, "Change my bank account number to 0170211111111",
     all_of(form_for("/api/payment-methods/", bank_account_number="0170211111111"),
            shows_only("bank_account_number", never=("mpesa_", "mtn_", "fapshi_", "zenopay_")))),
    (_with_bank, "Rename my Equity Bank payment method to Equity Main",
     all_of(form_for("/api/payment-methods/", label="Equity Main"), shows_only(never=("mpesa_", "mtn_", "fapshi_")))),
    (_full, "Weka paybill yangu 222111 ndio wateja walipe",
     all_of(form_for("/api/payment-methods", method_type="mpesa_paybill"),
            shows_only("mpesa_paybill_number", never=("bank_", "mtn_", "fapshi_", "mpesa_till")))),
    (_full, "Set up M-Pesa payments with my own Daraja keys, shortcode 600999",
     all_of(form_for("/api/payment-methods", method_type="mpesa_paybill_with_keys"),
            shows_only("mpesa_shortcode", "mpesa_passkey", never=("bank_", "mtn_", "fapshi_", "mpesa_till")))),
    (_full, "Add MTN Mobile Money so my customers in Uganda can pay",
     all_of(form_for("/api/payment-methods", method_type="mtn_momo"),
            shows_only("mtn_api_user", never=("bank_", "mpesa_", "fapshi_")))),
    (_full, "Customers should pay into my bank: Equity paybill 247247, account 0170288888888",
     all_of(form_for("/api/payment-methods", method_type="bank_account"),
            shows_only("bank_paybill_number", "bank_account_number", never=("mpesa_", "mtn_", "fapshi_")))),
    # ads: a photo ad and a video ad have different fields
    (_full, "Create a video ad for my phone shop, Kahawa Phones, 0712000111",
     all_of(form_for("/api/ads"), shows_only("video_url", never=("image_url",)))),
    (_full, "Make a photo ad for Mama Mboga groceries, call 0712000222",
     all_of(form_for("/api/ads"), shows_only("image_url", never=("video_url", "poster_url")))),
    # messaging: texting customers, templates, automatic messages, credits, own provider
    (_messaging, "Send an SMS to all my active customers saying we have maintenance tonight from 10pm",
     form_for("/api/messaging/send", filter="active")),
    (_messaging, "Text Amina that her internet ends today", form_for("/api/messaging/send", customer_ids=...)),
    (_messaging, "Tuma ujumbe kwa wateja wote kuwa bei ya Weekly imepanda", form_for("/api/messaging/send")),
    (_messaging, "Remind the customers whose time ends this week to renew", form_for("/api/messaging/send")),
    (_messaging, "Send a message to everyone on the Weekly 300 plan", form_for("/api/messaging/send", plan_id=...)),
    (_messaging, "Create an SMS template for payment reminders", form_for("/api/messaging/templates")),
    (_messaging, "Delete my Promo template", delete_card("/api/messaging/templates/")),
    (_messaging, "Send customers a reminder 1 hour before their time ends", form_for("/api/messaging/expiry-settings")),
    # welcome SMS is off by default: saying so is as right as a form
    (_messaging, "Stop the welcome SMS for new customers",
     any_of(form_for("/api/messaging/customer-events"), guides_to("already"))),
    (_messaging, "Buy 500 SMS credits", form_for("/api/messaging/credits/purchase", quantity=500)),
    (_messaging, "How many SMS credits do I have?", all_of(answers_without_a_card, guides_to("200"))),
    (_messaging, "Use my own Africa's Talking account to send SMS", form_for("/api/messaging/provider-accounts")),
    (_no_credits, "Send an SMS to all my customers about a price change",
     all_of(any_of(form_for("/api/messaging/credits/purchase"), form_for("/api/messaging/send")), guides_to("credit"))),
    # the Bitwave subscription: suspended or about to end, and paying it here
    (_suspended, "Why can't my customers buy internet?", guides_to("subscription", "suspend")),
    (_suspended, "Pay my Bitwave subscription", form_for("/api/subscription/pay")),
    (_suspended, "Lipia subscription yangu ya Bitwave", form_for("/api/subscription/pay")),
    (_suspended, "Add a new plan", form_for("/api/plans/create")),
    (_ending_soon, "How many customers do I have?", all_of(answers_without_a_card, guides_to("subscription"))),
    (_ending_soon, "How much do I owe Bitwave?", guides_to("1,500", "1500")),
]


def _value(card, name):
    return next((f.get("value") for f in card.get("form", []) if f["name"] == name), "")


def _asks_in_text(text: str) -> bool:
    """The old habit: a numbered or bulleted list of fields to type back."""
    lines = [line.strip() for line in text.splitlines()]
    listed = [line for line in lines if re.match(r"^(\d+[.)]|[-*•])\s+\**[A-Za-z]", line)]
    return len(listed) >= 3 and bool(re.search(r"\b(name|price|duration|speed|email|phone|password)\b", text, re.I))


@pytest.mark.asyncio
@pytest.mark.parametrize("setup,question,check", CASES, ids=[f"{s.__name__}:{q[:40]}" for s, q, _ in CASES])
async def test_add_and_edit_requests_come_back_as_forms(client, owner, db, monkeypatch, setup, question, check):  # noqa: F811
    only = os.environ.get("ASSISTANT_EVAL_ONLY")
    if only and only.lower() not in question.lower():
        pytest.skip("not selected")
    reseller, token = owner
    await setup(db, reseller)
    await db.commit()
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", KEY)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", KEY if settings.ASSISTANT_PROVIDER == "claude" else "")
    agent_mod.set_client(None)

    # what the model was told when a call failed, to see why a form did not appear
    errors: list[dict] = []
    original = agent_mod.Turn._tool_result

    def recording(tool_use_id, payload, is_error=False):
        if is_error:
            errors.append(payload)
        return original(tool_use_id, payload, is_error)

    monkeypatch.setattr(agent_mod.Turn, "_tool_result", staticmethod(recording))

    r = await client.post("/api/assistant/chat", json={"message": question}, headers=auth(token), timeout=180)
    events = sse_events(r.text)
    cards = [e for e in events if e["type"] == "action"]
    text = visible_text(events)
    form_card = next((c for c in reversed(cards) if c.get("form")), None)
    card = form_card or (cards[-1] if cards else None)
    row = {
        "state": setup.__name__.strip("_"), "question": question,
        "card": bool(card), "form": bool(form_card),
        "path": f"{card['method']} {card['path']}" if card else None,
        "prefilled": {f["name"]: f.get("option_labels", {}).get(str(f["value"]), f["value"])
                      for f in (form_card or {}).get("form", []) if "value" in f} if form_card else None,
        "pickers": [f["name"] for f in (form_card or {}).get("form", []) if f.get("option_labels")] if form_card else None,
        # what the page shows: fields without a condition, and those whose choice is the one picked
        "visible": [f["name"] for f in (form_card or {}).get("form", [])
                    if all(str(_value(form_card, c)).lower() in {v.lower() for v in vs}
                           for c, vs in (f.get("when") or {}).items())] if form_card else None,
        "asked_in_text": _asks_in_text(text),
        # the worst failure: saying a form is ready when none was made
        "claimed_without_card": not cards and bool(re.search(
            r"(tap confirm|form is ready|fill (it )?in and|fomu iko tayari|bonyeza confirm)", text, re.I)),
        "said": re.sub(r"\s+", " ", text)[:260],
        "errors": [str(e.get("error", e))[:300] for e in errors],
    }
    problem = check(row)
    if row["asked_in_text"]:
        problem = (problem + "; " if problem else "") + "asked for the fields in text"
    if row["claimed_without_card"]:
        problem = (problem + "; " if problem else "") + "said a form was ready but made none"
    row["problem"] = problem
    print(json.dumps(row, ensure_ascii=False))
    if os.environ.get("ASSISTANT_EVAL_REPORT"):
        with open(os.environ["ASSISTANT_EVAL_REPORT"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    assert problem is None, problem

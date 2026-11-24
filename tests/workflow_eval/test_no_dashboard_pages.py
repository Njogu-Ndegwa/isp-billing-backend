"""The assistant does the job in the chat instead of sending a reseller to a dashboard page.

From the 22-24 Nov 2026 chat review: with the classic dashboard closed to resellers, replies
still said "do the router-only send from the messaging page", "open Messaging -> Credits",
"Settings -> Portal", "open their page -> Get PPPoE credentials". The scripted checks of
the same rule are in tests/test_assistant_no_dashboard_links.py.
"""
import pytest

from tests.assistant_eval_kit import (
    KEY, any_of, ask, build, card_for, customer, evaluate, never_says, plan, report, use_real_model,
)
from tests.test_assistant import client, owner  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(not KEY, reason="needs ASSISTANT_EVAL_KEY (a real model key)")

HOTSPOT = [plan("1 Hour", 10), plan("Daily pass", 35)]
NO_PAGE = never_says("](/", "dashboard", "messaging page", "settings page", "on the page", "open the page",
                     "settings →", "settings ->")


@pytest.mark.asyncio
@pytest.mark.parametrize("question, checks", [
    ("Send an SMS to the active customers on Rongai only", [card_for("POST", "/api/messaging/send")]),
    ("How do I send to one router from the dashboard?", [card_for("POST", "/api/messaging/send")]),
    ("I want to buy sms credits", [card_for("POST", "/api/messaging/credits/purchase")]),
    ("I want to change my password", [card_for("PUT", "/api/profile/password")]),
    ("Where do I change who gets the router offline alerts?",
     [any_of(card_for("PUT", "/api/messaging/alert-contacts"), lambda row: None if any(
         "/api/messaging/alert-contacts" in t for t in row["tools"]) else "did not read the alert contacts")]),
])
async def test_the_job_is_done_in_the_chat(client, owner, db, monkeypatch, question, checks):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Rongai", "Town"], plans=HOTSPOT, sms_credits=200,
                customers=[customer("Amina", "254711000001", "Daily pass", router="Rongai"),
                           customer("Baraka", "254711000002", "Daily pass", router="Town")])
    use_real_model(monkeypatch)
    row = await ask(client, token, question, monkeypatch)
    problems = evaluate(row, [NO_PAGE, *checks])
    report(f"no-dashboard/{question[:30]}", row, problems)
    assert not problems, problems


def offers_a_tour(row):
    said = row["said"].lower()
    return None if any(w in said for w in ("tour", "ziara", "nikuonyeshe", "visite", "show you around")) \
        else "did not offer a quick tour"


def gives_the_way_back(row):
    """Dennis, 24 Nov: tell them how to go back to the classic dashboard, with its link."""
    return None if "](/dashboard)" in row["said"] else "did not give the classic dashboard link"


def gives_examples(row):
    said = row["said"].lower()
    hits = [w for w in ("sales", "plan", "voucher", "router", "mauzo", "vocha", "mpango") if w in said]
    return None if len(hits) >= 2 else f"too few examples of what can be done here ({hits})"


@pytest.mark.asyncio
@pytest.mark.parametrize("question", [
    "How can I exit AI mode?",
    "Nataka kurudi kwa app ya zamani",
    "Comment revenir à l'ancienne application ?",
])
async def test_asking_for_the_old_app_gets_examples_and_a_tour(client, owner, db, monkeypatch, question):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Rongai"], plans=HOTSPOT, sms_credits=200)
    use_real_model(monkeypatch)
    row = await ask(client, token, question, monkeypatch)
    problems = evaluate(row, [gives_the_way_back, never_says("one tap away", "](/customers", "](/settings", "](/messaging"),
                              offers_a_tour, gives_examples])
    report(f"no-dashboard/exit/{question[:24]}", row, problems)
    assert not problems, problems


@pytest.mark.asyncio
async def test_still_wanting_the_old_app_gets_the_menu_way_back(client, owner, db, monkeypatch):  # noqa: F811
    reseller, token = owner
    await build(db, reseller, routers=["Rongai"], plans=HOTSPOT, sms_credits=200)
    use_real_model(monkeypatch)
    first = await ask(client, token, "How can I exit AI mode?", monkeypatch)
    row = await ask(client, token, "No tour, I still want the old dashboard", monkeypatch,
                    conversation_id=first["conversation_id"])
    problems = evaluate(row, [gives_the_way_back, lambda r: None if "classic dashboard" in r["said"].lower()
                              and "menu" in r["said"].lower() else "did not say where the Classic dashboard item is"])
    report("no-dashboard/exit/still-wants-old", row, problems)
    assert not problems, problems

"""The assistant is the whole of Bitwave for resellers: it never sends them to a dashboard page.

With the rollout at Everyone the classic dashboard is closed to reseller accounts, and a
relative link in a reply opens that old page (alone, with a way back). So for resellers the
instructions forbid page links and "go to the page" answers and name the in-chat way for each
thing the bot used to send people off for; platform admins keep their page links.
"""
from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest

from app.api.auth_routes import login_token_claims
from app.services.auth import create_access_token

from app.services.assistant import agent as agent_mod
from app.services.assistant import known_issues, shaping
from app.services.assistant.caller import Caller
from app.services.assistant.catalog import Catalog, form_fields
from tests.factories import make_admin
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, text_reply, use_model,
)


def _caller(**kw) -> Caller:
    base = dict(user_id=1, role="reseller", authorization="Bearer x", organization="Org")
    base.update(kw)
    return Caller(**base)


async def _system_text(client, token) -> str:
    model = use_model([text_reply("Hello.")])
    r = await client.post("/api/assistant/chat", json={"message": "hi"}, headers=auth(token))
    assert r.status_code == 200
    return model.requests[0]["system"][0]["text"]


@pytest.mark.asyncio
async def test_a_reseller_is_never_sent_to_a_dashboard_page(client, owner):
    _, token = owner
    text = await _system_text(client, token)
    assert "relative links" not in text
    assert "](/" not in text
    assert "never write links to dashboard paths" in text
    assert "dashboard page to use" not in text
    # the in-chat way for what it used to send people off for
    for way in ("router_id", "/api/messaging/alert-contacts", "/api/messaging/customer-events",
                "PUT /api/profile/password", "PPPoE login card", "the next page",
                "POST /api/feedback/requests", "the purchase form", "portal settings form"):
        assert way in text, way
    assert 'never "how do I do it on the dashboard"' in text


@pytest.mark.asyncio
async def test_a_platform_admin_keeps_the_page_links(client, db):
    admin = await make_admin(db, email="boss@example.com")
    token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    text = await _system_text(client, token)
    assert "You may link to dashboard pages with relative links" in text
    assert "never write links to dashboard paths" not in text


def test_hidden_values_and_big_results_do_not_point_at_a_page():
    masked = shaping.mask({"pppoe_password": "x"})["pppoe_password"]
    assert "page" not in masked.lower()
    big = shaping.for_screen([{"v": "x" * 2000} for _ in range(400)], limit_chars=1000)
    assert "page for the full list" not in json.dumps(big).lower()
    assert "dashboard page" not in (shaping.__doc__ or "")


def test_known_issues_do_the_job_in_the_chat():
    page = re.compile(r"in the dashboard|from the dashboard|on the dashboard|dashboard page|"
                      r"subscription page|messaging page|settings page|portal configuration", re.I)
    for issue in json.load(open(known_issues.__file__.replace("known_issues.py", "known_issues.json"),
                                encoding="utf-8"))["issues"]:
        for key in ("cause", "checks", "fix", "bitwave", "not_this_if"):
            assert not page.search(json.dumps(issue.get(key))), (issue["id"], key)


def test_what_the_bot_used_to_send_people_off_for_is_in_its_index():
    import main

    catalog = Catalog.from_openapi(main.app.openapi())
    owner = {a.key for a in catalog.for_caller(_caller())}
    for key in ("POST /api/messaging/send", "POST /api/messaging/credits/purchase",
                "GET /api/messaging/alert-contacts", "PUT /api/messaging/alert-contacts",
                "GET /api/messaging/customer-events", "PUT /api/messaging/customer-events",
                "GET /api/reseller/account-statement", "PUT /api/portal/settings",
                "DELETE /api/customers/{customer_id}/devices/{pairing_id}",
                "GET /api/customers/{customer_id}/pppoe-credentials", "PUT /api/profile/password",
                "POST /api/reseller/withdraw", "POST /api/feedback/requests"):
        assert key in owner, key

    send = catalog.get("POST", "/api/messaging/send")
    assert "router_id" in send.body_schema["properties"]
    statement = catalog.get("GET", "/api/reseller/account-statement")
    assert {"page", "per_page"} <= {q["name"] for q in statement.query_params}

    # the person's own password is typed into the card, never into the chat
    fields = {f["name"]: f["kind"] for f in form_fields(catalog.get("PUT", "/api/profile/password"), {})}
    assert fields == {"current_password": "password", "new_password": "password"}


@pytest.mark.asyncio
async def test_asking_for_the_old_app_gets_the_assistant_and_a_tour(client, owner):
    """'How can I exit AI mode?' / 'Nataka kurudi kwa app ya zamani': the classic dashboard is
    replaced, so the answer is what can be done here, with examples, and an offer of a tour."""
    _, token = owner
    text = await _system_text(client, token)
    assert "exit AI mode" in text and "nataka kurudi kwa app ya zamani" in text
    assert "the classic dashboard has been replaced" in text
    assert "Never say how to reach the classic dashboard, never call it one tap away and never link to it" in text
    assert "quick tour" in text and "Yes, give me a quick tour" in text
    tour = text[text.index("The tour, once they say yes"):]
    order = ["customers", "plans and vouchers", "routers", "payments and earnings", "messaging", "login page look"]
    assert [tour.index(a) for a in order] == sorted(tour.index(a) for a in order)
    assert "Move on only when they ask for the next area" in tour
    assert "one tap away" not in text.replace("never call it one tap away", "")


@pytest.mark.asyncio
async def test_a_platform_admin_gets_no_tour_instructions(client, db):
    admin = await make_admin(db, email="boss2@example.com")
    token = create_access_token(login_token_claims(admin), timedelta(hours=1))
    text = await _system_text(client, token)
    assert "The tour, once they say yes" not in text

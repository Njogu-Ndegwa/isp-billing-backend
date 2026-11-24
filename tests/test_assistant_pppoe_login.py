"""The assistant hands a reseller their PPPoE customer's login on a card only they see.

The password is drawn on the person's screen straight from the API result; the
model, the stored conversation and the support view only ever get it masked.
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from app.db.models import ResellerStaff
from app.services import staff_access
from app.services.assistant import agent as agent_mod
from app.services.assistant import known_issues
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)

SECRET = "Kq7-zebra-41"


async def _pppoe_customer(db, reseller):
    router = await make_router(db, reseller, name="Hill Top", pppoe_ports=["ether2", "ether3"])
    plan = await make_plan(db, reseller, name="Home 1000", price=1000, duration_value=30)
    return await make_customer(db, reseller, plan, router, name="Home One",
                               pppoe_username="HOME ONE", pppoe_password=SECRET)


@pytest.mark.asyncio
async def test_the_login_card_carries_the_password_and_the_model_gets_it_masked(client, owner, db):
    reseller, token = owner
    customer = await _pppoe_customer(db, reseller)

    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": f"/api/customers/{customer.id}/pppoe-credentials",
                                "show": "card"}),
        text_reply("Their login is on the card: tap Show to see the password."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Show their password please"},
                          headers=auth(token))
    assert r.status_code == 200
    events = sse_events(r.text)

    card = next(e for e in events if e["type"] == "data")
    assert card["show"] == "pppoe_login"
    login = card["payload"]
    assert login["pppoe_username"] == "HOME ONE"
    assert login["pppoe_password"] == SECRET          # drawn for the signed-in person
    assert login["router_name"] == "Hill Top"
    assert login["pppoe_ports"] == ["ether2", "ether3"]
    assert login["customer_id"] == customer.id

    # The model never sees it, but knows the card is on screen.
    result = tool_results(model.requests[1])[0]
    assert "GET /api/customers/{customer_id}/pppoe-credentials" in model.requests[0]["system"][0]["text"]
    assert SECRET not in json.dumps(model.requests)
    assert result["data"]["pppoe_username"] == "HOME ONE"
    assert "card" in result["display"].lower() and "show" in result["display"].lower()

    # Nor does the stored conversation (read again later, and by Bitwave support).
    stored = await client.get(f"/api/assistant/conversations/{events[0]['id']}", headers=auth(token))
    assert SECRET not in stored.text
    kept = next(t for t in stored.json()["transcript"] if t["type"] == "data")
    assert kept["show"] == "pppoe_login" and kept["payload"]["pppoe_username"] == "HOME ONE"
    assert "pppoe_password" not in kept["payload"] and kept["payload"]["password_on_request"] is True


@pytest.mark.asyncio
async def test_the_card_is_drawn_even_when_the_model_asked_for_no_drawing(client, owner, db):
    reseller, token = owner
    customer = await _pppoe_customer(db, reseller)
    use_model([
        tool_reply("call_api", {"method": "GET", "path": f"/api/customers/{customer.id}/pppoe-credentials",
                                "show": "none"}),
        text_reply("Here is their login."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "give me the customers credentials"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "data")
    assert card["show"] == "pppoe_login" and card["payload"]["pppoe_password"] == SECRET


@pytest.mark.asyncio
async def test_staff_who_cannot_manage_customers_get_no_password(client, owner, db):
    reseller, _ = owner
    customer = await _pppoe_customer(db, reseller)
    member = ResellerStaff(parent_reseller_id=reseller.id, name="Cashier Jo", email="jo@example.com",
                           password_hash=pwd_context.hash("pw-123456"),
                           permissions=["customers.view", "vouchers.generate"])
    db.add(member)
    await db.commit()
    token = create_access_token(staff_access.staff_token_claims(member, reseller), timedelta(hours=1))

    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": f"/api/customers/{customer.id}/pppoe-credentials",
                                "show": "card"}),
        text_reply("You do not have permission to see customer logins."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "show the pppoe password"}, headers=auth(token))
    assert r.status_code == 200
    assert SECRET not in r.text
    assert not any(e["type"] == "data" for e in sse_events(r.text))
    refused = tool_results(model.requests[1])[0]
    assert refused["_is_error"] and "customers.manage" in refused["error"]
    assert "GET /api/customers/{customer_id}/pppoe-credentials" not in model.requests[0]["system"][0]["text"]  # not in their index


def test_the_instructions_give_the_login_and_set_up_the_customer_router_in_router_mode():
    prompt = agent_mod.SYSTEM_TEMPLATE.lower()
    assert "pppoe login card" in prompt
    assert "router mode" in prompt and "wan" in prompt and "pppoe" in prompt
    assert "not the account's access credentials" in prompt

    hit = known_issues.search("how do I set up the customer's router for PPPoE")["matches"][0]
    assert hit["id"] == "pppoe-customer-router-setup"
    fix = hit["fix"].lower()
    assert "router mode" in fix and "wan" in fix and "pppoe" in fix and "vlan" in fix
    assert "bridge" not in hit["title"].lower()
    # "route WAN or bridge WAN?" lands on the same entry, not the access-point one
    hit = known_issues.search("should the customer's pppoe router be route wan or bridge wan")["matches"][0]
    assert hit["id"] == "pppoe-customer-router-setup"
    ap = known_issues.search(issue_id="ap-in-router-mode")["matches"][0]
    assert "pppoe customer" in ap["not_this_if"].lower()

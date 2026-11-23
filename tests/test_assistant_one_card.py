"""One live confirm card per change.

A change proposed again must not leave two cards that both run: the older card is
retired when a newer one is made for the same method and path, a typed go-ahead
("confirm", "sawa") never makes a second card, and words that point at a card which
is already waiting are not sent back to make it again.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.db.models import AssistantAction, Plan
from app.services.assistant import agent as agent_mod
from tests.factories import make_plan
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)

DESCRIBE_DELETE = ("describe_action", {"method": "DELETE", "path": "/api/plans/{plan_id}"}, "tu_d")
DESCRIBE_CREATE = ("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d")
WEEKLY = {"name": "Weekly 300", "speed": "5M/5M", "price": 300, "duration_value": 7,
          "duration_unit": "DAYS", "connection_type": "hotspot"}


async def _chat(client, token, message, conversation_id=None):
    payload = {"message": message, **({"conversation_id": conversation_id} if conversation_id else {})}
    return sse_events((await client.post("/api/assistant/chat", json=payload, headers=auth(token))).text)


async def _confirm(client, token, conv_id, action_id):
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": action_id, "approve": True}]})
    return sse_events(r.text)


async def _statuses(db) -> dict[str, str]:
    db.expire_all()
    return {a.id: a.status for a in (await db.execute(select(AssistantAction))).scalars().all()}


@pytest.mark.asyncio
async def test_the_same_change_proposed_again_leaves_one_live_card(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Old Promo", price=10, duration_value=1)
    plan_id = plan.id
    await db.commit()
    delete = {"method": "DELETE", "path": f"/api/plans/{plan_id}", "summary": "Delete Old Promo"}
    use_model([tool_reply(*DESCRIBE_DELETE), tool_reply("call_api", delete), text_reply("Ready. Tap Confirm.")])
    events = await _chat(client, token, "delete old promo")
    conv_id = events[0]["id"]
    first = next(e for e in events if e["type"] == "action")

    model = use_model([tool_reply("call_api", delete), text_reply("Ready again. Tap Confirm.")])
    events = await _chat(client, token, "delete the old promo plan", conv_id)
    second = next(e for e in events if e["type"] == "action")
    retired = next(e for e in events if e["type"] == "action_result")
    assert retired["action_id"] == first["action_id"] and retired["status"] == "expired" and not retired["ok"]
    assert await _statuses(db) == {first["action_id"]: "expired", second["action_id"]: "pending"}
    assert "replaced" in tool_results(model.requests[1])[0]  # the model knows the old card is closed

    # A reopened chat draws the old card as closed: by the action table and by the transcript.
    stored = (await client.get(f"/api/assistant/conversations/{conv_id}", headers=auth(token))).json()
    assert stored["actions"][first["action_id"]]["status"] == "expired"
    assert stored["actions"][second["action_id"]]["status"] == "pending"
    assert any(t["type"] == "action_result" and t["action_id"] == first["action_id"]
               and t["status"] == "expired" for t in stored["transcript"])

    # Confirming the retired card is refused and nothing runs.
    use_model([text_reply("That card was replaced.")])
    refused = next(e for e in await _confirm(client, token, conv_id, first["action_id"])
                   if e["type"] == "action_result")
    assert refused["status"] == "expired" and refused["ok"] is False
    db.expire_all()
    assert await db.get(Plan, plan_id) is not None

    # The newest card still runs, once.
    use_model([text_reply("Old Promo is deleted.")])
    done = next(e for e in await _confirm(client, token, conv_id, second["action_id"])
                if e["type"] == "action_result")
    assert done["status"] == "done", done


@pytest.mark.asyncio
async def test_two_different_changes_both_stay_pending(client, owner, db):
    _, token = owner
    daily = {**WEEKLY, "name": "Daily 50", "price": 50, "duration_value": 1}
    use_model([
        tool_reply(*DESCRIBE_DELETE),
        tool_reply("call_api", {"method": "DELETE", "path": "/api/plans/1"}, "tu_1"),
        tool_reply("call_api", {"method": "DELETE", "path": "/api/plans/2"}, "tu_2"),   # another record
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/create"}, "tu_d2"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": WEEKLY}, "tu_3"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": daily}, "tu_4"),  # another plan
        text_reply("Four cards are ready. Tap Confirm on each."),
    ])
    events = await _chat(client, token, "delete plans 1 and 2, then add a weekly and a daily plan")
    assert len([e for e in events if e["type"] == "action"]) == 4
    assert not any(e["type"] == "action_result" for e in events)
    assert sorted((await _statuses(db)).values()) == ["pending"] * 4


@pytest.mark.asyncio
async def test_a_corrected_request_replaces_the_card_it_corrects(client, owner, db):
    _, token = owner
    use_model([tool_reply(*DESCRIBE_CREATE),
               tool_reply("call_api", {"method": "POST", "path": "/api/plans/create", "body": WEEKLY}),
               text_reply("Ready to create Weekly 300. Tap Confirm.")])
    events = await _chat(client, token, "add a weekly plan for 300")
    conv_id = events[0]["id"]
    first = next(e for e in events if e["type"] == "action")

    use_model([tool_reply("call_api", {"method": "POST", "path": "/api/plans/create",
                                       "body": {**WEEKLY, "price": 350}}),
               text_reply("Now at 350. Tap Confirm.")])
    events = await _chat(client, token, "make it 350", conv_id)
    second = next(e for e in events if e["type"] == "action")
    assert second["body"]["price"] == 350
    assert await _statuses(db) == {first["action_id"]: "expired", second["action_id"]: "pending"}


@pytest.mark.parametrize("text,expected", [
    ("confirm", True), ("Confirm.", True), ("Yes", True), ("ok do it", True), ("sawa", True), ("Ndio!", True),
    ("yes please", True), ("go ahead", True), ("OK", True),
    ("yes, and delete plan 2 as well", False), ("confirm the second one only", False),
    ("ok but make it 350", False), ("Deactivate rebecca", False), ("", False),
    ("is it ok to delete a plan customers are on", False),
])
def test_a_bare_go_ahead_is_told_from_a_request(text, expected):
    assert agent_mod.is_go_ahead(text) is expected


@pytest.mark.asyncio
async def test_a_typed_go_ahead_never_makes_a_second_card(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Old Promo", price=10, duration_value=1)
    plan_id = plan.id
    await db.commit()
    delete = {"method": "DELETE", "path": f"/api/plans/{plan_id}", "summary": "Delete Old Promo"}
    use_model([tool_reply(*DESCRIBE_DELETE), tool_reply("call_api", delete), text_reply("Ready. Tap Confirm.")])
    events = await _chat(client, token, "delete old promo")
    conv_id = events[0]["id"]
    card = next(e for e in events if e["type"] == "action")

    model = use_model([
        tool_reply("call_api", delete),   # the model tries to put the same card up again
        text_reply("It runs when you tap Confirm on the card."),
    ])
    events = await _chat(client, token, "Confirm", conv_id)
    assert not any(e["type"] in ("action", "action_result", "notice") for e in events), events
    # the model was told a card is waiting, and its repeat was turned down
    asked = json.dumps(model.requests[0]["messages"][-1])
    assert "Delete Old Promo" in asked and "waiting" in asked.lower()
    turned_down = tool_results(model.requests[1])[0]
    assert turned_down["status"] == "already_waiting" and turned_down["action_id"] == card["action_id"]
    assert len(model.requests) == 2  # and its "tap Confirm" was not sent back for a card
    assert await _statuses(db) == {card["action_id"]: "pending"}
    db.expire_all()
    assert await db.get(Plan, plan_id) is not None  # typing confirm ran nothing

    # the one card still runs from its own tap
    use_model([text_reply("Old Promo is deleted.")])
    done = next(e for e in await _confirm(client, token, conv_id, card["action_id"])
                if e["type"] == "action_result")
    assert done["status"] == "done", done


@pytest.mark.asyncio
async def test_pointing_at_a_waiting_card_does_not_make_it_again(client, owner, db):
    """After one of two cards ran, "the other card is still waiting, tap Confirm" is the right answer."""
    reseller, token = owner
    one = await make_plan(db, reseller, name="Old Promo", price=10, duration_value=1)
    two = await make_plan(db, reseller, name="Older Promo", price=20, duration_value=2)
    one_id, two_id = one.id, two.id
    await db.commit()
    use_model([
        tool_reply(*DESCRIBE_DELETE),
        tool_reply("call_api", {"method": "DELETE", "path": f"/api/plans/{one_id}"}, "tu_1"),
        tool_reply("call_api", {"method": "DELETE", "path": f"/api/plans/{two_id}"}, "tu_2"),
        text_reply("Two cards are ready. Tap Confirm on each."),
    ])
    events = await _chat(client, token, "delete both promo plans")
    conv_id = events[0]["id"]
    first, second = [e for e in events if e["type"] == "action"]

    model = use_model([text_reply("Old Promo is deleted. Older Promo still has its card waiting: tap Confirm there.")])
    events = await _confirm(client, token, conv_id, first["action_id"])
    assert len(model.requests) == 1                                   # no "[Check] ... call call_api now"
    assert not any(e["type"] in ("action", "notice") for e in events), events
    assert await _statuses(db) == {first["action_id"]: "done", second["action_id"]: "pending"}

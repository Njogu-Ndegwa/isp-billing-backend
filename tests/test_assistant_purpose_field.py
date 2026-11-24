"""A form opened for one field ("add her phone", "set the speed", "rename") cannot be confirmed without it.

CR-1123-B9: Edit Customer and Update Plan cards were confirmed with the one field they
were opened for left empty (it sat under "More options"), and saved "ok" without it.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models import AssistantAction, Customer, Plan
from tests.factories import make_customer, make_plan
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)


async def _open(client, token, method, path, body, purpose, template, message="fix it"):
    model = use_model([
        tool_reply("describe_action", {"method": method, "path": template}, "tu_d"),
        tool_reply("call_api", {"method": method, "path": path, "form": True, "body": body,
                                "purpose": purpose, "summary": "Fix it"}),
        text_reply("Fill it in and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": message},
                                           headers=auth(token))).text)
    card = next((e for e in events if e["type"] == "action"), None)
    return events[0]["id"], card, model


@pytest.mark.asyncio
async def test_a_speed_form_refuses_confirm_while_the_speed_is_empty_and_runs_once_filled(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="", price=30, duration_value=8, speed="")
    plan_id = plan.id
    body = {"price": 30, "duration_value": 8, "duration_unit": "HOURS", "connection_type": "hotspot"}
    conv_id, card, _ = await _open(client, token, "PUT", f"/api/plans/{plan_id}", body, "speed", "/api/plans/{plan_id}")

    # the purpose field comes first, marked, with what it is now
    first = card["form"][0]
    assert first["name"] == "speed" and first["purpose"] is True and first.get("original") in (None, "")

    # Confirm with the speed left empty (what the page sends for an untouched field): refused, nothing runs
    model = use_model([text_reply("The speed is still empty: type it on the card and tap Confirm.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"speed": "", "price": "30", "duration_value": "8"}}]})
    refused = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert refused["status"] == "pending" and not refused["ok"]
    assert "Speed" in refused["detail"] and "empty" in refused["detail"]
    db.expire_all()
    assert (await db.get(Plan, plan_id)).speed == ""
    assert (await db.execute(select(AssistantAction))).scalars().one().status == "pending"
    told = model.requests[0]["messages"][-1]["content"][0]["text"]
    assert "Not run" in told and "Speed" in told  # the assistant is told, so it can say so

    # filled in: it runs with the typed speed
    use_model([text_reply("The KES 30 plan now runs at 5M/2M.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True, "values": {"speed": "5M/2M"}}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done", result
    db.expire_all()
    assert (await db.get(Plan, plan_id)).speed == "5M/2M"


@pytest.mark.asyncio
async def test_a_rename_form_refuses_the_old_name(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Guest Plan", price=30, duration_value=8)
    plan_id = plan.id
    conv_id, card, _ = await _open(client, token, "PUT", f"/api/plans/{plan_id}", {"name": "Guest Plan"},
                                   "name", "/api/plans/{plan_id}", "rename it")
    assert card["form"][0]["name"] == "name" and card["form"][0]["original"] == "Guest Plan"

    use_model([text_reply("The name is unchanged.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True, "values": {"name": " Guest Plan "}}]})
    refused = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert refused["status"] == "pending" and "unchanged" in refused["detail"]
    db.expire_all()
    assert (await db.get(Plan, plan_id)).name == "Guest Plan"

    use_model([text_reply("Renamed.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True, "values": {"name": "Saa 8 - 30"}}]})
    assert next(e for e in sse_events(r.text) if e["type"] == "action_result")["status"] == "done"
    db.expire_all()
    assert (await db.get(Plan, plan_id)).name == "Saa 8 - 30"


@pytest.mark.asyncio
async def test_a_phone_typed_on_an_edit_customer_form_reaches_the_record(client, owner, db):
    """Rules out (c): a phone typed into a blank phone field is saved, spaces and all."""
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Static 15M", price=1500)
    customer = await make_customer(db, reseller, plan, phone="", name="Irene Test")
    customer_id = customer.id
    conv_id, card, _ = await _open(client, token, "PUT", f"/api/customers/{customer_id}",
                                   {"name": "Irene Test", "plan_id": plan.id}, "phone",
                                   "/api/customers/{customer_id}", "add her phone")
    phone = card["form"][0]
    assert phone["name"] == "phone" and phone["purpose"] and phone.get("format") == "phone"

    # what the page sends when the field is left blank: refused
    use_model([text_reply("Her phone is still empty.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"name": "Irene Test", "phone": ""}}]})
    assert next(e for e in sse_events(r.text) if e["type"] == "action_result")["status"] == "pending"

    use_model([text_reply("Saved her phone.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"name": "Irene Test", "phone": "0712 345 678"}}]})
    result = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert result["status"] == "done", result
    db.expire_all()
    assert (await db.get(Customer, customer_id)).phone.endswith("712345678")
    assert (await db.execute(select(AssistantAction))).scalars().one().body["phone"] == "0712345678"


@pytest.mark.asyncio
async def test_a_purpose_that_is_not_on_the_form_is_sent_back_to_the_model(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="X", price=30, duration_value=8)
    conv_id, card, model = await _open(client, token, "PUT", f"/api/plans/{plan.id}", {"name": "X"},
                                       "colour", "/api/plans/{plan_id}")
    assert card is None
    err = tool_results(model.requests[2])[0]
    assert err["_is_error"] and "colour" in err["error"]

"""Assistant forms with the depth of the classic dashboard.

Safety flags the person alone sets (do it anyway after a refusal), preview before
apply, moments on the person's own clock, clearing a field on an edit, record
pickers (x-pick), live options (x-options-from), labelled choices (x-enum-labels)
and switches that show the router's own setting (x-current).
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.db.models import AssistantAction, Router
from app.services.assistant import agent as agent_mod
from app.services.assistant import executor as executor_mod
from app.services.assistant.catalog import (
    Action, apply_form_values, form_fields, get_catalog, local_input, pick_label, utc_from_local,
)
from tests.factories import make_customer, make_plan, make_router
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, tool_results, use_model,
)


def _act(method: str, template: str) -> Action:
    import main

    return get_catalog(main.app).get(method, template)


# -- flags the person alone sets ---------------------------------------------

def test_override_apply_and_idempotency_flags_are_never_form_inputs():
    import main

    from app.services.assistant.catalog import reset_catalog

    reset_catalog()
    outage = _act("POST", "/api/compensation/outage")
    assert outage.overrides == ("allow_duplicate",) and outage.preview == "/api/compensation/outage/preview"
    assert "allow_duplicate" not in {f["name"] for f in form_fields(outage, {})}
    activate = _act("POST", "/api/customers/{customer_id}/activate-pppoe")
    assert "force" not in {f["name"] for f in form_fields(activate, {"force": True})}
    transfer = _act("POST", "/api/routers/{source_router_id}/pppoe-customers/transfer")
    assert transfer.apply_flag == "apply" and transfer.previews
    assert "apply" not in {f["name"] for f in form_fields(transfer, {"apply": True})}
    # apply=false only shows what would happen: it runs as a read, without a card
    assert transfer.is_read(None, {"target_router_id": 2})
    assert not transfer.is_read(None, {"target_router_id": 2, "apply": True})
    charge = _act("POST", "/api/customers/{customer_id}/charges")
    if charge is not None:
        assert "idempotency_key" not in {f["name"] for f in form_fields(charge, {})}
    assert get_catalog(main.app).describe(activate)["set_only_by_the_person"].startswith("force")


@pytest.mark.asyncio
async def test_a_refusal_with_a_flag_offers_do_it_anyway_which_runs_after_its_own_confirm(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    router = await make_router(db, reseller, name="Old Tower")
    await make_customer(db, reseller, plan, router, name="Amina")
    router_id = router.id
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "DELETE", "path": "/api/routers/{router_id}"}, "tu_d"),
        # the model tries to push past the safety net itself: the flag is taken off
        tool_reply("call_api", {"method": "DELETE", "path": f"/api/routers/{router_id}",
                                "query": {"force": "true"}, "summary": "Delete Old Tower"}),
        text_reply("Ready to delete Old Tower. Tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "delete old tower"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    assert not card.get("query")  # no force on what the person confirms first
    conv_id = events[0]["id"]

    model = use_model([text_reply("Old Tower still has a customer, so it was not deleted.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": card["action_id"], "approve": True}]})
    out = sse_events(r.text)
    result = next(e for e in out if e["type"] == "action_result")
    assert result["status"] == "failed" and "customer" in result["detail"]
    retry = next(e for e in out if e["type"] == "action")
    assert retry["retry_of"] == card["action_id"] and retry["query"] == {"force": True}
    assert retry["sensitive"] and retry["status"] == "pending"
    told = json.dumps(model.requests[-1]["messages"][-1])
    assert "Do it anyway" in told
    assert await db.get(Router, router_id) is not None  # nothing ran past the refusal yet

    use_model([text_reply("Old Tower is deleted.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token),
                          json={"decisions": [{"action_id": retry["action_id"], "approve": True}]})
    done = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert done["status"] == "done", done
    db.expire_all()
    assert await db.get(Router, router_id) is None


@pytest.mark.asyncio
async def test_a_change_with_a_preview_shows_it_first_then_the_next_confirm_does_it(client, owner, db):
    reseller, token = owner
    await make_router(db, reseller, name="Main Tower")
    await db.commit()
    body = {"outage_start": "2026-11-20T08:00:00", "outage_end": "2026-11-20T10:00:00"}
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/compensation/outage"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/compensation/outage", "form": True,
                                "body": {**body, "allow_duplicate": True}, "summary": "Credit the outage"}),
        text_reply("Check the outage window and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "credit this morning's outage"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    assert card["previews"] is True and "allow_duplicate" not in (card["body"] or {})
    fields = {f["name"]: f for f in card["form"]}
    # 08:00 UTC is 11:00 on a Nairobi clock: the form shows the person's own time
    assert fields["outage_start"]["value"] == "2026-11-20T11:00" and fields["outage_start"]["zone"] == "EAT"
    conv_id = events[0]["id"]

    use_model([])  # a preview is drawn on the card: no model call
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"outage_start": "2026-11-20T11:00", "outage_end": "2026-11-20T13:00"}}]})
    shown = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert shown["status"] == "pending" and shown["ok"] and shown["preview_of"], shown
    assert shown["preview"] is not None
    pending = (await db.execute(select(AssistantAction))).scalars().one()
    assert pending.status == "pending"
    assert pending.body["outage_start"] == "2026-11-20T08:00:00Z"  # typed on the clock, sent as UTC

    use_model([text_reply("Done: nobody was affected in that window.")])
    r = await client.post(f"/api/assistant/conversations/{conv_id}/decide", headers=auth(token), json={
        "decisions": [{"action_id": card["action_id"], "approve": True,
                       "values": {"outage_start": "2026-11-20T11:00", "outage_end": "2026-11-20T13:00"}}]})
    done = next(e for e in sse_events(r.text) if e["type"] == "action_result")
    assert done["status"] == "done", done


# -- moments, clearing, choices -------------------------------------------------

def test_a_moment_is_shown_and_typed_on_the_persons_clock():
    assert local_input("2026-11-21T11:00:00", "Africa/Nairobi") == "2026-11-21T14:00"
    assert local_input("2026-11-21T11:00:00Z", "Africa/Nairobi") == "2026-11-21T14:00"
    assert utc_from_local("2026-11-21T14:00", "Africa/Nairobi") == "2026-11-21T11:00:00Z"
    assert utc_from_local("2026-11-21T14:00+00:00", "Africa/Nairobi") == "2026-11-21T14:00:00Z"
    ad = _act("POST", "/api/ads")
    body, _, problems = apply_form_values(ad, {"title": "Promo"}, {"starts_at": "2026-12-01T08:30"}, None, "Africa/Nairobi")
    assert not problems and body["starts_at"] == "2026-12-01T05:30:00Z"
    _, _, problems = apply_form_values(ad, {"title": "Promo"}, {"starts_at": "tomorrow"}, None, "Africa/Nairobi")
    assert problems == ["'starts_at' must be a date and time"]


def test_an_emptied_field_on_an_edit_is_cleared_not_kept():
    edit = _act("PUT", "/api/customers/{customer_id}")
    record = {"name": "Amina", "national_id": "12345678", "notes": "gate code 44", "phone": "254711000001"}
    body, _, problems = apply_form_values(edit, {"name": "Amina"}, {"national_id": "", "notes": "  "}, record)
    assert not problems
    assert body["national_id"] == "" and body["notes"] == ""  # this endpoint clears with ""
    # an add leaves an emptied field out
    add = _act("POST", "/api/customers/register")
    body, _, _ = apply_form_values(add, {"name": "Amina", "national_id": "1"}, {"national_id": ""})
    assert "national_id" not in body
    # a nullable field elsewhere is cleared with null; a required one never
    action = Action(method="PUT", template="/api/things/{id}", title="Edit", description="", tag="things",
                    body_schema={"type": "object", "required": ["name"], "properties": {
                        "name": {"type": "string"}, "note": {"type": "string", "nullable": True},
                        "count": {"type": "integer"}}})
    body, _, _ = apply_form_values(action, {}, {"name": "", "note": "", "count": ""},
                                   {"name": "A", "note": "x", "count": 3})
    assert body == {"note": None}


def test_choices_read_as_words_and_numbers_go_as_numbers():
    ad = {f["name"]: f for f in form_fields(_act("POST", "/api/ads"), {"title": "x"})}
    assert ad["placement"]["option_labels"]["hero"] == "Big banner at the top"
    assert ad["badge_type"]["options"] == ["hot", "new", "sale"]
    payout = {f["name"]: f for f in form_fields(_act("POST", "/api/admin/resellers/{reseller_id}/payouts"), {})}
    assert payout["payment_method"]["options"] == ["mpesa", "bank", "cash"]  # not the customer-payment enum
    alerts = _act("PUT", "/api/routers/{router_id}/status-alerts")
    delay = {f["name"]: f for f in form_fields(alerts, {})}["delay_minutes"]
    assert delay["kind"] == "select" and delay["value_kind"] == "integer"
    body, _, problems = apply_form_values(alerts, {}, {"delay_minutes": "30"})
    assert not problems and body["delay_minutes"] == 30
    mtn = {f["name"]: f for f in form_fields(_act("POST", "/api/payment-methods"), {"method_type": "mtn_momo"})}
    assert "mtnuganda" in mtn["mtn_target_environment"]["options"]


def test_long_text_mac_and_phone_inputs():
    send = {f["name"]: f for f in form_fields(_act("POST", "/api/messaging/send"), {})}
    assert send["body"]["sms"] and send["body"]["multiline"]
    edit = _act("PUT", "/api/customers/{customer_id}")
    fields = {f["name"]: f for f in form_fields(edit, {})}
    assert fields["mac_address"]["format"] == "mac" and fields["phone"]["format"] == "phone"
    assert fields["installation_date"]["kind"] == "date"
    body, _, problems = apply_form_values(edit, {}, {"mac_address": "aa-bb-cc-dd-ee-ff"})
    assert not problems and body["mac_address"] == "AA:BB:CC:DD:EE:FF"
    body, _, _ = apply_form_values(edit, {}, {"phone": "0712 345-678"})
    assert body["phone"] == "0712345678"
    _, _, problems = apply_form_values(edit, {}, {"mac_address": "not a mac"})
    assert problems and "MAC address" in problems[0]
    register = {f["name"]: f for f in form_fields(_act("POST", "/api/customers/register"), {})}
    assert "pppoe" in register["static_ip"]["when"]["plan_id.connection_type"]  # a PPPoE customer's fixed IP


def test_a_ticked_set_is_sent_as_what_changed():
    ports = _act("PUT", "/api/routers/{router_id}/pppoe-ports")
    body, _, problems = apply_form_values(ports, {"add": ["ether3"]}, {"ports": {"add": ["ether3"], "remove": ["ether2"]}})
    assert not problems and body == {"add": ["ether3"], "remove": ["ether2"]}


def test_a_picker_row_reads_by_its_label():
    assert pick_label({"id": 1, "name": "Amina", "phone": "0711"}, "{name} · {phone}") == "Amina · 0711"
    assert pick_label({"id": 1, "name": "Amina", "phone": None}, "{name} · {phone}") == "Amina"
    assert pick_label({"id": 9}, "{name}") == "#9"
    assert pick_label({"id": 3, "period_label": "Oct 2026", "currency": "KES", "balance_remaining": 1500.0,
                       "status": "pending"},
                      "{period_label} · {currency} {balance_remaining} · {status}") == "Oct 2026 · KES 1,500 · pending"


# -- pickers, live options, current switches -------------------------------------

@pytest.mark.asyncio
async def test_a_router_ports_form_ticks_the_live_ports_with_their_modes(client, owner, db, monkeypatch):
    reseller, token = owner
    router = await make_router(db, reseller, name="Main Tower", pppoe_ports=["ether2"])
    router_id = router.id
    await db.commit()
    real = executor_mod.call_api

    async def fake(app, caller, method, path, query=None, body=None):
        if method == "GET" and path == f"/api/routers/{router_id}/ports":
            return executor_mod.ApiResult(status=200, data={
                "pppoe_ports": ["ether2"], "plain_ports": [], "dual_ports": [],
                "ports": [{"port": "ether2", "service": "pppoe", "link_up": True},
                          {"port": "ether3", "service": "hotspot", "link_up": True},
                          {"port": "ether4", "service": "hotspot", "link_up": False}]})
        return await real(app, caller, method, path, query, body)

    monkeypatch.setattr(agent_mod.executor, "call_api", fake)
    use_model([
        tool_reply("describe_action", {"method": "PUT", "path": "/api/routers/{router_id}/pppoe-ports"}, "tu_d"),
        tool_reply("call_api", {"method": "PUT", "path": f"/api/routers/{router_id}/pppoe-ports", "form": True,
                                "body": {"add": ["ether3"]}, "summary": "PPPoE on ether3"}),
        text_reply("Tick the PPPoE ports and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "put ether3 on pppoe"},
                                           headers=auth(token))).text)
    card = next(e for e in events if e["type"] == "action")
    fields = {f["name"]: f for f in card["form"]}
    assert set(fields) == {"ports"}  # add/remove are what the ticks send, not inputs of their own
    ports = fields["ports"]
    assert ports["options"] == ["ether2", "ether3", "ether4"]
    assert ports["option_labels"] == {"ether2": "ether2 · PPPoE", "ether3": "ether3 · Hotspot",
                                      "ether4": "ether4 · Hotspot · no cable"}
    assert ports["value"] == ["ether2", "ether3"] and ports["baseline"] == ["ether2"]
    assert ports["changes"] == {"add": "add", "remove": "remove"}


@pytest.mark.asyncio
async def test_record_pickers_list_the_persons_own_records(client, owner, db):
    reseller, token = owner
    plan = await make_plan(db, reseller, name="Daily 50", price=50, duration_value=1)
    await make_customer(db, reseller, plan, name="Amina Wanjiru", phone="254711000001")
    await make_router(db, reseller, name="Main Tower")
    await make_router(db, reseller, name="Block C")
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "POST", "path": "/api/compensation/outage"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/compensation/outage", "form": True, "body": {}}),
        text_reply("Fill in the outage and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "outage"}, headers=auth(token))).text)
    fields = {f["name"]: f for f in next(e for e in events if e["type"] == "action")["form"]}
    routers = fields["router_ids"]
    assert sorted(routers["option_labels"].values()) == ["Block C", "Main Tower"] and routers["value"] == []
    people = fields["exclude_customer_ids"]
    assert people["pick"]["search"] == "search"  # thousands of customers: found by search on the phone
    assert people["options"] == []


@pytest.mark.asyncio
async def test_a_switch_on_a_router_shows_the_routers_own_setting(client, owner, db):
    reseller, token = owner
    router = await make_router(db, reseller, name="Main Tower", status_alerts_enabled=True,
                               status_alert_delay_minutes=30)
    router_id = router.id
    await db.commit()
    use_model([
        tool_reply("describe_action", {"method": "PUT", "path": "/api/routers/{router_id}/status-alerts"}, "tu_d"),
        tool_reply("call_api", {"method": "PUT", "path": f"/api/routers/{router_id}/status-alerts", "form": True,
                                "body": {}}),
        text_reply("Check the alert settings and tap Confirm."),
    ])
    events = sse_events((await client.post("/api/assistant/chat", json={"message": "router alerts"},
                                           headers=auth(token))).text)
    fields = {f["name"]: f for f in next(e for e in events if e["type"] == "action")["form"]}
    assert fields["enabled"]["value"] is True  # on, as the router has it, not "off" for unknown
    assert str(fields["delay_minutes"]["value"]) == "30"

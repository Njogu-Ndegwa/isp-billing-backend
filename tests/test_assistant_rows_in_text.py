"""Rows of a result typed out as text instead of drawn (2026-11-25 chat review).

"Show today's sales per router" and "Which router earned the most this month?" were answered
in sentences, "Compare my three routers' internet lines" with a markdown table, plans and a
router's customers as bulleted lists: the bot read quietly and drew nothing. The [Check] sends
such an answer back once to draw the read; GET /api/mpesa/transactions/by-router gives the
per-router figures a chart needs."""
import json
from types import SimpleNamespace

import pytest

from app.api import payment_routes
from app.db.models import MpesaTransaction, MpesaTransactionStatus, UserRole
from app.services.assistant import agent as agent_mod
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.test_assistant import (auth, client, owner, sse_events, text_reply, tool_reply,  # noqa: F401
                                  use_model)


@pytest.mark.parametrize("said, asked", [
    ("| Router | Uptime |\n|---|---|\n| Pro #4 | 95.3% |\n| KLN | 80.3% |", "Compare my routers"),
    ("- **8MBps** — 9M/9M (KES 800)\n- **10 Mbps** — 12M/12M (KES 1,000)\n- **15MBPS** — 17M/17M (KES 1,400)",
     "Why are my speeds low?"),
    ("Pro.1-KLN earned the most: KES 60,530, over 4x Pro.3-BMB's KES 14,410 and Pro #4's KES 2,600.",
     "Which router earned the most this month?"),
    ("Today's KES 200 came from two routers: #3 with 12 payments worth KES 120 and #1 with 5 worth KES 80.",
     "Show today's sales per router"),
])
def test_rows_written_as_text_are_spotted(said, asked):
    assert agent_mod._rows_in_text(said, asked)


@pytest.mark.parametrize("said, asked", [
    ("1. Check the router has power\n2. Reseat the cable in port 1\n3. Restart the modem",
     "Why is my router offline?"),
    ("Your unpaid balance is KES 1,743. The fee is KES 20, so you receive KES 1,723.", "I want to withdraw money"),
    ("You've made KES 2,179 this week from 153 payments.", "How much did I make this week?"),
])
def test_answers_and_steps_are_not_spotted(said, asked):
    assert not agent_mod._rows_in_text(said, asked)


TYPED = ("Pro #1 earned the most today: KES 120, then Pro #2 KES 80 and Pro #3 KES 40.\n\n"
         "NEXT: Show this week's sales")
FINAL = "Pro #1 earned the most today, KES 120 of your KES 240.\n\nNEXT: Show this week's sales"
BY_ROUTER = {"method": "GET", "path": "/api/mpesa/transactions/by-router"}


async def _sales(db, reseller):
    plan = await make_plan(db, reseller)
    for i, name in enumerate(["Pro #1", "Pro #2"]):
        rtr = await make_router(db, reseller, name=name)
        customer = await make_customer(db, reseller, plan, rtr)
        db.add(MpesaTransaction(checkout_request_id=f"rows-{i}", phone_number=customer.phone, amount=120 - 40 * i,
                                reference=f"rows-{i}", customer_id=customer.id, plan_id=plan.id, router_id=rtr.id,
                                status=MpesaTransactionStatus.completed))
    await db.commit()


@pytest.mark.asyncio
async def test_a_ranking_typed_as_text_is_sent_back_to_be_drawn(client, owner, db):  # noqa: F811
    from tests.test_assistant import visible_text

    reseller, token = owner
    await _sales(db, reseller)
    model = use_model([
        tool_reply("call_api", BY_ROUTER),                     # a quiet read
        text_reply(TYPED),                                     # the figures typed out
        tool_reply("call_api", {**BY_ROUTER, "show": "bars"}),  # drawn after the check
        text_reply(FINAL),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Which router earned the most today?"},
                          headers=auth(token))
    events = sse_events(r.text)
    nudge = json.dumps(model.requests[2]["messages"][-1])
    assert "[Check]" in nudge and "by-router" in nudge
    drawn = [e for e in events if e.get("type") == "data"]
    assert [d["path"] for d in drawn] == ["/api/mpesa/transactions/by-router"]
    assert visible_text(events) == FINAL


@pytest.mark.asyncio
async def test_no_check_when_drawn_or_only_steps(client, owner, db):  # noqa: F811
    reseller, token = owner
    await _sales(db, reseller)
    model = use_model([tool_reply("call_api", {**BY_ROUTER, "show": "bars"}), text_reply(TYPED)])
    await client.post("/api/assistant/chat", json={"message": "Which router earned the most today?"},
                      headers=auth(token))
    assert len(model.requests) == 2

    steps = "1. Check the power\n2. Reseat the cable in port 1\n3. Restart the modem\n\nNEXT: Is it back?"
    model = use_model([tool_reply("call_api", {"method": "GET", "path": "/api/routers"}), text_reply(steps)])
    await client.post("/api/assistant/chat", json={"message": "Why is my router offline?"}, headers=auth(token))
    assert len(model.requests) == 2


@pytest.mark.asyncio
async def test_sent_back_once_and_never_again(client, owner):  # noqa: F811
    reseller, token = owner
    model = use_model([tool_reply("call_api", BY_ROUTER), text_reply(TYPED), text_reply(TYPED)])
    await client.post("/api/assistant/chat", json={"message": "Which router earned the most today?"},
                      headers=auth(token))
    assert len(model.requests) == 3


@pytest.mark.asyncio
async def test_money_per_router_best_first_completed_only(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    small = await make_router(db, reseller, name="Small")
    big = await make_router(db, reseller, name="Big")
    for i, (rtr, amount, status) in enumerate([
        (small, 50, MpesaTransactionStatus.completed),
        (big, 100, MpesaTransactionStatus.completed),
        (big, 200, MpesaTransactionStatus.completed),
        (big, 500, MpesaTransactionStatus.failed),
        (small, 70, MpesaTransactionStatus.expired),
    ]):
        customer = await make_customer(db, reseller, plan, rtr)
        db.add(MpesaTransaction(checkout_request_id=f"by-router-{i}", phone_number=customer.phone, amount=amount,
                                reference=f"by-router-{i}", customer_id=customer.id, plan_id=plan.id,
                                router_id=rtr.id, status=status))
    await db.commit()

    async def _current_user(_token, _db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER)

    monkeypatch.setattr(payment_routes, "get_current_user", _current_user)
    result = await payment_routes.get_mpesa_transactions_by_router(
        payment_method=None, date=None, start_date=None, end_date=None, db=db, token="t")
    assert [(r["router"], r["amount"], r["payments"], r["failed_attempts"]) for r in result["routers"]] == [
        ("Big", 300, 2, 1), ("Small", 50, 1, 1)]
    assert result["total_amount"] == 350

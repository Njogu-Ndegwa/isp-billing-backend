"""Guided setup (CR-1123-F3): the setup status the assistant reads first, the starter plans, unhide.

"Help me set up my account" gave a router setup code to accounts that had a router, blank plan
forms to accounts with no plans, and nothing at all for an account whose plans were all hidden.
"""
from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import select

from app.db.models import Plan, ResellerPaymentMethod, ResellerPaymentMethodType
from app.services.account_setup import starter_prices
from tests.factories import make_plan, make_reseller, make_router
from tests.test_assistant import (  # noqa: F401  (fixtures)
    auth, client, owner, sse_events, text_reply, tool_reply, use_model,
)


async def _status(client, token) -> dict:
    r = await client.get("/api/profile/setup-status", headers=auth(token))
    assert r.status_code == 200, r.text
    return r.json()


def _steps(status: dict) -> dict:
    return {s["key"]: s["state"] for s in status["steps"]}


async def _payment_method(db, reseller, router=None):
    pm = ResellerPaymentMethod(user_id=reseller.id, method_type=ResellerPaymentMethodType.MPESA_TILL,
                               label="Shop till", mpesa_till_number="123456", is_active=True)
    db.add(pm)
    await db.commit()
    await db.refresh(pm)
    if router is not None:
        router.payment_method_id = pm.id
        await db.commit()
    return pm


@pytest.mark.asyncio
async def test_router_and_hidden_plans_report_plans_hidden_not_a_router_code(client, owner, db):
    reseller, token = owner
    await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=datetime.utcnow())
    hidden = [await make_plan(db, reseller, name=f"Static {n}M", is_hidden=True) for n in (3, 5)]

    status = await _status(client, token)

    assert _steps(status)["router"] == "done"
    plans = next(s for s in status["steps"] if s["key"] == "plans")
    assert plans["state"] == "problem" and "hidden" in plans["detail"]
    nxt = status["next"]
    assert nxt["step"] == "plans"
    assert nxt["propose"]["path"] == "/api/plans/unhide"
    assert nxt["propose"]["body"]["plan_ids"] == [p.id for p in hidden]
    assert "/api/provision/create" not in str(status)
    assert status["set_up"] is False

    # the proposal does what it says
    r = await client.post("/api/plans/unhide", json=nxt["propose"]["body"], headers=auth(token))
    assert r.status_code == 200 and r.json()["count"] == 2
    assert _steps(await _status(client, token))["plans"] == "done"


@pytest.mark.asyncio
async def test_first_plan_proposal_is_a_filled_starter_set(client, owner, db):
    reseller, token = owner
    await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=datetime.utcnow())

    status = await _status(client, token)

    assert status["next"]["step"] == "plans"
    propose = status["next"]["propose"]
    assert propose["path"] == "/api/plans/starter-set"
    body = propose["body"]
    assert body == {"price_1_hour": 10, "price_3_hours": 20, "price_24_hours": 50, "price_1_week": 250,
                    "speed": "5M/5M", "max_shared_users": 1}
    assert "KES" in propose["summary"]

    r = await client.post("/api/plans/starter-set", json=body, headers=auth(token))
    assert r.status_code == 200, r.text
    assert [p["name"] for p in r.json()["created"]] == ["1 Hour", "3 Hours", "24 Hours", "1 Week"]
    plans = (await db.execute(select(Plan).where(Plan.user_id == reseller.id))).scalars().all()
    assert {p.name: (p.price, p.duration_value, p.duration_unit.value, p.is_hidden) for p in plans} == {
        "1 Hour": (10, 1, "HOURS", False), "3 Hours": (20, 3, "HOURS", False),
        "24 Hours": (50, 24, "HOURS", False), "1 Week": (250, 7, "DAYS", False)}
    # sending it again creates nothing twice
    again = (await client.post("/api/plans/starter-set", json=body, headers=auth(token))).json()
    assert again["created"] == [] and len(again["skipped_existing"]) == 4


def test_starter_prices_follow_the_market():
    assert starter_prices("KE") == {"price_1_hour": 10, "price_3_hours": 20, "price_24_hours": 50,
                                    "price_1_week": 250}
    ug = starter_prices("UG")
    assert ug["price_1_hour"] < ug["price_3_hours"] < ug["price_24_hours"] < ug["price_1_week"]
    assert ug["price_1_hour"] == 300  # about KES 10 in UGX, rounded to a price people quote


@pytest.mark.asyncio
async def test_payment_step_asks_one_question_before_the_form(client, owner, db):
    reseller, token = owner
    await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=datetime.utcnow())
    await make_plan(db, reseller, name="Daily 50", price=50)

    nxt = (await _status(client, token))["next"]
    assert nxt["step"] == "payments"
    assert nxt["ask"] == "Do your customers pay to a Paybill, a Till, or a bank?"
    assert nxt["answers"] == {"Paybill": "mpesa_paybill", "Till": "mpesa_till", "Bank": "bank_account"}
    assert "propose" not in nxt and nxt["then"]["path"] == "/api/payment-methods"


@pytest.mark.asyncio
async def test_an_account_with_everything_done_is_set_up(client, owner, db):
    reseller, token = owner
    reseller.support_phone = "0700000000"
    await db.commit()
    router = await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=datetime.utcnow())
    await make_plan(db, reseller, name="Daily 50", price=50)
    await _payment_method(db, reseller, router)

    status = await _status(client, token)

    assert status["set_up"] is True and status["next"] is None
    assert set(_steps(status).values()) == {"done"}


@pytest.mark.asyncio
async def test_offline_router_is_a_problem_and_never_a_new_setup_code(client, owner, db):
    reseller, token = owner
    router = await make_router(db, reseller, name="Shop", last_status=False, last_checked_at=datetime.utcnow())

    status = await _status(client, token)

    step = next(s for s in status["steps"] if s["key"] == "router")
    assert step["state"] == "problem" and "offline" in step["detail"]
    assert status["next"]["read"]["path"] == f"/api/routers/{router.id}/checkup"
    assert "/api/provision/create" not in str(status)

    other = await make_reseller(db, email="fresh@example.com")
    from datetime import timedelta

    from app.api.auth_routes import login_token_claims
    from app.services.auth import create_access_token
    fresh = await _status(client, create_access_token(login_token_claims(other), timedelta(hours=1)))
    assert fresh["next"]["step"] == "router"
    assert fresh["next"]["propose"]["path"] == "/api/provision/create"


@pytest.mark.asyncio
async def test_setup_chat_reads_the_status_and_proposes_the_filled_starter_set(client, owner, db):
    reseller, token = owner
    await make_router(db, reseller, name="Shop", last_status=True, last_checked_at=datetime.utcnow())
    starter = {"price_1_hour": 10, "price_3_hours": 20, "price_24_hours": 50, "price_1_week": 250,
               "speed": "5M/5M", "max_shared_users": 1}
    model = use_model([
        tool_reply("call_api", {"method": "GET", "path": "/api/profile/setup-status"}, "tu_s"),
        tool_reply("describe_action", {"method": "POST", "path": "/api/plans/starter-set"}, "tu_d"),
        tool_reply("call_api", {"method": "POST", "path": "/api/plans/starter-set", "form": True,
                                "body": starter, "summary": "Create 4 hotspot plans"}, "tu_c"),
        text_reply("Your router is online. Next: your first plans. Tap Confirm to create them."),
    ])
    r = await client.post("/api/assistant/chat", json={"message": "Help me set up my account"},
                          headers=auth(token))
    events = sse_events(r.text)

    system = model.requests[0]["system"][0]["text"]
    assert "GET /api/profile/setup-status" in system and "POST /api/plans/starter-set" in system
    status = __import__("json").loads(model.requests[1]["messages"][-1]["content"][0]["content"])
    assert status["data"]["next"]["propose"]["body"] == starter
    card = next(e for e in events if e["type"] == "action")
    assert card["path"] == "/api/plans/starter-set"
    values = {f["name"]: f.get("value") for f in card["form"]}
    assert values["price_1_hour"] == 10 and values["price_1_week"] == 250 and values["speed"] == "5M/5M"

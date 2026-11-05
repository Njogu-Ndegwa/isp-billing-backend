"""The guards on the public PPPoE expired page: rate limits, which plan can be
charged, and that the wall holds against the usage jobs. See
app/services/pppoe_expired_guards.py.
"""

import json
from datetime import datetime, timedelta
from typing import List

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.pppoe_expired_routes as routes
from app.config import settings
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    FupAction,
    MpesaTransaction,
    SubscriptionStatus,
)
from app.services import fup
from app.services import pppoe_expired_guards as guards
from app.services import pppoe_expired_redirect as rx
from app.services.account_numbers import luhn_check_digit
from app.services.c2b_handler import SUCCESS_RESPONSE, handle_confirmation
from app.services.customer_pay_by_mpesa import _pending_plan_id
from app.services.plan_cache import invalidate_plan_cache
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.fake_routeros import FakeRouterOS, typical_router_menus

pytestmark = pytest.mark.asyncio


class _Stk:
    def __init__(self, n):
        self.checkout_request_id = f"ws_CO_{n}"
        self.merchant_request_id = f"m_{n}"


@pytest_asyncio.fixture(autouse=True)
async def clean_state():
    guards.reset_limits()
    await invalidate_plan_cache()
    yield
    guards.reset_limits()
    await invalidate_plan_cache()


@pytest_asyncio.fixture
async def client(db, monkeypatch, session_factory):
    monkeypatch.setattr(routes.db_module, "async_session", session_factory)

    async def _db():
        yield db

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = _db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
def stk(monkeypatch):
    sent: List[dict] = []

    async def fake_stk(**kwargs):
        sent.append(kwargs)
        return _Stk(len(sent))

    monkeypatch.setattr("app.services.mpesa.initiate_stk_push", fake_stk)
    return sent


async def _setup(db, *, redirect=True, plan_kwargs=None, status=CustomerStatus.INACTIVE, username="jane"):
    reseller = await make_reseller(db, business_name="FastNet", subscription_status=SubscriptionStatus.ACTIVE)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, speed="10Mbps",
                           price=1500, name="Home 10M", **(plan_kwargs or {}))
    router = await make_router(db, reseller, ip_address="10.0.3.17", pppoe_expired_redirect=redirect)
    base = "100007"
    customer = await make_customer(
        db, reseller, plan, router, status=status, expiry=datetime.utcnow() - timedelta(minutes=10),
        mac_address=None, pppoe_username=username, pppoe_password=f"pw-{username}",
        name="Jane Wanjiku", phone="0712345678",
        account_number=base + str(len(username)) + luhn_check_digit(base + str(len(username))),
    )
    return reseller, plan, router, customer


async def _forget_recent_prompts(session_factory):
    """Move the prompts out of the 3-minute "still on the phone" window."""
    async with session_factory() as s:
        for txn in (await s.execute(select(MpesaTransaction))).scalars():
            txn.created_at = datetime.utcnow() - timedelta(hours=1)
        await s.commit()
    for key in list(guards._hits):
        if key[0] == "prompt-customer":
            guards._hits[key] = type(guards._hits[key])(t - 60 for t in guards._hits[key])


# ---------------------------------------------------------------------------
# Which plan and amount can be charged
# ---------------------------------------------------------------------------


async def test_pay_refuses_a_hidden_plan_the_page_does_not_offer(db, client, stk):
    """Another customer's private price is out of reach, even with its plan id."""
    reseller, _, router, _ = await _setup(db)
    private = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=100,
                              name="Private deal", is_hidden=True)

    resp = await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": private.id})

    assert resp.status_code == 400
    assert stk == []


async def test_pay_still_takes_the_customers_own_hidden_plan(db, client, stk):
    _, plan, router, _ = await _setup(db, plan_kwargs={"is_hidden": True})

    resp = await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": plan.id})

    assert resp.status_code == 200, resp.text
    assert stk[0]["amount"] == 1500


async def test_a_prompt_nobody_paid_cannot_change_what_paybill_renews(db, session_factory, client, stk):
    """Someone who knows a username picks a dearer plan and ignores the prompt.
    The customer's usual paybill payment still renews their own plan."""
    reseller, plan, router, customer = await _setup(db)
    dearer = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=9000, name="Big")
    resp = await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": dearer.id, "phone": "0799000111"})
    assert resp.status_code == 200, resp.text
    async with session_factory() as s:
        assert _pending_plan_id(await s.get(Customer, customer.id)) is None  # the paybill card ignores it

    bg = BackgroundTasks()
    bg.add_task = lambda *a, **k: None  # type: ignore[assignment]
    assert await handle_confirmation({
        "TransactionType": "Pay Bill", "TransID": "RXP100", "TransTime": "20261105120000",
        "TransAmount": "1500", "BusinessShortCode": settings.MPESA_SHORTCODE,
        "BillRefNumber": customer.account_number, "MSISDN": "254712345678",
        "FirstName": "Jane", "LastName": "W",
    }, db, background_tasks=bg) == SUCCESS_RESPONSE

    async with session_factory() as s:
        refreshed = await s.get(Customer, customer.id)
        assert refreshed.plan_id == plan.id
        assert refreshed.status == CustomerStatus.ACTIVE
        assert refreshed.pending_update_data is None


async def test_paying_the_exact_amount_of_the_plan_picked_applies_it(db, session_factory, client, stk):
    reseller, _, router, customer = await _setup(db)
    bigger = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=2500, name="Home 20M")
    await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": bigger.id})

    bg = BackgroundTasks()
    bg.add_task = lambda *a, **k: None  # type: ignore[assignment]
    await handle_confirmation({
        "TransactionType": "Pay Bill", "TransID": "RXP101", "TransTime": "20261105120000",
        "TransAmount": "2500", "BusinessShortCode": settings.MPESA_SHORTCODE,
        "BillRefNumber": customer.account_number, "MSISDN": "254712345678",
        "FirstName": "Jane", "LastName": "W",
    }, db, background_tasks=bg)

    async with session_factory() as s:
        assert (await s.get(Customer, customer.id)).plan_id == bigger.id


async def test_a_public_prompt_keeps_what_others_stored_on_the_customer(db, session_factory, client, stk):
    """An imported customer's metadata lives in the same column."""
    reseller, _, router, customer = await _setup(db)
    bigger = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=2500, name="Home 20M")
    customer.pending_update_data = {"pppoe_import": {"file": "x.csv"}}
    await db.commit()

    await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})
    async with session_factory() as s:
        assert (await s.get(Customer, customer.id)).pending_update_data == {"pppoe_import": {"file": "x.csv"}}

    await _forget_recent_prompts(session_factory)
    await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": bigger.id})
    async with session_factory() as s:
        stored = (await s.get(Customer, customer.id)).pending_update_data
    stored = json.loads(stored) if isinstance(stored, str) else stored
    assert stored["pppoe_import"] == {"file": "x.csv"} and stored["plan_id"] == bigger.id


async def test_drop_unpaid_page_plan_only_touches_page_entries():
    class C:
        pending_update_data = json.dumps({"plan_id": 7})

    guards.drop_unpaid_page_plan(C, 100)
    assert json.loads(C.pending_update_data) == {"plan_id": 7}  # the old flows are untouched

    guards.set_page_plan(C, plan_id=8, amount=500)
    guards.drop_unpaid_page_plan(C, "500.00")
    assert json.loads(C.pending_update_data)["plan_id"] == 8

    guards.drop_unpaid_page_plan(C, 400)
    assert C.pending_update_data is None or "source" not in json.loads(C.pending_update_data)


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


async def test_wrong_usernames_get_blocked_per_caller_on_every_endpoint(db, client):
    _, _, router, _ = await _setup(db)
    url = f"/api/public/pppoe/expired/{router.id}"

    for i in range(guards.MAX_LOOKUP_MISSES_PER_CALLER):
        resp = await client.get(url, params={"u": f"guess{i}"})
        assert resp.status_code == 200 and resp.json()["lookup"] == "not_found"

    # A correct guess now can't be told apart from a wrong one, on any endpoint.
    assert (await client.get(url, params={"u": "jane"})).status_code == 429
    assert (await client.get(f"{url}/status", params={"u": "jane"})).status_code == 429
    assert (await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane"})).status_code == 429


async def test_rotating_callers_still_hit_the_router_ceiling(db, client):
    """The IP can be faked or rotated; the router-wide count can't."""
    _, _, router, _ = await _setup(db)
    url = f"/api/public/pppoe/expired/{router.id}"

    for i in range(guards.MAX_LOOKUP_MISSES_PER_ROUTER):
        resp = await client.get(url, params={"u": f"guess{i}"}, headers={"cf-connecting-ip": f"10.1.{i}.1"})
        assert resp.status_code == 200

    blocked = await client.get(url, params={"u": "jane"}, headers={"cf-connecting-ip": "10.9.9.9"})
    assert blocked.status_code == 429


async def test_correct_lookups_and_polls_never_count_as_misses(db, client):
    _, _, router, _ = await _setup(db)
    for _ in range(guards.MAX_LOOKUP_MISSES_PER_CALLER + 5):
        assert (await client.get(f"/api/public/pppoe/expired/{router.id}/status",
                                 params={"u": "jane"})).status_code == 200


async def test_request_flood_from_one_caller_is_refused(db, client, monkeypatch):
    _, _, router, _ = await _setup(db)
    monkeypatch.setattr(guards, "MAX_REQUESTS_PER_CALLER", 3)
    url = f"/api/public/pppoe/expired/{router.id}"
    assert [(await client.get(url)).status_code for _ in range(4)] == [200, 200, 200, 429]


async def test_prompts_to_one_customer_are_capped_even_when_each_one_fails(db, session_factory, client, stk):
    _, _, router, _ = await _setup(db)
    url = "/api/public/pppoe/expired/pay"

    for i in range(guards.MAX_PROMPTS_PER_CUSTOMER):
        assert (await client.post(url, json={"router_id": router.id, "username": "jane"})).status_code == 200
        await _forget_recent_prompts(session_factory)

    refused = await client.post(url, json={"router_id": router.id, "username": "jane"})
    assert refused.status_code == 429
    assert len(stk) == guards.MAX_PROMPTS_PER_CUSTOMER


async def test_a_second_prompt_straight_away_is_refused_before_any_row_exists(db, client, stk):
    """The transaction row is written after Safaricom answers, so the database
    guard alone lets two requests at the same moment both through."""
    _, _, router, customer = await _setup(db)
    guards.claim_prompt(customer.id, "254700000000", "x")  # the first request, still at Safaricom

    resp = await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})

    assert resp.status_code == 409 and stk == []


async def test_prompts_to_one_phone_are_capped_across_accounts():
    phone = "254799000111"
    for customer_id in range(1, guards.MAX_PROMPTS_PER_PHONE + 1):
        guards.claim_prompt(customer_id, phone, "x")
    with pytest.raises(HTTPException) as exc:
        guards.claim_prompt(99, phone, "x")
    assert exc.value.status_code == 429


async def test_a_failed_send_releases_the_customer(db, client, monkeypatch):
    _, _, router, customer = await _setup(db)

    async def broken(**kwargs):
        raise RuntimeError("safaricom down")

    monkeypatch.setattr("app.services.mpesa.initiate_stk_push", broken)
    resp = await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})

    assert resp.status_code == 502
    assert customer.id not in guards._prompts_in_flight


def _request_with(headers):
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "headers": raw, "client": ("172.18.0.1", 1)})


async def test_caller_key_sees_through_the_portal_proxy():
    # Direct, via Cloudflare.
    assert guards.caller_key(_request_with({"cf-connecting-ip": "41.90.1.1"})) == "41.90.1.1"
    # Through /api/bw Cloudflare reports Vercel; the customer is in x-forwarded-for.
    assert guards.caller_key(_request_with({
        "cf-connecting-ip": "76.76.21.9", "x-bw-proxy": "1", "x-forwarded-for": "41.90.1.1, 76.76.21.9",
    })) == "41.90.1.1"


# ---------------------------------------------------------------------------
# The usage jobs and the wall
# ---------------------------------------------------------------------------


async def _capped_period(db, customer, *, used_mb, triggered=False):
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(days=30), period_end=now + timedelta(days=30),
        total_bytes=used_mb * 1024 * 1024, upload_bytes=0, download_bytes=used_mb * 1024 * 1024,
        cap_mb_snapshot=100, fup_action_snapshot=FupAction.THROTTLE,
        fup_triggered_at=now - timedelta(days=1) if triggered else None,
        fup_action_taken=FupAction.THROTTLE if triggered else None,
    )
    db.add(period)
    await db.commit()
    return period


def _spy_on_router_actions(monkeypatch):
    calls = []

    async def spy(name):
        calls.append(name)
        return {"success": True}

    async def throttle(*a, **k):
        return await spy("throttle")

    async def block(*a, **k):
        return await spy("block")

    async def restore(*a, **k):
        return await spy("restore")

    monkeypatch.setattr(fup, "apply_throttle", throttle)
    monkeypatch.setattr(fup, "apply_block", block)
    monkeypatch.setattr(fup, "restore_normal_profile", restore)
    return calls


CAPPED = {"data_cap_mb": 100, "fup_action": FupAction.THROTTLE}


async def test_going_over_the_cap_does_not_move_a_walled_customer_off_the_wall(db, monkeypatch):
    _, plan, _, customer = await _setup(db, plan_kwargs=CAPPED)
    period = await _capped_period(db, customer, used_mb=500)
    calls = _spy_on_router_actions(monkeypatch)

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) is None
    assert calls == []


async def test_a_stale_trigger_does_not_restore_the_plan_profile_for_a_walled_customer(db, monkeypatch):
    _, plan, _, customer = await _setup(db, plan_kwargs=CAPPED)
    period = await _capped_period(db, customer, used_mb=1, triggered=True)
    calls = _spy_on_router_actions(monkeypatch)

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) is None
    assert calls == []


async def test_fup_on_routers_without_the_switch_decides_exactly_as_before(db, monkeypatch):
    _, plan, _, customer = await _setup(db, redirect=False, plan_kwargs=CAPPED)
    period = await _capped_period(db, customer, used_mb=500)
    calls = _spy_on_router_actions(monkeypatch)

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) == FupAction.THROTTLE
    assert calls == ["throttle"]


async def test_fup_still_applies_to_a_paying_customer_on_a_router_with_the_switch(db, monkeypatch):
    _, plan, _, customer = await _setup(db, plan_kwargs=CAPPED, status=CustomerStatus.ACTIVE)
    customer.expiry = datetime.utcnow() + timedelta(days=10)
    await db.commit()
    period = await _capped_period(db, customer, used_mb=500)
    calls = _spy_on_router_actions(monkeypatch)

    assert await fup.evaluate_and_enforce(db, customer, period, plan=plan) == FupAction.THROTTLE
    assert calls == ["throttle"]


async def test_walling_enables_a_secret_a_fup_block_left_disabled():
    api = FakeRouterOS(typical_router_menus())
    api.menus["/ppp/secret"].append({
        ".id": "*50", "name": "jane", "password": "x", "profile": "pppoe_10M_10M", "disabled": "true",
    })

    out = rx.wall_pppoe_users(api, [{"id": 1, "pppoe_username": "jane"}])

    assert out[1]["ok"]
    secret = api.rows("/ppp/secret", name="jane")[0]
    assert secret["profile"] == rx.EXPIRED_PROFILE and secret["disabled"] == "no"

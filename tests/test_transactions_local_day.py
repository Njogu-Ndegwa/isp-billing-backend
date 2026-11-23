"""A date in a payments query is the reseller's own calendar day.

Chat review 2026-11-23 (CR-1123-B2): at 00:56 EAT on Mon 23 Nov a Kenyan
reseller asked the assistant how much had come in. The model sent
``date=2026-11-22`` (the UTC date in its message header) and answered
"Today (Sun 22 Nov)"; the result held a payment stamped 21:53 UTC on the
22nd, which is 00:53 on the 23rd in Nairobi. ``date`` was a UTC day, so
payments between local midnight and 03:00 landed in the previous day, on the
Transactions page as well (it sends the day the person picked, as it is).

Now a date without a time is that calendar day in the account's market time
zone, in all three payment listings; a time written with its offset is that
exact moment whoever asks; a time without one is UTC, as the API's own are.
"""

from datetime import datetime

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.payment_routes as pr
from app.db.database import get_db
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
)
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(pr.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(pr, "get_current_user", _fake)


# Every row has its own amount, so a set of amounts names the rows returned.
#                       UTC                              Nairobi (UTC+3)     Douala (UTC+1)
EVENING = 30.0        # Sun 22 Nov 15:00                 Sun 22 18:00        Sun 22 16:00
FAILED_EVENING = 12.0  # Sun 22 Nov 18:00, failed prompt  Sun 22 21:00        Sun 22 19:00
PAYBILL = 40.0        # Sun 22 Nov 21:10, paybill        Mon 23 00:10        Sun 22 22:10
FAILED_NIGHT = 11.0   # Sun 22 Nov 21:20, failed prompt  Mon 23 00:20        Sun 22 22:20
AFTER_MIDNIGHT = 50.0  # Sun 22 Nov 21:53 (the evidence)  Mon 23 00:53        Sun 22 22:53
LATE_NIGHT = 60.0     # Sun 22 Nov 23:30                 Mon 23 02:30        Mon 23 00:30
CASH_LATE = 20.0      # Mon 23 Nov 20:30, cash           Mon 23 23:30        Mon 23 21:30
CASH_NEXT_DAY = 70.0  # Mon 23 Nov 21:30, cash           Tue 24 00:30        Mon 23 22:30


async def _seed(db, market_code="KE"):
    reseller = await make_reseller(db, market_code=market_code)
    plan = await make_plan(db, reseller, price=50)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan=plan, router=router)

    def prompt(amount, at, status=MpesaTransactionStatus.completed):
        db.add(MpesaTransaction(
            checkout_request_id=f"ws_CO_{int(amount)}", phone_number="254700000001", amount=amount,
            reference=f"R{int(amount)}", customer_id=customer.id, plan_id=plan.id, status=status,
            created_at=at,
        ))

    def cash(amount, at):
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, plan_id=plan.id, amount=amount,
            payment_method=PaymentMethod.CASH, days_paid_for=1, status=PaymentStatus.COMPLETED,
            payment_reference=f"CASH{int(amount)}", created_at=at,
        ))

    prompt(EVENING, datetime(2026, 11, 22, 15, 0))
    prompt(FAILED_EVENING, datetime(2026, 11, 22, 18, 0), MpesaTransactionStatus.failed)
    db.add(C2BTransaction(
        trans_id="C2B40", trans_amount=PAYBILL, bill_ref_number="ACC40", business_shortcode="123456",
        matched_customer_id=customer.id, matched_reseller_id=reseller.id,
        status=C2BTransactionStatus.PROCESSED, received_at=datetime(2026, 11, 22, 21, 10),
    ))
    prompt(FAILED_NIGHT, datetime(2026, 11, 22, 21, 20), MpesaTransactionStatus.failed)
    prompt(AFTER_MIDNIGHT, datetime(2026, 11, 22, 21, 53))
    prompt(LATE_NIGHT, datetime(2026, 11, 22, 23, 30))
    cash(CASH_LATE, datetime(2026, 11, 23, 20, 30))
    cash(CASH_NEXT_DAY, datetime(2026, 11, 23, 21, 30))
    await db.commit()
    return reseller


async def _amounts(client, path="/api/mpesa/transactions", **params):
    resp = await client.get(path, params=params)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    rows = body["transactions"] if isinstance(body, dict) else body
    return {row["amount"] for row in rows}


async def _summary(client, **params):
    resp = await client.get("/api/mpesa/transactions/summary", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- the evidence: 21:53 UTC on the 22nd is the 23rd in Nairobi ----------------

async def test_a_payment_just_after_local_midnight_is_in_that_local_day(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    monday = await _amounts(client, date="2026-11-23")
    sunday = await _amounts(client, date="2026-11-22")

    assert AFTER_MIDNIGHT in monday and AFTER_MIDNIGHT not in sunday
    assert monday == {PAYBILL, FAILED_NIGHT, AFTER_MIDNIGHT, LATE_NIGHT, CASH_LATE}
    assert sunday == {EVENING, FAILED_EVENING}
    # 00:30 on Tuesday in Nairobi, still Monday in UTC
    assert await _amounts(client, date="2026-11-24") == {CASH_NEXT_DAY}


async def test_start_and_end_dates_mean_the_same_days_as_date(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    assert await _amounts(client, start_date="2026-11-23", end_date="2026-11-23") == \
        await _amounts(client, date="2026-11-23")
    assert await _amounts(client, start_date="2026-11-22", end_date="2026-11-23") == {
        EVENING, FAILED_EVENING, PAYBILL, FAILED_NIGHT, AFTER_MIDNIGHT, LATE_NIGHT, CASH_LATE}
    # open ended: from Monday on, and up to Sunday
    assert await _amounts(client, start_date="2026-11-23") == {
        PAYBILL, FAILED_NIGHT, AFTER_MIDNIGHT, LATE_NIGHT, CASH_LATE, CASH_NEXT_DAY}
    assert await _amounts(client, end_date="2026-11-22") == {EVENING, FAILED_EVENING}


async def test_the_summary_counts_the_same_local_day(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    monday = await _summary(client, date="2026-11-23")
    assert monday["status_breakdown"]["completed"] == {
        "count": 4, "amount": PAYBILL + AFTER_MIDNIGHT + LATE_NIGHT + CASH_LATE}
    assert monday["status_breakdown"]["failed"]["count"] == 1
    assert monday["method_breakdown"]["cash"] == {"count": 1, "amount": CASH_LATE}

    sunday = await _summary(client, date="2026-11-22")
    assert sunday["status_breakdown"]["completed"] == {"count": 1, "amount": EVENING}

    ranged = await _summary(client, start_date="2026-11-23", end_date="2026-11-23")
    assert ranged["status_breakdown"] == monday["status_breakdown"]
    assert ranged["total_transactions"] == monday["total_transactions"] == 5


async def test_failed_payments_follow_the_same_local_day(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))
    failed = "/api/mpesa/transactions/failed"

    assert await _amounts(client, failed, start_date="2026-11-23", end_date="2026-11-23") == {FAILED_NIGHT}
    assert await _amounts(client, failed, start_date="2026-11-22", end_date="2026-11-22") == {FAILED_EVENING}
    assert await _amounts(client, failed, start_date="2026-11-22", end_date="2026-11-23") == {
        FAILED_EVENING, FAILED_NIGHT}


# --- another market: Cameroon is UTC+1 -----------------------------------------

async def test_a_cameroon_account_uses_its_own_day(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db, market_code="CM"))

    sunday = await _amounts(client, date="2026-11-22")
    monday = await _amounts(client, date="2026-11-23")

    # 21:53 UTC is 22:53 in Douala: still Sunday there
    assert AFTER_MIDNIGHT in sunday and AFTER_MIDNIGHT not in monday
    assert sunday == {EVENING, FAILED_EVENING, PAYBILL, FAILED_NIGHT, AFTER_MIDNIGHT}
    # 23:30 UTC on the 22nd is 00:30 on the 23rd in Douala
    assert monday == {LATE_NIGHT, CASH_LATE, CASH_NEXT_DAY}

    summary = await _summary(client, date="2026-11-23")
    assert summary["status_breakdown"]["completed"] == {
        "count": 3, "amount": LATE_NIGHT + CASH_LATE + CASH_NEXT_DAY}
    assert await _amounts(client, "/api/mpesa/transactions/failed",
                          start_date="2026-11-23", end_date="2026-11-23") == set()


# --- a time with its offset is that moment, whoever asks -----------------------

@pytest.mark.parametrize("market_code", ["KE", "CM"])
@pytest.mark.parametrize("start, end", [
    ("2026-11-23T00:30:00+03:00", "2026-11-23T01:00:00+03:00"),   # written on the Nairobi clock
    ("2026-11-22T22:30:00+01:00", "2026-11-22T23:00:00+01:00"),   # the same half hour in Douala
    ("2026-11-22T21:30:00Z", "2026-11-22T22:00:00Z"),             # in UTC
    ("2026-11-22T21:30:00", "2026-11-22T22:00:00"),               # no offset: UTC, as before
])
async def test_a_time_with_an_offset_keeps_its_meaning(db, client, monkeypatch, market_code, start, end):
    _auth_as(monkeypatch, await _seed(db, market_code=market_code))

    assert await _amounts(client, start_date=start, end_date=end) == {AFTER_MIDNIGHT}
    summary = await _summary(client, start_date=start, end_date=end)
    assert summary["status_breakdown"] == {"completed": {"count": 1, "amount": AFTER_MIDNIGHT}}


async def test_failed_payments_accept_a_time_with_an_offset(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    assert await _amounts(client, "/api/mpesa/transactions/failed",
                          start_date="2026-11-23T00:00:00+03:00",
                          end_date="2026-11-23T00:30:00+03:00") == {FAILED_NIGHT}


async def test_a_date_that_is_not_a_date_is_still_refused(db, client, monkeypatch):
    _auth_as(monkeypatch, await _seed(db))

    assert (await client.get("/api/mpesa/transactions", params={"date": "yesterday"})).status_code == 400
    assert (await client.get("/api/mpesa/transactions", params={"start_date": "soon"})).status_code == 400
    assert (await client.get("/api/mpesa/transactions/failed", params={"end_date": "soon"})).status_code == 400


# --- plan performance reads its dates the same way -----------------------------

async def test_plan_performance_counts_the_same_local_day(db, session_factory, monkeypatch):
    import app.api.plan_routes as plr

    reseller = await _seed(db)
    _auth_as(monkeypatch, reseller)
    monkeypatch.setattr(plr, "get_current_user", pr.get_current_user)
    application = FastAPI()
    application.include_router(plr.router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        async def sales(**params):
            resp = await c.get("/api/plans/performance", params=params)
            assert resp.status_code == 200, resp.text
            return sum(p["total_sales"] for p in resp.json()["plans"])

        # cash at 23:30 on Monday in Nairobi is Monday; 00:30 on Tuesday is not
        assert await sales(start_date="2026-11-23", end_date="2026-11-23") == 1
        assert await sales(start_date="2026-11-24", end_date="2026-11-24") == 1
        assert await sales(start_date="2026-11-23T23:00:00+03:00", end_date="2026-11-24T01:00:00+03:00") == 2


# --- the bounds themselves -----------------------------------------------------

def test_day_bounds_are_local_midnights_in_utc():
    from types import SimpleNamespace

    from app.services import local_day

    kenya, cameroon = SimpleNamespace(market_code="KE"), SimpleNamespace(market_code="CM")
    start, end = local_day.day_bounds("2026-11-23", kenya)
    assert start == datetime(2026, 11, 22, 21, 0)
    assert end == datetime(2026, 11, 23, 20, 59, 59, 999999)
    assert local_day.day_bounds("2026-11-23", cameroon)[0] == datetime(2026, 11, 22, 23, 0)
    # an account with no market is Kenyan, like everywhere else
    assert local_day.day_bounds("2026-11-23", SimpleNamespace())[0] == start

    assert local_day.range_start("2026-11-23", kenya) == start
    assert local_day.range_end("2026-11-23", kenya) == end
    assert local_day.range_start("2026-11-23T00:00:00+03:00", cameroon) == datetime(2026, 11, 22, 21, 0)
    assert local_day.range_end("2026-11-22T21:00:00Z", kenya) == datetime(2026, 11, 22, 21, 0)
    assert local_day.range_end("2026-11-22T21:00:00", kenya) == datetime(2026, 11, 22, 21, 0)
    with pytest.raises(ValueError):
        local_day.range_start("soon", kenya)


# --- what the assistant is told ------------------------------------------------

def test_the_message_header_gives_the_local_date_the_way_a_query_needs_it():
    from app.services.assistant import agent

    # the moment of the evidence: 21:56 UTC on Sun 22 Nov is 00:56 on Mon 23 Nov in Nairobi
    label = agent._now_label("Africa/Nairobi", now=datetime(2026, 11, 22, 21, 56))
    assert "Mon 23 Nov 00:56 EAT" in label
    assert "their date today is 2026-11-23" in label
    # in Douala it is still Sunday
    assert "their date today is 2026-11-22" in agent._now_label("Africa/Douala", now=datetime(2026, 11, 22, 21, 56))


def test_the_instructions_say_query_dates_are_the_persons_local_dates():
    from app.services.assistant import agent

    rule = next(line for line in agent.SYSTEM_TEMPLATE.splitlines() if line.startswith("- Dates in a query"))
    assert "their date today" in rule and "never the UTC date" in rule
    assert "+03:00" in rule   # a time of day goes with its offset

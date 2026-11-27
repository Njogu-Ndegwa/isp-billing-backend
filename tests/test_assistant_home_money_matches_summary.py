"""The assistant's home screen and its chat must give the same money.

Reported 2026-11-27 (Dennis, Bitwave Soko Wifi): at 21:23 EAT the home screen
said "KES 683 today from 57 payments" while the chat, asked for today's
payments, said "KES 707 from 59". The chat was right. The home screen
(GET /api/assistant/briefing) began "today" at UTC midnight, 03:00 in Nairobi,
so the two payments (KES 24) made between local midnight and 03:00 were left
out. The chat reads GET /api/mpesa/transactions/summary, which already used
the account's own calendar day.

These tests seed one realistic ledger (STK prompts with their ledger twin,
paybill payments with theirs, cash, a comp voucher, failed and pending
attempts, another reseller's money) and ask both sides at many moments of
the day, in Kenya (UTC+3) and Cameroon (UTC+1): the totals and the payment
counts must agree every time.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

import pytest

import app.api.payment_routes as pr
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
)
from app.services.assistant import briefing
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

_SEQ = {"n": 0}


def _ref(prefix: str) -> str:
    _SEQ["n"] += 1
    return f"{prefix}{_SEQ['n']:06d}"


class Ledger:
    """Writes payments the way production does, twins included."""

    def __init__(self, db, reseller, customer, plan):
        self.db, self.reseller, self.customer, self.plan = db, reseller, customer, plan

    def stk(self, amount, at, status=MpesaTransactionStatus.completed, ledger_at=None):
        """An STK prompt; a completed one also leaves its customer_payments twin
        (written when the callback lands, ``ledger_at``: seconds later)."""
        receipt = _ref("UK")
        checkout = _ref("ws_CO_")
        self.db.add(MpesaTransaction(
            checkout_request_id=checkout, phone_number="254700000001", amount=amount,
            reference=_ref("R"), customer_id=self.customer.id, plan_id=self.plan.id, status=status,
            mpesa_receipt_number=receipt if status == MpesaTransactionStatus.completed else None,
            created_at=at,
        ))
        if status == MpesaTransactionStatus.completed:
            self.db.add(CustomerPayment(
                customer_id=self.customer.id, reseller_id=self.reseller.id, plan_id=self.plan.id,
                amount=amount, payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
                status=PaymentStatus.COMPLETED, payment_reference=receipt,
                notes=f"M-Pesa STK Push. TX: {checkout}", created_at=ledger_at or at,
            ))

    def paybill(self, amount, at, status=C2BTransactionStatus.PROCESSED, ledger_at=None):
        """A paybill payment; a processed one also leaves its customer_payments twin
        (written at once, or when someone attributes it by hand: ``ledger_at``)."""
        trans_id = _ref("PB")
        processed = status == C2BTransactionStatus.PROCESSED
        self.db.add(C2BTransaction(
            trans_id=trans_id, trans_amount=amount, bill_ref_number="ACC1", business_shortcode="4159825",
            matched_customer_id=self.customer.id if processed else None,
            matched_reseller_id=self.reseller.id if processed else None,
            status=status, received_at=at,
        ))
        if processed:
            self.db.add(CustomerPayment(
                customer_id=self.customer.id, reseller_id=self.reseller.id, plan_id=self.plan.id,
                amount=amount, payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=1,
                status=PaymentStatus.COMPLETED, payment_reference=trans_id,
                notes="M-Pesa C2B Paybill (shortcode 4159825)", created_at=ledger_at or at,
            ))

    def cash(self, amount, at, status=PaymentStatus.COMPLETED):
        self.db.add(CustomerPayment(
            customer_id=self.customer.id, reseller_id=self.reseller.id, plan_id=self.plan.id,
            amount=amount, payment_method=PaymentMethod.CASH, days_paid_for=1, status=status,
            payment_reference=_ref("CASH"), created_at=at,
        ))

    def comp(self, amount, at):
        """A free voucher: a payment, not revenue."""
        self.db.add(CustomerPayment(
            customer_id=self.customer.id, reseller_id=self.reseller.id, plan_id=self.plan.id,
            amount=amount, payment_method=PaymentMethod.OTHER, days_paid_for=1,
            status=PaymentStatus.COMPLETED, payment_reference=_ref("VOUCHER-"),
            counts_as_revenue=False, created_at=at,
        ))


async def _seed(db, market_code: str, utc_offset_hours: int, local_day: date):
    """Payments spread over the 15 local days ending ``local_day``, crowded around midnight."""
    reseller = await make_reseller(db, market_code=market_code, email=f"home-{market_code}@example.com")
    plan = await make_plan(db, reseller, price=20)
    router = await make_router(db, reseller, ip_address=f"10.0.{utc_offset_hours}.9")
    customer = await make_customer(db, reseller, plan, router, phone="254700000011",
                                   mac_address="AA:00:00:00:00:11")
    ledger = Ledger(db, reseller, customer, plan)

    def utc(day: date, hour: int, minute: int = 0) -> datetime:
        """A local wall time on ``day`` as naive UTC."""
        return datetime(day.year, day.month, day.day, hour, minute) - timedelta(hours=utc_offset_hours)

    amount = 10
    for back in range(15):
        day = local_day - timedelta(days=back)
        # the edges of the day: just after local midnight (still the previous
        # UTC day), the last minute before it, and the UTC midnight itself
        for hour, minute in ((0, 0), (0, 1), (0, 30), (1, 15), (2, 59), (3, 0), (utc_offset_hours, 0),
                             (12, 0), (18, 0), (21, 23), (23, 59)):
            amount += 1
            at = utc(day, hour, minute)
            kind = (hour + minute + back) % 4
            if kind == 0:
                ledger.stk(amount, at)
            elif kind == 1:
                ledger.paybill(amount, at)
            elif kind == 2:
                ledger.cash(amount, at)
            else:
                ledger.stk(amount, at)
        # what must never count as money made
        ledger.stk(500 + back, utc(day, 0, 20), MpesaTransactionStatus.failed)
        ledger.stk(600 + back, utc(day, 1, 40), MpesaTransactionStatus.expired)
        ledger.stk(700 + back, utc(day, 13, 0), MpesaTransactionStatus.pending)
        ledger.paybill(800 + back, utc(day, 0, 45), C2BTransactionStatus.UNMATCHED)
        ledger.cash(900 + back, utc(day, 1, 5), PaymentStatus.FAILED)
        ledger.cash(950 + back, utc(day, 9, 5), PaymentStatus.PENDING)
        # a comp is counted as a payment but adds nothing
        ledger.comp(70, utc(day, 0, 10))
        # found on production: a prompt sent seconds before local midnight whose
        # callback lands after it, and paybill money attributed by hand the next
        # morning; both belong to the day the money came
        ledger.stk(31 + back, utc(day, 23, 59) + timedelta(seconds=50),
                   ledger_at=utc(day, 23, 59) + timedelta(seconds=75))
        ledger.paybill(1500 + back, utc(day, 20, 26), ledger_at=utc(day, 20, 26) + timedelta(hours=10))

    other = await make_reseller(db, market_code=market_code, email=f"other-{market_code}@example.com")
    other_plan = await make_plan(db, other, price=20)
    other_customer = await make_customer(db, other, other_plan, None, phone="254700000012",
                                         mac_address="AA:00:00:00:00:12")
    Ledger(db, other, other_customer, other_plan).stk(5000, utc(local_day, 0, 5))
    await db.commit()
    return reseller


async def _summary(db, monkeypatch, reseller, **params):
    async def fake_current_user(token, db):
        return reseller

    monkeypatch.setattr(pr, "get_current_user", fake_current_user)
    args = dict(router_id=None, payment_method=None, date=None, start_date=None, end_date=None)
    args.update(params)
    return await pr.get_mpesa_transactions_summary(db=db, token="t", **args)


MARKETS = [("KE", 3), ("CM", 1)]
# local wall times on the day Dennis reported, chosen around both midnights
MOMENTS = [(0, 0), (0, 1), (0, 31), (2, 59), (3, 0), (3, 1), (12, 0), (21, 23), (23, 59)]


@pytest.mark.parametrize("market_code,offset", MARKETS)
async def test_home_money_today_equals_the_chat_summary_at_every_moment(db, monkeypatch, market_code, offset):
    local_today = date(2026, 11, 27)
    reseller = await _seed(db, market_code, offset, local_today)

    for hour, minute in MOMENTS:
        now = datetime(2026, 11, 27, hour, minute) - timedelta(hours=offset)
        clock = briefing.make_clock(reseller, now)
        assert clock.today == local_today, (hour, minute)

        money = await briefing._money(db, reseller.id, clock)
        # The chat asks the summary for "today" as a date: the whole local day.
        summary = await _summary(db, monkeypatch, reseller, date=local_today.isoformat())
        assert money["today"] == summary["total_amount"], (market_code, hour, minute)
        assert money["payments_today"] == summary["total_transactions"], (market_code, hour, minute)


@pytest.mark.parametrize("market_code,offset", MARKETS)
async def test_every_past_day_week_and_month_match_the_summary(db, monkeypatch, market_code, offset):
    local_today = date(2026, 11, 27)
    reseller = await _seed(db, market_code, offset, local_today)
    end_of_today = datetime(2026, 11, 27, 23, 59, 59) - timedelta(hours=offset)
    money = await briefing._money(db, reseller.id, briefing.make_clock(reseller, end_of_today))

    for item in money["daily"]:
        summary = await _summary(db, monkeypatch, reseller, date=item["day"])
        assert item["revenue"] == summary["total_amount"], (market_code, item["day"])
        assert item["payments"] == summary["total_transactions"], (market_code, item["day"])

    last7 = await _summary(db, monkeypatch, reseller, start_date="2026-11-21", end_date="2026-11-27")
    prev7 = await _summary(db, monkeypatch, reseller, start_date="2026-11-14", end_date="2026-11-20")
    month = await _summary(db, monkeypatch, reseller, start_date="2026-11-01", end_date="2026-11-27")
    assert money["last7"] == last7["total_amount"]
    assert money["prev7"] == prev7["total_amount"]
    assert money["month"] == month["total_amount"]
    assert money["yesterday"] == (await _summary(db, monkeypatch, reseller, date="2026-11-26"))["total_amount"]


async def test_the_reported_evening_two_payments_after_local_midnight_are_today(db):
    """The numbers from the report: KES 24 in two payments between 00:00 and 03:00 EAT."""
    reseller = await make_reseller(db, market_code="KE", email="soko@example.com")
    plan = await make_plan(db, reseller, price=10)
    router = await make_router(db, reseller, ip_address="10.0.0.77")
    customer = await make_customer(db, reseller, plan, router, phone="254700000013",
                                   mac_address="AA:00:00:00:00:13")
    ledger = Ledger(db, reseller, customer, plan)
    ledger.stk(10, datetime(2026, 11, 26, 21, 5))    # 00:05 EAT on the 27th
    ledger.stk(14, datetime(2026, 11, 26, 23, 40))   # 02:40 EAT on the 27th
    ledger.stk(30, datetime(2026, 11, 27, 8, 0))     # 11:00 EAT
    ledger.stk(99, datetime(2026, 11, 26, 20, 59))   # 23:59 EAT on the 26th: yesterday
    await db.commit()

    clock = briefing.make_clock(reseller, datetime(2026, 11, 27, 18, 23))   # 21:23 EAT
    money = await briefing._money(db, reseller.id, clock)
    assert money["today"] == 54 and money["payments_today"] == 3
    assert money["yesterday"] == 99
    assert money["daily"][-1]["day"] == "2026-11-27"


async def test_plans_and_expiring_today_follow_the_local_day(db):
    reseller = await make_reseller(db, market_code="KE", email="plans@example.com")
    plan = await make_plan(db, reseller, name="Daily 20", price=20)
    router = await make_router(db, reseller, ip_address="10.0.0.78")
    now = datetime(2026, 11, 27, 18, 23)   # 21:23 EAT; local midnight is 21:00 UTC
    # expires 23:30 EAT tonight (20:30 UTC): today on the account's clock
    tonight = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                                  expiry=datetime(2026, 11, 27, 20, 30), phone="254700000014",
                                  mac_address="AA:00:00:00:00:14", name="Tonight")
    # expires 01:00 EAT tomorrow (22:00 UTC, still the 27th in UTC): not today
    await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                        expiry=datetime(2026, 11, 27, 22, 0), phone="254700000015",
                        mac_address="AA:00:00:00:00:15", name="After midnight")
    ledger = Ledger(db, reseller, tonight, plan)
    ledger.stk(20, datetime(2026, 11, 20, 21, 30))   # 00:30 EAT on the 21st: inside the 7 days
    ledger.stk(20, datetime(2026, 11, 20, 20, 30))   # 23:30 EAT on the 20th: outside
    ledger.cash(20, datetime(2026, 11, 27, 10, 0), PaymentStatus.FAILED)   # not a sale
    await db.commit()

    clock = briefing.make_clock(reseller, now)
    customers = await briefing._customers(db, reseller.id, clock)
    assert customers["expiring_today"] == 1
    plans = await briefing._plans(db, reseller.id, clock)
    assert plans == [{"name": "Daily 20", "revenue": 20, "sales": 1}]


async def test_money_counts_the_moment_it_came_not_when_the_ledger_was_written(db):
    """Seen on production on 27 Nov: a 23:59:50 prompt whose callback landed at
    00:00:15, and a paybill payment received at 23:26 and attributed by hand at
    07:01 the next morning. The chat put both in the day the money came, the
    home screen in the day the ledger row was written."""
    reseller = await make_reseller(db, market_code="KE", email="drift@example.com")
    plan = await make_plan(db, reseller, price=20)
    router = await make_router(db, reseller, ip_address="10.0.0.79")
    customer = await make_customer(db, reseller, plan, router, phone="254700000016",
                                   mac_address="AA:00:00:00:00:16")
    ledger = Ledger(db, reseller, customer, plan)
    ledger.stk(20, datetime(2026, 11, 26, 20, 59, 50), ledger_at=datetime(2026, 11, 26, 21, 0, 15))
    ledger.paybill(1500, datetime(2026, 11, 26, 20, 26), ledger_at=datetime(2026, 11, 27, 4, 1))
    await db.commit()

    money = await briefing._money(db, reseller.id, briefing.make_clock(reseller, datetime(2026, 11, 27, 18, 23)))
    assert money["yesterday"] == 1520 and money["today"] == 0 and money["payments_today"] == 0


# --- every screen, every day: the classic dashboard too (Dennis, 2026-11-27) -----

async def _classic(db, monkeypatch, reseller, now_utc):
    """The classic dashboard's endpoints, called as that reseller at ``now_utc``."""
    from app.api import dashboard_routes as dr

    async def fake_current_user(token, db):
        return reseller

    monkeypatch.setattr(dr, "get_current_user", fake_current_user)
    monkeypatch.setattr(dr, "_utcnow", lambda: now_utc)
    return dr


@pytest.mark.parametrize("market_code,offset", MARKETS)
async def test_every_screen_gives_the_same_money_for_every_day(db, monkeypatch, market_code, offset):
    """Chat (transactions summary), home screen, and the classic dashboard's
    analytics, revenue chart, daily-transactions chart, day breakdown, stats and
    overview: the same seeded ledger must give the same money and the same
    number of payments for each day on all of them."""
    local_today = date(2026, 11, 27)
    reseller = await _seed(db, market_code, offset, local_today)
    now = datetime(2026, 11, 27, 23, 59, 59) - timedelta(hours=offset)   # the last second of the local day
    dr = await _classic(db, monkeypatch, reseller, now)

    home = await briefing._money(db, reseller.id, briefing.make_clock(reseller, now))
    first, last = home["daily"][0]["day"], home["daily"][-1]["day"]
    chart = await dr.get_revenue_over_time(period=None, start_date=first, end_date=last, router_id=None,
                                           db=db, token="t")
    counts = await dr.get_daily_transaction_counts(period=None, start_date=first, end_date=last, router_id=None,
                                                   payment_method=None, status="completed", by_port=False,
                                                   db=db, token="t")
    chart_by_day = {p["date"]: p for p in chart["data"]}
    counts_by_day = {p["date"]: p for p in counts["data"]}

    for item in home["daily"]:
        day = item["day"]
        chat = await _summary(db, monkeypatch, reseller, date=day)
        analytics = await dr.get_dashboard_analytics(router_id=None, days=None, start_date=day, end_date=day,
                                                     preset=None, db=db, token="t")
        breakdown = await dr.get_daily_revenue_metrics(router_id=None, date=day, db=db, token="t")
        want = (chat["total_amount"], chat["total_transactions"])
        seen = {
            "home": (item["revenue"], item["payments"]),
            "analytics": (analytics["summary"]["totalRevenue"], analytics["summary"]["totalTransactions"]),
            "revenue_chart": (chart_by_day[day]["revenue"], chart_by_day[day]["transactions"]),
            "transactions_chart": (counts_by_day[day]["revenue"], counts_by_day[day]["transactions"]),
            "day_breakdown": (breakdown["summary"]["total_revenue"] if "summary" in breakdown
                              else breakdown["total_revenue"],
                              breakdown["summary"]["total_transactions"] if "summary" in breakdown
                              else breakdown["total_transactions"]),
        }
        for screen, got in seen.items():
            assert got == pytest.approx(want), (market_code, day, screen, got, want)
        assert want[1] > 0   # every day has payments, so a match is not two zeros

    today_chat = await _summary(db, monkeypatch, reseller, date=local_today.isoformat())
    stats = await dr.get_dashboard_stats(router_id=None, period=30, db=db, token="t")
    assert (stats["today"]["revenue"], stats["today"]["transactions"]) == pytest.approx(
        (today_chat["total_amount"], today_chat["total_transactions"]))
    overview = await dr.get_dashboard_overview(router_id=None, db=db, token="t")
    assert overview["revenue"]["today"] == pytest.approx(today_chat["total_amount"])
    month_chat = await _summary(db, monkeypatch, reseller, start_date="2026-11-01", end_date="2026-11-27")
    assert overview["revenue"]["this_month"] == pytest.approx(month_chat["total_amount"])
    assert home["month"] == pytest.approx(month_chat["total_amount"])

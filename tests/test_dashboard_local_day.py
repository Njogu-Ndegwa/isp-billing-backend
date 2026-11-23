"""Dashboard overview, daily revenue and revenue over time count local days.

Follow-up to CR-1123-B2 (chat review 2026-11-23): at 00:56 EAT on Mon 23 Nov a
Kenyan reseller's "today" was still Sunday, because these three endpoints cut
days at UTC midnight (03:00 in Nairobi). They now use the account's market
time zone through app.services.local_day, like /api/dashboard/analytics.
"""
from datetime import datetime
from types import SimpleNamespace

from app.api import dashboard_routes
from app.db.models import CustomerPayment, PaymentMethod, PaymentStatus, UserRole
from tests.factories import make_customer, make_plan, make_reseller, make_router

# Mon 23 Nov 00:56 in Nairobi, Sun 22 Nov 22:56 in Douala
NOW_UTC = datetime(2026, 11, 22, 21, 56)

#                        UTC                    Nairobi (UTC+3)    Douala (UTC+1)
OCT_LAST = 7.0         # Sat 31 Oct 22:00      Sun 1 Nov 01:00    Sat 31 Oct 23:00
SUNDAY = 30.0          # Sun 22 Nov 15:00      Sun 22 18:00       Sun 22 16:00
AFTER_MIDNIGHT = 50.0  # Sun 22 Nov 21:53      Mon 23 00:53       Sun 22 22:53


async def _seed(db, market_code="KE"):
    reseller = await make_reseller(db, email=f"dash-{market_code}@example.com", market_code=market_code)
    plan = await make_plan(db, reseller, price=20)
    router = await make_router(db, reseller, ip_address=f"10.0.8.{len(market_code)}")
    customer = await make_customer(db, reseller, plan, router,
                                   phone="254700000088", mac_address="AA:00:00:00:08:88")
    for amount, at in ((OCT_LAST, datetime(2026, 10, 31, 22, 0)),
                       (SUNDAY, datetime(2026, 11, 22, 15, 0)),
                       (AFTER_MIDNIGHT, datetime(2026, 11, 22, 21, 53))):
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, plan_id=plan.id, amount=amount,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_reference=f"D{int(amount)}",
            days_paid_for=1, status=PaymentStatus.COMPLETED, created_at=at, payment_date=at,
        ))
    await db.commit()
    return reseller


def _as(monkeypatch, reseller):
    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER, market_code=reseller.market_code)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(dashboard_routes, "_utcnow", lambda: NOW_UTC)


# --- overview -----------------------------------------------------------------

async def test_overview_today_week_and_month_are_local(db, monkeypatch):
    _as(monkeypatch, await _seed(db))

    revenue = (await dashboard_routes.get_dashboard_overview(router_id=None, db=db, token="t"))["revenue"]

    # Monday in Nairobi: today and this week (from Monday) hold only the 00:53 payment
    assert revenue["today"] == AFTER_MIDNIGHT
    assert revenue["this_week"] == AFTER_MIDNIGHT
    # 22:00 UTC on 31 Oct is 1 Nov in Nairobi, so it is in November
    assert revenue["this_month"] == OCT_LAST + SUNDAY + AFTER_MIDNIGHT


async def test_overview_for_a_cameroon_account(db, monkeypatch):
    _as(monkeypatch, await _seed(db, market_code="CM"))

    revenue = (await dashboard_routes.get_dashboard_overview(router_id=None, db=db, token="t"))["revenue"]

    # still Sunday 22:56 in Douala; the week began on Mon 16 Nov, the month on 1 Nov 00:00 WAT
    assert revenue["today"] == SUNDAY + AFTER_MIDNIGHT
    assert revenue["this_week"] == SUNDAY + AFTER_MIDNIGHT
    assert revenue["this_month"] == SUNDAY + AFTER_MIDNIGHT


# --- daily revenue --------------------------------------------------------------

async def _daily(db, **params):
    return await dashboard_routes.get_daily_revenue_metrics(router_id=None, db=db, token="t", **params)


async def test_daily_revenue_today_is_the_local_day_with_local_hours(db, monkeypatch):
    _as(monkeypatch, await _seed(db))

    today = await _daily(db, date=None)
    assert today["date"] == "2026-11-23"
    assert today["total_revenue"] == AFTER_MIDNIGHT
    assert today["hourly"][0]["revenue"] == AFTER_MIDNIGHT   # 00:53 EAT is in the 00:00 hour

    sunday = await _daily(db, date="2026-11-22")
    assert sunday["total_revenue"] == SUNDAY
    assert sunday["hourly"][18]["revenue"] == SUNDAY          # 15:00 UTC is 18:00 EAT


async def test_daily_revenue_for_a_cameroon_account(db, monkeypatch):
    _as(monkeypatch, await _seed(db, market_code="CM"))

    today = await _daily(db, date=None)
    assert today["date"] == "2026-11-22"
    assert today["total_revenue"] == SUNDAY + AFTER_MIDNIGHT
    assert today["hourly"][22]["revenue"] == AFTER_MIDNIGHT  # 22:53 WAT


# --- revenue over time ----------------------------------------------------------

async def _over_time(db, **params):
    args = dict(period="30d", start_date=None, end_date=None, router_id=None)
    args.update(params)
    result = await dashboard_routes.get_revenue_over_time(db=db, token="t", **args)
    return result, {p["date"]: p["revenue"] for p in result["data"]}


async def test_revenue_over_time_buckets_by_local_day(db, monkeypatch):
    _as(monkeypatch, await _seed(db))

    result, days = await _over_time(db, period="7d")
    assert result["end_date"] == "2026-11-23"
    assert days["2026-11-23"] == AFTER_MIDNIGHT
    assert days["2026-11-22"] == SUNDAY

    result, days = await _over_time(db, start_date="2026-11-01", end_date="2026-11-01")
    assert days == {"2026-11-01": OCT_LAST}
    assert result["totals"]["revenue"] == OCT_LAST


async def test_revenue_over_time_for_a_cameroon_account(db, monkeypatch):
    _as(monkeypatch, await _seed(db, market_code="CM"))

    result, days = await _over_time(db, period="7d")
    assert result["end_date"] == "2026-11-22"
    assert days["2026-11-22"] == SUNDAY + AFTER_MIDNIGHT
    _, days = await _over_time(db, start_date="2026-11-01", end_date="2026-11-01")
    assert days == {"2026-11-01": 0.0}

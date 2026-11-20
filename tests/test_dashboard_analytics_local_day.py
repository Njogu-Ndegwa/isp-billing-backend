"""/api/dashboard/analytics day windows follow the reseller's local calendar.

Reported 2026-11-21: at 00:06 EAT a Kenyan reseller's Dashboard with "Today"
selected still showed the previous day's KES 280 / 15 transactions, because
"today" was the UTC day (still 20 Nov until 03:00 EAT).
"""
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.api import dashboard_routes
from app.db.models import CustomerPayment, PaymentMethod, PaymentStatus, UserRole
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio

# 21 Nov 2026 00:06 EAT == 20 Nov 2026 21:06 UTC
NOW_UTC = datetime(2026, 11, 20, 21, 6, 0)


async def _seed(db, market_code="KE"):
    reseller = await make_reseller(db, email=f"tz-{market_code}@example.com", market_code=market_code)
    plan = await make_plan(db, reseller, price=20)
    router = await make_router(db, reseller, ip_address=f"10.0.9.{len(market_code)}")
    customer = await make_customer(
        db, reseller, plan, router,
        phone="254700000099", mac_address="AA:00:00:00:09:99",
    )
    return reseller, customer


async def _pay(db, customer, reseller, *, amount, created_at, ref):
    db.add(CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference=ref,
        days_paid_for=1,
        status=PaymentStatus.COMPLETED,
        created_at=created_at,
        payment_date=created_at,
    ))
    await db.commit()


async def _analytics(db, monkeypatch, reseller, **params):
    async def fake_current_user(token, db):
        return SimpleNamespace(id=reseller.id, role=UserRole.RESELLER, market_code=reseller.market_code)

    monkeypatch.setattr(dashboard_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(dashboard_routes, "_utcnow", lambda: NOW_UTC)
    args = dict(router_id=None, days=None, start_date=None, end_date=None, preset=None)
    args.update(params)
    return await dashboard_routes.get_dashboard_analytics(db=db, token="t", **args)


async def test_today_resets_at_local_midnight_not_utc_midnight(db, monkeypatch):
    reseller, customer = await _seed(db)
    # 20 Nov 18:00 EAT (15:00 UTC): yesterday in Kenya, but same UTC day as "now".
    await _pay(db, customer, reseller, amount=280.0, created_at=datetime(2026, 11, 20, 15, 0), ref="Y1")
    # 21 Nov 00:03 EAT (20 Nov 21:03 UTC): today in Kenya.
    await _pay(db, customer, reseller, amount=20.0, created_at=datetime(2026, 11, 20, 21, 3), ref="T1")

    result = await _analytics(db, monkeypatch, reseller, preset="today")

    assert result["today"]["date"] == "2026-11-21"
    assert result["today"]["revenue"] == 20.0
    assert result["today"]["transactions"] == 1
    assert result["summary"]["totalRevenue"] == 20.0
    assert result["period"]["startDate"] == "2026-11-21"
    assert result["period"]["endDate"] == "2026-11-21"
    # Hour buckets are local; the time string stays UTC because the admin UI
    # converts it to local itself.
    day = result["days"]["2026-11-21"]
    assert day["hourlyActivity"] == {0: 1}
    assert day["firstTransaction"] == "21:03:00"


async def test_yesterday_preset_and_days_window_use_local_days(db, monkeypatch):
    reseller, customer = await _seed(db)
    await _pay(db, customer, reseller, amount=280.0, created_at=datetime(2026, 11, 20, 15, 0), ref="Y1")
    # 19 Nov 23:30 EAT (20:30 UTC) -> belongs to 19 Nov locally.
    await _pay(db, customer, reseller, amount=50.0, created_at=datetime(2026, 11, 19, 20, 30), ref="D1")
    await _pay(db, customer, reseller, amount=20.0, created_at=datetime(2026, 11, 20, 21, 3), ref="T1")

    yesterday = await _analytics(db, monkeypatch, reseller, preset="yesterday")
    assert yesterday["summary"]["totalRevenue"] == 280.0
    assert list(yesterday["days"]) == ["2026-11-20"]

    week = await _analytics(db, monkeypatch, reseller, days=7)
    assert week["period"]["startDate"] == "2026-11-15"
    assert week["period"]["endDate"] == "2026-11-21"
    assert {d["date"]: d["revenue"] for d in week["dailyTrend"]} == {
        "2026-11-19": 50.0, "2026-11-20": 280.0, "2026-11-21": 20.0,
    }


async def test_custom_dates_are_local_calendar_dates(db, monkeypatch):
    reseller, customer = await _seed(db)
    await _pay(db, customer, reseller, amount=50.0, created_at=datetime(2026, 11, 19, 20, 30), ref="D1")
    await _pay(db, customer, reseller, amount=280.0, created_at=datetime(2026, 11, 20, 15, 0), ref="Y1")

    result = await _analytics(db, monkeypatch, reseller, start_date="2026-11-20", end_date="2026-11-20")
    assert result["summary"]["totalRevenue"] == 280.0


async def test_cameroon_reseller_uses_wat(db, monkeypatch):
    reseller, customer = await _seed(db, market_code="CM")
    # 20 Nov 21:30 UTC == 22:30 WAT on 20 Nov: still "today" in Douala at NOW_UTC
    # (22:06 WAT), even though it is already 21 Nov in Nairobi.
    await _pay(db, customer, reseller, amount=500.0, created_at=datetime(2026, 11, 20, 21, 0), ref="C1")
    await _pay(db, customer, reseller, amount=300.0, created_at=datetime(2026, 11, 20, 12, 0), ref="C2")

    result = await _analytics(db, monkeypatch, reseller, preset="today")
    assert result["today"]["date"] == "2026-11-20"
    assert result["today"]["revenue"] == 800.0
    assert result["currency"] == "XAF"

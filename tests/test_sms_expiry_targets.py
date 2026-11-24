"""SMS and the customer list pick customers by when their paid time ends: "today" is the
reseller's own calendar day, not the next 24 hours, and never the 7-day group."""
from datetime import datetime, timedelta

import pytest

from app.services import sms_dispatch
from app.services.sms_dispatch import expiry_window
from tests.factories import make_customer, make_plan, make_reseller

# 23 Nov 2026, 08:00 UTC = 11:00 in Nairobi
NOW = datetime(2026, 11, 23, 8, 0)


def test_today_is_the_local_calendar_day():
    start, end = expiry_window("today", NOW, "Africa/Nairobi")
    assert start == datetime(2026, 11, 22, 21, 0)   # midnight EAT
    assert end == datetime(2026, 11, 23, 21, 0)


def test_tomorrow_and_the_rolling_windows():
    assert expiry_window("tomorrow", NOW, "Africa/Nairobi") == (datetime(2026, 11, 23, 21, 0),
                                                                datetime(2026, 11, 24, 21, 0))
    assert expiry_window("next_7_days", NOW) == (NOW, NOW + timedelta(days=7))
    assert expiry_window("past_7_days", NOW) == (NOW - timedelta(days=7), NOW)
    with pytest.raises(ValueError):
        expiry_window("someday", NOW)


@pytest.mark.asyncio
async def test_send_filters_pick_only_that_day(db):
    r = await make_reseller(db)
    plan = await make_plan(db, r)
    when = {
        "ran_out_this_morning": NOW - timedelta(hours=3),   # 08:00 EAT today
        "tonight": NOW + timedelta(hours=10),               # 21:00 EAT today
        "after_midnight": NOW + timedelta(hours=14),        # 01:00 EAT tomorrow
        "next_week": NOW + timedelta(days=5),
        "last_week": NOW - timedelta(days=3),
    }
    for i, (name, expiry) in enumerate(when.items()):
        await make_customer(db, r, plan, name=name, phone=f"25471100000{i}", expiry=expiry)
    paused = await make_customer(db, r, plan, name="paused", phone="254711999999", expiry=NOW + timedelta(hours=2))
    paused.paused_at = NOW - timedelta(days=1)
    await db.commit()

    async def names(f):
        out = await sms_dispatch.resolve_recipients(db, r.id, filter=f, now=NOW, tz_name="Africa/Nairobi")
        return sorted(x["name"] for x in out)

    assert await names("expiring_today") == ["ran_out_this_morning", "tonight"]
    assert await names("expiring_tomorrow") == ["after_midnight"]
    assert await names("expired_recently") == ["last_week", "ran_out_this_morning"]


@pytest.mark.asyncio
async def test_expiring_is_time_still_running_never_time_that_ran_out(db):
    """"Expiring (7d)" on the messaging page and the assistant's "expiring" filter: 29 ending
    later today and 5 in 3 days are 34 people, not the 1,200 whose time ran out weeks ago."""
    from app.db.models import Customer, CustomerStatus

    r = await make_reseller(db)
    plan = await make_plan(db, r)
    n = 0

    def customer(name, expiry, status):
        nonlocal n
        n += 1
        return Customer(name=name, phone=f"2547{n:08d}", mac_address=f"AA:BB:{n // 65536 % 256:02X}:"
                        f"{n // 256 % 256:02X}:{n % 256:02X}:01", status=status, expiry=expiry,
                        plan_id=plan.id, user_id=r.id)

    db.add_all([customer(f"today {i}", NOW + timedelta(minutes=10 + 15 * i), CustomerStatus.ACTIVE)
                for i in range(29)])                                    # 08:10 to 15:10 UTC, still today in EAT
    db.add_all([customer(f"in 3 days {i}", NOW + timedelta(days=3, hours=i), CustomerStatus.ACTIVE)
                for i in range(5)])
    db.add_all([customer(f"lapsed {i}", NOW - timedelta(days=14 + i % 30), CustomerStatus.INACTIVE)
                for i in range(1200)])
    await db.commit()

    expiring = await sms_dispatch.resolve_recipients(db, r.id, filter="expiring", now=NOW)
    assert len(expiring) == 34
    assert not any(x["name"].startswith("lapsed") for x in expiring)
    today = await sms_dispatch.resolve_recipients(db, r.id, filter="expiring_today", now=NOW,
                                                  tz_name="Africa/Nairobi")
    assert len(today) == 29

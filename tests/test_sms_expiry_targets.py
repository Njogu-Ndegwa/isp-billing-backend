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

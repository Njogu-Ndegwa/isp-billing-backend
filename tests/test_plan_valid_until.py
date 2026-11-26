"""Tests: a plan's "valid until" (end date) saves, on the reseller's clock.

Feedback #74 (2026-11-25): giving a special offer an end date of 24 Dec 23:10
failed with asyncpg's "can't subtract offset-naive and offset-aware datetimes".
`plans.valid_until` is a naive UTC column, but the create and update endpoints
parsed "2026-12-24T23:10:00Z" into a tz-aware datetime and wrote it as-is.

The rules the endpoints must follow:
  * a time with a zone ("Z", "+03:00") is converted to naive UTC;
  * a time without a zone is the reseller's local clock (EAT, UTC+3), so
    "2026-12-24T23:10" is stored as 20:10 UTC;
  * "" on update clears the end date; nonsense is a 400.

SQLite (the default test DB) silently drops tzinfo instead of failing like
asyncpg, so a flush guard below rejects tz-aware values the way production does.
"""

from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import event

from app.api import plan_routes
from app.api.plan_routes import (
    PlanCreateRequest,
    PlanUpdateRequest,
    create_plan_api,
    update_plan_api,
)
from app.core.local_time import parse_local_moment
from app.db.models import Plan
from tests.factories import make_plan, make_reseller

pytestmark = pytest.mark.asyncio


@pytest.fixture
def naive_only_valid_until(db):
    """Fail a flush that writes a tz-aware valid_until, as asyncpg does in prod."""

    def guard(session, flush_context, instances):
        for obj in list(session.new) + list(session.dirty):
            if isinstance(obj, Plan) and obj.valid_until is not None and obj.valid_until.tzinfo is not None:
                raise ValueError("can't subtract offset-naive and offset-aware datetimes")

    event.listen(db.sync_session, "before_flush", guard)
    yield
    event.remove(db.sync_session, "before_flush", guard)


@pytest.fixture
def as_reseller(monkeypatch):
    def install(user):
        async def fake_current_user(token, db):
            return user

        monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
        monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda u: None)

    return install


# ---------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2026-12-24T23:10:00Z", datetime(2026, 12, 24, 23, 10)),
        ("2026-12-24T23:10:00+00:00", datetime(2026, 12, 24, 23, 10)),
        ("2026-12-24T23:10:00+03:00", datetime(2026, 12, 24, 20, 10)),
        ("2026-12-24T23:10", datetime(2026, 12, 24, 20, 10)),      # no zone: EAT
        ("2026-12-24 23:10", datetime(2026, 12, 24, 20, 10)),
        ("2026-12-24", datetime(2026, 12, 23, 21, 0)),             # local midnight
        ("2026-12-25T01:30+03:00", datetime(2026, 12, 24, 22, 30)),  # crosses the date
    ],
)
async def test_parse_local_moment_gives_naive_utc(raw, expected):
    got = parse_local_moment(raw)
    assert got == expected
    assert got.tzinfo is None


@pytest.mark.parametrize("raw", ["", "   ", "tomorrow", "24/12/2026"])
async def test_parse_local_moment_rejects_non_times(raw):
    with pytest.raises(ValueError):
        parse_local_moment(raw)


# ---------------------------------------------------------------------------
# The endpoints
# ---------------------------------------------------------------------------

async def test_update_with_utc_end_date_saves(db, as_reseller, naive_only_valid_until):
    """The exact payload from the prod traceback (plan 2937, 24 Dec 23:10)."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    as_reseller(reseller)

    body = await update_plan_api(
        plan.id,
        PlanUpdateRequest(plan_type="special_offer", valid_until="2026-12-24T23:10:00Z"),
        db=db,
        token="tok",
    )

    await db.refresh(plan)
    assert plan.valid_until == datetime(2026, 12, 24, 23, 10)
    assert body["valid_until"] == "2026-12-24T23:10:00"


async def test_update_with_local_end_date_is_read_as_eat(db, as_reseller, naive_only_valid_until):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    as_reseller(reseller)

    await update_plan_api(
        plan.id, PlanUpdateRequest(valid_until="2026-12-24T23:10"), db=db, token="tok"
    )

    await db.refresh(plan)
    assert plan.valid_until == datetime(2026, 12, 24, 20, 10)


async def test_update_with_offset_end_date_converts_not_drops(db, as_reseller, naive_only_valid_until):
    """The admin dashboard sends local time with its offset."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    as_reseller(reseller)

    await update_plan_api(
        plan.id, PlanUpdateRequest(valid_until="2026-12-24T23:10:00+03:00"), db=db, token="tok"
    )

    await db.refresh(plan)
    assert plan.valid_until == datetime(2026, 12, 24, 20, 10)


async def test_update_with_empty_end_date_clears_it(db, as_reseller, naive_only_valid_until):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, valid_until=datetime(2026, 12, 24, 20, 10))
    as_reseller(reseller)

    await update_plan_api(plan.id, PlanUpdateRequest(valid_until=""), db=db, token="tok")

    await db.refresh(plan)
    assert plan.valid_until is None


async def test_update_with_bad_end_date_is_400(db, as_reseller):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    as_reseller(reseller)

    with pytest.raises(HTTPException) as exc:
        await update_plan_api(plan.id, PlanUpdateRequest(valid_until="next week"), db=db, token="tok")
    assert exc.value.status_code == 400


async def test_create_with_utc_end_date_saves(db, as_reseller, naive_only_valid_until):
    reseller = await make_reseller(db)
    as_reseller(reseller)

    body = await create_plan_api(
        PlanCreateRequest(
            name="Christmas offer",
            speed="5M/5M",
            price=20,
            duration_value=2,
            duration_unit="HOURS",
            connection_type="hotspot",
            plan_type="special_offer",
            valid_until="2026-12-24T20:10:00Z",
        ),
        db=db,
        token="tok",
    )

    plan = await db.get(Plan, body["id"])
    assert plan.valid_until == datetime(2026, 12, 24, 20, 10)

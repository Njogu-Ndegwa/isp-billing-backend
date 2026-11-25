"""A reseller lifts a customer's FUP mid-session (Tedd, 25 Nov 2026).

The lift restores full speed and keeps the cap off for the rest of the
period: the next usage evaluation must not throttle the customer again.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.usage_routes as ur
from app.db.database import get_db
from app.db.models import ConnectionType, CustomerUsagePeriod, FupAction
from app.services import fup
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _throttled(db, reseller=None, *, expiry_days=30):
    reseller = reseller or await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db, reseller, connection_type=ConnectionType.PPPOE, data_cap_mb=1,
        fup_action=FupAction.THROTTLE, fup_throttle_profile="3M/1M",
    )
    customer = await make_customer(
        db, reseller, plan, router, pppoe_username=f"user{router.id}",
        expiry=datetime.utcnow() + timedelta(days=expiry_days),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(hours=1),
        period_end=now + timedelta(days=30),
        upload_bytes=1_200_000, download_bytes=1_200_000, total_bytes=2_400_000,
        cap_mb_snapshot=1, fup_action_snapshot=FupAction.THROTTLE,
        fup_triggered_at=now - timedelta(minutes=10),
        fup_action_taken=FupAction.THROTTLE,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)
    return reseller, customer, plan, period


def _fake_router(monkeypatch, result=None):
    calls = {"restore": 0, "throttle": 0}

    async def restore(db, customer, plan):
        calls["restore"] += 1
        return result or {"success": True}

    async def throttle(db, customer, plan):
        calls["throttle"] += 1
        return {"success": True}

    monkeypatch.setattr(fup, "restore_normal_profile", restore)
    monkeypatch.setattr(fup, "apply_throttle", throttle)
    return calls


@pytest.mark.asyncio
async def test_lift_restores_speed_and_cap_stays_off(db, monkeypatch):
    _, customer, plan, period = await _throttled(db)
    calls = _fake_router(monkeypatch)

    await fup.lift_until_next_window(db, customer, period, plan=plan)
    again = await fup.evaluate_and_enforce(db, customer, period, plan=plan)

    assert calls == {"restore": 1, "throttle": 0}
    assert period.fup_reverted_at is not None
    assert period.fup_triggered_at is not None  # kept, so the cap stays off
    assert again is None


@pytest.mark.asyncio
async def test_lift_refuses_when_not_capped_or_expired(db, monkeypatch):
    _, customer, plan, period = await _throttled(db)
    calls = _fake_router(monkeypatch)
    period.fup_triggered_at = None
    with pytest.raises(fup.FupLiftError) as not_capped:
        await fup.lift_until_next_window(db, customer, period, plan=plan)

    _, expired, plan2, period2 = await _throttled(db, expiry_days=-1)
    with pytest.raises(fup.FupLiftError) as gone:
        await fup.lift_until_next_window(db, expired, period2, plan=plan2)

    assert not_capped.value.code == "not_restricted"
    assert gone.value.code == "expired"
    assert calls["restore"] == 0


@pytest.mark.asyncio
async def test_router_failure_leaves_the_cap_recorded(db, monkeypatch):
    _, customer, plan, period = await _throttled(db)
    _fake_router(monkeypatch, result={"error": "timeout"})

    with pytest.raises(fup.FupLiftError) as err:
        await fup.lift_until_next_window(db, customer, period, plan=plan)

    assert err.value.code == "router"
    assert period.fup_reverted_at is None


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(ur.router)

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


@pytest.mark.asyncio
async def test_endpoint_lifts_own_customer_only(db, client, monkeypatch):
    owner, customer, _, _ = await _throttled(db)
    stranger = await make_reseller(db)
    _fake_router(monkeypatch)
    who = {"user": stranger}

    async def _fake_user(token, db):
        return who["user"]
    monkeypatch.setattr(ur, "get_current_user", _fake_user)

    denied = await client.post(f"/api/customers/{customer.id}/fup/lift")
    who["user"] = owner
    ok = await client.post(f"/api/customers/{customer.id}/fup/lift")
    twice = await client.post(f"/api/customers/{customer.id}/fup/lift")

    assert denied.status_code == 404
    assert ok.status_code == 200
    assert ok.json()["period"]["fup_active"] is False
    assert twice.status_code == 409

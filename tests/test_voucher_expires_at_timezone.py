"""Voucher generate with a timezone-aware expires_at must not 500.

The admin sent `new Date(...).toISOString()` ("...Z"), pydantic parsed it as a
timezone-aware datetime, and asyncpg refused to write it into the naive
`vouchers.expires_at` column ("can't subtract offset-naive and offset-aware
datetimes"). generate_vouchers now stores it as naive UTC.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.voucher_routes as vr
from app.api.voucher_routes import router as voucher_router
from app.db.database import get_db
from app.db.models import Voucher, VoucherStatus
from app.services.auth import verify_token
from app.services.voucher_service import generate_vouchers, verify_voucher
from tests.factories import make_plan, make_reseller


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(voucher_router)

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
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(vr, "get_current_user", _fake)
    monkeypatch.setattr(vr, "enforce_active_subscription", lambda u: None)


async def _stored(db, user_id):
    return (await db.execute(select(Voucher).where(Voucher.user_id == user_id))).scalars().all()


@pytest.mark.asyncio
async def test_generate_with_utc_z_expiry_returns_200(db, client, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/vouchers/generate", json={
        "plan_id": plan.id, "quantity": 2, "expires_at": "2030-10-30T09:00:00.000Z",
    })

    assert resp.status_code == 200, resp.text
    rows = await _stored(db, reseller.id)
    assert len(rows) == 2
    for v in rows:
        await db.refresh(v)
        assert v.expires_at.tzinfo is None
        assert v.expires_at == datetime(2030, 10, 30, 9, 0, 0)


@pytest.mark.asyncio
async def test_offset_expiry_is_converted_to_utc(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    eat = timezone(timedelta(hours=3))

    result = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=1,
        expires_at=datetime(2030, 10, 30, 12, 0, tzinfo=eat),
    )

    assert "error" not in result
    assert result["expires_at"] == "2030-10-30T09:00:00"
    (v,) = await _stored(db, reseller.id)
    assert v.expires_at == datetime(2030, 10, 30, 9, 0)


@pytest.mark.asyncio
async def test_generate_without_expiry_still_has_none(db, client, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    _auth_as(monkeypatch, reseller)

    resp = await client.post("/api/vouchers/generate", json={"plan_id": plan.id, "quantity": 1})

    assert resp.status_code == 200, resp.text
    assert resp.json()["expires_at"] is None
    (v,) = await _stored(db, reseller.id)
    assert v.expires_at is None
    assert v.status == VoucherStatus.AVAILABLE


@pytest.mark.asyncio
async def test_past_aware_expiry_still_blocks_redeem_check(db):
    """Existing behaviour kept: a voucher past its expiry is reported expired."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)

    result = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=1,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    code = result["vouchers"][0]["code"]

    check = await verify_voucher(db, code)
    assert check["valid"] is False
    assert "expired" in check["error"].lower()

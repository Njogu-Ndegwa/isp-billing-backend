"""Paging on GET /api/customers and /api/customers/active.

The dashboard asks for `page=1&per_page=1` just to show a count. Before paging
existed the backend ignored those parameters and returned every customer
(about 3 MB for a large reseller, ~1,400 times a day). With both parameters the
endpoints now return one page plus totals; without them they still return the
full plain array that older clients expect.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.customer_routes as cr
from app.api.customer_routes import router as customer_router
from app.db.database import get_db
from app.db.models import CustomerStatus
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(customer_router)

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
    monkeypatch.setattr(cr, "get_current_user", _fake)


async def _seed(db):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    now = datetime.utcnow()
    active = []
    for hours in (5, 1, 3):
        active.append(await make_customer(
            db, reseller, plan, router, status=CustomerStatus.ACTIVE, expiry=now + timedelta(hours=hours),
        ))
    inactive = [await make_customer(db, reseller, plan, router, status=CustomerStatus.INACTIVE) for _ in range(2)]
    other_plan = await make_plan(db, other)
    await make_customer(db, other, other_plan, await make_router(db, other), status=CustomerStatus.ACTIVE,
                        expiry=now + timedelta(hours=2))
    return reseller, active, inactive


@pytest.mark.asyncio
async def test_unpaged_request_still_returns_the_full_array(db, client, monkeypatch):
    reseller, active, inactive = await _seed(db)
    _auth_as(monkeypatch, reseller)

    listed = (await client.get("/api/customers")).json()
    active_listed = (await client.get("/api/customers/active")).json()

    assert isinstance(listed, list) and len(listed) == 5
    assert isinstance(active_listed, list) and len(active_listed) == 3


@pytest.mark.asyncio
async def test_count_only_request_returns_one_row_and_the_true_total(db, client, monkeypatch):
    reseller, active, inactive = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/customers", params={"page": 1, "per_page": 1})).json()

    assert body["total"] == 5  # the other reseller's customer is not counted
    assert body["total_pages"] == 5
    assert len(body["data"]) == 1
    assert body["data"][0]["id"] == min(c.id for c in active + inactive)


@pytest.mark.asyncio
async def test_pages_cover_every_customer_once_in_id_order(db, client, monkeypatch):
    reseller, active, inactive = await _seed(db)
    _auth_as(monkeypatch, reseller)

    first = (await client.get("/api/customers", params={"page": 1, "per_page": 2})).json()
    second = (await client.get("/api/customers", params={"page": 2, "per_page": 2})).json()
    third = (await client.get("/api/customers", params={"page": 3, "per_page": 2})).json()

    ids = [c["id"] for page in (first, second, third) for c in page["data"]]
    assert ids == sorted(c.id for c in active + inactive)
    assert [len(p["data"]) for p in (first, second, third)] == [2, 2, 1]
    assert first["page"] == 1 and first["per_page"] == 2 and first["total_pages"] == 3


@pytest.mark.asyncio
async def test_active_pages_keep_soonest_expiry_first(db, client, monkeypatch):
    reseller, active, _ = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/customers/active", params={"page": 1, "per_page": 2})).json()

    by_expiry = sorted(active, key=lambda c: c.expiry)
    assert body["total"] == 3
    assert [c["id"] for c in body["data"]] == [by_expiry[0].id, by_expiry[1].id]


@pytest.mark.asyncio
async def test_page_past_the_end_is_empty_not_an_error(db, client, monkeypatch):
    reseller, _, _ = await _seed(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get("/api/customers", params={"page": 9, "per_page": 20})).json()

    assert body["data"] == [] and body["total"] == 5


@pytest.mark.asyncio
async def test_per_page_is_capped(db, client, monkeypatch):
    reseller, _, _ = await _seed(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.get("/api/customers", params={"page": 1, "per_page": 100000})

    assert resp.status_code == 422

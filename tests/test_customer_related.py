"""GET /api/customers/{id}/related — the linked accounts on a customer's page.

The admin customer page downloaded the reseller's whole customer list (2-3 MB)
to find three kinds of linked account. This endpoint returns just those: the
subscription owner, the companions it covers, and other accounts with the
same phone number (last 9 digits, like the page's phoneKey).
"""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.customer_routes as cr
from app.api.customer_routes import router as customer_router
from app.db.database import get_db
from app.services import staff_permissions
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


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


async def _family(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    owner = await make_customer(db, reseller, plan, router, phone="254711111111", name="Owner")
    me = await make_customer(db, reseller, plan, router, phone="+254 722 333 444", name="Me",
                             subscription_owner_id=owner.id)
    companion = await make_customer(db, reseller, plan, router, phone="254700000001", name="TV",
                                    subscription_owner_id=me.id)
    same_phone = await make_customer(db, reseller, plan, router, phone="0722333444", name="Old phone record")
    stranger = await make_customer(db, reseller, plan, router, phone="254799999999", name="Stranger")
    other = await make_reseller(db)
    other_plan = await make_plan(db, other)
    foreign = await make_customer(db, other, other_plan, await make_router(db, other), phone="254722333444")
    return reseller, dict(owner=owner, me=me, companion=companion, same_phone=same_phone,
                          stranger=stranger, foreign=foreign)


async def test_returns_owner_companions_and_same_phone_only(db, client, monkeypatch):
    reseller, c = await _family(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get(f"/api/customers/{c['me'].id}/related")).json()

    ids = {row["id"] for row in body["customers"]}
    assert ids == {c["owner"].id, c["companion"].id, c["same_phone"].id}
    assert c["foreign"].id not in ids and c["stranger"].id not in ids
    assert set(body["customers"][0]) == {"id", "name", "mac_address", "phone", "subscription_owner_id"}


async def test_customer_with_no_links_gets_an_empty_list(db, client, monkeypatch):
    reseller, c = await _family(db)
    _auth_as(monkeypatch, reseller)

    body = (await client.get(f"/api/customers/{c['stranger'].id}/related")).json()

    assert body == {"customers": []}


async def test_other_resellers_customer_is_not_found(db, client, monkeypatch):
    reseller, c = await _family(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.get(f"/api/customers/{c['foreign'].id}/related")

    assert resp.status_code == 404


async def test_short_or_missing_phone_matches_nothing_by_phone(db, client, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller)
    lonely = await make_customer(db, reseller, plan, router, phone="123")
    await make_customer(db, reseller, plan, router, phone="0000123")
    _auth_as(monkeypatch, reseller)

    body = (await client.get(f"/api/customers/{lonely.id}/related")).json()

    assert body == {"customers": []}


def test_staff_need_customers_view():
    rule, _ = staff_permissions.match_rule("GET", "/api/customers/5/related")
    assert rule is not None and rule.template == "/api/customers/{customer_id}/related"
    assert rule.requirement == "customers.view"

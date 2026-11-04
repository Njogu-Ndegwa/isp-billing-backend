"""Customer location and map endpoints stay tenant-scoped (security fix, 29 Oct).

* POST /api/customers/location/by-phone is gone (it was unauthenticated, wrote
  any tenant's coordinates by phone and created ownerless customer rows).
* POST /api/customers/{id}/location is registered exactly once and is
  authenticated and owner-scoped.
* GET /api/customers/map and the ratings reads only return the caller's own
  customers, never another tenant's and never ownerless (user_id NULL) rows.

Runs through the real app with no external I/O, like tests/test_staff.py.
"""
from datetime import timedelta

import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.api.auth_routes import login_token_claims
from app.db.models import Customer, CustomerRating, ResellerStaff
from app.services import staff_access, staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_customer, make_plan, make_reseller


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    staff_access.reset_cache()

    async def no_sms(*args, **kwargs):
        pass

    monkeypatch.setattr(staff_access, "alert_owner", no_sms)
    yield
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


@pytest_asyncio.fixture
async def tenants(db):
    """Two resellers with a located customer each, sharing one phone number,
    plus an ownerless located row with the same phone."""
    alice = await make_reseller(db)
    bob = await make_reseller(db)
    alice_plan = await make_plan(db, alice)
    bob_plan = await make_plan(db, bob)
    shared_phone = "254700111222"
    alice_customer = await make_customer(
        db, alice, alice_plan, name="Alice Customer", phone=shared_phone,
        latitude=-1.28, longitude=36.82,
    )
    bob_customer = await make_customer(
        db, bob, bob_plan, name="Bob Customer", phone=shared_phone,
        latitude=-0.42, longitude=36.95,
    )
    orphan = Customer(phone=shared_phone, latitude=-1.29, longitude=36.81)
    db.add(orphan)
    await db.commit()
    await db.refresh(orphan)
    return dict(
        alice=alice, bob=bob, alice_customer=alice_customer,
        bob_customer=bob_customer, orphan=orphan, phone=shared_phone,
    )


def _walk(routes):
    """(method, path) for every route; handles FastAPI's lazy include wrappers."""
    for route in routes:
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                yield method, route.path, route
        elif hasattr(route, "original_router"):
            yield from _walk(route.original_router.routes)


def _routes(method, path):
    import main
    return [r for m, p, r in _walk(main.app.routes) if m == method and p == path]


# ---------------------------------------------------------------------------
# POST /api/customers/location/by-phone is removed
# ---------------------------------------------------------------------------

def test_by_phone_route_is_not_registered():
    assert _routes("POST", "/api/customers/location/by-phone") == []


def test_by_phone_has_no_staff_rule():
    rule, _ = perms.match_rule("POST", "/api/customers/location/by-phone")
    assert rule is None


async def test_by_phone_cannot_write_or_create_customers(client, db, tenants):
    before = (await db.execute(select(func.count()).select_from(Customer))).scalar_one()
    for phone in (tenants["phone"], "254799999999"):
        response = await client.post(
            "/api/customers/location/by-phone",
            json={"phone": phone, "latitude": 1.0, "longitude": 2.0},
        )
        assert response.status_code in (401, 404, 405), response.text
    after = (await db.execute(select(func.count()).select_from(Customer))).scalar_one()
    assert after == before
    await db.refresh(tenants["alice_customer"])
    await db.refresh(tenants["bob_customer"])
    assert tenants["alice_customer"].latitude == -1.28
    assert tenants["bob_customer"].latitude == -0.42


# ---------------------------------------------------------------------------
# POST /api/customers/{id}/location: one route, authenticated, owner-scoped
# ---------------------------------------------------------------------------

def test_location_route_registered_once_from_customer_routes():
    routes = _routes("POST", "/api/customers/{customer_id}/location")
    assert len(routes) == 1
    assert routes[0].endpoint.__module__ == "app.api.customer_routes"


async def test_location_requires_auth(client, tenants):
    response = await client.post(
        f"/api/customers/{tenants['alice_customer'].id}/location",
        json={"latitude": 1.0, "longitude": 2.0},
    )
    assert response.status_code == 401


async def test_location_of_another_resellers_customer_is_404(client, db, tenants):
    response = await client.post(
        f"/api/customers/{tenants['bob_customer'].id}/location",
        json={"latitude": 1.0, "longitude": 2.0},
        headers=headers(owner_token(tenants["alice"])),
    )
    assert response.status_code == 404
    await db.refresh(tenants["bob_customer"])
    assert tenants["bob_customer"].latitude == -0.42


async def test_location_of_ownerless_row_is_404(client, db, tenants):
    response = await client.post(
        f"/api/customers/{tenants['orphan'].id}/location",
        json={"latitude": 1.0, "longitude": 2.0},
        headers=headers(owner_token(tenants["alice"])),
    )
    assert response.status_code == 404
    await db.refresh(tenants["orphan"])
    assert tenants["orphan"].latitude == -1.29


async def test_owner_updates_own_customer_location(client, db, tenants):
    customer = tenants["alice_customer"]
    response = await client.post(
        f"/api/customers/{customer.id}/location",
        json={"latitude": -1.3, "longitude": 36.9},
        headers=headers(owner_token(tenants["alice"])),
    )
    assert response.status_code == 200, response.text
    await db.refresh(customer)
    assert (customer.latitude, customer.longitude) == (-1.3, 36.9)
    assert customer.location_captured_at is not None


def test_location_staff_rule_needs_customers_manage():
    rule, _ = perms.match_rule("POST", "/api/customers/7/location")
    assert rule is not None and rule.allows(["customers.manage"])
    assert not rule.allows(["customers.view"])


# ---------------------------------------------------------------------------
# GET /api/customers/map: own customers only
# ---------------------------------------------------------------------------

async def test_map_requires_auth(client):
    response = await client.get("/api/customers/map")
    assert response.status_code == 401


async def test_map_excludes_other_tenants_and_ownerless_rows(client, tenants):
    response = await client.get(
        "/api/customers/map", headers=headers(owner_token(tenants["alice"]))
    )
    assert response.status_code == 200, response.text
    ids = {c["id"] for c in response.json()["customers"]}
    assert ids == {tenants["alice_customer"].id}
    assert tenants["bob_customer"].id not in ids
    assert tenants["orphan"].id not in ids


async def test_map_with_ratings_and_duplicate_phones(client, db, tenants):
    db.add(CustomerRating(customer_id=tenants["alice_customer"].id, phone=tenants["phone"], rating=4))
    await db.commit()
    response = await client.get(
        "/api/customers/map?with_ratings=true", headers=headers(owner_token(tenants["bob"]))
    )
    assert response.status_code == 200, response.text
    customers = response.json()["customers"]
    assert [c["id"] for c in customers] == [tenants["bob_customer"].id]
    assert customers[0]["total_ratings"] == 0


async def test_map_for_staff_shows_the_owners_customers_only(client, db, tenants):
    owner = tenants["alice"]
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Map viewer", email="mapviewer@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=["customers.view"],
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    response = await client.get("/api/customers/map", headers=headers(token))
    assert response.status_code == 200, response.text
    assert {c["id"] for c in response.json()["customers"]} == {tenants["alice_customer"].id}


# ---------------------------------------------------------------------------
# Ratings reads: same tenant scoping; public submit survives duplicate phones
# ---------------------------------------------------------------------------

async def test_rating_submit_with_duplicate_phones_does_not_500(client, tenants):
    response = await client.post(
        "/api/ratings/submit", json={"phone": tenants["phone"], "rating": 5}
    )
    assert response.status_code == 200, response.text


async def test_ratings_reads_exclude_other_tenants_anonymous_and_ownerless(client, db, tenants):
    db.add_all([
        CustomerRating(customer_id=tenants["alice_customer"].id, phone="a", rating=5,
                       latitude=-1.28, longitude=36.82),
        CustomerRating(customer_id=tenants["bob_customer"].id, phone="b", rating=1,
                       latitude=-1.28, longitude=36.82),
        CustomerRating(customer_id=tenants["orphan"].id, phone="o", rating=2,
                       latitude=-1.28, longitude=36.82),
        CustomerRating(customer_id=None, phone="anon", rating=3,
                       latitude=-1.28, longitude=36.82),
    ])
    await db.commit()
    auth = headers(owner_token(tenants["alice"]))

    listing = await client.get("/api/ratings", headers=auth)
    assert listing.status_code == 200, listing.text
    assert [r["phone"] for r in listing.json()["ratings"]] == ["a"]

    summary = await client.get("/api/ratings/summary", headers=auth)
    assert summary.status_code == 200, summary.text
    assert summary.json()["total_ratings"] == 1

    by_location = await client.get(
        "/api/ratings/by-location?min_lat=-2&max_lat=0&min_lng=36&max_lng=37", headers=auth
    )
    assert by_location.status_code == 200, by_location.text
    assert [r["phone"] for r in by_location.json()["ratings"]] == ["a"]

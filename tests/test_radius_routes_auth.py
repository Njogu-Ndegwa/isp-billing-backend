"""/api/radius/* management routes need a login and only reach the caller's own data.

Until 29 Oct 2026 every route in app/api/radius_endpoints.py was open to the
internet: anyone could switch any router to RADIUS, mint RADIUS logins (free
internet on any RADIUS router), read passwords or disconnect sessions. These
tests pin the fix through the real app:

* no token -> 401 on every management route;
* another reseller -> 404 (same answer as "does not exist");
* the owner, an admin, and staff with the right permission succeed;
* staff without the permission get 403 from the staff map (deny by default);
* the public captive-portal routes and the M-Pesa callback still answer
  without a token (the only machine/anonymous callers of /api/radius).

The CoA disconnect is faked at RadiusCoA; nothing leaves the process.
"""

import itertools
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.api import radius_endpoints
from app.api.auth_routes import login_token_claims
from app.db.models import ResellerStaff, Router, RouterAuthMethod, SubscriptionStatus
from app.services import staff_access
from app.services import staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

SECRET = "router-shared-secret"

RADIUS_DDL = [
    """CREATE TABLE IF NOT EXISTS radius_check (
        username VARCHAR(64), attribute VARCHAR(64), op VARCHAR(2), value VARCHAR(253),
        expiry TIMESTAMP, customer_id INTEGER, created_at TIMESTAMP, updated_at TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS radius_reply (
        username VARCHAR(64), attribute VARCHAR(64), op VARCHAR(2), value VARCHAR(253),
        expiry TIMESTAMP, customer_id INTEGER)""",
    """CREATE TABLE IF NOT EXISTS radius_usergroup (username VARCHAR(64), groupname VARCHAR(64))""",
    """CREATE TABLE IF NOT EXISTS radius_accounting (
        acctsessionid VARCHAR(64), username VARCHAR(64), nasipaddress VARCHAR(15),
        framedipaddress VARCHAR(15), callingstationid VARCHAR(50),
        acctstarttime TIMESTAMP, acctupdatetime TIMESTAMP, acctstoptime TIMESTAMP,
        acctsessiontime INTEGER, acctinputoctets BIGINT, acctoutputoctets BIGINT)""",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _fresh_staff_cache(monkeypatch):
    staff_access.reset_cache()

    async def no_sms(*args, **kwargs):
        pass
    monkeypatch.setattr(staff_access, "alert_owner", no_sms)
    yield
    staff_access.reset_cache()


class FakeCoA:
    calls: list = []

    def __init__(self, nas_ip, secret, coa_port=3799):
        self.nas_ip, self.secret = nas_ip, secret

    def disconnect_user(self, username=None, **kwargs):
        FakeCoA.calls.append((self.nas_ip, self.secret, username))
        return True, "Disconnect-ACK"


@pytest.fixture(autouse=True)
def fake_coa(monkeypatch):
    FakeCoA.calls = []
    monkeypatch.setattr(radius_endpoints, "RadiusCoA", FakeCoA)
    return FakeCoA


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user):
    token = create_access_token(login_token_claims(user), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


_STAFF_SEQ = itertools.count(1)


async def _staff_headers(db, owner, permissions):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Staff",
        email=f"staff{owner.id}-{next(_STAFF_SEQ)}@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=permissions,
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


async def _add_radius_user(db, username, customer_id):
    await db.execute(text(
        "INSERT INTO radius_check (username, attribute, op, value, customer_id) "
        "VALUES (:u, 'Cleartext-Password', ':=', 'secretpw', :c)"
    ), {"u": username, "c": customer_id})
    await db.commit()


async def _add_session(db, username, nas_ip, session_id, octets=1000):
    await db.execute(text(
        "INSERT INTO radius_accounting (acctsessionid, username, nasipaddress, acctstarttime, "
        "acctsessiontime, acctinputoctets, acctoutputoctets) "
        "VALUES (:s, :u, :n, :t, 60, :o, :o)"
    ), {"s": session_id, "u": username, "n": nas_ip, "t": datetime.utcnow() - timedelta(minutes=5), "o": octets})
    await db.commit()


@pytest_asyncio.fixture
async def world(db):
    """Two resellers, each with a RADIUS router, a customer and a RADIUS login."""
    for ddl in RADIUS_DDL:
        await db.execute(text(ddl))
    await db.commit()

    a = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    b = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    admin = await make_admin(db)
    plan_a, plan_b = await make_plan(db, a), await make_plan(db, b)
    router_a = await make_router(db, a, ip_address="10.0.1.1", auth_method=RouterAuthMethod.RADIUS,
                                 radius_secret=SECRET)
    router_b = await make_router(db, b, ip_address="10.0.2.2", auth_method=RouterAuthMethod.RADIUS,
                                 radius_secret=SECRET)
    cust_a = await make_customer(db, a, plan_a, router_a)
    cust_b = await make_customer(db, b, plan_b, router_b)
    await _add_radius_user(db, "userA", cust_a.id)
    await _add_radius_user(db, "userB", cust_b.id)
    await _add_session(db, "userA", "10.0.1.1", "sA")
    await _add_session(db, "userB", "10.0.2.2", "sB")
    # A login seen on BOTH routers: B must not see A's share of it.
    await _add_session(db, "roamer", "10.0.1.1", "sR1", octets=5000)
    await _add_session(db, "roamer", "10.0.2.2", "sR2", octets=7)
    return dict(a=a, b=b, admin=admin, router_a=router_a, router_b=router_b,
                cust_a=cust_a, cust_b=cust_b)


# Every management route, with a request that would act on reseller A's data.
def _routes(w):
    ra, ca = w["router_a"].id, w["cust_a"].id
    return [
        ("POST", f"/api/radius/routers/{ra}/enable", {"radius_secret": "attacker-secret"}),
        ("POST", f"/api/radius/routers/{ra}/disable", None),
        ("GET", f"/api/radius/routers/{ra}/status", None),
        ("GET", "/api/radius/routers", None),
        ("POST", "/api/radius/users", {"username": "evil", "customer_id": ca}),
        ("GET", "/api/radius/users/userA", None),
        ("DELETE", "/api/radius/users/userA", None),
        ("GET", "/api/radius/sessions", None),
        ("POST", f"/api/radius/sessions/userA/disconnect?router_id={ra}", None),
        ("GET", "/api/radius/accounting/userA", None),
        ("POST", "/api/radius/cleanup", None),
        ("GET", f"/api/radius/test/{ra}", None),
    ]


async def _call(client, method, path, body=None, headers=None):
    return await client.request(method, path, json=body, headers=headers or {})


# ---------------------------------------------------------------------------
# No token
# ---------------------------------------------------------------------------

async def test_every_management_route_refuses_anonymous_callers(client, db, world):
    for method, path, body in _routes(world):
        resp = await _call(client, method, path, body)
        assert resp.status_code == 401, (method, path, resp.status_code, resp.text)

    router_a = await db.get(Router, world["router_a"].id)
    await db.refresh(router_a)
    assert router_a.auth_method == RouterAuthMethod.RADIUS
    assert router_a.radius_secret == SECRET
    assert (await db.execute(text("SELECT COUNT(*) FROM radius_check WHERE username = 'userA'"))).scalar() == 1
    assert (await db.execute(text("SELECT COUNT(*) FROM radius_check WHERE username = 'evil'"))).scalar() == 0
    assert FakeCoA.calls == []


async def test_garbage_token_is_refused(client, world):
    resp = await client.post(
        f"/api/radius/routers/{world['router_a'].id}/disable",
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Another reseller
# ---------------------------------------------------------------------------

async def test_other_reseller_gets_404_on_routers_users_and_disconnect(client, db, world):
    hb = _bearer(world["b"])
    ra = world["router_a"].id
    for method, path, body in [
        ("POST", f"/api/radius/routers/{ra}/enable", {"radius_secret": "attacker-secret"}),
        ("POST", f"/api/radius/routers/{ra}/disable", None),
        ("GET", f"/api/radius/routers/{ra}/status", None),
        ("GET", f"/api/radius/test/{ra}", None),
        ("POST", "/api/radius/users", {"username": "evil", "customer_id": world["cust_a"].id}),
        ("GET", "/api/radius/users/userA", None),
        ("DELETE", "/api/radius/users/userA", None),
        ("GET", f"/api/radius/sessions?router_id={ra}", None),
        ("POST", f"/api/radius/sessions/userA/disconnect?router_id={ra}", None),
    ]:
        resp = await _call(client, method, path, body, hb)
        assert resp.status_code == 404, (method, path, resp.status_code, resp.text)

    router_a = await db.get(Router, ra)
    await db.refresh(router_a)
    assert router_a.auth_method == RouterAuthMethod.RADIUS and router_a.radius_secret == SECRET
    assert (await db.execute(text("SELECT COUNT(*) FROM radius_check WHERE username = 'userA'"))).scalar() == 1
    assert FakeCoA.calls == []


async def test_other_reseller_cannot_overwrite_a_username_they_do_not_own(client, db, world):
    # B uses their OWN customer but A's username: create_user would wipe A's login first.
    resp = await client.post("/api/radius/users", headers=_bearer(world["b"]),
                             json={"username": "userA", "customer_id": world["cust_b"].id})
    assert resp.status_code == 409
    row = (await db.execute(text(
        "SELECT customer_id, value FROM radius_check WHERE username = 'userA' AND attribute = 'Cleartext-Password'"
    ))).one()
    assert row.customer_id == world["cust_a"].id and row.value == "secretpw"


async def test_reseller_must_link_manual_logins_to_their_customer(client, world):
    resp = await client.post("/api/radius/users", headers=_bearer(world["b"]), json={"username": "free"})
    assert resp.status_code == 400


async def test_unlinked_logins_are_admin_only(client, db, world):
    await _add_radius_user(db, "orphan", None)
    assert (await client.get("/api/radius/users/orphan", headers=_bearer(world["a"]))).status_code == 404
    assert (await client.get("/api/radius/users/orphan", headers=_bearer(world["admin"]))).status_code == 200


async def test_lists_and_stats_only_show_the_callers_routers(client, world):
    hb = _bearer(world["b"])

    listed = (await client.get("/api/radius/routers", headers=hb)).json()
    assert [r["router_id"] for r in listed] == [world["router_b"].id]
    # The old default listed user_id=1's routers to anyone; a reseller can't ask for another's.
    spoofed = (await client.get(f"/api/radius/routers?user_id={world['a'].id}", headers=hb)).json()
    assert [r["router_id"] for r in spoofed] == [world["router_b"].id]

    sessions = (await client.get("/api/radius/sessions", headers=hb)).json()
    assert sorted(s["session_id"] for s in sessions) == ["sB", "sR2"]

    stats = (await client.get("/api/radius/accounting/roamer", headers=hb)).json()
    # Postgres SUM(bigint) is numeric and serialises as a string; SQLite gives an int.
    assert stats["total_sessions"] == 1 and int(stats["total_bytes_in"]) == 7
    stats_a = (await client.get("/api/radius/accounting/userA", headers=hb)).json()
    assert stats_a["total_sessions"] == 0


async def test_reseller_with_no_routers_sees_no_sessions(client, db, world):
    lonely = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    resp = await client.get("/api/radius/sessions", headers=_bearer(lonely))
    assert resp.status_code == 200 and resp.json() == []


async def test_cleanup_is_admin_only(client, world, monkeypatch):
    # The real sweep uses Postgres NOW(); only the access decision is under test.
    async def fake_cleanup(self):
        return 3
    monkeypatch.setattr(radius_endpoints.RadiusService, "cleanup_expired_users", fake_cleanup)
    assert (await client.post("/api/radius/cleanup", headers=_bearer(world["a"]))).status_code == 403
    resp = await client.post("/api/radius/cleanup", headers=_bearer(world["admin"]))
    assert resp.status_code == 200 and resp.json()["expired_users_removed"] == 3


# ---------------------------------------------------------------------------
# Owner and admin
# ---------------------------------------------------------------------------

async def test_owner_manages_their_router_end_to_end(client, db, world):
    ha = _bearer(world["a"])
    ra = world["router_a"].id

    resp = await client.post(f"/api/radius/routers/{ra}/disable", headers=ha)
    assert resp.status_code == 200 and resp.json()["auth_method"] == "DIRECT_API"
    status = (await client.get(f"/api/radius/routers/{ra}/status", headers=ha)).json()
    assert status["radius_enabled"] is False

    resp = await client.post(f"/api/radius/routers/{ra}/enable", headers=ha,
                             json={"radius_secret": "new-shared-secret"})
    assert resp.status_code == 200
    status = (await client.get(f"/api/radius/routers/{ra}/status", headers=ha)).json()
    assert status["radius_enabled"] is True and status["radius_secret_set"] is True
    assert status["active_sessions"] == 2  # sA + sR1 on 10.0.1.1

    test = (await client.get(f"/api/radius/test/{ra}", headers=ha)).json()
    assert test["checks"]["can_create_user"] and test["checks"]["can_delete_user"]
    assert test["success"] is True


async def test_owner_manages_their_customers_logins_and_sessions(client, db, world):
    ha = _bearer(world["a"])
    ra = world["router_a"].id

    resp = await client.post("/api/radius/users", headers=ha,
                             json={"username": "newA", "customer_id": world["cust_a"].id})
    assert resp.status_code == 200 and resp.json()["password"]
    got = (await client.get("/api/radius/users/newA", headers=ha)).json()
    assert got["customer_id"] == world["cust_a"].id

    # Re-creating your own username is allowed (it replaces the login).
    resp = await client.post("/api/radius/users", headers=ha,
                             json={"username": "userA", "customer_id": world["cust_a"].id, "password": "pw2"})
    assert resp.status_code == 200

    sessions = (await client.get(f"/api/radius/sessions?router_id={ra}", headers=ha)).json()
    assert sorted(s["session_id"] for s in sessions) == ["sA", "sR1"]

    resp = await client.post(f"/api/radius/sessions/userA/disconnect?router_id={ra}", headers=ha)
    assert resp.status_code == 200 and resp.json()["success"] is True
    assert FakeCoA.calls == [("10.0.1.1", SECRET, "userA")]

    resp = await client.delete(f"/api/radius/users/newA?router_id={ra}", headers=ha)
    assert resp.status_code == 200 and resp.json()["deleted"] is True
    assert resp.json()["disconnect_result"]["success"] is True
    assert (await db.execute(text("SELECT COUNT(*) FROM radius_check WHERE username = 'newA'"))).scalar() == 0


async def test_admin_reaches_any_reseller(client, world):
    h = _bearer(world["admin"])
    ra = world["router_a"].id
    assert (await client.get(f"/api/radius/routers/{ra}/status", headers=h)).status_code == 200
    assert (await client.get("/api/radius/users/userB", headers=h)).status_code == 200
    listed = (await client.get(f"/api/radius/routers?user_id={world['a'].id}", headers=h)).json()
    assert [r["router_id"] for r in listed] == [ra]
    sessions = (await client.get("/api/radius/sessions", headers=h)).json()
    assert len(sessions) == 4


# ---------------------------------------------------------------------------
# Staff
# ---------------------------------------------------------------------------

async def test_staff_need_the_right_permission(client, db, world):
    a, ra = world["a"], world["router_a"].id
    technician = await _staff_headers(db, a, ["routers.view", "routers.manage", "customers.view"])
    cashier = await _staff_headers(db, a, ["customers.view", "vouchers.generate", "transactions.view"])
    manager = await _staff_headers(db, a, ["customers.manage", "routers.view"])

    # Technician: router mode yes, logins no.
    assert (await client.post(f"/api/radius/routers/{ra}/enable", headers=technician,
                              json={"radius_secret": "tech-secret-1"})).status_code == 200
    resp = await client.post("/api/radius/users", headers=technician,
                             json={"username": "t1", "customer_id": world["cust_a"].id})
    assert resp.status_code == 403
    assert (await client.get("/api/radius/users/userA", headers=technician)).status_code == 403

    # Cashier: can read accounting and sessions, cannot touch the router.
    assert (await client.post(f"/api/radius/routers/{ra}/disable", headers=cashier)).status_code == 403
    assert (await client.get("/api/radius/accounting/userA", headers=cashier)).status_code == 200
    assert (await client.get("/api/radius/sessions", headers=cashier)).status_code == 200

    # Manager (customers.manage): logins and disconnects.
    assert (await client.post("/api/radius/users", headers=manager,
                              json={"username": "m1", "customer_id": world["cust_a"].id})).status_code == 200
    assert (await client.post(f"/api/radius/sessions/userA/disconnect?router_id={ra}",
                              headers=manager)).status_code == 200

    # Nobody on staff reaches the global cleanup.
    full = await _staff_headers(db, a, list(perms.PERMISSIONS))
    assert (await client.post("/api/radius/cleanup", headers=full)).status_code == 403


async def test_staff_of_another_reseller_get_404(client, db, world):
    staff_b = await _staff_headers(db, world["b"], ["routers.manage", "customers.manage"])
    ra = world["router_a"].id
    assert (await client.post(f"/api/radius/routers/{ra}/disable", headers=staff_b)).status_code == 404
    assert (await client.get("/api/radius/users/userA", headers=staff_b)).status_code == 404


# ---------------------------------------------------------------------------
# Staff map coverage for /api/radius (until tests/test_staff_coverage.py lands)
# ---------------------------------------------------------------------------

STAFF_RADIUS_ROUTES = {
    ("GET", "/api/radius/routers"): "routers.view",
    ("GET", "/api/radius/routers/{router_id}/status"): "routers.view",
    ("POST", "/api/radius/routers/{router_id}/enable"): "routers.manage",
    ("POST", "/api/radius/routers/{router_id}/disable"): "routers.manage",
    ("GET", "/api/radius/test/{router_id}"): "routers.manage",
    ("GET", "/api/radius/sessions"): ("routers.view", "customers.view"),
    ("POST", "/api/radius/sessions/{username}/disconnect"): ("customers.manage", "routers.manage"),
    ("GET", "/api/radius/accounting/{username}"): "customers.view",
    ("GET", "/api/radius/users/{username}"): "customers.manage",
    ("POST", "/api/radius/users"): "customers.manage",
    ("DELETE", "/api/radius/users/{username}"): "customers.manage",
}
NOT_FOR_STAFF_RADIUS = {
    ("POST", "/api/radius/cleanup"),                           # admin-only, every reseller
    ("POST", "/api/radius/hotspot/register-and-pay"),          # public captive portal
    ("GET", "/api/radius/hotspot/payment-status/{customer_id}"),  # public captive portal
    ("POST", "/api/radius/mpesa/callback"),                    # Safaricom callback
}


def _walk(routes, prefix=""):
    """(method, path) for every route. FastAPI 0.14x (CI, production) keeps each
    include_router() as a lazy wrapper with `original_router`; older FastAPI
    flattens. Walk both so this never passes or fails vacuously."""
    for route in routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, prefix + route.path
        elif hasattr(route, "original_router"):
            ctx = getattr(route, "include_context", None)
            yield from _walk(route.original_router.routes, prefix + (getattr(ctx, "prefix", "") or ""))


def _app_radius_routes():
    import main
    every = set(_walk(main.app.routes))
    assert len(every) > 400, f"only {len(every)} routes found; route walk is broken"
    return {(m, p) for m, p in every if p.startswith("/api/radius")}


def test_every_radius_route_is_classified_for_staff():
    routes = _app_radius_routes()
    assert routes == set(STAFF_RADIUS_ROUTES) | NOT_FOR_STAFF_RADIUS


@pytest.mark.parametrize("method,path", sorted(STAFF_RADIUS_ROUTES))
def test_radius_staff_rules(method, path):
    rule, _ = perms.match_rule(method, path.replace("{router_id}", "7").replace("{username}", "u1"))
    assert rule is not None and rule.template == path
    assert rule.requirement == STAFF_RADIUS_ROUTES[(method, path)]


@pytest.mark.parametrize("method,path", sorted(NOT_FOR_STAFF_RADIUS))
def test_radius_routes_not_in_staff_map(method, path):
    rule, _ = perms.match_rule(method, path.replace("{customer_id}", "7"))
    assert rule is None


# ---------------------------------------------------------------------------
# Public / machine callers keep working without a token
# ---------------------------------------------------------------------------

async def test_public_portal_and_callback_routes_still_answer_without_a_token(client, world):
    resp = await client.get("/api/radius/hotspot/payment-status/999999")
    assert resp.status_code == 404  # reached the handler, not an auth wall

    resp = await client.post("/api/radius/hotspot/register-and-pay", json={
        "mac_address": "AA:BB:CC:DD:EE:FF", "phone": "254700000000",
        "plan_id": 1, "router_id": 999999,
    })
    assert resp.status_code == 404

    resp = await client.post("/api/radius/mpesa/callback", json={"Body": {"stkCallback": {}}})
    assert resp.status_code == 200 and resp.json()["ResultCode"] == 1

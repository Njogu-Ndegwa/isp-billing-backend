"""The /api/radius/* HTTP routes are gone, and stay gone.

Until 29 Oct 2026 app/api/radius_endpoints.py and app/api/radius_hotspot.py
served fifteen routes with no authentication: anyone on the internet could
switch any router to RADIUS, mint RADIUS logins, read their passwords,
disconnect sessions, and read RADIUS credentials of any active customer from
the public payment-status route. RADIUS is not used (only the admin test
router 4 was ever switched to it; the live captive portal only calls the
RADIUS pay routes for a router in RADIUS mode), so the routes were removed
rather than secured.

These tests pin that:

* every former route answers 404 for anonymous callers, resellers and admins,
  and nothing in the RADIUS tables or the router row changes;
* no route under /api/radius is registered, and no staff rule names one;
* the normal (non-RADIUS) hotspot pay flow and M-Pesa callback still exist.
"""

from datetime import timedelta

import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient

from app.api.auth_routes import login_token_claims
from app.db.models import RouterAuthMethod, SubscriptionStatus
from app.services import staff_permissions as perms
from app.services.auth import create_access_token
from tests.factories import make_admin, make_reseller, make_router


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user):
    token = create_access_token(login_token_claims(user), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


def _former_routes(router_id):
    return [
        ("POST", f"/api/radius/routers/{router_id}/enable", {"radius_secret": "attacker-secret"}),
        ("POST", f"/api/radius/routers/{router_id}/disable", None),
        ("GET", f"/api/radius/routers/{router_id}/status", None),
        ("GET", "/api/radius/routers", None),
        ("POST", "/api/radius/users", {"username": "evil"}),
        ("GET", "/api/radius/users/someone", None),
        ("DELETE", "/api/radius/users/someone", None),
        ("GET", "/api/radius/sessions", None),
        ("POST", f"/api/radius/sessions/someone/disconnect?router_id={router_id}", None),
        ("GET", "/api/radius/accounting/someone", None),
        ("POST", "/api/radius/cleanup", None),
        ("GET", f"/api/radius/test/{router_id}", None),
        ("POST", "/api/radius/hotspot/register-and-pay",
         {"mac_address": "AA:BB:CC:DD:EE:FF", "phone": "254700000000", "plan_id": 1, "router_id": router_id}),
        ("GET", "/api/radius/hotspot/payment-status/1", None),
        ("POST", "/api/radius/mpesa/callback", {"Body": {"stkCallback": {"CheckoutRequestID": "x", "ResultCode": 0}}}),
    ]


async def test_every_former_radius_route_is_404_for_everyone(client, db):
    owner = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    admin = await make_admin(db)
    router = await make_router(db, owner, auth_method=RouterAuthMethod.RADIUS, radius_secret="router-secret")

    for headers in ({}, _bearer(owner), _bearer(admin)):
        for method, path, body in _former_routes(router.id):
            resp = await client.request(method, path, json=body, headers=headers)
            assert resp.status_code == 404, (method, path, headers.keys(), resp.status_code, resp.text)

    await db.refresh(router)
    assert router.auth_method == RouterAuthMethod.RADIUS
    assert router.radius_secret == "router-secret"


def _walk(routes, prefix=""):
    """(method, path) for every route. FastAPI 0.14x (CI, production) keeps each
    include_router() as a lazy wrapper with `original_router`; older FastAPI
    flattens. Walk both so this never passes vacuously."""
    for route in routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, prefix + route.path
        elif hasattr(route, "original_router"):
            ctx = getattr(route, "include_context", None)
            yield from _walk(route.original_router.routes, prefix + (getattr(ctx, "prefix", "") or ""))


def _app_routes():
    import main
    routes = set(_walk(main.app.routes))
    assert len(routes) > 400, f"only {len(routes)} routes found; route walk is broken"
    return routes


def test_no_radius_route_is_registered():
    assert sorted(p for _, p in _app_routes() if p.startswith("/api/radius")) == []


def test_no_staff_rule_names_a_radius_route():
    assert [r.template for r in perms.RULES if r.template.startswith("/api/radius")] == []


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/hotspot/register-and-pay"),
    ("GET", "/api/hotspot/payment-status/{customerId}"),
    ("POST", "/api/mpesa/callback"),
])
def test_normal_hotspot_pay_flow_is_still_served(method, path):
    assert (method, path) in _app_routes()

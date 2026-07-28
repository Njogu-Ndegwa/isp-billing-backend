"""Contract for the router-facing usage-push endpoint.

This endpoint is different from every other route in the app: it is called *by
customer hardware in the field*, on an interval the router chooses, and the fleet
is expected to grow. Polling had a natural throttle — we decided when to call.
Push does not, so the throttle has to live here.

What these tests pin:

* **Auth** — a router proves identity with a token derived from the server secret.
  Nothing is stored for this, so it costs no schema and no migration.
* **Tenant isolation** — router A's token cannot report for router B.
* **Load shedding** — when the DB pool is under pressure the server says "not now"
  instead of falling over. This is safe *because reports are cumulative*: the next
  push carries the same totals, so a dropped push loses nothing.
* **Rate limiting** — one router cannot pin the server by pushing in a loop,
  whether misconfigured or malicious.

Together those are what make a thousand routers pushing survivable when a single
worker on a 1 GB box is receiving them.
"""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.usage_push_routes import router as usage_push_router
from app.db.models import ConnectionType, CustomerStatus, CustomerUsagePeriod
from app.services import usage_push
from app.services.usage_push_auth import derive_router_token
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


@pytest_asyncio.fixture
async def app(session_factory, monkeypatch):
    monkeypatch.setattr(usage_push, "async_session", session_factory, raising=False)
    import app.api.usage_push_routes as routes
    monkeypatch.setattr(routes, "async_session", session_factory, raising=False)
    # Default to a healthy pool; individual tests override.
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    routes.reset_rate_limiter()

    application = FastAPI()
    application.include_router(usage_push_router)
    return application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _setup(db, *, identity="Router-0721", mac="AA:BB:CC:11:22:33"):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=identity)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(
        db, reseller, plan, router,
        mac_address=mac, status=CustomerStatus.ACTIVE,
    )
    return router, customer


def _body(identity, reports):
    return {"identity": identity, "reports": reports}


def _auth(identity):
    return {"Authorization": f"Bearer {derive_router_token(identity)}"}


@pytest.mark.asyncio
async def test_authenticated_push_is_accepted_and_recorded(db, client, session_factory):
    router, customer = await _setup(db)

    r1 = await client.post(
        "/api/router/usage-push",
        json=_body("Router-0721", [
            {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": 0, "download_bytes": 0},
        ]),
        headers=_auth("Router-0721"),
    )
    assert r1.status_code == 200

    import app.api.usage_push_routes as routes
    routes.reset_rate_limiter()

    r2 = await client.post(
        "/api/router/usage-push",
        json=_body("Router-0721", [
            {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": 2 * MB, "download_bytes": 8 * MB},
        ]),
        headers=_auth("Router-0721"),
    )
    assert r2.status_code == 200
    assert r2.json()["accepted"] == 1

    async with session_factory() as s:
        period = (await s.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id
            )
        )).scalar_one()
    assert period.total_bytes == 10 * MB


@pytest.mark.asyncio
async def test_missing_or_wrong_token_is_rejected(db, client):
    await _setup(db)
    payload = _body("Router-0721", [
        {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": MB, "download_bytes": MB},
    ])

    no_auth = await client.post("/api/router/usage-push", json=payload)
    assert no_auth.status_code == 401

    wrong = await client.post(
        "/api/router/usage-push", json=payload,
        headers={"Authorization": "Bearer not-the-right-token"},
    )
    assert wrong.status_code == 401


@pytest.mark.asyncio
async def test_token_for_one_router_cannot_report_for_another(db, client):
    """The token is bound to the identity it was derived from."""
    await _setup(db, identity="Router-AAAA", mac="AA:BB:CC:00:00:01")
    await _setup(db, identity="Router-BBBB", mac="AA:BB:CC:00:00:02")

    resp = await client.post(
        "/api/router/usage-push",
        json=_body("Router-AAAA", [
            {"queue_key": "AA:BB:CC:00:00:02", "upload_bytes": MB, "download_bytes": MB},
        ]),
        headers=_auth("Router-BBBB"),  # B's token, claiming to be A
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unknown_identity_is_rejected(db, client):
    await _setup(db)
    resp = await client.post(
        "/api/router/usage-push",
        json=_body("Router-DOES-NOT-EXIST", []),
        headers=_auth("Router-DOES-NOT-EXIST"),
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_server_sheds_load_when_the_db_pool_is_under_pressure(db, client, monkeypatch):
    """The protection that matters at fleet scale.

    Under pool pressure the endpoint must refuse cheaply and tell the router when
    to come back, rather than queue work that drains the pool. Nothing is lost:
    counters are cumulative, so the next push carries the same totals.
    """
    await _setup(db)
    import app.api.usage_push_routes as routes
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: True)

    resp = await client.post(
        "/api/router/usage-push",
        json=_body("Router-0721", [
            {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": MB, "download_bytes": MB},
        ]),
        headers=_auth("Router-0721"),
    )

    assert resp.status_code == 503
    assert int(resp.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_router_pushing_too_fast_is_rate_limited(db, client):
    """One router cannot pin the server by looping, misconfigured or otherwise."""
    await _setup(db)
    payload = _body("Router-0721", [
        {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": MB, "download_bytes": MB},
    ])

    first = await client.post("/api/router/usage-push", json=payload, headers=_auth("Router-0721"))
    assert first.status_code == 200

    second = await client.post("/api/router/usage-push", json=payload, headers=_auth("Router-0721"))
    assert second.status_code == 429
    assert int(second.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_rate_limit_is_per_router_not_global(db, client):
    """A busy router must not throttle everyone else's reports."""
    await _setup(db, identity="Router-AAAA", mac="AA:BB:CC:00:00:11")
    await _setup(db, identity="Router-BBBB", mac="AA:BB:CC:00:00:22")

    a1 = await client.post(
        "/api/router/usage-push",
        json=_body("Router-AAAA", [
            {"queue_key": "AA:BB:CC:00:00:11", "upload_bytes": MB, "download_bytes": MB}]),
        headers=_auth("Router-AAAA"),
    )
    a2 = await client.post(
        "/api/router/usage-push",
        json=_body("Router-AAAA", [
            {"queue_key": "AA:BB:CC:00:00:11", "upload_bytes": MB, "download_bytes": MB}]),
        headers=_auth("Router-AAAA"),
    )
    b1 = await client.post(
        "/api/router/usage-push",
        json=_body("Router-BBBB", [
            {"queue_key": "AA:BB:CC:00:00:22", "upload_bytes": MB, "download_bytes": MB}]),
        headers=_auth("Router-BBBB"),
    )

    assert a1.status_code == 200
    assert a2.status_code == 429
    assert b1.status_code == 200


@pytest.mark.asyncio
async def test_oversized_batch_is_refused_before_any_work(db, client):
    """A malformed or hostile payload cannot make the server do unbounded work."""
    await _setup(db)
    reports = [
        {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": 1, "download_bytes": 1}
    ] * 5000

    resp = await client.post(
        "/api/router/usage-push",
        json=_body("Router-0721", reports),
        headers=_auth("Router-0721"),
    )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_response_tells_the_router_when_to_come_back(db, client):
    """The router takes its cadence from the server, so the interval can be
    tuned centrally without touching 1,000 devices."""
    await _setup(db)

    resp = await client.post(
        "/api/router/usage-push",
        json=_body("Router-0721", [
            {"queue_key": "AA:BB:CC:11:22:33", "upload_bytes": 0, "download_bytes": 0}]),
        headers=_auth("Router-0721"),
    )

    assert resp.status_code == 200
    assert resp.json()["next_push_seconds"] > 0

"""Admin "View as reseller": read-only, 30-minute, revocable sessions.

Driven through the real ``main.app`` (no lifespan, so no migrations or
scheduler) so the middleware order -- shadow mode, CORS, then the View-as guard
-- is exactly what production runs.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import select

from app.config import settings
from app.core.security import ALGORITHM
from app.db.models import ImpersonationSession
from app.services import impersonation
from app.services.auth import create_access_token
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

REASON = "Checking a reported billing issue"


def _token_for(user, **extra) -> str:
    claims = {
        "sub": str(user.id),
        "user_code": user.user_code,
        "user_id": user.id,
        "role": user.role.value,
        "organization_name": user.organization_name,
        **extra,
    }
    return create_access_token(claims, timedelta(minutes=30))


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _fresh_cache():
    impersonation.reset_cache()
    yield
    impersonation.reset_cache()


@pytest_asyncio.fixture
async def client(engine):
    import main

    async with AsyncClient(
        transport=ASGITransport(app=main.app), base_url="http://test"
    ) as c:
        yield c


@pytest_asyncio.fixture
async def actors(db):
    admin = await make_admin(db)
    reseller = await make_reseller(db, organization_name="Acme WiFi")
    return admin, reseller


async def _start(client, admin, reseller, reason=REASON):
    return await client.post(
        f"/api/admin/impersonate/{reseller.id}",
        json={"reason": reason},
        headers={**_bearer(_token_for(admin)), "User-Agent": "pytest-agent"},
    )


# --------------------------------------------------------------------------
# Starting a session
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_starts_session_with_claims_ttl_and_shape(client, actors, session_factory):
    admin, reseller = actors
    before = datetime.utcnow()
    resp = await _start(client, admin, reseller, reason=f"  {REASON}  ")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["token_type"] == "bearer"
    assert body["read_only"] is True
    assert body["impersonator"] == {"id": admin.id, "email": admin.email}
    # Same user shape the reseller's own login returns.
    assert set(body["user"]) == {
        "id", "email", "role", "organization_name", "business_name",
        "support_phone", "mpesa_shortcode", "subscription_status",
        "subscription_expires_at", "preferred_language", "market",
    }
    assert body["user"]["id"] == reseller.id
    assert body["user"]["role"] == "reseller"
    assert body["expires_at"].endswith("Z")

    claims = jwt.decode(body["access_token"], settings.SECRET_KEY, algorithms=[ALGORITHM])
    assert claims["imp_sid"] == body["session_id"]
    assert claims["imp_by"] == admin.id
    assert claims["ro"] is True
    assert claims["user_id"] == reseller.id
    assert claims["sub"] == str(reseller.id)
    assert claims["role"] == "reseller"
    assert claims["user_code"] == reseller.user_code
    assert claims["organization_name"] == "Acme WiFi"

    ttl = datetime.utcfromtimestamp(claims["exp"]) - before
    assert timedelta(minutes=29) < ttl <= timedelta(minutes=30, seconds=1)
    expires_at = datetime.fromisoformat(body["expires_at"].rstrip("Z"))
    assert datetime.utcfromtimestamp(claims["exp"]) == expires_at

    async with session_factory() as s:
        row = await s.get(ImpersonationSession, body["session_id"])
    assert row.admin_id == admin.id
    assert row.reseller_id == reseller.id
    assert row.reason == REASON  # stripped
    assert row.ended_at is None and row.end_reason is None
    assert row.expires_at == expires_at
    assert row.user_agent == "pytest-agent"


@pytest.mark.asyncio
async def test_non_admin_cannot_start(client, db, actors):
    _, reseller = actors
    other = await make_reseller(db)
    resp = await client.post(
        f"/api/admin/impersonate/{other.id}",
        json={"reason": REASON},
        headers=_bearer(_token_for(reseller)),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_impersonation_token_cannot_start_another(client, db, actors):
    admin, reseller = actors
    other = await make_reseller(db)
    token = (await _start(client, admin, reseller)).json()["access_token"]

    resp = await client.post(
        f"/api/admin/impersonate/{other.id}",
        json={"reason": REASON},
        headers=_bearer(token),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Already viewing as a reseller"


@pytest.mark.asyncio
async def test_forged_admin_role_with_imp_sid_cannot_start(client, actors):
    """Even an imp_sid token that claimed admin is refused first."""
    admin, reseller = actors
    real = (await _start(client, admin, reseller)).json()
    forged = _token_for(admin, imp_sid=real["session_id"], imp_by=admin.id, ro=True)
    resp = await client.post(
        f"/api/admin/impersonate/{reseller.id}",
        json={"reason": REASON},
        headers=_bearer(forged),
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Already viewing as a reseller"


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [None, "", "    ", "abcd", "  ab  ", "x" * 301])
async def test_reason_validation(client, actors, session_factory, reason):
    admin, reseller = actors
    payload = {} if reason is None else {"reason": reason}
    resp = await client.post(
        f"/api/admin/impersonate/{reseller.id}",
        json=payload,
        headers=_bearer(_token_for(admin)),
    )
    assert resp.status_code == 400
    async with session_factory() as s:
        assert (await s.execute(select(ImpersonationSession))).first() is None


@pytest.mark.asyncio
async def test_reason_boundaries_accepted(client, actors):
    admin, reseller = actors
    assert (await _start(client, admin, reseller, reason="abcde")).status_code == 200
    assert (await _start(client, admin, reseller, reason="x" * 300)).status_code == 200


@pytest.mark.asyncio
async def test_target_admin_or_missing_is_404(client, db, actors):
    admin, _ = actors
    other_admin = await make_admin(db)
    for target in (other_admin.id, admin.id, 999999):
        resp = await client.post(
            f"/api/admin/impersonate/{target}",
            json={"reason": REASON},
            headers=_bearer(_token_for(admin)),
        )
        assert resp.status_code == 404, target


# --------------------------------------------------------------------------
# Using the token
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_allowed_and_authenticates_as_reseller(client, actors, caplog):
    admin, reseller = actors
    started = (await _start(client, admin, reseller)).json()
    caplog.set_level("INFO", logger="app.services.impersonation")
    resp = await client.get("/api/profile", headers=_bearer(started["access_token"]))
    assert resp.status_code == 200, resp.text
    assert resp.json()["email"] == reseller.email
    assert (
        f"[view-as sid={started['session_id']} admin={admin.id} reseller={reseller.id}] "
        "GET /api/profile -> 200"
    ) in caplog.text


@pytest.mark.asyncio
async def test_impersonation_token_never_passes_admin_checks(client, actors):
    admin, reseller = actors
    token = (await _start(client, admin, reseller)).json()["access_token"]
    resp = await client.get("/api/admin/resellers", headers=_bearer(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/api/plans/create", {"name": "x"}),
        ("POST", "/api/compensation/outage", {}),
        ("PATCH", "/api/profile", {"business_name": "Changed"}),
        ("PUT", "/api/profile/password", {}),
        ("DELETE", "/api/profile", None),
        ("DELETE", "/api/plans/1", None),
        ("POST", "/api/routers/1/load-balancing/preflight", {"wan_ports": ["ether1"]}),
        ("POST", "/graphql", {"query": "mutation { x }"}),
        ("POST", "/api/customers/usage/bulk/extra", {}),
    ],
)
async def test_writes_blocked_with_code(client, db, actors, method, path, body):
    admin, reseller = actors
    token = (await _start(client, admin, reseller)).json()["access_token"]
    resp = await client.request(method, path, json=body, headers=_bearer(token))
    assert resp.status_code == 403, resp.text
    assert resp.json() == {
        "detail": impersonation.READ_ONLY_DETAIL,
        "code": "impersonation_read_only",
    }
    await db.refresh(reseller)
    assert reseller.business_name is None


@pytest.mark.asyncio
async def test_blocked_response_carries_cors_headers(client, actors):
    """CORS wraps the guard, so the browser can read the 403 body and code."""
    admin, reseller = actors
    token = (await _start(client, admin, reseller)).json()["access_token"]
    resp = await client.patch(
        "/api/profile",
        json={"business_name": "x"},
        headers={**_bearer(token), "Origin": "https://app.example.com"},
    )
    assert resp.status_code == 403
    assert resp.headers.get("access-control-allow-origin")


@pytest.mark.asyncio
async def test_allowlisted_post_reaches_handler(client, db, actors):
    admin, reseller = actors
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    token = (await _start(client, admin, reseller)).json()["access_token"]

    resp = await client.post(
        "/api/customers/usage/bulk",
        json={"customer_ids": [customer.id]},
        headers=_bearer(token),
    )
    assert resp.status_code == 200, resp.text
    assert [row["customer_id"] for row in resp.json()] == [customer.id]

    # The handler's own validation runs (not the guard's 403).
    resp = await client.post(
        "/api/customers/usage/bulk", json={"customer_ids": []}, headers=_bearer(token)
    )
    assert resp.status_code == 400


def test_allowlist_is_exactly_the_reviewed_read_only_posts():
    allowed = [
        "/api/impersonation/end",
        "/api/customers/usage/bulk",
        "/api/messaging/customer-events/preview",
        "/api/compensation/outage/preview",
    ]
    for path in allowed:
        assert impersonation.is_allowlisted(path), path
    for path in [
        "/api/compensation/outage",
        "/api/routers/7/load-balancing/preflight",
        "/api/routers/7/load-balancing/enable",
        "/graphql",
        "/api/customers/usage/bulkx",
        "/x/api/customers/usage/bulk",
        "/api/admin/impersonate/5",
    ]:
        assert not impersonation.is_allowlisted(path), path


# --------------------------------------------------------------------------
# Ending and expiry
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_end_revokes_token(client, actors, session_factory):
    admin, reseller = actors
    started = (await _start(client, admin, reseller)).json()
    token = started["access_token"]
    assert (await client.get("/api/profile", headers=_bearer(token))).status_code == 200

    resp = await client.post("/api/impersonation/end", headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json() == {"ended": True}

    async with session_factory() as s:
        row = await s.get(ImpersonationSession, started["session_id"])
    assert row.ended_at is not None
    assert row.end_reason == "exit"

    for method, path in [("GET", "/api/profile"), ("POST", "/api/impersonation/end"),
                         ("PATCH", "/api/profile")]:
        resp = await client.request(method, path, json={}, headers=_bearer(token))
        assert resp.status_code == 401, (method, path)
        assert resp.json() == {"detail": "View-as session ended",
                               "code": "impersonation_ended"}


@pytest.mark.asyncio
async def test_session_ended_elsewhere_is_seen_after_cache_ttl(
    client, actors, session_factory, monkeypatch
):
    """Ended in the DB (another process): picked up once the cache entry ages."""
    admin, reseller = actors
    started = (await _start(client, admin, reseller)).json()
    token = started["access_token"]
    assert (await client.get("/api/profile", headers=_bearer(token))).status_code == 200

    async with session_factory() as s:
        row = await s.get(ImpersonationSession, started["session_id"])
        row.ended_at = datetime.utcnow()
        row.end_reason = "exit"
        await s.commit()

    monkeypatch.setattr(impersonation, "SESSION_CHECK_TTL_SECONDS", 0)
    resp = await client.get("/api/profile", headers=_bearer(token))
    assert resp.status_code == 401
    assert resp.json()["code"] == "impersonation_ended"


@pytest.mark.asyncio
async def test_end_with_normal_token_is_400(client, actors):
    admin, reseller = actors
    for user in (admin, reseller):
        resp = await client.post("/api/impersonation/end", headers=_bearer(_token_for(user)))
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_expired_token_rejected_and_session_marked(client, actors, session_factory):
    admin, reseller = actors
    started = (await _start(client, admin, reseller)).json()
    sid = started["session_id"]
    claims = jwt.decode(started["access_token"], settings.SECRET_KEY, algorithms=[ALGORITHM])
    claims["exp"] = datetime.utcnow() - timedelta(minutes=1)
    expired = jwt.encode(claims, settings.SECRET_KEY, algorithm=ALGORITHM)

    resp = await client.get("/api/profile", headers=_bearer(expired))
    assert resp.status_code == 401
    assert resp.json()["code"] == "impersonation_ended"

    async with session_factory() as s:
        row = await s.get(ImpersonationSession, sid)
    assert row.ended_at is not None
    assert row.end_reason == "expired"


@pytest.mark.asyncio
async def test_session_past_db_expiry_rejected(client, actors, session_factory):
    admin, reseller = actors
    started = (await _start(client, admin, reseller)).json()
    async with session_factory() as s:
        row = await s.get(ImpersonationSession, started["session_id"])
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        await s.commit()

    resp = await client.get("/api/profile", headers=_bearer(started["access_token"]))
    assert resp.status_code == 401
    assert resp.json()["code"] == "impersonation_ended"


@pytest.mark.asyncio
async def test_unknown_session_id_rejected(client, actors):
    _, reseller = actors
    token = _token_for(reseller, imp_sid=424242, imp_by=1, ro=True)
    resp = await client.get("/api/profile", headers=_bearer(token))
    assert resp.status_code == 401
    assert resp.json()["code"] == "impersonation_ended"


@pytest.mark.asyncio
async def test_new_session_closes_this_admins_timed_out_sessions(client, actors, session_factory):
    admin, reseller = actors
    first = (await _start(client, admin, reseller)).json()
    async with session_factory() as s:
        row = await s.get(ImpersonationSession, first["session_id"])
        row.expires_at = datetime.utcnow() - timedelta(minutes=5)
        await s.commit()

    assert (await _start(client, admin, reseller)).status_code == 200
    async with session_factory() as s:
        row = await s.get(ImpersonationSession, first["session_id"])
    assert row.end_reason == "expired"
    assert row.ended_at == row.expires_at


# --------------------------------------------------------------------------
# Ordinary tokens are untouched
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_normal_tokens_unaffected_for_writes(client, db, actors):
    admin, reseller = actors
    resp = await client.patch(
        "/api/profile",
        json={"business_name": "Acme Ltd"},
        headers=_bearer(_token_for(reseller)),
    )
    assert resp.status_code == 200, resp.text
    await db.refresh(reseller)
    assert reseller.business_name == "Acme Ltd"

    # An admin's own write goes to the handler (validation 422), not the guard.
    resp = await client.post("/api/plans/create", json={}, headers=_bearer(_token_for(admin)))
    assert resp.status_code == 422
    assert "impersonation" not in resp.text


@pytest.mark.asyncio
async def test_garbage_and_missing_tokens_left_to_normal_auth(client):
    resp = await client.patch("/api/profile", json={})
    assert resp.status_code == 401
    assert "code" not in resp.json()
    resp = await client.patch("/api/profile", json={}, headers=_bearer("not.a.jwt"))
    assert resp.status_code == 401
    assert "code" not in resp.json()


def test_guard_registered_inside_cors_and_shadow():
    import main

    order = [
        m.kwargs.get("dispatch").__name__ if m.kwargs.get("dispatch") else m.cls.__name__
        for m in main.app.user_middleware
    ]
    assert order.index("enforce_shadow_mode") < order.index("CORSMiddleware")
    assert order.index("CORSMiddleware") < order.index("enforce_impersonation_read_only")


@pytest.mark.asyncio
async def test_shadow_mode_still_blocks_normal_writes(client, actors, monkeypatch):
    _, reseller = actors
    monkeypatch.setattr(settings, "SHADOW_MODE", True)
    resp = await client.patch(
        "/api/profile", json={"business_name": "x"}, headers=_bearer(_token_for(reseller))
    )
    assert resp.status_code == 503
    assert resp.json()["code"] == "shadow_mode_blocked"
    assert resp.headers["X-ISP-Runtime-Mode"] == "shadow"

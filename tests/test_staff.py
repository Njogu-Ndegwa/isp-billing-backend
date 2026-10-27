"""Staff permissions and revocation through the real app, with no external I/O."""
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.auth_routes import login_token_claims
from app.db.models import ResellerStaff, StaffActivityLog
from app.services import staff_access, staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router


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
async def actor(db):
    owner = await make_reseller(db)
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Test technician", email="staff@example.com",
        password_hash=pwd_context.hash("staff-password"), permissions=["customers.view", "routers.view"],
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    return owner, staff, token


@pytest.mark.parametrize("rule", perms.RULES, ids=lambda rule: f"{','.join(sorted(rule.methods))} {rule.template}")
def test_permission_matrix(rule):
    assert rule.allows(perms.PERMISSIONS)
    if rule.requirement != perms.ANY_STAFF:
        assert not rule.allows([])
        required = rule.requirement if isinstance(rule.requirement, tuple) else (rule.requirement,)
        for permission in required:
            assert permission in perms.PERMISSIONS
            assert rule.allows([permission])
    assert perms.STAFF_MANAGE not in (rule.requirement if isinstance(rule.requirement, tuple) else (rule.requirement,))


def test_presets_never_grant_sensitive_or_staff_management():
    for preset in perms.PRESETS:
        assert not set(preset["permissions"]) & (perms.SENSITIVE_PERMISSIONS | {perms.STAFF_MANAGE})
    assert perms.match_rule("POST", "/api/new-money-endpoint")[0] is None
    assert perms.match_rule("PUT", "/api/staff/123")[0] is None


@pytest.mark.asyncio
async def test_staff_login_is_own_identity_in_owner_scope(client, actor):
    owner, staff, token = actor
    response = await client.post("/api/auth/login", json={"email": " STAFF@EXAMPLE.COM ", "password": "staff-password"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["user"]["id"] == owner.id
    assert payload["user"]["email"] == staff.email
    assert payload["user"]["staff"]["id"] == staff.id
    me = await client.get("/api/staff/me", headers=headers(payload["access_token"]))
    assert me.status_code == 200
    assert me.json()["permissions"] == staff.permissions
    bad = await client.post("/api/auth/login", json={"email": staff.email, "password": "wrong-password"})
    assert bad.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", [
    ("POST", "/api/reseller/withdraw"), ("POST", "/api/payment-methods"),
    ("PUT", "/api/reseller/settlement-mode"), ("PUT", "/api/reseller/payout-settings"),
    ("PUT", "/api/routers/123/payment-method"), ("GET", "/api/admin/resellers"),
    ("GET", "/api/staff"), ("POST", "/api/staff"),
    ("PUT", "/api/staff/1"), ("GET", "/api/staff/activity"),
    ("PUT", "/api/profile"), ("POST", "/graphql"), ("GET", "/api/future-admin-route"),
])
async def test_staff_denied_before_handler(client, actor, method, path):
    response = await client.request(method, path, headers=headers(actor[2]), json={})
    assert response.status_code == 403, response.text
    assert response.json()["code"] == "staff_permission_denied"


@pytest.mark.asyncio
async def test_tenant_isolation_and_customer_edit_audit(client, actor, db):
    owner, staff, token = actor
    own_router = await make_router(db, owner)
    own_plan = await make_plan(db, owner)
    own_customer = await make_customer(db, owner, own_plan, own_router)
    other = await make_reseller(db)
    other_router = await make_router(db, other)
    other_plan = await make_plan(db, other)
    other_customer = await make_customer(db, other, other_plan, other_router)
    own = await client.get(f"/api/customers/{own_customer.id}", headers=headers(token))
    assert own.status_code == 200, own.text
    foreign = await client.get(f"/api/customers/{other_customer.id}", headers=headers(token))
    assert foreign.status_code in (403, 404), foreign.text
    foreign_plan = await client.get(f"/api/plans/by-router/{other_router.id}", headers=headers(token))
    assert foreign_plan.status_code in (403, 404), foreign_plan.text
    edit = await client.put(f"/api/customers/{own_customer.id}", headers=headers(token), json={})
    assert edit.status_code == 403
    audit = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.staff_id == staff.id))).scalars().all()
    assert any(row.status_code == 403 and "customer" in row.path for row in audit)


@pytest.mark.asyncio
async def test_owner_cannot_manage_other_tenants_staff(client, actor, db):
    other = await make_reseller(db)
    response = await client.put(f"/api/staff/{actor[1].id}", headers=headers(owner_token(other)), json={"is_active": False})
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["permissions", "deactivate", "remove", "password"])
async def test_revocation_immediate_for_tokens_and_webfig(client, actor, db, change):
    from app.services.router_remote_access import create_webfig_proxy_session
    owner, staff, token = actor
    staff.permissions = ["customers.view", "routers.manage"]
    await db.commit()
    webfig = create_webfig_proxy_session(1, "Test router", "192.0.2.1", owner.id,
                                        staff_id=staff.id, staff_token_version=0)
    assert await staff_access.webfig_staff_session_valid(webfig)
    assert (await client.get("/api/staff/me", headers=headers(token))).status_code == 200
    url = f"/api/staff/{staff.id}"
    auth = headers(owner_token(owner))
    if change == "remove":
        response = await client.delete(url, headers=auth)
    elif change == "password":
        response = await client.post(url + "/reset-password", headers=auth, json={"password": "new-password"})
    else:
        body = {"permissions": []} if change == "permissions" else {"is_active": False}
        response = await client.put(url, headers=auth, json=body)
    assert response.status_code == 200, response.text
    rejected = await client.get("/api/staff/me", headers=headers(token))
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "staff_session_revoked"
    assert not await staff_access.webfig_staff_session_valid(webfig)


@pytest.mark.asyncio
async def test_forged_owner_scope_rejected(client, actor, db):
    owner, staff, token = actor
    other = await make_reseller(db)
    claims = staff_access.staff_token_claims(staff, other)
    foreign = create_access_token(claims, timedelta(hours=1))
    assert (await client.get("/api/staff/me", headers=headers(foreign))).status_code == 401


@pytest.mark.asyncio
async def test_owner_creates_default_deny_staff_and_ungrantable_permission(client, actor):
    auth = headers(owner_token(actor[0]))
    body = {"name": "New staff", "email": "new@example.com", "password": "new-password"}
    created = await client.post("/api/staff", headers=auth, json=body)
    assert created.status_code == 200, created.text
    assert created.json()["permissions"] == []
    login = await client.post("/api/auth/login", json={"email": body["email"], "password": body["password"]})
    denied = await client.post("/api/reseller/withdraw", headers=headers(login.json()["access_token"]), json={})
    assert denied.status_code == 403
    for path in ("/api/routers", "/api/plans"):
        response = await client.get(path, headers=headers(login.json()["access_token"]))
        assert response.status_code == 403
    invalid = await client.put(f"/api/staff/{created.json()['id']}", headers=auth, json={"permissions": ["staff.manage"]})
    assert invalid.status_code == 400


@pytest.mark.asyncio
async def test_explicit_settlement_grant_and_owner_alerts(client, actor, db, monkeypatch):
    owner, staff, token = actor
    calls = []
    async def capture_alert(*args):
        calls.append(args)
    monkeypatch.setattr(staff_access, "alert_owner", capture_alert)
    staff.permissions = ["settlement.manage"]
    await db.commit()
    response = await client.put("/api/reseller/settlement-mode", headers=headers(token), json={"settlement_mode": "platform"})
    assert response.status_code == 200, response.text
    assert calls[0][0] == owner.id
    assert "staff" in calls[0][1]
    response = await client.put("/api/reseller/settlement-mode", headers=headers(owner_token(owner)), json={"settlement_mode": "platform"})
    assert response.status_code == 200
    assert len(calls) == 2 and calls[1][1] == "Account owner"
    rows = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.owner_id == owner.id))).scalars().all()
    assert {row.staff_id for row in rows} == {staff.id, None}


@pytest.mark.asyncio
async def test_owner_password_change_revokes_old_session_and_reissues_current(client, actor, db):
    owner = actor[0]
    owner.password_hash = pwd_context.hash("old-password")
    await db.commit()
    old_token = owner_token(owner)
    response = await client.put("/api/profile/password", headers=headers(old_token), json={
        "current_password": "old-password", "new_password": "new-password",
    })
    assert response.status_code == 200, response.text
    assert (await client.get("/api/profile", headers=headers(old_token))).status_code == 401
    new_token = response.json()["access_token"]
    assert (await client.get("/api/profile", headers=headers(new_token))).status_code == 200


@pytest.mark.asyncio
async def test_admin_password_reset_revokes_owner_sessions(client, actor, db):
    admin = await make_admin(db)
    owner = actor[0]
    old_token = owner_token(owner)
    response = await client.post("/api/admin/users/password-reset", headers=headers(owner_token(admin)), json={
        "email": owner.email, "new_password": "new-password",
    })
    assert response.status_code == 200, response.text
    assert (await client.get("/api/profile", headers=headers(old_token))).status_code == 401


@pytest.mark.asyncio
async def test_migration_preserves_old_user_and_is_idempotent(monkeypatch):
    import main
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(main, "async_engine", engine)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR NOT NULL)"))
            await conn.execute(text("INSERT INTO users(id, email) VALUES (1, 'old@example.com')"))
        await main.run_staff_migrations()
        await main.run_staff_migrations()
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT email, token_version FROM users"))).one() == ("old@example.com", 0)
            tables = (await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))).scalars().all()
            assert {"reseller_staff", "staff_activity_log"} <= set(tables)
    finally:
        await engine.dispose()

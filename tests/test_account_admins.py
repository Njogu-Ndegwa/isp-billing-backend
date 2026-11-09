"""Account admins share tenant scope, never passwords or platform authority."""
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.auth_routes import login_token_claims
from app.db.models import ResellerStaff, StaffActivityLog
from app.services import staff_access, email_service
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_reseller, make_router, make_plan, make_customer


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def client(engine, monkeypatch):
    import main
    from app.api import auth_routes
    staff_access.reset_cache()
    auth_routes._reset_request_log.clear()
    async def no_alert(*args, **kwargs):
        pass
    monkeypatch.setattr(staff_access, "alert_owner", no_alert)
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c
    staff_access.reset_cache()


@pytest_asyncio.fixture
async def actors(db):
    owner = await make_reseller(db, email="owner@example.com")
    member = ResellerStaff(parent_reseller_id=owner.id, name="Second admin",
                           email="second@example.com", password_hash=pwd_context.hash("admin-password"),
                           permissions=[], is_account_admin=True)
    db.add(member)
    await db.commit()
    owner_jwt = create_access_token(login_token_claims(owner), timedelta(hours=1))
    member_jwt = create_access_token(staff_access.staff_token_claims(member, owner), timedelta(hours=1))
    return owner, member, owner_jwt, member_jwt

@pytest.fixture
def sent(monkeypatch):
    messages = []
    async def capture(to, url):
        messages.append((to, url.split("token=", 1)[1]))
        return True
    monkeypatch.setattr(email_service, "send_password_reset_email", capture)
    return messages


@pytest.mark.asyncio
async def test_admin_login_staff_management_and_tenant_isolation(client, actors, db):
    owner, member, owner_jwt, token = actors
    login = await client.post("/api/auth/login", json={"email": member.email, "password": "admin-password"})
    assert login.status_code == 200, login.text
    identity = login.json()["user"]
    assert identity["id"] == owner.id and identity["role"] == "reseller"
    assert identity["email"] == member.email and identity["staff"] is None
    assert identity["account_admin"]["id"] == member.id
    me = await client.get("/api/staff/me", headers=auth(token))
    assert me.json()["is_staff"] is False
    assert "staff.manage" in me.json()["permissions"]
    created = await client.post("/api/staff", headers=auth(token), json={
        "name": "Technician", "email": "tech@example.com", "password": "tech-password",
        "permissions": ["customers.view"]})
    assert created.status_code == 200, created.text
    logs = (await db.execute(select(StaffActivityLog).where(StaffActivityLog.staff_id == member.id))).scalars().all()
    assert any("Added staff" in (r.summary or "") for r in logs)
    for tenant, allowed in [(owner, True), (await make_reseller(db), False)]:
        router = await make_router(db, tenant)
        plan = await make_plan(db, tenant)
        customer = await make_customer(db, tenant, plan, router)
        response = await client.get(f"/api/customers/{customer.id}", headers=auth(token))
        assert response.status_code == 200 if allowed else response.status_code in (403, 404)
    assert (await client.get("/api/admin/resellers", headers=auth(token))).status_code == 403
    other = await make_reseller(db)
    foreign = ResellerStaff(parent_reseller_id=other.id, name="Foreign", email="foreign@example.com",
                            password_hash="unused", permissions=[])
    db.add(foreign)
    await db.commit()
    assert (await client.put(f"/api/staff/{foreign.id}", headers=auth(token), json={"is_account_admin": True})).status_code == 404


@pytest.mark.asyncio
async def test_recovery_independent_single_use_and_revocation(client, actors, db, sent):
    owner, member, owner_jwt, token = actors
    owner_hash = owner.password_hash
    for email in (owner.email, member.email):
        response = await client.post("/api/auth/forgot-password", json={"email": email})
        assert response.status_code == 200
    assert [email for email, _ in sent] == [owner.email, member.email]
    import hashlib
    from app.api.auth_routes import _hash_reset_token
    assert hashlib.sha256(sent[1][1].encode()).hexdigest() != _hash_reset_token(sent[1][1])
    body = {"token": sent[1][1], "new_password": "second-new-password"}
    assert (await client.post("/api/auth/reset-password", json=body)).status_code == 200
    assert (await client.post("/api/auth/reset-password", json=body)).status_code == 400
    await db.refresh(owner)
    await db.refresh(member)
    assert owner.password_hash == owner_hash and owner.token_version == 0
    assert pwd_context.verify("second-new-password", member.password_hash)
    assert (await client.get("/api/staff/me", headers=auth(token))).status_code == 401
    assert (await client.get("/api/staff/me", headers=auth(owner_jwt))).status_code == 200
    assert (await client.post("/api/auth/login", json={"email": member.email, "password": "second-new-password"})).status_code == 200
    assert (await client.post("/api/auth/reset-password", json={"token": sent[0][1], "new_password": "owner-new-password"})).status_code == 200
    await db.refresh(member)
    assert pwd_context.verify("second-new-password", member.password_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["deactivate", "remove", "email", "demote", "password"])
async def test_recovery_link_cannot_restore_revoked_access(client, actors, db, sent, change):
    owner, member, owner_jwt, token = actors
    await client.post("/api/auth/forgot-password", json={"email": member.email})
    url = f"/api/staff/{member.id}"
    if change == "remove":
        response = await client.delete(url, headers=auth(owner_jwt))
    elif change == "password":
        response = await client.post(url + "/reset-password", headers=auth(owner_jwt), json={"password": "changed-password"})
    else:
        values = {"deactivate": {"is_active": False}, "email": {"email": "changed@example.com"},
                  "demote": {"is_account_admin": False}}
        response = await client.put(url, headers=auth(owner_jwt), json=values[change])
    assert response.status_code == 200
    assert (await client.post("/api/auth/reset-password", json={"token": sent[0][1], "new_password": "replay-password"})).status_code == 400
    assert (await client.get("/api/staff", headers=auth(token))).status_code == 401


@pytest.mark.asyncio
async def test_profile_updates_only_own_credentials(client, actors, db):
    owner, member, owner_jwt, token = actors
    original_hash, original_email = owner.password_hash, owner.email
    profile = await client.get("/api/profile", headers=auth(token))
    assert profile.json()["email"] == member.email
    response = await client.put("/api/profile/password", headers=auth(token), json={
        "current_password": "admin-password", "new_password": "changed-password"})
    assert response.status_code == 200, response.text
    new_token = response.json()["access_token"]
    assert (await client.get("/api/staff", headers=auth(new_token))).status_code == 200
    assert (await client.get("/api/staff", headers=auth(token))).status_code == 401
    response = await client.patch("/api/profile", headers=auth(new_token), json={"email": "new@example.com", "business_name": "Shared business"})
    assert response.status_code == 200, response.text
    await db.refresh(owner)
    await db.refresh(member)
    assert owner.email == original_email and owner.password_hash == original_hash
    assert owner.business_name == "Shared business" and member.email == "new@example.com"


@pytest.mark.asyncio
async def test_ordinary_staff_cannot_promote_itself(client, actors, db):
    owner, member, owner_jwt, token = actors
    member.is_account_admin = False
    await db.commit()
    response = await client.put(f"/api/staff/{member.id}", headers=auth(token), json={"is_account_admin": True})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_existing_database_migrations_are_idempotent(monkeypatch):
    import main
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(main, "async_engine", eng)
    try:
        async with eng.begin() as conn:
            await conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
            await conn.execute(text("CREATE TABLE reseller_staff (id INTEGER PRIMARY KEY, email VARCHAR, deleted_at TIMESTAMP)"))
            await conn.execute(text("CREATE TABLE password_reset_tokens (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, token_hash VARCHAR, created_at TIMESTAMP, expires_at TIMESTAMP, used_at TIMESTAMP)"))
        for _ in range(2):
            await main.run_staff_migrations()
            await main.run_password_reset_migrations()
        async with eng.connect() as conn:
            staff_cols = {r[1] for r in (await conn.execute(text("PRAGMA table_info(reseller_staff)"))).all()}
            reset_cols = {r[1] for r in (await conn.execute(text("PRAGMA table_info(password_reset_tokens)"))).all()}
        assert "is_account_admin" in staff_cols
        assert {"staff_id", "staff_token_version", "identity_email"} <= reset_cols
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_postgres_existing_schema_upgrade(engine, monkeypatch):
    import main
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL migration is exercised in CI")
    monkeypatch.setattr(main, "async_engine", engine)
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE reseller_staff DROP COLUMN is_account_admin"))
        await conn.execute(text("ALTER TABLE password_reset_tokens DROP COLUMN staff_id, DROP COLUMN staff_token_version, DROP COLUMN identity_email"))
    for _ in range(2):
        await main.run_staff_migrations()
        await main.run_password_reset_migrations()
    async with engine.connect() as conn:
        await conn.execute(text("SELECT is_account_admin FROM reseller_staff LIMIT 1"))
        await conn.execute(text("SELECT staff_id, staff_token_version, identity_email FROM password_reset_tokens LIMIT 1"))


@pytest.mark.asyncio
async def test_postgres_concurrent_reset_only_one_wins(client, actors, sent, engine):
    import asyncio
    if engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL row locks are exercised in CI")
    await client.post("/api/auth/forgot-password", json={"email": actors[1].email})
    body = {"token": sent[0][1], "new_password": "concurrent-new-password"}
    results = await asyncio.gather(*[client.post("/api/auth/reset-password", json=body) for _ in range(2)])
    assert sorted(r.status_code for r in results) == [200, 400]

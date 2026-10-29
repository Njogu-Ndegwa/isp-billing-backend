"""Staff route coverage after #272: every route is either mapped or deliberately
not for staff, the routes added since (#273-#277) are reachable with the right
permission, and the gaps closed in the 29 Oct audit stay closed.

Runs through the real app with no external I/O, like tests/test_staff.py.
"""
import re
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api.auth_routes import login_token_claims
from app.db.models import Customer, ResellerStaff, Router, StaffActivityLog
from app.services import staff_access, staff_permissions as perms
from app.services.auth import create_access_token, pwd_context
from tests.factories import make_customer, make_plan, make_reseller, make_router


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def owner_token(owner):
    return create_access_token(login_token_claims(owner), timedelta(hours=1))


PRESETS = {p["key"]: p["permissions"] for p in perms.PRESETS}


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


async def make_staff(db, owner, permissions, *, email=None, password="staff-password"):
    staff = ResellerStaff(
        parent_reseller_id=owner.id, name="Audit staff",
        email=email or f"staff{owner.id}-{len(permissions)}@example.com",
        password_hash=pwd_context.hash(password), permissions=list(permissions),
    )
    db.add(staff)
    await db.commit()
    await db.refresh(staff)
    token = create_access_token(staff_access.staff_token_claims(staff, owner), timedelta(hours=1))
    return staff, token


# ---------------------------------------------------------------------------
# Every route is classified
# ---------------------------------------------------------------------------

# Routes outside /api/admin/* that staff deliberately can't reach. They are
# refused by default anyway; listing them here means a NEW route has to be
# put either in staff_permissions._RULES_SPEC or here, on purpose.
NOT_FOR_STAFF = {
    # Owner's own account and staff management (staff.manage is owner-only).
    ("PATCH", "/api/profile"), ("DELETE", "/api/profile"), ("PUT", "/api/profile/password"),
    ("GET", "/api/staff"), ("POST", "/api/staff"), ("GET", "/api/staff/activity"),
    ("GET", "/api/staff/permissions"), ("PUT", "/api/staff/{staff_id}"),
    ("DELETE", "/api/staff/{staff_id}"), ("POST", "/api/staff/{staff_id}/reset-password"),
    ("POST", "/api/impersonation/end"),
    # Hero ads: reviewing ads and the advertiser list are Bitwave-admin only (#282).
    ("POST", "/api/ads/{ad_id}/review"), ("GET", "/api/advertisers"), ("POST", "/api/advertisers"),
    # Bitwave -> owner inbox (owner alerts land here) and the Ideas + Bugs board.
    ("GET", "/api/messaging/inbox"), ("POST", "/api/messaging/inbox/{message_id}/read"),
    ("GET", "/api/feedback/posts"), ("POST", "/api/feedback/posts"),
    ("GET", "/api/feedback/posts/{post_id}"), ("POST", "/api/feedback/posts/{post_id}/comments"),
    ("POST", "/api/feedback/posts/{post_id}/vote"),
    # Bitwave admin tools living outside /api/admin.
    ("GET", "/api/leads"), ("POST", "/api/leads"), ("POST", "/api/leads/backfill"),
    ("GET", "/api/leads/followups/upcoming"), ("PATCH", "/api/leads/followups/{followup_id}/complete"),
    ("GET", "/api/leads/pipeline/stats"), ("GET", "/api/leads/pipeline/summary"),
    ("GET", "/api/leads/sources"), ("POST", "/api/leads/sources"),
    ("PUT", "/api/leads/sources/{source_id}"), ("DELETE", "/api/leads/sources/{source_id}"),
    ("GET", "/api/leads/{lead_id}"), ("PUT", "/api/leads/{lead_id}"), ("DELETE", "/api/leads/{lead_id}"),
    ("GET", "/api/leads/{lead_id}/activities"), ("POST", "/api/leads/{lead_id}/activities"),
    ("POST", "/api/leads/{lead_id}/convert"), ("POST", "/api/leads/{lead_id}/followups"),
    ("PATCH", "/api/leads/{lead_id}/stage"),
    ("GET", "/api/shop/admin/orders"), ("GET", "/api/shop/admin/orders/{order_id}"),
    ("PUT", "/api/shop/admin/orders/{order_id}/status"),
    ("POST", "/api/shop/admin/orders/{order_id}/tracking"), ("GET", "/api/shop/admin/products"),
    ("GET", "/api/shop/analytics"), ("GET", "/api/shop/dashboard"), ("POST", "/api/shop/products"),
    ("PUT", "/api/shop/products/{product_id}"), ("DELETE", "/api/shop/products/{product_id}"),
    ("GET", "/api/radius/accounting/{username}"), ("POST", "/api/radius/cleanup"),
    ("GET", "/api/radius/routers"), ("POST", "/api/radius/routers/{router_id}/disable"),
    ("POST", "/api/radius/routers/{router_id}/enable"), ("GET", "/api/radius/routers/{router_id}/status"),
    ("GET", "/api/radius/sessions"), ("POST", "/api/radius/sessions/{username}/disconnect"),
    ("GET", "/api/radius/test/{router_id}"), ("POST", "/api/radius/users"),
    ("GET", "/api/radius/users/{username}"), ("DELETE", "/api/radius/users/{username}"),
    ("GET", "/api/test-remove/{router_id}/{mac_address}"),
    # Public: captive portal, shop storefront, callbacks/webhooks, router agents.
    # They need no user token, so a staff token adds nothing there.
    ("POST", "/api/ads/click"), ("POST", "/api/ads/impression"), ("POST", "/api/ratings/submit"),
    ("POST", "/api/clients/mac-register/{router_id}"),
    ("GET", "/api/hotspot/payment-status/{customerId}"), ("POST", "/api/hotspot/register-and-pay"),
    ("GET", "/api/radius/hotspot/payment-status/{customer_id}"),
    ("POST", "/api/radius/hotspot/register-and-pay"), ("POST", "/api/radius/mpesa/callback"),
    ("GET", "/api/shop/products"), ("GET", "/api/shop/products/{product_id}"),
    ("POST", "/api/shop/orders"), ("GET", "/api/shop/orders/track/{order_number}"),
    ("POST", "/api/shop/orders/{order_id}/pay"), ("GET", "/api/shop/orders/{order_id}/payment-status"),
    ("POST", "/api/shop/mpesa/callback"),
    ("POST", "/api/c2b/confirmation"), ("POST", "/api/c2b/validation"),
    ("POST", "/api/mpesa/callback"), ("POST", "/api/messaging/credits/mpesa/callback"),
    ("POST", "/api/subscription/mpesa/callback"),
    ("POST", "/api/mpesa/b2b/result"), ("POST", "/api/mpesa/b2b/status-result"),
    ("POST", "/api/mpesa/b2b/status-timeout"), ("POST", "/api/mpesa/b2b/timeout"),
    ("GET", "/api/fapshi/status/{trans_id}"), ("POST", "/api/fapshi/webhook"),
    ("POST", "/api/mtn-momo/callback/{reseller_id}"), ("GET", "/api/mtn-momo/status/{reference_id}"),
    ("GET", "/api/payafrica/webhook/{payment_id}/{token}"),
    ("POST", "/api/payafrica/webhook/{payment_id}/{token}"),
    ("GET", "/api/zenopay/order-status/{order_id}"), ("POST", "/api/zenopay/webhook/{reseller_id}"),
    ("GET", "/api/provision/router-mgmt-ca.crt"), ("GET", "/api/provision/{provision_token}"),
    ("GET", "/api/provision/{provision_token}/complete"),
    ("POST", "/api/provision/{provision_token}/complete"),
    ("GET", "/api/provision/{provision_token}/login-page"),
    ("POST", "/api/router/agent/commands/{command_id}/ack"), ("GET", "/api/router/agent/poll"),
    ("POST", "/api/router/checkin"), ("POST", "/api/router/expiry-check"),
    ("POST", "/api/router/usage-push"),
}


def _walk(routes, prefix=""):
    """Every (method, path) the app serves. FastAPI 0.14x (what CI and
    production install) keeps each include_router() as a lazy wrapper with
    `original_router` instead of flattening it into app.routes; older FastAPI
    flattens. Walk both shapes so the guard never passes vacuously."""
    for route in routes:
        if isinstance(route, APIRoute):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, prefix + route.path
        elif hasattr(route, "original_router"):
            ctx = getattr(route, "include_context", None)
            yield from _walk(route.original_router.routes, prefix + (getattr(ctx, "prefix", "") or ""))


def _app_routes():
    import main
    out = sorted(set(_walk(main.app.routes)))
    # Sanity: the walk must see the whole app, not just the top level.
    assert len(out) > 400, f"only {len(out)} routes found; route walk is broken"
    return out


def _sample(path):
    return re.sub(r"\{[a-zA-Z_0-9]+(:path)?\}", "1", path)


def test_every_rule_matches_a_real_route():
    """A rule with a typo would silently grant nothing (or the wrong route)."""
    routes = _app_routes()
    for rule in perms.RULES:
        for method in rule.methods:
            assert any(
                m == method and perms.match_rule(m, _sample(p))[0] is rule for m, p in routes
            ), f"rule {method} {rule.template} matches no route in the app"


def test_every_route_is_mapped_or_deliberately_not_for_staff():
    unclassified = []
    for method, path in _app_routes():
        if not path.startswith("/api/") or path.startswith("/api/admin/") or perms.is_public(path):
            continue
        if (method, path) in NOT_FOR_STAFF:
            continue
        if perms.match_rule(method, _sample(path))[0] is None:
            unclassified.append(f"{method} {path}")
    assert not unclassified, (
        "New routes not classified for staff. Add each to _RULES_SPEC in "
        "app/services/staff_permissions.py with the permission it needs, or to "
        f"NOT_FOR_STAFF in this test if staff must never reach it: {unclassified}"
    )


def test_not_for_staff_entries_are_really_refused():
    for method, path in NOT_FOR_STAFF:
        assert perms.match_rule(method, _sample(path))[0] is None, f"{method} {path}"


# ---------------------------------------------------------------------------
# Routes added since #272
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,needs", [
    # Activate / Activate without payment (#273, #276): same routes, body decides.
    ("POST", "/api/customers/7/activate-pppoe", "customers.manage"),
    ("POST", "/api/customers/7/activate-static", "customers.manage"),
    ("PUT", "/api/customers/7", "customers.manage"),
    # Pause / resume (#274).
    ("POST", "/api/customers/7/pause", "customers.manage"),
    ("POST", "/api/customers/7/resume", "customers.manage"),
    # Access credentials (#275).
    ("GET", "/api/access-credentials", "customers.view"),
    ("GET", "/api/access-credentials/3", "customers.view"),
    ("POST", "/api/access-credentials", "customers.manage"),
    ("PATCH", "/api/access-credentials/3", "customers.manage"),
    ("DELETE", "/api/access-credentials/3", "customers.manage"),
    ("POST", "/api/access-credentials/3/rotate-password", "customers.manage"),
    ("POST", "/api/access-credentials/3/force-logout", "customers.manage"),
    ("POST", "/api/access-credentials/3/revoke", "customers.manage"),
    ("POST", "/api/access-credentials/3/restore", "customers.manage"),
    ("POST", "/api/access-credentials/3/sync", "customers.manage"),
    # Port restart (#277).
    ("GET", "/api/routers/5/interfaces/restart-options", "routers.view"),
    ("POST", "/api/routers/5/interfaces/ether3/restart", "routers.manage"),
    # Load balancing.
    ("GET", "/api/routers/5/load-balancing", "routers.view"),
    ("POST", "/api/routers/5/load-balancing/enable", "routers.manage"),
    ("POST", "/api/routers/5/load-balancing/disable", "routers.manage"),
    ("POST", "/api/routers/5/load-balancing/preflight", "routers.manage"),
    ("POST", "/api/routers/5/load-balancing/verify", "routers.manage"),
])
def test_new_routes_need_the_right_permission(method, path, needs):
    rule, _ = perms.match_rule(method, path)
    assert rule is not None, f"{method} {path} is not in the staff map"
    assert rule.allows([needs])
    # A .view read may also be open to its .manage sibling; nothing else.
    sibling = needs.replace(".view", ".manage")
    others = [k for k in perms.PERMISSIONS if k not in (needs, sibling)]
    assert not rule.allows(others), f"{method} {path} is reachable without {needs}"


@pytest.mark.parametrize("method,path,allowed,denied", [
    ("POST", "/api/customers/7/activate-pppoe", ["manager"], ["technician", "cashier"]),
    ("POST", "/api/customers/7/pause", ["manager"], ["technician", "cashier"]),
    ("PUT", "/api/customers/7", ["manager"], ["technician", "cashier"]),
    ("POST", "/api/routers/5/interfaces/ether3/restart", ["technician", "manager"], ["cashier"]),
    ("POST", "/api/routers/5/load-balancing/enable", ["technician", "manager"], ["cashier"]),
    ("POST", "/api/access-credentials", ["manager"], ["technician", "cashier"]),
    ("GET", "/api/access-credentials", ["technician", "cashier", "manager"], []),
    ("POST", "/api/vouchers/generate", ["cashier", "manager"], ["technician"]),
    ("GET", "/api/mpesa/transactions", ["cashier", "manager"], ["technician"]),
    ("POST", "/api/mpesa/initiate-payment", ["manager"], ["technician", "cashier"]),
    ("POST", "/api/reseller/withdraw", [], ["technician", "cashier", "manager"]),
    ("PUT", "/api/staff/me/password", ["technician", "cashier", "manager"], []),
])
def test_presets_on_new_and_key_routes(method, path, allowed, denied):
    rule, _ = perms.match_rule(method, path)
    for preset in allowed:
        assert rule is not None and rule.allows(PRESETS[preset]), f"{preset} refused {method} {path}"
    for preset in denied:
        assert rule is None or not rule.allows(PRESETS[preset]), f"{preset} allowed {method} {path}"


# ---------------------------------------------------------------------------
# Gaps closed in the audit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/realtime/routers", "/api/pppoe/5/users", "/api/hotspot/5/users",
])
def test_customer_list_live_status_reads_open_to_customers_view(path):
    rule, _ = perms.match_rule("GET", path)
    assert rule.allows(["customers.view"]) and rule.allows(["routers.view"])
    assert not rule.allows(["vouchers.generate", "transactions.view"])
    # Secrets (PPPoE passwords) stay behind routers.manage.
    assert not perms.match_rule("GET", "/api/pppoe/5/secrets")[0].allows(["customers.view"])


def test_pickers_open_to_the_screens_that_use_them():
    assert perms.match_rule("GET", "/api/plans")[0].allows(["messaging.send"])
    routers = perms.match_rule("GET", "/api/routers")[0]
    assert routers.allows(["payment_methods.manage"]) and routers.allows(["messaging.settings"])
    assert not routers.allows(["transactions.view"])


@pytest.mark.asyncio
async def test_staff_changes_own_password_and_other_sessions_end(client, db):
    owner = await make_reseller(db)
    staff, token = await make_staff(db, owner, PRESETS["cashier"], email="cashier@example.com")
    other_device = await client.post(
        "/api/auth/login", json={"email": "cashier@example.com", "password": "staff-password"},
    )
    assert other_device.status_code == 200, other_device.text
    other_token = other_device.json()["access_token"]

    wrong = await client.put("/api/staff/me/password", headers=headers(token), json={
        "current_password": "nope", "new_password": "brand-new-pass",
    })
    assert wrong.status_code == 400
    short = await client.put("/api/staff/me/password", headers=headers(token), json={
        "current_password": "staff-password", "new_password": "abc",
    })
    assert short.status_code == 400
    same = await client.put("/api/staff/me/password", headers=headers(token), json={
        "current_password": "staff-password", "new_password": "staff-password",
    })
    assert same.status_code == 400

    ok = await client.put("/api/staff/me/password", headers=headers(token), json={
        "current_password": "staff-password", "new_password": "brand-new-pass",
    })
    assert ok.status_code == 200, ok.text
    fresh = ok.json()["access_token"]

    for stale in (token, other_token):
        revoked = await client.get("/api/staff/me", headers=headers(stale))
        assert revoked.status_code == 401
        assert revoked.json()["code"] == "staff_session_revoked"
    me = await client.get("/api/staff/me", headers=headers(fresh))
    assert me.status_code == 200 and me.json()["staff"]["id"] == staff.id

    old_login = await client.post(
        "/api/auth/login", json={"email": "cashier@example.com", "password": "staff-password"},
    )
    assert old_login.status_code == 401
    new_login = await client.post(
        "/api/auth/login", json={"email": "cashier@example.com", "password": "brand-new-pass"},
    )
    assert new_login.status_code == 200

    rows = (await db.execute(
        select(StaffActivityLog).where(StaffActivityLog.staff_id == staff.id)
    )).scalars().all()
    assert any(r.summary == "Changed own password" and r.status_code == 200 for r in rows)


@pytest.mark.asyncio
async def test_owner_and_disabled_staff_cannot_use_staff_password_route(client, db):
    owner = await make_reseller(db)
    response = await client.put("/api/staff/me/password", headers=headers(owner_token(owner)), json={
        "current_password": "x", "new_password": "brand-new-pass",
    })
    assert response.status_code == 400
    staff, token = await make_staff(db, owner, [])
    staff.is_active = False
    await db.commit()
    response = await client.put("/api/staff/me/password", headers=headers(token), json={
        "current_password": "staff-password", "new_password": "brand-new-pass",
    })
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_staff_edits_customer_expiry_only_with_customers_manage(client, db):
    """The one item the 28 Oct end-to-end run could not reach (test0012's
    subscription had lapsed): a staff member changing a customer's expiry."""
    owner = await make_reseller(db, subscription_status="active")
    router = await make_router(db, owner)
    plan = await make_plan(db, owner)
    old_expiry = datetime.utcnow() + timedelta(days=2)
    customer = await make_customer(db, owner, plan, router, expiry=old_expiry)
    new_expiry = (old_expiry + timedelta(days=5)).replace(microsecond=0)

    _, technician = await make_staff(db, owner, PRESETS["technician"], email="tech@example.com")
    denied = await client.put(f"/api/customers/{customer.id}", headers=headers(technician),
                              json={"expiry": new_expiry.isoformat()})
    assert denied.status_code == 403
    assert denied.json()["permission"] == "customers.manage"

    manager, manager_token = await make_staff(db, owner, PRESETS["manager"], email="mgr@example.com")
    allowed = await client.put(f"/api/customers/{customer.id}", headers=headers(manager_token),
                               json={"expiry": new_expiry.isoformat()})
    assert allowed.status_code == 200, allowed.text
    saved = (await db.execute(
        select(Customer.expiry).where(Customer.id == customer.id)
    )).scalar_one()
    assert abs((saved - new_expiry).total_seconds()) < 2

    rows = (await db.execute(
        select(StaffActivityLog).where(StaffActivityLog.staff_id == manager.id)
    )).scalars().all()
    assert any(r.summary == f"Edited customer {customer.id}" and r.status_code == 200 for r in rows)


@pytest.mark.asyncio
async def test_staff_of_a_lapsed_reseller_is_blocked_like_the_owner(client, db):
    owner = await make_reseller(db, subscription_status="inactive")
    router = await make_router(db, owner)
    plan = await make_plan(db, owner)
    customer = await make_customer(db, owner, plan, router, expiry=datetime.utcnow())
    _, token = await make_staff(db, owner, PRESETS["manager"])
    response = await client.put(f"/api/customers/{customer.id}", headers=headers(token),
                                json={"expiry": (datetime.utcnow() + timedelta(days=3)).isoformat()})
    assert response.status_code == 403
    assert "subscription" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_router_form_cannot_toggle_emergency_without_plans_manage(client, db):
    owner = await make_reseller(db, subscription_status="active")
    router = await make_router(db, owner)
    base = {"name": router.name, "ip_address": router.ip_address, "port": router.port}

    _, technician = await make_staff(db, owner, PRESETS["technician"], email="tech2@example.com")
    unchanged = await client.put(f"/api/routers/{router.id}", headers=headers(technician),
                                 json={**base, "name": "Renamed", "emergency_active": False})
    assert unchanged.status_code == 200, unchanged.text
    flipped = await client.put(f"/api/routers/{router.id}", headers=headers(technician),
                               json={**base, "emergency_active": True, "emergency_message": "Down"})
    assert flipped.status_code == 403
    assert flipped.json()["permission"] == "plans.manage"
    assert not (await db.execute(
        select(Router.emergency_active).where(Router.id == router.id)
    )).scalar_one()

    _, manager = await make_staff(db, owner, PRESETS["manager"], email="mgr2@example.com")
    ok = await client.put(f"/api/routers/{router.id}", headers=headers(manager),
                          json={**base, "emergency_active": True, "emergency_message": "Down"})
    assert ok.status_code == 200, ok.text
    owner_ok = await client.put(f"/api/routers/{router.id}", headers=headers(owner_token(owner)),
                                json={**base, "emergency_active": False})
    assert owner_ok.status_code == 200, owner_ok.text

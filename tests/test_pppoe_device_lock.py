"""PPPoE device lock: learn, bind, unbind, and every re-push keeps caller-id.

RouterOS is the stateful fake in fake_routeros.py; the DB is the test DB.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.pppoe_device_lock_routes as routes
from app.db.database import get_db
from app.db.models import ConnectionType, Customer, CustomerEvent, CustomerStatus, Router, SubscriptionStatus
from app.services import pppoe_device_lock as lock
from app.services import pppoe_provisioning, staff_permissions
from app.services.auth import verify_token
from app.services.pppoe_router_transfer import _target_provision_item
from app.services.router_agent_commands import render_pppoe_provision_action
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.fake_routeros import FakeRouterOS, typical_router_menus

pytestmark = pytest.mark.asyncio

CPE = "04:95:E6:11:22:33"
OTHER = "C8:3A:35:AA:BB:CC"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake(monkeypatch):
    api = FakeRouterOS(typical_router_menus())
    factory = lambda *a, **k: api  # noqa: E731
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", factory)
    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", factory)
    return api


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(routes.router)

    async def _get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user

    monkeypatch.setattr(routes, "get_current_user", _fake)


async def _setup(db, **customer_overrides):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, speed="10Mbps", price=1500)
    router = await make_router(db, reseller, ip_address="10.0.3.17")
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10), mac_address=None,
        pppoe_username="jane", pppoe_password="pw-jane", **customer_overrides,
    )
    return reseller, plan, router, customer


def _session(fake, *, mac=CPE, uptime="1h2m3s"):
    row = fake.rows("/ppp/active", name="jane")[0]
    row["caller-id"] = mac
    row["uptime"] = uptime


def _secret(fake):
    return fake.rows("/ppp/secret", name="jane")[0]


async def _row(session_factory, customer_id):
    async with session_factory() as s:
        return await s.get(Customer, customer_id)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("04:95:e6:11:22:33", CPE),
    ("04-95-E6-11-22-33", CPE),
    ("0495.e611.2233", CPE),
    ("0495E6112233", CPE),
    ("", None),
    (None, None),
    ("10.0.0.5", None),
    ("04:95:E6:11:22", None),
    ('04:95:E6:11:22:33" disabled=yes', None),
])
async def test_normalize_mac(raw, expected):
    assert lock.normalize_mac(raw) == expected


class _C:
    def __init__(self, **kw):
        self.pppoe_device_lock = kw.get("lock", False)
        self.pppoe_bound_mac = kw.get("bound")
        self.pppoe_lock_applied_mac = kw.get("applied")


async def test_desired_caller_id_leaves_unlocked_customers_alone():
    assert lock.desired_caller_id(_C()) is None
    assert lock.desired_caller_id(_C(lock=True)) is None              # still learning
    assert lock.desired_caller_id(_C(lock=True, bound=CPE)) == CPE
    assert lock.desired_caller_id(_C(applied=CPE)) == ""               # turned off: clear it
    assert lock.desired_caller_id(_C(lock=True, applied=CPE)) == ""    # allow new router: clear


async def test_payload_for_an_unlocked_customer_has_no_caller_id(db):
    _, _, router, customer = await _setup(db)
    payload = pppoe_provisioning.build_pppoe_payload(customer, router)
    assert "caller_id" not in payload


async def test_payload_for_a_locked_customer_carries_the_mac(db):
    _, _, router, customer = await _setup(db, pppoe_device_lock=True, pppoe_bound_mac=CPE)
    assert pppoe_provisioning.build_pppoe_payload(customer, router)["caller_id"] == CPE


# ---------------------------------------------------------------------------
# re-push paths keep caller-id
# ---------------------------------------------------------------------------


def _provision(payload):
    return pppoe_provisioning._provision_pppoe_sync(payload)


async def test_renewal_after_expiry_re_adds_the_secret_with_caller_id(db, fake):
    _, _, router, customer = await _setup(db, pppoe_device_lock=True, pppoe_bound_mac=CPE,
                                          pppoe_lock_applied_mac=CPE)
    fake.menus["/ppp/secret"] = [s for s in fake.menus["/ppp/secret"] if s["name"] != "jane"]  # removed at expiry

    result = _provision(pppoe_provisioning.build_pppoe_payload(customer, router))

    assert result.get("success"), result
    assert _secret(fake)["caller-id"] == CPE


async def test_plan_change_on_an_existing_secret_keeps_caller_id(db, fake):
    _, _, router, customer = await _setup(db, pppoe_device_lock=True, pppoe_bound_mac=CPE,
                                          pppoe_lock_applied_mac=CPE)
    _secret(fake)["caller-id"] = CPE

    result = _provision(pppoe_provisioning.build_pppoe_payload(customer, router))

    assert result.get("success"), result
    assert _secret(fake)["caller-id"] == CPE
    set_calls = [a for c, a in fake.writes() if c == "/ppp/secret/set"]
    assert set_calls and all(a.get("caller-id") == CPE for a in set_calls)


async def test_unlocked_re_push_never_touches_caller_id(db, fake):
    """Existing customers: a caller-id a reseller set by hand in Winbox survives."""
    _, _, router, customer = await _setup(db)
    _secret(fake)["caller-id"] = OTHER

    result = _provision(pppoe_provisioning.build_pppoe_payload(customer, router))

    assert result.get("success"), result
    assert _secret(fake)["caller-id"] == OTHER
    assert all("caller-id" not in a for c, a in fake.writes() if c.startswith("/ppp/secret"))


async def test_add_pppoe_secret_without_password_updates_caller_id(fake):
    result = fake.add_pppoe_secret("jane", "", "pppoe_10M_10M", caller_id=CPE)
    assert result.get("success"), result
    assert _secret(fake)["caller-id"] == CPE


async def test_router_transfer_item_carries_caller_id(db):
    _, _, router, customer = await _setup(db, pppoe_device_lock=True, pppoe_bound_mac=CPE)
    customer.plan = None
    assert _target_provision_item(customer, router)["caller_id"] == CPE


async def test_walled_secret_recreated_with_caller_id(fake):
    from app.services.pppoe_expired_redirect import wall_pppoe_users

    fake.menus["/ppp/secret"] = []
    wall_pppoe_users(fake, [{"id": 1, "pppoe_username": "jane", "pppoe_password": "pw",
                             "caller_id": CPE}])
    assert _secret(fake)["caller-id"] == CPE


async def test_router_agent_script_carries_caller_id():
    script = render_pppoe_provision_action(username="jane", password="pw", bandwidth_limit="10Mbps",
                                           caller_id=CPE)
    assert f'caller-id="{CPE}"' in script
    plain = render_pppoe_provision_action(username="jane", password="pw", bandwidth_limit="10Mbps")
    assert "caller-id" not in plain
    with pytest.raises(ValueError):
        render_pppoe_provision_action(username="jane", password="pw", bandwidth_limit="10Mbps",
                                      caller_id='x" disabled=yes')


# ---------------------------------------------------------------------------
# admin endpoints + reconcile job
# ---------------------------------------------------------------------------


async def test_enable_while_online_binds_the_connected_device(db, session_factory, client, fake, monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)
    _session(fake)

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pppoe_lock_state"] == "locked" and body["pppoe_bound_mac"] == CPE
    assert body["router_updated"] is True and body["pppoe_lock_router_pending"] is False
    assert _secret(fake)["caller-id"] == CPE
    row = await _row(session_factory, customer.id)
    assert row.pppoe_lock_applied_mac == CPE
    async with session_factory() as s:
        events = (await s.execute(select(CustomerEvent).where(
            CustomerEvent.customer_id == customer.id))).scalars().all()
    assert any(e.event_type == "pppoe_device_locked" for e in events)
    # the session that taught us the MAC is left connected
    assert not [c for c, _ in fake.writes() if c.startswith("/ppp/active")]


async def test_enable_while_offline_learns_on_first_connection(db, session_factory, client, fake, monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)
    fake.menus["/ppp/active"] = [r for r in fake.menus["/ppp/active"] if r["name"] != "jane"]

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})

    assert resp.json()["pppoe_lock_state"] == "learning"
    assert "caller-id" not in _secret(fake)

    fake.menus["/ppp/active"].append({".id": "*99", "name": "jane", "address": "192.168.89.30",
                                      "caller-id": CPE, "uptime": "12s"})
    summary = await lock.reconcile_device_locks_background()

    assert summary["learned"] == 1
    row = await _row(session_factory, customer.id)
    assert row.pppoe_bound_mac == CPE and row.pppoe_lock_applied_mac == CPE
    assert _secret(fake)["caller-id"] == CPE
    # nothing left to do: the next tick reads no router
    again = await lock.reconcile_device_locks_background()
    assert again["routers"] == 0


async def test_manual_mac_binds_without_a_session(db, session_factory, client, fake, monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock",
                            json={"enabled": True, "mac": "04-95-e6-11-22-33"})

    assert resp.json()["pppoe_bound_mac"] == CPE
    assert _secret(fake)["caller-id"] == CPE
    bad = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock",
                           json={"enabled": True, "mac": "nope"})
    assert bad.status_code == 400


async def test_allow_new_router_clears_and_relearns_only_a_new_session(db, session_factory, client, fake,
                                                                       monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)
    _session(fake, mac=CPE, uptime="3h")
    await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})
    assert _secret(fake)["caller-id"] == CPE

    resp = await client.post(f"/api/customers/{customer.id}/pppoe-device-lock/allow-new-router")

    assert resp.status_code == 200, resp.text
    assert resp.json()["pppoe_lock_state"] == "learning"
    assert _secret(fake)["caller-id"] == ""          # the new router can log in
    row = await _row(session_factory, customer.id)
    assert row.pppoe_bound_mac is None and row.pppoe_lock_applied_mac is None

    # The old router's session (up for 3h) is still there: not learned again.
    await lock.reconcile_device_locks_background()
    assert (await _row(session_factory, customer.id)).pppoe_bound_mac is None

    # The new router dials in.
    _session(fake, mac=OTHER, uptime="5s")
    await lock.reconcile_device_locks_background()
    row = await _row(session_factory, customer.id)
    assert row.pppoe_bound_mac == OTHER
    assert _secret(fake)["caller-id"] == OTHER


async def test_disable_clears_caller_id(db, session_factory, client, fake, monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)
    _session(fake)
    await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": False})

    assert resp.json()["pppoe_lock_state"] == "off"
    assert _secret(fake)["caller-id"] == ""
    row = await _row(session_factory, customer.id)
    assert row.pppoe_lock_applied_mac is None and row.pppoe_bound_mac is None
    # an unlocked customer is invisible to the job
    assert (await lock.reconcile_device_locks_background())["routers"] == 0


async def test_disable_while_router_unreachable_is_retried_by_the_job(db, session_factory, client, fake,
                                                                     monkeypatch):
    reseller, _, _, customer = await _setup(db)
    _auth_as(monkeypatch, reseller)
    _session(fake)
    await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})
    fake.reject = lambda command, args: "timeout" if command == "/ppp/secret/set" else None

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": False})

    body = resp.json()
    assert resp.status_code == 200
    assert body["router_updated"] is False and body["router_note"]
    assert body["pppoe_lock_router_pending"] is True
    assert _secret(fake)["caller-id"] == CPE

    fake.reject = None
    await lock.reconcile_device_locks_background()
    assert _secret(fake)["caller-id"] == ""
    assert (await _row(session_factory, customer.id)).pppoe_lock_applied_mac is None


async def test_payment_while_clear_is_pending_clears_it(db, session_factory, fake):
    """Lock turned off but the router missed it: the next renewal push clears it."""
    _, _, router, customer = await _setup(db, pppoe_lock_applied_mac=CPE)
    _secret(fake)["caller-id"] = CPE

    _provision(pppoe_provisioning.build_pppoe_payload(customer, router))

    assert _secret(fake)["caller-id"] == ""


async def test_other_resellers_cannot_touch_the_lock(db, client, fake, monkeypatch):
    _, _, _, customer = await _setup(db)
    stranger = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    _auth_as(monkeypatch, stranger)

    resp = await client.put(f"/api/customers/{customer.id}/pppoe-device-lock", json={"enabled": True})

    assert resp.status_code == 404
    assert fake.writes() == []


async def test_router_default_flag(db, session_factory, client, monkeypatch):
    reseller, _, router, _ = await _setup(db)
    _auth_as(monkeypatch, reseller)

    resp = await client.put(f"/api/routers/{router.id}/pppoe-device-lock-default", json={"enabled": True})

    assert resp.status_code == 200 and resp.json()["pppoe_lock_new_customers"] is True
    async with session_factory() as s:
        assert (await s.get(Router, router.id)).pppoe_lock_new_customers is True


async def test_staff_permissions():
    rule, _ = staff_permissions.match_rule("PUT", "/api/customers/5/pppoe-device-lock")
    assert rule is not None and rule.requirement == "customers.manage"
    rule, _ = staff_permissions.match_rule("POST", "/api/customers/5/pppoe-device-lock/allow-new-router")
    assert rule is not None and rule.requirement == "customers.manage"
    rule, _ = staff_permissions.match_rule("GET", "/api/customers/5/pppoe-device-lock")
    assert rule is not None and rule.requirement == "customers.view"
    rule, _ = staff_permissions.match_rule("PUT", "/api/routers/5/pppoe-device-lock-default")
    assert rule is not None and rule.requirement == "routers.manage"

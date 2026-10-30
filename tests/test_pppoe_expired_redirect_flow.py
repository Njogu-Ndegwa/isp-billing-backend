"""PPPoE expired redirect end to end through the DB: expiry job, inactive
safety net, paybill renewal, recovery sweep, the per-router toggle and the
portal's public endpoints. RouterOS is the stateful fake in fake_routeros.py.
"""

import json
from datetime import datetime, timedelta
from typing import List

import pytest
import pytest_asyncio
from fastapi import BackgroundTasks, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.pppoe_expired_routes as routes
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DurationUnit,
    MpesaTransaction,
    MpesaTransactionStatus,
    ProvisioningLog,
    Router,
    SubscriptionStatus,
)
from app.services import mikrotik_background, pppoe_provisioning, pppoe_resync, staff_permissions
from app.services import pppoe_expired_redirect as rx
from app.services.account_numbers import luhn_check_digit
from app.services.auth import verify_token
from tests.factories import make_customer, make_plan, make_reseller, make_router
from tests.fake_routeros import FakeRouterOS, typical_router_menus

pytestmark = pytest.mark.asyncio


async def _async_zero(*_a, **_k):
    return 0


async def _async_none(*_a, **_k):
    return None


@pytest.fixture
def fake(monkeypatch):
    api = FakeRouterOS(typical_router_menus())
    factory = lambda *a, **k: api  # noqa: E731
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", factory)
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", factory)
    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", factory)
    return api


@pytest.fixture
def cleanup_env(monkeypatch, session_factory):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "inactive_pppoe_reconcile_running", False)
    monkeypatch.setattr(mikrotik_background, "_inactive_pppoe_reconcile_cursor", 0)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _async_none)

    async def _noop(*a, **k):
        return {"ok": True}

    monkeypatch.setattr("app.services.fup.restore_normal_profile", _noop)


async def _setup(db, *, redirect=True, status=CustomerStatus.ACTIVE, expiry_delta=timedelta(minutes=-10),
                 username="jane", plan_hidden=False):
    reseller = await make_reseller(db, business_name="FastNet", support_phone="0700111222",
                                   subscription_status=SubscriptionStatus.ACTIVE)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, speed="10Mbps",
                           price=1500, name="Home 10M", is_hidden=plan_hidden)
    router = await make_router(db, reseller, ip_address="10.0.3.17", pppoe_expired_redirect=redirect)
    base = "100007"
    customer = await make_customer(
        db, reseller, plan, router, status=status, expiry=datetime.utcnow() + expiry_delta,
        mac_address=None, pppoe_username=username, pppoe_password=f"pw-{username}",
        name="Jane Wanjiku", phone="0712345678", account_number=base + str(len(username)) + luhn_check_digit(base + str(len(username))),
    )
    return reseller, plan, router, customer


# ---------------------------------------------------------------------------
# expiry job and safety net
# ---------------------------------------------------------------------------


async def test_expiry_job_walls_the_customer_logs_it_and_stores_the_router_config(
    db, session_factory, fake, cleanup_env,
):
    _, _, router, customer = await _setup(db)

    await mikrotik_background.cleanup_expired_users_background()

    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE
    jane = fake.rows("/ppp/secret", name="jane")[0]
    assert jane["profile"] == rx.EXPIRED_PROFILE
    log = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.customer_id == customer.id, ProvisioningLog.action == "pppoe_deactivation",
    ))).scalar_one()
    assert "walled expired profile" in log.details
    async with session_factory() as s:
        stored = await s.get(Router, router.id)
        assert stored.pppoe_expired_redirect_config["cidr"] == "10.254.252.0/22"

    # Already walled: the inactive safety net finds nothing to do.
    first = await mikrotik_background.reconcile_inactive_pppoe_access_background()
    assert first["selected"] == 0


async def test_expiry_job_without_the_toggle_removes_the_secret(db, fake, cleanup_env):
    _, _, _, customer = await _setup(db, redirect=False)

    await mikrotik_background.cleanup_expired_users_background()

    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE
    assert fake.rows("/ppp/secret", name="jane") == []
    assert fake.rows("/ppp/profile", name=rx.EXPIRED_PROFILE) == []


async def test_safety_net_walls_a_leftover_secret_on_a_redirect_router(db, fake, cleanup_env):
    _, _, _, customer = await _setup(db, status=CustomerStatus.INACTIVE)

    out = await mikrotik_background.reconcile_inactive_pppoe_access_background()

    assert out["removed"] == 1
    assert fake.rows("/ppp/secret", name="jane")[0]["profile"] == rx.EXPIRED_PROFILE
    log = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.customer_id == customer.id, ProvisioningLog.action == "pppoe_deactivation",
    ))).scalar_one()
    assert "walled" in log.details


# ---------------------------------------------------------------------------
# paybill (C2B) renewal of a walled customer
# ---------------------------------------------------------------------------


async def test_paybill_payment_restores_a_walled_customer(db, session_factory, fake, cleanup_env):
    from app.services.c2b_handler import SUCCESS_RESPONSE, handle_confirmation
    from app.config import settings

    _, plan, _, customer = await _setup(db, status=CustomerStatus.INACTIVE)
    rx.ensure_expired_infra(fake, router_id=customer.router_id)
    rx.wall_pppoe_users(fake, [{"id": customer.id, "pppoe_username": "jane"}])
    fake.menus["/ppp/active"].append({".id": "*99", "name": "jane", "address": "10.254.252.7"})

    bg = BackgroundTasks()
    queued: List[tuple] = []
    bg.add_task = lambda func, *a, **k: queued.append((func, a, k))  # type: ignore[assignment]
    payload = {
        "TransactionType": "Pay Bill", "TransID": "RXP001", "TransTime": "20261029120000",
        "TransAmount": str(plan.price), "BusinessShortCode": settings.MPESA_SHORTCODE,
        "BillRefNumber": customer.account_number, "MSISDN": "254712345678",
        "FirstName": "Jane", "LastName": "W",
    }
    assert await handle_confirmation(payload, db, background_tasks=bg) == SUCCESS_RESPONSE

    async with session_factory() as s:
        refreshed = await s.get(Customer, customer.id)
        assert refreshed.status == CustomerStatus.ACTIVE
    (func, args, _), = queued
    assert func is pppoe_provisioning.call_pppoe_provision
    result = await func(*args)  # what the background task does

    assert result.get("success"), result
    assert fake.rows("/ppp/secret", name="jane")[0]["profile"] == "pppoe_10M_10M"
    assert fake.rows("/ppp/active", name="jane") == []  # kicked; redials with full access


# ---------------------------------------------------------------------------
# recovery sweep
# ---------------------------------------------------------------------------


async def test_recovery_sweep_restores_a_paid_customer_left_walled(db, monkeypatch):
    _, _, router, customer = await _setup(db, expiry_delta=timedelta(days=5))
    secrets = [{"name": "jane", "profile": rx.EXPIRED_PROFILE, "comment": f"CID:{customer.id}|Jane|x"}]
    pushed = []

    async def router_io(_info, func, *args):
        assert func is pppoe_resync._list_pppoe_secrets_sync
        return {"success": True, "secrets": secrets}

    async def provision(payload):
        pushed.append(payload)
        return {"success": True}

    monkeypatch.setattr(pppoe_resync, "_router_io", router_io)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", provision)

    summary = await pppoe_resync.sweep_router_pppoe(router.id)

    assert summary["provisioned"] == 1
    assert pushed[0]["pppoe_username"] == "jane" and pushed[0]["disconnect"] is True


# ---------------------------------------------------------------------------
# the toggle
# ---------------------------------------------------------------------------


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


async def test_toggle_needs_routers_manage_for_staff():
    rule, params = staff_permissions.match_rule("PUT", "/api/routers/12/pppoe-expired-redirect")
    assert rule is not None and rule.requirement == "routers.manage"
    assert params == {"router_id": "12"}


async def test_toggle_on_applies_then_stores_and_off_tears_down(db, session_factory, client, fake, monkeypatch):
    reseller, _, router, _ = await _setup(db, redirect=False)
    _auth_as(monkeypatch, reseller)

    on = await client.put(f"/api/routers/{router.id}/pppoe-expired-redirect", json={"enabled": True})
    assert on.status_code == 200, on.text
    assert on.json()["pppoe_expired_redirect"] is True
    async with session_factory() as s:
        row = await s.get(Router, router.id)
        assert row.pppoe_expired_redirect is True
        assert row.pppoe_expired_redirect_config["cidr"] == "10.254.252.0/22"
        assert row.pppoe_expired_redirect_config["proxy_enabled_by_us"] is True
    assert fake.rows("/ppp/profile", name=rx.EXPIRED_PROFILE)

    off = await client.put(f"/api/routers/{router.id}/pppoe-expired-redirect", json={"enabled": False})
    assert off.status_code == 200, off.text
    async with session_factory() as s:
        row = await s.get(Router, router.id)
        assert row.pppoe_expired_redirect is False and row.pppoe_expired_redirect_config is None
    assert fake.rows("/ppp/profile", name=rx.EXPIRED_PROFILE) == []
    assert fake.menus["/ip/proxy"][0]["enabled"] == "no"


async def test_toggle_keeps_the_flag_when_the_router_refuses(db, session_factory, client, fake, monkeypatch):
    reseller, _, router, _ = await _setup(db, redirect=False)
    _auth_as(monkeypatch, reseller)
    fake.reject = lambda command, args: "timeout" if command == "/ip/pool/add" else None

    resp = await client.put(f"/api/routers/{router.id}/pppoe-expired-redirect", json={"enabled": True})

    assert resp.status_code == 502 and "Router not updated" in resp.json()["detail"]
    async with session_factory() as s:
        assert (await s.get(Router, router.id)).pppoe_expired_redirect is False


async def test_toggle_refuses_another_resellers_router(db, client, fake, monkeypatch):
    _, _, router, _ = await _setup(db, redirect=False)
    stranger = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    _auth_as(monkeypatch, stranger)

    resp = await client.put(f"/api/routers/{router.id}/pppoe-expired-redirect", json={"enabled": True})

    assert resp.status_code == 404
    assert fake.writes() == []


# ---------------------------------------------------------------------------
# portal endpoints
# ---------------------------------------------------------------------------


async def test_page_data_masks_the_customer_and_offers_their_hidden_plan(db, client):
    reseller, plan, router, customer = await _setup(db, status=CustomerStatus.INACTIVE, plan_hidden=True)
    other = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=2500, name="Home 20M")
    await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT, price=20, name="1 hour")

    resp = await client.get(f"/api/public/pppoe/expired/{router.id}", params={"u": "jane"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["lookup"] == "found"
    c = body["customer"]
    assert c["username"] == "jane" and c["first_name"] == "Jane"
    assert c["phone_hint"] == "*******678" and "0712345678" not in resp.text
    assert c["online"] is False and c["plan_name"] == "Home 10M"
    assert [p["id"] for p in body["plans"]] == [plan.id, other.id]   # no hotspot plan
    assert body["router"]["business_name"] == "FastNet"
    assert body["paybill"]  # platform-collected: the platform paybill + account number

    by_account = await client.get(f"/api/public/pppoe/expired/{router.id}", params={"u": customer.account_number})
    assert by_account.json()["customer"]["username"] == "jane"
    unknown = await client.get(f"/api/public/pppoe/expired/{router.id}", params={"u": "nobody"})
    assert unknown.json()["lookup"] == "not_found" and unknown.json()["customer"] is None


async def test_public_endpoints_are_closed_when_the_toggle_is_off(db, client):
    _, _, router, _ = await _setup(db, redirect=False)

    assert (await client.get(f"/api/public/pppoe/expired/{router.id}")).status_code == 404
    pay = await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})
    assert pay.status_code == 404


class _Stk:
    checkout_request_id = "ws_CO_123"
    merchant_request_id = "m-1"


async def test_pay_sends_the_plan_price_to_the_phone_on_file(db, session_factory, client, monkeypatch):
    _, plan, router, customer = await _setup(db, status=CustomerStatus.INACTIVE)
    sent = []

    async def fake_stk(**kwargs):
        sent.append(kwargs)
        return _Stk()

    monkeypatch.setattr("app.services.mpesa.initiate_stk_push", fake_stk)

    resp = await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["amount"] == 1500 and resp.json()["phone_hint"].endswith("678")
    assert sent[0]["phone_number"] == "254712345678" and sent[0]["amount"] == 1500
    async with session_factory() as s:
        txn = (await s.execute(select(MpesaTransaction))).scalar_one()
        assert (txn.customer_id, txn.amount, txn.plan_id) == (customer.id, 1500, plan.id)
        assert txn.status == MpesaTransactionStatus.pending
        refreshed = await s.get(Customer, customer.id)
        assert refreshed.status == CustomerStatus.INACTIVE  # nothing changes until paid
        assert refreshed.pending_update_data is None

    again = await client.post("/api/public/pppoe/expired/pay", json={"router_id": router.id, "username": "jane"})
    assert again.status_code == 409


async def test_pay_for_another_plan_is_held_until_paid(db, session_factory, client, monkeypatch):
    reseller, plan, router, customer = await _setup(db, status=CustomerStatus.INACTIVE)
    bigger = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, price=2500, name="Home 20M",
                             duration_unit=DurationUnit.DAYS)
    hotspot = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT, price=20)

    async def fake_stk(**kwargs):
        return _Stk()

    monkeypatch.setattr("app.services.mpesa.initiate_stk_push", fake_stk)

    bad = await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": hotspot.id})
    assert bad.status_code == 400

    resp = await client.post("/api/public/pppoe/expired/pay", json={
        "router_id": router.id, "username": "jane", "plan_id": bigger.id, "phone": "0799 000 111"})
    assert resp.status_code == 200, resp.text
    async with session_factory() as s:
        refreshed = await s.get(Customer, customer.id)
        assert refreshed.plan_id == plan.id                      # unchanged until paid
        assert json.loads(refreshed.pending_update_data)["plan_id"] == bigger.id
        txn = (await s.execute(select(MpesaTransaction))).scalar_one()
        assert (txn.amount, txn.phone_number) == (2500, "254799000111")


async def test_status_poll_reports_back_online_after_payment(db, session_factory, client):
    _, _, router, customer = await _setup(db, status=CustomerStatus.INACTIVE)

    before = await client.get(f"/api/public/pppoe/expired/{router.id}/status", params={"u": "jane"})
    assert before.status_code == 200 and before.json()["online"] is False

    async with session_factory() as s:
        row = await s.get(Customer, customer.id)
        row.status = CustomerStatus.ACTIVE
        row.expiry = datetime.utcnow() + timedelta(days=30)
        await s.commit()

    after = await client.get(f"/api/public/pppoe/expired/{router.id}/status", params={"u": "jane"})
    assert after.json()["online"] is True

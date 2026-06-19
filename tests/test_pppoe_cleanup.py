from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

from app.api import customer_routes, pppoe_monitor
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
)
from app.services import pppoe_provisioning
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def _seed_pppoe_customer(db, *, status=CustomerStatus.INACTIVE):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=status,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address=None,
        pppoe_username="Festo",
        pppoe_password="secret",
        name="Festus",
    )
    return reseller, router, customer


async def test_delete_customer_deprovisions_inactive_pppoe_before_db_delete(db, monkeypatch):
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.INACTIVE)
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    await db.commit()
    calls = []

    async def _cleanup(payload):
        calls.append(payload)
        return {
            "success": True,
            "disconnect_result": {"success": True, "disconnected": 1},
            "remove_result": {"success": True, "action": "removed"},
        }

    monkeypatch.setattr(customer_routes, "call_pppoe_remove", _cleanup)

    response = await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert response["success"] is True
    assert response["pppoe_deprovisioned"] == "ok"
    assert calls == [{
        "pppoe_username": "Festo",
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
    }]

    remaining = (
        await db.execute(select(Customer).where(Customer.id == customer.id))
    ).scalar_one_or_none()
    assert remaining is None


async def test_delete_customer_keeps_db_row_when_pppoe_cleanup_fails(db, monkeypatch):
    reseller, _, customer = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    async def _cleanup(_payload):
        return {"error": "Failed to connect to router"}

    monkeypatch.setattr(customer_routes, "call_pppoe_remove", _cleanup)

    with pytest.raises(HTTPException) as exc:
        await customer_routes.delete_customer(customer.id, db, _token(reseller))

    assert exc.value.status_code == 503
    assert "customer was not deleted" in exc.value.detail

    await db.rollback()
    remaining = (
        await db.execute(select(Customer).where(Customer.id == customer.id))
    ).scalar_one_or_none()
    assert remaining is not None


async def test_cleanup_pppoe_user_endpoint_removes_orphan_router_secret(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    calls = []

    async def _cleanup(payload):
        calls.append(payload)
        return {
            "success": True,
            "disconnect_result": {"success": True, "disconnected": 1},
            "remove_result": {"success": True, "action": "removed"},
        }

    monkeypatch.setattr(pppoe_monitor, "call_pppoe_remove", _cleanup)

    response = await pppoe_monitor.cleanup_pppoe_user(
        router.id,
        "Festo",
        False,
        db,
        _token(reseller),
    )

    assert response["success"] is True
    assert response["username"] == "Festo"
    assert response["customer_present"] is False
    assert calls[0]["pppoe_username"] == "Festo"
    assert calls[0]["router_ip"] == router.ip_address


async def test_cleanup_pppoe_user_endpoint_refuses_existing_customer_without_force(db, monkeypatch):
    reseller, router, _ = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    async def _cleanup(_payload):
        raise AssertionError("cleanup should not run for a DB-owned username without force")

    monkeypatch.setattr(pppoe_monitor, "call_pppoe_remove", _cleanup)

    with pytest.raises(HTTPException) as exc:
        await pppoe_monitor.cleanup_pppoe_user(
            router.id,
            "Festo",
            False,
            db,
            _token(reseller),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["customer"]["name"] == "Festus"


async def test_pppoe_customer_presence_uses_db_values_and_reports_offline(db, monkeypatch):
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)
    calls = []

    async def _run_with_guard(router_id, fn, router_info, username, **kwargs):
        calls.append({
            "router_id": router_id,
            "helper": fn.__name__,
            "router_ip": router_info["ip"],
            "router_port": router_info["port"],
            "username": username,
            "acquire_timeout_seconds": kwargs.get("acquire_timeout_seconds"),
        })
        return {
            "success": True,
            "username": username,
            "present_on_router": True,
            "online": False,
            "state": "offline",
            "secret": {
                "name": username,
                "service": "pppoe",
                "profile": "pppoe_5M_5M",
                "disabled": False,
                "comment": f"CID:{customer.id}|Festus|2026-06-01",
                "last_logged_out": "1970-01-01 00:00:00",
                "last_disconnect_reason": "",
                "last_caller_id": "",
            },
            "active_session": None,
            "profile_detail": {"name": "pppoe_5M_5M", "rate_limit": "5000000/5000000"},
            "profile_lookup_success": True,
            "profile_lookup_error": None,
            "session_lookup_success": True,
            "session_lookup_error": None,
        }

    monkeypatch.setattr(pppoe_monitor, "run_with_guard", _run_with_guard)

    response = await pppoe_monitor.pppoe_customer_presence(customer.id, db, _token(reseller))

    assert response["success"] is True
    assert response["customer"]["id"] == customer.id
    assert response["lookup"] == {
        "source": "customers.pppoe_username",
        "value": "Festo",
    }
    assert response["mikrotik"]["present_on_router"] is True
    assert response["mikrotik"]["online"] is False
    assert response["verdict"]["code"] == "router_account_exists_but_customer_offline"
    assert response["verdict"]["our_side_confirmed"] is True
    assert calls == [{
        "router_id": router.id,
        "helper": "_pppoe_customer_presence_sync",
        "router_ip": router.ip_address,
        "router_port": router.port,
        "username": "Festo",
        "acquire_timeout_seconds": pppoe_monitor._PRESENCE_ACQUIRE_TIMEOUT_SECONDS,
    }]


async def test_pppoe_customer_presence_flags_plan_rate_mismatch(db, monkeypatch):
    pppoe_monitor._pppoe_presence_cache.clear()
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    async def _run_with_guard(_router_id, _fn, _router_info, username, **_kwargs):
        return {
            "success": True,
            "username": username,
            "present_on_router": True,
            "online": False,
            "state": "offline",
            "secret": {
                "name": username,
                "service": "pppoe",
                "profile": "pppoe_10M_10M",
                "disabled": False,
            },
            "active_session": None,
            "profile_detail": {"name": "pppoe_10M_10M", "rate_limit": "10M/10M"},
            "profile_lookup_success": True,
            "profile_lookup_error": None,
            "session_lookup_success": True,
            "session_lookup_error": None,
        }

    monkeypatch.setattr(pppoe_monitor, "run_with_guard", _run_with_guard)

    response = await pppoe_monitor.pppoe_customer_presence(customer.id, db, _token(reseller), refresh=True)

    assert response["speed_enforcement"] == {
        "plan_speed": "5M/5M",
        "expected_rate_limit": "5M/5M",
        "profile_rate_limit": "10M/10M",
        "profile_rate_matches_plan": False,
        "active_queue_limit": "",
        "active_queue_matches_plan": None,
    }
    assert response["verdict"]["code"] == "rate_limit_mismatch"
    assert response["verdict"]["our_side_confirmed"] is False


async def test_edit_active_pppoe_plan_reprovisions_with_new_speed(db, monkeypatch):
    reseller = await make_reseller(db)
    old_plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        speed="20M/20M",
    )
    new_plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        speed="5M/5M",
    )
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        old_plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address=None,
        pppoe_username="plan_change_user",
        pppoe_password="secret",
    )

    async def fake_current_user(_token, _db):
        return reseller

    provision_calls = []
    remove_calls = []

    async def fake_provision(payload):
        provision_calls.append(payload)
        return {"success": True}

    async def fake_remove(payload):
        remove_calls.append(payload)
        return {"success": True}

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(customer_routes, "call_pppoe_provision", fake_provision)
    monkeypatch.setattr(customer_routes, "call_pppoe_remove", fake_remove)

    response = await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(plan_id=new_plan.id),
        db,
        "token",
    )

    assert response["success"] is True
    assert response["pppoe_reprovisioned"] == "ok"
    assert response["customer"]["plan_id"] == new_plan.id
    assert len(provision_calls) == 1
    assert provision_calls[0]["pppoe_username"] == "plan_change_user"
    assert provision_calls[0]["bandwidth_limit"] == "5M/5M"
    assert remove_calls == []


async def test_activate_pppoe_customer_tracks_failed_router_provision_for_retry(db, monkeypatch):
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.INACTIVE)

    async def fake_current_user(_token, _db):
        return reseller

    async def fake_provision(payload):
        return {"error": "Profile creation failed: invalid value for argument remote-address:"}

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    response = await customer_routes.activate_pppoe_customer(
        customer.id,
        customer_routes.ActivatePPPoERequest(payment_method="cash"),
        db,
        "token",
    )

    assert response["success"] is True
    assert response["provision_result"] == "retry_pending"
    assert "remote-address" in response["provision_error"]
    assert response["delivery"]["provisioning_state"] == ProvisioningState.RETRY_PENDING.value

    attempt = (
        await db.execute(select(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == customer.id))
    ).scalar_one()
    assert attempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT
    assert attempt.entrypoint == ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION
    assert attempt.router_id == router.id
    assert attempt.provisioning_state == ProvisioningState.RETRY_PENDING
    assert attempt.online_state == ProvisioningOnlineState.UNKNOWN
    assert attempt.attempt_count == 1
    assert "remote-address" in attempt.last_error


async def test_retry_pending_pppoe_provisioning_replays_active_customer_attempt(db, monkeypatch):
    reseller, router, customer = await _seed_pppoe_customer(db, status=CustomerStatus.ACTIVE)

    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=500,
        payment_method=PaymentMethod.CASH,
        days_paid_for=30,
        status=PaymentStatus.COMPLETED,
        customer_name=customer.name,
    )
    db.add(payment)
    await db.flush()

    attempt = ProvisioningAttempt(
        customer_id=customer.id,
        router_id=router.id,
        mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        source_pk=payment.id,
        entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        provisioning_state=ProvisioningState.RETRY_PENDING,
        online_state=ProvisioningOnlineState.UNKNOWN,
        attempt_count=1,
        last_error="Profile creation failed",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(attempt)
    await db.commit()

    calls = []

    async def fake_provision(payload):
        calls.append(payload)
        return {
            "success": True,
            "profile": "pppoe_5M_5M",
            "rate_limit": "5M/5M",
        }

    monkeypatch.setattr(pppoe_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert len(calls) == 1
    assert calls[0]["pppoe_username"] == "Festo"
    assert calls[0]["router_ip"] == router.ip_address

    refreshed = await db.get(ProvisioningAttempt, attempt.id)
    await db.refresh(refreshed)
    assert refreshed.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert refreshed.online_state == ProvisioningOnlineState.UNKNOWN
    assert refreshed.attempt_count == 2
    assert refreshed.last_error is None
    assert refreshed.router_updated_at is not None


async def test_pppoe_customer_presence_requires_pppoe_username(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=1),
        mac_address=None,
        pppoe_username=None,
        name="No PPPoE",
    )

    async def _run_with_guard(*_args, **_kwargs):
        raise AssertionError("router lookup should not run without a PPPoE username")

    monkeypatch.setattr(pppoe_monitor, "run_with_guard", _run_with_guard)

    with pytest.raises(HTTPException) as exc:
        await pppoe_monitor.pppoe_customer_presence(customer.id, db, _token(reseller))

    assert exc.value.status_code == 400
    assert exc.value.detail == "Customer does not have a PPPoE username"

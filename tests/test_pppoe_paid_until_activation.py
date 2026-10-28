"""'Already paid until' activation from the customer edit form, and re-save.

Case (reseller 597, router 621, 2026-10-24): 49 PPPoE customers migrated from
another system were created and their expiry EDITED to the date they had
already paid until. Editing never activates, so they stayed INACTIVE, nothing
was written to the router and their devices sat in "authentication failed".
The edit form now offers an explicit "Activate now - already paid until
<date>" that activates without recording money and provisions with retries.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import customer_routes
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
)
from app.services import pppoe_provisioning
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def _seed(db, monkeypatch, *, status=CustomerStatus.INACTIVE, expiry=None):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, speed="10M/10M")
    # TEST-NET address: nothing here may ever reach a real router.
    router = await make_router(db, reseller, ip_address="192.0.2.10")
    customer = await make_customer(
        db, reseller, plan, router,
        status=status,
        expiry=expiry,
        mac_address=None,
        pppoe_username="techmid_client_1",
        pppoe_password="pw-123",
        name="Migrated Client",
    )

    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)
    return reseller, plan, router, customer


def _record_provisions(monkeypatch, result=None):
    calls = []

    async def fake_provision(payload):
        calls.append(payload)
        return result if result is not None else {"success": True, "profile": "pppoe_10M_10M"}

    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    async def no_router_remove(payload):
        raise AssertionError(f"unexpected PPPoE removal: {payload}")

    monkeypatch.setattr(customer_routes, "call_pppoe_remove", no_router_remove)
    return calls


async def test_editing_expiry_alone_never_activates(db, monkeypatch):
    _, _, _, customer = await _seed(db, monkeypatch)
    calls = _record_provisions(monkeypatch)
    paid_until = datetime.utcnow() + timedelta(days=20)

    response = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(expiry=paid_until), db, "t",
    )

    assert response["customer"]["status"] == "inactive"
    assert response["activated_paid_until"] is False
    assert response["pppoe_reprovisioned"] is None
    assert calls == []
    assert (await db.execute(select(func.count(CustomerPayment.id)))).scalar_one() == 0


async def test_activate_paid_until_activates_without_revenue_and_provisions(db, monkeypatch):
    reseller, plan, router, customer = await _seed(db, monkeypatch)
    calls = _record_provisions(monkeypatch)
    paid_until = (datetime.utcnow() + timedelta(days=20)).replace(microsecond=0)

    response = await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(expiry=paid_until, activate_paid_until=True),
        db, "t",
    )

    assert response["success"] is True
    assert response["activated_paid_until"] is True
    assert response["customer"]["status"] == "active"
    # The date the reseller typed is kept, not replaced by now + plan length.
    assert response["customer"]["expiry"] == paid_until.isoformat()
    assert response["pppoe_reprovisioned"] == "ok"

    # Secret written once, with the customer's credentials and plan speed.
    assert len(calls) == 1
    assert calls[0]["pppoe_username"] == "techmid_client_1"
    assert calls[0]["pppoe_password"] == "pw-123"
    assert calls[0]["bandwidth_limit"] == "10M/10M"
    assert calls[0]["comment"].startswith(f"CID:{customer.id}|")

    # Ledger: one zero-amount row that is explicitly not revenue and not cash.
    payment = (await db.execute(select(CustomerPayment))).scalar_one()
    assert payment.amount == 0
    assert payment.counts_as_revenue is False
    assert payment.payment_method == PaymentMethod.OTHER
    assert payment.status == PaymentStatus.COMPLETED
    assert payment.reseller_id == reseller.id
    assert "No payment collected" in payment.notes
    revenue = (
        await db.execute(
            select(func.coalesce(func.sum(CustomerPayment.amount), 0))
            .where(CustomerPayment.counts_as_revenue == True)  # noqa: E712
        )
    ).scalar_one()
    assert revenue == 0

    # Delivery tracked by an attempt hanging off that row, so it is retried.
    attempt = (await db.execute(select(ProvisioningAttempt))).scalar_one()
    assert attempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT
    assert attempt.source_pk == payment.id
    assert attempt.router_id == router.id
    assert attempt.provisioning_state == ProvisioningState.ROUTER_UPDATED

    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry == paid_until


async def test_activate_paid_until_uses_existing_future_expiry(db, monkeypatch):
    paid_until = (datetime.utcnow() + timedelta(days=9)).replace(microsecond=0)
    _, _, _, customer = await _seed(db, monkeypatch, expiry=paid_until)
    calls = _record_provisions(monkeypatch)

    response = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(activate_paid_until=True), db, "t",
    )

    assert response["customer"]["status"] == "active"
    assert response["customer"]["expiry"] == paid_until.isoformat()
    assert len(calls) == 1


async def test_activate_paid_until_router_down_is_retried(db, monkeypatch):
    _, _, _, customer = await _seed(db, monkeypatch)
    _record_provisions(monkeypatch, result={"error": "Failed to connect to router"})
    paid_until = datetime.utcnow() + timedelta(days=20)

    response = await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(expiry=paid_until, activate_paid_until=True),
        db, "t",
    )

    assert response["customer"]["status"] == "active"
    assert response["pppoe_reprovisioned"] == "retry_pending"
    attempt = (await db.execute(select(ProvisioningAttempt))).scalar_one()
    assert attempt.provisioning_state == ProvisioningState.RETRY_PENDING

    # The PPPoE retry worker picks it up once the router answers.
    retry_calls = _record_provisions(monkeypatch)
    attempt.last_attempt_at = datetime.utcnow() - timedelta(minutes=5)
    await db.commit()
    monkeypatch.setattr(pppoe_provisioning, "_retry_db_pool_is_busy", lambda: False)
    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert [c["pppoe_username"] for c in retry_calls] == ["techmid_client_1"]
    await db.refresh(attempt)
    assert attempt.provisioning_state == ProvisioningState.ROUTER_UPDATED


@pytest.mark.parametrize(
    "expiry_delta, detail",
    [
        (timedelta(days=-1), "already paid until"),
        (timedelta(days=800), "more than 400 days"),
    ],
)
async def test_activate_paid_until_rejects_bad_expiry_and_changes_nothing(
    db, monkeypatch, expiry_delta, detail,
):
    _, _, _, customer = await _seed(db, monkeypatch)
    calls = _record_provisions(monkeypatch)

    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id,
            customer_routes.CustomerEditRequest(
                expiry=datetime.utcnow() + expiry_delta, activate_paid_until=True, name="Changed",
            ),
            db, "t",
        )

    assert err.value.status_code == 400
    assert detail in err.value.detail
    assert calls == []
    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE
    assert customer.name == "Migrated Client"
    assert (await db.execute(select(func.count(CustomerPayment.id)))).scalar_one() == 0


async def test_activate_paid_until_refuses_active_customer(db, monkeypatch):
    _, _, _, customer = await _seed(
        db, monkeypatch, status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=3),
    )
    _record_provisions(monkeypatch)

    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id, customer_routes.CustomerEditRequest(activate_paid_until=True), db, "t",
        )
    assert err.value.status_code == 409
    assert (await db.execute(select(func.count(CustomerPayment.id)))).scalar_one() == 0


async def test_activate_paid_until_refuses_hotspot_customer(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    router = await make_router(db, reseller, ip_address="192.0.2.11")
    customer = await make_customer(db, reseller, plan, router, status=CustomerStatus.INACTIVE)

    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", fake_current_user)
    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id,
            customer_routes.CustomerEditRequest(
                expiry=datetime.utcnow() + timedelta(days=3), activate_paid_until=True,
            ),
            db, "t",
        )
    assert err.value.status_code == 400


async def test_activate_paid_until_only_for_own_customers(db, monkeypatch):
    _, _, _, customer = await _seed(db, monkeypatch)
    other = await make_reseller(db)

    async def other_user(_token, _db):
        return other

    monkeypatch.setattr(customer_routes, "get_current_user", other_user)
    with pytest.raises(HTTPException) as err:
        await customer_routes.edit_customer(
            customer.id,
            customer_routes.CustomerEditRequest(
                expiry=datetime.utcnow() + timedelta(days=3), activate_paid_until=True,
            ),
            db, "t",
        )
    assert err.value.status_code == 404


# ---------------------------------------------------------------------------
# Re-save of an ACTIVE customer
# ---------------------------------------------------------------------------


async def _active_with_payment(db, monkeypatch):
    reseller, plan, router, customer = await _seed(
        db, monkeypatch, status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=5),
    )
    payment = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id, amount=500,
        payment_method=PaymentMethod.CASH, days_paid_for=30,
        status=PaymentStatus.COMPLETED, customer_name=customer.name,
        created_at=datetime.utcnow() - timedelta(days=25),
    )
    db.add(payment)
    await db.commit()
    return reseller, router, customer, payment


async def test_resave_active_customer_provisions_through_attempt_without_kicking(db, monkeypatch):
    _, router, customer, payment = await _active_with_payment(db, monkeypatch)
    # The old delivery for that payment finished weeks ago.
    db.add(ProvisioningAttempt(
        customer_id=customer.id, router_id=router.id, mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT, source_pk=payment.id,
        entrypoint="manual_transaction_provision",
        provisioning_state=ProvisioningState.ROUTER_UPDATED,
        online_state=ProvisioningOnlineState.UNKNOWN, attempt_count=3,
        created_at=datetime.utcnow() - timedelta(days=25),
        updated_at=datetime.utcnow() - timedelta(days=25),
    ))
    await db.commit()
    calls = _record_provisions(monkeypatch, result={"error": "Failed to connect to router"})

    response = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(), db, "t",
    )

    assert len(calls) == 1
    assert calls[0]["pppoe_username"] == "techmid_client_1"
    assert calls[0]["disconnect"] is False  # nothing changed: leave devices connected
    assert response["pppoe_reprovisioned"] == "retry_pending"
    attempt = (await db.execute(select(ProvisioningAttempt))).scalar_one()
    await db.refresh(attempt)
    # Re-armed as a fresh delivery, so the 4 h retry window applies again.
    assert attempt.provisioning_state == ProvisioningState.RETRY_PENDING
    assert attempt.attempt_count == 1
    assert attempt.created_at > datetime.utcnow() - timedelta(minutes=5)


async def test_resave_skips_push_while_another_push_runs(db, monkeypatch):
    _, router, customer, payment = await _active_with_payment(db, monkeypatch)
    db.add(ProvisioningAttempt(
        customer_id=customer.id, router_id=router.id, mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT, source_pk=payment.id,
        entrypoint="manual_transaction_provision",
        provisioning_state=ProvisioningState.IN_PROGRESS,
        online_state=ProvisioningOnlineState.UNKNOWN, attempt_count=1,
        last_attempt_at=datetime.utcnow(),
        created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
    ))
    await db.commit()
    calls = _record_provisions(monkeypatch)

    response = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(), db, "t",
    )

    assert calls == []
    assert response["pppoe_reprovisioned"] == "in_progress"


async def test_resave_with_login_change_reconnects(db, monkeypatch):
    _, _, customer, _ = await _active_with_payment(db, monkeypatch)
    calls = _record_provisions(monkeypatch)

    response = await customer_routes.edit_customer(
        customer.id, customer_routes.CustomerEditRequest(pppoe_password="new-pw"), db, "t",
    )

    assert response["pppoe_reprovisioned"] == "ok"
    assert len(calls) == 1
    assert calls[0]["pppoe_password"] == "new-pw"
    assert calls[0]["disconnect"] is True

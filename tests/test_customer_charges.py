"""Tracking-only means HTTP ledger writes cannot touch existing service/accounting."""
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text, func

from app.api.auth_routes import login_token_claims
from app.api import customer_charge_routes as routes, customer_routes
from app.config import settings
from app.db.models import (Customer, CustomerCharge, CustomerChargeEvent, CustomerPayment,
                           CustomerStatus, ConnectionType, ResellerStaff, SubscriptionStatus,
                           Payment, MpesaTransaction, ResellerTransactionCharge, B2BTransaction,
                           ProvisioningAttempt, ProvisioningLog, SmsMessage, CustomerUsagePeriod)
from app.services import staff_access
from app.services.auth import create_access_token
from tests.factories import make_customer, make_plan, make_reseller
from tests.conftest import running_on_postgres


def key():
    return uuid4().hex


def headers(owner, staff=None):
    claims = staff_access.staff_token_claims(staff, owner) if staff else login_token_claims(owner)
    return {"Authorization": "Bearer " + create_access_token(claims, timedelta(hours=1))}


@pytest_asyncio.fixture
async def client(engine, monkeypatch):
    import main
    monkeypatch.setattr(settings, "TECHMID_INSTALLATION_CHARGES_ENABLED", True)
    staff_access.reset_cache()
    async def no_sms(*args, **kwargs):
        raise AssertionError("Ledger must not send SMS")
    monkeypatch.setattr(staff_access, "alert_owner", no_sms)
    from app.services import reseller_payments, pppoe_provisioning, static_ip
    async def forbidden(*args, **kwargs):
        raise AssertionError("Installation ledger crossed a service/payment boundary")
    monkeypatch.setattr(reseller_payments, "record_customer_payment", forbidden)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", forbidden)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_remove", forbidden)
    monkeypatch.setattr(static_ip, "provision_static_customer", forbidden)
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value
    staff_access.reset_cache()


async def setup(db, connection=ConnectionType.PPPOE, **customer_fields):
    owner = await make_reseller(db, id=routes.TECHMID_OWNER_ID)
    plan = await make_plan(db, owner, connection_type=connection)
    customer = await make_customer(db, owner, plan, **customer_fields)
    return owner, customer, f"/api/customers/{customer.id}/installation-charges"


async def add(client, path, auth, amount=10000, request_key=None):
    return await client.post(path, headers=auth, json={"idempotency_key": request_key or key(),
        "amount_minor": amount, "description": "Installation"})


async def settle(client, path, auth, charge_id, amount, kind="external_payment", request_key=None):
    return await client.post(f"{path}/{charge_id}/events", headers=auth, json={
        "idempotency_key": request_key or key(), "kind": kind, "amount_minor": amount,
        "reason": "Receipt recorded" if kind == "external_payment" else "Owner waiver"})


async def reverse(client, path, auth, charge_id, event_id, request_key=None):
    return await client.post(f"{path}/{charge_id}/events/{event_id}/reversal", headers=auth,
        json={"idempotency_key": request_key or key(), "reason": "Correct mistaken entry"})


@pytest.mark.asyncio
@pytest.mark.parametrize("connection", [ConnectionType.PPPOE, ConnectionType.STATIC_IP])
@pytest.mark.parametrize("state", ["active", "paused", "inactive"])
async def test_ledger_never_changes_customer_or_platform_payments(client, db, connection, state):
    fields = dict(status=CustomerStatus.ACTIVE if state == "active" else CustomerStatus.INACTIVE,
                  expiry=datetime.utcnow() + timedelta(days=5), wallet_credit_kes=73,
                  grace_period_minutes=60, pending_update_data={"keep": "unchanged"})
    if state == "paused":
        fields.update(paused_at=datetime.utcnow(), paused_remaining_seconds=12345,
                      pause_resume_at=datetime.utcnow() + timedelta(days=1))
    owner, customer, path = await setup(db, connection, **fields)
    auth = headers(owner)
    before = dict((await db.execute(select(Customer.__table__).where(Customer.id == customer.id))).mappings().one())
    async def assert_customer_unchanged():
        persisted = dict((await db.execute(select(Customer.__table__).where(Customer.id == customer.id))).mappings().one())
        assert persisted == before
    created = await add(client, path, auth, amount=10001)
    assert created.status_code == 201, created.text
    await assert_customer_unchanged()
    charge = created.json()
    paid = await settle(client, path, auth, charge["id"], 4001)
    assert paid.status_code == 201, paid.text
    await assert_customer_unchanged()
    waived = await settle(client, path, auth, charge["id"], 2000, "waiver")
    assert waived.status_code == 201, waived.text
    await assert_customer_unchanged()
    assert waived.json()["outstanding_minor"] == 4000
    undone = await reverse(client, path, auth, charge["id"], paid.json()["events"][-1]["id"])
    assert undone.status_code == 201, undone.text
    assert undone.json()["outstanding_minor"] == 8001
    assert undone.json()["payments_minor"] == 0
    await assert_customer_unchanged()  # Includes pause, wallet, plan, pending edits and expiry.
    for model in (CustomerPayment, Payment, MpesaTransaction, ResellerTransactionCharge,
                  B2BTransaction, ProvisioningAttempt, ProvisioningLog, SmsMessage, CustomerUsagePeriod):
        assert (await db.scalar(select(func.count()).select_from(model))) == 0, model.__name__
    listed = await client.get(path, headers=auth)
    assert listed.status_code == 200
    assert len(listed.json()["charges"][0]["events"]) == 4


@pytest.mark.asyncio
async def test_reversal_validation_and_idempotency(client, db):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    request_key = key()
    charge = (await add(client, path, auth, request_key=request_key)).json()
    repeated = await add(client, path, auth, request_key=request_key)
    assert repeated.json()["id"] == charge["id"]
    assert (await add(client, path, auth, amount=99, request_key=request_key)).status_code == 409
    paid = (await settle(client, path, auth, charge["id"], 10000)).json()
    assert (await settle(client, path, auth, charge["id"], 1)).status_code == 409
    assert (await reverse(client, path, auth, charge["id"], charge["events"][0]["id"])).status_code == 409
    payment_event = paid["events"][-1]["id"]
    reversal_key = key()
    undone = await reverse(client, path, auth, charge["id"], payment_event, reversal_key)
    assert undone.status_code == 201
    assert (await reverse(client, path, auth, charge["id"], payment_event, reversal_key)).status_code == 201
    assert (await reverse(client, path, auth, charge["id"], payment_event)).status_code == 409
    assert (await reverse(client, path, auth, charge["id"], undone.json()["events"][-1]["id"])).status_code == 409
    cancelled = await reverse(client, path, auth, charge["id"], charge["events"][0]["id"])
    assert cancelled.json()["reversed"] is True
    assert cancelled.json()["outstanding_minor"] == 0
    assert (await settle(client, path, auth, charge["id"], 1)).status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [0, -1, True, 1.25, "100", 100_000_001])
async def test_strict_money_validation(client, db, amount):
    owner, customer, path = await setup(db)
    assert (await add(client, path, headers(owner), amount)).status_code == 422


@pytest.mark.asyncio
async def test_feature_gate_and_tenant_isolation(client, db, monkeypatch):
    owner, customer, path = await setup(db)
    other = await make_reseller(db)
    other_plan = await make_plan(db, other, connection_type=ConnectionType.PPPOE)
    other_customer = await make_customer(db, other, other_plan)
    foreign = f"/api/customers/{other_customer.id}/installation-charges"
    assert (await client.get(path, headers=headers(other))).status_code == 404
    assert (await add(client, path, headers(other))).status_code == 404
    assert (await client.get(foreign, headers=headers(owner))).status_code == 404
    assert (await add(client, foreign, headers(owner))).status_code == 404
    monkeypatch.setattr(settings, "TECHMID_INSTALLATION_CHARGES_ENABLED", False)
    assert (await client.get(path, headers=headers(owner))).status_code == 404
    assert (await add(client, path, headers(owner))).status_code == 404


@pytest.mark.asyncio
async def test_plan_removal_keeps_history_and_corrections_but_no_new_debt(client, db):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    charge = (await add(client, path, auth)).json()
    customer.plan_id = None
    await db.commit()
    history = await client.get(path, headers=auth)
    assert history.json()["can_create"] is False
    assert len(history.json()["charges"]) == 1
    assert (await add(client, path, auth)).status_code == 409
    paid = await settle(client, path, auth, charge["id"], 500)
    assert paid.status_code == 201
    assert (await reverse(client, path, auth, charge["id"], paid.json()["events"][-1]["id"])).status_code == 201


@pytest.mark.asyncio
async def test_inactive_subscription_reads_history_but_cannot_write(client, db):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    charge = (await add(client, path, auth)).json()
    owner.subscription_status = SubscriptionStatus.INACTIVE
    await db.commit()
    assert (await client.get(path, headers=auth)).status_code == 200
    assert (await add(client, path, auth)).status_code == 403
    assert (await settle(client, path, auth, charge["id"], 500)).status_code == 403
    assert (await reverse(client, path, auth, charge["id"], charge["events"][0]["id"])).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("account_admin", [False, True])
async def test_staff_can_read_but_never_mutate_even_account_admin(client, db, account_admin):
    owner, customer, path = await setup(db)
    charge = (await add(client, path, headers(owner))).json()
    staff = ResellerStaff(parent_reseller_id=owner.id, name="Reader", email="reader@example.com",
        password_hash="unused", permissions=["customers.view", "customers.manage"], is_account_admin=account_admin)
    db.add(staff)
    await db.commit()
    auth = headers(owner, staff)
    assert (await client.get(path, headers=auth)).status_code == 200
    assert (await add(client, path, auth)).status_code == 403
    assert (await settle(client, path, auth, charge["id"], 1)).status_code == 403
    assert (await reverse(client, path, auth, charge["id"], charge["events"][0]["id"])).status_code == 403
    staff.permissions = []
    staff.is_account_admin = False
    await db.commit()
    assert (await client.get(path, headers=auth)).status_code == 403


@pytest.mark.asyncio
async def test_customer_delete_retains_ledger_and_snapshots(client, db):
    owner, customer, path = await setup(db, status=CustomerStatus.INACTIVE)
    charge = (await add(client, path, headers(owner))).json()
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    await db.commit()
    await customer_routes.delete_customer(customer.id, db, {"user_id": owner.id, "role": "reseller"})
    saved = await db.get(CustomerCharge, charge["id"])
    assert saved.customer_id is None
    assert saved.customer_id_snapshot == customer.id
    assert saved.customer_name_snapshot == "Test Customer"
    assert (await db.scalar(select(func.count()).select_from(CustomerChargeEvent))) == 1


@pytest.mark.asyncio
@pytest.mark.skipif(not running_on_postgres(), reason="Row locking requires PostgreSQL")
@pytest.mark.parametrize("duplicate", [False, True])
async def test_concurrent_settlements_cannot_overpay_or_duplicate(client, db, duplicate):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    charge = (await add(client, path, auth)).json()
    request_key = key()
    responses = await asyncio.gather(
        settle(client, path, auth, charge["id"], 8000, request_key=request_key),
        settle(client, path, auth, charge["id"], 8000, request_key=request_key if duplicate else key()))
    assert sorted(r.status_code for r in responses) == ([201, 201] if duplicate else [201, 409])
    saved = (await client.get(path, headers=auth)).json()["charges"][0]
    assert saved["outstanding_minor"] == 2000
    assert len(saved["events"]) == 2


@pytest.mark.asyncio
@pytest.mark.skipif(not running_on_postgres(), reason="Row locking requires PostgreSQL")
async def test_concurrent_create_and_reversal_are_once_only(client, db):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    request_key = key()
    creates = await asyncio.gather(*(add(client, path, auth, request_key=request_key) for _ in range(2)))
    assert [r.status_code for r in creates] == [201, 201]
    assert creates[0].json()["id"] == creates[1].json()["id"]
    charge = creates[0].json()
    reversals = await asyncio.gather(*(reverse(client, path, auth, charge["id"], charge["events"][0]["id"]) for _ in range(2)))
    assert sorted(r.status_code for r in reversals) == [201, 409]
    assert (await db.scalar(select(func.count()).select_from(CustomerCharge))) == 1
    assert (await db.scalar(select(func.count()).select_from(CustomerChargeEvent))) == 2


@pytest.mark.asyncio
async def test_request_key_cannot_be_reused_across_customers_or_charges(client, db):
    owner, customer, path = await setup(db)
    auth = headers(owner)
    request_key = key()
    charge = (await add(client, path, auth, request_key=request_key)).json()
    plan = await make_plan(db, owner, connection_type=ConnectionType.PPPOE)
    other = await make_customer(db, owner, plan)
    other_path = f"/api/customers/{other.id}/installation-charges"
    assert (await add(client, other_path, auth, request_key=request_key)).status_code == 409
    assert (await settle(client, other_path, auth, charge["id"], 1)).status_code == 404
    request_key = key()
    assert (await settle(client, path, auth, charge["id"], 1, request_key=request_key)).status_code == 201
    another = (await add(client, path, auth)).json()
    assert (await settle(client, path, auth, another["id"], 1, request_key=request_key)).status_code == 409


@pytest.mark.asyncio
async def test_pagination_and_hotspot_creation_refusal(client, db):
    owner, customer, path = await setup(db, ConnectionType.HOTSPOT)
    auth = headers(owner)
    response = await client.get(path, headers=auth)
    assert response.json() == {"can_create": False, "charges": [], "next_offset": None}
    assert (await add(client, path, auth)).status_code == 409
    customer.plan_id = (await make_plan(db, owner, connection_type=ConnectionType.PPPOE)).id
    await db.commit()
    first = (await add(client, path, auth)).json()
    second = (await add(client, path, auth)).json()
    page = (await client.get(path + "?limit=1", headers=auth)).json()
    assert [c["id"] for c in page["charges"]] == [second["id"]]
    assert page["next_offset"] == 1
    page2 = (await client.get(path + "?limit=1&offset=1", headers=auth)).json()
    assert [c["id"] for c in page2["charges"]] == [first["id"]]
    assert page2["next_offset"] is None


@pytest.mark.asyncio
async def test_migration_is_additive_and_repeatable(engine, monkeypatch):
    import main
    monkeypatch.setattr(main, "async_engine", engine)
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE customer_charge_events"))
        await conn.execute(text("DROP TABLE customer_charges"))
    await main.run_customer_charge_migrations()
    await main.run_customer_charge_migrations()
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM customer_charges"))).scalar() == 0
        assert (await conn.execute(text("SELECT count(*) FROM customer_charge_events"))).scalar() == 0

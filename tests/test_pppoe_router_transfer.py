from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import router_operations
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningState,
    UsageCapWatchState,
)
from app.services.auth import verify_token
from app.services.pppoe_router_transfer import transfer_pppoe_customers_between_routers
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _seed_pppoe_plan(db, reseller):
    return await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        speed="15M/15M",
        name="PPPoE 15M",
    )


@pytest_asyncio.fixture
async def transfer_app(session_factory):
    app = FastAPI()
    app.include_router(router_operations.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[verify_token] = lambda: "test-token"
    return app


@pytest_asyncio.fixture
async def transfer_client(transfer_app):
    async with AsyncClient(
        transport=ASGITransport(app=transfer_app),
        base_url="http://test",
    ) as client:
        yield client


async def test_pppoe_router_transfer_dry_run_preserves_rows(db):
    reseller = await make_reseller(db)
    source = await make_router(db, reseller, name="Old Router")
    target = await make_router(db, reseller, name="New Router")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)

    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=10),
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password=None,
        status=CustomerStatus.INACTIVE,
    )
    hotspot = await make_customer(
        db,
        reseller,
        hotspot_plan,
        source,
        status=CustomerStatus.ACTIVE,
    )

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=True,
    )

    assert report.errors == []
    assert report.selected == 2
    assert report.moved == 2
    assert report.active == 1
    assert report.inactive == 1
    assert report.missing_passwords == 1
    assert report.samples[0]["pppoe_username"] == "alice"
    assert "blank destination router" in report.warnings[0]

    await db.refresh(active)
    await db.refresh(inactive)
    await db.refresh(hotspot)
    assert active.router_id == source.id
    assert inactive.router_id == source.id
    assert hotspot.router_id == source.id


async def test_pppoe_router_transfer_apply_moves_customer_and_operational_state(db):
    reseller = await make_reseller(db)
    source = await make_router(db, reseller, name="Old Router")
    target = await make_router(db, reseller, name="New Router")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    hotspot_plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    expiry = datetime.utcnow() + timedelta(days=15)

    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
        expiry=expiry,
        account_number="10000001",
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
        account_number="10000002",
    )
    pending = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="carol",
        pppoe_password="secret-c",
        status=CustomerStatus.PENDING,
        account_number="10000003",
    )
    hotspot = await make_customer(
        db,
        reseller,
        hotspot_plan,
        source,
        status=CustomerStatus.ACTIVE,
        account_number="10000004",
    )

    watch = UsageCapWatchState(
        customer_id=active.id,
        router_id=source.id,
        queue_key="pppoe:alice",
        next_poll_at=datetime.utcnow(),
    )
    attempt = ProvisioningAttempt(
        customer_id=active.id,
        router_id=source.id,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        source_pk=9001,
        entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        provisioning_state=ProvisioningState.SCHEDULED,
    )
    db.add_all([watch, attempt])
    await db.commit()

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=False,
        provision_target=False,
    )

    assert report.errors == []
    assert report.selected == 3
    assert report.moved == 3
    assert report.usage_watch_states_updated == 1
    assert report.provisioning_attempts_updated == 1

    for customer in (active, inactive, pending):
        await db.refresh(customer)
        assert customer.router_id == target.id
        assert customer.plan_id == pppoe_plan.id
        assert customer.pppoe_password.startswith("secret-")

    assert active.status == CustomerStatus.ACTIVE
    assert active.expiry == expiry
    assert active.account_number == "10000001"
    assert inactive.status == CustomerStatus.INACTIVE
    assert pending.status == CustomerStatus.PENDING

    await db.refresh(hotspot)
    assert hotspot.router_id == source.id

    refreshed_watch = (
        await db.execute(select(UsageCapWatchState).where(UsageCapWatchState.id == watch.id))
    ).scalar_one()
    refreshed_attempt = (
        await db.execute(select(ProvisioningAttempt).where(ProvisioningAttempt.id == attempt.id))
    ).scalar_one()
    assert refreshed_watch.router_id == target.id
    assert refreshed_attempt.router_id == target.id


async def test_pppoe_router_transfer_active_only_moves_only_active_customers(db):
    reseller = await make_reseller(db)
    source = await make_router(db, reseller)
    target = await make_router(db, reseller)
    pppoe_plan = await _seed_pppoe_plan(db, reseller)

    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
    )

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=False,
        active_only=True,
        provision_target=False,
    )

    assert report.errors == []
    assert report.selected == 1
    assert report.moved == 1
    assert "inactive/expired PPPoE customers" in report.warnings[0]

    await db.refresh(active)
    await db.refresh(inactive)
    assert active.router_id == target.id
    assert inactive.router_id == source.id


async def test_pppoe_router_transfer_refuses_cross_owner_transfer(db):
    reseller = await make_reseller(db)
    other_reseller = await make_reseller(db)
    source = await make_router(db, reseller)
    target = await make_router(db, other_reseller)
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=False,
    )

    assert "different users" in report.errors[0]
    await db.refresh(customer)
    assert customer.router_id == source.id


async def test_pppoe_router_transfer_provisions_active_customers_before_move(db, monkeypatch):
    calls = []

    async def fake_provision(router_info, items):
        calls.append((router_info, items))
        return {
            "success": True,
            "provisioned": [
                {"customer_id": item["customer_id"], "pppoe_username": item["pppoe_username"]}
                for item in items
            ],
            "failed": [],
        }

    monkeypatch.setattr(
        "app.services.pppoe_router_transfer._provision_target_router",
        fake_provision,
    )

    reseller = await make_reseller(db)
    source = await make_router(db, reseller, name="Old Router")
    target = await make_router(db, reseller, name="New Router", ip_address="10.0.0.44")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)

    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
    )

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=False,
    )

    assert report.errors == []
    assert report.selected == 2
    assert report.target_provision is True
    assert report.target_provision_required == 1
    assert report.target_provision_skipped == 1
    assert report.target_provisioned == 1
    assert report.moved == 2
    assert len(calls) == 1
    router_info, items = calls[0]
    assert router_info["id"] == target.id
    assert router_info["ip"] == "10.0.0.44"
    assert [item["pppoe_username"] for item in items] == ["alice"]
    assert items[0]["bandwidth_limit"] == "15M/15M"

    await db.refresh(active)
    await db.refresh(inactive)
    assert active.router_id == target.id
    assert inactive.router_id == target.id


async def test_pppoe_router_transfer_does_not_move_db_when_target_provision_fails(db, monkeypatch):
    async def fake_provision(_router_info, items):
        return {
            "success": False,
            "provisioned": [],
            "failed": [
                {
                    "customer_id": items[0]["customer_id"],
                    "pppoe_username": items[0]["pppoe_username"],
                    "error": "Secret creation failed",
                }
            ],
        }

    monkeypatch.setattr(
        "app.services.pppoe_router_transfer._provision_target_router",
        fake_provision,
    )

    reseller = await make_reseller(db)
    source = await make_router(db, reseller)
    target = await make_router(db, reseller)
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
    )

    report = await transfer_pppoe_customers_between_routers(
        db,
        source_router_id=source.id,
        target_router_id=target.id,
        dry_run=False,
    )

    assert report.moved == 0
    assert report.target_provision_failed == 1
    assert report.target_provision_failures[0]["pppoe_username"] == "alice"
    assert "DB move was not applied" in report.errors[0]

    await db.refresh(active)
    await db.refresh(inactive)
    assert active.router_id == source.id
    assert inactive.router_id == source.id


async def test_move_pppoe_customers_cli_end_to_end_with_fake_routeros(
    db,
    session_factory,
    monkeypatch,
):
    import scripts.move_pppoe_customers as cli

    class FakeMikroTikAPI:
        instances = []

        def __init__(self, ip, username, password, port, timeout=None, connect_timeout=None):
            self.ip = ip
            self.username = username
            self.password = password
            self.port = port
            self.timeout = timeout
            self.connect_timeout = connect_timeout
            self.connected = False
            self.pools = []
            self.profiles = []
            self.secrets = []
            self.disconnected_users = []
            self.fasttrack_pools = []
            FakeMikroTikAPI.instances.append(self)

        def connect(self):
            self.connected = True
            return True

        def disconnect(self):
            self.connected = False

        def get_active_pppoe_profile(self):
            return {"found": False}

        def ensure_ip_pool(self, name, ranges):
            self.pools.append({"name": name, "ranges": ranges})
            return {"success": True}

        def _parse_speed_to_mikrotik(self, speed):
            return speed

        def ensure_pppoe_profile(
            self,
            name,
            rate_limit,
            local_address=None,
            pool_name=None,
            dns_server="",
            change_tcp_mss="",
        ):
            self.profiles.append(
                {
                    "name": name,
                    "rate_limit": rate_limit,
                    "local_address": local_address,
                    "pool_name": pool_name,
                    "dns_server": dns_server,
                    "change_tcp_mss": change_tcp_mss,
                }
            )
            return {"success": True}

        def add_pppoe_secret(self, username, password, profile, service="pppoe", comment=""):
            self.secrets.append(
                {
                    "username": username,
                    "password": password,
                    "profile": profile,
                    "service": service,
                    "comment": comment,
                }
            )
            return {"success": True}

        def disconnect_pppoe_session(self, username):
            self.disconnected_users.append(username)
            return {"success": True, "disconnected": 0}

        def ensure_pppoe_fasttrack_bypass(self, pool_name=None):
            self.fasttrack_pools.append(pool_name)
            return {"success": True}

    class DummyEngine:
        async def dispose(self):
            return None

    monkeypatch.setattr(cli, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(cli, "async_engine", DummyEngine())
    monkeypatch.setattr(
        "app.services.pppoe_router_transfer.MikroTikAPI",
        FakeMikroTikAPI,
    )

    reseller = await make_reseller(db)
    source = await make_router(db, reseller, name="Old Router", ip_address="10.0.0.11")
    target = await make_router(db, reseller, name="New Router", ip_address="10.0.0.22")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    expiry = datetime.utcnow() + timedelta(days=12)

    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
        expiry=expiry,
        account_number="10000011",
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
        account_number="10000012",
    )

    payment = CustomerPayment(
        customer_id=active.id,
        reseller_id=reseller.id,
        amount=500.0,
        payment_method=PaymentMethod.MOBILE_MONEY,
        payment_reference="PAY-001",
        days_paid_for=30,
        status=PaymentStatus.COMPLETED,
        customer_name=active.name,
    )
    txn = MpesaTransaction(
        checkout_request_id="ws_CO_TRANSFER_TEST",
        phone_number=active.phone,
        amount=500,
        reference=active.account_number,
        status=MpesaTransactionStatus.completed,
        customer_id=active.id,
        mpesa_receipt_number="RCP001",
    )
    db.add_all([payment, txn])
    await db.commit()

    exit_code = await cli.main(
        SimpleNamespace(
            source_router_id=source.id,
            target_router_id=target.id,
            active_only=False,
            sample_limit=10,
            skip_target_provision=False,
            apply=True,
        )
    )

    assert exit_code == 0
    assert len(FakeMikroTikAPI.instances) == 1
    fake_router = FakeMikroTikAPI.instances[0]
    assert fake_router.ip == target.ip_address
    assert fake_router.pools == [{"name": "pppoe-pool", "ranges": "192.168.89.2-192.168.89.254"}]
    assert [profile["name"] for profile in fake_router.profiles] == ["pppoe_15M_15M"]
    assert fake_router.profiles[0]["pool_name"] == "pppoe-pool"
    assert len(fake_router.secrets) == 1
    assert fake_router.secrets[0]["username"] == "alice"
    assert fake_router.secrets[0]["password"] == "secret-a"
    assert fake_router.secrets[0]["profile"] == "pppoe_15M_15M"
    assert "CID:" in fake_router.secrets[0]["comment"]
    assert fake_router.disconnected_users == ["alice"]
    assert fake_router.fasttrack_pools == ["pppoe-pool"]

    await db.refresh(active)
    await db.refresh(inactive)
    await db.refresh(payment)
    await db.refresh(txn)

    assert active.router_id == target.id
    assert inactive.router_id == target.id
    assert active.status == CustomerStatus.ACTIVE
    assert active.expiry == expiry
    assert active.account_number == "10000011"
    assert payment.customer_id == active.id
    assert payment.amount == 500.0
    assert payment.payment_reference == "PAY-001"
    assert txn.customer_id == active.id
    assert txn.checkout_request_id == "ws_CO_TRANSFER_TEST"
    assert txn.mpesa_receipt_number == "RCP001"


async def test_pppoe_transfer_endpoint_preview_returns_report_without_moving(
    db,
    transfer_client,
    monkeypatch,
):
    reseller = await make_reseller(db)

    async def fake_current_user(_token, _db):
        return reseller

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)

    source = await make_router(db, reseller, name="Old Router")
    target = await make_router(db, reseller, name="New Router")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )

    response = await transfer_client.post(
        f"/api/routers/{source.id}/pppoe-customers/transfer",
        json={"target_router_id": target.id},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["dry_run"] is True
    assert payload["source_router_id"] == source.id
    assert payload["target_router_id"] == target.id
    assert payload["report"]["selected"] == 1
    assert payload["report"]["target_provision_required"] == 1

    await db.refresh(customer)
    assert customer.router_id == source.id


async def test_pppoe_transfer_endpoint_apply_updates_target_then_moves_db(
    db,
    transfer_client,
    monkeypatch,
):
    calls = []

    async def fake_current_user(_token, _db):
        return reseller

    async def fake_provision(router_info, items):
        calls.append((router_info, items))
        return {
            "success": True,
            "provisioned": [
                {"customer_id": item["customer_id"], "pppoe_username": item["pppoe_username"]}
                for item in items
            ],
            "failed": [],
        }

    monkeypatch.setattr(router_operations, "get_current_user", fake_current_user)
    monkeypatch.setattr(
        "app.services.pppoe_router_transfer._provision_target_router",
        fake_provision,
    )

    reseller = await make_reseller(db)
    source = await make_router(db, reseller, name="Old Router")
    target = await make_router(db, reseller, name="New Router", ip_address="10.0.0.77")
    pppoe_plan = await _seed_pppoe_plan(db, reseller)
    active = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="alice",
        pppoe_password="secret-a",
        status=CustomerStatus.ACTIVE,
    )
    inactive = await make_customer(
        db,
        reseller,
        pppoe_plan,
        source,
        pppoe_username="bob",
        pppoe_password="secret-b",
        status=CustomerStatus.INACTIVE,
    )

    response = await transfer_client.post(
        f"/api/routers/{source.id}/pppoe-customers/transfer",
        json={"target_router_id": target.id, "apply": True},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["dry_run"] is False
    assert payload["report"]["moved"] == 2
    assert payload["report"]["target_provisioned"] == 1
    assert len(calls) == 1
    router_info, items = calls[0]
    assert router_info["id"] == target.id
    assert router_info["ip"] == "10.0.0.77"
    assert [item["pppoe_username"] for item in items] == ["alice"]

    await db.refresh(active)
    await db.refresh(inactive)
    assert active.router_id == target.id
    assert inactive.router_id == target.id

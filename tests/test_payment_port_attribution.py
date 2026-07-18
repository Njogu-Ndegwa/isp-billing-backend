from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.db.models import CustomerPayment, CustomerStatus
from app.services import payment_port_attribution as ppa
from tests.factories import make_customer, make_plan, make_reseller, make_router


class FakeBridgeHostAPI:
    """Router with the paying customer's MAC learned on ether3."""

    connect_result = True

    def __init__(self, *_args, **_kwargs):
        self.last_connect_error = "connect_failed"

    def connect(self):
        return self.connect_result

    def disconnect(self):
        pass

    def send_command_optimized(self, command, proplist=None, query=None):
        assert command == "/interface/bridge/host/print"
        return {
            "success": True,
            "data": [
                {"mac-address": "AA:BB:CC:DD:EE:01", "on-interface": "ether3", "local": "false"},
                # Router's own bridge MAC must be ignored
                {"mac-address": "AA:BB:CC:DD:EE:99", "on-interface": "bridge", "local": "true"},
            ],
        }


@pytest.fixture
def attribution_env(session_factory, monkeypatch):
    monkeypatch.setattr(ppa, "async_session", session_factory)
    monkeypatch.setattr(ppa, "_db_pool_is_busy", lambda: False)
    ppa._router_backoff.clear()
    return session_factory


@pytest.mark.asyncio
async def test_recent_payment_gets_stamped_with_current_port(db, attribution_env, monkeypatch):
    monkeypatch.setattr(ppa, "MikroTikAPI", FakeBridgeHostAPI)
    FakeBridgeHostAPI.connect_result = True

    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router A")
    plan = await make_plan(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        mac_address="aa-bb-cc-dd-ee-01",
    )
    recent = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id,
        amount=500.0, days_paid_for=30,
    )
    old = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id,
        amount=999.0, days_paid_for=30,
        created_at=datetime.utcnow() - ppa.ATTRIBUTION_WINDOW - timedelta(minutes=5),
    )
    db.add_all([recent, old])
    await db.commit()
    recent_id, old_id = recent.id, old.id

    await ppa.attribute_recent_payment_ports_background()

    async with attribution_env() as check:
        rows = {
            payment.id: payment.port_name
            for payment in (await check.execute(select(CustomerPayment))).scalars()
        }
    assert rows[recent_id] == "ether3"
    # Outside the window: never retried, stays unattributed
    assert rows[old_id] is None


@pytest.mark.asyncio
async def test_unreachable_router_backs_off_and_leaves_payment_null(db, attribution_env, monkeypatch):
    monkeypatch.setattr(ppa, "MikroTikAPI", FakeBridgeHostAPI)
    FakeBridgeHostAPI.connect_result = False

    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router B")
    plan = await make_plan(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        mac_address="aa-bb-cc-dd-ee-01",
    )
    payment = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id,
        amount=500.0, days_paid_for=30,
    )
    db.add(payment)
    await db.commit()
    payment_id = payment.id

    await ppa.attribute_recent_payment_ports_background()

    async with attribution_env() as check:
        stored = await check.get(CustomerPayment, payment_id)
        assert stored.port_name is None
    assert router.id in ppa._router_backoff

    # While backed off, the router must not be contacted at all
    def explode(*_a, **_k):
        raise AssertionError("router contacted during backoff")

    monkeypatch.setattr(ppa, "MikroTikAPI", explode)
    await ppa.attribute_recent_payment_ports_background()


@pytest.mark.asyncio
async def test_customer_without_mac_is_skipped(db, attribution_env, monkeypatch):
    monkeypatch.setattr(ppa, "MikroTikAPI", FakeBridgeHostAPI)
    FakeBridgeHostAPI.connect_result = True

    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="Router C")
    plan = await make_plan(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
    )
    customer.mac_address = None
    payment = CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id,
        amount=500.0, days_paid_for=30,
    )
    db.add(payment)
    await db.commit()
    payment_id = payment.id

    await ppa.attribute_recent_payment_ports_background()

    async with attribution_env() as check:
        stored = await check.get(CustomerPayment, payment_id)
        assert stored.port_name is None

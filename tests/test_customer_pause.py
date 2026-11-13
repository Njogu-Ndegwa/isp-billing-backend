"""Pause / resume a customer's subscription (app/services/customer_pause.py).

Router I/O is always mocked: PPPoE removal (call_pppoe_remove), PPPoE
provisioning (call_pppoe_provision underneath push_active_pppoe_customer) and
static-IP provisioning (provision_static_customer).
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import customer_routes
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerEvent,
    CustomerExpirySmsSettings,
    CustomerStatus,
    MessagingSettings,
    ProvisioningLog,
    SmsMessage,
)
from app.services import (
    customer_expiry_notifications,
    customer_grace,
    customer_pause,
    mikrotik_background,
    pppoe_provisioning,
    pppoe_resync,
    sms_dispatch,
)
from tests.factories import (
    make_admin,
    make_customer,
    make_plan,
    make_reseller,
    make_router,
    make_sms_account,
)


pytestmark = pytest.mark.asyncio

DAY = 86400


def _user_getter(user):
    async def _get(token, db):
        return user
    return _get


class FakeRouter:
    """Records what pause/resume asked the router to do."""

    def __init__(self, *, remove_ok=True, provision_ok=True):
        self.removed = []
        self.provisioned = []
        self.static_calls = []
        self.remove_ok = remove_ok
        self.provision_ok = provision_ok

    async def remove(self, payload):
        self.removed.append(payload)
        if not self.remove_ok:
            return {"error": "Failed to connect to router"}
        return {"success": True, "disconnect_result": {"success": True, "disconnected": 1},
                "remove_result": {"success": True, "action": "removed"}}

    async def provision(self, payload):
        self.provisioned.append(payload)
        if not self.provision_ok:
            return {"error": "Failed to connect to router"}
        return {"success": True, "profile": "pppoe_10M_10M"}

    async def static(self, customer_id, **kw):
        self.static_calls.append((customer_id, kw))
        enabled = kw.get("force_enabled", True)
        return {"success": True, "access": "enabled" if enabled is not False else "suspended",
                "changes": []}


def _install(monkeypatch, fake):
    monkeypatch.setattr(customer_pause, "call_pppoe_remove", fake.remove)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake.provision)
    monkeypatch.setattr(customer_pause, "provision_static_customer", fake.static)


async def _pppoe(db, *, reseller=None, days_left=5, status=CustomerStatus.ACTIVE, **kw):
    reseller = reseller or await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, status=status,
        expiry=datetime.utcnow() + timedelta(days=days_left),
        pppoe_username="kk-joe", pppoe_password="s3cret", name="Joe", **kw,
    )
    customer.mac_address = None
    await db.commit()
    return reseller, router, customer


async def _static(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=3), static_ip="192.168.2.24", name="Shop",
    )
    customer.mac_address = None
    await db.commit()
    return reseller, router, customer


async def _pause(customer, user, resume_at=None, db=None):
    request = customer_routes.PauseCustomerRequest(resume_at=resume_at)
    return await customer_routes.pause_customer_api(customer.id, request, db, "t")


async def _events(db, customer_id, event_type):
    return (await db.execute(
        select(CustomerEvent).where(
            CustomerEvent.customer_id == customer_id, CustomerEvent.event_type == event_type,
        )
    )).scalars().all()


# --- pause --------------------------------------------------------------------

async def test_pause_pppoe_stores_remaining_time_and_cuts_the_router(db, monkeypatch):
    reseller, router, customer = await _pppoe(db, days_left=5)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)

    out = await _pause(customer, reseller, db=db)

    assert out["is_paused"] is True and out["status"] == "inactive"
    assert fake.removed == [{
        "pppoe_username": "kk-joe", "router_ip": router.ip_address,
        "router_username": router.username, "router_password": router.password,
        "router_port": router.port,
    }]
    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE
    assert customer.paused_at is not None
    assert 5 * DAY - 60 <= customer.paused_remaining_seconds <= 5 * DAY
    # The paid clock is stopped: expiry is the pause moment, not 5 days out.
    assert customer.expiry == customer.paused_at
    # Credentials stay, so resume puts back exactly the same secret.
    assert customer.pppoe_username == "kk-joe" and customer.pppoe_password == "s3cret"
    log = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.customer_id == customer.id))).scalars().all()
    assert [(l.action, l.status) for l in log] == [("pppoe_deactivation", "success")]
    (event,) = await _events(db, customer.id, "customer_paused")
    assert event.message.startswith("Paused by Test ISP, 4d 23h left")
    assert "secret removed from the router" in event.message


async def test_pause_keeps_customer_untouched_when_router_fails(db, monkeypatch):
    reseller, _, customer = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    _install(monkeypatch, FakeRouter(remove_ok=False))
    expiry = customer.expiry

    with pytest.raises(HTTPException) as exc:
        await _pause(customer, reseller, db=db)

    assert exc.value.status_code == 503 and "nothing was changed" in exc.value.detail
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.paused_at is None and customer.expiry == expiry


async def test_pausing_twice_is_idempotent(db, monkeypatch):
    reseller, _, customer = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)

    first = await _pause(customer, reseller, db=db)
    second = await _pause(customer, reseller, db=db)

    assert first["already_paused"] is False and second["already_paused"] is True
    assert second["paused_remaining_seconds"] == first["paused_remaining_seconds"]
    assert second["paused_at"] == first["paused_at"]
    assert len(fake.removed) == 1
    assert len(await _events(db, customer.id, "customer_paused")) == 1


@pytest.mark.parametrize("case", ["expired", "inactive", "in_grace"])
async def test_cannot_pause_without_paid_time(db, monkeypatch, case):
    reseller, _, customer = await _pppoe(db)
    if case == "expired":
        customer.expiry = datetime.utcnow() - timedelta(hours=1)
    elif case == "inactive":
        customer.status = CustomerStatus.INACTIVE
    else:  # paid time over, still connected inside a grace window
        customer.expiry = datetime.utcnow() - timedelta(minutes=10)
        customer.grace_period_minutes = 120
    await db.commit()
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)

    with pytest.raises(HTTPException) as exc:
        await _pause(customer, reseller, db=db)

    assert exc.value.status_code == 400 and "no paid time" in exc.value.detail
    assert fake.removed == []


async def test_hotspot_customers_cannot_be_paused(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                                   expiry=datetime.utcnow() + timedelta(days=1))
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    _install(monkeypatch, FakeRouter())

    with pytest.raises(HTTPException) as exc:
        await _pause(customer, reseller, db=db)
    assert exc.value.status_code == 400 and "PPPoE and static-IP" in exc.value.detail


async def test_auto_resume_date_must_be_in_the_future(db, monkeypatch):
    reseller, _, customer = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)

    with pytest.raises(HTTPException) as exc:
        await _pause(customer, reseller, resume_at=datetime.utcnow() - timedelta(days=1), db=db)
    assert exc.value.status_code == 400
    assert fake.removed == []


# --- resume -------------------------------------------------------------------

async def test_resume_pppoe_sets_expiry_from_remaining_and_restores_the_secret(db, monkeypatch):
    reseller, router, customer = await _pppoe(db, days_left=12)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)
    await _pause(customer, reseller, db=db)

    # Ten days pass while paused.
    await db.refresh(customer)
    remaining = customer.paused_remaining_seconds
    customer.paused_at -= timedelta(days=10)
    customer.expiry = customer.paused_at
    await db.commit()

    before = datetime.utcnow()
    out = await customer_routes.resume_customer_api(customer.id, db, "t")
    after = datetime.utcnow()

    assert out["router_result"] == "ok" and out["is_paused"] is False
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.paused_at is None and customer.paused_remaining_seconds is None
    assert before + timedelta(seconds=remaining) - timedelta(seconds=1) <= customer.expiry
    assert customer.expiry <= after + timedelta(seconds=remaining)
    # Same username and password back on the same router: the CPE just redials.
    (payload,) = fake.provisioned
    assert payload["pppoe_username"] == "kk-joe" and payload["pppoe_password"] == "s3cret"
    assert payload["router_ip"] == router.ip_address
    (event,) = await _events(db, customer.id, "customer_resumed")
    assert "Resumed by Test ISP, new expiry" in event.message and "11d 23h restored" in event.message


async def test_resume_survives_an_unreachable_router(db, monkeypatch):
    reseller, _, customer = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter(provision_ok=False)
    _install(monkeypatch, fake)
    await _pause(customer, reseller, db=db)

    out = await customer_routes.resume_customer_api(customer.id, db, "t")

    # Still resumed: ACTIVE customers are re-delivered by the retry worker and
    # the recovery sweep.
    assert out["status"] == "active" and out["router_result"] in ("retry_pending", "failed")
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE and customer.paused_at is None


async def test_resume_of_a_customer_that_is_not_paused(db, monkeypatch):
    reseller, _, customer = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    _install(monkeypatch, FakeRouter())

    out = await customer_routes.resume_customer_api(customer.id, db, "t")
    assert out["already_active"] is True

    customer.status = CustomerStatus.INACTIVE
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await customer_routes.resume_customer_api(customer.id, db, "t")
    assert exc.value.status_code == 400


async def test_static_ip_pause_and_resume(db, monkeypatch):
    reseller, _, customer = await _static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)

    await _pause(customer, reseller, db=db)
    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE and customer.paused_at is not None
    assert fake.static_calls[0] == (customer.id, {"action": "customer_pause", "force_enabled": False})

    out = await customer_routes.resume_customer_api(customer.id, db, "t")
    assert out["router_result"] == "ok"
    assert fake.static_calls[1] == (customer.id, {"action": "static_ip_resume"})
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry > datetime.utcnow() + timedelta(days=2, hours=23)


async def test_auto_resume_job_resumes_due_customers_only(db, monkeypatch):
    reseller, _, due = await _pppoe(db)
    _, _, later = await _pppoe(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    fake = FakeRouter()
    _install(monkeypatch, fake)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _job: False)
    await _pause(due, reseller, resume_at=datetime.utcnow() + timedelta(days=2), db=db)
    later_owner = (await db.get(Customer, later.id)).user_id
    from app.db.models import User
    monkeypatch.setattr(customer_routes, "get_current_user",
                        _user_getter(await db.get(User, later_owner)))
    await _pause(later, None, resume_at=datetime.utcnow() + timedelta(days=9), db=db)
    # Two days later.
    row = await db.get(Customer, due.id)
    row.pause_resume_at = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()

    summary = await customer_pause.auto_resume_due_customers_background()

    assert summary == {"due": 1, "resumed": 1, "failed": 0}
    await db.refresh(due)
    await db.refresh(later)
    assert due.status == CustomerStatus.ACTIVE and due.paused_at is None
    assert later.paused_at is not None
    (event,) = await _events(db, due.id, "customer_resumed")
    assert event.message.startswith("Auto-resumed on schedule")


# --- guards: tenancy ----------------------------------------------------------

async def test_another_reseller_cannot_pause_or_resume(db, monkeypatch):
    owner, _, customer = await _pppoe(db)
    intruder = await make_reseller(db)
    fake = FakeRouter()
    _install(monkeypatch, fake)

    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(intruder))
    with pytest.raises(HTTPException) as exc:
        await _pause(customer, intruder, db=db)
    assert exc.value.status_code == 404
    assert fake.removed == []

    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(owner))
    await _pause(customer, owner, db=db)

    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(intruder))
    with pytest.raises(HTTPException) as exc:
        await customer_routes.resume_customer_api(customer.id, db, "t")
    assert exc.value.status_code == 404
    await db.refresh(customer)
    assert customer.paused_at is not None and customer.status == CustomerStatus.INACTIVE


async def test_platform_admin_can_pause_any_customer(db, monkeypatch):
    _, _, customer = await _pppoe(db)
    admin = await make_admin(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(admin))
    _install(monkeypatch, FakeRouter())

    out = await _pause(customer, admin, db=db)
    assert out["is_paused"] is True
    (event,) = await _events(db, customer.id, "customer_paused")
    assert event.message.startswith("Paused by Platform admin")


# --- guards: jobs ignore paused customers -------------------------------------

async def _paused_customer(db, monkeypatch, **kw):
    reseller, router, customer = await _pppoe(db, **kw)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    _install(monkeypatch, FakeRouter())
    await _pause(customer, reseller, db=db)
    await db.refresh(customer)
    return reseller, router, customer


async def test_expiry_cleanup_skips_paused_customers(db, session_factory, monkeypatch):
    _, _, customer = await _paused_customer(db, monkeypatch)
    snapshot = (customer.status, customer.expiry, customer.paused_remaining_seconds)

    async def _zero(*_a, **_k):
        return 0

    async def _none(*_a, **_k):
        return None

    removed = []
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _j: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _none)
    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_pppoe_sync",
                        lambda _r, items: removed.extend(items) or {"removed": [], "failed": []})
    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync",
                        lambda _r, items: removed.extend(items) or {"removed": [], "failed": []})

    await mikrotik_background.cleanup_expired_users_background()

    await db.refresh(customer)
    assert removed == []
    assert (customer.status, customer.expiry, customer.paused_remaining_seconds) == snapshot


async def test_no_expiry_sms_or_reminder_for_paused_customers(db, session_factory, monkeypatch):
    reseller, _, customer = await _paused_customer(db, monkeypatch)
    await make_sms_account(db, reseller, balance=5)
    db.add(MessagingSettings(id=1, enabled=True))
    db.add(CustomerExpirySmsSettings(
        user_id=reseller.id, enabled=True, reminder_offsets_minutes=[1440], send_at_expiry=True,
    ))
    await db.commit()

    # At-expiry message: the frozen expiry is in the past, but they are paused.
    campaigns = await customer_expiry_notifications.queue_customer_expiry_notifications(
        [customer.id], session_factory=session_factory,
    )
    assert campaigns == []

    # Pre-expiry reminder: nothing is "about to expire" while paused.
    monkeypatch.setattr(customer_expiry_notifications.database, "async_session", session_factory)
    monkeypatch.setattr(customer_expiry_notifications.database, "db_pool_snapshot",
                        lambda: {"pressure": {"level": "healthy"}})
    monkeypatch.setattr(customer_expiry_notifications, "spawn_expiry_campaign_dispatch",
                        lambda ids: None)
    assert await customer_expiry_notifications.scan_customer_expiry_reminders() == 0
    assert (await db.execute(select(SmsMessage))).scalars().all() == []

    # Manual "expiring" campaigns leave them out too.
    recipients = await sms_dispatch.resolve_recipients(db, reseller.id, filter="expiring")
    assert customer.id not in [r["customer_id"] for r in recipients]


async def test_pppoe_retry_worker_and_recovery_sweep_do_not_restore_paused(db, monkeypatch):
    _, router, customer = await _paused_customer(db, monkeypatch)
    now = datetime.utcnow()
    assert not pppoe_resync._customer_can_have_pppoe_access(
        await _with_plan_router(db, customer.id), now,
    )
    out = await pppoe_resync.push_active_pppoe_customer(customer.id)
    assert out == {"result": "not_eligible"}


async def _with_plan_router(db, customer_id):
    from sqlalchemy.orm import selectinload

    return (await db.execute(
        select(Customer).options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == customer_id)
    )).scalar_one()


async def test_grace_change_does_not_unpause(db, monkeypatch):
    reseller, _, customer = await _paused_customer(db, monkeypatch)

    out = await customer_routes.set_customer_grace_period(
        customer.id, customer_routes.CustomerGraceRequest(grace_period_minutes=3 * 24 * 60), db, "t",
    )

    assert out["restored"] is False
    await db.refresh(customer)
    assert customer.status == CustomerStatus.INACTIVE and customer.paused_at is not None


async def test_paused_customer_gets_no_grace():
    now = datetime(2026, 10, 27, 12, 0)
    c = Customer(expiry=now - timedelta(minutes=5), grace_period_minutes=600, paused_at=now - timedelta(minutes=5))
    assert customer_grace.effective_expiry(c) == now - timedelta(minutes=5)
    assert not customer_grace.has_access_time(c, now)
    # Renewal while paused restarts from now (the paused time is added by the flush hook).
    assert customer_grace.renewal_expiry(c, now, timedelta(days=30)) == now + timedelta(days=30)


# --- a payment while paused ---------------------------------------------------

async def test_payment_while_paused_ends_pause_and_keeps_paused_time(db, monkeypatch):
    _, _, customer = await _paused_customer(db, monkeypatch, days_left=12)
    remaining = customer.paused_remaining_seconds

    # What every renewal path does: new expiry, ACTIVE.
    now = datetime.utcnow()
    customer.expiry = customer_grace.renewal_expiry(customer, now, timedelta(days=30))
    customer.status = CustomerStatus.ACTIVE
    await db.commit()

    await db.refresh(customer)
    assert customer.paused_at is None and customer.paused_remaining_seconds is None
    expected = now + timedelta(days=30, seconds=remaining)
    assert abs((customer.expiry - expected).total_seconds()) < 2


async def test_expiry_edit_is_refused_while_paused(db, monkeypatch):
    reseller, _, customer = await _paused_customer(db, monkeypatch)

    with pytest.raises(HTTPException) as exc:
        await customer_routes.edit_customer(
            customer.id,
            customer_routes.CustomerEditRequest(expiry=datetime.utcnow() + timedelta(days=40)),
            db, "t",
        )
    assert exc.value.status_code == 409

    # Other edits (and the unchanged expiry the form sends back) still work.
    out = await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(name="Joe K", expiry=customer.expiry),
        db, "t",
    )
    assert out["customer"]["name"] == "Joe K"
    await db.refresh(customer)
    assert customer.paused_at is not None

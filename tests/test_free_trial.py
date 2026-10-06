"""Free-trial plans: claim once vs. repeatedly, no revenue, paid paths refuse them."""

import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    DurationUnit,
    FreeTrialClaim,
    PlanType,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def no_background_provisioning(monkeypatch):
    from app.services import voucher_service

    async def _fake_provision(*args, **kwargs):
        return {"success": True}

    monkeypatch.setattr(voucher_service, "provision_hotspot_customer", _fake_provision)


async def _trial_plan(db, reseller, **overrides):
    defaults = dict(
        price=0,
        duration_value=30,
        duration_unit=DurationUnit.MINUTES,
        plan_type=PlanType.FREE_TRIAL,
        name="Free 30 min",
    )
    defaults.update(overrides)
    return await make_plan(db, reseller, **defaults)


async def _expire(db, customer_id):
    customer = await db.get(Customer, customer_id)
    customer.expiry = datetime.utcnow() - timedelta(minutes=1)
    customer.status = CustomerStatus.INACTIVE
    await db.commit()


async def test_claim_grants_access_without_revenue(db, no_background_provisioning):
    from app.services.free_trial import claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    result = await claim_free_trial(db, plan.id, MAC, router.id, phone="0712 345 678")
    assert result["success"] is True, result

    customer = await db.get(Customer, result["customer_id"])
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.plan_id == plan.id
    assert customer.phone == "0712345678"
    # Exactly one plan duration, not stacked.
    remaining = customer.expiry - datetime.utcnow()
    assert timedelta(minutes=28) < remaining <= timedelta(minutes=30)

    payment = (await db.execute(select(CustomerPayment))).scalar_one()
    assert payment.amount == 0
    assert payment.counts_as_revenue is False

    attempt = (await db.execute(select(ProvisioningAttempt))).scalar_one()
    assert attempt.entrypoint == ProvisioningAttemptEntrypoint.FREE_TRIAL

    claim = (await db.execute(select(FreeTrialClaim))).scalar_one()
    assert (claim.plan_id, claim.customer_id, claim.payment_id) == (plan.id, customer.id, payment.id)
    # A one-device trial has nothing to share.
    assert "access_code" not in result


async def test_once_only_trial_cannot_be_claimed_twice(db, no_background_provisioning):
    from app.services.free_trial import TRIAL_ALREADY_USED, claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller, trial_once_per_customer=True)

    first = await claim_free_trial(db, plan.id, MAC, router.id)
    assert first["success"] is True
    await _expire(db, first["customer_id"])

    second = await claim_free_trial(db, plan.id, MAC.lower(), router.id)
    assert second == {"success": False, "error": TRIAL_ALREADY_USED}


async def test_once_only_survives_customer_deletion(db, monkeypatch, no_background_provisioning):
    """Deleting the customer through the real endpoint must not make the
    device eligible for the trial again."""
    import app.api.customer_routes as customer_routes
    from app.services.free_trial import TRIAL_ALREADY_USED, claim_free_trial
    from tests.test_admin_reseller_deletion import _create_radius_tables

    await _create_radius_tables(db)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    async def _current_user(token, session):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", _current_user)

    first = await claim_free_trial(db, plan.id, MAC, router.id)
    await customer_routes.delete_customer(first["customer_id"], db=db, token="t")
    assert await db.scalar(select(func.count(Customer.id))) == 0

    again = await claim_free_trial(db, plan.id, MAC, router.id)
    assert again["error"] == TRIAL_ALREADY_USED


async def test_once_only_matches_phone_on_a_new_device(db, no_background_provisioning):
    from app.services.free_trial import TRIAL_ALREADY_USED, claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    assert (await claim_free_trial(db, plan.id, MAC, router.id, phone="0712345678"))["success"]
    other_mac = await claim_free_trial(db, plan.id, "AA:BB:CC:DD:EE:02", router.id, phone="+254 712 345 678")
    assert other_mac["error"] == TRIAL_ALREADY_USED


async def test_short_phone_numbers_are_not_used_to_match(db, no_background_provisioning):
    from app.services.free_trial import claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    assert (await claim_free_trial(db, plan.id, MAC, router.id, phone="123"))["success"]
    assert (await claim_free_trial(db, plan.id, "AA:BB:CC:DD:EE:02", router.id, phone="123"))["success"]


async def test_repeatable_trial_can_be_claimed_again_after_it_ends(db, no_background_provisioning):
    from app.services.free_trial import claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller, trial_once_per_customer=False)

    first = await claim_free_trial(db, plan.id, MAC, router.id)
    await _expire(db, first["customer_id"])
    second = await claim_free_trial(db, plan.id, MAC, router.id)

    assert second["success"] is True
    assert second["customer_id"] == first["customer_id"]
    claims = await db.scalar(select(func.count(FreeTrialClaim.id)))
    assert claims == 2


async def test_repeatable_trial_refused_while_still_active(db, no_background_provisioning):
    from app.services.free_trial import TRIAL_WHILE_ACTIVE, claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller, trial_once_per_customer=False)

    assert (await claim_free_trial(db, plan.id, MAC, router.id))["success"]
    again = await claim_free_trial(db, plan.id, MAC, router.id)
    assert again["error"] == TRIAL_WHILE_ACTIVE


async def test_paying_customer_cannot_stack_a_trial(db, no_background_provisioning):
    from app.services.free_trial import TRIAL_WHILE_ACTIVE, claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    paid = await make_plan(db, reseller, price=500)
    plan = await _trial_plan(db, reseller)
    await make_customer(
        db, reseller, paid, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=3),
        mac_address=MAC,
    )

    result = await claim_free_trial(db, plan.id, MAC, router.id)
    assert result["error"] == TRIAL_WHILE_ACTIVE


@pytest.mark.parametrize(
    "overrides,router_scoped_away",
    [
        ({"plan_type": PlanType.REGULAR, "price": 50}, False),
        ({"is_hidden": True}, False),
        ({"valid_until": datetime.utcnow() - timedelta(days=1)}, False),
        ({}, True),
    ],
)
async def test_unavailable_trials_are_refused(db, no_background_provisioning, overrides, router_scoped_away):
    from app.services.free_trial import claim_free_trial

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    other_router = await make_router(db, reseller)
    if router_scoped_away:
        overrides = {**overrides, "router_ids": [other_router.id]}
    plan = await _trial_plan(db, reseller, **overrides)

    result = await claim_free_trial(db, plan.id, MAC, router.id)
    assert result["success"] is False
    assert await db.scalar(select(func.count(FreeTrialClaim.id))) == 0


async def test_trial_from_another_reseller_is_refused(db, no_background_provisioning):
    from app.services.free_trial import claim_free_trial

    owner = await make_reseller(db)
    other = await make_reseller(db)
    router = await make_router(db, owner)
    plan = await _trial_plan(db, other)

    result = await claim_free_trial(db, plan.id, MAC, router.id)
    assert result["success"] is False


async def test_eligibility_reports_used_trials(db, no_background_provisioning):
    from app.services.free_trial import TRIAL_ALREADY_USED, claim_free_trial, get_trial_eligibility

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    once = await _trial_plan(db, reseller, name="Once")
    repeat = await _trial_plan(db, reseller, name="Repeat", trial_once_per_customer=False)
    await make_plan(db, reseller, price=100, name="Paid")

    before = await get_trial_eligibility(db, router.id, MAC)
    assert {t["plan_id"]: t["eligible"] for t in before["trials"]} == {once.id: True, repeat.id: True}

    first = await claim_free_trial(db, once.id, MAC, router.id)
    await _expire(db, first["customer_id"])

    after = {t["plan_id"]: t for t in (await get_trial_eligibility(db, router.id, MAC))["trials"]}
    assert after[once.id]["eligible"] is False
    assert after[once.id]["reason"] == TRIAL_ALREADY_USED
    assert after[repeat.id]["eligible"] is True


async def test_plan_validation_forces_free_hotspot_trials():
    from app.api.plan_routes import _validate_free_trial_plan
    from app.db.models import Plan

    _validate_free_trial_plan(Plan(plan_type=PlanType.FREE_TRIAL, price=0, connection_type=ConnectionType.HOTSPOT))
    _validate_free_trial_plan(Plan(plan_type=PlanType.REGULAR, price=50, connection_type=ConnectionType.PPPOE))

    with pytest.raises(HTTPException):
        _validate_free_trial_plan(Plan(plan_type=PlanType.FREE_TRIAL, price=20, connection_type=ConnectionType.HOTSPOT))
    with pytest.raises(HTTPException):
        _validate_free_trial_plan(Plan(plan_type=PlanType.FREE_TRIAL, price=0, connection_type=ConnectionType.PPPOE))
    # A trial may cover several devices, like any hotspot plan.
    _validate_free_trial_plan(Plan(
        plan_type=PlanType.FREE_TRIAL, price=0, connection_type=ConnectionType.HOTSPOT, max_shared_users=3,
    ))


async def test_new_plans_default_to_once_per_customer(db):
    reseller = await make_reseller(db)
    plan = await _trial_plan(db, reseller)
    assert plan.trial_once_per_customer is True


async def test_hotspot_pay_refuses_a_free_trial_plan(db):
    """The trial is claimed, never bought: an M-Pesa push for KES 0 must not start."""
    from app.api import payment_routes
    from app.services.plan_cache import FREE_TRIAL_NOT_PURCHASABLE

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    request = payment_routes.HotspotPaymentRequest(
        mac_address=MAC,
        phone="254700000000",
        plan_id=plan.id,
        router_id=router.id,
        payment_method="mobile_money",
    )
    with pytest.raises(HTTPException) as exc:
        await payment_routes.register_hotspot_and_pay_api(request, db=db)

    assert exc.value.status_code == 400
    assert exc.value.detail == FREE_TRIAL_NOT_PURCHASABLE


async def test_trial_is_provisioned_with_its_expiry_deadline(db, monkeypatch):
    """The router's own reaper removes a customer at the EXP: deadline written
    from customer_expiry, so the trial must hand the router its real expiry."""
    from app.services import voucher_service
    from app.services.free_trial import claim_free_trial

    captured = {}

    async def _capture(customer_id, router_id, payload, action, attempt_id):
        captured.update(payload=payload, action=action)
        return {"success": True}

    monkeypatch.setattr(voucher_service, "provision_hotspot_customer", _capture)

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    result = await claim_free_trial(db, plan.id, MAC, router.id)
    await asyncio.sleep(0)  # let the scheduled provisioning task run

    customer = await db.get(Customer, result["customer_id"])
    assert captured["action"] == "free_trial"
    assert captured["payload"]["customer_expiry"] == customer.expiry
    assert captured["payload"]["mac_address"] == MAC


async def test_expired_trial_is_removed_by_both_expiry_paths(db, no_background_provisioning):
    """Trials expire like any customer: the router reaper is told to remove the
    MAC, and the server cleanup job selects the row."""
    from app.services.free_trial import claim_free_trial
    from app.services.router_expiry import CustomerRow, decide

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)

    result = await claim_free_trial(db, plan.id, MAC, router.id)
    customer = await db.get(Customer, result["customer_id"])
    now = datetime.utcnow()

    row = CustomerRow(customer.id, MAC, customer.status == CustomerStatus.ACTIVE, customer.expiry)
    remove, keep, _ = decide([MAC], [row], now)
    assert remove == [] and keep and keep[0][0] == MAC  # still inside the trial

    later = customer.expiry + timedelta(seconds=1)
    remove, keep, _ = decide([MAC], [row], later)
    assert remove == [MAC] and keep == []

    # Same selection as cleanup_expired_users_background.
    customer.expiry = now - timedelta(seconds=1)
    await db.commit()
    due = (await db.execute(
        select(Customer.id).where(
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry.isnot(None),
            Customer.expiry <= datetime.utcnow(),
            Customer.mac_address.isnot(None),
        )
    )).scalars().all()
    assert due == [customer.id]


async def test_deleting_a_reseller_removes_their_trial_claims(db, monkeypatch, no_background_provisioning):
    import app.api.admin_reseller_routes as admin_resellers
    from app.db.models import User, UserRole
    from app.services.free_trial import claim_free_trial
    from tests.test_admin_reseller_deletion import _create_radius_tables

    await _create_radius_tables(db)
    admin = await make_reseller(db, role=UserRole.ADMIN, email="admin-trial@example.com")
    reseller = await make_reseller(db, email="trial-reseller@example.com")
    router = await make_router(db, reseller)
    plan = await _trial_plan(db, reseller)
    assert (await claim_free_trial(db, plan.id, MAC, router.id))["success"]

    async def _fake_current_user(token, session):
        return admin

    async def _no_vpn_cleanup(value):
        return None

    monkeypatch.setattr(admin_resellers, "get_current_user", _fake_current_user)
    monkeypatch.setattr(admin_resellers, "remove_wireguard_peer", _no_vpn_cleanup)
    monkeypatch.setattr(admin_resellers, "remove_l2tp_peer", _no_vpn_cleanup)

    await admin_resellers.delete_reseller(reseller.id, True, db, "token")

    assert await db.get(User, reseller.id) is None
    assert await db.scalar(select(func.count(FreeTrialClaim.id))) == 0

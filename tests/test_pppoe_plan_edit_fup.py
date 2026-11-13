"""A dashboard edit of a PPPoE customer must not quietly undo a FUP throttle or block.

Editing the plan, password, username or router re-provisions the secret, which
puts it on the plan's normal profile. These tests run the real edit route, the
real provisioning and FUP router functions and the real retry worker against a
fake router that remembers its secrets, so they check where the secret ends up
and how many times the customer was reconnected, not which function was called.
"""

import asyncio
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.api import customer_routes
from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    CustomerUsagePeriod,
    FupAction,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningState,
)
from app.services import fup, pppoe_provisioning, pppoe_resync
from app.services.mikrotik_api import parse_speed_to_mikrotik
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

MB = 1024 * 1024
USERNAME = "john_doe"
THROTTLE_PROFILE = "fup-1M-3M"  # plan speed 3M/1M, RouterOS form is upload/download
OLD_PLAN_PROFILE = "pppoe_5M_5M"
NEW_PLAN_PROFILE = "pppoe_20M_20M"


class RouterBox:
    """What one router holds, shared by every connection the code opens to it."""

    def __init__(self):
        self.secrets = {}
        self.kicks = []
        self.down = False
        # Commands left before the router stops answering, for a drop mid-edit.
        self.commands_until_down = None


def fake_api_for(boxes):
    class FakeMikroTikAPI:
        def __init__(self, ip, *_args, **_kwargs):
            self.box = boxes[ip]

        def connect(self):
            return not self.box.down

        def disconnect(self):
            pass

        def _tick(self):
            if self.box.commands_until_down is not None:
                if self.box.commands_until_down == 0:
                    self.box.down = True
                self.box.commands_until_down -= 1

        def add_pppoe_secret(self, username, password, profile, service="pppoe", comment=""):
            # Like RouterOS: updating an existing secret leaves `disabled` alone.
            secret = self.box.secrets.setdefault(username, {"disabled": False})
            secret.update(password=password, profile=profile)
            self._tick()
            return {"success": True}

        def remove_pppoe_secret(self, username):
            self.box.secrets.pop(username, None)
            return {"success": True}

        def ensure_pppoe_fasttrack_bypass(self, **_kwargs):
            return {"success": True}

        def ensure_pppoe_profile(self, *_args, **_kwargs):
            if self.box.down:
                return {"error": "connect_failed"}
            return {"success": True}

        def disconnect_pppoe_session(self, username):
            self.box.kicks.append(username)
            return {"success": True}

        def send_command(self, command, args=None):
            assert command == "/ppp/secret/set", command
            secret = self.box.secrets[args["numbers"]]
            if "profile" in args:
                secret["profile"] = args["profile"]
            if "disabled" in args:
                secret["disabled"] = args["disabled"] == "yes"
            return {"success": True}

    return FakeMikroTikAPI


@pytest.fixture
def boxes(monkeypatch):
    """Router IP -> RouterBox. RouterOS is never reached."""
    routers = {}

    def fake_ensure_plan_profile(api, bandwidth_limit, max_devices=1):
        if api.box.down:
            return {"error": "connect_failed"}
        rate = parse_speed_to_mikrotik(bandwidth_limit)
        return {
            "profile": f"pppoe_{rate.replace('/', '_')}",
            "base_rate_limit": rate,
            "rate_limit": rate,
            "headroom_factor": 1.0,
            "pool_name": "pool",
            "profile_result": {"success": True},
        }

    fake_api = fake_api_for(routers)
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", fake_api)
    monkeypatch.setattr(fup, "MikroTikAPI", fake_api)
    monkeypatch.setattr(pppoe_provisioning, "ensure_plan_pppoe_profile", fake_ensure_plan_profile)
    return routers


@pytest.fixture
def background_tasks(monkeypatch):
    """Lets a test wait for what the route starts in the background."""
    tasks = []
    real_create_task = asyncio.create_task

    def tracking_create_task(coro, *args, **kwargs):
        task = real_create_task(coro, *args, **kwargs)
        tasks.append(task)
        return task

    monkeypatch.setattr(asyncio, "create_task", tracking_create_task)

    async def drain():
        while tasks:
            await asyncio.gather(*tasks)
            tasks[:] = [task for task in tasks if not task.done()]

    return drain


async def _setup(
    db,
    boxes,
    *,
    new_cap=100,
    new_action=FupAction.THROTTLE,
    restriction=FupAction.THROTTLE,
    used_mb=150,
):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    box = RouterBox()
    boxes[router.ip_address] = box
    plan = await make_plan(
        db, reseller, speed="5M/5M", connection_type=ConnectionType.PPPOE, data_cap_mb=100,
        fup_action=restriction or FupAction.THROTTLE, fup_throttle_profile="3M/1M",
    )
    other_plan = await make_plan(
        db, reseller, name="Other", speed="20M/20M", connection_type=ConnectionType.PPPOE,
        data_cap_mb=new_cap, fup_action=new_action, fup_throttle_profile="3M/1M",
    )
    customer = await make_customer(
        db, reseller, plan, router, pppoe_username=USERNAME, pppoe_password="old-pass",
        status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=30),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(hours=1),
        period_end=now + timedelta(days=30),
        download_bytes=used_mb * MB,
        total_bytes=used_mb * MB,
        cap_mb_snapshot=100,
        fup_action_snapshot=restriction or FupAction.THROTTLE,
        fup_triggered_at=(now - timedelta(minutes=5)) if restriction else None,
        fup_action_taken=restriction,
    )
    db.add(period)
    await db.commit()
    box.secrets[USERNAME] = {
        "password": "old-pass",
        "profile": THROTTLE_PROFILE if restriction == FupAction.THROTTLE else OLD_PLAN_PROFILE,
        "disabled": restriction == FupAction.BLOCK,
    }
    return reseller, customer, other_plan, period.id, box


async def _edit(db, reseller, customer, **fields):
    return await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(**fields),
        db,
        {"user_id": reseller.id, "role": reseller.role.value},
    )


async def _period(db, period_id):
    return (
        await db.execute(
            select(CustomerUsagePeriod)
            .where(CustomerUsagePeriod.id == period_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.mark.parametrize(
    "new_cap",
    [
        pytest.param(100, id="same_cap"),
        pytest.param(50, id="smaller_cap"),
        pytest.param(120, id="bigger_cap_still_under_the_usage"),
    ],
)
async def test_plan_edit_keeps_a_throttle_the_new_cap_still_justifies(
    db, boxes, background_tasks, new_cap,
):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes, new_cap=new_cap)

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == [USERNAME]
    period = await _period(db, period_id)
    assert period.fup_triggered_at is not None
    assert period.fup_reverted_at is None
    assert period.fup_action_taken == FupAction.THROTTLE


@pytest.mark.parametrize(
    "new_cap",
    [
        pytest.param(1000, id="bigger_cap_above_the_usage"),
        pytest.param(None, id="no_cap"),
    ],
)
async def test_plan_edit_lifts_a_throttle_the_new_cap_no_longer_justifies_with_one_reconnect(
    db, boxes, background_tasks, new_cap,
):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes, new_cap=new_cap)

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    assert box.secrets[USERNAME]["disabled"] is False
    assert box.kicks == [USERNAME]
    period = await _period(db, period_id)
    assert period.fup_triggered_at is None
    assert period.fup_reverted_at is not None


async def test_plan_edit_keeps_a_block_the_new_cap_still_justifies(db, boxes, background_tasks):
    reseller, customer, other_plan, period_id, box = await _setup(
        db, boxes, new_cap=120, new_action=FupAction.BLOCK, restriction=FupAction.BLOCK,
    )

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["disabled"] is True
    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    period = await _period(db, period_id)
    assert period.fup_triggered_at is not None
    assert period.fup_action_taken == FupAction.BLOCK


async def test_plan_edit_lifts_a_block_the_new_cap_no_longer_justifies(db, boxes, background_tasks):
    reseller, customer, other_plan, period_id, box = await _setup(
        db, boxes, new_cap=1000, new_action=FupAction.BLOCK, restriction=FupAction.BLOCK,
    )

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["disabled"] is False
    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    assert box.kicks == [USERNAME]
    assert (await _period(db, period_id)).fup_triggered_at is None


async def test_plan_edit_to_a_plan_that_only_notifies_gives_full_speed(db, boxes, background_tasks):
    # The new plan's own rule for going over its cap is "tell them", so holding
    # them down would apply a rule neither plan has any more.
    reseller, customer, other_plan, period_id, box = await _setup(
        db, boxes, new_cap=120, new_action=FupAction.NOTIFY_ONLY,
    )

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    assert box.kicks == [USERNAME]
    assert await pppoe_provisioning.active_fup_restriction(db, customer.id) is None


@pytest.mark.parametrize(
    "new_cap",
    [
        pytest.param(100, id="same_cap"),
        pytest.param(1000, id="bigger_cap"),
    ],
)
async def test_plan_edit_for_a_customer_who_is_not_throttled_is_unchanged(
    db, boxes, background_tasks, new_cap,
):
    reseller, customer, other_plan, period_id, box = await _setup(
        db, boxes, new_cap=new_cap, restriction=None, used_mb=10,
    )

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    assert box.secrets[USERNAME]["disabled"] is False
    assert box.kicks == [USERNAME]
    period = await _period(db, period_id)
    assert period.fup_triggered_at is None
    assert period.fup_reverted_at is None


async def test_password_change_keeps_the_throttle(db, boxes, background_tasks):
    reseller, customer, _other, period_id, box = await _setup(db, boxes)

    await _edit(db, reseller, customer, pppoe_password="new-pass")
    await background_tasks()

    assert box.secrets[USERNAME]["password"] == "new-pass"
    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == [USERNAME]
    assert (await _period(db, period_id)).fup_triggered_at is not None


async def test_username_change_keeps_the_throttle_on_the_new_secret(db, boxes, background_tasks):
    reseller, customer, _other, _period_id, box = await _setup(db, boxes)

    await _edit(db, reseller, customer, pppoe_username="john_new")
    await background_tasks()

    assert USERNAME not in box.secrets
    assert box.secrets["john_new"]["profile"] == THROTTLE_PROFILE


async def test_username_change_keeps_a_block_on_the_new_secret(db, boxes, background_tasks):
    # A new secret starts enabled, so this block really would be lost.
    reseller, customer, _other, _period_id, box = await _setup(
        db, boxes, restriction=FupAction.BLOCK,
    )

    await _edit(db, reseller, customer, pppoe_username="john_new")
    await background_tasks()

    assert box.secrets["john_new"]["disabled"] is True


async def test_resave_with_nothing_changed_leaves_a_throttled_customer_alone(
    db, boxes, background_tasks,
):
    reseller, customer, _other, period_id, box = await _setup(db, boxes)

    await _edit(db, reseller, customer, name="Renamed")
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == []
    assert (await _period(db, period_id)).fup_triggered_at is not None


async def _add_payment(db, reseller, customer, plan):
    db.add(CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        plan_id=plan.id,
        amount=100.0,
        payment_method=PaymentMethod.OTHER,
        payment_reference=f"TEST-{customer.id}",
        days_paid_for=30,
        status=PaymentStatus.COMPLETED,
        customer_name=customer.name,
    ))
    await db.commit()


async def _make_attempt_due(db, customer_id):
    attempt = (
        await db.execute(
            select(ProvisioningAttempt)
            .where(ProvisioningAttempt.customer_id == customer_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert attempt.provisioning_state == ProvisioningState.RETRY_PENDING
    attempt.last_attempt_at = datetime.utcnow() - timedelta(hours=1)
    await db.commit()


async def test_retry_after_a_failed_push_keeps_the_throttle(db, boxes, background_tasks):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes)
    await _add_payment(db, reseller, customer, other_plan)
    box.down = True

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == []

    box.down = False
    await _make_attempt_due(db, customer.id)
    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == [USERNAME]
    assert (await _period(db, period_id)).fup_triggered_at is not None


async def test_retry_after_a_failed_push_lifts_once_when_the_new_cap_allows(
    db, boxes, background_tasks,
):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes, new_cap=1000)
    await _add_payment(db, reseller, customer, other_plan)
    box.down = True

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    box.down = False
    await _make_attempt_due(db, customer.id)
    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    assert box.kicks == [USERNAME]
    assert (await _period(db, period_id)).fup_triggered_at is None


async def test_router_lost_after_the_write_rearms_the_cap_so_the_next_check_throttles(
    db, boxes, background_tasks,
):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes)
    box.commands_until_down = 0  # answers the secret write, then drops

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    # The write landed but the throttle didn't. With the trigger left recorded
    # nothing would ever throttle them again this period.
    assert box.secrets[USERNAME]["profile"] == NEW_PLAN_PROFILE
    period = await _period(db, period_id)
    assert period.fup_triggered_at is None

    box.down = False
    box.commands_until_down = None
    await db.refresh(customer, attribute_names=["plan"])
    action = await fup.evaluate_and_enforce(db, customer, period, plan=customer.plan)
    await db.commit()

    assert action == FupAction.THROTTLE
    assert box.secrets[USERNAME]["profile"] == THROTTLE_PROFILE
    assert box.kicks == [USERNAME]


async def test_router_lost_before_a_lift_finishes_is_retried_by_the_next_check(
    db, boxes, background_tasks,
):
    reseller, customer, other_plan, period_id, box = await _setup(db, boxes, new_cap=1000)
    box.commands_until_down = 0

    await _edit(db, reseller, customer, plan_id=other_plan.id)
    await background_tasks()

    period = await _period(db, period_id)
    assert period.fup_triggered_at is not None

    box.down = False
    box.commands_until_down = None
    await db.refresh(customer, attribute_names=["plan"])
    await fup.evaluate_and_enforce(db, customer, period, plan=customer.plan)
    await db.commit()

    assert (await _period(db, period_id)).fup_triggered_at is None
    assert box.kicks == [USERNAME]


async def test_resume_path_still_does_its_own_rethrottle(db, boxes, background_tasks):
    # Resume calls the push without asking it to settle the hold. It must not
    # start throttling inside the push, or resume would reconnect people twice.
    _reseller, customer, _other, _period_id, box = await _setup(db, boxes)

    await pppoe_resync.push_active_pppoe_customer(customer.id, action="pppoe_resume")

    assert box.secrets[USERNAME]["profile"] == OLD_PLAN_PROFILE
    assert box.kicks == [USERNAME]

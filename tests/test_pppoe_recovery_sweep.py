"""Router offline -> online: re-add missing PPPoE secrets, remove orphans.

Writes made while a router is down are lost: the paid-delivery retry gives up
after 4 h, and a customer deleted or moved while it was down leaves their old
secret on it. When the router comes back, one bounded sweep repairs both.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    ConnectionType,
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    PaymentStatus,
    ProvisioningAttempt,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningOnlineState,
    ProvisioningState,
)
from app.services import pppoe_provisioning, pppoe_resync, router_availability
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


class FakeRouter:
    """Stands in for RouterOS: a secret list plus a record of what was done."""

    def __init__(self, secrets):
        self.secrets = list(secrets)
        self.removed = []
        self.provisioned = []

    async def router_io(self, router_info, func, *args):
        if func is pppoe_resync._list_pppoe_secrets_sync:
            return {"success": True, "secrets": list(self.secrets)}
        if func is pppoe_resync._remove_pppoe_secrets_sync:
            (usernames,) = args
            self.removed.extend(usernames)
            self.secrets = [s for s in self.secrets if s["name"] not in usernames]
            return {"success": True, "removed": list(usernames), "failed": []}
        raise AssertionError(f"unexpected router call {func}")

    async def provision(self, payload):
        self.provisioned.append(payload)
        return {"success": True, "profile": "pppoe_5M_5M"}


def _install(monkeypatch, fake):
    monkeypatch.setattr(pppoe_resync, "_router_io", fake.router_io)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake.provision)


async def _setup(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller, ip_address="192.0.2.20")
    other_router = await make_router(db, reseller, ip_address="192.0.2.21")
    future = datetime.utcnow() + timedelta(days=10)

    async def customer(username, *, status=CustomerStatus.ACTIVE, expiry=future, on=router):
        return await make_customer(
            db, reseller, plan, on, status=status, expiry=expiry, mac_address=None,
            pppoe_username=username, pppoe_password=f"pw-{username}", name=username,
        )

    return reseller, plan, router, other_router, customer


def _secret(name, cid=None):
    return {"name": name, "comment": f"CID:{cid}|{name}|2026-10-01" if cid else "", "disabled": "false"}


async def test_sweep_adds_missing_and_removes_orphans(db, monkeypatch):
    reseller, plan, router, other_router, customer = await _setup(db)
    missing = await customer("alice")                       # active, secret lost
    present = await customer("bob")                         # active, secret fine
    inactive = await customer("carol", status=CustomerStatus.INACTIVE)
    expired = await customer("dave", expiry=datetime.utcnow() - timedelta(hours=1))
    moved = await customer("erin", on=other_router)          # moved away while down
    fake = FakeRouter([
        _secret("bob", present.id),
        _secret("erin", moved.id),
        _secret("ghost", 999999),                            # customer deleted
        _secret("frank_manual"),                             # reseller's own, untagged
        _secret("carol", inactive.id),                       # left to the inactive safety net
    ])
    _install(monkeypatch, fake)

    summary = await pppoe_resync.sweep_router_pppoe(router.id)

    assert summary["status"] == "done"
    assert [p["pppoe_username"] for p in fake.provisioned] == ["alice"]
    assert fake.provisioned[0]["disconnect"] is False
    assert sorted(fake.removed) == ["erin", "ghost"]
    assert summary["provisioned"] == 1 and summary["removed"] == 2
    assert {s["name"] for s in fake.secrets} == {"bob", "frank_manual", "carol"}

    # The missing customer had no payment row: pushed without an attempt.
    assert (await db.execute(select(ProvisioningAttempt))).scalars().all() == []

    logs = (await db.execute(
        select(ProvisioningLog).where(ProvisioningLog.action == "pppoe_orphan_removed")
    )).scalars().all()
    by_detail = {log.details: log for log in logs}
    assert len(logs) == 2
    ghost_log = next(log for d, log in by_detail.items() if "'ghost'" in d)
    erin_log = next(log for d, log in by_detail.items() if "'erin'" in d)
    assert ghost_log.customer_id is None and "deleted" in ghost_log.details
    assert erin_log.customer_id == moved.id and "moved" in erin_log.details
    assert expired.id and missing.id  # silence unused


async def test_sweep_uses_attempt_path_and_never_double_provisions(db, monkeypatch):
    reseller, plan, router, _, customer = await _setup(db)
    lost = await customer("lost")
    pending = await customer("pending")

    def pay(c):
        p = CustomerPayment(
            customer_id=c.id, reseller_id=reseller.id, amount=500,
            payment_method=PaymentMethod.CASH, days_paid_for=30,
            status=PaymentStatus.COMPLETED, customer_name=c.name,
        )
        db.add(p)
        return p

    lost_payment, pending_payment = pay(lost), pay(pending)
    await db.flush()
    long_ago = datetime.utcnow() - timedelta(hours=6)
    # "lost": its delivery gave up during a 6 h outage.
    db.add(ProvisioningAttempt(
        customer_id=lost.id, router_id=router.id, mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT, source_pk=lost_payment.id,
        entrypoint="manual_transaction_provision",
        provisioning_state=ProvisioningState.FAILED, online_state=ProvisioningOnlineState.UNKNOWN,
        attempt_count=14, last_error="Failed to connect to router",
        last_attempt_at=long_ago, created_at=long_ago, updated_at=long_ago,
    ))
    # "pending": the retry worker still owns a live attempt for it.
    db.add(ProvisioningAttempt(
        customer_id=pending.id, router_id=router.id, mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT, source_pk=pending_payment.id,
        entrypoint="manual_transaction_provision",
        provisioning_state=ProvisioningState.RETRY_PENDING, online_state=ProvisioningOnlineState.UNKNOWN,
        attempt_count=2, last_attempt_at=datetime.utcnow(),
        created_at=datetime.utcnow() - timedelta(minutes=10), updated_at=datetime.utcnow(),
    ))
    await db.commit()
    fake = FakeRouter([])
    _install(monkeypatch, fake)

    summary = await pppoe_resync.sweep_router_pppoe(router.id)

    assert [p["pppoe_username"] for p in fake.provisioned] == ["lost"]
    assert summary["skipped"] == 1
    lost_attempt = (await db.execute(
        select(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == lost.id)
    )).scalar_one()
    await db.refresh(lost_attempt)
    assert lost_attempt.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert lost_attempt.attempt_count == 1  # re-armed, not stacked on the old 14

    # A second sweep right after finds nothing to do.
    fake.secrets = [_secret("lost", lost.id), _secret("pending", pending.id)]
    fake.provisioned.clear()
    again = await pppoe_resync.sweep_router_pppoe(router.id)
    assert fake.provisioned == [] and again["provisioned"] == 0


async def test_sweep_holds_removals_when_orphans_outnumber_own_secrets(db, monkeypatch):
    # e.g. two router rows that reach the same box: never mass-delete.
    reseller, plan, router, other_router, customer = await _setup(db)
    await customer("mine")
    strangers = [await customer(f"other{n}", on=other_router) for n in range(5)]
    fake = FakeRouter([_secret("mine", None)] + [_secret(c.pppoe_username, c.id) for c in strangers])
    _install(monkeypatch, fake)

    summary = await pppoe_resync.sweep_router_pppoe(router.id)

    assert fake.removed == []
    assert summary["orphans_held"] == 5


async def test_sweep_skips_router_without_pppoe_customers(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="192.0.2.30")

    async def no_io(*_a, **_k):
        raise AssertionError("no router I/O expected")

    monkeypatch.setattr(pppoe_resync, "_router_io", no_io)
    summary = await pppoe_resync.sweep_router_pppoe(router.id)
    assert summary["status"] == "no_pppoe_customers"


async def test_sweep_reports_unreachable_router_without_changes(db, monkeypatch):
    _, _, router, _, customer = await _setup(db)
    await customer("alice")

    async def unreachable(router_info, func, *args):
        return {"error": "Failed to connect to router"}

    monkeypatch.setattr(pppoe_resync, "_router_io", unreachable)
    summary = await pppoe_resync.sweep_router_pppoe(router.id)
    assert summary["status"] == "router_unreachable"


# ---------------------------------------------------------------------------
# Trigger: the offline -> online flip in record_router_availability
# ---------------------------------------------------------------------------


async def test_offline_to_online_flip_schedules_one_sweep(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="192.0.2.40")
    router.last_status = False
    router.last_checked_at = datetime.utcnow() - timedelta(hours=5)
    await db.commit()
    scheduled = []
    monkeypatch.setattr(
        pppoe_resync, "schedule_pppoe_recovery_sweep",
        lambda router_id, now=None: scheduled.append(router_id) or True,
    )

    await router_availability.record_router_availability(db, router.id, True, "health_check")
    await router_availability.record_router_availability(db, router.id, True, "health_check")

    assert scheduled == [router.id]  # only the flip, not every online sample


async def test_online_router_staying_online_schedules_nothing(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, ip_address="192.0.2.41")
    router.last_status = True
    router.last_checked_at = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()
    scheduled = []
    monkeypatch.setattr(
        pppoe_resync, "schedule_pppoe_recovery_sweep",
        lambda router_id, now=None: scheduled.append(router_id) or True,
    )

    await router_availability.record_router_availability(db, router.id, True, "health_check")
    assert scheduled == []


async def test_schedule_dedupes_per_router_with_cooldown(monkeypatch):
    monkeypatch.setattr(pppoe_resync.settings, "PPPOE_RECOVERY_SWEEP_ENABLED", True)
    monkeypatch.setattr(pppoe_resync, "_sweeps_in_flight", set())
    monkeypatch.setattr(pppoe_resync, "_sweep_last_started", {})
    ran = []

    async def fake_run(router_id):
        ran.append(router_id)
        pppoe_resync._sweeps_in_flight.discard(router_id)

    monkeypatch.setattr(pppoe_resync, "_run_recovery_sweep", fake_run)
    now = datetime.utcnow()

    assert pppoe_resync.schedule_pppoe_recovery_sweep(7, now=now) is True
    assert pppoe_resync.schedule_pppoe_recovery_sweep(7, now=now + timedelta(minutes=1)) is False
    assert pppoe_resync.schedule_pppoe_recovery_sweep(8, now=now) is True
    for task in list(pppoe_resync._sweep_tasks):
        await task
    assert sorted(ran) == [7, 8]
    assert pppoe_resync.schedule_pppoe_recovery_sweep(
        7, now=now + pppoe_resync.RECOVERY_SWEEP_COOLDOWN + timedelta(seconds=1),
    ) is True
    for task in list(pppoe_resync._sweep_tasks):
        await task


async def test_schedule_is_off_when_disabled(monkeypatch):
    monkeypatch.setattr(pppoe_resync.settings, "PPPOE_RECOVERY_SWEEP_ENABLED", False)
    assert pppoe_resync.schedule_pppoe_recovery_sweep(9) is False

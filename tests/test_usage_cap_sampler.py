from collections import deque
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    CustomerStatus,
    CustomerUsagePeriod,
    FupAction,
    RouterAuthMethod,
    UsageCapWatchState,
)
from app.services import usage_cap_sampler
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _queue_for(mac: str, bytes_value: str) -> dict:
    compact = mac.replace(":", "")
    return {
        ".id": f"*{compact[-2:]}",
        "name": f"plan_{compact}",
        "comment": f"MAC:{mac}|Plan rate limit",
        "bytes": bytes_value,
        "target": "192.168.88.10/32",
        "max-limit": "10M/10M",
        "disabled": "false",
    }


@pytest.mark.asyncio
async def test_cap_sampler_updates_usage_period_with_one_router_poll_per_run(
    db,
    session_factory,
    monkeypatch,
):
    monkeypatch.setattr(usage_cap_sampler, "async_session", session_factory)
    monkeypatch.setattr(usage_cap_sampler, "cap_sampler_running", False)
    monkeypatch.setattr(usage_cap_sampler, "_db_pool_is_busy", lambda: False)

    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        auth_method=RouterAuthMethod.DIRECT_API,
    )
    plan = await make_plan(
        db,
        reseller,
        data_cap_mb=500,
        fup_action=FupAction.THROTTLE,
        fup_throttle_profile="512K/512K",
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address="AA:BB:CC:DD:EE:10",
        phone="254700000010",
    )
    other_customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address="AA:BB:CC:DD:EE:11",
        phone="254700000011",
    )

    mib = 1024 * 1024
    payloads = deque(
        [
            [
                _queue_for(customer.mac_address, f"0/{5 * mib}"),
                _queue_for(other_customer.mac_address, f"0/{10 * mib}"),
            ],
            [
                _queue_for(customer.mac_address, f"0/{600 * mib}"),
                _queue_for(other_customer.mac_address, f"0/{20 * mib}"),
            ],
        ]
    )
    fetch_calls = []

    def fake_fetch(router_info):
        fetch_calls.append(router_info["id"])
        return {"success": True, "data": payloads.popleft()}

    async def fake_enforce(db_session, customer_obj, period, plan=None, now=None):
        period.fup_triggered_at = now or datetime.utcnow()
        period.fup_action_taken = FupAction.THROTTLE
        return FupAction.THROTTLE

    monkeypatch.setattr(usage_cap_sampler, "_fetch_queue_usage_for_router_sync", fake_fetch)
    monkeypatch.setattr(usage_cap_sampler, "evaluate_and_enforce", fake_enforce)

    await usage_cap_sampler.sample_capped_usage_background()

    async with session_factory() as s:
        states = (await s.execute(select(UsageCapWatchState))).scalars().all()
        assert len(states) == 2
        for state in states:
            state.next_poll_at = datetime.utcnow() - timedelta(seconds=1)
        await s.commit()

    await usage_cap_sampler.sample_capped_usage_background()

    async with session_factory() as s:
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one()
        other_period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == other_customer.id
                )
            )
        ).scalar_one()
        state = (
            await s.execute(
                select(UsageCapWatchState).where(
                    UsageCapWatchState.customer_id == customer.id
                )
            )
        ).scalar_one()

    assert fetch_calls == [router.id, router.id]
    assert period.total_bytes == 595 * mib
    assert period.fup_triggered_at is not None
    assert period.fup_action_taken == FupAction.THROTTLE
    assert other_period.total_bytes == 10 * mib
    assert state.poll_tier == "over_cap"


@pytest.mark.asyncio
async def test_cap_sampler_backs_off_router_errors(
    db,
    session_factory,
    monkeypatch,
):
    monkeypatch.setattr(usage_cap_sampler, "async_session", session_factory)
    monkeypatch.setattr(usage_cap_sampler, "cap_sampler_running", False)
    monkeypatch.setattr(usage_cap_sampler, "_db_pool_is_busy", lambda: False)

    reseller = await make_reseller(db)
    router = await make_router(
        db,
        reseller,
        auth_method=RouterAuthMethod.DIRECT_API,
    )
    plan = await make_plan(db, reseller, data_cap_mb=1000)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address="AA:BB:CC:DD:EE:22",
    )

    monkeypatch.setattr(
        usage_cap_sampler,
        "_fetch_queue_usage_for_router_sync",
        lambda _router_info: {"error": "connect_failed"},
    )

    await usage_cap_sampler.sample_capped_usage_background()

    async with session_factory() as s:
        state = (
            await s.execute(
                select(UsageCapWatchState).where(
                    UsageCapWatchState.customer_id == customer.id
                )
            )
        ).scalar_one()
        period = (
            await s.execute(
                select(CustomerUsagePeriod).where(
                    CustomerUsagePeriod.customer_id == customer.id
                )
            )
        ).scalar_one_or_none()

    assert state.poll_tier == "backoff"
    assert state.consecutive_errors == 1
    assert state.backoff_until is not None
    assert state.last_error == "connect_failed"
    assert period is None

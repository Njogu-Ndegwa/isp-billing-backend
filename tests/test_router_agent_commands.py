from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    AppSetting,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    RouterCommand,
)
from app.services import router_agent_commands as commands
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _enabled_hotspot(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=1)
    router = await make_router(
        db,
        reseller,
        identity="Router-Agent-Test",
        router_agent_enabled=True,
    )
    db.add(AppSetting(key="router_agent_enabled", value="true"))
    await db.commit()
    return reseller, plan, router


def _payload(customer, router, *, lb_enabled=False):
    username = customer.mac_address.replace(":", "")
    return {
        "mac_address": customer.mac_address,
        "username": username,
        "password": username,
        "time_limit": "1h",
        "bandwidth_limit": "5M/5M",
        "comment": f"CID:{customer.id}",
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
        "lb_enabled": lb_enabled,
    }


@pytest.mark.asyncio
async def test_direct_push_terminal_state_wins_over_late_failed_ack(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert command_id is not None
    await commands.complete_command_from_push(command_id)
    command, found = await commands.acknowledge_command(
        router_id=router.id,
        command_id=command_id,
        applied=False,
        error="late fetch failure",
    )
    assert found is True
    assert command.state == "applied"
    assert command.acknowledgement_source == "direct_push"


@pytest.mark.asyncio
async def test_renewal_cancels_removal_before_delivery(db, session_factory, monkeypatch):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=1),
    )
    command_id = await commands.queue_hotspot_remove_command(
        router_id=router.id,
        customer_id=customer.id,
        mac_address=customer.mac_address,
        username=customer.mac_address.replace(":", ""),
    )
    customer.expiry = datetime.utcnow() + timedelta(hours=1)
    await db.commit()

    assert await commands.next_command_for_router(router.id) is None
    await db.refresh(await db.get(RouterCommand, command_id))
    command = await db.get(RouterCommand, command_id)
    assert command.state == "cancelled"


@pytest.mark.asyncio
async def test_each_expiry_generation_gets_a_new_removal(db, session_factory, monkeypatch):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=2),
    )
    first = await commands.queue_hotspot_remove_command(
        router_id=router.id,
        customer_id=customer.id,
        mac_address=customer.mac_address,
        username=customer.mac_address.replace(":", ""),
    )
    customer.expiry = datetime.utcnow() - timedelta(minutes=1)
    await db.commit()
    second = await commands.queue_hotspot_remove_command(
        router_id=router.id,
        customer_id=customer.id,
        mac_address=customer.mac_address,
        username=customer.mac_address.replace(":", ""),
    )
    assert first != second


@pytest.mark.asyncio
async def test_removal_ack_after_renewal_queues_repair(db, session_factory, monkeypatch):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=1),
    )
    remove_id = await commands.queue_hotspot_remove_command(
        router_id=router.id,
        customer_id=customer.id,
        mac_address=customer.mac_address,
        username=customer.mac_address.replace(":", ""),
    )
    delivered = await commands.next_command_for_router(router.id)
    assert delivered.id == remove_id

    customer.expiry = datetime.utcnow() + timedelta(hours=2)
    customer.status = CustomerStatus.ACTIVE
    await db.commit()
    command, found = await commands.acknowledge_command(
        router_id=router.id,
        command_id=remove_id,
        applied=True,
    )
    assert found and command.state == "applied"
    repairs = (
        await db.execute(
            select(RouterCommand).where(
                RouterCommand.command_type == "hotspot_provision",
                RouterCommand.idempotency_key.like("repair-after-remove:%"),
            )
        )
    ).scalars().all()
    assert len(repairs) == 1
    assert repairs[0].state == "pending"


@pytest.mark.asyncio
async def test_stale_grant_ack_queues_verified_cleanup(db, session_factory, monkeypatch):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    grant_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert (await commands.next_command_for_router(router.id)).id == grant_id
    customer.status = CustomerStatus.INACTIVE
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    command, found = await commands.acknowledge_command(
        router_id=router.id,
        command_id=grant_id,
        applied=True,
    )
    assert found and "cleanup queued" in command.last_error
    cleanup = (
        await db.execute(
            select(RouterCommand).where(
                RouterCommand.idempotency_key == f"cleanup-after-stale-grant:{grant_id}"
            )
        )
    ).scalar_one()
    assert cleanup.command_type == "hotspot_remove"
    assert "binding remains" in cleanup.action_script


@pytest.mark.asyncio
async def test_active_but_expired_customer_never_receives_queued_grant(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    assert await commands.next_command_for_router(router.id) is None
    command = await db.get(RouterCommand, command_id)
    await db.refresh(command)
    assert command.state == "cancelled"
    assert "ended" in command.last_error


@pytest.mark.asyncio
async def test_provision_command_expiry_is_capped_to_paid_entitlement(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    paid_expiry = datetime.utcnow() + timedelta(minutes=20)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=paid_expiry,
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )

    command = await db.get(RouterCommand, command_id)
    assert command.expires_at == paid_expiry


@pytest.mark.asyncio
async def test_expired_customer_after_delivery_queues_precautionary_cleanup(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert (await commands.next_command_for_router(router.id)).id == command_id
    command = await db.get(RouterCommand, command_id)
    command.available_at = datetime.utcnow() - timedelta(seconds=1)
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    assert await commands.next_command_for_router(router.id) is None
    await db.refresh(command)
    assert command.state == "cancelled"
    cleanup = (
        await db.execute(
            select(RouterCommand).where(
                RouterCommand.idempotency_key == f"cleanup-after-stale-grant:{command_id}"
            )
        )
    ).scalar_one()
    assert cleanup.command_type == "hotspot_remove"


@pytest.mark.asyncio
async def test_expired_delivered_command_keeps_live_customer_connected(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert (await commands.next_command_for_router(router.id)).id == command_id
    command = await db.get(RouterCommand, command_id)
    command.expires_at = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    assert await commands.expire_active_commands() == 1
    await db.refresh(command)
    assert command.state == "expired"
    assert "entitlement remains active" in command.last_error
    cleanup = (
        await db.execute(
            select(RouterCommand).where(
                RouterCommand.idempotency_key == f"cleanup-after-stale-grant:{command_id}"
            )
        )
    ).scalar_one_or_none()
    assert cleanup is None


@pytest.mark.asyncio
async def test_expired_delivered_command_cleans_up_ended_entitlement(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert (await commands.next_command_for_router(router.id)).id == command_id
    command = await db.get(RouterCommand, command_id)
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    command.expires_at = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    assert await commands.expire_active_commands() == 1
    await db.refresh(command)
    assert command.state == "expired"
    assert "cleanup queued" in command.last_error
    cleanup = (
        await db.execute(
            select(RouterCommand).where(
                RouterCommand.idempotency_key == f"cleanup-after-stale-grant:{command_id}"
            )
        )
    ).scalar_one()
    assert cleanup.command_type == "hotspot_remove"


@pytest.mark.asyncio
async def test_expired_delivered_command_flags_unrenderable_stale_cleanup(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
    )
    command_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        hotspot_payload=_payload(customer, router),
    )
    assert (await commands.next_command_for_router(router.id)).id == command_id
    command = await db.get(RouterCommand, command_id)
    command.metadata_json = {}
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    command.expires_at = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()

    assert await commands.expire_active_commands() == 1
    await db.refresh(command)
    assert command.state == "expired"
    assert command.last_error.startswith("CRITICAL:")


@pytest.mark.asyncio
async def test_delayed_agent_ack_aligns_paid_time_usage_and_sharing(
    db, session_factory, monkeypatch
):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    original_expiry = datetime.utcnow() + timedelta(hours=1)
    owner = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=original_expiry,
    )
    companion = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=original_expiry,
        subscription_owner_id=owner.id,
    )
    period = CustomerUsagePeriod(
        customer_id=owner.id,
        period_start=datetime.utcnow(),
        period_end=original_expiry,
    )
    pairing = DevicePairing(
        customer_id=companion.id,
        device_mac=companion.mac_address,
        router_id=router.id,
        subscription_owner_customer_id=owner.id,
        is_subscription_share=True,
        is_active=True,
        expires_at=original_expiry,
    )
    db.add_all([period, pairing])
    await db.commit()

    grant_id = await commands.queue_hotspot_provision_command(
        router_id=router.id,
        customer_id=owner.id,
        attempt_id=None,
        hotspot_payload=_payload(owner, router),
    )
    command = await db.get(RouterCommand, grant_id)
    command.metadata_json = {
        **command.metadata_json,
        "service_start": (datetime.utcnow() - timedelta(minutes=2)).isoformat(),
        "original_expiry": original_expiry.isoformat(),
    }
    await db.commit()
    assert (await commands.next_command_for_router(router.id)).id == grant_id
    await commands.acknowledge_command(
        router_id=router.id,
        command_id=grant_id,
        applied=True,
    )

    await db.refresh(owner)
    await db.refresh(companion)
    await db.refresh(period)
    await db.refresh(pairing)
    assert owner.expiry > original_expiry + timedelta(seconds=100)
    assert companion.expiry == owner.expiry
    assert period.period_end == owner.expiry
    assert pairing.expires_at == owner.expiry


@pytest.mark.asyncio
async def test_pppoe_commands_remain_separately_disabled(db, session_factory, monkeypatch):
    monkeypatch.setattr(commands, "async_session", session_factory)
    reseller, plan, router = await _enabled_hotspot(db)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=1),
        pppoe_username="paid-user",
        pppoe_password="secret",
    )
    command_id = await commands.queue_pppoe_provision_command(
        router_id=router.id,
        customer_id=customer.id,
        attempt_id=None,
        pppoe_payload={
            "pppoe_username": "paid-user",
            "pppoe_password": "secret",
            "bandwidth_limit": "5M/5M",
        },
    )
    assert command_id is None


@pytest.mark.asyncio
async def test_oversized_router_action_is_rejected_before_database_use():
    with pytest.raises(ValueError, match="safe delivery size"):
        await commands._enqueue_command(
            router_id=1,
            customer_id=None,
            attempt_id=None,
            idempotency_key="too-large",
            command_type="hotspot_provision",
            action_script="x" * (commands.MAX_ACTION_SCRIPT_BYTES + 1),
        )

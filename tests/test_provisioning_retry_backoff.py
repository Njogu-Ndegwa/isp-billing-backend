from datetime import datetime, timedelta

from app.db.models import (
    ConnectionType,
    CustomerStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
    RouterAuthMethod,
)
from app.services import hotspot_provisioning, pppoe_provisioning
from app.services.provisioning_retry_policy import (
    PAID_PROVISIONING_RETRY_MAX_ATTEMPTS,
    retry_delay_seconds,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


async def _seed_attempt(
    db,
    *,
    connection_type=ConnectionType.HOTSPOT,
    state=ProvisioningState.RETRY_PENDING,
    attempt_count=5,
    last_error="Failed to connect",
    last_attempt_at=None,
):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=connection_type)
    router = await make_router(
        db,
        reseller,
        auth_method=RouterAuthMethod.DIRECT_API,
        identity=f"Router-retry-{reseller.id}",
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(hours=2),
        mac_address=None,
        pppoe_username=("retry-user" if connection_type == ConnectionType.PPPOE else None),
        pppoe_password=("retry-password" if connection_type == ConnectionType.PPPOE else None),
    )
    attempt = ProvisioningAttempt(
        customer_id=customer.id,
        router_id=router.id,
        mac_address=(customer.mac_address if connection_type == ConnectionType.HOTSPOT else None),
        source_table=(
            ProvisioningAttemptSource.MPESA_TRANSACTION
            if connection_type == ConnectionType.HOTSPOT
            else ProvisioningAttemptSource.CUSTOMER_PAYMENT
        ),
        source_pk=100_000 + customer.id,
        entrypoint=(
            ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT
            if connection_type == ConnectionType.HOTSPOT
            else ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION
        ),
        provisioning_state=state,
        online_state=ProvisioningOnlineState.UNKNOWN,
        attempt_count=attempt_count,
        last_error=last_error,
        last_attempt_at=last_attempt_at,
        created_at=datetime.utcnow() - timedelta(minutes=20),
        updated_at=datetime.utcnow(),
    )
    db.add(attempt)
    await db.commit()
    await db.refresh(attempt)
    return attempt, customer, router


def test_shared_retry_policy_spreads_attempts_across_four_hours():
    assert PAID_PROVISIONING_RETRY_MAX_ATTEMPTS == 14
    assert [retry_delay_seconds(count) for count in range(1, 9)] == [
        60,
        120,
        180,
        300,
        480,
        780,
        1260,
        1800,
    ]
    assert retry_delay_seconds(13) == 1800


async def test_hotspot_recent_retry_is_not_replayed_before_backoff(db, monkeypatch):
    await _seed_attempt(
        db,
        attempt_count=5,
        last_attempt_at=datetime.utcnow() - timedelta(seconds=479),
    )
    groups_seen = []

    async def capture_groups(groups):
        groups_seen.append(groups)

    monkeypatch.setattr(hotspot_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(
        hotspot_provisioning,
        "_process_hotspot_retry_router_groups",
        capture_groups,
    )

    await hotspot_provisioning.retry_pending_hotspot_provisioning_background()

    assert groups_seen == []


async def test_hotspot_legacy_connectivity_failure_resumes_after_backoff(db, monkeypatch):
    attempt, _, _ = await _seed_attempt(
        db,
        state=ProvisioningState.FAILED,
        attempt_count=5,
        last_error="Failed to connect",
        last_attempt_at=datetime.utcnow() - timedelta(seconds=481),
    )
    captured_attempt_ids = []

    async def capture_groups(groups):
        captured_attempt_ids.extend(
            item[0].id for items in groups.values() for item in items
        )

    monkeypatch.setattr(hotspot_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(
        hotspot_provisioning,
        "_process_hotspot_retry_router_groups",
        capture_groups,
    )

    await hotspot_provisioning.retry_pending_hotspot_provisioning_background()

    assert captured_attempt_ids == [attempt.id]


async def test_hotspot_legacy_config_failure_stays_terminal(db, monkeypatch):
    await _seed_attempt(
        db,
        state=ProvisioningState.FAILED,
        attempt_count=5,
        last_error="invalid value for argument remote-address",
        last_attempt_at=datetime.utcnow() - timedelta(hours=1),
    )
    groups_seen = []

    async def capture_groups(groups):
        groups_seen.append(groups)

    monkeypatch.setattr(hotspot_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(
        hotspot_provisioning,
        "_process_hotspot_retry_router_groups",
        capture_groups,
    )

    await hotspot_provisioning.retry_pending_hotspot_provisioning_background()

    assert groups_seen == []


async def test_pppoe_recent_retry_is_not_replayed_before_backoff(db, monkeypatch):
    await _seed_attempt(
        db,
        connection_type=ConnectionType.PPPOE,
        attempt_count=5,
        last_attempt_at=datetime.utcnow() - timedelta(seconds=479),
    )
    calls = []

    async def fake_provision(payload):
        calls.append(payload)
        return {"success": True}

    monkeypatch.setattr(pppoe_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert calls == []


async def test_pppoe_legacy_connectivity_failure_resumes_after_backoff(db, monkeypatch):
    attempt, _, _ = await _seed_attempt(
        db,
        connection_type=ConnectionType.PPPOE,
        state=ProvisioningState.FAILED,
        attempt_count=5,
        last_error="Connection timed out",
        last_attempt_at=datetime.utcnow() - timedelta(seconds=481),
    )
    calls = []

    async def fake_provision(payload):
        calls.append(payload)
        return {"success": True, "profile": "pppoe_5M_5M", "rate_limit": "5M/5M"}

    monkeypatch.setattr(pppoe_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    await pppoe_provisioning.retry_pending_pppoe_provisioning_background()

    assert len(calls) == 1
    refreshed = await db.get(ProvisioningAttempt, attempt.id)
    await db.refresh(refreshed)
    assert refreshed.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert refreshed.attempt_count == 6


def test_attempt_five_is_no_longer_terminal_but_fourteen_is():
    now = datetime.utcnow()
    attempt = ProvisioningAttempt(
        attempt_count=5,
        created_at=now - timedelta(minutes=20),
    )
    assert hotspot_provisioning._attempt_should_be_terminal(attempt, now) is False
    assert pppoe_provisioning._attempt_should_be_terminal(attempt, now) is False

    attempt.attempt_count = PAID_PROVISIONING_RETRY_MAX_ATTEMPTS
    assert hotspot_provisioning._attempt_should_be_terminal(attempt, now) is True
    assert pppoe_provisioning._attempt_should_be_terminal(attempt, now) is True

"""One phone number, a plan per device: reconnects never steal another device's plan.

Reseller 498 case (24 Oct): a customer bought a 1-device month on her TV (fixed
vendor MAC) and 1-device plans on her phone (randomized MAC), all on one phone
number. Reconnecting from the phone used to pick the latest-expiring row (the
TV's month), revoke the TV and rewrite that row to the phone.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import inspect as sa_inspect, select

from app.api import access_code_routes, public_routes
from app.api.access_code_routes import AccessCodeRedeemRequest
from app.db.models import (
    Customer,
    CustomerStatus,
    CustomerUsageBucket,
    DevicePairing,
    MpesaTransaction,
    MpesaTransactionStatus,
    ReconnectionAttempt,
)
from app.services import device_entitlements
from app.services.code_attempt_limiter import reset_code_attempt_limiter
from app.services.device_entitlements import (
    FIXED_DEVICE_RECENT_WINDOW,
    PLAN_IN_USE_ERROR,
    classify_device_use,
    is_randomized_mac,
    probe_online_macs_sync,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio

PHONE_NUMBER = "254700002002"
TV_MAC = "3C:5A:B4:12:F3:3F"        # vendor (universally administered)
PHONE_MAC = "AA:BB:CC:00:20:01"     # randomized (locally administered)
PHONE_MAC_ROTATED = "AE:11:22:00:20:02"
OTHER_PHONE_MAC = "DA:A1:19:00:20:03"
NEW_LAPTOP_MAC = "F0:18:98:00:20:04"


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_code_attempt_limiter()
    yield
    reset_code_attempt_limiter()


@pytest.fixture
def router_io(monkeypatch):
    """Record every revocation and provisioning; set what is live on the router."""

    class RouterIO:
        cleaned: list[str] = []
        provisioned: list[str] = []
        live: set[str] | None = set()
        probed: list[list[str]] = []

    io = RouterIO()
    io.cleaned, io.provisioned, io.probed = [], [], []

    async def cleanup_ok(_router_info, old_mac):
        io.cleaned.append(old_mac)
        return {"success": True}

    async def provision_ok(**kwargs):
        io.provisioned.append(kwargs["hotspot_payload"]["mac_address"])
        return {"success": True}

    async def probe(_router_info, macs):
        io.probed.append(sorted(macs))
        if io.live is None:
            return None
        return {m for m in macs if m in io.live}

    from app.services import hotspot_provisioning

    monkeypatch.setattr(public_routes, "_cleanup_old_mac_with_retry", cleanup_ok)
    monkeypatch.setattr(hotspot_provisioning, "provision_hotspot_customer", provision_ok)
    monkeypatch.setattr(device_entitlements, "probe_online_macs", probe)
    return io


async def _household(db, *, tv_plan_devices=1, phone_row=True, phone_mac=PHONE_MAC):
    reseller = await make_reseller(db)
    single = await make_plan(db, reseller, max_shared_users=1)
    tv_plan = single if tv_plan_devices == 1 else await make_plan(
        db, reseller, max_shared_users=tv_plan_devices,
    )
    router = await make_router(db, reseller)
    tv = await make_customer(
        db, reseller, tv_plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
        mac_address=TV_MAC, phone=PHONE_NUMBER, name="Vivian TV",
    )
    phone = None
    if phone_row:
        phone = await make_customer(
            db, reseller, single, router,
            status=CustomerStatus.ACTIVE,
            expiry=datetime.utcnow() + timedelta(days=1),
            mac_address=phone_mac, phone=PHONE_NUMBER, name="Vivian phone",
        )
    return reseller, single, router, tv, phone


async def _seen(db, customer, ago: timedelta):
    at = datetime.utcnow() - ago
    db.add(CustomerUsageBucket(
        customer_id=customer.id, router_id=customer.router_id,
        bucket_start=at.replace(minute=0, second=0, microsecond=0),
        upload_bytes=1000, download_bytes=50000, updated_at=at,
    ))
    await db.commit()


async def _reconnect(db, router, mac, *, phone="0700002002", code=None):
    tasks = BackgroundTasks()
    result = await public_routes.reconnect_self_service(
        public_routes.ReconnectRequest(
            phone=None if code else phone,
            voucher_code=code,
            mac_address=mac,
            router_id=router.id,
        ),
        tasks,
        db,
    )
    await tasks()
    return result


async def _mac_of(db, customer):
    # identity, not customer.id: a rolled-back request expires the instance.
    row = await db.get(Customer, sa_inspect(customer).identity[0])
    await db.refresh(row)
    return row.mac_address


async def _receipt(db, customer, receipt):
    db.add(MpesaTransaction(
        checkout_request_id=f"ws_{receipt}",
        phone_number=customer.phone,
        amount=100,
        reference="ref",
        customer_id=customer.id,
        status=MpesaTransactionStatus.completed,
        mpesa_receipt_number=receipt,
    ))
    await db.commit()


# ---------------------------------------------------------------- phone number


async def test_phone_reconnect_restores_the_asking_devices_own_plan(db, router_io):
    _r, _p, router, tv, phone = await _household(db)
    await _seen(db, tv, timedelta(minutes=5))

    result = await _reconnect(db, router, PHONE_MAC)

    assert result["success"] is True
    assert result["customer_name"] == "Vivian phone"
    assert result["mac_changed"] is False
    assert await _mac_of(db, tv) == TV_MAC
    assert await _mac_of(db, phone) == PHONE_MAC
    assert router_io.cleaned == []                  # the TV was never revoked
    assert router_io.provisioned == [PHONE_MAC]     # provisioned once, phone only


async def test_tv_reconnect_by_phone_number_gets_the_tvs_plan(db, router_io):
    _r, _p, router, tv, phone = await _household(db)
    router_io.live = {PHONE_MAC}

    result = await _reconnect(db, router, TV_MAC)

    assert result["customer_name"] == "Vivian TV"
    assert await _mac_of(db, phone) == PHONE_MAC
    assert router_io.cleaned == []
    assert router_io.provisioned == [TV_MAC]


async def test_device_without_own_plan_is_refused_while_tv_in_use(db, router_io):
    _r, _p, router, tv, _phone = await _household(db, phone_row=False)
    # TV switched off a few hours ago: still its plan.
    await _seen(db, tv, timedelta(hours=3))

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, OTHER_PHONE_MAC)

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == PLAN_IN_USE_ERROR
    assert exc.value.detail["offer_purchase"] is True
    assert "F3:3F" in exc.value.detail["message"]
    assert "Buy a plan for this device" in exc.value.detail["message"]
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []
    assert router_io.provisioned == []

    attempt = (await db.execute(select(ReconnectionAttempt))).scalars().one()
    assert attempt.success is False
    assert attempt.failure_reason == "plan_in_use:fixed_device_recent"
    assert attempt.old_mac_address == TV_MAC


async def test_tv_online_on_the_router_is_never_revoked(db, router_io):
    # No usage history at all, but the router shows the TV right now.
    _r, _p, router, tv, _phone = await _household(db, phone_row=False)
    router_io.live = {TV_MAC}

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, OTHER_PHONE_MAC)

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == PLAN_IN_USE_ERROR
    assert router_io.probed == [[TV_MAC]]
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []


async def test_rotated_phone_mac_reclaims_its_own_plan(db, router_io):
    _r, _p, router, tv, phone = await _household(db)
    await _seen(db, tv, timedelta(minutes=2))
    await _seen(db, phone, timedelta(minutes=3))   # recent, but old MAC is gone
    router_io.live = {TV_MAC}

    result = await _reconnect(db, router, PHONE_MAC_ROTATED)

    assert result["success"] is True
    assert result["customer_name"] == "Vivian phone"
    assert result["mac_changed"] is True
    assert await _mac_of(db, phone) == PHONE_MAC_ROTATED
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == [PHONE_MAC]
    assert router_io.provisioned == [PHONE_MAC_ROTATED]


async def test_rotated_phone_whose_old_mac_is_still_live_waits(db, router_io):
    _r, _p, router, tv, phone = await _household(db)
    await _seen(db, tv, timedelta(minutes=2))
    router_io.live = {TV_MAC, PHONE_MAC}

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, PHONE_MAC_ROTATED)

    assert exc.value.status_code == 409
    assert "wait a minute" in exc.value.detail["message"]
    assert await _mac_of(db, phone) == PHONE_MAC
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []


async def test_router_unreachable_keeps_phone_recovery(db, router_io):
    # Probe can't tell: a randomized MAC counts as idle, as before this change.
    _r, _p, router, tv, phone = await _household(db)
    await _seen(db, tv, timedelta(hours=1))
    router_io.live = None

    result = await _reconnect(db, router, PHONE_MAC_ROTATED)

    assert result["customer_name"] == "Vivian phone"
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == [PHONE_MAC]


async def test_fixed_device_unseen_for_a_day_can_move(db, router_io):
    _r, _p, router, tv, _phone = await _household(db, phone_row=False)
    await _seen(db, tv, FIXED_DEVICE_RECENT_WINDOW + timedelta(hours=2))

    result = await _reconnect(db, router, NEW_LAPTOP_MAC)

    assert result["customer_name"] == "Vivian TV"
    assert await _mac_of(db, tv) == NEW_LAPTOP_MAC
    assert router_io.cleaned == [TV_MAC]
    assert router_io.provisioned == [NEW_LAPTOP_MAC]


async def test_multi_device_plan_still_adds_the_device(db, router_io):
    _r, _p, router, tv, _phone = await _household(db, tv_plan_devices=3, phone_row=False)
    await _seen(db, tv, timedelta(minutes=1))

    result = await _reconnect(db, router, OTHER_PHONE_MAC)

    assert result["outcome"] == "device_added"
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []
    pairing = (await db.execute(select(DevicePairing))).scalars().one()
    assert pairing.device_mac == OTHER_PHONE_MAC


async def test_full_multi_device_plan_keeps_its_main_device_when_in_use(db, router_io, monkeypatch):
    _r, _p, router, tv, _phone = await _household(db, tv_plan_devices=2, phone_row=False)
    await _seen(db, tv, timedelta(minutes=1))

    async def full(*_args, **_kwargs):
        raise HTTPException(status_code=409, detail={
            "error": "device_limit_reached", "message": "full", "devices": [],
        })

    monkeypatch.setattr(access_code_routes, "add_device_to_owner_plan", full)

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, OTHER_PHONE_MAC)

    assert exc.value.detail["error"] == "device_limit_reached"
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []


async def test_full_multi_device_plan_still_moves_an_idle_main_device(db, router_io, monkeypatch):
    # The pre-existing recovery: the owner's own phone changed MAC.
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, max_shared_users=2)
    router = await make_router(db, reseller)
    owner = await make_customer(
        db, reseller, plan, router, status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=3),
        mac_address=PHONE_MAC, phone=PHONE_NUMBER,
    )

    async def full(*_args, **_kwargs):
        raise HTTPException(status_code=409, detail={
            "error": "device_limit_reached", "message": "full", "devices": [],
        })

    monkeypatch.setattr(access_code_routes, "add_device_to_owner_plan", full)

    result = await _reconnect(db, router, PHONE_MAC_ROTATED)

    assert result["success"] is True
    assert await _mac_of(db, owner) == PHONE_MAC_ROTATED
    assert router_io.cleaned == [PHONE_MAC]


async def test_concurrent_move_after_assessment_is_refused(db, router_io, monkeypatch):
    _r, _p, router, tv, phone = await _household(db)
    router_io.live = {TV_MAC}
    real_assess = device_entitlements.assess_bound_devices

    async def assess_then_race(db_, customers, **kwargs):
        uses = await real_assess(db_, customers, **kwargs)
        row = await db_.get(Customer, phone.id)
        row.mac_address = OTHER_PHONE_MAC      # another request moved it meanwhile
        await db_.commit()
        return uses

    monkeypatch.setattr(device_entitlements, "assess_bound_devices", assess_then_race)

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, PHONE_MAC_ROTATED)

    assert exc.value.status_code == 409
    assert await _mac_of(db, phone) == OTHER_PHONE_MAC
    assert router_io.cleaned == []


# ------------------------------------------------------------------- code path


async def test_tv_receipt_on_phone_refused_while_tv_in_use(db, router_io):
    _r, _p, router, tv, _phone = await _household(db, phone_row=False)
    await _receipt(db, tv, "SIGTV00001")
    await _seen(db, tv, timedelta(hours=5))

    with pytest.raises(HTTPException) as exc:
        await access_code_routes.redeem_access_code(
            AccessCodeRedeemRequest(code="SIGTV00001", router_id=router.id, mac_address=OTHER_PHONE_MAC),
            BackgroundTasks(),
            db,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == PLAN_IN_USE_ERROR
    assert await _mac_of(db, tv) == TV_MAC
    assert router_io.cleaned == []


async def test_reconnect_with_code_uses_the_same_rule(db, router_io):
    _r, _p, router, tv, _phone = await _household(db, phone_row=False)
    await _receipt(db, tv, "SIGTV00002")
    router_io.live = {TV_MAC}

    with pytest.raises(HTTPException) as exc:
        await _reconnect(db, router, OTHER_PHONE_MAC, code="SIGTV00002")

    assert exc.value.status_code == 409
    assert await _mac_of(db, tv) == TV_MAC


async def test_tv_receipt_on_phone_with_its_own_plan_restores_the_phone(db, router_io):
    _r, _p, router, tv, phone = await _household(db)
    await _receipt(db, tv, "SIGTV00003")
    router_io.live = {TV_MAC}

    result = await _reconnect(db, router, PHONE_MAC, code="SIGTV00003")

    assert result["outcome"] == "main_device"
    assert result["customer_name"] == "Vivian phone"
    assert await _mac_of(db, tv) == TV_MAC
    assert await _mac_of(db, phone) == PHONE_MAC
    assert router_io.cleaned == []
    assert router_io.provisioned == [PHONE_MAC]


async def test_receipt_moves_a_rotated_phones_plan(db, router_io):
    _r, _p, router, _tv, phone = await _household(db)
    await _receipt(db, phone, "SIGPH00001")

    result = await _reconnect(db, router, PHONE_MAC_ROTATED, code="SIGPH00001")

    assert result["outcome"] == "main_device"
    assert result["mac_changed"] is True
    assert await _mac_of(db, phone) == PHONE_MAC_ROTATED
    assert router_io.cleaned == [PHONE_MAC]


# ------------------------------------------------------------------ the rules


async def test_mac_kind():
    assert is_randomized_mac(PHONE_MAC)
    assert is_randomized_mac("da:a1:19:00:00:01")
    assert not is_randomized_mac(TV_MAC)
    assert not is_randomized_mac(NEW_LAPTOP_MAC)
    assert not is_randomized_mac(None)


async def test_classification():
    now = datetime.utcnow()
    recent = now - timedelta(hours=10)
    assert classify_device_use(customer_id=1, mac=TV_MAC, last_seen=recent, online_now=False, now=now).in_use
    assert not classify_device_use(customer_id=1, mac=PHONE_MAC, last_seen=recent, online_now=False, now=now).in_use
    assert classify_device_use(customer_id=1, mac=PHONE_MAC, last_seen=None, online_now=True, now=now).in_use
    assert not classify_device_use(
        customer_id=1, mac=TV_MAC, last_seen=now - timedelta(hours=30), online_now=False, now=now,
    ).in_use
    assert not classify_device_use(customer_id=1, mac=None, last_seen=None, online_now=False, now=now).in_use


class _FakeProbeApi:
    def __init__(self, rows, connect_ok=True):
        self.rows = rows
        self.connect_ok = connect_ok
        self.queries = []

    def connect(self):
        return self.connect_ok

    def disconnect(self):
        return None

    def send_command_optimized(self, command, proplist=None, query=None):
        self.queries.append((command, query))
        path = command.removesuffix("/print")
        mac = query.split("=", 1)[1]
        return {
            "success": True,
            "data": [r for r in self.rows.get(path, []) if r["mac-address"] == mac],
        }


async def test_live_probe_reads_idle_time(monkeypatch):
    fake = _FakeProbeApi({
        "/ip/hotspot/host": [
            {"mac-address": TV_MAC, "idle-time": "3s"},
            {"mac-address": PHONE_MAC, "idle-time": "4m10s"},   # gone a while
        ],
        "/ip/hotspot/active": [
            {"mac-address": OTHER_PHONE_MAC, "idle-time": "00:00:20"},
        ],
    })
    monkeypatch.setattr(device_entitlements, "MikroTikAPI", lambda *a, **k: fake)

    online = probe_online_macs_sync(
        {"ip": "10.0.0.2", "username": "a", "password": "b", "port": 8728},
        [TV_MAC, PHONE_MAC, OTHER_PHONE_MAC, NEW_LAPTOP_MAC],
    )

    assert online == {TV_MAC, OTHER_PHONE_MAC}
    assert ("/ip/hotspot/host/print", f"?mac-address={TV_MAC}") in fake.queries


async def test_live_probe_unreachable_router_is_unknown(monkeypatch):
    fake = _FakeProbeApi({}, connect_ok=False)
    monkeypatch.setattr(device_entitlements, "MikroTikAPI", lambda *a, **k: fake)
    assert probe_online_macs_sync(
        {"ip": "10.0.0.2", "username": "a", "password": "b", "port": 8728}, [TV_MAC],
    ) is None

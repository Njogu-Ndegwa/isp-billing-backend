"""PPPoE customers allowed several devices on one login.

A device limit above 1 (plan ``max_shared_users`` or the customer's override)
puts the secret on a ``pppoe_<rate>_d<N>`` profile: ``only-one=no`` plus an
on-up script that keeps the login to N sessions. Every session's queue is
credited to the customer, so the plan's data cap stays one shared total.
"""

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.api import customer_device_routes
from app.api.customer_device_routes import DeviceLimitRequest
from app.db.models import ConnectionType, CustomerStatus, CustomerUsagePeriod, FupAction, UserBandwidthUsage
from app.services import fup, pppoe_provisioning, usage_push
from app.services.mikrotik_api import (
    MikroTikAPI,
    is_multi_device_profile,
    multi_device_on_up_script,
)
from app.services.usage_push import UsageReport, resolve_pppoe_queue_owner
from tests.factories import make_customer, make_plan, make_reseller, make_router

MB = 1024 * 1024


class FakeProfileApi:
    """Records ensure_pppoe_profile calls; enough for ensure_plan_pppoe_profile."""

    def __init__(self):
        self.profiles = []

    def _parse_speed_to_mikrotik(self, speed):
        return MikroTikAPI._parse_speed_to_mikrotik(self, speed)

    def get_active_pppoe_profile(self):
        return {"found": True, "data": {"local_address": "192.168.89.1", "remote_address": "pppoe-pool"}}

    def ensure_ip_pool(self, name, ranges):
        return {"success": True}

    def ensure_pppoe_profile(self, name, rate_limit, **kwargs):
        self.profiles.append((name, rate_limit, kwargs))
        return {"success": True}


def test_single_device_keeps_the_shared_plan_profile():
    api = FakeProfileApi()
    result = pppoe_provisioning.ensure_plan_pppoe_profile(api, "10M/10M")

    name, _rate, kwargs = api.profiles[0]
    assert result["profile"] == name == "pppoe_10M_10M"
    assert "only_one" not in kwargs and "on_up" not in kwargs  # untouched: only-one=yes default


def test_multi_device_profile_allows_n_sessions():
    api = FakeProfileApi()
    result = pppoe_provisioning.ensure_plan_pppoe_profile(api, "10M/10M", max_devices=3)

    name, _rate, kwargs = api.profiles[0]
    assert result["profile"] == name == "pppoe_10M_10M_d3"
    assert kwargs["only_one"] == "no"
    assert "> 3" in kwargs["on_up"]
    assert "/ppp active remove $newest" in kwargs["on_up"]
    assert is_multi_device_profile(name)
    assert not is_multi_device_profile("pppoe_10M_10M")
    assert not is_multi_device_profile("default-pppoe")


def test_access_defaults_leave_multi_device_profiles_alone():
    sets = []

    class FakeRouter(MikroTikAPI):
        def __init__(self):
            self.connected = True

        def send_command_optimized(self, command, proplist=None, query=None):
            if command == "/interface/pppoe-server/server/print":
                return {"success": True, "data": []}
            if command == "/ppp/secret/print":
                return {"success": True, "data": [
                    {"name": "alice", "service": "pppoe", "profile": "pppoe_10M_10M_d3"},
                    {"name": "bob", "service": "pppoe", "profile": "pppoe_10M_10M"},
                ]}
            if command == "/ppp/profile/print":
                name = (query or "").removeprefix("?name=")
                return {"success": True, "data": [{".id": f"*{name}", "name": name, "only-one": "no"}]}
            return {"success": True, "data": []}

        def send_command(self, command, args=None):
            if command == "/ppp/profile/set":
                sets.append(args["numbers"])
            return {"success": True, "data": []}

    result = FakeRouter().apply_pppoe_reconnect_defaults()

    assert result.get("success") is True
    assert sets == ["*pppoe_10M_10M"]


def _stub(username, override=None):
    return SimpleNamespace(pppoe_username=username, max_devices_override=override)


def test_extra_session_queue_resolves_to_its_owner():
    alice = _stub("alice", override=3)
    index = {"pppoe:alice": alice, "pppoe:al-2": _stub("al-2")}

    # By the session IP from /ppp active.
    assert resolve_pppoe_queue_owner(
        "pppoe:alice-1", "192.168.89.11/32", index, {"192.168.89.11": "alice"},
    ) == "pppoe:alice"
    # By the -N suffix when the router sent no session list.
    assert resolve_pppoe_queue_owner("pppoe:alice-2", "", index, None) == "pppoe:alice"
    # A real customer's own key is never re-pointed.
    assert resolve_pppoe_queue_owner("pppoe:al-2", "", index, None) is None
    # Unknown base: nothing to credit.
    assert resolve_pppoe_queue_owner("pppoe:carol-1", "", index, None) is None


def test_leftover_login_is_never_billed_to_a_lookalike_customer():
    john = _stub("john")  # single device
    index = {"pppoe:john": john}

    # A router-only secret "john-2" must not be credited to john.
    assert resolve_pppoe_queue_owner("pppoe:john-2", "", index, None) is None

    # Even for a multi-device customer, the router's session list wins: this
    # IP belongs to the login "john-2", not to john.
    john.max_devices_override = 3
    assert resolve_pppoe_queue_owner(
        "pppoe:john-2", "192.168.89.40/32", index, {"192.168.89.40": "john-2"},
    ) is None


async def _pppoe_customer(db, *, max_shared_users=1, override=None, cap_mb=None):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db, reseller,
        connection_type=ConnectionType.PPPOE,
        max_shared_users=max_shared_users,
        data_cap_mb=cap_mb,
    )
    customer = await make_customer(
        db, reseller, plan, router,
        pppoe_username="alice",
        pppoe_password="secret",
        mac_address=None,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=30),
        max_devices_override=override,
    )
    return reseller, router, plan, customer


@pytest.mark.asyncio
async def test_every_session_counts_toward_one_customer_period(db, session_factory):
    _reseller, router, _plan, customer = await _pppoe_customer(db, max_shared_users=3)
    sessions = {"192.168.89.10": "alice", "192.168.89.11": "alice"}

    def batch(first_up, second_up):
        return [
            UsageReport(queue_key="pppoe:alice", upload_bytes=first_up, download_bytes=0,
                        target_ip="192.168.89.10/32"),
            UsageReport(queue_key="pppoe:alice-1", upload_bytes=second_up, download_bytes=0,
                        target_ip="192.168.89.11/32"),
        ]

    first = await usage_push.ingest_usage_reports(
        router.id, batch(1 * MB, 1 * MB), session_factory=session_factory, pppoe_session_users=sessions,
    )
    await usage_push.ingest_usage_reports(
        router.id, batch(3 * MB, 6 * MB), session_factory=session_factory, pppoe_session_users=sessions,
    )

    assert first.rejected == 0
    async with session_factory() as s:
        period = (
            await s.execute(select(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer.id))
        ).scalar_one()
        rows = (
            await s.execute(select(UserBandwidthUsage).where(UserBandwidthUsage.customer_id == customer.id))
        ).scalars().all()
    # +2 MB on the first device, +5 MB on the second: one total.
    assert period.upload_bytes == 7 * MB
    # Each session keeps its own counter row (and baseline).
    assert sorted(r.mac_address for r in rows) == ["pppoe:alice", "pppoe:alice-1"]


def test_build_payload_carries_the_device_limit():
    class Plan:
        speed = "10M/10M"
        max_shared_users = 1

    class Customer:
        id = 7
        name = "Alice"
        phone = "254700000000"
        pppoe_username = "alice"
        pppoe_password = "secret"
        max_devices_override = 4
        plan = Plan()

    class Router:
        ip_address = "10.0.0.2"
        username = "admin"
        password = "x"
        port = 8728

    assert pppoe_provisioning.build_pppoe_payload(Customer(), Router())["max_devices"] == 4


@pytest.mark.asyncio
async def test_fup_throttle_keeps_the_device_allowance(db, monkeypatch):
    _reseller, _router, plan, customer = await _pppoe_customer(db, max_shared_users=3)
    calls = []

    async def inline_to_thread(fn, *args):
        return fn(*args)

    def fake_throttle(router_info, username, profile_name, rate_limit, max_devices=1):
        calls.append((username, profile_name, max_devices))
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(fup, "_set_secret_throttle_profile_sync", fake_throttle)

    await fup.apply_throttle(db, customer, plan)

    assert len(calls) == 1
    username, profile_name, max_devices = calls[0]
    assert username == "alice" and max_devices == 3
    assert profile_name.startswith("fup-") and profile_name.endswith("_d3")


def test_on_up_script_drops_only_the_newest_session_over_the_limit():
    script = multi_device_on_up_script(2)
    assert script.startswith(":local ids [/ppp active find where name=$user]; :if ([:len $ids] > 2) do={")
    # The lowest-uptime session is the one removed, so simultaneous dials
    # agree on one victim instead of each removing itself.
    assert "($up < $best)" in script
    assert script.count("/ppp active remove") == 1


@pytest.mark.asyncio
async def test_device_limit_change_reprovisions_an_active_pppoe_customer(db, monkeypatch):
    reseller, _router, _plan, customer = await _pppoe_customer(db, max_shared_users=1)
    token = {"user_id": reseller.id, "role": reseller.role.value}
    pushed = []

    async def fake_provision(payload):
        pushed.append(payload)
        return {"success": True}

    monkeypatch.setattr(customer_device_routes, "call_pppoe_provision", fake_provision)

    result = await customer_device_routes.set_customer_device_limit(
        customer.id, DeviceLimitRequest(max_devices=3), db, token,
    )

    assert result["max_devices"] == 3
    assert result["router_update"] == "applied"
    assert [p["max_devices"] for p in pushed] == [3]
    assert pushed[0]["pppoe_username"] == "alice"


@pytest.mark.asyncio
async def test_device_limit_change_keeps_an_active_fup_throttle(db, monkeypatch):
    reseller, _router, plan, customer = await _pppoe_customer(db, max_shared_users=1, cap_mb=100)
    token = {"user_id": reseller.id, "role": reseller.role.value}
    db.add(CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=datetime.utcnow() - timedelta(days=1),
        period_end=datetime.utcnow() + timedelta(days=29),
        fup_triggered_at=datetime.utcnow(),
        fup_action_taken=FupAction.THROTTLE,
    ))
    await db.commit()
    throttled, provisioned = [], []

    async def fake_throttle(_db, c, _plan):
        throttled.append(c.id)
        return {"success": True}

    async def fake_provision(payload):
        provisioned.append(payload)
        return {"success": True}

    monkeypatch.setattr(customer_device_routes, "apply_throttle", fake_throttle)
    monkeypatch.setattr(customer_device_routes, "call_pppoe_provision", fake_provision)

    result = await customer_device_routes.set_customer_device_limit(
        customer.id, DeviceLimitRequest(max_devices=3), db, token,
    )

    assert result["router_update"] == "applied"
    assert throttled == [customer.id]  # throttle re-applied with the new limit
    assert provisioned == []  # never moved back to the full-speed profile


@pytest.mark.asyncio
async def test_plan_device_change_reaches_active_customers(db, session_factory, monkeypatch):
    _reseller, _router, plan, customer = await _pppoe_customer(db, max_shared_users=3)
    await make_customer(
        db, _reseller, plan, _router,
        pppoe_username="bob", pppoe_password="pw", mac_address=None,
        status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=5),
        max_devices_override=1,  # has their own limit: left alone
    )
    pushed = []

    async def fake_provision(payload):
        pushed.append((payload["pppoe_username"], payload["max_devices"]))
        return {"success": True}

    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)
    import app.db.database as database
    monkeypatch.setattr(database, "async_session", session_factory)

    # Device count only: bob has his own limit, so the plan's number is not his.
    summary = await pppoe_provisioning.reprovision_plan_pppoe_customers(plan.id, speed_changed=False)
    assert pushed == [("alice", 3)]
    assert summary["applied"] == 1 and summary["failed"] == 0

    # A speed change reaches everyone on the plan, bob included.
    pushed.clear()
    await pppoe_provisioning.reprovision_plan_pppoe_customers(plan.id, speed_changed=True)
    assert sorted(pushed) == [("alice", 3), ("bob", 1)]


@pytest.mark.asyncio
async def test_editing_a_pppoe_plan_schedules_the_router_push(db, monkeypatch):
    from app.api import plan_routes

    reseller, _router, plan, _customer = await _pppoe_customer(db, max_shared_users=1)
    scheduled = []

    async def fake_push(plan_id, *, speed_changed):
        scheduled.append((plan_id, speed_changed))
        return {}

    async def fake_current_user(_token, _db):
        return reseller

    async def no_cache():
        return None

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda _user: None)
    monkeypatch.setattr(plan_routes, "invalidate_plan_cache", no_cache)
    monkeypatch.setattr(pppoe_provisioning, "reprovision_plan_pppoe_customers", fake_push)

    async def update(**fields):
        await plan_routes.update_plan_api(
            plan.id, plan_routes.PlanUpdateRequest(**fields), db=db, token="token",
        )
        await asyncio.sleep(0)  # let the background task run

    await update(speed="20M/20M")
    await update(max_shared_users=3)
    await update(price=999)  # nothing the router holds

    assert scheduled == [(plan.id, True), (plan.id, False)]

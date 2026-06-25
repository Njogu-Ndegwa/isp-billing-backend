"""FUP enforcement for PPPoE customers.

Throttling a PPPoE plan limits the connection to a lesser *speed* (the same
``5M/2M`` form hotspot uses), not a hand-named PPP profile.  The enforcer
derives a rate-limit from ``plan.fup_throttle_profile``, ensures a dedicated
``/ppp/profile`` carries that rate, and points the customer's PPP secret at it.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import ConnectionType, CustomerUsagePeriod, FupAction
from app.services import fup
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest.mark.asyncio
async def test_pppoe_fup_throttle_derives_rate_and_ensures_speed_profile(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        data_cap_mb=1,
        fup_action=FupAction.THROTTLE,
        fup_throttle_profile="3M/1M",  # a SPEED, not a hand-named profile
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        pppoe_username="john_doe",
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(hours=1),
        period_end=now + timedelta(hours=1),
        upload_bytes=1_200_000,
        download_bytes=1_200_000,
        total_bytes=2_400_000,
        cap_mb_snapshot=1,
        fup_action_snapshot=FupAction.THROTTLE,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    calls = []

    def fake_set_throttle(router_info, username, profile_name, rate_limit):
        calls.append(
            {
                "router": router_info["ip"],
                "username": username,
                "profile": profile_name,
                "rate": rate_limit,
            }
        )
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(
        fup, "_set_secret_throttle_profile_sync", fake_set_throttle, raising=False
    )

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=now)

    assert action == FupAction.THROTTLE
    assert period.fup_triggered_at == now
    assert period.fup_action_taken == FupAction.THROTTLE
    assert calls == [
        {
            "router": router.ip_address,
            "username": "john_doe",
            "profile": "fup-3M-1M",
            "rate": "3M/1M",
        }
    ]


@pytest.mark.asyncio
async def test_pppoe_fup_throttle_blank_profile_falls_back_to_default_rate(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        data_cap_mb=1,
        fup_action=FupAction.THROTTLE,
        fup_throttle_profile=None,  # blank -> default throttle speed
    )
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        pppoe_username="jane_doe",
        expiry=datetime.utcnow() + timedelta(days=30),
    )
    now = datetime.utcnow()
    period = CustomerUsagePeriod(
        customer_id=customer.id,
        period_start=now - timedelta(hours=1),
        period_end=now + timedelta(hours=1),
        upload_bytes=1_200_000,
        download_bytes=1_200_000,
        total_bytes=2_400_000,
        cap_mb_snapshot=1,
        fup_action_snapshot=FupAction.THROTTLE,
    )
    db.add(period)
    await db.commit()
    await db.refresh(period)

    async def inline_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    calls = []

    def fake_set_throttle(router_info, username, profile_name, rate_limit):
        calls.append({"username": username, "profile": profile_name, "rate": rate_limit})
        return {"success": True}

    monkeypatch.setattr(fup.asyncio, "to_thread", inline_to_thread)
    monkeypatch.setattr(
        fup, "_set_secret_throttle_profile_sync", fake_set_throttle, raising=False
    )

    action = await fup.evaluate_and_enforce(db, customer, period, plan=plan, now=now)

    assert action == FupAction.THROTTLE
    assert calls == [{"username": "jane_doe", "profile": "fup-1M-1M", "rate": "1M/1M"}]


def test_set_secret_throttle_profile_sync_ensures_profile_then_points_secret(monkeypatch):
    instances = []

    class FakeMikroTik:
        def __init__(self, *args, **kwargs):
            self.commands = []
            self.ensured = []
            self.disconnected_sessions = []
            instances.append(self)

        def connect(self):
            return True

        def disconnect(self):
            self.commands.append(("disconnect", None))

        def ensure_pppoe_profile(self, profile_name, rate_limit):
            self.ensured.append((profile_name, rate_limit))
            return {"success": True}

        def send_command(self, command, args=None):
            self.commands.append((command, args))
            return {"success": True}

        def disconnect_pppoe_session(self, username):
            self.disconnected_sessions.append(username)
            return {"success": True}

    monkeypatch.setattr(fup, "MikroTikAPI", FakeMikroTik)

    result = fup._set_secret_throttle_profile_sync(
        {"ip": "10.0.0.2", "username": "admin", "password": "pw", "port": 8728},
        "john_doe",
        "fup-3M-1M",
        "3M/1M",
    )

    assert "error" not in result
    api = instances[0]
    # Profile is ensured with the rate BEFORE the secret is pointed at it.
    assert api.ensured == [("fup-3M-1M", "3M/1M")]
    assert (
        "/ppp/secret/set",
        {"numbers": "john_doe", "profile": "fup-3M-1M", "disabled": "no"},
    ) in api.commands
    assert api.disconnected_sessions == ["john_doe"]

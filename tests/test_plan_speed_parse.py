"""Plan speeds as resellers type them (8 Nov 2026).

Reseller 563's PPPoE plan was saved as "5mbs". The parser only knew
"5M"/"5Mbps", silently fell back to 10M/10M, and customer LKR0101 got a
pppoe_10M_10M profile on a 5 Mbps plan. The parser now reads the spellings
seen in real plans, and plan create/edit refuse anything it still cannot read
instead of storing it.
"""

from datetime import timedelta
from unittest.mock import Mock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.api import pppoe_monitor
from app.api.auth_routes import login_token_claims
from app.db.models import ConnectionType, Plan
from app.services.auth import create_access_token
from app.services.mikrotik_api import (
    MikroTikAPI,
    parse_speed_to_mikrotik,
    plan_speed_error,
    try_parse_speed_to_mikrotik,
)
from app.services.plan_cache import _serialize_plan
from tests.factories import make_plan, make_reseller


# Plan text (DOWNLOAD/UPLOAD) -> RouterOS rate-limit (UPLOAD/DOWNLOAD).
@pytest.mark.parametrize(
    "speed,expected",
    [
        ("5mbs", "5M/5M"),
        ("5MBS", "5M/5M"),
        ("5mbps", "5M/5M"),
        ("5 Mbps", "5M/5M"),
        ("5M", "5M/5M"),
        ("5m", "5M/5M"),
        ("5MB", "5M/5M"),
        ("5mb", "5M/5M"),
        ("5mb/s", "5M/5M"),
        ("5 MB/s", "5M/5M"),
        ("5Mbit/s", "5M/5M"),
        ("5mbit", "5M/5M"),
        ("5 mbits", "5M/5M"),
        ("5mps", "5M/5M"),
        ("5", "5M/5M"),
        ("5/5", "5M/5M"),
        ("5M/2M", "2M/5M"),
        ("5 M / 2 M", "2M/5M"),
        ("5mb/s/2mb/s", "2M/5M"),
        ("5mps/3mps", "3M/5M"),
        ("15M/14mb", "14M/15M"),
        ("512k", "512K/512K"),
        ("512Kbps", "512K/512K"),
        ("512 kb/s", "512K/512K"),
        ("1.5M", "1500k/1500k"),
        ("1.5mbps", "1500k/1500k"),
        ("2/.3", "300k/2M"),
        ("1G", "1G/1G"),
        ("4M/4/", "4M/4M"),
        ("5000000/2000000", "2000000/5000000"),
    ],
)
def test_parser_reads_common_reseller_spellings(speed, expected):
    assert try_parse_speed_to_mikrotik(speed) == expected
    assert parse_speed_to_mikrotik(speed) == expected
    assert plan_speed_error(speed) is None


@pytest.mark.parametrize(
    "speed",
    ["", "   ", "Unlimited", "Happy hour", "mbps", "1om/10m", "10m/10mm", "2mg",
     "3M3M", "7M(tv and laptops)", "5M/2M/1M", "5x"],
)
def test_unreadable_speeds_are_reported_not_guessed(speed):
    assert try_parse_speed_to_mikrotik(speed) is None
    error = plan_speed_error(speed)
    assert error and "Use a speed like 5M or 5M/2M" in error


def test_legacy_unreadable_rows_still_provision_at_the_old_default():
    # Rows saved before validation keep working exactly as before.
    assert parse_speed_to_mikrotik("Unlimited") == "10M/10M"
    assert parse_speed_to_mikrotik("") == ""


def test_zero_stays_unlimited_and_absurd_speeds_are_refused():
    # "0M/0M" is a live PPPoE plan: RouterOS reads 0 as unlimited.
    assert parse_speed_to_mikrotik("0M/0M") == "0M/0M"
    assert plan_speed_error("0M/0M") is None
    assert "above 10 Gbps" in plan_speed_error("50G")


def _bearer(owner):
    token = create_access_token(login_token_claims(owner), timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def client(engine):
    import main
    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as value:
        yield value


def _plan_body(**overrides):
    body = {
        "name": "1 month plan",
        "speed": "5mbs",
        "price": 1500,
        "duration_value": 30,
        "duration_unit": "DAYS",
        "connection_type": "pppoe",
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_create_plan_accepts_5mbs_and_rejects_words(client, db):
    owner = await make_reseller(db)

    ok = await client.post("/api/plans/create", headers=_bearer(owner), json=_plan_body())
    assert ok.status_code == 200, ok.text
    assert ok.json()["speed"] == "5mbs"

    bad = await client.post(
        "/api/plans/create", headers=_bearer(owner),
        json=_plan_body(name="Unlimited plan", speed="Unlimited"),
    )
    assert bad.status_code == 400, bad.text
    assert bad.json()["detail"] == (
        "Speed 'Unlimited' is not recognised. Use a speed like 5M or 5M/2M (download/upload)."
    )


@pytest.mark.asyncio
async def test_edit_plan_rejects_unreadable_speed_and_keeps_old_one(client, db):
    owner = await make_reseller(db)
    plan = await make_plan(db, owner, connection_type=ConnectionType.HOTSPOT, speed="5M")

    bad = await client.put(f"/api/plans/{plan.id}", headers=_bearer(owner), json={"speed": "1om/10m"})
    assert bad.status_code == 400, bad.text
    await db.refresh(plan)
    assert plan.speed == "5M"

    # Edits that do not touch the speed still work on a legacy plan.
    plan.speed = "Unlimited"
    await db.commit()
    hide = await client.put(f"/api/plans/{plan.id}", headers=_bearer(owner), json={"is_hidden": True})
    assert hide.status_code == 200, hide.text


@pytest.mark.asyncio
async def test_plan_payload_says_whether_speed_is_recognised(db):
    owner = await make_reseller(db)
    good = await make_plan(db, owner, speed="5mbs", name="Good")
    legacy = await make_plan(db, owner, speed="Unlimited", name="Legacy")

    assert _serialize_plan(good)["speed_recognised"] is True
    assert _serialize_plan(legacy)["speed_recognised"] is False


def _fake_api(messages, success=True):
    api = MikroTikAPI.__new__(MikroTikAPI)
    api.get_router_logs = Mock(return_value={
        "success": success,
        "data": [{"time": f"19:02:{i:02d}", "topics": "pppoe,ppp,error", "message": m}
                 for i, m in enumerate(messages)],
    })
    return api


def test_recent_auth_failures_counts_only_this_login():
    api = _fake_api([
        "<086b>: user LKR0101 authentication failed",
        "<086c>: user LKR0101 authentication failed",
        "<086d>: user LKR01011 authentication failed",
        "<086e>: user OTHER authentication failed",
        "<pppoe-LKR0101>: authenticated",
        "<086f>: user lkr0101 authentication failed",
    ])

    result = pppoe_monitor._recent_auth_failures(api, "LKR0101")

    assert result == {"lookup_success": True, "count": 3, "last_at": "19:02:05", "error": None}


def test_recent_auth_failures_unknown_when_log_unreadable():
    api = _fake_api([], success=False)
    result = pppoe_monitor._recent_auth_failures(api, "LKR0101")
    assert result["lookup_success"] is False and result["count"] == 0


def _token(user):
    return create_access_token(login_token_claims(user), timedelta(hours=1))


@pytest.mark.asyncio
async def test_presence_reports_auth_failures_for_a_login_not_on_the_router(db, monkeypatch):
    from tests.factories import make_customer, make_router
    from app.db.models import CustomerStatus

    pppoe_monitor._pppoe_presence_cache.clear()
    owner = await make_reseller(db)
    plan = await make_plan(db, owner, connection_type=ConnectionType.PPPOE, speed="5mbs")
    router = await make_router(db, owner)
    customer = await make_customer(
        db, owner, plan, router, status=CustomerStatus.INACTIVE, mac_address=None,
        pppoe_username="LKR0101", pppoe_password="secret", name="Luka customer",
    )
    failures = {"lookup_success": True, "count": 457, "last_at": "19:14:50", "error": None}

    async def _run_with_guard(_router_id, _fn, _router_info, username, **_kwargs):
        return {
            "success": True, "username": username, "present_on_router": False,
            "online": None, "state": "missing", "secret": None,
            "pppoe_server": {"lookup_success": True, "enabled_interfaces": ["ether2"], "error": None},
            "auth_failures": failures,
        }

    monkeypatch.setattr(pppoe_monitor, "run_with_guard", _run_with_guard)

    response = await pppoe_monitor.pppoe_customer_presence(customer.id, db, _token(owner), refresh=True)

    assert response["verdict"]["code"] == "missing_from_mikrotik"
    assert response["auth_failures"] == failures
    assert response["speed_enforcement"]["plan_rate_limit"] == "5M/5M"

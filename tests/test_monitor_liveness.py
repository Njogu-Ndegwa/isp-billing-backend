"""A router that is not answering must never report connected customers.

Reported by a reseller on 2026-08-14: the site had lost power, so the router
was off and every customer behind it was disconnected — yet the customers table
kept showing them Active/Online with live download and upload speeds.

Cause: both monitor endpoints answered an unreachable router by replaying their
last successful snapshot verbatim. `online: true` and the last observed rates
came back on every poll, indefinitely, marked only by a `stale` flag that no
caller read.

These tests pin the contract: when the router does not answer, the roster and
the cumulative byte counters survive, and every claim about *right now* does
not.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.hotspot_monitor as hotspot_monitor
import app.api.pppoe_monitor as pppoe_monitor
from app.db.database import get_db
from app.db.models import CustomerStatus
from app.services.auth import verify_token
from app.services.monitor_liveness import clear_live_state, mark_snapshot_unverified
from tests.factories import make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------

def _hotspot_snapshot():
    return {
        "router_id": 7,
        "router_name": "Bitwave Wangige",
        "cached": False,
        "live": True,
        "router_reachable": True,
        "users": [
            {
                "username": "aabbccddeeff",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "disabled": False,
                "online": True,
                "online_source": "host",
                "address": "10.5.50.12",
                "uptime": "2h13m",
                "idle_time": "1s",
                "login_by": "mac",
                "upload_bytes": 12_000_000,
                "download_bytes": 543_000_000,
                "upload_rate": "51000",
                "download_rate": "1100000",
                "max_limit": "5M/5M",
                "binding_type": "bypassed",
                "bypassed": True,
                "authorized": True,
                "has_queue": True,
                "customer": {"id": 42, "name": "Guest 5461"},
            },
            {
                "username": "112233445566",
                "mac_address": "11:22:33:44:55:66",
                "disabled": True,
                "online": False,
                "online_source": None,
                "address": None,
                "uptime": None,
                "idle_time": None,
                "login_by": "",
                "upload_bytes": 0,
                "download_bytes": 0,
                "upload_rate": "0",
                "download_rate": "0",
                "max_limit": "",
                "binding_type": "",
                "bypassed": False,
                "authorized": False,
                "has_queue": False,
                "customer": None,
            },
        ],
        "summary": {
            "total": 2,
            "online": 1,
            "offline": 1,
            "disabled": 1,
            "total_upload_rate_bps": 51000,
            "total_download_rate_bps": 1100000,
        },
    }


def test_clear_live_state_takes_everyone_offline():
    snapshot = _hotspot_snapshot()
    result = clear_live_state(snapshot, reason="connect_failed", age_seconds=91.27)

    online_user = result["users"][0]
    assert online_user["online"] is False
    assert online_user["online_source"] is None
    assert online_user["upload_rate"] == "0"
    assert online_user["download_rate"] == "0"
    assert online_user["address"] is None
    assert online_user["uptime"] is None
    assert online_user["idle_time"] is None
    assert online_user["login_by"] == ""
    assert online_user["authorized"] is False

    assert result["summary"] == {
        "total": 2,
        "online": 0,
        "offline": 2,
        "disabled": 1,
        "total_upload_rate_bps": 0,
        "total_download_rate_bps": 0,
    }
    assert result["live"] is False
    assert result["router_reachable"] is False
    assert result["stale"] is True
    assert result["fallback_reason"] == "connect_failed"
    assert result["cache_age_seconds"] == 91.3


def test_clear_live_state_keeps_identity_and_cumulative_usage():
    """The reseller still needs to know who their customers are and what they used."""
    result = clear_live_state(_hotspot_snapshot(), reason="timeout")
    user = result["users"][0]

    assert user["username"] == "aabbccddeeff"
    assert user["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert user["customer"] == {"id": 42, "name": "Guest 5461"}
    assert user["download_bytes"] == 543_000_000
    assert user["upload_bytes"] == 12_000_000
    assert user["max_limit"] == "5M/5M"
    # `bypassed` is an IP-binding, i.e. configuration, not a live session.
    assert user["bypassed"] is True


def test_clear_live_state_does_not_mutate_the_cache():
    """The input dict IS the process-wide response cache."""
    snapshot = _hotspot_snapshot()
    clear_live_state(snapshot, reason="connect_failed")

    assert snapshot["users"][0]["online"] is True
    assert snapshot["summary"]["online"] == 1


def test_unverified_snapshot_keeps_state_but_not_the_live_claim():
    """DB pool pressure means we didn't ask — not that the router is down."""
    result = mark_snapshot_unverified(
        _hotspot_snapshot(), reason="db_pool_pressure", age_seconds=42.0,
    )

    assert result["users"][0]["online"] is True
    assert result["live"] is False
    assert result["router_reachable"] is None
    assert result["fallback_reason"] == "db_pool_pressure"
    assert result["cache_age_seconds"] == 42.0


def test_last_online_at_is_serialized():
    when = datetime(2026, 8, 14, 16, 25, 0)
    result = clear_live_state(_hotspot_snapshot(), reason="connect_failed", last_online_at=when)
    assert result["router_last_online_at"] == "2026-08-14T16:25:00"


# ---------------------------------------------------------------------------
# The endpoints
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(hotspot_monitor.router)
    application.include_router(pppoe_monitor.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(hotspot_monitor, "get_current_user", _fake)
    monkeypatch.setattr(pppoe_monitor, "get_current_user", _fake)


async def _reseller_router(db, **router_overrides):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, **router_overrides)
    plan = await make_plan(db, reseller)
    return reseller, router, plan


@pytest.mark.asyncio
async def test_hotspot_users_stops_claiming_online_when_router_stops_answering(
    db, client, monkeypatch,
):
    """The reported bug: power cut at the site, customers still shown Online."""
    reseller, router, plan = await _reseller_router(db)
    _auth_as(monkeypatch, reseller)

    live = _hotspot_snapshot()
    live["router_id"] = router.id
    hotspot_monitor._hotspot_users_cache[router.id] = {
        "data": live,
        "timestamp": datetime.utcnow() - timedelta(minutes=5),
    }

    async def _dead_router(*args, **kwargs):
        return {"error": "connect_failed"}
    monkeypatch.setattr(hotspot_monitor, "run_with_guard", _dead_router)

    resp = await client.get(f"/api/hotspot/{router.id}/users")
    assert resp.status_code == 200
    body = resp.json()

    assert body["router_reachable"] is False
    assert body["live"] is False
    assert body["fallback_reason"] == "connect_failed"
    assert [u["online"] for u in body["users"]] == [False, False]
    assert {u["download_rate"] for u in body["users"]} == {"0"}
    assert body["summary"]["online"] == 0
    # ...and the customer list is still there, with its usage totals.
    assert body["users"][0]["download_bytes"] == 543_000_000

    hotspot_monitor._hotspot_users_cache.pop(router.id, None)


@pytest.mark.asyncio
async def test_hotspot_users_falls_back_to_db_with_no_cache(db, client, monkeypatch):
    """A router that has been dark since the last restart has no snapshot to strip."""
    reseller, router, plan = await _reseller_router(db)
    await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE, name="Guest 5461", mac_address="AA:BB:CC:00:11:22",
    )
    _auth_as(monkeypatch, reseller)
    hotspot_monitor._hotspot_users_cache.pop(router.id, None)

    async def _dead_router(*args, **kwargs):
        return {"error": "connect_failed"}
    monkeypatch.setattr(hotspot_monitor, "run_with_guard", _dead_router)

    resp = await client.get(f"/api/hotspot/{router.id}/users")
    assert resp.status_code == 200
    body = resp.json()

    assert body["router_reachable"] is False
    assert body["summary"]["online"] == 0
    assert len(body["users"]) == 1
    assert body["users"][0]["online"] is False
    assert body["users"][0]["customer"]["name"] == "Guest 5461"


@pytest.mark.asyncio
async def test_hotspot_users_skips_a_router_known_to_be_dark(db, client, monkeypatch):
    """No point spending a connect timeout per poll on a router we know is off."""
    reseller, router, plan = await _reseller_router(
        db, last_status=False, last_checked_at=datetime.utcnow() - timedelta(minutes=2),
    )
    _auth_as(monkeypatch, reseller)

    live = _hotspot_snapshot()
    hotspot_monitor._hotspot_users_cache[router.id] = {
        "data": live,
        "timestamp": datetime.utcnow() - timedelta(minutes=10),
    }

    async def _must_not_run(*args, **kwargs):
        raise AssertionError("the router should not have been contacted")
    monkeypatch.setattr(hotspot_monitor, "run_with_guard", _must_not_run)

    resp = await client.get(f"/api/hotspot/{router.id}/users")
    body = resp.json()

    assert body["fallback_reason"] == "router_recently_offline"
    assert body["router_reachable"] is False
    assert all(u["online"] is False for u in body["users"])

    hotspot_monitor._hotspot_users_cache.pop(router.id, None)


@pytest.mark.asyncio
async def test_hotspot_users_serves_live_state_when_the_router_answers(
    db, client, monkeypatch,
):
    """The fix must not blind the normal path: an answering router reports the truth."""
    reseller, router, plan = await _reseller_router(db)
    customer = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE, mac_address="AA:BB:CC:DD:EE:FF",
    )
    _auth_as(monkeypatch, reseller)
    hotspot_monitor._hotspot_users_cache.pop(router.id, None)

    async def _live(*args, **kwargs):
        snapshot = _hotspot_snapshot()
        return {
            "success": True,
            "users": snapshot["users"],
            "summary": snapshot["summary"],
        }
    monkeypatch.setattr(hotspot_monitor, "run_with_guard", _live)

    resp = await client.get(f"/api/hotspot/{router.id}/users")
    body = resp.json()

    assert body["live"] is True
    assert body["router_reachable"] is True
    assert body["users"][0]["online"] is True
    assert body["users"][0]["download_rate"] == "1100000"
    assert body["users"][0]["customer"]["id"] == customer.id

    hotspot_monitor._hotspot_users_cache.pop(router.id, None)


@pytest.mark.asyncio
async def test_pppoe_users_stops_claiming_online_when_router_stops_answering(
    db, client, monkeypatch,
):
    reseller, router, plan = await _reseller_router(db)
    _auth_as(monkeypatch, reseller)

    pppoe_monitor._pppoe_users_cache[router.id] = {
        "data": {
            "router_id": router.id,
            "router_name": router.name,
            "live": True,
            "users": [{
                "username": "kim",
                "disabled": False,
                "online": True,
                "address": "10.20.0.4",
                "uptime": "5h",
                "upload_bytes": 1_000,
                "download_bytes": 9_000,
                "upload_rate": "220000",
                "download_rate": "4400000",
                "customer": {"id": 3, "name": "Kim"},
            }],
            "summary": {
                "total": 1, "online": 1, "offline": 0, "disabled": 0,
                "total_upload_rate_bps": 220000,
                "total_download_rate_bps": 4400000,
            },
        },
        "timestamp": datetime.utcnow() - timedelta(minutes=3),
    }

    async def _dead_router(*args, **kwargs):
        return {"error": "timeout"}
    monkeypatch.setattr(pppoe_monitor, "run_with_guard", _dead_router)

    resp = await client.get(f"/api/pppoe/{router.id}/users")
    assert resp.status_code == 200
    body = resp.json()

    assert body["router_reachable"] is False
    assert body["fallback_reason"] == "timeout"
    assert body["users"][0]["online"] is False
    assert body["users"][0]["download_rate"] == "0"
    assert body["summary"]["online"] == 0
    assert body["users"][0]["download_bytes"] == 9_000

    pppoe_monitor._pppoe_users_cache.pop(router.id, None)

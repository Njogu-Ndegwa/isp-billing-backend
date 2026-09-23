"""Operations health monitor: rules, registry, section builders, delivery, endpoint.

Pins the detectors for the three incidents of 2026-09-21/22 that motivated the
monitor (see app/services/ops_health.py):

* a second app instance running the scheduler against another database
  (control_plane.multiple_writers) -- the fenced-AWS restart;
* a provisioning retry backlog with rising p95 -- "paying but not added";
* expired customers left ACTIVE on reachable routers -- the cleanup starvation;
* a safety-net removal spike -- the 1,062 deleted paid bindings.

Everything runs on the test database the conftest fixtures provide; the job
does no network I/O so nothing needs to be mocked except the clock inputs.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_metrics_routes as routes_module
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.db.database import get_db
from app.db.models import (
    AppInstanceHeartbeat,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    OpsHealthSnapshot,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningState,
    ResellerInboxMessage,
    RouterAvailabilityCheck,
    SubscriptionStatus,
)
from app.services import job_registry, ops_health
from app.services import ops_health_rules as rules
from app.services.auth import verify_token
from app.services.mikrotik_background import _record_safety_net_removals
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_monitor_state(monkeypatch):
    """Module memory (alert dedupe, job registry, cached DB identity) must not
    leak between tests, and the heartbeat must describe a deterministic
    'active writer with scheduler' regardless of the test env."""
    ops_health._alert_last_sent.clear()
    ops_health._DB_IDENTITY = None
    ops_health._pool_busy_logged = False
    job_registry.reset()
    monkeypatch.setattr(ops_health, "runtime_mode_name", lambda: "active")
    monkeypatch.setattr(ops_health, "scheduler_enabled", lambda: True)
    monkeypatch.setattr(ops_health.settings, "OPS_ALERT_SMS_PHONE", "", raising=False)
    monkeypatch.setattr(ops_health.settings, "OPS_ROUTE_STATE_FILE", "", raising=False)
    yield
    ops_health._alert_last_sent.clear()
    ops_health._DB_IDENTITY = None
    job_registry.reset()


@pytest_asyncio.fixture
async def app(session_factory):
    application = FastAPI()
    application.include_router(admin_metrics_router)

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
    monkeypatch.setattr(routes_module, "get_current_user", _fake)


_SOURCE_PK = iter(range(1, 10_000))


def _attempt(customer, router, *, state, created, attempted=None, updated=None, error=None):
    return ProvisioningAttempt(
        customer_id=customer.id,
        router_id=router.id,
        mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION,
        source_pk=next(_SOURCE_PK),  # (source_table, source_pk) is unique
        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
        provisioning_state=state,
        attempt_count=1,
        last_error=error,
        last_attempt_at=attempted,
        router_updated_at=updated,
        created_at=created,
        updated_at=updated or attempted or created,
    )


# ---------------------------------------------------------------------------
# pure helpers and rules
# ---------------------------------------------------------------------------

def test_percentile_interpolates_and_handles_edges():
    assert ops_health.percentile([], 95) is None
    assert ops_health.percentile([7], 95) == 7
    assert ops_health.percentile([1, 2, 3, 4, 5], 50) == 3
    # rank = 0.95 * 4 = 3.8 -> 4 + 0.8 * (5 - 4)
    assert ops_health.percentile([1, 2, 3, 4, 5], 95) == 4.8


def test_latency_block_ratio_needs_a_real_baseline():
    thin = ops_health.latency_block([10.0, 12.0], 5.0, baseline_samples=3)
    assert thin["ratio"] is None
    solid = ops_health.latency_block([10.0, 12.0], 5.0, baseline_samples=50)
    assert solid["ratio"] == pytest.approx(2.38, abs=0.01)
    assert solid["samples"] == 2


def test_rules_flag_second_writer_as_critical_and_sort_most_severe_first():
    sections = {
        "control_plane": {
            "active_writers": 2,
            "db_identity_mismatch": True,
            "minutes_since_writer_heartbeat": 0.2,
            "instances": [
                {"hostname": "hetzner", "runtime_mode": "active", "db_identity": "7301"},
                {"hostname": "aws", "runtime_mode": "active", "db_identity": "1188"},
            ],
        },
        "provisioning": {"counts": {"retry_pending": 30}, "window_minutes": 60,
                         "routers_with_backlog": 4},
    }
    alerts = rules.evaluate(sections, datetime(2026, 9, 22, 12, 0))
    keys = [a["key"] for a in alerts]
    assert keys[0] == "control_plane.multiple_writers"
    assert alerts[0]["severity"] == "critical"
    assert "aws" in alerts[0]["message"]
    assert "provisioning.retry_backlog" in keys
    backlog = next(a for a in alerts if a["key"] == "provisioning.retry_backlog")
    assert backlog["severity"] == "warning"


def test_rules_retry_backlog_thresholds_and_p95_floor():
    base = {"control_plane": {"active_writers": 1, "minutes_since_writer_heartbeat": 0.5}}
    quiet = rules.evaluate({**base, "provisioning": {"counts": {"retry_pending": 3}}})
    assert quiet == []

    critical = rules.evaluate({**base, "provisioning": {
        "counts": {"retry_pending": 344}, "window_minutes": 60, "routers_with_backlog": 59,
        "latency": {"end_to_end": {"p95": 75.0, "samples": 14, "ratio": None, "baseline_p95": None}},
    }})
    by_key = {a["key"]: a for a in critical}
    assert by_key["provisioning.retry_backlog"]["severity"] == "critical"
    assert by_key["provisioning.retry_backlog"]["value"] == 344
    # 60 s absolute floor fires even without a baseline ratio.
    assert by_key["provisioning.latency_p95"]["severity"] == "critical"


def test_rules_safety_net_spike_uses_baseline_multiplier():
    base = {"control_plane": {"active_writers": 1, "minutes_since_writer_heartbeat": 0.5}}
    none = rules.evaluate({**base, "safety_net": {"removals_last_hour": 5, "baseline_per_hour": 0.3}})
    assert none == []
    warn = rules.evaluate({**base, "safety_net": {"removals_last_hour": 40, "baseline_per_hour": 0.3}})
    assert [a["severity"] for a in warn] == ["warning"]
    crit = rules.evaluate({**base, "safety_net": {"removals_last_hour": 1062, "baseline_per_hour": 0.3}})
    assert crit[0]["key"] == "safety_net.spike" and crit[0]["severity"] == "critical"


def test_rules_no_writer_heartbeat_escalates_with_silence():
    warn = rules.evaluate({"control_plane": {"active_writers": 0, "minutes_since_writer_heartbeat": 4}})
    assert [(a["key"], a["severity"]) for a in warn] == [("control_plane.no_writer", "warning")]
    crit = rules.evaluate({"control_plane": {"active_writers": 0, "minutes_since_writer_heartbeat": None}})
    assert crit[0]["severity"] == "critical"


def test_callback_silence_only_counts_during_kenyan_daytime():
    pay = {"payments": {"counts": {"created": 12}, "minutes_since_last_completed": 45}}
    base = {"control_plane": {"active_writers": 1, "minutes_since_writer_heartbeat": 0.5}}
    # 09:00 UTC = 12:00 EAT -> in hours
    day = rules.evaluate({**base, **pay}, datetime(2026, 9, 22, 9, 0))
    assert [a["key"] for a in day] == ["payments.callback_silence"]
    # 23:30 UTC = 02:30 EAT -> nobody is buying; stay quiet
    night = rules.evaluate({**base, **pay}, datetime(2026, 9, 22, 23, 30))
    assert night == []


def test_section_and_overall_status_roll_up():
    alerts = [{"key": "expiry.hot_backlog", "severity": "warning"}]
    assert rules.section_status("expiry", {"expired_active_hot": 126}, alerts) == "warning"
    # No alert, but above the "watch" hint threshold.
    assert rules.section_status("expiry", {"expired_active_hot": 60}, []) == "watch"
    assert rules.section_status("expiry", {"expired_active_hot": 0}, []) == "healthy"
    assert rules.section_status("tunnels", {"available": False}, []) == "unknown"
    assert rules.overall_status({
        "a": {"status": "healthy"}, "b": {"status": "critical"}, "c": {"status": "watch"},
    }) == "critical"


# ---------------------------------------------------------------------------
# job registry
# ---------------------------------------------------------------------------

def test_job_registry_tracks_duration_skips_and_staleness():
    t0 = datetime(2026, 9, 22, 12, 0, 0)
    job_registry.set_interval("cleanup_expired_users", 67, name="Cleanup", now=t0)
    job_registry.record_started("cleanup_expired_users", now=t0)
    job_registry.record_finished("cleanup_expired_users", now=t0 + timedelta(seconds=55))
    job_registry.record_skipped("cleanup_expired_users", now=t0 + timedelta(minutes=1))
    job_registry.record_skipped("cleanup_expired_users", now=t0 + timedelta(minutes=2))

    item = job_registry.get("cleanup_expired_users", now=t0 + timedelta(minutes=3))
    assert item["last_duration_seconds"] == 55
    assert item["missed_or_skipped_last_hour"] == 2
    assert item["stale"] is False

    # 3 x 67 s < the 5-minute floor, so 6 minutes of silence is stale.
    later = job_registry.get("cleanup_expired_users", now=t0 + timedelta(minutes=7))
    assert later["stale"] is True
    # Skips older than an hour age out.
    aged = job_registry.get("cleanup_expired_users", now=t0 + timedelta(hours=2))
    assert aged["missed_or_skipped_last_hour"] == 0

    job_registry.record_finished("cleanup_expired_users", now=t0 + timedelta(minutes=8),
                                 error=RuntimeError("router timeout"))
    assert "router timeout" in job_registry.get("cleanup_expired_users")["last_error"]


# ---------------------------------------------------------------------------
# section builders against seeded rows
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_provisioning_section_counts_backlog_and_latency(db, now):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    other = await make_router(db, reseller)
    custs = [await make_customer(db, reseller, plan, router) for _ in range(6)]

    recent = now - timedelta(minutes=10)
    for c in custs[:3]:
        db.add(_attempt(c, router, state=ProvisioningState.RETRY_PENDING, created=recent,
                        attempted=recent, error="timed out after 75s"))
    db.add(_attempt(custs[3], other, state=ProvisioningState.RETRY_PENDING, created=recent,
                    attempted=recent))
    # Two confirmed: 4 s and 20 s end-to-end, 1 s and 10 s router calls.
    db.add(_attempt(custs[4], router, state=ProvisioningState.ROUTER_UPDATED,
                    created=recent, attempted=recent + timedelta(seconds=3),
                    updated=recent + timedelta(seconds=4)))
    db.add(_attempt(custs[5], router, state=ProvisioningState.ROUTER_UPDATED,
                    created=recent, attempted=recent + timedelta(seconds=10),
                    updated=recent + timedelta(seconds=20)))
    # Old, outside the 60-minute window: ignored.
    db.add(_attempt(custs[0], router, state=ProvisioningState.FAILED,
                    created=now - timedelta(hours=5), attempted=now - timedelta(hours=5)))
    await db.commit()

    section = await ops_health.build_provisioning_section(now)
    assert section["counts"]["retry_pending"] == 4
    assert section["counts"]["router_updated"] == 2
    assert section["counts"]["failed"] == 0
    assert section["success_ratio"] == pytest.approx(2 / 6, abs=0.001)
    assert section["routers_with_backlog"] == 1
    top = section["top_routers"][0]
    assert top["router_id"] == router.id and top["pending"] == 3
    assert top["last_error"] == "timed out after 75s"
    e2e = section["latency"]["end_to_end"]
    assert e2e["samples"] == 2 and e2e["p50"] == 12 and e2e["p95"] == pytest.approx(19.2)
    call = section["latency"]["router_call"]
    assert call["p95"] == pytest.approx(9.55)


def test_tunnel_type_follows_management_ip_ranges():
    assert ops_health.tunnel_type_for_ip("10.0.0.244") == "wireguard"
    assert ops_health.tunnel_type_for_ip("10.0.99.7") == "wireguard"
    assert ops_health.tunnel_type_for_ip("10.0.100.12") == "l2tp"
    assert ops_health.tunnel_type_for_ip("10.251.3.9") == "wg2_insurance"
    assert ops_health.tunnel_type_for_ip("10.250.0.44") == "aws_insurance"
    assert ops_health.tunnel_type_for_ip("192.168.88.1") == "other"
    assert ops_health.tunnel_type_for_ip(None) == "other"
    assert ops_health.tunnel_type_for_ip("not-an-ip") == "other"


@pytest.mark.asyncio
async def test_provisioning_section_splits_latency_and_backlog_by_tunnel(db, now):
    """L2TP routers slow while WireGuard stays flat: the split must show it and
    every problematic router must carry its tunnel."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    wg = await make_router(db, reseller, ip_address="10.0.0.5", name="WG-A")
    l2 = await make_router(db, reseller, ip_address="10.0.100.9", name="L2TP-B")
    l2_backlog = await make_router(db, reseller, ip_address="10.0.101.3", name="L2TP-C")
    recent = now - timedelta(minutes=5)

    for secs in (1.0, 1.5, 2.0):
        c = await make_customer(db, reseller, plan, wg)
        db.add(_attempt(c, wg, state=ProvisioningState.ROUTER_UPDATED, created=recent,
                        attempted=recent, updated=recent + timedelta(seconds=secs)))
    for secs in (30.0, 40.0, 45.0, 50.0, 70.0):   # >= 5 samples: enough to alert
        c = await make_customer(db, reseller, plan, l2)
        db.add(_attempt(c, l2, state=ProvisioningState.ROUTER_UPDATED, created=recent,
                        attempted=recent, updated=recent + timedelta(seconds=secs)))
    for _ in range(4):
        c = await make_customer(db, reseller, plan, l2_backlog)
        db.add(_attempt(c, l2_backlog, state=ProvisioningState.RETRY_PENDING,
                        created=recent, attempted=recent, error="timeout"))
    c = await make_customer(db, reseller, plan, wg)
    db.add(_attempt(c, wg, state=ProvisioningState.RETRY_PENDING, created=recent, attempted=recent))
    await db.commit()

    section = await ops_health.build_provisioning_section(now)
    by_tunnel = section["latency"]["by_tunnel"]
    assert list(by_tunnel) == ["wireguard", "l2tp"]
    assert by_tunnel["wireguard"]["router_call"]["p95"] == pytest.approx(1.95)
    assert by_tunnel["wireguard"]["routers"] == 1
    assert by_tunnel["l2tp"]["router_call"]["p95"] == pytest.approx(66.0)
    assert by_tunnel["l2tp"]["router_call"]["samples"] == 5
    assert by_tunnel["l2tp"]["routers"] == 2
    assert section["backlog_by_tunnel"] == {
        "wireguard": {"routers": 1, "pending": 1, "routers_with_backlog": 0},
        "l2tp": {"routers": 1, "pending": 4, "routers_with_backlog": 1},
    }
    top = section["top_routers"][0]
    assert top["router_name"] == "L2TP-C" and top["tunnel"] == "l2tp"
    assert section["top_routers"][1]["tunnel"] == "wireguard"

    # The per-tunnel p95s are stored flat so the 7-day baseline can be per tunnel.
    metrics = ops_health.metrics_from_sections({"provisioning": section})
    assert metrics["provisioning_p95_router_call__l2tp"] == pytest.approx(66.0)
    assert metrics["provisioning_samples_router_call__wireguard"] == 3

    # And the alert names the tunnel (L2TP p95 is over the 60 s floor).
    alerts = rules.evaluate({"provisioning": section,
                             "control_plane": {"active_writers": 1,
                                               "minutes_since_writer_heartbeat": 0.5}})
    keys = {a["key"]: a for a in alerts}
    assert keys["provisioning.tunnel_latency_l2tp"]["severity"] == "critical"
    assert "L2TP/IPsec" in keys["provisioning.tunnel_latency_l2tp"]["title"]
    assert "2 routers use this tunnel" in keys["provisioning.tunnel_latency_l2tp"]["message"]
    assert "provisioning.tunnel_latency_wireguard" not in keys
    assert rules.section_status("provisioning", section, alerts) == "critical"


@pytest.mark.asyncio
async def test_expiry_section_splits_hot_from_quarantined_and_measures_removal(db, now):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    online = await make_router(db, reseller, last_status=True, last_checked_at=now,
                               last_online_at=now)
    dead = await make_router(db, reseller, last_status=False, last_checked_at=now,
                             last_online_at=now - timedelta(days=4))
    hot_old = await make_customer(db, reseller, plan, online, status=CustomerStatus.ACTIVE,
                                  expiry=now - timedelta(minutes=41))
    await make_customer(db, reseller, plan, online, status=CustomerStatus.ACTIVE,
                        expiry=now - timedelta(minutes=5))
    for _ in range(3):
        await make_customer(db, reseller, plan, dead, status=CustomerStatus.ACTIVE,
                            expiry=now - timedelta(days=2))
    # A suspended reseller's router looks online but is cut off at the platform
    # level: its 16-day-old expiries must not masquerade as the oldest hot one
    # (the first live alert on 2026-09-23 did exactly that).
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    cut_off = await make_router(db, suspended, last_status=True, last_checked_at=now,
                                last_online_at=now)
    for _ in range(2):
        await make_customer(db, suspended, plan, cut_off, status=CustomerStatus.ACTIVE,
                            expiry=now - timedelta(days=16))
    # Already removed: does not count as a backlog, but feeds removal latency.
    removed = await make_customer(db, reseller, plan, online, status=CustomerStatus.INACTIVE,
                                  expiry=now - timedelta(minutes=30))
    db.add(ProvisioningLog(customer_id=removed.id, router_id=online.id,
                           action="hotspot_deactivation", status="success",
                           details="Expiry cleanup removed hotspot access",
                           log_date=now - timedelta(minutes=25)))
    await db.commit()

    section = await ops_health.build_expiry_section(now)
    assert section["expired_active_total"] == 7
    assert section["expired_active_hot"] == 2
    assert section["expired_active_quarantined"] == 3
    assert section["expired_active_suspended_owner"] == 2
    assert section["oldest_hot_expired_minutes"] == pytest.approx(41, abs=0.1)
    assert section["removal_latency"]["samples"] == 1
    assert section["removal_latency"]["p95"] == pytest.approx(300)
    assert hot_old.expiry < now
    # Factory routers sit on 10.0.0.2 (WireGuard); quarantined ones are excluded.
    assert section["hot_by_tunnel"] == {"wireguard": {"routers": 1, "customers": 2}}
    assert section["removal_latency_by_tunnel"]["wireguard"]["p95"] == pytest.approx(300)
    metrics = ops_health.metrics_from_sections({"expiry": section})
    assert metrics["expiry_samples_removal__wireguard"] == 1


@pytest.mark.asyncio
async def test_payments_section_measures_callback_latency_and_stuck_pending(db, now):
    def tx(i, status, created, updated):
        return MpesaTransaction(
            checkout_request_id=f"ws_CO_{i}", phone_number="254700000000", amount=20,
            reference="Router-1", status=status, created_at=created, updated_at=updated,
        )
    db.add(tx(1, MpesaTransactionStatus.completed, now - timedelta(minutes=20),
              now - timedelta(minutes=20) + timedelta(seconds=8)))
    db.add(tx(2, MpesaTransactionStatus.completed, now - timedelta(minutes=3),
              now - timedelta(minutes=3) + timedelta(seconds=22)))
    db.add(tx(3, MpesaTransactionStatus.failed, now - timedelta(minutes=9), now - timedelta(minutes=9)))
    db.add(tx(4, MpesaTransactionStatus.pending, now - timedelta(minutes=9), now - timedelta(minutes=9)))
    db.add(tx(5, MpesaTransactionStatus.pending, now - timedelta(minutes=1), now - timedelta(minutes=1)))
    await db.commit()

    section = await ops_health.build_payments_section(now)
    assert section["counts"] == {"created": 5, "completed": 2, "failed": 1,
                                 "pending": 2, "pending_over_5m": 1}
    assert section["callback_latency"]["p50"] == 15
    assert section["callback_latency"]["p95"] == pytest.approx(21.3)
    assert section["minutes_since_last_completed"] == pytest.approx(2.6, abs=0.1)


@pytest.mark.asyncio
async def test_tunnels_section_counts_fleet_drops(db, now):
    reseller = await make_reseller(db)
    routers = [
        await make_router(db, reseller, last_status=True, last_checked_at=now)
        for _ in range(3)
    ]
    stale = await make_router(db, reseller, last_status=True,
                              last_checked_at=now - timedelta(hours=1))
    for r in routers[:2]:
        db.add(RouterAvailabilityCheck(router_id=r.id, is_online=True, source="t",
                                       checked_at=now - timedelta(minutes=8)))
        db.add(RouterAvailabilityCheck(router_id=r.id, is_online=False, source="t",
                                       checked_at=now - timedelta(minutes=4)))
    # Went offline 15 minutes ago: outside the 10-minute drop window.
    db.add(RouterAvailabilityCheck(router_id=routers[2].id, is_online=True, source="t",
                                   checked_at=now - timedelta(minutes=18)))
    db.add(RouterAvailabilityCheck(router_id=routers[2].id, is_online=False, source="t",
                                   checked_at=now - timedelta(minutes=15)))
    await db.commit()

    section = await ops_health.build_tunnels_section(now)
    assert section["counts"] == {"online": 3, "offline": 0, "stale": 1, "total": 4}
    # Factory routers all sit on 10.0.0.2 -> one WireGuard bucket.
    assert section["by_tunnel"] == {"wireguard": {"online": 3, "offline": 0, "stale": 1, "total": 4}}
    assert section["recent_drops_10m"] == 2
    assert section["platform_event"] is False
    assert section["control_path"]["available"] is False
    assert stale.id


def test_count_recent_drops_needs_an_online_to_offline_edge():
    now = datetime(2026, 9, 22, 12, 0)
    checks = [
        (1, now - timedelta(minutes=6), True), (1, now - timedelta(minutes=2), False),
        (2, now - timedelta(minutes=6), False), (2, now - timedelta(minutes=2), False),
        (3, now - timedelta(minutes=2), False),
    ]
    assert ops_health.count_recent_drops(checks, now) == 1


def test_route_state_file_reader(tmp_path):
    assert ops_health.read_route_state_file("")["available"] is False
    assert ops_health.read_route_state_file(str(tmp_path / "missing.json"))["available"] is False
    p = tmp_path / "routes.json"
    p.write_text('{"checked_at": "2026-09-22T19:00:00Z", "native": 76, "transit_fallback": 7, "unrouted": 10}')
    state = ops_health.read_route_state_file(str(p))
    assert state == {"available": True, "native": 76, "transit_fallback": 7,
                     "unrouted": 10, "checked_at": "2026-09-22T19:00:00Z"}


@pytest.mark.asyncio
async def test_safety_net_removals_are_logged_per_router_without_a_customer(
    db, session_factory, monkeypatch, now,
):
    # mikrotik_background binds async_session at import time; point it at the
    # test database like the conftest does for the other background modules.
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    reseller = await make_reseller(db)
    r1 = await make_router(db, reseller)
    r2 = await make_router(db, reseller)

    await _record_safety_net_removals({r1.id: 500, r2.id: 562})

    rows = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.action == ops_health.SAFETY_NET_ACTION))).scalars().all()
    assert sorted(r.details for r in rows) == ["count=500", "count=562"]
    assert all(r.customer_id is None for r in rows)

    section = await ops_health.build_safety_net_section(datetime.utcnow())
    assert section["removals_last_hour"] == 1062
    assert section["last_removal_at"] is not None


# ---------------------------------------------------------------------------
# heartbeat, delivery, full cycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_heartbeat_upserts_one_row_per_process(db):
    first = await ops_health.write_heartbeat()
    second = await ops_health.write_heartbeat()
    assert first["instance_id"] == second["instance_id"]
    rows = (await db.execute(select(AppInstanceHeartbeat))).scalars().all()
    assert len(rows) == 1
    assert rows[0].runtime_mode == "active" and rows[0].scheduler_enabled is True
    assert rows[0].db_identity  # "sqlite" locally, pg system identifier in CI


@pytest.mark.asyncio
async def test_second_active_writer_alerts_admins_once_per_dedupe_window(db, now):
    admin_a = await make_admin(db)
    admin_b = await make_admin(db)
    await make_reseller(db)
    rogue = AppInstanceHeartbeat(
        instance_id="aws-stale-1234", hostname="ip-172-31-0-1", runtime_mode="active",
        scheduler_enabled=True, db_identity="1188", app_version="old",
        started_at=now - timedelta(hours=2), last_seen_at=now,   # heartbeating NOW = concurrent
    )
    db.add(rogue)
    await db.commit()

    async def _rogue_still_alive(at: datetime) -> None:
        rogue.last_seen_at = at - timedelta(seconds=30)
        await db.commit()

    result = await ops_health.run_cycle(now)
    assert result["overall_status"] == "critical"
    assert result["delivered"] == 2 and result["sms_queued"] == 0

    inbox = (await db.execute(select(ResellerInboxMessage))).scalars().all()
    assert {m.recipient_user_id for m in inbox} == {admin_a.id, admin_b.id}
    assert "Multiple active writers" in inbox[0].subject
    assert "ip-172-31-0-1" in inbox[0].body

    snap = await ops_health.load_latest_snapshot()
    keys = [a["key"] for a in snap["alerts"]]
    assert keys[0] == "control_plane.multiple_writers"
    assert snap["sections"]["control_plane"]["active_writers"] == 2
    assert snap["sections"]["control_plane"]["db_identity_mismatch"] is True
    assert snap["alerts"][0]["notified_at"] is not None

    # Same alert ten minutes later: nothing new is sent, but `since` is kept.
    await _rogue_still_alive(now + timedelta(minutes=10))
    again = await ops_health.run_cycle(now + timedelta(minutes=10))
    assert again["delivered"] == 0
    assert len((await db.execute(select(ResellerInboxMessage))).scalars().all()) == 2
    latest = await ops_health.load_latest_snapshot()
    assert latest["alerts"][0]["key"] == "control_plane.multiple_writers"
    assert latest["alerts"][0]["since"] == snap["alerts"][0]["since"]

    # Past the 30-minute dedupe window it is re-sent.
    await _rogue_still_alive(now + timedelta(minutes=31))
    third = await ops_health.run_cycle(now + timedelta(minutes=31))
    assert third["delivered"] == 2

    # Once the rogue instance stops heartbeating the alert clears on its own.
    cleared = await ops_health.run_cycle(now + timedelta(minutes=40))
    assert cleared["overall_status"] == "healthy" and cleared["alerts"] == 0


@pytest.mark.asyncio
async def test_deploy_handover_is_not_a_second_writer(db, monkeypatch, now):
    """The outgoing container of a deploy still has a heartbeat inside the live
    window but has not written one since the new process started: superseded,
    not concurrent. Fired a false critical after every deploy on 2026-09-23."""
    # Pin "our" process start so the test does not depend on how long the
    # pytest worker has been alive (a fresh CI worker starts < 70 s before this).
    monkeypatch.setattr(ops_health, "_PROCESS_STARTED_AT", now - timedelta(seconds=30))
    await make_admin(db)
    db.add(AppInstanceHeartbeat(
        instance_id="old-container-aaaa", hostname="4110e55ae77d", runtime_mode="active",
        scheduler_enabled=True, db_identity="7566", app_version="prev",
        started_at=now - timedelta(hours=3), last_seen_at=now - timedelta(seconds=70),
    ))
    await db.commit()
    # Our own heartbeat: started when this test process started (before `now`),
    # written at `now` -> the newest instance.
    result = await ops_health.run_cycle(now)
    assert result["delivered"] == 0
    snap = await ops_health.load_latest_snapshot()
    cp = snap["sections"]["control_plane"]
    assert cp["active_writers"] == 1
    assert cp["db_identity_mismatch"] is False
    by_id = {i["instance_id"]: i for i in cp["instances"]}
    assert by_id["old-container-aaaa"]["superseded"] is True
    assert [k for k in snap["alerts"] if k["key"].startswith("control_plane")] == []

    # ...but if that "old" instance keeps heartbeating after we started, it is
    # a real second writer and the alert fires on the next cycle.
    row = await db.get(AppInstanceHeartbeat, "old-container-aaaa")
    row.last_seen_at = now + timedelta(minutes=1)
    await db.commit()
    result = await ops_health.run_cycle(now + timedelta(minutes=1))
    assert result["overall_status"] == "critical" and result["delivered"] == 1
    snap = await ops_health.load_latest_snapshot()
    assert snap["sections"]["control_plane"]["active_writers"] == 2


@pytest.mark.asyncio
async def test_retire_heartbeat_removes_own_row(db):
    await ops_health.write_heartbeat()
    assert await ops_health.retire_heartbeat() is True
    assert (await db.execute(select(AppInstanceHeartbeat))).scalars().all() == []
    assert await ops_health.retire_heartbeat() is False


@pytest.mark.asyncio
async def test_dedupe_survives_restart_via_snapshot_notified_at(now):
    alerts = [{"key": "expiry.hot_backlog", "severity": "warning",
               "notified_at": ops_health._iso(now - timedelta(minutes=5)),
               "notified_severity": "warning"}]
    assert ops_health.select_alerts_to_notify(alerts, now, memory={}) == []
    escalated = [{**alerts[0], "severity": "critical"}]
    assert ops_health.select_alerts_to_notify(escalated, now, memory={}) == escalated


@pytest.mark.asyncio
async def test_cycle_skips_when_pool_is_busy_but_still_heartbeats(db, monkeypatch, now):
    monkeypatch.setattr(ops_health, "db_pool_snapshot", lambda: {
        "checked_out": 20, "checked_out_percent": 67.0, "pressure": {"level": "warning"},
    })
    result = await ops_health.run_cycle(now)
    assert result == {"skipped": "db_pool_busy"}
    assert len((await db.execute(select(AppInstanceHeartbeat))).scalars().all()) == 1
    assert (await db.execute(select(OpsHealthSnapshot))).scalars().all() == []


@pytest.mark.asyncio
async def test_healthy_cycle_stores_snapshot_metrics_and_prunes_old_rows(db, now):
    await make_admin(db)
    db.add(OpsHealthSnapshot(generated_at=now - timedelta(days=8), overall_status="healthy",
                             payload={"sections": {}, "alerts": []}, metrics={}))
    await db.commit()

    result = await ops_health.run_cycle(now)
    assert result["overall_status"] == "healthy"
    assert result["alerts"] == 0 and result["delivered"] == 0

    rows = (await db.execute(select(OpsHealthSnapshot))).scalars().all()
    assert len(rows) == 1  # the 8-day-old row is pruned
    metrics = rows[0].metrics
    assert metrics["active_writers"] == 1
    assert metrics["provisioning_retry_pending"] == 0
    assert set(metrics) >= {"provisioning_p95_end_to_end", "payments_p95_callback",
                            "expiry_active_hot", "tunnels_offline", "safety_net_removals"}
    assert rows[0].payload["baseline_source"] == "raw"


def test_history_points_take_one_snapshot_per_five_minute_bucket():
    t0 = datetime(2026, 9, 22, 12, 0, 0)
    rows = [(t0 + timedelta(seconds=60 * i), {"tunnels_offline": i}) for i in range(12)]
    points = ops_health.sample_history_points(rows)
    assert [p["tunnels_offline"] for p in points] == [0, 5, 10]
    assert points[0]["t"] == "2026-09-22T12:00:00Z"


# ---------------------------------------------------------------------------
# endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ops_health_endpoint_is_admin_only(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    response = await client.get("/api/admin/ops-health")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_ops_health_endpoint_reports_unknown_before_first_snapshot(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    body = (await client.get("/api/admin/ops-health")).json()
    assert body["overall_status"] == "unknown"
    assert body["generated_at"] is None and body["snapshot_age_seconds"] is None
    assert body["alerts"] == [] and body["sections"] == {}
    assert body["history"] == {"points": []}


@pytest.mark.asyncio
async def test_ops_health_endpoint_serves_latest_snapshot_and_history(db, client, monkeypatch):
    _auth_as(monkeypatch, await make_admin(db))
    now = datetime.utcnow()
    await ops_health.run_cycle(now - timedelta(minutes=2))

    body = (await client.get("/api/admin/ops-health")).json()
    assert body["overall_status"] == "healthy"
    assert 100 <= body["snapshot_age_seconds"] <= 200
    assert set(body["sections"]) == {"provisioning", "payments", "expiry", "tunnels",
                                     "control_plane", "safety_net", "jobs", "db_pool"}
    assert body["sections"]["control_plane"]["active_writers"] == 1
    assert len(body["history"]["points"]) == 1

    history = (await client.get("/api/admin/ops-health/history?hours=1")).json()
    assert len(history["points"]) == 1
    assert (await client.get("/api/admin/ops-health/history?hours=0")).status_code == 422

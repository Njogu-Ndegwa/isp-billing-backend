"""Look-back window report: arbitrary time slice, optional single router."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import app.api.admin_metrics_routes as routes_module
from app.api.admin_metrics_routes import router as admin_metrics_router
from app.db.database import get_db
from app.db.models import (
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningState,
)
from app.services import ops_health_window as window
from app.services.auth import verify_token
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router

_PK = iter(range(50_000, 60_000))


def _attempt(customer, router, *, state, created, attempted=None, updated=None, tries=1, error=None):
    return ProvisioningAttempt(
        customer_id=customer.id, router_id=router.id, mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_PK),
        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, provisioning_state=state,
        attempt_count=tries, last_error=error, last_attempt_at=attempted or created,
        router_updated_at=updated, created_at=created, updated_at=updated or attempted or created,
    )


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


def test_clamp_window_orders_and_caps():
    end = datetime(2026, 9, 23, 12, 0)
    assert window.clamp_window(end, end - timedelta(hours=3)) == (end - timedelta(hours=3), end)
    start, capped_end = window.clamp_window(end - timedelta(days=40), end)
    assert capped_end == end and start == end - window.MAX_WINDOW


@pytest.mark.asyncio
async def test_window_report_isolates_the_slice_and_ranks_routers(db, now):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    wg = await make_router(db, reseller, ip_address="10.0.0.7", name="WG fast")
    l2 = await make_router(db, reseller, ip_address="10.0.100.7", name="L2TP slow")
    t0 = now - timedelta(hours=6)          # slice: 6h..3h ago
    t1 = now - timedelta(hours=3)

    # Inside the slice: 3 fast WG deliveries, 2 slow L2TP deliveries, 2 L2TP stuck.
    for secs in (5, 6, 7):
        c = await make_customer(db, reseller, plan, wg)
        db.add(_attempt(c, wg, state=ProvisioningState.ROUTER_UPDATED, created=t0 + timedelta(minutes=10),
                        updated=t0 + timedelta(minutes=10, seconds=secs)))
    for secs in (60, 120):
        c = await make_customer(db, reseller, plan, l2)
        db.add(_attempt(c, l2, state=ProvisioningState.ROUTER_UPDATED, created=t0 + timedelta(minutes=20),
                        attempted=t0 + timedelta(minutes=20, seconds=secs - 30),
                        updated=t0 + timedelta(minutes=20, seconds=secs), tries=3))
    for _ in range(2):
        c = await make_customer(db, reseller, plan, l2)
        db.add(_attempt(c, l2, state=ProvisioningState.RETRY_PENDING, created=t0 + timedelta(minutes=30),
                        tries=9, error="Failed to connect"))
    # Outside the slice (the "incident" that must not pollute it): a 1-hour delivery.
    c = await make_customer(db, reseller, plan, wg)
    db.add(_attempt(c, wg, state=ProvisioningState.ROUTER_UPDATED, created=now - timedelta(hours=1),
                    updated=now - timedelta(minutes=0)))
    # Expiry removals: one inside (10 min after expiry), one outside.
    removed = await make_customer(db, reseller, plan, wg, status=CustomerStatus.INACTIVE,
                                  expiry=t0 + timedelta(minutes=40))
    db.add(ProvisioningLog(customer_id=removed.id, router_id=wg.id, action="hotspot_deactivation",
                           status="success", log_date=t0 + timedelta(minutes=50)))
    db.add(ProvisioningLog(customer_id=removed.id, router_id=wg.id, action="hotspot_deactivation",
                           status="success", log_date=now - timedelta(minutes=5)))
    # Payments inside the slice.
    for i, secs in enumerate((8, 12, 30)):
        db.add(MpesaTransaction(checkout_request_id=f"ws_{i}", phone_number="254700000000", amount=20,
                                reference="r", status=MpesaTransactionStatus.completed,
                                created_at=t0 + timedelta(minutes=5), updated_at=t0 + timedelta(minutes=5, seconds=secs)))
    await db.commit()

    report = await window.build_window_report(t0, t1)
    prov = report["provisioning"]
    assert prov["counts"]["router_updated"] == 5
    assert prov["counts"]["retry_pending"] == 2
    assert prov["success_ratio"] == pytest.approx(5 / 7, abs=0.001)
    assert prov["end_to_end"]["samples"] == 5
    assert prov["end_to_end"]["max"] == 120          # the 1-hour outlier is outside the slice
    assert prov["by_tunnel"]["wireguard"]["end_to_end"]["p95"] == pytest.approx(6.9)
    assert prov["by_tunnel"]["l2tp"]["not_delivered"] == 2
    assert prov["retries_per_delivery"]["max"] == 3
    # Worst router first: the one with undelivered payments.
    assert prov["routers"][0]["router_name"] == "L2TP slow"
    assert prov["routers"][0]["not_delivered"] == 2
    assert prov["routers"][0]["last_error"] == "Failed to connect"
    assert prov["routers"][0]["tunnel"] == "l2tp"
    assert prov["routers"][1]["router_name"] == "WG fast"
    assert report["expiry"]["removals"] == 1
    assert report["expiry"]["removal_latency"]["p95"] == pytest.approx(600)
    # Enforcement: `removed` expired in the slice and was removed -> 100%.
    assert report["expiry"]["enforcement"]["expired"] == 1
    assert report["expiry"]["enforcement"]["pct_removed"] == 100.0
    assert report["expiry"]["enforcement"]["routers"] == []
    assert report["payments"]["counts"]["completed"] == 3
    assert report["payments"]["callback_latency"]["p95"] == pytest.approx(28.2)
    assert report["window"]["hours"] == 3
    assert report["truncated"] is False

    # Single-router view: only that router, payments omitted, router echoed back.
    single = await window.build_window_report(t0, t1, router_id=l2.id)
    assert single["router"] == {"router_id": l2.id, "router_name": "L2TP slow", "tunnel": "l2tp"}
    assert single["provisioning"]["counts"]["router_updated"] == 2
    assert single["provisioning"]["counts"]["retry_pending"] == 2
    assert list(single["provisioning"]["by_tunnel"]) == ["l2tp"]
    assert single["payments"] is None
    assert single["expiry"]["removals"] == 0


@pytest.mark.asyncio
async def test_window_endpoint_is_admin_only_and_parses_bounds(db, client, monkeypatch, now):
    _auth_as(monkeypatch, await make_reseller(db))
    assert (await client.get("/api/admin/ops-health/window", params={"start": "2026-09-22T18:00:00Z"})).status_code == 403

    _auth_as(monkeypatch, await make_admin(db))
    r = await client.get("/api/admin/ops-health/window",
                         params={"start": "2026-09-22T18:00:00Z", "end": "2026-09-22T21:00:00Z"})
    assert r.status_code == 200
    body = r.json()
    assert body["window"] == {"start": "2026-09-22T18:00:00Z", "end": "2026-09-22T21:00:00Z", "hours": 3}
    assert body["provisioning"]["counts"]["router_updated"] == 0
    assert body["payments"]["counts"]["created"] == 0
    # end defaults to now
    r = await client.get("/api/admin/ops-health/window", params={"start": (now - timedelta(hours=2)).isoformat()})
    assert r.status_code == 200 and 1.9 <= r.json()["window"]["hours"] <= 2.1
    assert (await client.get("/api/admin/ops-health/window")).status_code == 422


@pytest.mark.asyncio
async def test_enforcement_percentage_and_drilldown_by_reason(db, now):
    from app.db.models import SubscriptionStatus
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    online = await make_router(db, reseller, ip_address="10.0.0.9", name="Online",
                               last_status=True, last_checked_at=now, last_online_at=now)
    stale = await make_router(db, reseller, ip_address="10.0.0.10", name="Stale online",
                              last_status=True, last_checked_at=now - timedelta(hours=20),
                              last_online_at=now - timedelta(hours=20))
    dead = await make_router(db, reseller, ip_address="10.0.100.11", name="Dead",
                             last_status=False, last_checked_at=now, last_online_at=now - timedelta(days=5))
    susp_owner = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    cut = await make_router(db, susp_owner, ip_address="10.0.0.12", name="Cut off",
                            last_status=True, last_checked_at=now, last_online_at=now)
    t0, t1 = now - timedelta(hours=6), now - timedelta(hours=1)
    exp = t0 + timedelta(hours=1)

    # 4 expired in slice on the online router: 3 removed (log), 1 still active.
    for i in range(4):
        c = await make_customer(db, reseller, plan, online, status=CustomerStatus.ACTIVE, expiry=exp)
        if i < 3:
            db.add(ProvisioningLog(customer_id=c.id, router_id=online.id, action="hotspot_deactivation",
                                   status="success", log_date=exp + timedelta(minutes=2)))
    # 1 removed by status flip without a log (still counts as enforced).
    await make_customer(db, reseller, plan, online, status=CustomerStatus.INACTIVE, expiry=exp)
    # 2 still active on the stale-online router, 2 on the dead router, 1 on the cut-off one.
    for _ in range(2):
        await make_customer(db, reseller, plan, stale, status=CustomerStatus.ACTIVE, expiry=exp)
    for _ in range(2):
        await make_customer(db, reseller, plan, dead, status=CustomerStatus.ACTIVE, expiry=exp)
    await make_customer(db, susp_owner, plan, cut, status=CustomerStatus.ACTIVE, expiry=exp)
    # Expired outside the slice: ignored.
    await make_customer(db, reseller, plan, online, status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=10))
    await db.commit()

    enf = (await window.build_window_report(t0, t1))["expiry"]["enforcement"]
    assert (enf["expired"], enf["removed"], enf["still_active"]) == (10, 4, 6)
    assert enf["pct_removed"] == 40.0
    assert enf["by_reason"] == {"router_online_not_removed": 1, "router_status_stale": 2,
                                "router_offline_3d_plus": 2, "owner_suspended": 1}
    by_name = {r["router_name"]: r for r in enf["routers"]}
    assert by_name["Stale online"]["reason"] == "router_status_stale"
    assert by_name["Dead"]["reason"] == "router_offline_3d_plus"
    assert by_name["Cut off"]["reason"] == "owner_suspended"
    assert by_name["Online"]["still_active"] == 1
    assert by_name["Online"]["oldest_expired_minutes"] == pytest.approx(300, abs=1)
    assert enf["routers"][0]["still_active"] == 2   # worst first

    single = (await window.build_window_report(t0, t1, router_id=dead.id))["expiry"]["enforcement"]
    assert (single["expired"], single["pct_removed"]) == (2, 0.0)

"""Fleet CPU per router model (router_cpu_buckets) and the admin chart endpoint."""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import app.api.admin_metrics_routes as amr
from app.db.database import get_db
from app.db.models import AppDeploy, AppInstanceHeartbeat, RouterCpuBucket, UserRole
from app.services import router_cpu_history as ch
from app.services import router_health as rh
from app.services.auth import verify_token
from tests.factories import make_reseller, make_router

T0 = datetime(2026, 11, 23, 10, 0, 0)        # a bucket boundary
RB951 = "RB951Ui-2HnD"


@pytest.fixture(autouse=True)
def fresh_tally(monkeypatch):
    ch._open.clear()
    monkeypatch.setattr(ch, "_last_prune", None)
    monkeypatch.setattr(ch, "_flush_lock", None)
    spawned = []
    monkeypatch.setattr(ch, "_spawn", lambda coro: spawned.append(coro))
    yield spawned
    for c in spawned:
        c.close()
    ch._open.clear()


def test_keys_and_bucket_boundaries():
    assert ch.bucket_start(T0 + timedelta(minutes=4, seconds=59)) == T0
    assert ch.bucket_start(T0 + timedelta(minutes=5)) == T0 + timedelta(minutes=5)
    assert ch.model_key(RB951, "7.20.7 (long-term)") == (RB951, "7")
    assert ch.model_key(RB951, "6.49.20 (long-term)") == (RB951, "6")
    assert ch.model_key(None, None) == ("unknown", "?")
    assert ch._percentile([0, 0, 1, 0, 0, 0, 0, 0, 0, 1], 0.5) == 30.0
    assert ch._percentile([0] * 10, 0.9) is None


def test_percentiles_sit_inside_the_bin_not_on_its_upper_edge():
    # 70 routers, 8 of them in [40, 50); p90 (the 63rd) is the 6th of those 8.
    # The upper edge reported 50 for this (24 Nov 2026: 50 shown, 47 real).
    hist = [8, 28, 14, 7, 8, 5, 0, 0, 0, 0]
    assert ch._percentile(hist, 0.9) == 47.5               # 40 + 10 * 6/8
    assert ch._percentile(hist, 0.5) == 19.6               # 10 + 10 * 27/28, not 20
    assert ch._percentile([0] * 9 + [3], 1.0) == 100.0
    assert ch._percentile([5] + [0] * 9, 0.5) == 5.0


async def test_each_router_counts_once_per_bucket(db):
    # Router 1 pushes every minute at 20%, router 2 every two minutes at 80%.
    for m in range(5):
        ch.note(1, 20, RB951, "7.20.7", now=T0 + timedelta(minutes=m))
    for m in (0, 2, 4):
        ch.note(2, 80, RB951, "7.20.7", now=T0 + timedelta(minutes=m))
    ch.note(3, 97, "hAP lite", "6.48.6", now=T0 + timedelta(minutes=1))
    ch.note(3, 7, "hAP lite", "6.48.6", now=T0 + timedelta(minutes=3))

    assert await ch.flush(T0 + timedelta(minutes=5)) == 0        # bucket not closed yet
    assert await ch.flush(T0 + timedelta(minutes=6)) == 2

    rows = {r.board_name: r for r in (await db.execute(select(RouterCpuBucket))).scalars()}
    rb = rows[RB951]
    assert (rb.bucket_start, rb.ros_major, rb.routers, rb.samples) == (T0, "7", 2, 8)
    assert rb.cpu_mean_sum / rb.routers == 50.0                  # not (5*20 + 3*80) / 8
    assert (rb.cpu_peak, rb.routers_ge80, rb.routers_peak_ge95) == (80, 1, 0)
    assert rb.hist[2] == 1 and rb.hist[8] == 1
    lite = rows["hAP lite"]
    assert (lite.ros_major, lite.routers, lite.cpu_mean_sum, lite.cpu_peak, lite.routers_peak_ge95) == ("6", 1, 52.0, 97, 1)
    assert ch._open == {}


async def test_a_bucket_written_twice_adds_up(db):
    ch.note(1, 40, RB951, "7.20.7", now=T0)
    await ch.flush(T0, include_open=True)                       # e.g. app shutdown mid-bucket
    ch.note(2, 60, RB951, "7.20.7", now=T0 + timedelta(minutes=3))
    await ch.flush(T0 + timedelta(minutes=6))
    row = (await db.execute(select(RouterCpuBucket))).scalar_one()
    assert (row.routers, row.samples, row.cpu_mean_sum, row.cpu_peak) == (2, 2, 100.0, 60)
    assert sum(row.hist) == 2


async def test_a_restart_does_not_count_routers_twice(db, monkeypatch):
    # Old process: two routers, then the shutdown flush writes the open bucket.
    ch.note(1, 40, RB951, "7.20.7", now=T0 + timedelta(minutes=1))
    ch.note(2, 20, RB951, "7.20.7", now=T0 + timedelta(minutes=1))
    await ch.flush(T0 + timedelta(minutes=2), include_open=True)
    # New process starts inside the same bucket; the same routers push again.
    monkeypatch.setattr(ch, "_start_bucket", T0)
    ch.note(1, 60, RB951, "7.20.7", now=T0 + timedelta(minutes=3))
    ch.note(2, 30, RB951, "7.20.7", now=T0 + timedelta(minutes=3))
    ch.note(1, 50, RB951, "7.20.7", now=T0 + timedelta(minutes=6))       # next bucket: normal
    await ch.flush(T0 + timedelta(minutes=11))
    rows = {r.bucket_start: r for r in (await db.execute(select(RouterCpuBucket))).scalars()}
    assert (rows[T0].routers, rows[T0].cpu_mean_sum) == (2, 60.0)          # was 4 routers
    assert rows[T0 + timedelta(minutes=5)].routers == 1


async def test_a_start_bucket_nobody_wrote_is_still_kept(db, monkeypatch):
    # Crash or first boot: no shutdown flush, so the new process's half is all there is.
    monkeypatch.setattr(ch, "_start_bucket", T0)
    ch.note(1, 40, RB951, "7.20.7", now=T0 + timedelta(minutes=3))
    await ch.flush(T0 + timedelta(minutes=6))
    row = (await db.execute(select(RouterCpuBucket))).scalar_one()
    assert (row.bucket_start, row.routers) == (T0, 1)


async def test_chart_agrees_with_the_per_router_history(db):
    """The chart and the per-router graphs (router_metric_buckets) are folded
    from the same samples by separate code. On prod they are compared by
    scripts/router_cpu_history_crosscheck.py; here, on mixed cadences."""
    from app.db.models import RouterMetricBucket

    owner = await make_reseller(db)
    routers = [await make_router(db, owner) for _ in range(3)]
    cadence = {routers[0].id: (0, 1, 2, 3, 4), routers[1].id: (0, 2, 4), routers[2].id: (1, 3)}
    cpu = {routers[0].id: [11, 13, 15, 17, 19], routers[1].id: [70, 90, 80], routers[2].id: [5, 45]}
    for r in routers:
        for minute, value in zip(cadence[r.id], cpu[r.id]):
            await rh.record(r.id, rh.HealthSample(cpu_load=value, board_name=RB951,
                                                  routeros_version="7.20.7"),
                            source="push", now=T0 + timedelta(minutes=minute))
    await ch.flush(T0 + timedelta(minutes=6))

    chart = (await db.execute(select(RouterCpuBucket))).scalar_one()
    per_router = (await db.execute(select(RouterMetricBucket).where(
        RouterMetricBucket.step_seconds == 300, RouterMetricBucket.bucket_start == T0))).scalars().all()
    means = [b.cpu_sum / b.cpu_samples for b in per_router]
    assert chart.routers == len(means) == 3
    assert chart.cpu_mean_sum / chart.routers == pytest.approx(sum(means) / len(means), abs=0.01)
    assert chart.samples == sum(b.cpu_samples for b in per_router)


async def test_closing_a_bucket_schedules_a_flush(fresh_tally):
    ch.note(1, 40, RB951, "7.20.7", now=T0)
    assert fresh_tally == []
    ch.note(1, 40, RB951, "7.20.7", now=T0 + timedelta(minutes=5, seconds=31))
    assert len(fresh_tally) == 1


def test_bad_input_never_raises_and_is_bounded(monkeypatch):
    ch.note(1, 150, RB951, "7")             # out of range: ignored
    ch.note(1, "x", RB951, "7")             # garbage: ignored
    assert ch._open == {}
    monkeypatch.setattr(ch, "MAX_KEYS_PER_BUCKET", 2)
    for i in range(5):
        ch.note(i, 10, f"board-{i}", "7", now=T0)
    assert len(ch._open[T0].routers) == 2


async def test_router_health_samples_feed_the_tally(db):
    owner = await make_reseller(db)
    router = await make_router(db, owner)
    await rh.record(router.id, rh.HealthSample(cpu_load=33, board_name=RB951, routeros_version="7.20.7 (long-term)"),
                    source="push", now=T0)
    # An SNMP reading has CPU only; it is filed under the model the push reported.
    await rh.record(router.id, rh.HealthSample(cpu_load=55), source="snmp", now=T0 + timedelta(minutes=2))
    tally = ch._open[T0].routers[(RB951, "7")][router.id]
    assert (tally.n, tally.total, tally.peak) == (2, 88, 55)


async def test_old_buckets_are_pruned(db):
    db.add(RouterCpuBucket(bucket_start=T0 - timedelta(days=91), board_name=RB951, ros_major="7",
                           routers=1, samples=1, cpu_mean_sum=5, cpu_peak=5, hist=[1] + [0] * 9))
    await db.commit()
    ch.note(1, 40, RB951, "7.20.7", now=T0)
    await ch.flush(T0 + timedelta(minutes=6))
    starts = [r.bucket_start for r in (await db.execute(select(RouterCpuBucket))).scalars()]
    assert starts == [T0]


# --- endpoint --------------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(amr.router)

    async def _override_get_db():
        async with session_factory() as s:
            yield s

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(amr, "get_current_user", _fake)


async def _seed(db, now):
    for i in range(12):                     # one hour of 5-minute buckets, RB951 on v6 and v7
        start = ch.bucket_start(now) - timedelta(minutes=5 * (12 - i))
        db.add(RouterCpuBucket(bucket_start=start, board_name=RB951, ros_major="7", routers=4, samples=6,
                               cpu_mean_sum=4 * 30.0, cpu_peak=70, routers_ge80=0, routers_peak_ge95=0,
                               hist=[0, 0, 0, 4, 0, 0, 0, 0, 0, 0]))
        db.add(RouterCpuBucket(bucket_start=start, board_name=RB951, ros_major="6", routers=1, samples=2,
                               cpu_mean_sum=90.0, cpu_peak=100, routers_ge80=1, routers_peak_ge95=1,
                               hist=[0] * 9 + [1]))
    db.add(AppInstanceHeartbeat(instance_id="i-1", runtime_mode="active", app_version="abc123",
                                started_at=now - timedelta(minutes=30), last_seen_at=now))
    await db.commit()


async def test_endpoint_returns_series_per_model_with_deploys(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    now = datetime.utcnow()
    await _seed(db, now)

    r = await client.get("/api/admin/router-cpu/by-model", params={"hours": 2, "step": 3600})
    assert r.status_code == 200
    body = r.json()
    assert body["step_seconds"] == 3600
    [model] = body["models"]
    assert model["board_name"] == RB951 and model["ros_major"] is None
    total_routers = sum(p["routers"] * 1 for p in model["points"])
    assert total_routers > 0
    for p in model["points"]:
        assert p["avg"] == 42.0                 # (4*30 + 90) / 5 routers
        # 4 routers in [30, 40) for every 1 in [90, 100], interpolated in the bin.
        assert p["p50"] == 36.2 and p["p90"] == 95.0
        assert p["max"] == 100 and p["pct_over_80"] == 20.0
    assert [d["version"] for d in body["deploys"]] == ["abc123"]

    split = (await client.get("/api/admin/router-cpu/by-model",
                              params={"hours": 2, "split_version": "true"})).json()
    by_major = {m["ros_major"]: m for m in split["models"]}
    assert set(by_major) == {"6", "7"}
    assert split["step_seconds"] == 300
    assert {p["avg"] for p in by_major["7"]["points"]} == {30.0}


async def test_endpoint_marks_every_deploy_not_only_the_live_one(db, client, monkeypatch):
    admin = await make_reseller(db, role=UserRole.ADMIN)
    _auth_as(monkeypatch, admin)
    now = datetime.utcnow()
    # Five earlier processes are gone from the heartbeats; the live one is in both tables.
    for i, minutes in enumerate((180, 170, 165, 160, 140)):
        db.add(AppDeploy(instance_id=f"old-{i}", started_at=now - timedelta(minutes=minutes),
                         app_version=f"sha{i}", runtime_mode="active"))
    db.add(AppDeploy(instance_id="live", started_at=now - timedelta(minutes=10),
                     app_version="sha-live", runtime_mode="active"))
    db.add(AppInstanceHeartbeat(instance_id="live", runtime_mode="active", app_version="sha-live",
                                started_at=now - timedelta(minutes=10), last_seen_at=now))
    # A live process whose deploy insert failed still shows.
    db.add(AppInstanceHeartbeat(instance_id="orphan", runtime_mode="shadow", app_version="sha-x",
                                started_at=now - timedelta(minutes=5), last_seen_at=now))
    db.add(AppDeploy(instance_id="ancient", started_at=now - timedelta(days=3),
                     app_version="too-old", runtime_mode="active"))
    await db.commit()

    body = (await client.get("/api/admin/router-cpu/by-model", params={"hours": 6})).json()
    assert [d["version"] for d in body["deploys"]] == ["sha0", "sha1", "sha2", "sha3", "sha4", "sha-live", "sha-x"]
    assert body["deploys"][-1]["runtime_mode"] == "shadow"


async def test_endpoint_is_admin_only(db, client, monkeypatch):
    reseller = await make_reseller(db)
    _auth_as(monkeypatch, reseller)
    r = await client.get("/api/admin/router-cpu/by-model")
    assert r.status_code == 403

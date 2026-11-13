"""Budget exits must leave unattempted routers next in the polling rotation."""

from types import SimpleNamespace
import asyncio

import pytest

from app.services import mikrotik_background as background
from tests.factories import make_reseller, make_router


async def prepare(db, session_factory, monkeypatch, *, failed_read=False):
    owner = await make_reseller(db)
    routers = [await make_router(db, owner) for _ in range(8)]
    clock = SimpleNamespace(seconds=0.0)
    attempts = []

    def fetch(info):
        attempts.append(info["id"])
        clock.seconds += 100
        if failed_read:
            raise RuntimeError("simulated router failure")
        return None

    async def noop(*_args, **_kwargs):
        pass

    monkeypatch.setattr(background, "async_session", session_factory)
    monkeypatch.setattr(background, "time", SimpleNamespace(monotonic=lambda: clock.seconds))
    monkeypatch.setattr(background, "_bandwidth_router_cursor", 0)
    monkeypatch.setattr(background, "BANDWIDTH_MAX_ROUTERS_PER_RUN", 8)
    monkeypatch.setattr(background, "BANDWIDTH_RUN_TIME_BUDGET_SECONDS", 90)
    monkeypatch.setattr(background, "_background_db_pool_is_busy", lambda _job: False)
    monkeypatch.setattr(background, "_router_recently_offline", lambda *_a: False)
    monkeypatch.setattr(background, "reports_metrics", lambda *_a: False)
    monkeypatch.setattr(background, "_fetch_bandwidth_data_sync_for_router", fetch)
    monkeypatch.setattr(background, "record_router_availability", noop)
    monkeypatch.setattr(background, "_prune_bandwidth_history", noop)
    return [r.id for r in routers], clock, attempts


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_read", [False, True])
async def test_slow_first_router_does_not_skip_the_rest(db, session_factory, monkeypatch, failed_read):
    router_ids, _clock, attempts = await prepare(
        db, session_factory, monkeypatch, failed_read=failed_read
    )
    for _ in router_ids:
        await background.collect_bandwidth_snapshot()
    assert attempts == router_ids
    assert background._bandwidth_router_cursor == 0


@pytest.mark.asyncio
async def test_mid_run_pool_pressure_keeps_unattempted_routers_next(db, session_factory, monkeypatch):
    router_ids, _clock, attempts = await prepare(db, session_factory, monkeypatch)
    monkeypatch.setattr(background, "BANDWIDTH_RUN_TIME_BUDGET_SECONDS", 10_000)
    monkeypatch.setattr(background, "_background_db_pool_is_busy", lambda _job: bool(attempts))
    await background.collect_bandwidth_snapshot()
    assert attempts == router_ids[:1]
    assert background._bandwidth_router_cursor == 1


@pytest.mark.asyncio
async def test_zero_budget_does_not_advance_past_any_router(db, session_factory, monkeypatch):
    _router_ids, _clock, attempts = await prepare(db, session_factory, monkeypatch)
    monkeypatch.setattr(background, "BANDWIDTH_RUN_TIME_BUDGET_SECONDS", 0)
    monkeypatch.setattr(background, "_bandwidth_router_cursor", 3)
    await background.collect_bandwidth_snapshot()
    assert attempts == []
    assert background._bandwidth_router_cursor == 3


@pytest.mark.asyncio
async def test_full_batches_wrap_in_order(db, session_factory, monkeypatch):
    router_ids, _clock, attempts = await prepare(db, session_factory, monkeypatch)
    monkeypatch.setattr(background, "BANDWIDTH_RUN_TIME_BUDGET_SECONDS", 10_000)
    monkeypatch.setattr(background, "BANDWIDTH_MAX_ROUTERS_PER_RUN", 3)
    monkeypatch.setattr(background, "_bandwidth_router_cursor", 6)
    await background.collect_bandwidth_snapshot()
    await background.collect_bandwidth_snapshot()
    assert attempts == router_ids[6:] + router_ids[:4]
    assert background._bandwidth_router_cursor == 4


@pytest.mark.asyncio
async def test_cancelled_attempt_does_not_freeze_rotation(db, session_factory, monkeypatch):
    _router_ids, _clock, _attempts = await prepare(db, session_factory, monkeypatch)

    def cancel(_info):
        raise asyncio.CancelledError

    monkeypatch.setattr(background, "_fetch_bandwidth_data_sync_for_router", cancel)
    with pytest.raises(asyncio.CancelledError):
        await background.collect_bandwidth_snapshot()
    assert background._bandwidth_router_cursor == 1

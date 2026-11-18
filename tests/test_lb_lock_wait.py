"""Load-balancing dashboard actions run as user actions on the router's lock.

Router 542, 2026-11-18: saving an LB setup on an idle router answered 429
"busy with background maintenance" because the request first waited for one
of the 3 fleet slots, and the safety-net scan, LB_PAID reconcile and bandwidth
jobs held all three for minutes. A user action must not wait on fleet slots,
must go ahead of background work queued for the same router, and a busy answer
must name what is running on THAT router.
"""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack
from types import SimpleNamespace

import pytest

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_background
from app.services import router_mutations as mutations
from app.services.mikrotik_background import RouterLockManager

pytestmark = pytest.mark.asyncio

ROUTER = SimpleNamespace(ip_address="10.0.100.16", port=8728)
KEY = "10.0.100.16:8728"


@pytest.fixture
def locks(monkeypatch):
    manager = RouterLockManager(max_concurrent=3)
    pool = ThreadPoolExecutor(max_workers=2)
    monkeypatch.setattr(mikrotik_background, "router_locks", manager)
    monkeypatch.setattr(mutations, "_lb_lane", asyncio.Semaphore(2))
    monkeypatch.setattr(mutations, "_lb_pool", pool)
    monkeypatch.setattr(lbr, "LB_LOCK_WAIT_SECONDS", 0.2)
    yield manager
    pool.shutdown(wait=True)


async def _drain():
    tasks = list(mutations._inflight)
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 3)


async def test_full_fleet_slots_do_not_delay_an_idle_router(locks):
    """The router-542 case: every fleet slot held by jobs on OTHER routers."""
    async with AsyncExitStack() as stack:
        for n in range(3):
            await stack.enter_async_context(
                locks.acquire(f"10.0.0.{n}:8728", holder="safety-net bypass scan"))
        started = time.monotonic()
        result = await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": True})
        waited = time.monotonic() - started
    assert result == {"ok": True}
    assert waited < 0.15


async def test_busy_message_names_the_job_on_this_router(locks):
    async with locks.acquire(KEY, holder="bandwidth stats collection"):
        result = await lbr._run_locked_router_thread(ROUTER, lambda: pytest.fail("ran while busy"))
    assert result["error"] == "busy"
    assert "bandwidth stats collection" in result["detail"]
    assert "this router" in result["detail"]
    assert "background maintenance" not in result["detail"]


async def test_busy_message_names_another_dashboard_action(locks):
    async with locks.acquire_interactive(KEY, holder="a load-balancing setup save"):
        result = await lbr._run_locked_router_thread(ROUTER, lambda: pytest.fail("overlap"))
    assert result["error"] == "busy"
    assert "a load-balancing setup save" in result["detail"]


async def test_user_goes_ahead_of_background_work_queued_for_the_router(locks):
    order = []
    release_first = asyncio.Event()

    async def first_job():
        async with locks.acquire(KEY, holder="queue sync"):
            order.append("job1")
            await release_first.wait()

    async def second_job():
        async with locks.acquire(KEY, holder="LB_PAID reconcile"):
            order.append("job2")

    j1 = asyncio.create_task(first_job())
    await asyncio.sleep(0.01)
    j2 = asyncio.create_task(second_job())  # queued on the router before the user
    await asyncio.sleep(0.01)
    user = asyncio.create_task(lbr._run_locked_router_thread(
        ROUTER, lambda: order.append("user") or {"ok": True}))
    await asyncio.sleep(0.01)
    assert locks.interactive_pending(KEY)
    release_first.set()
    assert await user == {"ok": True}
    await asyncio.gather(j1, j2)
    assert order == ["job1", "user", "job2"]
    assert not locks.interactive_pending(KEY)


async def test_never_two_writers_after_a_request_timeout(locks, monkeypatch):
    """A timed-out request keeps the lock until its worker really finishes."""
    loop = asyncio.get_running_loop()
    started, release = asyncio.Event(), threading.Event()

    def slow_write():
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)
        return {"ok": True}

    try:
        result = await lbr._run_locked_router_thread(ROUTER, slow_write, timeout_seconds=0.05)
        assert result == {"error": "timeout"}
        assert started.is_set()
        second = await lbr._run_locked_router_thread(ROUTER, lambda: pytest.fail("overlap"))
        assert second["error"] == "busy"
        # Background work cannot slip in either.
        with pytest.raises(asyncio.TimeoutError):
            async with asyncio.timeout(0.05):
                async with locks.acquire(KEY):
                    pass
    finally:
        release.set()
        await _drain()
    assert await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": 2}) == {"ok": 2}


async def test_lock_released_after_worker_error(locks):
    def boom():
        raise RuntimeError("router exploded")

    with pytest.raises(RuntimeError):
        await lbr._run_locked_router_thread(ROUTER, boom)
    assert await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": 2}) == {"ok": 2}


async def test_waits_for_the_step_running_on_the_router(locks):
    async def hold_briefly():
        async with locks.acquire(KEY, holder="queue sync"):
            await asyncio.sleep(0.05)

    holder = asyncio.create_task(hold_briefly())
    await asyncio.sleep(0)
    result = await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": True})
    await holder
    assert result == {"ok": True}


async def test_lb_endpoints_use_the_interactive_lane(locks, monkeypatch):
    seen = {}

    async def fake_mutation(router_key, sync_func, *args, holder=None, lane=None,
                            lock_wait_seconds=None, **kwargs):
        seen.update(key=router_key, holder=holder, lane=lane, wait=lock_wait_seconds)
        return {"ok": True}

    monkeypatch.setattr(mutations, "run_router_mutation", fake_mutation)
    await lbr._run_locked_router_thread(ROUTER, lambda: None, holder="a load-balancing pre-check")
    assert seen == {"key": KEY, "holder": "a load-balancing pre-check",
                    "lane": mutations.LANE_LOAD_BALANCING, "wait": lbr.LB_LOCK_WAIT_SECONDS}


async def test_lane_full_is_not_reported_as_router_busy(locks, monkeypatch):
    async with mutations._lb_lane, mutations._lb_lane:
        result = await lbr._run_locked_router_thread(ROUTER, lambda: pytest.fail("ran"))
    assert result["error"] == "busy"
    assert "Router is busy" not in result["detail"]
    assert "dashboard router changes" in result["detail"]

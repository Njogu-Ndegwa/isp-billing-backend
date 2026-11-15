"""Interactive writes must not wait behind fleet work or overlap after cancellation."""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import mikrotik_background as background
from app.services import router_mutations as mutations


@pytest.fixture
def capacity(monkeypatch):
    locks = background.RouterLockManager(max_concurrent=3)
    pool = ThreadPoolExecutor(max_workers=2)
    monkeypatch.setattr(background, "router_locks", locks)
    monkeypatch.setattr(mutations, "_lane", asyncio.Semaphore(2))
    monkeypatch.setattr(mutations, "_pool", pool)
    monkeypatch.setattr(mutations, "LOCK_WAIT_SECONDS", 0.05)
    yield locks
    pool.shutdown(wait=True)


async def drain():
    tasks = list(mutations._inflight)
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 2)


async def test_full_fleet_lane_does_not_block_interactive_change(capacity):
    async with AsyncExitStack() as stack:
        for number in range(3):
            await stack.enter_async_context(capacity.acquire(f"fleet-{number}"))
        assert await mutations.run_router_mutation("target", lambda: "done") == "done"


async def test_full_default_executor_does_not_block_interactive_change(capacity):
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
    started, release = asyncio.Event(), threading.Event()

    def occupy():
        loop.call_soon_threadsafe(started.set)
        release.wait(3)

    blocked = loop.run_in_executor(None, occupy)
    try:
        await asyncio.wait_for(started.wait(), 1)
        assert await asyncio.wait_for(
            mutations.run_router_mutation("target", lambda: "done"), 1
        ) == "done"
    finally:
        release.set()
        await blocked


async def test_same_router_busy_rejects_without_running_worker(capacity):
    called = []
    async with capacity.acquire("target"):
        with pytest.raises(mutations.RouterMutationBusy):
            await mutations.run_router_mutation("target", lambda: called.append(True))
        assert await mutations.run_router_mutation("other", lambda: True)
    assert called == []
    assert await mutations.run_router_mutation("target", lambda: True)


async def test_capacity_timeout_releases_router_lock(capacity):
    async with mutations._lane, mutations._lane:
        with pytest.raises(mutations.RouterMutationBusy):
            await mutations.run_router_mutation("target", lambda: pytest.fail("unexpected write"))
        async with asyncio.timeout(1):
            async with capacity.acquire_router_only("target"):
                pass
    assert await mutations.run_router_mutation("target", lambda: True)


async def test_cancelled_queued_request_never_writes(capacity):
    called = []
    async with capacity.acquire("target"):
        caller = asyncio.create_task(mutations.run_router_mutation("target", lambda: called.append(True)))
        await asyncio.sleep(0.01)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        await drain()
    assert await mutations.run_router_mutation("target", lambda: True)
    assert called == []


async def test_cancelled_capacity_wait_releases_router_lock(capacity):
    async with mutations._lane, mutations._lane:
        caller = asyncio.create_task(mutations.run_router_mutation("target", lambda: pytest.fail("unexpected write")))
        await asyncio.sleep(0.01)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        await drain()
        async with asyncio.timeout(1):
            async with capacity.acquire_router_only("target"):
                pass


async def test_cancellation_as_admission_completes_releases_both_resources(capacity, monkeypatch):
    called = []

    class CancelOnAdmission(asyncio.Semaphore):
        async def acquire(self):
            await super().acquire()
            caller.cancel()
            return True

    lane = CancelOnAdmission(1)
    monkeypatch.setattr(mutations, "_lane", lane)
    caller = asyncio.create_task(mutations.run_router_mutation("target", lambda: called.append(True)))
    with pytest.raises(asyncio.CancelledError):
        await caller
    await drain()
    assert called == []
    assert not lane.locked()
    async with asyncio.timeout(1):
        async with capacity.acquire_router_only("target"):
            pass


async def test_cancelled_running_request_retains_lock_and_capacity(capacity):
    loop = asyncio.get_running_loop()
    started, release = asyncio.Event(), threading.Event()

    def write():
        loop.call_soon_threadsafe(started.set)
        assert release.wait(3)

    caller = asyncio.create_task(mutations.run_router_mutation("target", write))
    try:
        await asyncio.wait_for(started.wait(), 1)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        with pytest.raises(mutations.RouterMutationBusy):
            await mutations.run_router_mutation("target", lambda: pytest.fail("overlapping write"))
        # One slot remains; occupying it must prevent a third worker.
        async with mutations._lane:
            with pytest.raises(mutations.RouterMutationBusy):
                await mutations.run_router_mutation("other", lambda: pytest.fail("capacity exceeded"))
    finally:
        release.set()
        await drain()
    assert await mutations.run_router_mutation("target", lambda: True)


async def test_worker_failure_releases_resources(capacity):
    def fail():
        raise ValueError("router refused write")

    with pytest.raises(ValueError, match="router refused"):
        await mutations.run_router_mutation("target", fail)
    assert await mutations.run_router_mutation("target", lambda: True)


@pytest.mark.parametrize("route", ["ports", "expired"])
async def test_routes_return_429_for_busy_router(capacity, route):
    from app.api import pppoe_expired_routes, router_operations

    async with capacity.acquire("192.0.2.1:8728"):
        with pytest.raises(HTTPException) as error:
            if route == "ports":
                await router_operations._run_locked_router_thread(
                    SimpleNamespace(ip_address="192.0.2.1", port=8728), lambda: None
                )
            else:
                await pppoe_expired_routes._locked_router_io(
                    {"ip": "192.0.2.1", "port": 8728}, lambda: None
                )
    assert error.value.status_code == 429
    assert "retry" in error.value.detail

"""The LB routes must not wait unbounded for a router slot.

Background jobs share the lock manager's fleet slots; an unbounded wait let a
dashboard preflight outlive Cloudflare's ~100s cut-off (router 537, 2026-09-30).
"""

import asyncio
from types import SimpleNamespace

import pytest

from app.api import load_balancing_routes as lbr
from app.services import mikrotik_background
from app.services.mikrotik_background import RouterLockManager

pytestmark = pytest.mark.asyncio

ROUTER = SimpleNamespace(ip_address="10.0.100.16", port=8728)


async def test_busy_when_all_fleet_slots_are_held(monkeypatch):
    locks = RouterLockManager(max_concurrent=1)
    monkeypatch.setattr(mikrotik_background, "router_locks", locks)
    monkeypatch.setattr(lbr, "LB_LOCK_WAIT_SECONDS", 0.05)

    async with locks.acquire("10.0.0.99:8728"):  # a background job on another router
        result = await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": True})

    assert result["error"] == "busy"
    assert "retry" in result["detail"]


async def test_lock_released_after_run_and_after_worker_error(monkeypatch):
    locks = RouterLockManager(max_concurrent=1)
    monkeypatch.setattr(mikrotik_background, "router_locks", locks)
    monkeypatch.setattr(lbr, "LB_LOCK_WAIT_SECONDS", 0.05)

    assert await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": True}) == {"ok": True}

    def boom():
        raise RuntimeError("router exploded")

    with pytest.raises(RuntimeError):
        await lbr._run_locked_router_thread(ROUTER, boom)

    # slot and per-router lock both free again
    result = await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": 2})
    assert result == {"ok": 2}


async def test_waits_for_slot_that_frees_up_in_time(monkeypatch):
    locks = RouterLockManager(max_concurrent=1)
    monkeypatch.setattr(mikrotik_background, "router_locks", locks)
    monkeypatch.setattr(lbr, "LB_LOCK_WAIT_SECONDS", 2)

    async def hold_briefly():
        async with locks.acquire("10.0.0.99:8728"):
            await asyncio.sleep(0.05)

    holder = asyncio.create_task(hold_briefly())
    await asyncio.sleep(0)
    result = await lbr._run_locked_router_thread(ROUTER, lambda: {"ok": True})
    await holder
    assert result == {"ok": True}

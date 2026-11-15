import asyncio
import threading

import pytest

from app.services import ap_control


@pytest.mark.asyncio
async def test_abandoned_queued_status_never_reaches_device():
    queued = []
    contacted = []

    async def busy_guard(router_id, worker, *args, **kwargs):
        queued.append(worker)
        return {"error": "busy"}

    result = await ap_control.run_claimed_action(
        99101, lambda: contacted.append(True), run_guard=busy_guard, timeout_seconds=1,
    )
    assert result == {"error": "busy"}
    assert not ap_control.ap_write_in_progress(99101)
    assert queued[0]()["error"] == "cancelled"
    assert contacted == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_status_owns_claim_until_worker_finishes_after_timeout_or_cancel(cancel):
    entered, finish = threading.Event(), threading.Event()
    futures = []

    def slow_read():
        entered.set()
        assert finish.wait(5)
        return {"success": True}

    async def timeout_guard(router_id, worker, *args, **kwargs):
        future = asyncio.get_running_loop().run_in_executor(None, worker)
        futures.append(future)
        try:
            return await asyncio.wait_for(asyncio.shield(future), 3 if cancel else 0.05)
        except asyncio.TimeoutError:
            return {"error": "timeout"}

    task = asyncio.create_task(ap_control.run_claimed_action(
        99102, slow_read, run_guard=timeout_guard, timeout_seconds=1,
    ))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert (await task)["error"] == "timeout"
        assert ap_control.ap_write_in_progress(99102)
        with pytest.raises(ap_control.ApActionBusy):
            await ap_control.run_claimed_action(
                99102, slow_read, run_guard=timeout_guard, timeout_seconds=1,
            )
        assert len(futures) == 1
    finally:
        finish.set()
        if futures:
            await futures[0]
        if not task.done():
            await task
    assert not ap_control.ap_write_in_progress(99102)

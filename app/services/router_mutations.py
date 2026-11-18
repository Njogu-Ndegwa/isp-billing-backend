"""Bounded admission for interactive router writes, separate from fleet jobs.

Use the same per-router lock as maintenance, but neither its fleet semaphore
nor the default asyncio executor, and ahead of background work queued for the
same router (``router_locks.acquire_interactive``). A cancelled HTTP caller must
not release the router lock while a synchronous RouterOS worker is still
writing.

Load balancing has its own lane: an enable can hold a worker for minutes, and
must not take capacity from quick port/redirect changes.
"""

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

INTERACTIVE_CONCURRENCY = 2
LOCK_WAIT_SECONDS = 5.0
_lane = asyncio.Semaphore(INTERACTIVE_CONCURRENCY)
_pool = ThreadPoolExecutor(
    max_workers=INTERACTIVE_CONCURRENCY, thread_name_prefix="router-interactive",
)
# Load-balancing actions (preflight/enable/disable/verify). Enable runs up to
# 7 minutes, so it gets its own workers instead of the quick-change lane's.
LB_CONCURRENCY = 2
_lb_lane = asyncio.Semaphore(LB_CONCURRENCY)
_lb_pool = ThreadPoolExecutor(
    max_workers=LB_CONCURRENCY, thread_name_prefix="router-interactive-lb",
)
LANE_DEFAULT = "default"
LANE_LOAD_BALANCING = "load_balancing"
_inflight: set[asyncio.Task] = set()


class RouterMutationBusy(Exception):
    """No write was started because admission took too long."""


def _finished(task: asyncio.Task) -> None:
    _inflight.discard(task)
    # A disconnected caller may no longer be awaiting the result.
    if not task.cancelled():
        task.exception()


def _busy_message(router_locks, router_key: str, router_acquired: bool) -> str:
    """Say what is actually in the way; never claim a free router is busy."""
    if router_acquired:
        return ("Too many dashboard router changes are running right now; "
                "retry in a few seconds.")
    reason = router_locks.busy_reason(router_key)
    if reason:
        return f"Router is busy: {reason}; retry in a minute."
    return "Router is busy with another operation; retry in a few seconds."


async def run_router_mutation(router_key: str, sync_func, *args,
                              holder: str | None = None,
                              lane: str = LANE_DEFAULT,
                              lock_wait_seconds: float | None = None,
                              **kwargs):
    """Run *sync_func* under this router's lock, as a user action.

    *holder* names the action for busy messages other callers see. Raises
    RouterMutationBusy (nothing written) when admission takes longer than
    *lock_wait_seconds* (default LOCK_WAIT_SECONDS).
    """
    from app.services.mikrotik_background import router_locks

    loop = asyncio.get_running_loop()
    caller = asyncio.current_task()
    submitted_at = loop.time()
    started = False
    router_acquired = False
    lane_acquired = False
    lane_name = lane
    if lane_name == LANE_LOAD_BALANCING:
        lane, pool = _lb_lane, _lb_pool
    else:
        lane, pool = _lane, _pool
    wait_seconds = LOCK_WAIT_SECONDS if lock_wait_seconds is None else lock_wait_seconds
    lock = router_locks.acquire_interactive(router_key, holder=holder)

    async def admit():
        nonlocal router_acquired, lane_acquired
        # Do not consume interactive capacity while waiting on a busy router.
        await lock.__aenter__()
        router_acquired = True
        await lane.acquire()
        lane_acquired = True

    async def operate():
        nonlocal started
        try:
            try:
                await asyncio.wait_for(admit(), timeout=wait_seconds)
            except asyncio.TimeoutError as exc:
                raise RouterMutationBusy(
                    _busy_message(router_locks, router_key, router_acquired)
                ) from exc
            # Cancellation can arrive as admission completes, before the
            # caller's shield handler has had a chance to cancel this task.
            if caller is not None and caller.cancelling():
                raise asyncio.CancelledError
            started = True
            admitted_at = loop.time()
            logger.info("Interactive router write %s (%s) admitted after %.3fs",
                        router_key, holder or lane_name, admitted_at - submitted_at)
            return await loop.run_in_executor(
                pool, functools.partial(sync_func, *args, **kwargs),
            )
        finally:
            # Also covers cancellation as admission completes, before the
            # executor submission: neither acquired resource may leak.
            if lane_acquired:
                lane.release()
            if router_acquired:
                await lock.__aexit__(None, None, None)
            if started:
                logger.info("Interactive router write %s finished after %.3fs",
                            router_key, loop.time() - submitted_at)

    task = asyncio.create_task(operate())
    _inflight.add(task)
    task.add_done_callback(_finished)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        if not started:
            # A caller that leaves the queue must not cause a delayed write.
            task.cancel()
        # Once submitted, the owner task holds the lock/capacity until the
        # actual worker finishes, even if the caller is cancelled repeatedly.
        raise

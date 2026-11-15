"""Bounded admission for interactive router writes, separate from fleet jobs.

Use the same per-router lock as maintenance, but neither its fleet semaphore
nor the default asyncio executor. A cancelled HTTP caller must not release the
router lock while a synchronous RouterOS worker is still writing.
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
_inflight: set[asyncio.Task] = set()


class RouterMutationBusy(Exception):
    """No write was started because admission took too long."""


def _finished(task: asyncio.Task) -> None:
    _inflight.discard(task)
    # A disconnected caller may no longer be awaiting the result.
    if not task.cancelled():
        task.exception()


async def run_router_mutation(router_key: str, sync_func, *args, **kwargs):
    from app.services.mikrotik_background import router_locks

    loop = asyncio.get_running_loop()
    caller = asyncio.current_task()
    submitted_at = loop.time()
    started = False
    router_acquired = False
    lane_acquired = False
    lane = _lane
    pool = _pool
    lock = router_locks.acquire_router_only(router_key)

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
                await asyncio.wait_for(admit(), timeout=LOCK_WAIT_SECONDS)
            except asyncio.TimeoutError as exc:
                raise RouterMutationBusy(
                    "Router is busy with another operation; retry in a few seconds."
                ) from exc
            # Cancellation can arrive as admission completes, before the
            # caller's shield handler has had a chance to cancel this task.
            if caller is not None and caller.cancelling():
                raise asyncio.CancelledError
            started = True
            admitted_at = loop.time()
            logger.info("Interactive router write %s admitted after %.3fs",
                        router_key, admitted_at - submitted_at)
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

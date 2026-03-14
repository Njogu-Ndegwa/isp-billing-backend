"""
Concurrency guards for MikroTik router API calls.

Prevents overloading routers with too many concurrent diagnostic connections
and adds hard timeouts so slow routers can't block thread pool workers forever.
"""
import asyncio
import functools
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

MAX_CONCURRENT_PER_ROUTER = 2
DIAGNOSTIC_TIMEOUT_SECONDS = 45

_router_semaphores: dict[int, asyncio.Semaphore] = defaultdict(
    lambda: asyncio.Semaphore(MAX_CONCURRENT_PER_ROUTER)
)

_diagnostic_pool = ThreadPoolExecutor(
    max_workers=6,
    thread_name_prefix="mikrotik-diag",
)


async def run_with_guard(router_id: int, sync_func, *args):
    """
    Run a synchronous MikroTik diagnostic function with:
    1. Per-router concurrency limit (max 2 simultaneous connections per router)
    2. Hard timeout (45s) so a hung router doesn't block workers forever
    3. Dedicated thread pool (6 workers) separate from the default pool

    Usage:
        result = await run_with_guard(router_id, _pppoe_overview_sync, router_info, ports)
    """
    sem = _router_semaphores[router_id]

    try:
        acquired = sem._value > 0
        if not acquired:
            logger.warning(
                f"Router {router_id}: waiting for concurrent diagnostic slot "
                f"(all {MAX_CONCURRENT_PER_ROUTER} slots busy)"
            )
    except Exception:
        pass

    async with sem:
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    _diagnostic_pool,
                    functools.partial(sync_func, *args),
                ),
                timeout=DIAGNOSTIC_TIMEOUT_SECONDS,
            )
            return result
        except asyncio.TimeoutError:
            logger.error(
                f"Router {router_id}: diagnostic timed out after {DIAGNOSTIC_TIMEOUT_SECONDS}s"
            )
            return {"error": "timeout", "detail": f"Diagnostic timed out after {DIAGNOSTIC_TIMEOUT_SECONDS}s"}

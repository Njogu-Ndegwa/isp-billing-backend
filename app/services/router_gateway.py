"""Central Router I/O Gateway.

Single entry point for direct MikroTik RouterOS calls. Enforces (centrally):
- no DB session across router I/O (signature accepts only RouterSnapshot, never a Session);
- a global concurrency cap (pinned to the prior default-executor limit);
- the circuit breaker (read from mikrotik_api during Phases 0-2);
- a BACKGROUND-only 30-min offline-skip (derived at snapshot-build time);
- BACKGROUND-only DB-pressure gating.

See docs/superpowers/specs/2026-06-03-router-io-gateway-design.md
"""
from __future__ import annotations

import asyncio
import enum
import logging
import os
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Generic, Optional, TypeVar

from app.services.router_availability import router_recently_offline
from app.services.mikrotik_api import _is_circuit_open  # circuit breaker stays here in Phases 0-2
from app.db.database import db_pool_snapshot
from app.services.router_helpers import connect_to_router

logger = logging.getLogger("router_gateway")

T = TypeVar("T")


class Priority(enum.Enum):
    INTERACTIVE = "interactive"   # customer/admin-facing; never offline-skipped or pressure-gated
    BACKGROUND = "background"     # cleanup/retry/bandwidth; subject to offline-skip + pressure gate


class RouterOpStatus(enum.Enum):
    OK = "ok"
    SKIPPED_OFFLINE = "skipped_offline"
    SKIPPED_CIRCUIT_OPEN = "skipped_circuit_open"
    SKIPPED_DB_PRESSURE = "skipped_db_pressure"
    FAILED_CONNECT = "failed_connect"
    FAILED_OP = "failed_op"
    TIMEOUT = "timeout"


_SKIP_STATUSES = frozenset({
    RouterOpStatus.SKIPPED_OFFLINE,
    RouterOpStatus.SKIPPED_CIRCUIT_OPEN,
    RouterOpStatus.SKIPPED_DB_PRESSURE,
})
_FAIL_STATUSES = frozenset({
    RouterOpStatus.FAILED_CONNECT,
    RouterOpStatus.FAILED_OP,
    RouterOpStatus.TIMEOUT,
})


@dataclass(frozen=True)
class RouterSnapshot:
    id: int
    name: str
    ip_address: str
    port: int
    username: str
    password: str
    identity: Optional[str]
    recently_offline: bool

    @classmethod
    def from_router(cls, router, now: Optional[datetime] = None) -> "RouterSnapshot":
        # Non-nullable Router columns are accessed directly so a missing field fails
        # loudly; only `identity` is nullable, hence getattr(..., None).
        return cls(
            id=router.id,
            name=router.name,
            ip_address=router.ip_address,
            port=router.port,
            username=router.username,
            password=router.password,
            identity=getattr(router, "identity", None),
            recently_offline=router_recently_offline(router, now),
        )


@dataclass(frozen=True)
class RouterOpResult(Generic[T]):
    status: RouterOpStatus
    router_id: Optional[int] = None
    value: Optional[T] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None

    @property
    def is_ok(self) -> bool:
        return self.status is RouterOpStatus.OK

    @classmethod
    def ok(cls, value, router_id=None, duration_ms=None) -> "RouterOpResult[T]":
        return cls(RouterOpStatus.OK, router_id=router_id, value=value, duration_ms=duration_ms)

    @classmethod
    def skipped(cls, status: RouterOpStatus, router_id=None) -> "RouterOpResult[None]":
        if status not in _SKIP_STATUSES:
            raise ValueError(f"skipped() requires a SKIPPED_* status, got {status}")
        return cls(status, router_id=router_id)

    @classmethod
    def failed(cls, status: RouterOpStatus, error: str, router_id=None, duration_ms=None) -> "RouterOpResult[None]":
        if status not in _FAIL_STATUSES:
            raise ValueError(f"failed() requires a FAILED_*/TIMEOUT status, got {status}")
        return cls(status, router_id=router_id, error=error, duration_ms=duration_ms)


# BACKGROUND router work is skipped when DB pool checkout reaches this percent.
BACKGROUND_DB_BUSY_THRESHOLD_PERCENT = 70


def _db_pool_busy() -> bool:
    snapshot = db_pool_snapshot()
    pct = snapshot.get("checked_out_percent")
    return isinstance(pct, (int, float)) and pct >= BACKGROUND_DB_BUSY_THRESHOLD_PERCENT


def _preflight_skip(snapshot: RouterSnapshot, priority: Priority) -> Optional[RouterOpStatus]:
    """Return a SKIPPED_* status if the call should not run, else None."""
    if _is_circuit_open(snapshot.ip_address, snapshot.port):
        return RouterOpStatus.SKIPPED_CIRCUIT_OPEN
    if priority is Priority.BACKGROUND:
        if snapshot.recently_offline:
            return RouterOpStatus.SKIPPED_OFFLINE
        if _db_pool_busy():
            return RouterOpStatus.SKIPPED_DB_PRESSURE
    return None


# Pinned global cap: the limit the asyncio default executor imposed before this gateway.
_GLOBAL_CAP = min(32, (os.cpu_count() or 1) + 4)
_EXECUTOR = ThreadPoolExecutor(max_workers=_GLOBAL_CAP, thread_name_prefix="router-io")
_SEMAPHORE = asyncio.Semaphore(_GLOBAL_CAP)

# Lightweight in-memory metrics for a future endpoint (purpose|status -> count).
_metrics: "Counter[str]" = Counter()


def _run_op_sync(snapshot: RouterSnapshot, op: Callable[[Any], T]) -> RouterOpResult:
    started = time.monotonic()
    api = connect_to_router(snapshot)
    if not api.connect():
        return RouterOpResult.failed(
            RouterOpStatus.FAILED_CONNECT,
            error=getattr(api, "last_connect_error", None) or "connection failed",
            router_id=snapshot.id,
            duration_ms=(time.monotonic() - started) * 1000,
        )
    try:
        value = op(api)
        return RouterOpResult.ok(
            value=value, router_id=snapshot.id,
            duration_ms=(time.monotonic() - started) * 1000,
        )
    except socket.timeout as exc:
        return RouterOpResult.failed(
            RouterOpStatus.TIMEOUT, error=str(exc) or "operation timed out",
            router_id=snapshot.id, duration_ms=(time.monotonic() - started) * 1000,
        )
    except Exception as exc:  # noqa: BLE001 - boundary: any op error becomes a typed result
        return RouterOpResult.failed(
            RouterOpStatus.FAILED_OP, error=repr(exc),
            router_id=snapshot.id, duration_ms=(time.monotonic() - started) * 1000,
        )
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


async def run_router_op(
    snapshot: RouterSnapshot,
    op: Callable[[Any], T],
    *,
    priority: Priority,
    purpose: str,
) -> RouterOpResult:
    """Run `op(connected_api)` for one router under all gateway invariants.

    `op` MUST NOT accept or touch a DB session. Build the snapshot and release
    the session before calling.
    """
    skip = _preflight_skip(snapshot, priority)
    if skip is not None:
        _metrics[f"{purpose}|{skip.value}"] += 1
        logger.info(
            "router op skipped router_id=%s purpose=%s priority=%s status=%s",
            snapshot.id, purpose, priority.value, skip.value,
        )
        return RouterOpResult.skipped(skip, router_id=snapshot.id)

    loop = asyncio.get_running_loop()
    async with _SEMAPHORE:
        result = await loop.run_in_executor(_EXECUTOR, _run_op_sync, snapshot, op)

    _metrics[f"{purpose}|{result.status.value}"] += 1
    logger.info(
        "router op done router_id=%s purpose=%s priority=%s status=%s duration_ms=%.1f",
        snapshot.id, purpose, priority.value, result.status.value, result.duration_ms or 0.0,
    )
    return result


def metrics_snapshot() -> dict[str, int]:
    """Copy of the in-memory purpose|status counters (for a future admin endpoint)."""
    return dict(_metrics)

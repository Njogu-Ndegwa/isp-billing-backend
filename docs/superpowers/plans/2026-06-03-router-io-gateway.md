# Router I/O Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every direct MikroTik RouterOS call through a single in-process gateway that structurally enforces: no DB session held across router I/O, a shared concurrency cap, the circuit breaker, a BACKGROUND-only 30-min offline-skip, and BACKGROUND-only DB-pressure gating.

**Architecture:** A thin closure-based facade (`app/services/router_gateway.py`) exposes `run_router_op(snapshot, op, *, priority, purpose)`. Callers load the `Router` row, build an immutable `RouterSnapshot`, release their DB session, then call the gateway with a closure that receives an already-connected `MikroTikAPI`. The gateway owns a dedicated bounded thread pool + semaphore, runs pre-flight skips, records timing/metrics, and returns a typed `RouterOpResult`. Migration is phased; the old direct API is import-locked only at the end. Approach C: facade now, promote hot operations to typed methods later (out of scope here).

**Tech Stack:** Python 3.13, asyncio, FastAPI, SQLAlchemy async, pytest + pytest-asyncio, existing synchronous `MikroTikAPI` socket client.

**Spec:** `docs/superpowers/specs/2026-06-03-router-io-gateway-design.md`

---

## Sequencing decisions (read before starting)

These resolve how the spec's locked decisions map onto safe, behavior-preserving steps. They are deliberate and should not be "optimized away" during execution:

1. **Concurrency is pinned to pre-refactor behaviour.** The gateway's global semaphore size = `min(32, (os.cpu_count() or 1) + 4)` — i.e. the same limit the asyncio default executor imposed before. The existing nested caps (`RouterLockManager(max_concurrent=3)`, `HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS=4`) are **kept as-is**, not replaced. No tuning in this plan.
2. **Circuit breaker stays in `mikrotik_api.py` during Phases 0–2.** The gateway's pre-flight *reads* the existing `_is_circuit_open`, and `MikroTikAPI.connect()` keeps recording success/failure. This keeps breaker behaviour byte-identical and shared between migrated and not-yet-migrated call sites. Consolidating/removing it from `mikrotik_api.py` happens in Phase 3, after every call site is gateway-routed (spec §4 + §8).
3. **The 30-min offline-skip stays DB-derived, passed via the snapshot.** It is computed at snapshot-build time (while the caller still holds the session) using the existing `router.last_status` / `router.last_checked_at` fields, so the gateway never touches the DB. Applies to `BACKGROUND` only.
4. **Background callers keep their existing pre-filters in v1.** `_router_recently_offline` and `_background_db_pool_is_busy` short-circuits already in `mikrotik_background.py` are caller-side optimizations that run *before* a snapshot is built; leave them in place. The gateway adds centralized enforcement on top; it does not require deleting them. (Removing the now-redundant pre-filters is an optional post-v1 cleanup, not part of this plan.)

---

## Plan scope & how to read it

**Phase 0 is fully concrete and bite-sized** — every step has complete code, exact commands, and expected output. Execute it verbatim.

**Phases 1–3 are recipe + per-file inventory.** Every interactive/background call site wraps a *different* bespoke `_sync` closure, so each migration task starts by reading its target file (Step 1) and then applies the identical mechanical recipe. Each phase includes one fully-worked exemplar; the `...` in remaining tasks' test stubs is filled from the file read in that task's Step 1 — it is not a deferred design decision, only fixture wiring that depends on code you read at execution time. Do **not** batch these; one file per task, one focused test per task, one commit per task.

If you prefer, Phases 1–3 can each be expanded into their own fully-concrete plan after Phase 0 lands (the gateway API is then fixed). Recommended only if a phase's files turn out to diverge from the recipe.

---

## File Structure

**Created:**
- `app/services/router_gateway.py` — the gateway: `RouterSnapshot`, `Priority`, `RouterOpStatus`, `RouterOpResult`, `run_router_op`, the dedicated executor + semaphore, the pressure-gate helper, in-memory metrics counters. Single cohesive module.
- `tests/test_router_gateway.py` — unit tests for the gateway (fake `op`, injected pressure/clock).
- `tests/test_router_gateway_import_guard.py` — Phase 3 guard that fails if anything outside the gateway imports `MikroTikAPI` / `connect_to_router`.

**Modified (Phase 0):**
- `app/services/router_availability.py` — add a public `router_recently_offline(router, now, threshold)` helper (extracted so both the snapshot builder and `mikrotik_background` share one definition).

**Modified (Phase 1 — background):** `app/services/mikrotik_background.py`, `app/services/hotspot_provisioning.py`, `app/services/fup.py`, `app/services/access_credentials.py`.

**Modified (Phase 2 — interactive):** `app/api/public_routes.py`, `app/api/mikrotik_routes.py`, `app/api/router_management.py`, `app/api/pppoe_monitor.py`, `app/services/pppoe_provisioning.py`, `app/api/device_pairing.py`, `app/api/dashboard_routes.py`, `app/api/hotspot_monitor.py`, `app/api/admin_routes.py`, `app/api/radius_hotspot.py`, `app/api/router_operations.py`, `app/services/billing.py`, `app/services/voucher_service.py`, `app/services/dual_port_diagnostic.py`, `app/services/insurance_wireguard.py`.

**Modified (Phase 3 — hard lock):** `app/services/mikrotik_api.py`, `app/services/router_helpers.py` (move behind a private import surface), plus a thin re-export shim consumed only by the gateway.

---

# Phase 0 — Foundation

Goal: a tested, importable gateway with zero call sites changed yet, and a runnable test environment.

### Task 0.1: Make the test environment runnable

**Files:** none (environment only).

- [ ] **Step 1: Install dev dependencies into the project venv**

Run (PowerShell, from repo root):
```powershell
& .\myEnv\Scripts\python.exe -m pip install -r requirements-dev.txt
```
Expected: pip reports `pytest`, `pytest-asyncio`, `aiosqlite`, `greenlet` installed (or already satisfied).

- [ ] **Step 2: Confirm the existing suite collects and runs**

Run:
```powershell
& .\myEnv\Scripts\python.exe -m pytest -q
```
Expected: tests are collected and run (some may be slow). If collection fails on import, stop and fix the import before continuing — Phase 0 depends on a green baseline.

- [ ] **Step 3: Record the baseline result** in the task notes (pass count / any pre-existing failures). Do not "fix" unrelated pre-existing failures in this plan; just note them.

---

### Task 0.2: Add a shared `router_recently_offline` helper

**Files:**
- Modify: `app/services/router_availability.py`
- Test: `tests/test_router_gateway.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_router_gateway.py` with:
```python
from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.router_availability import router_recently_offline


def test_router_recently_offline_true_when_recent_failure():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(last_status=False, last_checked_at=now - timedelta(minutes=5))
    assert router_recently_offline(router, now) is True


def test_router_recently_offline_false_when_window_passed():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(last_status=False, last_checked_at=now - timedelta(minutes=45))
    assert router_recently_offline(router, now) is False


def test_router_recently_offline_false_when_online_or_unknown():
    now = datetime(2026, 6, 3, 12, 0, 0)
    assert router_recently_offline(
        SimpleNamespace(last_status=True, last_checked_at=now), now
    ) is False
    assert router_recently_offline(
        SimpleNamespace(last_status=None, last_checked_at=None), now
    ) is False
```

- [ ] **Step 2: Run to verify it fails**

Run:
```powershell
& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q
```
Expected: FAIL — `ImportError: cannot import name 'router_recently_offline'`.

- [ ] **Step 3: Implement the helper**

In `app/services/router_availability.py`, add near the top (after imports):
```python
ROUTER_OFFLINE_SKIP_PERIOD = timedelta(minutes=30)


def router_recently_offline(
    router,
    now: Optional[datetime] = None,
    threshold: timedelta = ROUTER_OFFLINE_SKIP_PERIOD,
) -> bool:
    """True when the router's persisted status is offline and the failure is recent.

    Mirrors the previous private helper in mikrotik_background so the gateway and
    background jobs share one definition. Reads only already-loaded ORM fields.
    """
    now = now or datetime.utcnow()
    last_checked = getattr(router, "last_checked_at", None)
    return (
        getattr(router, "last_status", None) is False
        and last_checked is not None
        and (now - last_checked) < threshold
    )
```

- [ ] **Step 4: Run to verify it passes**

Run:
```powershell
& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q
```
Expected: PASS (3 tests).

- [ ] **Step 5: Point the existing background helper at the shared one (no behaviour change)**

In `app/services/mikrotik_background.py`, replace the body of `_router_recently_offline` (defined ~line 85) so it delegates, keeping its signature:
```python
from app.services.router_availability import router_recently_offline as _shared_router_recently_offline

def _router_recently_offline(
    router,
    now: datetime,
    threshold: timedelta = ROUTER_OFFLINE_CLEANUP_SKIP_PERIOD,
) -> bool:
    return _shared_router_recently_offline(router, now, threshold)
```
(Keep `ROUTER_OFFLINE_CLEANUP_SKIP_PERIOD = timedelta(minutes=30)` as-is so callers are unchanged.)

- [ ] **Step 6: Run the background tests to confirm no regression**

Run:
```powershell
& .\myEnv\Scripts\python.exe -m pytest tests/test_safety_net_bypass_cleanup.py tests/test_expired_hotspot_cleanup.py -q
```
Expected: PASS (same as baseline).

- [ ] **Step 7: Commit**

```powershell
git add app/services/router_availability.py app/services/mikrotik_background.py tests/test_router_gateway.py
git commit -m "Add shared router_recently_offline helper"
```

---

### Task 0.3: Gateway types — `Priority`, `RouterOpStatus`, `RouterOpResult`, `RouterSnapshot`

**Files:**
- Create: `app/services/router_gateway.py`
- Test: `tests/test_router_gateway.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_router_gateway.py`)

```python
from datetime import datetime, timedelta
from types import SimpleNamespace

from app.services.router_gateway import (
    Priority,
    RouterOpStatus,
    RouterOpResult,
    RouterSnapshot,
)


def test_router_snapshot_from_router_copies_connection_fields():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(
        id=7, name="R7", ip_address="10.0.0.7", port=8728,
        username="admin", password="pw", identity="ident-7",
        last_status=True, last_checked_at=now,
    )
    snap = RouterSnapshot.from_router(router, now=now)
    assert (snap.id, snap.ip_address, snap.port, snap.username, snap.password) == (
        7, "10.0.0.7", 8728, "admin", "pw"
    )
    assert snap.recently_offline is False


def test_router_snapshot_marks_recently_offline():
    now = datetime(2026, 6, 3, 12, 0, 0)
    router = SimpleNamespace(
        id=8, name="R8", ip_address="10.0.0.8", port=8728,
        username="admin", password="pw", identity=None,
        last_status=False, last_checked_at=now - timedelta(minutes=5),
    )
    snap = RouterSnapshot.from_router(router, now=now)
    assert snap.recently_offline is True


def test_router_snapshot_is_frozen():
    snap = RouterSnapshot(
        id=1, name="x", ip_address="1.1.1.1", port=8728,
        username="u", password="p", identity=None, recently_offline=False,
    )
    import dataclasses
    try:
        snap.password = "leak"
        assert False, "snapshot must be immutable"
    except dataclasses.FrozenInstanceError:
        pass


def test_result_ok_helper_sets_status_and_value():
    r = RouterOpResult.ok(value={"hello": 1}, router_id=3, duration_ms=12.5)
    assert r.status is RouterOpStatus.OK
    assert r.is_ok is True
    assert r.value == {"hello": 1}


def test_result_skipped_helper_is_not_ok():
    r = RouterOpResult.skipped(RouterOpStatus.SKIPPED_OFFLINE, router_id=3)
    assert r.is_ok is False
    assert r.value is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.router_gateway'`.

- [ ] **Step 3: Implement the types**

Create `app/services/router_gateway.py`:
```python
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

import enum
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Generic, Optional, TypeVar

from app.services.router_availability import router_recently_offline

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
    def ok(cls, value, router_id=None, duration_ms=None) -> "RouterOpResult":
        return cls(RouterOpStatus.OK, router_id=router_id, value=value, duration_ms=duration_ms)

    @classmethod
    def skipped(cls, status: RouterOpStatus, router_id=None) -> "RouterOpResult":
        return cls(status, router_id=router_id)

    @classmethod
    def failed(cls, status: RouterOpStatus, error: str, router_id=None, duration_ms=None) -> "RouterOpResult":
        return cls(status, router_id=router_id, error=error, duration_ms=duration_ms)
```

- [ ] **Step 4: Run to verify it passes**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: PASS (all snapshot/result tests).

- [ ] **Step 5: Commit**

```powershell
git add app/services/router_gateway.py tests/test_router_gateway.py
git commit -m "Add router gateway types and RouterSnapshot"
```

---

### Task 0.4: Pre-flight skip logic (circuit / offline / pressure)

**Files:**
- Modify: `app/services/router_gateway.py`
- Test: `tests/test_router_gateway.py`

- [ ] **Step 1: Write the failing test** (append)

```python
import app.services.router_gateway as gw


def _snap(recently_offline=False, ip="10.0.0.9", port=8728):
    return RouterSnapshot(
        id=9, name="R9", ip_address=ip, port=port, username="u",
        password="p", identity=None, recently_offline=recently_offline,
    )


def test_preflight_skips_circuit_open(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: True)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(), Priority.INTERACTIVE) is RouterOpStatus.SKIPPED_CIRCUIT_OPEN
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_CIRCUIT_OPEN


def test_preflight_offline_skips_background_only(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(recently_offline=True), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_OFFLINE
    assert gw._preflight_skip(_snap(recently_offline=True), Priority.INTERACTIVE) is None


def test_preflight_pressure_skips_background_only(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: True)
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is RouterOpStatus.SKIPPED_DB_PRESSURE
    assert gw._preflight_skip(_snap(), Priority.INTERACTIVE) is None


def test_preflight_returns_none_when_clear(monkeypatch):
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    assert gw._preflight_skip(_snap(), Priority.BACKGROUND) is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: FAIL — `AttributeError: module ... has no attribute '_preflight_skip'`.

- [ ] **Step 3: Implement pre-flight** (add to `router_gateway.py`)

```python
from app.services.mikrotik_api import _is_circuit_open  # circuit breaker stays here in Phases 0-2
from app.db.database import db_pool_snapshot

# Pinned to pre-refactor behaviour (the prior asyncio default-executor limit).
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add app/services/router_gateway.py tests/test_router_gateway.py
git commit -m "Add gateway pre-flight skip (circuit/offline/pressure)"
```

---

### Task 0.5: `run_router_op` — dispatch, concurrency cap, result mapping, metrics

**Files:**
- Modify: `app/services/router_gateway.py`
- Test: `tests/test_router_gateway.py`

- [ ] **Step 1: Write the failing test** (append)

```python
import asyncio
import pytest

pytestmark = pytest.mark.asyncio


class _FakeApi:
    def __init__(self, connect_ok=True, raise_exc=None):
        self._connect_ok = connect_ok
        self._raise = raise_exc
        self.disconnected = False
        self.last_connect_error = "boom" if not connect_ok else None

    def connect(self):
        return self._connect_ok

    def disconnect(self):
        self.disconnected = True


def _install_fake_connect(monkeypatch, api):
    monkeypatch.setattr(gw, "connect_to_router", lambda snapshot: api)
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)


async def test_run_router_op_ok_runs_op_with_connected_api(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.INTERACTIVE, purpose="unit"
    )
    assert result.is_ok
    assert result.value == {"ran": True}
    assert api.disconnected is True


async def test_run_router_op_connect_failure_maps_to_failed_connect(monkeypatch):
    api = _FakeApi(connect_ok=False)
    _install_fake_connect(monkeypatch, api)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.INTERACTIVE, purpose="unit"
    )
    assert result.status is RouterOpStatus.FAILED_CONNECT
    assert result.error == "boom"


async def test_run_router_op_op_exception_maps_to_failed_op(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    def boom(a):
        raise ValueError("kaboom")
    result = await gw.run_router_op(_snap(), boom, priority=Priority.BACKGROUND, purpose="unit")
    assert result.status is RouterOpStatus.FAILED_OP
    assert "kaboom" in result.error
    assert api.disconnected is True


async def test_run_router_op_honours_preflight_skip(monkeypatch):
    api = _FakeApi(connect_ok=True)
    _install_fake_connect(monkeypatch, api)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: True)
    result = await gw.run_router_op(
        _snap(), lambda a: {"ran": True}, priority=Priority.BACKGROUND, purpose="unit"
    )
    assert result.status is RouterOpStatus.SKIPPED_DB_PRESSURE
    assert api.disconnected is False  # never connected


async def test_run_router_op_respects_global_semaphore(monkeypatch):
    # Shrink the cap to 2 and prove no more than 2 ops run concurrently.
    monkeypatch.setattr(gw, "_SEMAPHORE", asyncio.Semaphore(2))
    monkeypatch.setattr(gw, "_is_circuit_open", lambda host, port: False)
    monkeypatch.setattr(gw, "_db_pool_busy", lambda: False)
    active = 0
    max_seen = 0
    lock = asyncio.Lock()

    class _SleepApi(_FakeApi):
        pass

    monkeypatch.setattr(gw, "connect_to_router", lambda snapshot: _SleepApi())

    def slow_op(a):
        nonlocal active, max_seen
        active += 1
        max_seen = max(max_seen, active)
        time.sleep(0.03)
        active -= 1
        return True

    await asyncio.gather(*[
        gw.run_router_op(_snap(), slow_op, priority=Priority.BACKGROUND, purpose="unit")
        for _ in range(6)
    ])
    assert max_seen <= 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: FAIL — `AttributeError: ... 'run_router_op'` / `'_SEMAPHORE'`.

- [ ] **Step 3: Implement dispatch** (add to `router_gateway.py`)

```python
import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from app.services.router_helpers import connect_to_router

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

    loop = asyncio.get_event_loop()
    async with _SEMAPHORE:
        result = await loop.run_in_executor(_EXECUTOR, _run_op_sync, snapshot, op)

    _metrics[f"{purpose}|{result.status.value}"] += 1
    logger.info(
        "router op done router_id=%s purpose=%s priority=%s status=%s duration_ms=%.1f",
        snapshot.id, purpose, priority.value, result.status.value, result.duration_ms or 0.0,
    )
    return result


def metrics_snapshot() -> dict:
    """Copy of the in-memory purpose|status counters (for a future admin endpoint)."""
    return dict(_metrics)
```

- [ ] **Step 4: Run to verify it passes**

Run: `& .\myEnv\Scripts\python.exe -m pytest tests/test_router_gateway.py -q`
Expected: PASS (all gateway tests, including the semaphore cap test).

- [ ] **Step 5: Run the full suite for regressions**

Run: `& .\myEnv\Scripts\python.exe -m pytest -q`
Expected: same pass set as the Task 0.1 baseline, plus the new gateway tests.

- [ ] **Step 6: Commit**

```powershell
git add app/services/router_gateway.py tests/test_router_gateway.py
git commit -m "Add run_router_op dispatch with concurrency cap and metrics"
```

**Phase 0 exit criteria:** `router_gateway` imports cleanly, all gateway unit tests pass, full suite matches baseline, no call sites changed.

---

# Phase 1 — Migrate background jobs

Goal: route the background fan-out (the source of the pool incidents) through the gateway, lowest-risk callers first. Keep each file's RouterOS command bodies verbatim; only the connect/dispatch wrapper changes. Keep existing pre-filters (see Sequencing decision #4).

**The mechanical recipe (apply per call site):**
1. Where the caller has the `Router` ORM object and an open session, build `snap = RouterSnapshot.from_router(router)`.
2. Ensure the session is committed/released before the gateway call (most background paths already do this).
3. Replace `await asyncio.to_thread(_some_sync, router_info, ...)` (which internally did `MikroTikAPI(...)` + `.connect()`) with:
   ```python
   result = await run_router_op(snap, lambda api: _some_op(api, ...), priority=Priority.BACKGROUND, purpose="<job>")
   ```
   where `_some_op(api, ...)` is the *existing* body with its `MikroTikAPI(...)` construction and `.connect()` guard removed (it now receives a connected `api`).
4. Map the result: `if result.is_ok: <use result.value>` else branch on `result.status` to the file's existing failure handling (e.g. keep customer ACTIVE for retry on any non-OK).
5. Leave existing `_router_recently_offline` / `_background_db_pool_is_busy` pre-filters in place.

### Worked exemplar — `fup.py` (smallest background caller)

`app/services/fup.py` already isolates router I/O behind `asyncio.to_thread` wrappers (per its module docstring, lines ~137-168). Migrate one wrapper end-to-end as the template the other files follow.

**Files:** Modify `app/services/fup.py`; Test: `tests/test_fup_gateway.py` (create).

- [ ] **Step 1: Read the three `asyncio.to_thread(...)` call sites** in `app/services/fup.py` (~lines 137, 151, 168) and the `_sync` functions they call. Identify, for each, the connection construction line and the command body.

- [ ] **Step 2: Write a failing test** that the migrated wrapper calls the gateway with `Priority.BACKGROUND`. Create `tests/test_fup_gateway.py`:
```python
import pytest
from types import SimpleNamespace
import app.services.fup as fup

pytestmark = pytest.mark.asyncio


async def test_fup_router_call_routes_through_gateway(monkeypatch):
    calls = {}
    async def fake_run_router_op(snapshot, op, *, priority, purpose):
        calls["priority"] = priority
        calls["purpose"] = purpose
        from app.services.router_gateway import RouterOpResult
        return RouterOpResult.ok(value={"ok": True}, router_id=snapshot.id)
    monkeypatch.setattr(fup, "run_router_op", fake_run_router_op)
    # Call the migrated wrapper here with a SimpleNamespace router + minimal args.
    # (Fill in the exact wrapper name + args from Step 1.)
    ...
    assert calls["priority"].name == "BACKGROUND"
```

- [ ] **Step 3: Run to verify it fails** — `& .\myEnv\Scripts\python.exe -m pytest tests/test_fup_gateway.py -q` → FAIL (`run_router_op` not imported in `fup`).

- [ ] **Step 4: Implement** — add `from app.services.router_gateway import run_router_op, Priority, RouterSnapshot` to `fup.py`; convert each `_sync` body to an `op(api)` (drop its own connect), and replace the `to_thread` dispatch with `run_router_op(...)` per the recipe.

- [ ] **Step 5: Run to verify it passes** — `& .\myEnv\Scripts\python.exe -m pytest tests/test_fup_gateway.py -q` → PASS.

- [ ] **Step 6: Run FUP + full suite** — `& .\myEnv\Scripts\python.exe -m pytest -q` → matches baseline + new test.

- [ ] **Step 7: Commit** — `git add app/services/fup.py tests/test_fup_gateway.py && git commit -m "Route FUP router I/O through gateway"`.

### Remaining Phase 1 files (each its own task, same recipe + a focused test)

- [ ] **Task 1.2: `app/services/access_credentials.py`** — migrate the `asyncio.to_thread(_..._direct_api_sync, _router_info(router), payload)` calls (~lines 643, 657, 684, 735, 760, 770). `purpose="access_credential_<provision|deprovision|bind|release>"`. Preserve return-shape consumed by callers.
- [ ] **Task 1.3: `app/services/hotspot_provisioning.py`** — migrate the provisioning + retry path I/O (note `loop.run_in_executor` at ~line 510 and the retry groups). **Keep `HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS=4` and `_process_hotspot_retry_router_groups` as-is** (nested cap, Sequencing decision #1). `purpose="hotspot_provision"` / `"hotspot_provision_retry"`. Re-run `tests/test_hotspot_retry_concurrency.py`.
- [ ] **Task 1.4: `app/services/mikrotik_background.py`** — the largest: migrate the expired-cleanup, safety-net, reaper, and bandwidth router I/O. **Keep `RouterLockManager`, `_router_recently_offline`, `_background_db_pool_is_busy`, and all interval/threshold constants** (Sequencing decisions #1, #4). For each per-router operation, build the snapshot from the already-loaded `Router` and call the gateway with `Priority.BACKGROUND`. Re-run `tests/test_safety_net_bypass_cleanup.py`, `tests/test_expired_hotspot_cleanup.py`, `tests/test_pppoe_cleanup.py`.

**Phase 1 exit criteria:** all background router I/O goes through `run_router_op`; existing background tests pass; full suite green. **Ship and verify in production** via `/api/admin/db-pool` + logs before starting Phase 2.

---

# Phase 2 — Migrate interactive paths

Goal: route customer/admin-facing router I/O through the gateway with `Priority.INTERACTIVE` (never offline-skipped or pressure-gated). Same mechanical recipe as Phase 1, except `priority=Priority.INTERACTIVE` and the failure mapping is to HTTP responses, not retry-keep-active.

### Worked exemplar — `public_routes.py::_register_mac_on_mikrotik_sync`

This is the highest-traffic interactive path (customer registration). The caller already builds a `router_info` dict (~lines 315-322) and calls `await db.commit()` (line 334) before `await asyncio.to_thread(_register_mac_on_mikrotik_sync, router_info, registration_data)` (line 337). The `_sync` body (lines 34-...) builds its own `MikroTikAPI`, calls `.connect()`, then runs the command sequence.

**Files:** Modify `app/api/public_routes.py`; Test: `tests/test_public_register_gateway.py` (create).

- [ ] **Step 1: Write the failing test** — assert registration routes through the gateway with `Priority.INTERACTIVE`:
```python
import pytest
import app.api.public_routes as pr
from app.services.router_gateway import RouterOpResult

pytestmark = pytest.mark.asyncio


async def test_register_uses_interactive_priority(monkeypatch):
    seen = {}
    async def fake_run_router_op(snapshot, op, *, priority, purpose):
        seen["priority"] = priority.name
        seen["purpose"] = purpose
        return RouterOpResult.ok(value={"success": True}, router_id=snapshot.id)
    monkeypatch.setattr(pr, "run_router_op", fake_run_router_op)
    # Drive the registration endpoint/helper with a fake router + payload (reuse existing
    # test factories/fixtures for Router + Customer), then assert:
    ...
    assert seen["priority"] == "INTERACTIVE"
```

- [ ] **Step 2: Run to verify it fails** — `pytest tests/test_public_register_gateway.py -q` → FAIL.

- [ ] **Step 3: Implement** — import the gateway in `public_routes.py`; build `snap = RouterSnapshot.from_router(router_obj)` before `await db.commit()`; extract the body of `_register_mac_on_mikrotik_sync` into `_register_mac_op(api, registration_data)` (drop the `MikroTikAPI(...)` + `.connect()` lines and the early `connection_failed` return — the gateway handles connect); replace line 337 with:
```python
result = await run_router_op(snap, lambda api: _register_mac_op(api, registration_data),
                             priority=Priority.INTERACTIVE, purpose="hotspot_register_mac")
```
Map: `result.status is FAILED_CONNECT` → the existing `connection_failed` branch; `result.is_ok` → use `result.value`; other non-OK → the existing generic error path.

- [ ] **Step 4: Run to verify it passes** — `pytest tests/test_public_register_gateway.py -q` → PASS.

- [ ] **Step 5: Run full suite** — `pytest -q` → green.

- [ ] **Step 6: Commit** — `git add app/api/public_routes.py tests/test_public_register_gateway.py && git commit -m "Route public MAC registration through gateway"`.

### Remaining Phase 2 files (each its own task, same recipe; `Priority.INTERACTIVE`)

- [ ] **Task 2.2:** `app/api/public_routes.py` remaining sites (`_check_mac_status_sync` ~437, `_disconnect_user_session_sync` ~478, cleanup ~1351).
- [ ] **Task 2.3:** `app/api/mikrotik_routes.py` (many `run_in_executor`/`to_thread` sites: ~105, 760-983, 1091, 1142, 1379). `purpose` per operation.
- [ ] **Task 2.4:** `app/api/router_management.py` (`connect_to_router` direct use ~215; `_configure_router` ~228; `_cleanup_router_users` ~691; `_remediate_blocking` ~1030; push/remove rules ~1096, 1159).
- [ ] **Task 2.5:** `app/api/pppoe_monitor.py` and `app/services/pppoe_provisioning.py`.
- [ ] **Task 2.6:** `app/api/device_pairing.py` (`_remove_device_from_router_sync` ~790).
- [ ] **Task 2.7:** `app/api/dashboard_routes.py` and `app/api/hotspot_monitor.py` (prefer snapshot/cached data; gate any live call as INTERACTIVE only on explicit diagnostics).
- [ ] **Task 2.8:** `app/api/admin_routes.py` (~531), `app/api/radius_hotspot.py`, `app/api/router_operations.py`.
- [ ] **Task 2.9:** `app/services/billing.py`, `app/services/voucher_service.py`, `app/services/dual_port_diagnostic.py`, `app/services/insurance_wireguard.py`.

For each: read the file's current MikroTik call(s), apply the recipe, add one focused test asserting gateway routing + correct priority, run the file's existing tests + full suite, commit per file.

**Phase 2 exit criteria:** no application module (outside the gateway) constructs `MikroTikAPI` or calls `connect_to_router` directly except via `run_router_op`. Confirm with:
```powershell
& .\myEnv\Scripts\python.exe -m pytest -q
```
plus a manual grep review (the import-guard test in Phase 3 enforces this automatically).

---

# Phase 3 — Hard lock + circuit-breaker consolidation

Goal: make bypass impossible and move the circuit breaker into the gateway as the single source of truth.

### Task 3.1: Import-guard test

**Files:** Create `tests/test_router_gateway_import_guard.py`.

- [ ] **Step 1: Write the test** (it should PASS only once Phases 1-2 are complete):
```python
import ast
import pathlib

ALLOWED = {"app/services/router_gateway.py", "app/services/router_helpers.py"}
FORBIDDEN_NAMES = {"MikroTikAPI", "connect_to_router"}
ROOT = pathlib.Path(__file__).resolve().parents[1]


def _imports_forbidden(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.services"):
            for alias in node.names:
                if alias.name in FORBIDDEN_NAMES:
                    hits.add(alias.name)
    return hits


def test_only_gateway_imports_low_level_router_api():
    offenders = {}
    for path in (ROOT / "app").rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if rel in ALLOWED:
            continue
        hits = _imports_forbidden(path)
        if hits:
            offenders[rel] = hits
    assert not offenders, f"Direct router-API imports outside the gateway: {offenders}"
```

- [ ] **Step 2: Run it** — `pytest tests/test_router_gateway_import_guard.py -q`. If it FAILS, the listed files still import the low-level API directly — finish migrating them (return to Phase 2) before proceeding.

- [ ] **Step 3: Commit** — `git add tests/test_router_gateway_import_guard.py && git commit -m "Add import guard for low-level router API"`.

### Task 3.2: Consolidate the circuit breaker into the gateway

**Files:** Modify `app/services/router_gateway.py`, `app/services/mikrotik_api.py`; Test: `tests/test_router_gateway.py`.

- [ ] **Step 1: Write failing tests** for a gateway-owned `RouterHealthRegistry` replicating today's thresholds (3 consecutive failures → open; 60s reset), asserting open/record/reset behaviour with an injected clock. (Mirror `CIRCUIT_BREAKER_THRESHOLD=3`, `CIRCUIT_BREAKER_RESET_TIME=60` exactly.)

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** the registry in `router_gateway.py`; have `_run_op_sync` record success/failure into it and `_preflight_skip` read from it; keep the same 3/60s constants. Then remove the now-duplicated breaker state from `mikrotik_api.py` (the connection code no longer self-records; the gateway is the sole recorder). Because every call site is now gateway-routed (Task 3.1 green), this loses no coverage.

- [ ] **Step 4: Run gateway + full suite → PASS.**

- [ ] **Step 5: Commit** — `git commit -m "Consolidate router circuit breaker into the gateway"`.

### Task 3.3: Lock the low-level API surface

**Files:** Modify `app/services/mikrotik_api.py`, `app/services/router_helpers.py`.

- [ ] **Step 1:** Add a module-level comment/`__all__` and a docstring to `mikrotik_api.py` and `router_helpers.py` stating they are gateway-internal: "Do not import `MikroTikAPI` / `connect_to_router` outside `router_gateway`. Use `run_router_op`."

- [ ] **Step 2:** Keep `tests/test_router_gateway_import_guard.py` as the enforcement (CI fails on violation). Confirm it still passes.

- [ ] **Step 3: Run full suite → green. Commit** — `git commit -m "Lock low-level router API behind the gateway"`.

**Phase 3 exit criteria:** import-guard test passes; circuit breaker lives only in the gateway; full suite green.

---

## Final verification

- [ ] Run the entire suite: `& .\myEnv\Scripts\python.exe -m pytest -q` → green.
- [ ] Grep sanity: no `app.*` module outside the gateway imports `MikroTikAPI`/`connect_to_router`.
- [ ] Update `docs/agent-memory/backlog.md`: mark "Central Router I/O Gateway" done; note the outbox now has its prerequisite. Add an incident-style note if production verification surfaces anything.
- [ ] Production watch after Phase 1 and after Phase 2: no `QueuePool limit` errors attributable to router fan-out for a sustained window (`/api/admin/db-pool`).

## Out of scope (future plans)

- Typed-method promotion of hot operations (`gateway.provision_hotspot(...)`).
- Router Command Outbox (`router_commands` table + worker).
- Native-async `MikroTikAPI`.
- Tuning the concurrency cap below the pinned pre-refactor value.

# Router I/O Gateway — Design Spec

- **Date:** 2026-06-03
- **Status:** Approved design, pending implementation plan
- **Branch:** `router-io-gateway`
- **Owner:** Dennis

## 1. Context

The backend talks to many MikroTik routers over the direct RouterOS API. `MikroTikAPI`
(`app/services/mikrotik_api.py`) is a synchronous socket client, dispatched from the async
app via `asyncio.to_thread` / `run_in_executor(None, …)`. It is imported directly across
~26 modules, each with its own call pattern (ad-hoc `router_info` dicts, inline `_sync`
closures, per-site error handling).

Three production incidents traced DB pool exhaustion to this scattered design:

- `docs/agent-memory/incidents/2026-05-31-db-pool-exhaustion.md`
- `docs/agent-memory/incidents/2026-06-02-db-pool-exhaustion-recurrence.md`
- (root-cause class also touches the dual-mode / orphan-secret incidents)

Tactical fixes shipped (release sessions before I/O, offline-skip, concurrency caps,
DB-pressure gating, `/api/admin/db-pool` observability). But the protective rules live
only inside specific files (mainly `mikrotik_background.py`) and any other call path can
bypass them. This refactor makes the rules structural.

Backlog items this implements:
- "Central Router I/O Gateway" (`docs/agent-memory/backlog.md`)
- Partially: "DB Pool And Router I/O Observability"
- Prerequisite for: "Router Command Outbox"

## 2. Goals

1. **No bypass.** Make it structurally impossible for any call site to (a) hold a DB
   session across router I/O, (b) skip offline/circuit-breaker checks, (c) exceed the
   global router-concurrency cap, or (d) run non-urgent router work under DB pressure.
2. Deliver the reliability guarantee across all ~26 call sites quickly and at low risk.
3. Provide a clean evolution path toward typed operations and, later, an async outbox.

## 3. Non-goals (v1)

- The **Router Command Outbox** (async DB-queue + worker). The gateway is its prerequisite.
- Native-async rewrite of `MikroTikAPI`. Stays synchronous behind the gateway's own pool.
- Full typed-method API up front. Promotion happens incrementally after v1 (see §9).
- Scheduler / multi-worker isolation. Gateway state is per-process; documented limitation.

## 4. Locked decisions

| Decision | Choice |
|---|---|
| Primary driver | Reliability / no-bypass (Central Router I/O Gateway) |
| Invariants enforced | All four: no-DB-session-across-I/O, offline-skip + circuit breaker, global concurrency cap, DB-pressure gating |
| Rollout | Phased migration, then hard-lock the old API |
| Execution model | Keep `MikroTikAPI` synchronous; gateway owns a dedicated bounded thread pool + semaphore (not the shared default executor) |
| Interface shape | Approach C — thin closure-based facade now, promote hot operations to typed methods later |
| Circuit breaker | Consolidated into the gateway's health registry; removed from `mikrotik_api.py` as a separate source of truth |
| Test environment | Getting `pytest` runnable in `myEnv` is a hard Phase-0 prerequisite |
| INTERACTIVE priority | Never DB-pressure gated (customer/admin-facing actions always attempt) |

## 5. Architecture

```
 request / job
      │ (1) load Router row, build snapshot, RELEASE db session
      ▼
 RouterSnapshot (immutable) ──► run_router_op(snapshot, op, priority, purpose)
                                      │
                          ┌───────────▼────────────┐
                          │      router_gateway      │
                          │  pre-flight skips:        │  ← health registry (offline / circuit)
                          │   • circuit open?         │  ← DB-pressure gate (BACKGROUND only)
                          │   • offline < 30m?        │
                          │   • db pressure?          │
                          │  asyncio.Semaphore(cap)   │  ← global concurrency cap
                          │  dedicated ThreadPool     │  ← bounded OS threads
                          │  timeout · timing · logs  │
                          └───────────┬────────────┘
                            connect_to_router → MikroTikAPI (sync, in pool thread)
                                      │
                          records success/failure → health registry
                                      ▼
                            RouterOpResult[T]  (status + value/error + duration)
```

The gateway signature **never accepts an `AsyncSession`** — that alone makes
"DB session held across router I/O" impossible to express.

## 6. Components

- **`RouterSnapshot`** — frozen dataclass: `id, name, ip_address, port, username, password,
  identity`, plus mode flags as needed (e.g. dual-mode). Built from a `Router` ORM row by
  the caller while the session is open; carries everything the socket layer needs so no DB
  access happens during I/O. Replaces today's hand-built `router_info` dicts.
- **`Priority`** — `INTERACTIVE` (reconnect, provision-on-payment, portal, live admin
  diagnostics) vs `BACKGROUND` (cleanup, retry, bandwidth, reaper).
- **`RouterOpResult[T]`** — standardized outcome:
  `status ∈ {OK, SKIPPED_OFFLINE, SKIPPED_CIRCUIT_OPEN, SKIPPED_DB_PRESSURE,
  FAILED_CONNECT, FAILED_OP, TIMEOUT}`, plus `value`, `error`, `duration_ms`, `router_id`.
  Callers branch on `status` instead of catching raw socket exceptions.
- **`run_router_op(snapshot, op, *, priority, purpose)`** — the facade. `op` is a
  `Callable[[MikroTikAPI], T]` receiving an already-connected api (so closures drop their
  own `MikroTikAPI(...)` + `.connect()` boilerplate; their command bodies are unchanged).
- **`RouterHealthRegistry`** — in-memory, process-global (same nature as today's
  `_router_failures`): consecutive failures, circuit state, `offline_until`. Single source
  of truth for offline-skip + circuit breaker.
- **Execution internals** — one `ThreadPoolExecutor(max_workers=N)` and one
  `asyncio.Semaphore(cap)` owned by the gateway module. The semaphore is the true global
  in-flight cap (web + background combined); the executor is sized ≥ cap. `N` and `cap`
  are env-configurable with conservative defaults.
- **DB-pressure source** — reuse the pool counters already exposed by
  `app/db/database.py` (the same data behind `/api/admin/db-pool`).

## 7. Gating semantics (the reliability core)

Pre-flight, before acquiring a thread (cheap fast-fail), in order:

1. Circuit open → `SKIPPED_CIRCUIT_OPEN` (both priorities).
2. Router offline within last 30 min → `SKIPPED_OFFLINE` (both priorities).
3. DB pressure high → for `BACKGROUND` only → `SKIPPED_DB_PRESSURE`. `INTERACTIVE` is
   never gated here.
4. Otherwise acquire semaphore → run `op` in pool → record health → return result.

Timeouts (connect/op) are standardized and owned by the gateway; no call site can pass an
unbounded timeout.

## 8. Rollout

- **Phase 0 — Foundation.** Build `router_gateway.py` (`RouterSnapshot`, `Priority`,
  `RouterOpResult`, `run_router_op`, `RouterHealthRegistry`, executor/semaphore, pressure
  hook). **Get `pytest` runnable in `myEnv`.** Write gateway unit tests. No call sites
  changed yet.
- **Phase 1 — Background jobs first** (where the incidents originated). Migrate
  `mikrotik_background.py`, `hotspot_provisioning.py` (retry path), `fup.py`,
  `access_credentials.py`, and bandwidth collection. Delete their bespoke
  offline-skip / pressure / concurrency code in favour of the gateway. Verify in prod via
  `/api/admin/db-pool` + logs.
- **Phase 2 — Interactive paths.** Migrate `public_routes.py`, `mikrotik_routes.py`,
  `router_management.py`, `pppoe_monitor.py`, `pppoe_provisioning.py`, `device_pairing.py`,
  `dashboard_routes.py`, `hotspot_monitor.py`, `admin_routes.py`, `radius_hotspot.py`,
  `router_operations.py`, `billing.py`, `voucher_service.py`, `dual_port_diagnostic.py`,
  `insurance_wireguard.py`.
- **Phase 3 — Hard lock.** Move `MikroTikAPI` + `connect_to_router` behind a private
  module imported only by the gateway. Add an **import-guard test** that fails if anything
  outside `router_gateway` imports them. Bypass becomes impossible.

Each phase is independently shippable and verified in production before the next.

## 9. Future (post-v1, not part of this spec)

- **Typed-method promotion:** move hot operations' bodies into the gateway as named
  methods (`gateway.provision_hotspot(...)`, `gateway.remove_expired(...)`), one at a time,
  each with its own test. This reaches "Approach B's" end state incrementally.
- **Router Command Outbox:** add a `router_commands` table + worker on top of the gateway
  so handlers can enqueue and return without waiting on live routers.
- **Native-async `MikroTikAPI`:** the gateway interface is the seam that lets the internal
  execution change later without touching call sites.

## 10. Testing

- Gateway unit tests with a fake `op` + injectable clock/pressure source: semaphore cap
  respected; offline-skip; circuit breaker open/reset; pressure-gate skips `BACKGROUND` but
  not `INTERACTIVE`; status → `RouterOpResult` mapping.
- Per-phase migration: keep/port the existing focused tests for each touched module.
- Phase-3 import-guard test.
- Test-env note: prior incident fixes shipped on compile-checks + smoke tests only because
  `pytest` was not installed locally. This refactor treats a runnable test env as a Phase-0
  deliverable.

## 11. Observability

Every `run_router_op` emits a structured log line: `router_id`, `purpose`, `priority`,
`status`, `duration_ms`. The gateway keeps in-memory counters per router/purpose, ready to
back a future metrics endpoint. This partially satisfies the backlog observability item
(router-call duration and counts by router ID, in one trail).

## 12. Risks & mitigations

- **Behaviour drift while wrapping closures.** Mitigation: closures' command bodies are
  copied verbatim; only connection/dispatch boilerplate is removed; migrate in small
  reviewable batches; verify each phase in prod.
- **Concurrency cap set too low → throughput regression.** Mitigation: env-configurable;
  start conservative, watch `/api/admin/db-pool` and router-call duration, tune.
- **Per-process state under multiple workers.** Mitigation: documented limitation; ties to
  the existing "Scheduler Isolation" backlog item; no regression vs today's per-process
  circuit breaker.
- **Consolidating the circuit breaker changes existing behaviour.** Mitigation: replicate
  current thresholds (3 failures / 60s reset) in the registry; cover with unit tests before
  removing the old path.

## 13. Success criteria

- All router I/O flows through `run_router_op`; `MikroTikAPI`/`connect_to_router` are
  import-locked to the gateway (enforced by test).
- No code path can hold a DB session across router I/O (enforced by signature).
- Offline-skip, circuit breaker, global concurrency cap, and BACKGROUND pressure-gating are
  applied uniformly, defined in exactly one place.
- No `QueuePool limit` exhaustion attributable to router fan-out for a sustained window
  after Phase 1 ships.
- `pytest` runs locally; gateway and migrated-path tests pass.

## 14. References

- `app/services/mikrotik_api.py`, `app/services/router_helpers.py`
- `app/services/mikrotik_background.py`, `app/services/hotspot_provisioning.py`
- `app/db/database.py`, `DB_POOL_MONITORING_FRONTEND.md`
- `docs/agent-memory/backlog.md`, `docs/agent-memory/README.md`
- Incident notes under `docs/agent-memory/incidents/`

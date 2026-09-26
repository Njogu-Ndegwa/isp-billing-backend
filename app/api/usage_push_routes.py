"""Router-facing usage-push endpoint.

Every other route in this app is called by our own frontend. This one is called
by customer hardware in the field, on a cadence the router picks, from a fleet
that is expected to grow — so the throttle that polling got for free (we decided
when to call) has to be built in here explicitly.

Three protections, in the order they run, cheapest first:

1. **Rate limit per router.** A misconfigured or hostile router cannot pin the
   server by looping. Enforced in memory — it is a throttle, not a fact worth a
   table, and losing it on restart just means one extra push per router.
2. **Load shedding.** When the DB pool is under pressure the endpoint refuses
   with 503 + ``Retry-After`` rather than queueing work that drains it. This is
   safe *because reports are cumulative snapshots, not deltas*: the next push
   carries the same totals, so a dropped push loses nothing. That property is
   what makes push survivable at fleet scale — under load we can simply say no.
3. **Batch cap.** A payload larger than one router could plausibly produce is
   refused before any DB work.

The response carries ``next_push_seconds``, so the cadence is set centrally by
the server and can be tuned without touching a thousand devices.
"""

from __future__ import annotations

import asyncio
import re
import logging
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.database import async_session, db_pool_snapshot
from app.db.models import Router as RouterModel
from app.services.usage_push import (
    MAX_REPORTS_PER_BATCH,
    RouterMetrics,
    UsageReport,
    _canonical_key,
    ingest_usage_reports,
)
from app.services.usage_push_auth import verify_router_token
from app.services import realtime_state
from app.services.realtime_state import (
    HostSample,
    PppSample,
    QueueSample,
    is_pilot_router,
    pilot_push_interval_seconds,
)

from app.services import router_health  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter(tags=["usage-push"])

# How often a router should report. Sent back on every accepted push so the
# fleet's cadence is a server-side setting, not something baked into 1,000
# scripts. Short enough that a customer sees their usage move within a couple of
# minutes — the "my data hasn't updated" complaint — and long enough that the
# fleet costs little.
DEFAULT_PUSH_INTERVAL_SECONDS = 120

# A router is allowed one accepted push per this window. Set below the interval
# above so a little clock drift or jitter never trips it.
MIN_SECONDS_BETWEEN_PUSHES = 60

# Real-time pilot routers report every few seconds; they get their own floor.
PILOT_MIN_SECONDS_BETWEEN_PUSHES = 3

MAX_HOSTS_PER_BATCH = 2000

# One repair per router at a time; a repair still marked running after this is
# presumed lost and may be started again.
REPAIR_RUNNING_GRACE_SECONDS = 600

# Shed load at the same threshold the background samplers use, so push and the
# background jobs back off together instead of fighting for the last connections.
POOL_PRESSURE_PERCENT = 60

RETRY_AFTER_ON_PRESSURE = 90

# The pool-pressure check is only a snapshot.  Without an admission gate, a
# synchronized fleet can all observe (say) 40% usage and then enter DB work at
# once, racing the 30-connection pool straight to 100%.  Keep router ingest to a
# small, known share of the pool; queued requests hold no DB connection and the
# reports are cumulative, so a delayed/retried report loses no usage.
MAX_CONCURRENT_USAGE_INGESTS = 3
_usage_ingest_gate = asyncio.Semaphore(MAX_CONCURRENT_USAGE_INGESTS)

# identity -> monotonic timestamp of last accepted push.
_last_push_at: dict[str, float] = {}

# Identities seen belonging to pilot routers (learned on first push, so the
# rate-limit check stays ahead of the DB lookup).
_pilot_identities: set[str] = set()

# Background work started from this endpoint (repairs, cap enforcement). Kept
# referenced so tasks are not garbage-collected mid-flight.
_background_tasks: set = set()


def reset_rate_limiter() -> None:
    """Test hook — the limiter is process state, so tests must start clean."""
    global _usage_ingest_gate
    _last_push_at.clear()
    _pilot_identities.clear()
    _usage_ingest_gate = asyncio.Semaphore(MAX_CONCURRENT_USAGE_INGESTS)


def _pool_under_pressure() -> bool:
    snapshot = db_pool_snapshot()
    percent = snapshot.get("checked_out_percent")
    try:
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except (TypeError, ValueError):
        return False


class UsageReportIn(BaseModel):
    queue_key: str = Field(max_length=128)
    upload_bytes: int = Field(ge=0)
    download_bytes: int = Field(ge=0)
    final: bool = False
    queue_name: str = Field(default="", max_length=128)
    target_ip: str = Field(default="", max_length=64)
    max_limit: str = Field(default="", max_length=64)
    disabled: bool = False


class HostReportIn(BaseModel):
    """One ``/ip hotspot host`` entry (v2 / real-time pilot)."""

    mac: str = Field(max_length=32)
    ip: str = Field(default="", max_length=64)
    bytes_in: int = Field(ge=0)
    bytes_out: int = Field(ge=0)
    bypassed: bool = False
    authorized: bool = False
    idle_time: str = Field(default="", max_length=32)
    uptime: str = Field(default="", max_length=32)


class PppActiveIn(BaseModel):
    """One ``/ppp active`` session (v2 / real-time pilot)."""

    name: str = Field(max_length=64)
    address: str = Field(default="", max_length=64)
    uptime: str = Field(default="", max_length=32)
    caller_id: str = Field(default="", max_length=64)


class PortIn(BaseModel):
    name: str = Field(max_length=64)
    running: bool = False
    disabled: bool = False
    rx_bytes: int = Field(default=0, ge=0)
    tx_bytes: int = Field(default=0, ge=0)
    link_downs: int = Field(default=0, ge=0)
    rx_packets: int = Field(default=0, ge=0)
    tx_packets: int = Field(default=0, ge=0)
    rx_errors: int = Field(default=0, ge=0)
    tx_errors: int = Field(default=0, ge=0)
    last_link_up: str = Field(default="", max_length=40)


class LeaseIn(BaseModel):
    mac: str = Field(default="", max_length=32)
    ip: str = Field(default="", max_length=64)
    host: str = Field(default="", max_length=128)
    status: str = Field(default="", max_length=32)
    comment: str = Field(default="", max_length=256)


class NeighborIn(BaseModel):
    mac: str = Field(default="", max_length=32)
    identity: str = Field(default="", max_length=128)
    board: str = Field(default="", max_length=128)
    platform: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=128)
    interface: str = Field(default="", max_length=128)
    address: str = Field(default="", max_length=64)


class BridgePortIn(BaseModel):
    interface: str = Field(default="", max_length=64)
    bridge: str = Field(default="", max_length=64)


class BridgeHostIn(BaseModel):
    mac: str = Field(max_length=32)
    port: str = Field(default="", max_length=64)


class BindingIn(BaseModel):
    mac: str = Field(default="", max_length=32)
    type: str = Field(default="", max_length=16)
    disabled: bool = False


class RouterMetricsIn(BaseModel):
    """Optional router-level readings — interface counters and session counts.

    Everything here is a read-only fact from the router; validation bounds live
    in the service layer alongside the usage-report bounds.
    """

    iface_rx_bytes: int = Field(ge=0)
    iface_tx_bytes: int = Field(ge=0)
    hotspot_active: int = Field(default=0, ge=0)
    pppoe_active: int = Field(default=0, ge=0)
    queue_count: int = Field(default=0, ge=0)
    # Health (optional: older installs of the script do not send these).
    # Implausible values are dropped field-by-field in router_health.sanitize.
    cpu_load: Optional[int] = None
    free_memory: Optional[int] = None
    total_memory: Optional[int] = None
    free_hdd: Optional[int] = None
    total_hdd: Optional[int] = None
    uptime: Optional[str] = Field(default=None, max_length=40)
    version: Optional[str] = Field(default=None, max_length=80)
    board: Optional[str] = Field(default=None, max_length=80)
    wan_link_downs: Optional[int] = None


class UsagePushIn(BaseModel):
    identity: str = Field(max_length=128)
    v: int = 1
    reports: list[UsageReportIn] = Field(default_factory=list)
    hosts: list[HostReportIn] = Field(default_factory=list)
    ppp: list[PppActiveIn] = Field(default_factory=list)
    # v3. None = not in this report (the long lists come every ~5 reports).
    ports: Optional[list[PortIn]] = None
    bridge_hosts: Optional[list[BridgeHostIn]] = None
    bindings: Optional[list[BindingIn]] = None
    leases: Optional[list[LeaseIn]] = None
    neighbors: Optional[list[NeighborIn]] = None
    bridge_ports: Optional[list[BridgePortIn]] = None
    router: Optional[RouterMetricsIn] = None


@router.post("/api/router/usage-push")
async def receive_usage_push(
    payload: UsagePushIn,
    response: Response,
    authorization: Optional[str] = Header(default=None),
    x_bitwave_push_channel: Optional[str] = Header(default=None),
):
    identity = (payload.identity or "").strip()
    presented = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()

    # Auth first and identically for every failure mode: a wrong token, a missing
    # token and an unknown identity all return the same 401, so this endpoint
    # cannot be used to enumerate which routers exist.
    if not verify_router_token(identity, presented):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Refuse an implausible payload before touching the database.
    if (
        len(payload.reports) > MAX_REPORTS_PER_BATCH
        or len(payload.hosts) > MAX_HOSTS_PER_BATCH
        or len(payload.ppp) > MAX_HOSTS_PER_BATCH
        or len(payload.ports or []) > MAX_HOSTS_PER_BATCH
        or len(payload.bridge_hosts or []) > MAX_HOSTS_PER_BATCH
        or len(payload.bindings or []) > MAX_HOSTS_PER_BATCH
        or len(payload.leases or []) > MAX_HOSTS_PER_BATCH
        or len(payload.neighbors or []) > MAX_HOSTS_PER_BATCH
        or len(payload.bridge_ports or []) > MAX_HOSTS_PER_BATCH
    ):
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large; max {MAX_REPORTS_PER_BATCH} reports",
        )

    now = time.monotonic()
    last = _last_push_at.get(identity)
    floor = (
        PILOT_MIN_SECONDS_BETWEEN_PUSHES
        if identity in _pilot_identities
        else MIN_SECONDS_BETWEEN_PUSHES
    )
    if last is not None and (now - last) < floor:
        retry_after = int(floor - (now - last)) + 1
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=429,
            detail="Too many pushes",
            headers={"Retry-After": str(retry_after)},
        )

    # Shedding is safe here and nowhere else in the app: the counters are
    # cumulative, so whatever we drop arrives again in the next push.
    if _pool_under_pressure():
        logger.warning("[USAGE-PUSH] Shedding push from %s: DB pool under pressure", identity)
        raise HTTPException(
            status_code=503,
            detail="Busy, retry later",
            headers={"Retry-After": str(RETRY_AFTER_ON_PRESSURE)},
        )

    async with _usage_ingest_gate:
        # A request may have waited behind the gate. Re-check pressure before it
        # becomes one of the admitted DB users instead of trusting the stale
        # snapshot taken on arrival.
        if _pool_under_pressure():
            logger.warning(
                "[USAGE-PUSH] Shedding queued push from %s: DB pool under pressure",
                identity,
            )
            raise HTTPException(
                status_code=503,
                detail="Busy, retry later",
                headers={"Retry-After": str(RETRY_AFTER_ON_PRESSURE)},
            )

        async with async_session() as db:
            router_row = (
                await db.execute(
                    select(RouterModel).where(RouterModel.identity == identity)
                )
            ).scalar_one_or_none()

        # A valid token for an identity with no router is still 401, not 404 —
        # same reason as above, no enumeration.
        if router_row is None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        _last_push_at[identity] = now
        # Sending the real-time report (v3+) is what enrols a router; see
        # realtime_state.REALTIME_MEMBERSHIP_FRESH_SECONDS.
        if payload.v >= 3:
            realtime_state.note_realtime_report(router_row.id)
        pilot = is_pilot_router(router_row.id)
        if pilot:
            _pilot_identities.add(identity)

        metrics = None
        if payload.router is not None:
            metrics = RouterMetrics(
                iface_rx_bytes=payload.router.iface_rx_bytes,
                iface_tx_bytes=payload.router.iface_tx_bytes,
                hotspot_active=payload.router.hotspot_active,
                pppoe_active=payload.router.pppoe_active,
                queue_count=payload.router.queue_count,
            )

        result = await ingest_usage_reports(
            router_row.id,
            [
                UsageReport(
                    queue_key=item.queue_key,
                    upload_bytes=item.upload_bytes,
                    download_bytes=item.download_bytes,
                    final=item.final,
                    queue_name=item.queue_name,
                    target_ip=item.target_ip,
                    max_limit=item.max_limit,
                )
                for item in payload.reports
            ] + ([
                UsageReport(
                    queue_key=host.mac,
                    upload_bytes=host.bytes_in,
                    download_bytes=host.bytes_out,
                    target_ip=host.ip,
                    source="host",
                )
                for host in payload.hosts
            ] if pilot else []),
            router_metrics=metrics,
            meter_hotspot_by_host=pilot and "hosts" in payload.model_fields_set,
        )

    if payload.router is not None:
        # Health goes to its own table in its own short session, after the
        # usage ingest has committed; failures never affect the push response.
        r = payload.router
        sample = router_health.HealthSample(
            cpu_load=r.cpu_load, memory_free_bytes=r.free_memory,
            memory_total_bytes=r.total_memory, storage_free_bytes=r.free_hdd,
            storage_total_bytes=r.total_hdd, uptime_seconds=r.uptime,
            routeros_version=r.version, board_name=r.board,
            wan_link_downs=r.wan_link_downs,
        )
        if not sample.is_empty():
            # ``now`` above is a monotonic clock for rate limiting; health rows
            # need wall-clock UTC, which record_and_evaluate supplies itself.
            await router_health.record_and_evaluate(
                router_row.id, sample, source=router_health.SOURCE_PUSH)

    # Set by the tunnel-only Caddy site (http://10.251.0.1): the report came
    # through the router's encrypted management tunnel as plain HTTP.
    via_tunnel = (x_bitwave_push_channel or "").strip().lower() == "tunnel"

    if payload.router is not None:
        realtime_state.note_metrics_report(router_row.id)

    if pilot:
        _record_live_state(router_row.id, payload, result, via_tunnel)
        _spawn(_enforce_caps(result.over_cap_customer_ids))

    if result.over_cap_customer_ids:
        # Enforcement does RouterOS I/O, so it must not run inside this request
        # with anything held. Handing the ids to the existing cap-enforcement
        # path is the remaining wiring; logged for now so the rollout can be
        # observed before enforcement is moved onto this trigger.
        logger.info(
            "[USAGE-PUSH] %s reported %d customer(s) over cap: %s",
            identity, len(result.over_cap_customer_ids), result.over_cap_customer_ids,
        )

    return {
        "accepted": result.accepted,
        "rejected": result.rejected,
        "next_push_seconds": (
            SMALL_BOARD_PUSH_SECONDS
            if payload.v >= 3 and payload.router is not None and is_small_board(payload.router.board)
            else pilot_push_interval_seconds(router_row.id, via_tunnel) if pilot
            else DEFAULT_PUSH_INTERVAL_SECONDS
        ),
    }


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


def _record_live_state(router_id: int, payload: UsagePushIn, result, via_tunnel: bool = False) -> None:
    """Fold a pilot report into the in-memory live view; start a repair if due."""
    now = datetime.utcnow()
    queues = []
    for item in payload.reports:
        key = _canonical_key(item.queue_key)
        if key:
            queues.append(QueueSample(
                key=key,
                target_ip=(item.target_ip or "").split("/")[0].strip(),
                max_limit=item.max_limit or "",
                disabled=bool(item.disabled),
                upload_bytes=item.upload_bytes,
                download_bytes=item.download_bytes,
            ))
    hosts = [
        HostSample(
            mac=h.mac, ip=h.ip, bytes_in=h.bytes_in, bytes_out=h.bytes_out,
            bypassed=h.bypassed, authorized=h.authorized,
            idle_time=h.idle_time, uptime=h.uptime,
        )
        for h in payload.hosts
        if _canonical_key(h.mac)
    ]
    state = realtime_state.record_push(
        router_id,
        now=now,
        interval_seconds=pilot_push_interval_seconds(router_id, via_tunnel),
        hosts=hosts,
        queues=queues,
        live_customers=result.live_hotspot_customers,
        metrics=payload.router.model_dump() if payload.router else None,
        ppp_sessions=[
            PppSample(name=p.name, address=p.address, uptime=p.uptime, caller_id=p.caller_id)
            for p in payload.ppp
        ],
        live_pppoe_customers=result.live_pppoe_customers,
        has_hosts="hosts" in payload.model_fields_set,
        ports=[p.model_dump() for p in payload.ports] if payload.ports is not None else None,
        bridge_hosts=[b.model_dump() for b in payload.bridge_hosts] if payload.bridge_hosts is not None else None,
        bindings=[b.model_dump() for b in payload.bindings] if payload.bindings is not None else None,
        leases=[x.model_dump() for x in payload.leases] if payload.leases is not None else None,
        neighbors=[x.model_dump() for x in payload.neighbors] if payload.neighbors is not None else None,
        bridge_ports=[x.model_dump() for x in payload.bridge_ports] if payload.bridge_ports is not None else None,
        hosts_raw=[h.model_dump() for h in payload.hosts],
        ppp_raw=[p.model_dump() for p in payload.ppp],
    )
    running = (
        state.last_repair_result is not None
        and state.last_repair_result.get("status") == "running"
        and state.last_repair_at is not None
        and (now - state.last_repair_at).total_seconds() < REPAIR_RUNNING_GRACE_SECONDS
    )
    if payload.hosts and not running and realtime_state.repair_due(state, now):
        realtime_state.note_repair(router_id, now, {"status": "running"})
        _spawn(_repair(router_id))


# Queue repairs are RouterOS work; after a deploy every real-time router with a
# queue problem asks for one on its first report. Run a few at a time.
_REPAIR_CONCURRENCY = 3
_repair_slots: Optional[asyncio.Semaphore] = None


def _repair_semaphore() -> asyncio.Semaphore:
    global _repair_slots
    if _repair_slots is None:
        _repair_slots = asyncio.Semaphore(_REPAIR_CONCURRENCY)
    return _repair_slots


_IDENTITY_IN_BODY = re.compile(rb'"identity"\s*:\s*"([^"]{1,64})"')


async def log_rejected_push(request, exc) -> None:
    """Log a rejected (422) router push: which router, which field, the offending text.

    Called from the app's RequestValidationError handler. Only acts on the
    push path; never raises.
    """
    try:
        if request.url.path != "/api/router/usage-push":
            return
        raw = b""
        try:
            raw = await request.body()
        except Exception:
            pass
        m = _IDENTITY_IN_BODY.search(raw or b"")
        identity = m.group(1).decode("ascii", "replace") if m else "?"
        details = []
        for err in exc.errors()[:5]:
            loc = err.get("loc") or ()
            snippet = ""
            if err.get("type") == "json_invalid" and len(loc) > 1 and isinstance(loc[1], int):
                pos = loc[1]
                snippet = (raw[max(0, pos - 60): pos + 60]).decode("utf-8", "backslashreplace")
            else:
                snippet = str(err.get("input"))[:80]
            details.append(f"{'.'.join(str(x) for x in loc)} {err.get('type')} {snippet!r}")
        logger.warning(
            "[USAGE-PUSH] 422 from %s via %s (%d bytes): %s",
            identity, request.headers.get("x-bitwave-push-channel") or "https",
            len(raw or b""), " | ".join(details),
        )
    except Exception as log_exc:  # never let logging break the response
        logger.debug("[USAGE-PUSH] could not log a rejected push: %s", log_exc)


# hAP lite / hAP mini (smips, 32 MB): on 2026-09-26 the real-time push on top of
# our other schedulers pinned them at 100% CPU with ~5 MB free, delaying a paying
# customer. The installer no longer puts v3 on them; any v3 script still on one
# (router offline during rollback) is told to report once an hour, which makes it
# harmless without logging in. Usage there falls back to server polling.
SMALL_BOARD_PUSH_SECONDS = 3600
_SMALL_BOARD_RE = re.compile(r"hap\s*(lite|mini)|rb9[34]1", re.IGNORECASE)


def is_small_board(board: Optional[str]) -> bool:
    return bool(board and _SMALL_BOARD_RE.search(board))


async def _repair(router_id: int) -> None:
    from app.services.mikrotik_background import repair_router_queues_now

    try:
        async with _repair_semaphore():
            details = await repair_router_queues_now(router_id)
        logger.info("[USAGE-PUSH] Queue repair for router %s: %s", router_id, details)
        realtime_state.note_repair(router_id, datetime.utcnow(), {"status": "done", **(details or {})})
    except Exception as exc:
        logger.warning("[USAGE-PUSH] Queue repair for router %s failed: %s", router_id, exc)
        realtime_state.note_repair(
            router_id, datetime.utcnow(), {"status": "failed", "error": str(exc)[:200]}
        )


async def _enforce_caps(customer_ids: list) -> None:
    """FUP for pilot routers, which the cap sampler no longer watches."""
    customer_ids = [c for c in customer_ids if c not in _enforcing]
    if not customer_ids:
        return
    _enforcing.update(customer_ids)
    try:
        await _enforce_caps_now(customer_ids)
    finally:
        _enforcing.difference_update(customer_ids)


_enforcing: set = set()


async def _enforce_caps_now(customer_ids: list) -> None:
    from app.db.models import Customer, CustomerUsagePeriod
    from app.services.fup import evaluate_and_enforce

    for customer_id in customer_ids:
        try:
            async with async_session() as db:
                customer = (
                    await db.execute(
                        select(Customer)
                        .options(selectinload(Customer.plan), selectinload(Customer.router))
                        .where(Customer.id == customer_id)
                    )
                ).scalar_one_or_none()
                period = (
                    await db.execute(
                        select(CustomerUsagePeriod)
                        .where(
                            CustomerUsagePeriod.customer_id == customer_id,
                            CustomerUsagePeriod.closed_at.is_(None),
                        )
                        .order_by(CustomerUsagePeriod.period_start.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if customer is None or period is None:
                    continue
                # Same helper and pattern as the cap sampler, which relies on
                # it committing before its router I/O.
                await evaluate_and_enforce(db, customer, period, plan=customer.plan, now=datetime.utcnow())
                await db.commit()
        except Exception as exc:
            logger.error("[USAGE-PUSH] FUP enforcement failed for customer %s: %s", customer_id, exc)

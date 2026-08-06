"""Router-push usage channel: routers report their own usage instead of us polling.

Why this exists
---------------
Usage has always been derived by polling every router for its simple-queue byte
counters and diffing consecutive samples.  That is a treadmill: the poller walks
the fleet in chunks, so each router is revisited only every ``fleet_size / chunk``
ticks — ~49 minutes at 187 routers, and worse with every router added.  Any
session shorter than that window opens and closes between two samples and is
never counted at all.  Measured on router 277 (SkyNet Connect, who sell 15/30/80
minute plans): 11.28 GB actually crossed the WAN in 24h, 0.37 GB was attributed
to customers — 3.3%.

Pushing inverts the cost.  The router reads counters it already holds in memory,
and reports them on its own outbound check-in — the same direction the
pull-provisioning channel already uses to survive flaky/Starlink uplinks.  Server
cost per router is zero polling, so it does not degrade as the fleet grows.

Two kinds of report arrive on this path:

* **periodic** — "here is where everyone stands right now", every couple of
  minutes.  Feeds the dashboard and cap watching.
* **final** (``final=True``) — sent from the hotspot profile's ``on-logout``
  hook (or PPP ``on-down``) when a session ends, carrying its exact total.  This
  is what makes short sessions exact rather than sampled.

Design constraints
------------------
* Usage is written through :func:`record_queue_usage_sample`, the same helper the
  poller uses, so both paths produce identical rows and the reseller dashboard
  keeps reading one source of truth.
* Ingest is **DB-only**.  Customers that cross their cap are returned to the
  caller for enforcement in a separate step, so no DB session is ever held across
  RouterOS I/O (AGENTS.md, Database Session Discipline).
* This endpoint is reachable from the field, so a report is only ever applied to
  a customer that belongs to the reporting router.  Anything else is rejected and
  counted, never silently dropped.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.database import async_session
from app.db.models import (
    BandwidthSnapshot,
    ConnectionType,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    Plan,
    SubscriptionStatus,
    User,
)
from app.services.mikrotik_api import normalize_mac_address
from app.services.router_availability import record_router_availability
from app.services.usage_counters import record_queue_usage_sample

logger = logging.getLogger(__name__)

# One router's batch is bounded by how many queues it has (fleet peak is ~53), but
# the commit is chunked anyway so a misbehaving or unusually large router can
# never hold a pooled connection open across hundreds of row writes.
PUSH_COMMIT_CHUNK = 100

# A single batch is capped so a malformed or hostile payload cannot make the
# server do unbounded work in one request.
MAX_REPORTS_PER_BATCH = 500

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{12}$")
_PPPOE_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")

# No real queue counter reaches 9 PB. A value above this is a corrupt read or a
# hostile router, and banking it would instantly trip FUP and cut off a paying
# customer — the mirror of the pull channel's free-internet bug. Also keeps every
# value JSON-safe and inside BIGINT.
MAX_PLAUSIBLE_COUNTER_BYTES = 2 ** 53

# Reseller subscription states whose routers we still do work for.
_PAYING_STATUSES = (SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL)


@dataclass
class UsageReport:
    """One queue's cumulative counters as the router sees them.

    ``queue_key`` is the canonical key: a MAC for hotspot queues (any separator
    style — it is normalized here) or ``pppoe:<username>`` for PPPoE.
    """

    queue_key: str
    upload_bytes: int
    download_bytes: int
    final: bool = False
    queue_name: str = ""
    target_ip: str = ""
    max_limit: str = ""


@dataclass
class RouterMetrics:
    """Router-level numbers a reporter may include alongside its usage batch.

    All values are read-only facts the router already holds; nothing here can
    instruct the server to change anything.
    """

    iface_rx_bytes: int
    iface_tx_bytes: int
    hotspot_active: int = 0
    pppoe_active: int = 0
    queue_count: int = 0


@dataclass
class IngestResult:
    accepted: int = 0
    rejected: int = 0
    over_cap_customer_ids: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    snapshot_written: bool = False


# A push-written snapshot at most this often per router. The fleet pushes every
# ~120s; unthrottled that multiplies bandwidth_snapshots growth ~15x over the
# poller. 300s keeps the dashboard ~2.5-5 min fresh at ~2x today's row rate.
PUSH_SNAPSHOT_MIN_INTERVAL_SECONDS = 300

_MAX_ACTIVE_COUNT = 100_000

# NOTE: dashboard usage bars are NOT written here. Every accepted delta reaches
# the per-router ledger (router_usage_buckets) inside record_usage — the same
# transaction that credits the customer's period — so the bars equal the sum of
# the per-customer numbers by construction. The earlier in-memory delta bank
# lost bytes on every restart and raced the poller (2.9%-182% capture,
# 2026-07-30); do not reintroduce process-state bookkeeping for usage.


def _canonical_key(raw: str) -> Optional[str]:
    """Normalize a reported key, or return None if it is not a shape we accept.

    ``normalize_mac_address`` reshapes whatever it is given without validating,
    so the MAC form is checked here — otherwise a junk key would be silently
    turned into a plausible-looking one.
    """
    key = str(raw or "").strip()
    if not key:
        return None
    if key.lower().startswith("pppoe:"):
        username = key.split(":", 1)[1].strip()
        if not username or not _PPPOE_USERNAME_RE.match(username):
            return None
        return f"pppoe:{username}"
    if not _MAC_RE.match(key):
        return None
    return normalize_mac_address(key).upper()


def _index_customers(customers: Iterable[Customer]) -> dict[str, Customer]:
    """Map every canonical key a router may legitimately report to its customer."""
    index: dict[str, Customer] = {}
    for customer in customers:
        if customer.pppoe_username:
            index[f"pppoe:{customer.pppoe_username}"] = customer
        if customer.mac_address:
            normalized = normalize_mac_address(customer.mac_address)
            if normalized:
                index[normalized.upper()] = customer
    return index


def _customer_is_live(customer: Customer, now: datetime) -> bool:
    """Whether this customer should still have usage banked against them.

    Both halves matter: the status flag goes stale (357 customers fleet-wide are
    flagged ACTIVE with an expiry in the past), and expiry alone would count
    someone an operator has explicitly deactivated.
    """
    if customer.status != CustomerStatus.ACTIVE:
        return False
    return customer.expiry is not None and customer.expiry > now


async def _latest_period_is_closed(db, customer_id: int) -> bool:
    """True when this customer's most recent period has been closed.

    A fresh customer with no periods at all is fine — the first report opens one.
    What must not happen is a late report clearing ``closed_at`` on a period that
    is already settled.
    """
    latest = (
        await db.execute(
            select(CustomerUsagePeriod.closed_at)
            .where(CustomerUsagePeriod.customer_id == customer_id)
            .order_by(CustomerUsagePeriod.period_start.desc(), CustomerUsagePeriod.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return latest is not None


def _cap_bytes_for(period: Optional[CustomerUsagePeriod], plan: Optional[Plan]) -> int:
    """Cap in bytes, preferring the period's snapshot so a mid-period plan change
    cannot retroactively move the line (same rule the sampler applies)."""
    cap_mb = None
    if period is not None and period.cap_mb_snapshot is not None:
        cap_mb = period.cap_mb_snapshot
    elif plan is not None:
        cap_mb = plan.data_cap_mb
    return int(cap_mb) * 1024 * 1024 if cap_mb and int(cap_mb) > 0 else 0


def _split_queue_keys(reports: list["UsageReport"]) -> tuple[int, int]:
    """Count the batch's queue keys as (hotspot, pppoe).

    The router names our queues ``plan_<MAC>`` for hotspot and
    ``<pppoe-USERNAME>`` for PPPoE, and the push script already reports only
    those two shapes (see ``usage_push_script``). Counting them here gives a
    hotspot figure that does not depend on ``/ip hotspot active``, which is
    empty on MAC-bypass hotspots — the model most of our resellers run.
    """
    hotspot = 0
    pppoe = 0
    for report in reports:
        key = _canonical_key(report.queue_key)
        if not key:
            continue
        if key.startswith("pppoe:"):
            pppoe += 1
        else:
            hotspot += 1
    return hotspot, pppoe


async def _persist_router_metrics(
    db,
    router_id: int,
    metrics: RouterMetrics,
    now: datetime,
    result: IngestResult,
    reports: list["UsageReport"],
) -> None:
    """Write a bandwidth snapshot from pushed router metrics, throttled.

    This is router HEALTH only — interface counters, throughput, session
    counts. The per-queue byte-delta fields stay zero: usage bars come from
    the router_usage_buckets ledger written by record_usage.

    ``active_queues`` MUST stay the COMBINED hotspot + PPPoE count. The health
    endpoint derives the PPPoE tile as ``active_queues - active_hotspot_users``
    (``mikrotik_routes._health_payload_from_live_result``), so writing the raw
    simple-queue count here republishes every hotspot customer as a phantom
    PPPoE user — see docs/agent-memory/incidents/2026-08-06-hotspot-shown-as-pppoe.md.
    """
    rx = int(metrics.iface_rx_bytes or 0)
    tx = int(metrics.iface_tx_bytes or 0)
    # ``/ip hotspot active`` is empty whenever customers are admitted by MAC
    # ip-binding/bypass rather than a portal login, so it reads 0 fleet-wide.
    # The per-customer queues the same push already carries are the honest
    # count; fall back to the router's own figure only if we got no queues.
    queue_hotspot, queue_pppoe = _split_queue_keys(reports)
    hotspot_sessions = int(metrics.hotspot_active or 0)
    hotspot = queue_hotspot or hotspot_sessions
    pppoe = int(metrics.pppoe_active or 0) or queue_pppoe
    queues = hotspot + pppoe
    if (
        rx < 0 or tx < 0
        or rx > MAX_PLAUSIBLE_COUNTER_BYTES or tx > MAX_PLAUSIBLE_COUNTER_BYTES
        or not (0 <= hotspot <= _MAX_ACTIVE_COUNT)
        or not (0 <= pppoe <= _MAX_ACTIVE_COUNT)
        or not (0 <= queues <= 2 * _MAX_ACTIVE_COUNT)
    ):
        result.errors.append("implausible_router_metrics")
        return

    prev = (
        await db.execute(
            select(BandwidthSnapshot)
            .where(BandwidthSnapshot.router_id == router_id)
            .order_by(BandwidthSnapshot.recorded_at.desc())
            .limit(1)
        )
    ).scalars().first()

    if prev is not None:
        elapsed = (now - prev.recorded_at).total_seconds()
        if elapsed < PUSH_SNAPSHOT_MIN_INTERVAL_SECONDS:
            return  # throttled — not an error, the next push carries the same counters

    avg_download_bps = 0.0
    avg_upload_bps = 0.0
    if prev is not None:
        elapsed = (now - prev.recorded_at).total_seconds()
        rx_delta = rx - int(prev.interface_rx_bytes or 0)
        tx_delta = tx - int(prev.interface_tx_bytes or 0)
        # Negative delta = the router rebooted and its counters reset. Zero
        # rate, never a negative or a spike.
        if elapsed > 0 and rx_delta >= 0 and tx_delta >= 0:
            avg_download_bps = rx_delta * 8 / elapsed
            avg_upload_bps = tx_delta * 8 / elapsed

    db.add(BandwidthSnapshot(
        router_id=router_id,
        interface_rx_bytes=rx,
        interface_tx_bytes=tx,
        active_hotspot_users=hotspot,
        # Hotspot portal logins, matching what mikrotik_background writes here.
        # PPPoE is NOT stored in this column — it is active_queues - hotspot.
        active_sessions=hotspot_sessions,
        active_queues=queues,
        total_download_bps=int(avg_download_bps),
        total_upload_bps=int(avg_upload_bps),
        avg_download_bps=avg_download_bps,
        avg_upload_bps=avg_upload_bps,
        recorded_at=now,
    ))
    result.snapshot_written = True


async def ingest_usage_reports(
    router_id: int,
    reports: list[UsageReport],
    *,
    now: Optional[datetime] = None,
    session_factory=None,
    router_metrics: Optional[RouterMetrics] = None,
) -> IngestResult:
    """Apply one router's batch of usage reports.

    Returns the counts plus the ids of customers whose period crossed its cap in
    this batch.  Enforcement is deliberately *not* done here — the caller runs it
    with no DB session held.
    """
    now = now or datetime.utcnow()
    factory = session_factory or async_session
    result = IngestResult()

    if not reports and router_metrics is None:
        return result

    if len(reports) > MAX_REPORTS_PER_BATCH:
        logger.warning(
            "[USAGE-PUSH] Router %s sent %d reports; truncating to %d",
            router_id, len(reports), MAX_REPORTS_PER_BATCH,
        )
        result.errors.append("batch_truncated")
        reports = reports[:MAX_REPORTS_PER_BATCH]

    async with factory() as db:
        # A reseller who stopped paying still has powered-on routers in the field
        # pushing at us. Do no work for them — this was the single biggest source
        # of junk in the poll path (one dead reseller's router carried 233 expired
        # customers).
        owner_ok = (
            await db.execute(
                select(User.subscription_status)
                .join(Customer, Customer.user_id == User.id)
                .where(Customer.router_id == router_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if owner_ok is not None and owner_ok not in _PAYING_STATUSES:
            result.rejected = len(reports)
            result.errors.append("owner_not_paying")
            return result

        # Only customers on THIS router are addressable. A report naming anyone
        # else is rejected rather than attributed, because this endpoint is
        # reachable from the field.
        owned = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan))
                .where(Customer.router_id == router_id)
            )
        ).scalars().all()
        index = _index_customers(owned)

        pending = 0
        for report in reports:
            key = _canonical_key(report.queue_key)
            if not key:
                result.rejected += 1
                result.errors.append("bad_queue_key")
                continue

            customer = index.get(key)
            if customer is None:
                result.rejected += 1
                result.errors.append(f"unknown_queue_key:{key}")
                continue

            upload = int(report.upload_bytes or 0)
            download = int(report.download_bytes or 0)
            if (
                upload < 0 or download < 0
                or upload > MAX_PLAUSIBLE_COUNTER_BYTES
                or download > MAX_PLAUSIBLE_COUNTER_BYTES
            ):
                result.rejected += 1
                result.errors.append(f"implausible_counter:{key}")
                continue

            plan = customer.plan
            # Usage cannot be sized without a plan, and silently accepting means
            # the reseller sees zero with no explanation.
            if plan is None:
                result.rejected += 1
                result.errors.append(f"customer_has_no_plan:{key}")
                continue
            if plan.connection_type not in (
                ConnectionType.HOTSPOT,
                ConnectionType.PPPOE,
            ):
                result.rejected += 1
                result.errors.append(f"unsupported_connection_type:{key}")
                continue

            # LIFECYCLE BOUND. The pull channel had none, kept serving a command
            # after the plan ended, and gave away free internet (incident
            # 2026-07-15). Our version of that mistake is worse in one direction:
            # a router keeps its queues until cleanup reaches it — which is
            # exactly what fails during the outages this channel exists to
            # survive — so it WILL report for customers whose plan ended. Banking
            # that bills them for traffic after expiry and can trip FUP on
            # someone who no longer has a subscription at all.
            if not _customer_is_live(customer, now):
                result.rejected += 1
                result.errors.append(f"customer_not_live:{key}")
                continue

            # Never resurrect a period that has already been closed and reported
            # on. A late report — a retry over a bad link, or a queue the router
            # only just flushed — must not reopen last month's books.
            if await _latest_period_is_closed(db, customer.id):
                result.rejected += 1
                result.errors.append(f"period_closed:{key}")
                continue

            try:
                update = await record_queue_usage_sample(
                    db,
                    customer=customer,
                    plan=plan,
                    queue_key=key,
                    upload_bytes=upload,
                    download_bytes=download,
                    queue_name=report.queue_name or "",
                    target_ip=report.target_ip or "",
                    max_limit=report.max_limit or "",
                    now=now,
                    first_sample_is_total=bool(report.final),
                )
            except Exception as exc:  # one bad row must not lose the whole batch
                result.rejected += 1
                result.errors.append(f"record_failed:{key}")
                logger.error(
                    "[USAGE-PUSH] Failed to record %s on router %s: %s", key, router_id, exc
                )
                continue

            result.accepted += 1
            pending += 1

            period = update.period
            cap_bytes = _cap_bytes_for(period, plan)
            if (
                period is not None
                and cap_bytes > 0
                and int(period.total_bytes or 0) >= cap_bytes
                and period.fup_triggered_at is None
                and customer.id not in result.over_cap_customer_ids
            ):
                result.over_cap_customer_ids.append(customer.id)

            if pending >= PUSH_COMMIT_CHUNK:
                await db.commit()
                pending = 0

        if router_metrics is not None:
            await _persist_router_metrics(
                db, router_id, router_metrics, now, result, reports
            )

        await db.commit()

    # A push that produced a snapshot is also proof of liveness. The stamp rides
    # the same throttle so the hot routers row is touched every ~5 min per
    # router, not every 2. record_router_availability commits in its OWN short
    # session (lock-convoy discipline; its db parameter is documented unused) —
    # called here with no transaction held.
    if result.snapshot_written:
        try:
            await record_router_availability(
                None, router_id, True, "usage_push", checked_at=now
            )
        except Exception as exc:
            logger.warning("[USAGE-PUSH] availability stamp failed for %s: %s", router_id, exc)

    return result

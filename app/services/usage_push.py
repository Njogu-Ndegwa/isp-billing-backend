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
from app.db.models import ConnectionType, Customer, CustomerUsagePeriod, Plan
from app.services.mikrotik_api import normalize_mac_address
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
class IngestResult:
    accepted: int = 0
    rejected: int = 0
    over_cap_customer_ids: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


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


def _cap_bytes_for(period: Optional[CustomerUsagePeriod], plan: Optional[Plan]) -> int:
    """Cap in bytes, preferring the period's snapshot so a mid-period plan change
    cannot retroactively move the line (same rule the sampler applies)."""
    cap_mb = None
    if period is not None and period.cap_mb_snapshot is not None:
        cap_mb = period.cap_mb_snapshot
    elif plan is not None:
        cap_mb = plan.data_cap_mb
    return int(cap_mb) * 1024 * 1024 if cap_mb and int(cap_mb) > 0 else 0


async def ingest_usage_reports(
    router_id: int,
    reports: list[UsageReport],
    *,
    now: Optional[datetime] = None,
    session_factory=None,
) -> IngestResult:
    """Apply one router's batch of usage reports.

    Returns the counts plus the ids of customers whose period crossed its cap in
    this batch.  Enforcement is deliberately *not* done here — the caller runs it
    with no DB session held.
    """
    now = now or datetime.utcnow()
    factory = session_factory or async_session
    result = IngestResult()

    if not reports:
        return result

    if len(reports) > MAX_REPORTS_PER_BATCH:
        logger.warning(
            "[USAGE-PUSH] Router %s sent %d reports; truncating to %d",
            router_id, len(reports), MAX_REPORTS_PER_BATCH,
        )
        result.errors.append("batch_truncated")
        reports = reports[:MAX_REPORTS_PER_BATCH]

    async with factory() as db:
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

            plan = customer.plan
            if plan is not None and plan.connection_type not in (
                ConnectionType.HOTSPOT,
                ConnectionType.PPPOE,
            ):
                result.rejected += 1
                result.errors.append(f"unsupported_connection_type:{key}")
                continue

            try:
                update = await record_queue_usage_sample(
                    db,
                    customer=customer,
                    plan=plan,
                    queue_key=key,
                    upload_bytes=max(0, int(report.upload_bytes or 0)),
                    download_bytes=max(0, int(report.download_bytes or 0)),
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

        await db.commit()

    return result

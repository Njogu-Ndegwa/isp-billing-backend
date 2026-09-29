"""Shared helpers for RouterOS queue byte counters.

Both the broad bandwidth snapshot job and the capped-user sampler work from
RouterOS simple-queue cumulative byte counters.  These helpers keep the
reset-safe delta calculation and period update semantics in one place so the
reseller dashboard continues to read one source of truth.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Customer, Plan, UserBandwidthUsage
from app.services.usage_tracking import record_usage

logger = logging.getLogger(__name__)

# Line-rate ceiling. No real counter can grow faster than the customer's plan
# speed, so a credit above that is a metering bug, not usage. The ceiling is
# deliberately loose (2x the faster direction, a 60 s floor on the window for
# push/poll jitter, plus fixed slack) so it never clips genuine traffic on a
# queue that bursts or lags; its job is to stop the whole-counter re-bookings
# that inflated ledgers 10-36x on 2026-09-26..29 (duplicate hotspot host
# entries per MAC — see docs/agent-memory/incidents/2026-09-29-host-metering-ghost-entries.md).
LINE_RATE_HEADROOM = 2.0
LINE_RATE_MIN_WINDOW_SECONDS = 60
LINE_RATE_SLACK_BYTES = 8 * 1024 * 1024

@dataclass
class UsageCounterUpdate:
    usage: UserBandwidthUsage
    period: object | None
    delta_upload_bytes: int
    delta_download_bytes: int
    reset_detected: bool
    created: bool
    stale: bool = False


def parse_queue_bytes(bytes_str: str) -> tuple[int, int]:
    parts = str(bytes_str or "0/0").split("/")
    upload = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    download = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return upload, download


def _rate_to_bps(token: str) -> int:
    token = (token or "").strip().upper()
    if not token:
        return 0
    mult = 1
    if token[-1] in "KMG":
        mult = {"K": 1_000, "M": 1_000_000, "G": 1_000_000_000}[token[-1]]
        token = token[:-1]
    try:
        return int(float(token) * mult)
    except ValueError:
        return 0


def plan_line_rate_bps(plan: Optional[Plan]) -> int:
    """Fastest direction of the plan's speed (``"5M/10M"`` -> 10_000_000), or 0."""
    speed = str(getattr(plan, "speed", "") or "").strip().split(" ", 1)[0]
    if not speed:
        return 0
    return max((_rate_to_bps(part) for part in speed.split("/")), default=0)


def line_rate_ceiling_bytes(plan: Optional[Plan], elapsed_seconds: float) -> Optional[int]:
    """Most bytes one direction can plausibly move in ``elapsed_seconds``.

    ``None`` when the plan speed is unknown — then nothing is clamped.
    """
    rate = plan_line_rate_bps(plan)
    if rate <= 0:
        return None
    window = max(float(elapsed_seconds or 0), 0.0) + LINE_RATE_MIN_WINDOW_SECONDS
    return int(rate / 8 * window * LINE_RATE_HEADROOM) + LINE_RATE_SLACK_BYTES


def clamp_to_line_rate(
    delta_up: int,
    delta_dn: int,
    plan: Optional[Plan],
    last_sampled_at: Optional[datetime],
    now: datetime,
    *,
    key: str = "",
) -> tuple[int, int]:
    """Cap a delta at what the plan's line rate allows since the last sample."""
    if last_sampled_at is None:
        return delta_up, delta_dn
    ceiling = line_rate_ceiling_bytes(plan, (now - last_sampled_at).total_seconds())
    if ceiling is None or (delta_up <= ceiling and delta_dn <= ceiling):
        return delta_up, delta_dn
    logger.warning(
        "[USAGE] Clamped impossible delta for %s: %s/%s bytes in %.0fs exceeds "
        "line-rate ceiling %s (plan speed %r)",
        key, delta_up, delta_dn, (now - last_sampled_at).total_seconds(),
        ceiling, getattr(plan, "speed", None),
    )
    return min(delta_up, ceiling), min(delta_dn, ceiling)


def usage_counter_delta(
    usage: UserBandwidthUsage,
    upload_bytes: int,
    download_bytes: int,
) -> tuple[int, int, bool]:
    """Return reset-safe deltas and whether the router counter reset."""
    prev_up = int(usage.last_upload_bytes or 0)
    prev_dn = int(usage.last_download_bytes or 0)
    legacy_baseline = (
        prev_up == 0
        and prev_dn == 0
        and ((usage.upload_bytes or 0) > 0 or (usage.download_bytes or 0) > 0)
    )
    if legacy_baseline:
        return 0, 0, False
    if upload_bytes < prev_up or download_bytes < prev_dn:
        return upload_bytes, download_bytes, True
    return upload_bytes - prev_up, download_bytes - prev_dn, False


async def record_queue_usage_sample(
    db: AsyncSession,
    *,
    customer: Optional[Customer],
    plan: Optional[Plan],
    queue_key: str,
    upload_bytes: int,
    download_bytes: int,
    queue_name: str = "",
    target_ip: str = "",
    max_limit: str = "",
    now: Optional[datetime] = None,
    legacy_keys: Optional[Iterable[str]] = None,
    first_sample_is_total: bool = False,
    sampled_at: Optional[datetime] = None,
) -> UsageCounterUpdate:
    """Persist one cumulative queue sample and roll its delta into the period.

    ``queue_key`` is the canonical key stored in ``user_bandwidth_usage``:
    normalized MAC for hotspot queues and ``pppoe:<username>`` for PPPoE
    dynamic queues.  ``legacy_keys`` lets callers find old rows stored under a
    compact or raw MAC form, then normalize them in-place.

    ``first_sample_is_total`` changes what an unseen queue means. Polling cannot
    know how much traffic preceded the first sample it happens to catch, so it
    records a baseline and counts nothing — the default. A router's on-logout
    report is different: it carries the whole session total and there is nothing
    before it, so the first sample IS the usage. Only the push channel sets this.

    ``sampled_at`` is when the counters were READ FROM THE ROUTER, as opposed to
    ``now`` (when they are applied). The counter stream has three readers (push
    ingest, the bandwidth poller, the cap sampler); a reader that fetched before
    another reader's write but applies after it would see a counter below the
    baseline, trip the reset rule, and re-book the queue's whole lifetime
    counter (bars at 142-182% of real traffic, 2026-07-30). Any sample older
    than the row's last write is therefore discarded whole — the fresher reader
    already accounted for those bytes. Genuine reboot/relogin resets are
    unaffected: their reads are fresh.
    """
    now = now or datetime.utcnow()
    sampled_at = sampled_at or now
    keys = [queue_key]
    if legacy_keys:
        keys.extend(k for k in legacy_keys if k)
    keys = list(dict.fromkeys(keys))

    # The lookup is scoped to THE KEY BEING SAMPLED, and within that key to this
    # customer (or an unclaimed legacy row). Two invariants, each learned the
    # hard way:
    #
    # * Never another customer's row for the same key — MAC is unique per
    #   RESELLER, not globally, so two resellers legitimately hold the same MAC;
    #   sharing one row interleaved their counters and billed each other's
    #   traffic (fixed in PR #20).
    # * Never a row for a DIFFERENT key — a customer owns one row per device key
    #   they have ever used (one in prod owns 25). PR #20's first attempt looked
    #   up by customer alone, grabbed an arbitrary row and rewrote its key,
    #   manufacturing duplicate rows per MAC; the bandwidth poller's
    #   one-row-expected lookup then aborted every run before its rotation
    #   cursor advanced, freezing router dashboards fleet-wide (2026-07-29).
    stmt = select(UserBandwidthUsage).where(UserBandwidthUsage.mac_address.in_(keys))
    order = []
    if customer is not None:
        stmt = stmt.where(
            or_(
                UserBandwidthUsage.customer_id == customer.id,
                UserBandwidthUsage.customer_id.is_(None),
            )
        )
        # Prefer this customer's claimed row over adopting an unclaimed one.
        order.append((UserBandwidthUsage.customer_id == customer.id).desc())
    order.append(UserBandwidthUsage.last_updated.desc())
    stmt = stmt.order_by(*order).limit(1)
    try:
        stmt = stmt.with_for_update()
    except Exception:
        pass
    usage = (await db.execute(stmt)).scalars().first()

    created = False
    if usage and usage.last_updated and sampled_at < usage.last_updated:
        # Stale read: a fresher writer has already advanced this row past the
        # moment these counters were fetched. Applying them would regress the
        # baseline and/or fake a reset. Drop the sample entirely — no counter
        # update, no period credit. The bytes it carried were (or will be)
        # accounted for by the fresher reader's own delta.
        return UsageCounterUpdate(
            usage=usage,
            period=None,
            delta_upload_bytes=0,
            delta_download_bytes=0,
            reset_detected=False,
            created=False,
            stale=True,
        )
    if usage:
        delta_up, delta_dn, reset_detected = usage_counter_delta(
            usage, upload_bytes, download_bytes
        )
        delta_up, delta_dn = clamp_to_line_rate(
            delta_up, delta_dn, plan, usage.last_updated, now, key=queue_key
        )
        usage.mac_address = queue_key
        usage.upload_bytes = upload_bytes
        usage.download_bytes = download_bytes
        usage.last_upload_bytes = upload_bytes
        usage.last_download_bytes = download_bytes
        usage.max_limit = max_limit
        usage.queue_name = queue_name
        usage.target_ip = target_ip
        usage.last_updated = now
        if customer:
            usage.customer_id = customer.id
    else:
        created = True
        delta_up = upload_bytes if first_sample_is_total else 0
        delta_dn = download_bytes if first_sample_is_total else 0
        reset_detected = False
        usage = UserBandwidthUsage(
            mac_address=queue_key,
            customer_id=customer.id if customer else None,
            queue_name=queue_name,
            target_ip=target_ip,
            upload_bytes=upload_bytes,
            download_bytes=download_bytes,
            last_upload_bytes=upload_bytes,
            last_download_bytes=download_bytes,
            max_limit=max_limit,
            last_updated=now,
        )
        db.add(usage)
        # Sessions run with autoflush off: without this, a second sample for the
        # same key in one batch would not find this pending row and would create
        # a duplicate, and later samples would alternate between the two rows.
        await db.flush()

    period = None
    if customer and plan:
        period = await record_usage(
            db,
            customer,
            delta_up,
            delta_dn,
            plan=plan,
            now=now,
        )

    return UsageCounterUpdate(
        usage=usage,
        period=period,
        delta_upload_bytes=delta_up,
        delta_download_bytes=delta_dn,
        reset_detected=reset_detected,
        created=created,
    )

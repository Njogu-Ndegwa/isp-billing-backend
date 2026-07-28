"""Shared helpers for RouterOS queue byte counters.

Both the broad bandwidth snapshot job and the capped-user sampler work from
RouterOS simple-queue cumulative byte counters.  These helpers keep the
reset-safe delta calculation and period update semantics in one place so the
reseller dashboard continues to read one source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Customer, Plan, UserBandwidthUsage
from app.services.usage_tracking import record_usage


@dataclass
class UsageCounterUpdate:
    usage: UserBandwidthUsage
    period: object | None
    delta_upload_bytes: int
    delta_download_bytes: int
    reset_detected: bool
    created: bool


def parse_queue_bytes(bytes_str: str) -> tuple[int, int]:
    parts = str(bytes_str or "0/0").split("/")
    upload = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    download = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return upload, download


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
    """
    now = now or datetime.utcnow()
    keys = [queue_key]
    if legacy_keys:
        keys.extend(k for k in legacy_keys if k)
    keys = list(dict.fromkeys(keys))

    # Scope to the customer whenever we know it. MAC is unique per RESELLER, not
    # globally, so two resellers legitimately hold the same MAC (randomised phone
    # MACs collide readily). Looking up on the key alone put both customers on one
    # counter row: each sample then looked like a counter reset to the other and
    # both accrued the other's traffic. Legacy rows predate the customer link, so
    # fall back to the key and adopt the row — it self-heals on first sight.
    usage = None
    if customer is not None:
        by_customer = select(UserBandwidthUsage).where(
            UserBandwidthUsage.customer_id == customer.id
        ).limit(1)
        try:
            by_customer = by_customer.with_for_update()
        except Exception:
            pass
        usage = (await db.execute(by_customer)).scalar_one_or_none()

    if usage is None:
        stmt = select(UserBandwidthUsage).where(
            UserBandwidthUsage.mac_address.in_(keys)
        )
        if customer is not None:
            stmt = stmt.where(UserBandwidthUsage.customer_id.is_(None))
        stmt = stmt.limit(1)
        try:
            stmt = stmt.with_for_update()
        except Exception:
            pass
        usage = (await db.execute(stmt)).scalar_one_or_none()

    created = False
    if usage:
        delta_up, delta_dn, reset_detected = usage_counter_delta(
            usage, upload_bytes, download_bytes
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

"""Lightweight capped-usage sampler for direct-API routers.

The broad bandwidth snapshot job gathers dashboard/router health data.  This
sampler is deliberately narrower: for routers with capped customers, fetch only
simple-queue byte counters, write reset-safe deltas into the existing usage
tables, and let FUP enforcement run when the period crosses its cap.

DB sessions are kept out of RouterOS I/O:

1. Claim due watch rows and close the DB transaction.
2. Poll RouterOS queues with no DB session open.
3. Persist usage deltas and schedule the next poll in a fresh DB transaction.
4. Trigger FUP using the existing helper, which commits before router I/O.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import selectinload

from app.db.database import async_session, db_pool_snapshot
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    Plan,
    Router,
    RouterAuthMethod,
    UsageCapWatchState,
)
from app.services.fup import evaluate_and_enforce
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.services.usage_counters import parse_queue_bytes, record_queue_usage_sample

logger = logging.getLogger(__name__)


CAP_WATCH_DB_BUSY_THRESHOLD_PERCENT = 60
CAP_WATCH_SEED_LIMIT = 500
CAP_WATCH_MAX_ROUTERS_PER_RUN = 6
CAP_WATCH_MAX_CUSTOMERS_PER_ROUTER = 250
CAP_WATCH_ROUTER_CONCURRENCY = 3
CAP_WATCH_LOCK_STALE_AFTER = timedelta(minutes=5)


@dataclass
class WatchItem:
    state_id: int
    customer_id: int
    router_id: int
    queue_key: str
    connection_type: ConnectionType
    mac_address: Optional[str]
    pppoe_username: Optional[str]
    router_info: dict[str, Any]


@dataclass
class QueueSample:
    item: WatchItem
    queue: Optional[dict[str, Any]] = None
    error: Optional[str] = None


cap_sampler_running = False


def _db_pool_is_busy() -> bool:
    snapshot = db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    if isinstance(checked_out_percent, (int, float)) and checked_out_percent >= CAP_WATCH_DB_BUSY_THRESHOLD_PERCENT:
        logger.warning(
            "[CAP-WATCH] Skipping capped-usage sampler because DB pool is busy: "
            "checked_out=%s/%s (%.2f%%), status=%s",
            snapshot.get("checked_out"),
            snapshot.get("configured_max_app_connections"),
            checked_out_percent,
            snapshot.get("status"),
        )
        return True
    return False


def _queue_key_for(customer: Customer, plan: Plan) -> Optional[str]:
    if plan.connection_type == ConnectionType.HOTSPOT:
        if not customer.mac_address:
            return None
        return normalize_mac_address(customer.mac_address)
    if plan.connection_type == ConnectionType.PPPOE:
        username = (customer.pppoe_username or "").strip()
        if not username:
            return None
        return f"pppoe:{username}"
    return None


def _router_info(router: Router) -> dict[str, Any]:
    return {
        "id": router.id,
        "name": router.name,
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
    }


async def _seed_missing_watch_states(db, now: datetime) -> int:
    """Create watch rows for active capped direct-API customers in small batches."""
    state_missing = UsageCapWatchState.id.is_(None)
    capped_plan_or_period = or_(
        and_(Plan.data_cap_mb.isnot(None), Plan.data_cap_mb > 0),
        and_(
            CustomerUsagePeriod.cap_mb_snapshot.isnot(None),
            CustomerUsagePeriod.cap_mb_snapshot > 0,
        ),
    )
    stmt = (
        select(Customer, Plan)
        .join(Plan, Customer.plan_id == Plan.id)
        .join(Router, Customer.router_id == Router.id)
        .outerjoin(UsageCapWatchState, UsageCapWatchState.customer_id == Customer.id)
        .outerjoin(
            CustomerUsagePeriod,
            and_(
                CustomerUsagePeriod.customer_id == Customer.id,
                CustomerUsagePeriod.closed_at.is_(None),
            ),
        )
        .where(
            state_missing,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.router_id.isnot(None),
            Plan.connection_type.in_([ConnectionType.HOTSPOT, ConnectionType.PPPOE]),
            capped_plan_or_period,
            Router.auth_method == RouterAuthMethod.DIRECT_API,
        )
        .order_by(Customer.id)
        .limit(CAP_WATCH_SEED_LIMIT)
    )
    rows = (await db.execute(stmt)).all()
    added = 0
    for customer, plan in rows:
        queue_key = _queue_key_for(customer, plan)
        if not queue_key or not customer.router_id:
            continue
        db.add(
            UsageCapWatchState(
                customer_id=customer.id,
                router_id=customer.router_id,
                queue_key=queue_key,
                next_poll_at=now,
                poll_interval_seconds=60,
                poll_tier="new",
                created_at=now,
                updated_at=now,
            )
        )
        added += 1
    if added:
        await db.flush()
        logger.info("[CAP-WATCH] Seeded %d capped customer watch row(s)", added)
    return added


def _due_filters(now: datetime):
    stale_lock_before = now - CAP_WATCH_LOCK_STALE_AFTER
    return (
        UsageCapWatchState.next_poll_at <= now,
        or_(UsageCapWatchState.backoff_until.is_(None), UsageCapWatchState.backoff_until <= now),
        or_(UsageCapWatchState.locked_at.is_(None), UsageCapWatchState.locked_at < stale_lock_before),
        Customer.status == CustomerStatus.ACTIVE,
        Customer.router_id.isnot(None),
        Plan.connection_type.in_([ConnectionType.HOTSPOT, ConnectionType.PPPOE]),
        or_(
            and_(Plan.data_cap_mb.isnot(None), Plan.data_cap_mb > 0),
            and_(
                CustomerUsagePeriod.cap_mb_snapshot.isnot(None),
                CustomerUsagePeriod.cap_mb_snapshot > 0,
            ),
        ),
        Router.auth_method == RouterAuthMethod.DIRECT_API,
    )


async def _claim_due_watch_items(now: datetime, run_id: str) -> list[WatchItem]:
    if _db_pool_is_busy():
        return []

    async with async_session() as db:
        await _seed_missing_watch_states(db, now)

        oldest_due = func.min(UsageCapWatchState.next_poll_at)
        router_rows = await db.execute(
            select(
                UsageCapWatchState.router_id,
                oldest_due.label("oldest_due"),
            )
            .join(Customer, UsageCapWatchState.customer_id == Customer.id)
            .join(Plan, Customer.plan_id == Plan.id)
            .join(Router, UsageCapWatchState.router_id == Router.id)
            .outerjoin(
                CustomerUsagePeriod,
                and_(
                    CustomerUsagePeriod.customer_id == Customer.id,
                    CustomerUsagePeriod.closed_at.is_(None),
                ),
            )
            .where(*_due_filters(now))
            .group_by(UsageCapWatchState.router_id)
            .order_by(oldest_due)
            .limit(CAP_WATCH_MAX_ROUTERS_PER_RUN)
        )
        router_ids = [row.router_id for row in router_rows]
        if not router_ids:
            await db.commit()
            return []

        rows = await db.execute(
            select(UsageCapWatchState, Customer, Plan, Router)
            .join(Customer, UsageCapWatchState.customer_id == Customer.id)
            .join(Plan, Customer.plan_id == Plan.id)
            .join(Router, UsageCapWatchState.router_id == Router.id)
            .outerjoin(
                CustomerUsagePeriod,
                and_(
                    CustomerUsagePeriod.customer_id == Customer.id,
                    CustomerUsagePeriod.closed_at.is_(None),
                ),
            )
            .where(UsageCapWatchState.router_id.in_(router_ids), *_due_filters(now))
            .order_by(UsageCapWatchState.router_id, UsageCapWatchState.next_poll_at)
        )

        items: list[WatchItem] = []
        per_router_counts: dict[int, int] = defaultdict(int)
        for state, customer, plan, router in rows:
            if per_router_counts[router.id] >= CAP_WATCH_MAX_CUSTOMERS_PER_ROUTER:
                continue
            queue_key = _queue_key_for(customer, plan)
            if not queue_key:
                state.last_error = "missing_queue_key"
                state.next_poll_at = now + timedelta(minutes=10)
                state.updated_at = now
                continue

            state.router_id = router.id
            state.queue_key = queue_key
            state.locked_at = now
            state.locked_by = run_id
            state.updated_at = now
            items.append(
                WatchItem(
                    state_id=state.id,
                    customer_id=customer.id,
                    router_id=router.id,
                    queue_key=queue_key,
                    connection_type=plan.connection_type,
                    mac_address=customer.mac_address,
                    pppoe_username=customer.pppoe_username,
                    router_info=_router_info(router),
                )
            )
            per_router_counts[router.id] += 1

        await db.commit()
        return items


def _fetch_queue_usage_for_router_sync(router_info: dict[str, Any]) -> dict[str, Any]:
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=10,
        connect_timeout=4,
    )
    if not api.connect():
        return {"error": api.last_connect_error or "connect_failed"}
    try:
        return api.send_command_optimized(
            "/queue/simple/print",
            proplist=[".id", "name", "target", "max-limit", "disabled", "comment", "bytes"],
        )
    finally:
        api.disconnect()


def _queue_indexes(queues: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    by_name: dict[str, dict[str, Any]] = {}
    by_mac: dict[str, dict[str, Any]] = {}
    by_pppoe: dict[str, dict[str, Any]] = {}

    for queue in queues:
        name = str(queue.get("name") or "").strip()
        lower_name = name.lower()
        if lower_name:
            by_name[lower_name] = queue

        comment = str(queue.get("comment") or "")
        if "MAC:" in comment:
            mac = comment.split("MAC:", 1)[1].split("|", 1)[0].strip()
            if mac:
                try:
                    normalized = normalize_mac_address(mac)
                except Exception:
                    normalized = mac.upper()
                by_mac[normalized.upper()] = queue
                by_mac[normalized.replace(":", "").upper()] = queue

        if lower_name.startswith("plan_"):
            suffix = name[5:].replace(":", "").upper()
            if len(suffix) == 12:
                by_mac[suffix] = queue

        if lower_name.startswith("<pppoe-") and lower_name.endswith(">"):
            username = name[7:-1]
            by_pppoe[f"pppoe:{username}"] = queue
            by_pppoe[f"pppoe:{username}".lower()] = queue

    return {"name": by_name, "mac": by_mac, "pppoe": by_pppoe}


def _find_queue_for_item(item: WatchItem, indexes: dict[str, dict[str, dict[str, Any]]]) -> Optional[dict[str, Any]]:
    if item.connection_type == ConnectionType.HOTSPOT:
        normalized = normalize_mac_address(item.mac_address or item.queue_key)
        compact = normalized.replace(":", "")
        return (
            indexes["mac"].get(normalized.upper())
            or indexes["mac"].get(compact.upper())
            or indexes["name"].get(f"plan_{compact}".lower())
            or indexes["name"].get(f"queue_{compact}".lower())
        )
    if item.connection_type == ConnectionType.PPPOE:
        key = item.queue_key
        username = key.split(":", 1)[1] if ":" in key else (item.pppoe_username or "")
        return (
            indexes["pppoe"].get(key)
            or indexes["pppoe"].get(key.lower())
            or indexes["name"].get(f"<pppoe-{username}>".lower())
        )
    return None


async def _poll_router(router_id: int, items: list[WatchItem], semaphore: asyncio.Semaphore) -> list[QueueSample]:
    router_info = items[0].router_info
    async with semaphore:
        raw = await asyncio.to_thread(_fetch_queue_usage_for_router_sync, router_info)

    if raw.get("error"):
        error = raw.get("error", "queue_fetch_failed")
        logger.warning("[CAP-WATCH] Router %s queue poll failed: %s", router_id, error)
        return [QueueSample(item=item, error=error) for item in items]

    queues = raw.get("data") or []
    indexes = _queue_indexes(queues)
    samples: list[QueueSample] = []
    for item in items:
        queue = _find_queue_for_item(item, indexes)
        if not queue:
            samples.append(QueueSample(item=item, error="queue_not_found"))
        else:
            samples.append(QueueSample(item=item, queue=queue))
    return samples


async def _poll_due_routers(items: list[WatchItem]) -> list[QueueSample]:
    if not items:
        return []
    grouped: dict[int, list[WatchItem]] = defaultdict(list)
    for item in items:
        grouped[item.router_id].append(item)

    semaphore = asyncio.Semaphore(CAP_WATCH_ROUTER_CONCURRENCY)
    outcomes = await asyncio.gather(
        *[_poll_router(router_id, router_items, semaphore) for router_id, router_items in grouped.items()],
        return_exceptions=True,
    )

    samples: list[QueueSample] = []
    for outcome in outcomes:
        if isinstance(outcome, Exception):
            logger.error("[CAP-WATCH] Router poll task crashed: %s", outcome)
            continue
        samples.extend(outcome)
    return samples


def _poll_schedule_for(period: Optional[CustomerUsagePeriod], plan: Plan) -> tuple[int, str]:
    cap_mb = period.cap_mb_snapshot if (period and period.cap_mb_snapshot is not None) else plan.data_cap_mb
    if not cap_mb or cap_mb <= 0:
        return 300, "uncapped"
    total_bytes = int(period.total_bytes or 0) if period else 0
    cap_bytes = int(cap_mb) * 1024 * 1024
    pct = total_bytes / cap_bytes if cap_bytes > 0 else 0

    if total_bytes >= cap_bytes:
        return 300, "over_cap"
    if cap_mb <= 100:
        return 15, "small_cap"
    if pct >= 0.95:
        return 15, "critical"
    if pct >= 0.80:
        return 30, "near_cap"
    if pct >= 0.50:
        return 60, "watch"
    return 300, "normal"


def _backoff_seconds(consecutive_errors: int) -> int:
    return min(900, 30 * (2 ** min(max(consecutive_errors - 1, 0), 5)))


async def _persist_samples(samples: list[QueueSample], now: datetime) -> list[int]:
    if not samples:
        return []

    by_customer_id = {sample.item.customer_id: sample for sample in samples}
    over_cap_customer_ids: list[int] = []

    async with async_session() as db:
        rows = await db.execute(
            select(UsageCapWatchState, Customer, Plan)
            .join(Customer, UsageCapWatchState.customer_id == Customer.id)
            .join(Plan, Customer.plan_id == Plan.id)
            .options(selectinload(Customer.plan))
            .where(UsageCapWatchState.customer_id.in_(by_customer_id.keys()))
        )
        for state, customer, plan in rows:
            sample = by_customer_id.get(customer.id)
            if not sample:
                continue

            state.locked_at = None
            state.locked_by = None
            state.updated_at = now

            if sample.error and sample.error != "queue_not_found":
                state.consecutive_errors = (state.consecutive_errors or 0) + 1
                seconds = _backoff_seconds(state.consecutive_errors)
                state.poll_interval_seconds = seconds
                state.poll_tier = "backoff"
                state.backoff_until = now + timedelta(seconds=seconds)
                state.next_poll_at = state.backoff_until
                state.last_error = sample.error[:500]
                continue

            if sample.error == "queue_not_found":
                # Usually means the customer is not currently connected or the
                # queue repair job has not created the plan queue yet. Keep this
                # lightweight and retry without treating it as router failure.
                state.consecutive_errors = 0
                state.backoff_until = None
                state.last_polled_at = now
                state.poll_interval_seconds = 120
                state.poll_tier = "queue_missing"
                state.next_poll_at = now + timedelta(seconds=120)
                state.last_error = "queue_not_found"
                continue

            queue = sample.queue or {}
            upload_bytes, download_bytes = parse_queue_bytes(queue.get("bytes", "0/0"))
            legacy_keys: list[str] = []
            if plan.connection_type == ConnectionType.HOTSPOT and customer.mac_address:
                normalized = normalize_mac_address(customer.mac_address)
                legacy_keys.extend([customer.mac_address, normalized.replace(":", "")])

            update = await record_queue_usage_sample(
                db,
                customer=customer,
                plan=plan,
                queue_key=sample.item.queue_key,
                upload_bytes=upload_bytes,
                download_bytes=download_bytes,
                queue_name=queue.get("name", ""),
                target_ip=queue.get("target", ""),
                max_limit=queue.get("max-limit", ""),
                now=now,
                legacy_keys=legacy_keys,
            )
            if update.reset_detected:
                logger.info(
                    "[CAP-WATCH] Counter reset for customer=%s key=%s now=%s/%s",
                    customer.id,
                    sample.item.queue_key,
                    upload_bytes,
                    download_bytes,
                )

            interval, tier = _poll_schedule_for(update.period, plan)
            state.consecutive_errors = 0
            state.backoff_until = None
            state.last_polled_at = now
            state.poll_interval_seconds = interval
            state.poll_tier = tier
            state.next_poll_at = now + timedelta(seconds=interval)
            state.last_error = None

            cap_mb = update.period.cap_mb_snapshot if (update.period and update.period.cap_mb_snapshot is not None) else plan.data_cap_mb
            cap_bytes = int(cap_mb or 0) * 1024 * 1024
            if (
                update.period
                and cap_bytes > 0
                and int(update.period.total_bytes or 0) >= cap_bytes
                and update.period.fup_triggered_at is None
            ):
                over_cap_customer_ids.append(customer.id)

        await db.commit()

    return over_cap_customer_ids


async def _enforce_over_cap_customers(customer_ids: list[int], now: datetime) -> int:
    if not customer_ids:
        return 0

    enforced = 0
    async with async_session() as db:
        result = await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan))
            .where(Customer.id.in_(customer_ids))
        )
        customers = result.scalars().all()
        for customer in customers:
            plan = customer.plan
            if not plan:
                continue
            period_result = await db.execute(
                select(CustomerUsagePeriod)
                .where(
                    CustomerUsagePeriod.customer_id == customer.id,
                    CustomerUsagePeriod.closed_at.is_(None),
                )
                .order_by(CustomerUsagePeriod.period_start.desc())
                .limit(1)
            )
            period = period_result.scalar_one_or_none()
            if not period:
                continue

            state = (
                await db.execute(
                    select(UsageCapWatchState)
                    .where(UsageCapWatchState.customer_id == customer.id)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if state:
                state.last_enforcement_attempt_at = now
                state.last_enforcement_error = None
                state.updated_at = now

            try:
                action = await evaluate_and_enforce(db, customer, period, plan=plan, now=now)
                if action is not None or period.fup_triggered_at is not None:
                    enforced += 1
                    if state:
                        state.last_enforcement_error = None
                elif state:
                    state.last_enforcement_error = "not_applied"
            except (socket.timeout, OSError) as exc:
                if state:
                    state.last_enforcement_error = str(exc)[:500]
                logger.warning("[CAP-WATCH] FUP enforcement I/O failed for customer %s: %s", customer.id, exc)
            except Exception as exc:
                if state:
                    state.last_enforcement_error = str(exc)[:500]
                logger.error("[CAP-WATCH] FUP enforcement failed for customer %s: %s", customer.id, exc)
            await db.commit()

    return enforced


async def sample_capped_usage_background() -> None:
    """APScheduler entrypoint for lightweight capped usage collection."""
    global cap_sampler_running
    if cap_sampler_running:
        logger.warning("[CAP-WATCH] Previous sampler run still active, skipping")
        return

    cap_sampler_running = True
    run_id = f"{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow()
    started = datetime.utcnow()
    try:
        items = await _claim_due_watch_items(now, run_id)
        if not items:
            return

        logger.info(
            "[CAP-WATCH] Polling %d capped customer(s) across %d router(s)",
            len(items),
            len({item.router_id for item in items}),
        )
        samples = await _poll_due_routers(items)

        if _db_pool_is_busy():
            return
        over_cap_ids = await _persist_samples(samples, datetime.utcnow())
        enforced = await _enforce_over_cap_customers(over_cap_ids, datetime.utcnow())
        duration = (datetime.utcnow() - started).total_seconds()
        logger.info(
            "[CAP-WATCH] Completed in %.2fs: samples=%d, over_cap=%d, enforced=%d",
            duration,
            len(samples),
            len(over_cap_ids),
            enforced,
        )
    except Exception as exc:
        logger.error("[CAP-WATCH] Sampler failed: %s", exc, exc_info=True)
    finally:
        cap_sampler_running = False

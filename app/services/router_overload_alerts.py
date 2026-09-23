"""Automatic "your router is overloaded" alerts to the router's owner (reseller).

Why (2026-09-23): router 371, a hAP lite, sat at 100% CPU every evening. Pings
still passed, but a RouterOS API login took ~100 s, so every evening payment on
it failed to provision (16 payments, 11 customers, one paid four times) and
nobody told the reseller.

Two signals, two levels:

* CRITICAL, from payments (no router access needed): at least
  ``PAYMENT_FAILURE_THRESHOLD`` payment provisioning attempts on one router
  failed or are retrying within ``PAYMENT_FAILURE_WINDOW`` while a bare TCP
  connect to its API port still succeeds. "TCP up but provisioning failing" is
  the overload signature; an unreachable router is left to the existing
  offline alerts (router_status_alerts).
* WARNING / CRITICAL, from CPU (SNMP, once a router is enrolled): CPU at or
  above ``CPU_WARNING_PERCENT`` for ``CPU_WARNING_SAMPLES`` consecutive samples
  (about 10 minutes at the 5-minute poll), or at ``CPU_CRITICAL_PERCENT`` for
  ``CPU_CRITICAL_SAMPLES`` consecutive samples.

Delivery: reseller inbox message plus an SMS, paid by the PLATFORM (Dennis,
2026-09-24): ``credits_charged = 0`` and sent on the platform gateway. At most
one alert per level per router per local (EAT) day, claimed with an atomic
UPDATE on ``routers.overload_{warning,critical}_notified_at``. Honours the
existing per-router opt-out ``routers.status_alerts_enabled`` and skips routers
whose owner is suspended/inactive (they are cut off anyway).

Safety (must never slow payments, expiry cleanup or the scheduler):
* The payment scan is one indexed read in a short session, then released.
* The TCP check is ``asyncio.open_connection`` with a short timeout, only for the
  handful of candidate routers; no thread, no RouterOS login, no router lock,
  no circuit breaker.
* SNMP runs on the event loop too (app/services/snmp_cpu.py), bounded by a
  semaphore and a per-request timeout.
* Alert rows commit in their own short session; the provider send happens
  afterwards in a fire-and-forget task. Every public entry point swallows and
  logs its own errors, and the scheduler jobs skip when the DB pool is busy.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Optional, Tuple

from sqlalchemy import func, select, update

from app.config import settings
from app.core.local_time import local_midnight_utc
from app.db import database
from app.db.models import (
    MessagingSettings,
    ProvisioningAttempt,
    ProvisioningState,
    ResellerInboxMessage,
    Router,
    SmsMessage, SmsMessageKind, SmsMessageStatus,
    SubscriptionStatus,
    User,
)
from app.services import sms_dispatch, snmp_cpu
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import count_segments
from app.services.reseller_welcome import _resolve_sender_admin_id
from app.services.router_status_alerts import _db_pool_too_busy

logger = logging.getLogger(__name__)

OVERLOAD_SMS_CATEGORY = "router_overload_alert"
LEVEL_WARNING = "warning"
LEVEL_CRITICAL = "critical"

PAYMENT_FAILURE_WINDOW = timedelta(minutes=20)
PAYMENT_FAILURE_THRESHOLD = 3
TCP_CHECK_TIMEOUT_SECONDS = 3.0

CPU_WARNING_PERCENT = 90
CPU_WARNING_SAMPLES = 3      # 3 x 5-min samples ~ sustained for 10 minutes
CPU_CRITICAL_PERCENT = 100
CPU_CRITICAL_SAMPLES = 2
CPU_SAMPLE_MAX_GAP = timedelta(minutes=8)   # a gap breaks "sustained"
SNMP_CONCURRENCY = 20

_FAILING_STATES = (ProvisioningState.RETRY_PENDING, ProvisioningState.FAILED)
_CUT_OFF_OWNER = (SubscriptionStatus.SUSPENDED, SubscriptionStatus.INACTIVE)
_UPGRADE_HINT = ("If this happens every evening, consider a stronger router "
                 "(hAP ac2, hEX or hAP ax lite).")

# router_id -> recent (sampled_at, cpu_percent); process-local on purpose: a
# restart only delays the "sustained" verdict by a few samples.
_cpu_history: Dict[int, Deque[Tuple[datetime, int]]] = defaultdict(lambda: deque(maxlen=6))


# --- copy -------------------------------------------------------------------------

def render_payment_overload(name: str, failures: int) -> Tuple[str, str]:
    subject = f"Router overloaded: {name}"
    body = (f"Bitwave: your router '{name}' is overloaded. {failures} payments in the "
            f"last 20 minutes could not be connected because it is too busy to respond. "
            f"Please restart it now. {_UPGRADE_HINT}")
    return subject, body


def render_cpu_alert(name: str, level: str, cpu: int) -> Tuple[str, str]:
    if level == LEVEL_CRITICAL:
        subject = f"Router overloaded: {name}"
        body = (f"Bitwave: your router '{name}' is at {cpu}% CPU and cannot reliably add "
                f"new customers right now. Please restart it. {_UPGRADE_HINT}")
    else:
        subject = f"Router near its limit: {name}"
        body = (f"Bitwave: your router '{name}' has been above {CPU_WARNING_PERCENT}% CPU "
                f"for 10 minutes (now {cpu}%). New customers may take longer to connect. "
                f"{_UPGRADE_HINT}")
    return subject, body


# --- delivery ---------------------------------------------------------------------

def _stamp_column(level: str):
    return (Router.overload_critical_notified_at if level == LEVEL_CRITICAL
            else Router.overload_warning_notified_at)


async def _deliver_sms(sms_id: int, sender_id: Optional[str]) -> None:
    """Platform-paid send (owner_user_id=None -> platform gateway). Never raises."""
    try:
        await sms_dispatch.dispatch_admin_sms_messages([sms_id], sender_id)
    except Exception:
        logger.exception("Overload alert SMS dispatch crashed for sms %s", sms_id)


_sms_tasks: set = set()


def _spawn_sms(sms_id: int, sender_id: Optional[str]) -> None:
    try:
        task = asyncio.create_task(_deliver_sms(sms_id, sender_id))
    except RuntimeError:
        logger.warning("No running event loop; overload alert SMS %s left queued", sms_id)
        return
    _sms_tasks.add(task)
    task.add_done_callback(_sms_tasks.discard)


async def send_overload_alert(router_id: int, level: str, subject: str, body: str,
                              now: Optional[datetime] = None) -> bool:
    """Claim today's slot for this level and create inbox (+ SMS) rows.

    Own short session; the provider send happens after commit. Never raises.
    Returns True only when a new alert was created.
    """
    now = now or datetime.utcnow()
    day_start = local_midnight_utc(now)
    column = _stamp_column(level)
    try:
        async with database.async_session() as db:
            claim = await db.execute(
                update(Router)
                .where(Router.id == router_id,
                       Router.status_alerts_enabled.is_(True),
                       (column.is_(None)) | (column < day_start))
                .values({column.key: now})
            )
            if claim.rowcount != 1:
                await db.rollback()
                return False
            router = await db.get(Router, router_id)
            owner = await db.get(User, router.user_id) if router else None
            if (router is None or owner is None
                    or owner.subscription_status in _CUT_OFF_OWNER):
                await db.rollback()
                return False
            admin_id = await _resolve_sender_admin_id(db, owner)
            if admin_id is None:
                await db.rollback()
                return False

            sms_id: Optional[int] = None
            sender_id: Optional[str] = None
            phone = (owner.support_phone or "").strip()
            settings_row = await db.get(MessagingSettings, 1)
            messaging_on = settings_row is None or bool(settings_row.enabled)
            if settings.SMS_DISPATCH_ENABLED and messaging_on and phone:
                row = SmsMessage(
                    user_id=owner.id, recipient_phone=phone, body=body,
                    segments=count_segments(body), credits_charged=0,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER,
                    category=OVERLOAD_SMS_CATEGORY, status=SmsMessageStatus.QUEUED,
                )
                db.add(row)
                await db.flush()
                sms_id = row.id
                sender_id = await provider_accounts.resolve_sender_id_for(
                    db, None, settings_row.sender_id if settings_row else None)
            db.add(ResellerInboxMessage(
                recipient_user_id=owner.id, sender_user_id=admin_id,
                subject=subject, body=body, sent_sms=sms_id is not None,
            ))
            await db.commit()
            logger.warning("Router overload alert (%s) sent: router %s -> user %s (sms=%s)",
                           level, router_id, owner.id, sms_id is not None)
        if sms_id is not None:
            _spawn_sms(sms_id, sender_id)
        return True
    except Exception:
        logger.exception("Router overload alert failed for router %s", router_id)
        return False


# --- signal 1: payments failing on a reachable router ------------------------------

async def tcp_reachable(host: str, port: int,
                        timeout: float = TCP_CHECK_TIMEOUT_SECONDS) -> bool:
    """Bare TCP connect to the API port, closed immediately. No login. Never raises."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port or 8728)), timeout)
    except Exception:  # noqa: BLE001
        return False
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:  # noqa: BLE001
        pass
    return True


async def find_payment_overload_candidates(now: datetime) -> list[tuple[int, str, int, int]]:
    """(router_id, ip, port, failures) with >= threshold failing payments in the window."""
    since = now - PAYMENT_FAILURE_WINDOW
    day_start = local_midnight_utc(now)
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.ip_address, Router.port, func.count(ProvisioningAttempt.id))
            .join(ProvisioningAttempt, ProvisioningAttempt.router_id == Router.id)
            .where(ProvisioningAttempt.provisioning_state.in_(_FAILING_STATES),
                   ProvisioningAttempt.last_attempt_at >= since,
                   Router.status_alerts_enabled.is_(True),
                   (Router.overload_critical_notified_at.is_(None))
                   | (Router.overload_critical_notified_at < day_start))
            .group_by(Router.id, Router.ip_address, Router.port)
            .having(func.count(ProvisioningAttempt.id) >= PAYMENT_FAILURE_THRESHOLD)
        )).all()
        await db.commit()
    return [(r[0], r[1], r[2], int(r[3])) for r in rows]


async def scan_payment_overload(now: Optional[datetime] = None) -> int:
    """Scheduler entry for signal 1. Returns alerts sent. Never raises."""
    if not settings.ROUTER_OVERLOAD_ALERTS_ENABLED:
        return 0
    if _db_pool_too_busy():
        logger.info("Skipping overload scan: DB pool under pressure")
        return 0
    now = now or datetime.utcnow()
    try:
        candidates = await find_payment_overload_candidates(now)
    except Exception:
        logger.exception("Overload scan could not list candidates")
        return 0
    sent = 0
    for router_id, ip, port, failures in candidates:
        if not ip or not await tcp_reachable(ip, port):
            continue  # unreachable -> offline alerts own it
        async with database.async_session() as db:
            name = (await db.execute(select(Router.name).where(Router.id == router_id))).scalar()
            await db.commit()
        subject, body = render_payment_overload(name or f"#{router_id}", failures)
        if await send_overload_alert(router_id, LEVEL_CRITICAL, subject, body, now=now):
            sent += 1
    if candidates:
        logger.info("Overload scan: %s candidate(s), %s alert(s) sent", len(candidates), sent)
    return sent


# --- signal 2: CPU via SNMP ------------------------------------------------------------

def record_cpu_sample(router_id: int, cpu: int, at: datetime) -> None:
    _cpu_history[router_id].append((at, cpu))


def _consecutive(router_id: int, threshold: int, count: int) -> bool:
    samples = list(_cpu_history.get(router_id, ()))[-count:]
    if len(samples) < count or any(cpu < threshold for _, cpu in samples):
        return False
    return all(b[0] - a[0] <= CPU_SAMPLE_MAX_GAP for a, b in zip(samples, samples[1:]))


def evaluate_cpu_level(router_id: int) -> Optional[str]:
    if _consecutive(router_id, CPU_CRITICAL_PERCENT, CPU_CRITICAL_SAMPLES):
        return LEVEL_CRITICAL
    if _consecutive(router_id, CPU_WARNING_PERCENT, CPU_WARNING_SAMPLES):
        return LEVEL_WARNING
    return None


async def poll_router_cpu(now: Optional[datetime] = None) -> int:
    """Scheduler entry for signal 2. Returns routers read. Never raises.

    Disabled unless ROUTER_SNMP_POLL_ENABLED and a community is configured; only
    routers enrolled by scripts/router_snmp_rollout.py (routers.snmp_enabled).
    """
    community = (settings.ROUTER_SNMP_COMMUNITY or "").strip()
    if not settings.ROUTER_SNMP_POLL_ENABLED or not community:
        return 0
    if _db_pool_too_busy():
        logger.info("Skipping SNMP CPU poll: DB pool under pressure")
        return 0
    now = now or datetime.utcnow()
    try:
        async with database.async_session() as db:
            targets = (await db.execute(
                select(Router.id, Router.name, Router.ip_address)
                .where(Router.snmp_enabled.is_(True), Router.ip_address.isnot(None))
            )).all()
            await db.commit()
    except Exception:
        logger.exception("SNMP CPU poll could not list routers")
        return 0

    sem = asyncio.Semaphore(SNMP_CONCURRENCY)

    async def _one(ip: str) -> Optional[int]:
        async with sem:
            return await snmp_cpu.read_cpu_load(ip, community, timeout=2.0, retries=1)

    loads = await asyncio.gather(*[_one(t[2]) for t in targets], return_exceptions=True)
    readings = [(t, load) for t, load in zip(targets, loads) if isinstance(load, int)]

    try:
        async with database.async_session() as db:
            for (router_id, _name, _ip), load in readings:
                await db.execute(update(Router).where(Router.id == router_id)
                                 .values(cpu_load=load, cpu_checked_at=now))
            await db.commit()
    except Exception:
        logger.exception("SNMP CPU poll could not persist readings")

    for (router_id, name, _ip), load in readings:
        record_cpu_sample(router_id, load, now)
        level = evaluate_cpu_level(router_id)
        if level is None:
            continue
        subject, body = render_cpu_alert(name or f"#{router_id}", level, load)
        await send_overload_alert(router_id, level, subject, body, now=now)
    return len(readings)

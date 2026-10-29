"""Put PPPoE customers back on their router through the retrying attempt path.

Two callers:

* ``push_active_pppoe_customer`` - a reseller re-saving an ACTIVE customer.
  The customer page tells them "Re-save the customer to provision it again"
  when the secret is missing, so a re-save must actually write the secret,
  and must keep retrying when the router is unreachable at that moment.

* ``schedule_pppoe_recovery_sweep`` / ``sweep_router_pppoe`` - a router that
  was offline comes back. Writes made while it was down were lost: the
  paid-delivery retry gives up after ``PPPOE_RETRY_MAX_AGE`` (4 h), and a
  customer moved to another router or deleted while it was down can leave
  their old secret behind. The sweep adds the missing secrets of ACTIVE,
  unexpired customers and removes secrets this app created for customers
  that were deleted, moved to another router or renamed.

Database Session Discipline (AGENTS.md): every DB read/write here happens in
a short session that is closed before any RouterOS I/O.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db import database as db_module
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterAuthMethod,
)
from app.services.customer_grace import has_access_time

logger = logging.getLogger("pppoe_resync")

# Secrets this app writes carry "CID:<customer id>|..." in their comment
# (build_pppoe_payload). Secrets without it belong to the reseller and are
# never touched here.
CID_COMMENT_RE = re.compile(r"^CID:(\d+)\|")

LIVE_ATTEMPT_STATES = (
    ProvisioningState.SCHEDULED,
    ProvisioningState.IN_PROGRESS,
    ProvisioningState.RETRY_PENDING,
)

RECOVERY_SWEEP_COOLDOWN = timedelta(minutes=10)
RECOVERY_SWEEP_START_DELAY_SECONDS = 20.0
RECOVERY_SWEEP_POOL_WAIT_SECONDS = 60.0
RECOVERY_SWEEP_POOL_WAITS = 3
RECOVERY_SWEEP_MAX_PROVISIONS = 40
RECOVERY_SWEEP_MAX_REMOVALS = 20
RECOVERY_SWEEP_FLEET_CONCURRENCY = 2

_sweeps_in_flight: set[int] = set()
_sweep_last_started: dict[int, datetime] = {}
_sweep_tasks: set[asyncio.Task] = set()
_fleet_slots: Optional[asyncio.Semaphore] = None


# ---------------------------------------------------------------------------
# Attempt bookkeeping
# ---------------------------------------------------------------------------


async def arm_pppoe_delivery_attempt(
    db,
    *,
    customer_id: int,
    router_id: int,
    interactive: bool,
    now: Optional[datetime] = None,
) -> tuple[Optional[ProvisioningAttempt], str]:
    """Get a retrying delivery attempt for a customer that is not a new payment.

    The attempt hangs off the customer's latest payment row (a source row is
    required by ``uq_provisioning_attempt_source``), so no ledger row is
    invented for a re-save or a sweep. Returns ``(attempt, status)``:

    * ``armed``          - push now with this attempt; the retry worker
                           replays it if the push fails.
    * ``busy``           - a push for this customer is running right now;
                           do not start a second one.
    * ``owned_by_retry`` - (sweep only) the retry worker already has a live
                           attempt for this customer and will deliver it.
    * ``no_source``      - the customer has no payment row; push without an
                           attempt (still logged, not retried).
    """
    from app.services.hotspot_provisioning import (
        get_or_create_provisioning_attempt,
        schedule_provisioning_attempt,
    )
    from app.services.pppoe_provisioning import (
        PPPOE_RETRY_MAX_AGE,
        PPPOE_RETRY_MAX_ATTEMPTS,
        PPPOE_RETRY_STALE_IN_PROGRESS_SECONDS,
    )

    now = now or datetime.utcnow()
    latest = (
        await db.execute(
            select(CustomerPayment.id, CustomerPayment.payment_reference)
            .where(CustomerPayment.customer_id == customer_id)
            .order_by(CustomerPayment.created_at.desc(), CustomerPayment.id.desc())
            .limit(1)
        )
    ).first()
    if latest is None:
        return None, "no_source"
    payment_id, reference = latest

    attempt = (
        await db.execute(
            select(ProvisioningAttempt).where(
                ProvisioningAttempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                ProvisioningAttempt.source_pk == payment_id,
            )
        )
    ).scalar_one_or_none()

    if attempt is None:
        attempt = await get_or_create_provisioning_attempt(
            db,
            customer_id=customer_id,
            router_id=router_id,
            mac_address=None,
            source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
            source_pk=payment_id,
            external_reference=reference,
            entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        )
        await schedule_provisioning_attempt(db, attempt)
        return attempt, "armed"

    live = (
        attempt.provisioning_state in LIVE_ATTEMPT_STATES
        and (attempt.attempt_count or 0) < PPPOE_RETRY_MAX_ATTEMPTS
        and attempt.created_at is not None
        and attempt.created_at > now - PPPOE_RETRY_MAX_AGE
    )
    if live:
        running = (
            attempt.provisioning_state == ProvisioningState.IN_PROGRESS
            and attempt.last_attempt_at is not None
            and attempt.last_attempt_at
            > now - timedelta(seconds=PPPOE_RETRY_STALE_IN_PROGRESS_SECONDS)
        )
        if running:
            return attempt, "busy"
        if not interactive:
            return attempt, "owned_by_retry"
        # A reseller pressing Save pushes now on the same attempt; it keeps
        # its remaining retry budget.
        attempt.router_id = router_id
        attempt.updated_at = now
        await db.flush()
        return attempt, "armed"

    # The attempt finished (delivered, or gave up). Re-arm it as a fresh
    # delivery so the retry worker's 4 h / 14-try window starts again.
    attempt.customer_id = customer_id
    attempt.router_id = router_id
    attempt.provisioning_state = ProvisioningState.SCHEDULED
    attempt.online_state = ProvisioningOnlineState.UNKNOWN
    attempt.attempt_count = 0
    attempt.last_attempt_at = None
    attempt.last_error = None
    attempt.created_at = now
    attempt.updated_at = now
    await db.flush()
    return attempt, "armed"


def _customer_can_have_pppoe_access(customer: Customer, now: datetime) -> bool:
    return bool(
        customer.status == CustomerStatus.ACTIVE
        and customer.pppoe_username
        and customer.pppoe_password
        and customer.plan is not None
        and customer.plan.connection_type == ConnectionType.PPPOE
        and customer.router is not None
        and has_access_time(customer, now)
    )


# ---------------------------------------------------------------------------
# Re-save of one ACTIVE customer
# ---------------------------------------------------------------------------


async def push_active_pppoe_customer(
    customer_id: int,
    *,
    action: str = "pppoe_resave",
    disconnect: bool = True,
    skip_if_fup_restricted: bool = False,
) -> dict[str, Any]:
    """Write one ACTIVE customer's secret to their router, with retries.

    ``disconnect=False`` leaves a connected device alone (nothing about the
    login changed; this only makes sure the secret exists).

    Returns ``{"result": ...}`` where result is ``ok``, ``retry_pending``
    (push failed, the retry worker will try again), ``failed`` (push failed
    and nothing will retry), ``in_progress`` (another push is running),
    ``fup_restricted`` or ``not_eligible``.
    """
    from app.services.pppoe_provisioning import (
        active_fup_restriction,
        build_pppoe_payload,
        provision_pppoe_customer,
    )

    now = datetime.utcnow()
    async with db_module.async_session() as db:
        customer = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .where(Customer.id == customer_id)
            )
        ).scalar_one_or_none()
        if customer is None or not _customer_can_have_pppoe_access(customer, now):
            await db.commit()
            return {"result": "not_eligible"}
        if skip_if_fup_restricted and await active_fup_restriction(db, customer.id):
            # Re-provisioning would put the secret back on its normal profile
            # and silently lift this period's FUP throttle/block.
            await db.commit()
            return {"result": "fup_restricted"}
        router_id = customer.router.id
        attempt, status = await arm_pppoe_delivery_attempt(
            db, customer_id=customer.id, router_id=router_id, interactive=True, now=now,
        )
        payload = build_pppoe_payload(customer, customer.router)
        payload["disconnect"] = disconnect
        attempt_id = attempt.id if attempt is not None else None
        await db.commit()

    if status == "busy":
        return {"result": "in_progress", "attempt_id": attempt_id}

    result = await provision_pppoe_customer(
        customer_id=customer_id,
        router_id=router_id,
        pppoe_payload=payload,
        action=action,
        attempt_id=attempt_id,
    )
    if result and result.get("success"):
        outcome = "ok"
    else:
        outcome = "retry_pending" if attempt_id is not None else "failed"
    return {
        "result": outcome,
        "attempt_id": attempt_id,
        "error": (result or {}).get("error"),
        "delivery": (result or {}).get("delivery"),
    }


# ---------------------------------------------------------------------------
# Offline -> online recovery sweep
# ---------------------------------------------------------------------------


def schedule_pppoe_recovery_sweep(router_id: int, *, now: Optional[datetime] = None) -> bool:
    """Queue a recovery sweep for a router that just came back online.

    Called from record_router_availability on the offline->online flip, which
    runs on ~40 request and background paths, so this only schedules: it
    never touches the DB or the router itself and never raises. One sweep per
    router at a time, at most one per RECOVERY_SWEEP_COOLDOWN.
    """
    try:
        if not getattr(settings, "PPPOE_RECOVERY_SWEEP_ENABLED", True):
            return False
        now = now or datetime.utcnow()
        if router_id in _sweeps_in_flight:
            return False
        last = _sweep_last_started.get(router_id)
        if last is not None and now - last < RECOVERY_SWEEP_COOLDOWN:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        _sweeps_in_flight.add(router_id)
        _sweep_last_started[router_id] = now
        task = loop.create_task(_run_recovery_sweep(router_id))
        _sweep_tasks.add(task)
        task.add_done_callback(_sweep_tasks.discard)
        return True
    except Exception as exc:  # never break the availability write
        logger.warning("[PPPOE-RECOVERY] could not schedule sweep for router %s: %s", router_id, exc)
        return False


def _fleet_semaphore() -> asyncio.Semaphore:
    global _fleet_slots
    if _fleet_slots is None:
        _fleet_slots = asyncio.Semaphore(RECOVERY_SWEEP_FLEET_CONCURRENCY)
    return _fleet_slots


async def _run_recovery_sweep(router_id: int) -> None:
    from app.services.pppoe_provisioning import _retry_db_pool_is_busy

    try:
        # Let the management path settle, and let the request that noticed
        # the recovery finish first.
        await asyncio.sleep(RECOVERY_SWEEP_START_DELAY_SECONDS)
        async with _fleet_semaphore():
            for _ in range(RECOVERY_SWEEP_POOL_WAITS):
                if not _retry_db_pool_is_busy():
                    break
                await asyncio.sleep(RECOVERY_SWEEP_POOL_WAIT_SECONDS)
            else:
                logger.warning(
                    "[PPPOE-RECOVERY] router %s: DB pool stayed busy, sweep skipped", router_id,
                )
                return
            summary = await sweep_router_pppoe(router_id)
            if summary.get("provisioned") or summary.get("removed") or summary.get("failed"):
                logger.warning("[PPPOE-RECOVERY] router %s: %s", router_id, summary)
            else:
                logger.info("[PPPOE-RECOVERY] router %s: %s", router_id, summary)
    except Exception as exc:
        logger.error("[PPPOE-RECOVERY] sweep for router %s failed: %s", router_id, exc)
    finally:
        _sweeps_in_flight.discard(router_id)


def _router_info(router: Router) -> dict[str, Any]:
    return {
        "id": router.id,
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port or 8728,
        "name": router.name,
    }


def _list_pppoe_secrets_sync(router_info: dict) -> dict:
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "Failed to connect to router"}
    try:
        result = api.get_pppoe_secrets_minimal()
        if not result.get("success"):
            return {"error": result.get("error") or "Failed to list PPPoE secrets"}
        return {"success": True, "secrets": result.get("data") or []}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        api.disconnect()


def _remove_pppoe_secrets_sync(router_info: dict, usernames: list[str]) -> dict:
    """Remove several secrets over one connection (secret first, then session)."""
    from app.services.mikrotik_api import MikroTikAPI

    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "Failed to connect to router"}
    removed, failed = [], []
    try:
        for username in usernames:
            # Same order as _remove_pppoe_sync: removing the session first
            # lets an instant redial authenticate before the secret is gone.
            result = api.remove_pppoe_secret(username)
            if result.get("error"):
                failed.append({"username": username, "error": result["error"]})
                continue
            api.disconnect_pppoe_session(username)
            removed.append(username)
        return {"success": True, "removed": removed, "failed": failed}
    except Exception as exc:
        return {"error": str(exc), "removed": removed, "failed": failed}
    finally:
        api.disconnect()


async def _router_io(router_info: dict, func, *args):
    from app.services.mikrotik_background import router_locks

    router_key = f"{router_info['ip']}:{router_info['port']}"
    async with router_locks.acquire_router_only(router_key):
        return await asyncio.to_thread(func, router_info, *args)


async def sweep_router_pppoe(router_id: int, *, now: Optional[datetime] = None) -> dict[str, Any]:
    """Make one router's PPPoE secrets match the database after an outage.

    * Adds the secret of every ACTIVE customer on this router who still has
      paid (or grace) time and whose secret is missing, through the retrying
      attempt path. Customers whose delivery the retry worker is already
      handling, or that a push is running for, are left to it.
    * Removes secrets this app created (comment ``CID:<id>|``) whose customer
      was deleted, now belongs to another router, or was renamed. Secrets
      without that comment, and any secret named after a customer of this
      router, are never removed. If the orphans outnumber the router's own
      matching secrets (e.g. two router rows reaching the same box), nothing
      is removed and a warning is logged instead.

    Bounded: one secret listing, at most RECOVERY_SWEEP_MAX_PROVISIONS pushes
    and RECOVERY_SWEEP_MAX_REMOVALS removals per sweep.
    """
    from app.services.pppoe_provisioning import (
        active_fup_restriction,
        build_pppoe_payload,
        provision_pppoe_customer,
    )

    now = now or datetime.utcnow()
    summary: dict[str, Any] = {
        "router_id": router_id, "provisioned": 0, "retry_pending": 0, "skipped": 0,
        "removed": 0, "failed": 0, "orphans_held": 0,
    }

    # 1. Who belongs on this router (short session).
    async with db_module.async_session() as db:
        router = await db.get(Router, router_id)
        if router is None or router.auth_method != RouterAuthMethod.DIRECT_API or not router.ip_address:
            await db.commit()
            return {**summary, "status": "not_direct_api"}
        router_info = _router_info(router)
        customers = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .where(Customer.router_id == router_id, Customer.pppoe_username.isnot(None))
            )
        ).scalars().all()
        own_usernames = {c.pppoe_username for c in customers}
        expected = {
            c.pppoe_username: c.id for c in customers if _customer_can_have_pppoe_access(c, now)
        }
        await db.commit()

    if not customers:
        return {**summary, "status": "no_pppoe_customers"}

    # 2. What the router has (RouterOS I/O, no session held).
    listing = await _router_io(router_info, _list_pppoe_secrets_sync)
    if listing.get("error"):
        return {**summary, "status": "router_unreachable", "error": listing["error"]}
    secrets = listing["secrets"]
    from app.services.pppoe_expired_redirect import EXPIRED_PROFILE

    # A secret still on the walled expired profile gives no internet: for a
    # customer who should have access it counts as missing, and the push
    # kicks the session so the CPE redials onto the plan profile.
    walled = {s.get("name") for s in secrets if s.get("name") and s.get("profile") == EXPIRED_PROFILE}
    present = {s.get("name") for s in secrets if s.get("name")} - walled

    missing_ids = [cid for username, cid in expected.items() if username not in present]
    tagged: list[tuple[str, int]] = []
    for secret in secrets:
        name = secret.get("name")
        match = CID_COMMENT_RE.match(secret.get("comment") or "")
        if name and match:
            tagged.append((name, int(match.group(1))))

    # 3. Classify tagged secrets and arm attempts for the missing (short session).
    orphans: list[tuple[str, int, str]] = []
    matched = 0
    work: list[tuple[int, int | None, dict]] = []
    async with db_module.async_session() as db:
        if tagged:
            ids = sorted({cid for _, cid in tagged})
            current: dict[int, tuple[int | None, str | None]] = {}
            for start in range(0, len(ids), 500):
                rows = await db.execute(
                    select(Customer.id, Customer.router_id, Customer.pppoe_username)
                    .where(Customer.id.in_(ids[start:start + 500]))
                )
                for cid, rid, username in rows.all():
                    current[cid] = (rid, username)
            for name, cid in tagged:
                if name in own_usernames:
                    if current.get(cid) == (router_id, name):
                        matched += 1
                    continue  # a customer of this router: other jobs own it
                row = current.get(cid)
                if row is None:
                    orphans.append((name, cid, "deleted"))
                elif row[0] != router_id:
                    orphans.append((name, cid, "moved"))
                elif row[1] != name:
                    orphans.append((name, cid, "renamed"))

        if missing_ids:
            rows = (
                await db.execute(
                    select(Customer)
                    .options(selectinload(Customer.plan), selectinload(Customer.router))
                    .where(Customer.id.in_(missing_ids[:RECOVERY_SWEEP_MAX_PROVISIONS]))
                    .order_by(Customer.id)
                )
            ).scalars().all()
            for customer in rows:
                # Re-check under this session: state may have moved on.
                if (
                    not _customer_can_have_pppoe_access(customer, now)
                    or customer.router_id != router_id
                ):
                    summary["skipped"] += 1
                    continue
                if await active_fup_restriction(db, customer.id):
                    summary["skipped"] += 1
                    continue
                attempt, status = await arm_pppoe_delivery_attempt(
                    db, customer_id=customer.id, router_id=router_id, interactive=False, now=now,
                )
                if status in ("busy", "owned_by_retry"):
                    summary["skipped"] += 1
                    continue
                payload = build_pppoe_payload(customer, customer.router)
                # A missing secret has nothing to kick; a walled one does.
                payload["disconnect"] = customer.pppoe_username in walled
                work.append((customer.id, attempt.id if attempt is not None else None, payload))
        await db.commit()
    summary["missing"] = len(missing_ids)
    summary["orphans"] = len(orphans)

    # 4. Remove orphans (one connection), guarded against mass deletion.
    removed: list[str] = []
    if orphans:
        if len(orphans) > RECOVERY_SWEEP_MAX_REMOVALS or len(orphans) > max(matched, 3):
            summary["orphans_held"] = len(orphans)
            logger.warning(
                "[PPPOE-RECOVERY] router %s: %d orphan secret(s) vs %d matching; not removing "
                "(check that this router row points at the right box): %s",
                router_id, len(orphans), matched, [o[0] for o in orphans[:10]],
            )
        else:
            outcome = await _router_io(router_info, _remove_pppoe_secrets_sync, [o[0] for o in orphans])
            removed = list(outcome.get("removed") or [])
            summary["removed"] = len(removed)
            summary["failed"] += len(orphans) - len(removed)
            if outcome.get("error"):
                summary["error"] = outcome["error"]

    # 5. Push the missing secrets, one at a time, through the attempt path.
    for customer_id, attempt_id, payload in work:
        result = await provision_pppoe_customer(
            customer_id=customer_id,
            router_id=router_id,
            pppoe_payload=payload,
            action="pppoe_recovery_sweep",
            attempt_id=attempt_id,
        )
        if result and result.get("success"):
            summary["provisioned"] += 1
        elif attempt_id is not None:
            summary["retry_pending"] += 1
        else:
            summary["failed"] += 1

    # 6. Durable proof of what was removed (short session).
    if removed:
        reasons = {name: (cid, why) for name, cid, why in orphans}
        async with db_module.async_session() as db:
            existing = set()
            ids = [reasons[name][0] for name in removed]
            if ids:
                existing = set(
                    (await db.execute(select(Customer.id).where(Customer.id.in_(ids)))).scalars().all()
                )
            for name in removed:
                cid, why = reasons[name]
                db.add(ProvisioningLog(
                    customer_id=cid if cid in existing else None,
                    router_id=router_id,
                    action="pppoe_orphan_removed",
                    status="success",
                    details=f"Recovery sweep removed secret '{name}' (CID {cid}, customer {why})"[:255],
                ))
            await db.commit()

    summary["status"] = "done"
    return summary

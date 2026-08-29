"""Push outage-compensated customers back onto their router.

Why this is a separate module from ``outage_compensation``:

The compensation run itself is pure DB work in one short transaction. Reviving
an *expired* customer is not — the cleanup cron already deleted them from the
MikroTik, so restoring their internet needs router I/O. Doing that inline would
pin a pooled connection across a slow, failure-prone network call, which is the
single most common cause of outages in this app (see **Database Session
Discipline** in AGENTS.md, and the 2026-06-05 pool lock-convoy incident).

So the split is:

* ``apply_outage_compensation`` commits the expiry/status changes, then hands
  the item ids to :func:`schedule_reprovision` and returns immediately. The
  reseller never waits on routers.
* This module runs detached, opens its **own** short sessions, and never holds
  one across a RouterOS call. Every customer's outcome is written back to
  ``OutageCompensationItem.reprovision_state`` so a partial failure is visible
  rather than silently claimed as success.

Failure is expected here, not exceptional: after a power cut the router may
still be dark. A router we already know is offline is skipped up front and
marked ``router_offline`` so it can be retried later, instead of burning a
timeout per customer on a device that cannot answer.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import selectinload

# Late-bound on purpose: the test suite swaps the engine/session factory onto
# app.db.database per test, so reading the attribute at call time (rather than
# importing the name at module load) keeps this module on the test engine.
# Same pattern as app/services/pppoe_provisioning.py.
from app.db import database as db_module
from app.db.models import (
    Customer,
    OutageCompensationItem,
    Plan,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    Router,
)

logger = logging.getLogger(__name__)


# --- reprovision_state values (plain strings, deliberately not a DB enum:
#     a native PG enum would need an ALTER TYPE migration for every new
#     outcome we learn we need) ---
REPROVISION_PENDING = "pending"
REPROVISION_SUCCEEDED = "succeeded"
REPROVISION_FAILED = "failed"
REPROVISION_ROUTER_OFFLINE = "router_offline"
REPROVISION_UNSUPPORTED = "unsupported"

# Router I/O runs a few at a time: enough to clear a big outage quickly,
# few enough that we never open a burst of sessions or hammer one device.
_MAX_CONCURRENT_REPROVISIONS = 4

# Optional background work must shed load when the pool is under pressure
# (AGENTS.md). Above this we defer rather than compete with paying traffic.
_POOL_BUSY_THRESHOLD_PERCENT = 70

# How long to wait for one customer's router write before giving up on it.
_PER_CUSTOMER_TIMEOUT_SECONDS = 45

# Customers per chunk. Bounds in-flight work and gives the pool-pressure check
# a chance to fire partway through a long run.
_CHUNK_SIZE = 25

# Keeps detached tasks referenced; asyncio only holds a weak reference, so
# without this a task can be garbage-collected mid-flight.
_background_tasks: set[asyncio.Task] = set()


def _pool_is_busy() -> bool:
    snapshot = db_module.db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    return (
        isinstance(checked_out_percent, (int, float))
        and checked_out_percent >= _POOL_BUSY_THRESHOLD_PERCENT
    )


async def _mark(
    item_id: int,
    state: str,
    error: Optional[str] = None,
) -> None:
    """Record one customer's outcome in its own short transaction."""
    try:
        async with db_module.async_session() as db:
            item = await db.get(OutageCompensationItem, item_id)
            if not item:
                return
            item.reprovision_state = state
            item.reprovision_error = (error or None) and str(error)[:500]
            item.reprovision_attempted_at = datetime.utcnow()
            await db.commit()
    except Exception:
        # Never let bookkeeping failure kill the run for other customers.
        logger.exception(
            "[OUTAGE-REPROV] Could not record state %s for item %s", state, item_id
        )


async def _load_job(item_id: int) -> Optional[dict]:
    """Read everything the router call needs -- and register the retry attempt
    -- in ONE short session, then close it.

    Read and attempt-create are both pure DB work with no I/O between them, so
    sharing a session halves the pool checkouts per customer. Returns a plain
    dict on purpose: the provisioning call must not run while an ORM session
    (and its pooled connection) is still open.
    """
    async with db_module.async_session() as db:
        item = await db.get(OutageCompensationItem, item_id)
        if not item or not item.customer_id:
            return None

        customer = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan))
                .where(Customer.id == item.customer_id)
            )
        ).scalar_one_or_none()
        if not customer:
            return None

        router = (
            await db.get(Router, customer.router_id) if customer.router_id else None
        )
        if not router:
            return {"item_id": item_id, "unsupported": "Customer has no router"}

        plan: Optional[Plan] = customer.plan
        connection_type = (
            plan.connection_type.value if plan and plan.connection_type else None
        )

        # A router last seen down cannot be provisioned into. Skip it up front
        # instead of spending a timeout per customer on a dark device.
        if router.last_status is False:
            return {
                "item_id": item_id,
                "router_offline": True,
                "router_name": router.name,
            }

        from app.services.hotspot_provisioning import build_hotspot_payload
        from app.services.pppoe_provisioning import build_pppoe_payload

        if connection_type == "pppoe":
            if not customer.pppoe_username:
                return {
                    "item_id": item_id,
                    "unsupported": "PPPoE customer has no username",
                }
            payload = build_pppoe_payload(customer, router)
            kind = "pppoe"
        else:
            if not customer.mac_address:
                return {
                    "item_id": item_id,
                    "unsupported": "Hotspot customer has no MAC address",
                }
            if not plan:
                return {"item_id": item_id, "unsupported": "Customer has no plan"}
            payload = build_hotspot_payload(
                customer,
                plan,
                router,
                comment=f"Outage compensation revival for customer {customer.id}",
            )
            kind = "hotspot"

        job = {
            "item_id": item_id,
            "kind": kind,
            "customer_id": customer.id,
            "router_id": router.id,
            "mac_address": customer.mac_address,
            "payload": payload,
        }
        job["attempt_id"] = await _register_attempt(db, job)
        await db.commit()
        return job


async def _register_attempt(db, job: dict) -> Optional[int]:
    """Register a ProvisioningAttempt so this revival joins the same retry and
    reconciliation machinery as a normal payment.

    Runs on the caller's already-open session (still no I/O in scope). Keyed on
    the compensation *item* id, so re-running the same item reuses its attempt
    row rather than creating a duplicate.
    """
    try:
        from app.services.hotspot_provisioning import (
            get_or_create_provisioning_attempt,
            schedule_provisioning_attempt,
        )

        attempt = await get_or_create_provisioning_attempt(
            db,
            customer_id=job["customer_id"],
            router_id=job["router_id"],
            mac_address=job.get("mac_address"),
            source_table=ProvisioningAttemptSource.OUTAGE_COMPENSATION,
            source_pk=job["item_id"],
            external_reference=f"outage-comp-item-{job['item_id']}",
            entrypoint=ProvisioningAttemptEntrypoint.OUTAGE_COMPENSATION,
        )
        await schedule_provisioning_attempt(db, attempt)
        return attempt.id
    except Exception:
        # The attempt row is for observability/retry; losing it must not stop
        # us actually putting the customer back online.
        logger.exception(
            "[OUTAGE-REPROV] Could not create provisioning attempt for item %s",
            job["item_id"],
        )
        return None


async def _reprovision_one(item_id: int) -> str:
    job = await _load_job(item_id)
    if job is None:
        return REPROVISION_FAILED

    if job.get("router_offline"):
        await _mark(
            item_id,
            REPROVISION_ROUTER_OFFLINE,
            f"Router {job.get('router_name')} was offline — credit applied, "
            "retry provisioning once it is back",
        )
        return REPROVISION_ROUTER_OFFLINE

    if job.get("unsupported"):
        await _mark(item_id, REPROVISION_UNSUPPORTED, job["unsupported"])
        return REPROVISION_UNSUPPORTED

    attempt_id = job.get("attempt_id")

    # --- router I/O: no DB session open here, by design ---
    try:
        if job["kind"] == "pppoe":
            from app.services.pppoe_provisioning import provision_pppoe_customer

            result = await asyncio.wait_for(
                provision_pppoe_customer(
                    customer_id=job["customer_id"],
                    router_id=job["router_id"],
                    pppoe_payload=job["payload"],
                    action="outage_compensation",
                    attempt_id=attempt_id,
                ),
                timeout=_PER_CUSTOMER_TIMEOUT_SECONDS,
            )
        else:
            from app.services.hotspot_provisioning import provision_hotspot_customer

            result = await asyncio.wait_for(
                provision_hotspot_customer(
                    job["customer_id"],
                    job["router_id"],
                    job["payload"],
                    "outage_compensation",
                    attempt_id,
                ),
                timeout=_PER_CUSTOMER_TIMEOUT_SECONDS,
            )
    except asyncio.TimeoutError:
        await _mark(item_id, REPROVISION_FAILED, "Router did not respond in time")
        return REPROVISION_FAILED
    except Exception as e:  # noqa: BLE001 - one customer must not kill the batch
        logger.exception("[OUTAGE-REPROV] item %s failed", item_id)
        await _mark(item_id, REPROVISION_FAILED, str(e))
        return REPROVISION_FAILED

    ok = bool(result.get("success")) if isinstance(result, dict) else bool(result)
    if ok:
        await _mark(item_id, REPROVISION_SUCCEEDED)
        return REPROVISION_SUCCEEDED

    error = (
        result.get("error") or result.get("message") or "Provisioning failed"
        if isinstance(result, dict)
        else "Provisioning failed"
    )
    await _mark(item_id, REPROVISION_FAILED, error)
    return REPROVISION_FAILED


async def reprovision_items(item_ids: Sequence[int]) -> dict:
    """Re-provision each compensated customer, a few at a time.

    Safe to call directly (tests, a retry endpoint) as well as via
    :func:`schedule_reprovision`. Never raises: every per-customer outcome is
    recorded on its item row and summarised in the return value.
    """
    item_ids = list(item_ids)
    if not item_ids:
        return {"attempted": 0}

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_REPROVISIONS)

    async def _guarded(item_id: int) -> str:
        async with semaphore:
            try:
                return await _reprovision_one(item_id)
            except Exception:  # noqa: BLE001 - belt and braces
                logger.exception("[OUTAGE-REPROV] unhandled failure on item %s", item_id)
                return REPROVISION_FAILED

    outcomes: list[str] = []
    deferred = 0

    # Chunked rather than one big gather. A town-wide outage can leave hundreds
    # of customers to reconnect and each router call takes seconds, so the run
    # is long -- long enough for the pool to come under pressure partway
    # through. Re-checking per chunk lets us stop then, instead of only having
    # looked once before the first customer. It also bounds how many
    # coroutines and in-flight sessions exist at any moment.
    for offset in range(0, len(item_ids), _CHUNK_SIZE):
        remaining = item_ids[offset:]
        if _pool_is_busy():
            # Shed load rather than compete with customer-facing traffic. The
            # credit is already committed; these rows stay 'pending' and are
            # picked up by the retry endpoint once the pool recovers.
            deferred = len(remaining)
            logger.warning(
                "[OUTAGE-REPROV] DB pool busy — deferring %s remaining customer(s)",
                deferred,
            )
            break
        chunk = item_ids[offset:offset + _CHUNK_SIZE]
        outcomes.extend(await asyncio.gather(*(_guarded(i) for i in chunk)))

    summary = {
        "attempted": len(outcomes),
        "succeeded": outcomes.count(REPROVISION_SUCCEEDED),
        "failed": outcomes.count(REPROVISION_FAILED),
        "router_offline": outcomes.count(REPROVISION_ROUTER_OFFLINE),
        "unsupported": outcomes.count(REPROVISION_UNSUPPORTED),
    }
    if deferred:
        summary["deferred"] = deferred
        summary["reason"] = "db_pool_pressure"
    logger.info("[OUTAGE-REPROV] batch complete: %s", summary)
    return summary


def schedule_reprovision(item_ids: Sequence[int]) -> None:
    """Fire re-provisioning as detached background work.

    Called *after* the compensation transaction commits, so the reseller's
    request returns immediately and no pooled connection is held across
    router I/O. Silently does nothing outside a running event loop, which is
    what tests that only exercise the DB path want.
    """
    item_ids = list(item_ids)
    if not item_ids:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning(
            "[OUTAGE-REPROV] no running event loop — %s customer(s) left pending",
            len(item_ids),
        )
        return

    task = loop.create_task(reprovision_items(item_ids))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

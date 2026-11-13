"""Router cleanup for hotspot customers that were deleted from the dashboard.

Deleting a customer used to leave its hotspot user, ip-binding and active
session on the MikroTik, so the device kept free internet until the router's
own expiry caught up (router 627, 2026-11-07: a comp voucher's user outlived
the deleted customer). The expiry job cannot catch these: it works from the
customer row, which no longer exists.

Removal uses the expiry job's own router cleanup
(``mikrotik_background._cleanup_single_router_hotspot_sync``), which also
verifies that the binding, user and session are gone. When the router cannot be
reached, the cleanup is recorded as a pending ``provisioning_logs`` row and
retried by :func:`retry_pending_cleanups` from the housekeeping job; routers
running the outbound agent also get a durable ``hotspot_remove`` command.

A MAC that another live customer (or an active access credential) holds on the
same router is never touched.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import async_session
from app.db.models import (
    AccessCredential,
    AccessCredStatus,
    ConnectionType,
    Customer,
    CustomerStatus,
    ProvisioningLog,
    Router,
    RouterAuthMethod,
)
from app.services.mikrotik_api import normalize_mac_address

logger = logging.getLogger(__name__)

CLEANUP_ACTION = "deleted_customer_router_cleanup"
STATUS_PENDING = "pending"
STATUS_DONE = "success"
STATUS_SKIPPED = "cancelled"
STATUS_ABANDONED = "abandoned"

RETRY_WINDOW = timedelta(days=7)
RETRY_MAX_ROWS_PER_RUN = 200
RETRY_MAX_ROUTERS_PER_RUN = 10
# A router that just failed is not retried until this has passed, so a few
# dead routers cannot take every slot of every run.
RETRY_ROUTER_BACKOFF = timedelta(minutes=30)

_router_failed_at: dict[int, datetime] = {}


def _compact(mac: str) -> str:
    return normalize_mac_address(mac).replace(":", "").upper()


def _mac_compact_expr(column):
    return func.replace(func.replace(func.upper(column), ":", ""), "-", "")


def _auth_value(router: Router) -> Any:
    method = getattr(router, "auth_method", None)
    return method.value if hasattr(method, "value") else method


def cleanup_target(customer: Customer) -> Optional[dict]:
    """Plain data needed to clean a hotspot customer off its router later.

    None for anything that is not a direct-API hotspot customer with a MAC and
    a router: PPPoE and static-IP customers have their own removal in the
    delete path, and RADIUS access goes with the radius rows.
    """
    router = customer.router
    if not customer.mac_address or router is None:
        return None
    connection_type = customer.plan.connection_type if customer.plan else None
    if connection_type in (ConnectionType.PPPOE, ConnectionType.STATIC_IP):
        return None
    if customer.pppoe_username and connection_type is None:
        return None
    if _auth_value(router) == RouterAuthMethod.RADIUS.value:
        return None
    try:
        mac = normalize_mac_address(customer.mac_address)
    except Exception:
        return None
    return {
        "customer_id": customer.id,
        "name": customer.name,
        "mac_address": mac,
        "router_id": router.id,
        "router_agent": bool(getattr(router, "router_agent_enabled", False) and router.identity),
        "router_info": _router_info(router),
    }


def _router_info(router: Router) -> dict:
    return {
        "id": router.id,
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
        "name": router.name,
        "lb_enabled": bool(getattr(router, "lb_enabled", False)),
    }


async def macs_in_use_on_router(db: AsyncSession, router_id: int, macs: set[str]) -> set[str]:
    """The MACs (normalized) that a live customer or credential holds on a router."""
    compacts = {_compact(m): m for m in macs if m}
    if not compacts:
        return set()
    in_use: set[str] = set()
    rows = await db.execute(
        select(Customer.mac_address).where(
            Customer.router_id == router_id,
            Customer.status.in_((CustomerStatus.ACTIVE, CustomerStatus.PENDING)),
            _mac_compact_expr(Customer.mac_address).in_(list(compacts)),
        )
    )
    in_use.update(compacts[_compact(mac)] for (mac,) in rows.all() if mac)
    rows = await db.execute(
        select(AccessCredential.bound_mac_address).where(
            AccessCredential.router_id == router_id,
            AccessCredential.status == AccessCredStatus.ACTIVE,
            _mac_compact_expr(AccessCredential.bound_mac_address).in_(list(compacts)),
        )
    )
    in_use.update(compacts[_compact(mac)] for (mac,) in rows.all() if mac)
    return in_use


def _cleanup_on_router(router_info: dict, customers_data: list) -> dict:
    """The expiry job's verified hotspot removal for one router."""
    from app.services import mikrotik_background

    return mikrotik_background._cleanup_single_router_hotspot_sync(router_info, customers_data)


async def _run_cleanup(router_info: dict, items: list[dict]) -> dict:
    """{item id: error or None} for each item. Never raises."""
    try:
        outcome = await asyncio.to_thread(_cleanup_on_router, router_info, items)
    except Exception as exc:
        return {item["id"]: str(exc) for item in items}
    errors = {item["id"]: "not verified" for item in items}
    for row in outcome.get("removed", []):
        errors[row["id"]] = None
    for row in outcome.get("failed", []):
        errors[row["id"]] = row.get("error") or "router cleanup failed"
    return errors


async def _queue_agent_remove(target: dict) -> Optional[int]:
    if not target.get("router_agent"):
        return None
    from app.services.router_agent_commands import queue_hotspot_remove_for_deleted_customer

    try:
        return await queue_hotspot_remove_for_deleted_customer(
            router_id=target["router_id"],
            deleted_customer_id=target["customer_id"],
            mac_address=target["mac_address"],
            lb_enabled=target["router_info"]["lb_enabled"],
        )
    except Exception as exc:
        logger.warning(
            "Could not queue router-agent removal for deleted customer %s: %s",
            target["customer_id"], exc,
        )
        return None


async def _record_pending(target: dict, error: str, agent_command_id: Optional[int]) -> None:
    details = f"deleted customer {target['customer_id']}"
    if agent_command_id is not None:
        details += f"; agent command {agent_command_id}"
    async with async_session() as db:
        db.add(ProvisioningLog(
            customer_id=None,
            router_id=target["router_id"],
            mac_address=target["mac_address"],
            action=CLEANUP_ACTION,
            status=STATUS_PENDING,
            error=(error or "")[:255],
            details=details[:255],
        ))
        await db.commit()


async def remove_deleted_customer_from_router(target: Optional[dict]) -> Optional[str]:
    """Remove a just-deleted hotspot customer from its router.

    Call after the customer row is committed as deleted, with no DB session
    held. Returns ``"removed"``, ``"queued"`` (router unreachable or removal not
    verified; retried later), ``"skipped"`` (another live customer or credential
    uses this MAC on the router) or None when there is nothing to clean.
    Never raises: the delete has already happened.
    """
    if not target:
        return None
    try:
        return await _remove(target)
    except Exception as exc:
        logger.error(
            "Router cleanup for deleted customer %s failed unexpectedly: %s",
            target["customer_id"], exc,
        )
        return "failed"


async def _remove(target: dict) -> str:
    mac = target["mac_address"]
    async with async_session() as db:
        in_use = await macs_in_use_on_router(db, target["router_id"], {mac})
        await db.commit()
    if in_use:
        logger.info(
            "Deleted customer %s: %s is still used by a live customer on router %s; "
            "router entries left in place",
            target["customer_id"], mac, target["router_id"],
        )
        return "skipped"

    item = {"id": target["customer_id"], "name": target["name"] or mac, "mac_address": mac}
    errors = await _run_cleanup(target["router_info"], [item])
    error = errors.get(item["id"])
    if error is None:
        return "removed"

    logger.warning(
        "Deleted customer %s (%s): router %s cleanup failed (%s); queued for retry",
        target["customer_id"], mac, target["router_id"], error,
    )
    agent_command_id = await _queue_agent_remove(target)
    await _record_pending(target, error, agent_command_id)
    return "queued"


async def queue_for_retry(targets: list[dict], error: str) -> None:
    """Record router cleanups that were attempted elsewhere and failed."""
    for target in targets:
        try:
            agent_command_id = await _queue_agent_remove(target)
            await _record_pending(target, error, agent_command_id)
        except Exception as exc:
            logger.error(
                "Could not queue router cleanup for deleted customer %s: %s",
                target["customer_id"], exc,
            )


async def retry_pending_cleanups(now: Optional[datetime] = None) -> dict:
    """Retry queued deleted-customer cleanups. Run from housekeeping.

    One short session reads the work and re-checks which MACs became live
    again; router I/O runs with no session held; one short session writes the
    results.
    """
    now = now or datetime.utcnow()
    summary = {"removed": 0, "skipped": 0, "still_pending": 0, "abandoned": 0}
    async with async_session() as db:
        abandoned = await db.execute(
            update(ProvisioningLog)
            .where(
                ProvisioningLog.action == CLEANUP_ACTION,
                ProvisioningLog.status == STATUS_PENDING,
                ProvisioningLog.log_date < now - RETRY_WINDOW,
            )
            .values(status=STATUS_ABANDONED)
        )
        summary["abandoned"] = abandoned.rowcount or 0
        rows = (
            await db.execute(
                select(ProvisioningLog, Router)
                .join(Router, Router.id == ProvisioningLog.router_id)
                .where(
                    ProvisioningLog.action == CLEANUP_ACTION,
                    ProvisioningLog.status == STATUS_PENDING,
                    ProvisioningLog.mac_address.isnot(None),
                )
                .order_by(ProvisioningLog.id)
                .limit(RETRY_MAX_ROWS_PER_RUN)
            )
        ).all()

        groups: dict[int, dict] = {}
        for log, router in rows:
            failed_at = _router_failed_at.get(router.id)
            if failed_at and now - failed_at < RETRY_ROUTER_BACKOFF:
                continue
            if router.id not in groups:
                if len(groups) >= RETRY_MAX_ROUTERS_PER_RUN:
                    continue
                groups[router.id] = {"router_info": _router_info(router), "items": []}
            groups[router.id]["items"].append({
                "id": log.id,
                "name": log.details or log.mac_address,
                "mac_address": normalize_mac_address(log.mac_address),
            })

        statuses: dict[int, str] = {}
        for router_id, group in groups.items():
            in_use = await macs_in_use_on_router(
                db, router_id, {item["mac_address"] for item in group["items"]},
            )
            keep = []
            for item in group["items"]:
                if item["mac_address"] in in_use:
                    statuses[item["id"]] = STATUS_SKIPPED
                else:
                    keep.append(item)
            group["items"] = keep
        await db.commit()

    async def _one(router_id: int, group: dict) -> dict:
        return await _run_cleanup(group["router_info"], group["items"])

    work = [(rid, g) for rid, g in groups.items() if g["items"]]
    outcomes = await asyncio.gather(*[_one(rid, g) for rid, g in work])
    errors: dict[int, str] = {}
    for (router_id, _group), result in zip(work, outcomes):
        router_failed = False
        for log_id, error in result.items():
            if error is None:
                statuses[log_id] = STATUS_DONE
            else:
                errors[log_id] = error
                router_failed = True
        if router_failed:
            _router_failed_at[router_id] = datetime.utcnow()
        else:
            _router_failed_at.pop(router_id, None)

    if statuses or errors:
        async with async_session() as db:
            for log_id, status in statuses.items():
                await db.execute(
                    update(ProvisioningLog)
                    .where(ProvisioningLog.id == log_id, ProvisioningLog.status == STATUS_PENDING)
                    .values(status=status, error=None)
                )
            for log_id, error in errors.items():
                await db.execute(
                    update(ProvisioningLog)
                    .where(ProvisioningLog.id == log_id)
                    .values(error=error[:255])
                )
            await db.commit()

    summary["removed"] = sum(1 for s in statuses.values() if s == STATUS_DONE)
    summary["skipped"] = sum(1 for s in statuses.values() if s == STATUS_SKIPPED)
    summary["still_pending"] = len(errors)
    if any(summary.values()):
        logger.info("[DELETED-CLEANUP] %s", summary)
    return summary

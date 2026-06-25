from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import (
    Customer,
    CustomerStatus,
    ProvisioningAttempt,
    Router,
    UsageCapWatchState,
)
from app.config import settings
from app.services.mikrotik_api import MikroTikAPI
from app.services.pppoe_provisioning import (
    PPPOE_DEFAULT_LOCAL_ADDRESS,
    PPPOE_DEFAULT_POOL_NAME,
    PPPOE_DEFAULT_POOL_RANGE,
    _apply_pppoe_headroom,
)


logger = logging.getLogger(__name__)


@dataclass
class PPPOERouterTransferReport:
    source_router_id: int
    target_router_id: int
    dry_run: bool
    active_only: bool = False
    source_router_name: str | None = None
    target_router_name: str | None = None
    selected: int = 0
    moved: int = 0
    active: int = 0
    inactive: int = 0
    pending: int = 0
    missing_passwords: int = 0
    missing_active_passwords: int = 0
    target_provision: bool = True
    target_provision_required: int = 0
    target_provisioned: int = 0
    target_provision_failed: int = 0
    target_provision_skipped: int = 0
    target_provision_failures: list[dict[str, Any]] = field(default_factory=list)
    usage_watch_states_updated: int = 0
    provisioning_attempts_updated: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _status_key(customer: Customer) -> str:
    value = customer.status.value if hasattr(customer.status, "value") else str(customer.status)
    return value.lower()


def _rowcount(result) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def _sample(customer: Customer) -> dict[str, Any]:
    plan = customer.plan
    return {
        "customer_id": customer.id,
        "name": customer.name,
        "phone": customer.phone,
        "pppoe_username": customer.pppoe_username,
        "status": customer.status.value if hasattr(customer.status, "value") else customer.status,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "plan_id": customer.plan_id,
        "plan_name": plan.name if plan else None,
        "plan_speed": plan.speed if plan else None,
        "password_present": bool(customer.pppoe_password),
    }


def _router_info(router: Router) -> dict[str, Any]:
    return {
        "id": router.id,
        "name": router.name,
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
    }


def _target_provision_item(customer: Customer, target_router: Router) -> dict[str, Any]:
    plan = customer.plan
    return {
        "customer_id": customer.id,
        "pppoe_username": customer.pppoe_username,
        "pppoe_password": customer.pppoe_password,
        "bandwidth_limit": plan.speed if plan else "10Mbps",
        "comment": f"CID:{customer.id}|{customer.name or customer.phone}|{datetime.utcnow().strftime('%Y-%m-%d')}",
        "router_id": target_router.id,
    }


def _failure(customer_id: int | None, username: str | None, error: str) -> dict[str, Any]:
    return {
        "customer_id": customer_id,
        "pppoe_username": username,
        "error": error,
    }


def _provision_target_router_sync(router_info: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    """Provision active PPPoE secrets on the target router using one RouterOS session."""
    if not items:
        return {"success": True, "provisioned": [], "failed": [], "fasttrack_bypass_result": None}

    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )

    if not api.connect():
        return {
            "success": False,
            "provisioned": [],
            "failed": [
                _failure(item.get("customer_id"), item.get("pppoe_username"), "Failed to connect to target router")
                for item in items
            ],
        }

    provisioned: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    ensured_profiles: dict[str, bool] = {}
    fasttrack_bypass_result = None

    try:
        base_profile = api.get_active_pppoe_profile()
        base_profile_data = base_profile.get("data") if base_profile.get("found") else {}
        local_address = base_profile_data.get("local_address") or PPPOE_DEFAULT_LOCAL_ADDRESS
        pool_name = base_profile_data.get("remote_address") or PPPOE_DEFAULT_POOL_NAME

        if pool_name == PPPOE_DEFAULT_POOL_NAME:
            pool_result = api.ensure_ip_pool(PPPOE_DEFAULT_POOL_NAME, PPPOE_DEFAULT_POOL_RANGE)
            if pool_result.get("error"):
                return {
                    "success": False,
                    "provisioned": [],
                    "failed": [
                        _failure(
                            item.get("customer_id"),
                            item.get("pppoe_username"),
                            f"IP pool ensure failed: {pool_result['error']}",
                        )
                        for item in items
                    ],
                    "ip_pool_result": pool_result,
                }

        headroom_factor = float(getattr(settings, "PPPOE_RATE_LIMIT_HEADROOM", 1.0) or 1.0)

        for item in items:
            customer_id = item.get("customer_id")
            username = item.get("pppoe_username")
            try:
                base_rate_limit = api._parse_speed_to_mikrotik(item["bandwidth_limit"])
                rate_limit = _apply_pppoe_headroom(base_rate_limit, headroom_factor)
                profile_name = f"pppoe_{base_rate_limit.replace('/', '_')}"

                if not ensured_profiles.get(profile_name):
                    profile_result = api.ensure_pppoe_profile(
                        profile_name,
                        rate_limit,
                        local_address=local_address,
                        pool_name=pool_name,
                        dns_server=base_profile_data.get("dns_server", ""),
                        change_tcp_mss=base_profile_data.get("change_tcp_mss", ""),
                    )
                    if profile_result.get("error"):
                        failed.append(
                            _failure(customer_id, username, f"Profile creation failed: {profile_result['error']}")
                        )
                        continue
                    ensured_profiles[profile_name] = True

                secret_result = api.add_pppoe_secret(
                    username=username,
                    password=item.get("pppoe_password"),
                    profile=profile_name,
                    comment=item.get("comment", ""),
                )
                if secret_result.get("error"):
                    failed.append(_failure(customer_id, username, f"Secret creation failed: {secret_result['error']}"))
                    continue

                disconnect_result = api.disconnect_pppoe_session(username)
                provisioned.append(
                    {
                        "customer_id": customer_id,
                        "pppoe_username": username,
                        "profile": profile_name,
                        "base_rate_limit": base_rate_limit,
                        "rate_limit": rate_limit,
                        "disconnect_result": disconnect_result,
                    }
                )
            except Exception as exc:
                failed.append(_failure(customer_id, username, str(exc)))

        if provisioned:
            fasttrack_bypass_result = api.ensure_pppoe_fasttrack_bypass(pool_name=pool_name)
            if fasttrack_bypass_result.get("error"):
                logger.warning(
                    "FastTrack bypass ensure failed on target router %s: %s",
                    router_info.get("id"),
                    fasttrack_bypass_result["error"],
                )

        return {
            "success": not failed,
            "provisioned": provisioned,
            "failed": failed,
            "fasttrack_bypass_result": fasttrack_bypass_result,
        }
    finally:
        api.disconnect()


async def _provision_target_router(router_info: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
    return await asyncio.to_thread(_provision_target_router_sync, router_info, items)


async def transfer_pppoe_customers_between_routers(
    db: AsyncSession,
    *,
    source_router_id: int,
    target_router_id: int,
    dry_run: bool = True,
    active_only: bool = False,
    provision_target: bool = True,
    sample_limit: int = 10,
) -> PPPOERouterTransferReport:
    """Move PPPoE customer ownership from one router to another.

    Active PPPoE customers are provisioned on the destination router before the
    DB move by default. Inactive/pending customers move in DB only, preserving
    their inactive state until a future renewal provisions them.
    """
    report = PPPOERouterTransferReport(
        source_router_id=source_router_id,
        target_router_id=target_router_id,
        dry_run=dry_run,
        active_only=active_only,
        target_provision=provision_target,
    )

    if source_router_id == target_router_id:
        report.errors.append("source_router_id and target_router_id must be different")
        return report

    routers = (
        await db.execute(
            select(Router).where(Router.id.in_([source_router_id, target_router_id]))
        )
    ).scalars().all()
    by_id = {router.id: router for router in routers}
    source_router = by_id.get(source_router_id)
    target_router = by_id.get(target_router_id)

    if not source_router:
        report.errors.append(f"source router {source_router_id} was not found")
    if not target_router:
        report.errors.append(f"target router {target_router_id} was not found")
    if report.errors:
        return report

    report.source_router_name = source_router.name
    report.target_router_name = target_router.name

    if source_router.user_id != target_router.user_id:
        report.errors.append(
            "source and target routers belong to different users; refusing cross-owner transfer"
        )
        return report

    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.router_id == source_router_id,
            Customer.pppoe_username.isnot(None),
            Customer.pppoe_username != "",
        )
        .order_by(Customer.id.asc())
    )
    if active_only:
        stmt = stmt.where(Customer.status == CustomerStatus.ACTIVE)

    customers = (await db.execute(stmt)).scalars().all()
    report.selected = len(customers)
    target_items: list[dict[str, Any]] = []

    for customer in customers:
        status = _status_key(customer)
        if status == CustomerStatus.ACTIVE.value:
            report.active += 1
            if provision_target:
                target_items.append(_target_provision_item(customer, target_router))
        elif status == CustomerStatus.INACTIVE.value:
            report.inactive += 1
        elif status == CustomerStatus.PENDING.value:
            report.pending += 1

        if not customer.pppoe_password:
            report.missing_passwords += 1
            if status == CustomerStatus.ACTIVE.value:
                report.missing_active_passwords += 1

        if len(report.samples) < sample_limit:
            report.samples.append(_sample(customer))

    report.target_provision_required = len(target_items)
    report.target_provision_skipped = report.selected - report.target_provision_required

    if active_only:
        report.warnings.append(
            "active_only is enabled; inactive/expired PPPoE customers will still point at the source router"
        )
    if report.missing_passwords:
        report.warnings.append(
            f"{report.missing_passwords} selected customer(s) have no PPPoE password in the DB. "
            "The DB move preserves that state, but a blank destination router cannot recreate "
            "those secrets without passwords imported from RouterOS."
        )
    if not provision_target and report.active:
        report.warnings.append(
            "target provisioning is disabled; active customers will be moved in DB without updating the target router"
        )

    if dry_run:
        report.moved = report.selected
        return report

    if provision_target and target_items:
        # End the read transaction before RouterOS I/O. No DB connection should
        # be pinned while the target router is being updated.
        await db.commit()
        target_result = await _provision_target_router(_router_info(target_router), target_items)
        report.target_provisioned = len(target_result.get("provisioned") or [])
        report.target_provision_failures = list(target_result.get("failed") or [])
        report.target_provision_failed = len(report.target_provision_failures)
        if report.target_provision_failures:
            report.errors.append(
                "Target router provisioning failed for one or more active PPPoE customers; DB move was not applied"
            )
            return report

    customer_ids = [customer.id for customer in customers]
    now = datetime.utcnow()

    for customer in customers:
        customer.router_id = target_router_id

    if customer_ids:
        usage_result = await db.execute(
            update(UsageCapWatchState)
            .where(
                UsageCapWatchState.customer_id.in_(customer_ids),
                UsageCapWatchState.router_id == source_router_id,
            )
            .values(router_id=target_router_id, updated_at=now)
        )
        report.usage_watch_states_updated = _rowcount(usage_result)

        attempt_result = await db.execute(
            update(ProvisioningAttempt)
            .where(
                ProvisioningAttempt.customer_id.in_(customer_ids),
                ProvisioningAttempt.router_id == source_router_id,
            )
            .values(router_id=target_router_id, updated_at=now)
        )
        report.provisioning_attempts_updated = _rowcount(attempt_result)

    await db.commit()
    report.moved = report.selected
    return report

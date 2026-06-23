"""Shared-customer subscription helpers.

Plan ``max_shared_users`` is the total-device allowance on one paid
subscription, including the paying owner's device. A value of 1 keeps sharing
disabled; values above 1 allow ``max_shared_users - 1`` extra devices/customers.
"""

import logging
from datetime import datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DevicePairing,
    Plan,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    Router,
    RouterAuthMethod,
)
from app.services.hotspot_provisioning import (
    get_or_create_provisioning_attempt,
    schedule_provisioning_attempt,
)
from app.services.mikrotik_api import normalize_mac_address

logger = logging.getLogger(__name__)


def max_shared_users_for_plan(plan: Plan | None) -> int:
    raw_value = getattr(plan, "max_shared_users", None) or 1
    try:
        return max(1, int(raw_value))
    except (TypeError, ValueError):
        return 1


def sharing_enabled_for_plan(plan: Plan | None) -> bool:
    return max_shared_users_for_plan(plan) > 1


def shared_device_limit_for_plan(plan: Plan | None) -> int:
    max_shared_users = max_shared_users_for_plan(plan)
    return max(0, max_shared_users - 1)


async def active_shared_device_count(
    db: AsyncSession,
    owner_customer_id: int,
    *,
    exclude_pairing_id: int | None = None,
) -> int:
    stmt = select(func.count(DevicePairing.id)).where(
        DevicePairing.subscription_owner_customer_id == owner_customer_id,
        DevicePairing.is_subscription_share == True,  # noqa: E712
        DevicePairing.is_active == True,  # noqa: E712
    )
    if exclude_pairing_id is not None:
        stmt = stmt.where(DevicePairing.id != exclude_pairing_id)

    return int((await db.execute(stmt)).scalar() or 0)


async def schedule_shared_device_delivery(
    db: AsyncSession,
    *,
    shared_customer: Customer,
    owner_customer: Customer,
    pairing: DevicePairing,
    router: Router,
):
    attempt = await get_or_create_provisioning_attempt(
        db,
        customer_id=shared_customer.id,
        router_id=router.id,
        mac_address=shared_customer.mac_address,
        source_table=ProvisioningAttemptSource.SUBSCRIPTION_SHARE,
        source_pk=pairing.id,
        external_reference=f"share:{owner_customer.id}:{pairing.id}",
        entrypoint=ProvisioningAttemptEntrypoint.SUBSCRIPTION_SHARE,
    )
    await schedule_provisioning_attempt(db, attempt)
    return attempt


async def update_radius_shared_device_expiry(
    db: AsyncSession,
    *,
    shared_customer: Customer,
    expires_at: datetime,
) -> None:
    if not shared_customer.mac_address:
        return

    username = normalize_mac_address(shared_customer.mac_address).replace(":", "").upper()
    now = datetime.utcnow()
    session_timeout = max(60, int((expires_at - now).total_seconds()))

    await db.execute(
        text(
            """
            UPDATE radius_check
            SET expiry = :expiry, updated_at = :updated_at
            WHERE username = :username
            """
        ),
        {"username": username, "expiry": expires_at, "updated_at": now},
    )
    await db.execute(
        text(
            """
            UPDATE radius_reply
            SET expiry = :expiry, updated_at = :updated_at
            WHERE username = :username
            """
        ),
        {"username": username, "expiry": expires_at, "updated_at": now},
    )
    await db.execute(
        text(
            """
            UPDATE radius_reply
            SET value = :session_timeout, updated_at = :updated_at
            WHERE username = :username AND attribute = 'Session-Timeout'
            """
        ),
        {
            "username": username,
            "session_timeout": str(session_timeout),
            "updated_at": now,
        },
    )


async def sync_shared_subscription_devices_after_owner_renewal(
    db: AsyncSession,
    *,
    owner_customer: Customer,
    plan: Plan | None,
) -> list[dict]:
    """Extend active companion devices to the paying owner's new expiry.

    Direct-API routers get a scheduled provisioning attempt. The scheduler or
    caller can deliver it after the current DB transaction is committed.
    """
    if not owner_customer.expiry or not sharing_enabled_for_plan(plan):
        return []

    rows = (
        await db.execute(
            select(DevicePairing, Customer, Router)
            .join(Customer, DevicePairing.customer_id == Customer.id)
            .join(Router, DevicePairing.router_id == Router.id)
            .where(
                DevicePairing.subscription_owner_customer_id == owner_customer.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).all()

    synced: list[dict] = []
    now = datetime.utcnow()
    for pairing, shared_customer, router in rows:
        if not shared_customer.mac_address:
            continue

        shared_customer.status = CustomerStatus.ACTIVE
        shared_customer.expiry = owner_customer.expiry
        shared_customer.plan_id = owner_customer.plan_id
        shared_customer.user_id = owner_customer.user_id
        shared_customer.router_id = router.id
        shared_customer.subscription_owner_id = owner_customer.id
        pairing.plan_id = owner_customer.plan_id
        pairing.expires_at = owner_customer.expiry

        try:
            from app.services.usage_tracking import on_renewal

            await on_renewal(db, shared_customer, plan=plan, now=now)
        except Exception as exc:
            logger.error(
                "[SUBSCRIPTION-SHARE] Failed to renew usage period for shared customer %s: %s",
                shared_customer.id,
                exc,
            )

        auth_method = getattr(router, "auth_method", None)
        auth_value = auth_method.value if hasattr(auth_method, "value") else auth_method
        if auth_value == RouterAuthMethod.RADIUS.value:
            try:
                async with db.begin_nested():
                    await update_radius_shared_device_expiry(
                        db,
                        shared_customer=shared_customer,
                        expires_at=owner_customer.expiry,
                    )
            except Exception as exc:
                logger.warning(
                    "[SUBSCRIPTION-SHARE] Failed to refresh RADIUS expiry for shared customer %s: %s",
                    shared_customer.id,
                    exc,
                )
            synced.append(
                {
                    "pairing_id": pairing.id,
                    "customer_id": shared_customer.id,
                    "router_id": router.id,
                    "auth_method": RouterAuthMethod.RADIUS.value,
                    "attempt_id": None,
                }
            )
            continue

        if plan and plan.connection_type == ConnectionType.HOTSPOT:
            attempt = await schedule_shared_device_delivery(
                db,
                shared_customer=shared_customer,
                owner_customer=owner_customer,
                pairing=pairing,
                router=router,
            )
            synced.append(
                {
                    "pairing_id": pairing.id,
                    "customer_id": shared_customer.id,
                    "router_id": router.id,
                    "auth_method": RouterAuthMethod.DIRECT_API.value,
                    "attempt_id": attempt.id,
                }
            )

    return synced

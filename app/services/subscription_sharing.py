"""Shared-customer subscription helpers.

Plan ``max_shared_users`` is the total-device allowance on one paid
subscription, including the paying owner's device. A value of 1 keeps sharing
disabled; values above 1 allow ``max_shared_users - 1`` extra devices/customers.
"""

import logging
from datetime import datetime, timedelta

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

# A reused delivery attempt older than this starts a fresh retry window.
SHARE_ATTEMPT_REUSE_RESET_AFTER = timedelta(minutes=5)


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


def max_devices_for_customer(customer: Customer | None, plan: Plan | None = None) -> int:
    """Total devices this customer may use, including their own.

    The reseller's per-customer ``max_devices_override`` wins over the plan's
    ``max_shared_users``. Pass ``plan`` whenever the customer's plan relation
    may not be loaded, so it is never lazy-loaded in async code.
    """
    override = getattr(customer, "max_devices_override", None) if customer is not None else None
    if override is not None:
        try:
            return max(1, int(override))
        except (TypeError, ValueError):
            pass
    if plan is None and customer is not None:
        plan = customer.__dict__.get("plan")
    return max_shared_users_for_plan(plan)


def sharing_enabled_for_customer(customer: Customer | None, plan: Plan | None = None) -> bool:
    return max_devices_for_customer(customer, plan) > 1


def shared_device_limit_for_customer(customer: Customer | None, plan: Plan | None = None) -> int:
    """Extra devices allowed beyond the customer's own."""
    return max(0, max_devices_for_customer(customer, plan) - 1)


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
    # One attempt row per pairing, reused on every renewal. Its retry window is
    # measured from created_at, so without a reset a renewal re-scheduled a
    # weeks-old row and the retry job failed it on its next tick ("retry window
    # exhausted") before pushing anything: the device only came back if the
    # router ran the check-in applier.
    now = datetime.utcnow()
    if attempt.created_at is None or now - attempt.created_at > SHARE_ATTEMPT_REUSE_RESET_AFTER:
        attempt.created_at = now
        attempt.attempt_count = 0
        attempt.last_attempt_at = None
        attempt.router_updated_at = None
        attempt.delivered_via = None
        attempt.access_seen_at = None
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


async def carry_owner_edit_to_shared_devices(
    db: AsyncSession,
    *,
    owner_customer: Customer,
) -> list[int]:
    """Copy an edited owner's expiry and plan onto its active shared devices.

    Renewals do this through sync_shared_subscription_devices_after_owner_renewal.
    A reseller editing the owner directly does not renew anything, so usage
    periods stay open; only the fields every device must agree on move. Returns
    the shared customer ids changed. The caller owns the transaction.
    """
    rows = (
        await db.execute(
            select(DevicePairing, Customer)
            .join(Customer, DevicePairing.customer_id == Customer.id)
            .where(
                DevicePairing.subscription_owner_customer_id == owner_customer.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).all()
    changed: list[int] = []
    for pairing, shared in rows:
        if shared.expiry == owner_customer.expiry and shared.plan_id == owner_customer.plan_id:
            continue
        shared.expiry = owner_customer.expiry
        shared.plan_id = owner_customer.plan_id
        pairing.expires_at = owner_customer.expiry
        pairing.plan_id = owner_customer.plan_id
        changed.append(shared.id)
    return changed


async def sync_shared_subscription_devices_after_owner_renewal(
    db: AsyncSession,
    *,
    owner_customer: Customer,
    plan: Plan | None,
    defer_router_io: bool = False,
) -> list[dict]:
    """Extend active companion devices to the paying owner's new expiry.

    Only as many devices as the (possibly new) plan allows come back, newest
    first; the rest are released so a downgrade from a 5-device plan to a
    2-device plan doesn't silently keep 4 extra devices online.

    Direct-API routers get a scheduled provisioning attempt. The scheduler or
    caller can deliver it after the current DB transaction is committed.
    """
    if not owner_customer.expiry:
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
            .order_by(DevicePairing.created_at.desc(), DevicePairing.id.desc())
        )
    ).all()

    limit = shared_device_limit_for_customer(owner_customer, plan)
    now = datetime.utcnow()
    for pairing, shared_customer, _router in rows[limit:]:
        pairing.is_active = False
        pairing.expires_at = now
        shared_customer.subscription_owner_id = None
        logger.info(
            "[SUBSCRIPTION-SHARE] Released shared device %s (pairing %s): owner %s renewed onto a plan allowing %d extra device(s)",
            shared_customer.id,
            pairing.id,
            owner_customer.id,
            limit,
        )

    synced: list[dict] = []
    for pairing, shared_customer, router in rows[:limit]:
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

            await on_renewal(db, shared_customer, plan=plan, now=now,
                             **({"defer_router_io": True} if defer_router_io else {}))
        except Exception as exc:
            if defer_router_io:
                raise
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
                if defer_router_io:
                    raise
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

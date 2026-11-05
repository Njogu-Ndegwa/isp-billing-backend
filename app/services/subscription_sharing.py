"""Shared-customer subscription helpers.

Plan ``max_shared_users`` is the total-device allowance on one paid
subscription, including the paying owner's device. A value of 1 keeps sharing
disabled; values above 1 allow ``max_shared_users - 1`` extra devices/customers.
"""

import asyncio
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
from app.services.device_entitlements import PINNED_DEVICE_TYPES
from app.services.hotspot_provisioning import (
    build_hotspot_payload,
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


def _cap_or_none(plan: Plan) -> int | None:
    cap = plan.data_cap_mb
    return cap if cap and cap > 0 else None


async def smaller_voucher_refusal(
    db: AsyncSession,
    *,
    customer: Customer | None,
    new_plan: Plan,
    now: datetime | None = None,
) -> str | None:
    """Why this voucher must not replace a live group plan, or None if it may.

    A purchase replaces the plan for all remaining time. On a group that drops
    the device limit and the cap for everyone (router 446: a 2,500 XAF voucher
    turned an 18,000 XAF plan for 10 devices into a plan for 1). So a voucher
    giving fewer devices or a lower cap is refused while the plan has paid time
    left, and stays unused. ``customer.plan`` must already be loaded.

    Only groups: a plan for one device changing to another is the ordinary
    top-up, such as an unlimited hour followed by a capped week. Paid time only:
    a customer in grace is renewing, so they are never refused here.
    """
    if customer is None or customer.subscription_owner_id is not None:
        return None
    current = customer.plan
    if current is None or current.connection_type != ConnectionType.HOTSPOT:
        return None
    now = now or datetime.utcnow()
    if customer.status != CustomerStatus.ACTIVE or not customer.expiry or customer.expiry <= now:
        return None

    shared_devices = await active_shared_device_count(db, customer.id)
    current_devices = max_devices_for_customer(customer, current)
    if current_devices <= 1 and shared_devices == 0:
        return None

    new_devices = max_devices_for_customer(customer, new_plan)
    fewer_devices = new_devices < current_devices or new_devices - 1 < shared_devices
    current_cap, new_cap = _cap_or_none(current), _cap_or_none(new_plan)
    lower_cap = new_cap is not None and (current_cap is None or new_cap < current_cap)
    if not fewer_devices and not lower_cap:
        return None

    logger.info(
        "[VOUCHER] Refused plan %s on customer %s: live plan %s (devices %d -> %d, shared %d, cap %s -> %s)",
        new_plan.id, customer.id, current.id, current_devices, new_devices,
        shared_devices, current_cap, new_cap,
    )
    return (
        f"This voucher is for a smaller plan than the {(current.name or '').strip()} plan on "
        "this device, so we did not use it. It is still valid. Use it after this plan ends, "
        "or on another device."
    )


def apply_voucher_plan_if_plan_ended(
    customer: Customer,
    new_plan: Plan,
    now: datetime | None = None,
) -> None:
    """Give a voucher's own limits to a customer with no paid time left.

    ``record_customer_payment`` keeps the old plan's cap and device limit when the
    new plan gives less and the old one is still loaded. That protects a live plan
    but not an ended one, where nothing is being taken away (router 563: a voucher
    for 1 device and 50 MB left a group on 3 devices and 200 MB). Vouchers only:
    other payments keep that rule. ``customer.plan`` must already be loaded.
    """
    now = now or datetime.utcnow()
    if customer.expiry is None or customer.expiry <= now:
        customer.plan = new_plan


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


async def push_plan_edit_to_router(
    db: AsyncSession,
    *,
    customer: Customer,
    plan: Plan | None,
    router: Router | None,
) -> dict | None:
    """Put an edited plan's speed on the router now, for the customer and any
    devices sharing their plan. Commits, then delivers in the background.

    Delivery drops the session for a moment, so the caller only asks when the
    speed changed. It also writes the plan's full speed, so a device under a FUP
    throttle or block is left alone. If a push fails, the fleet queue sync still
    applies the plan and any throttle. Returns None when nothing applies.
    """
    from app.services import hotspot_provisioning
    from app.services.customer_grace import has_access_time
    from app.services.pppoe_provisioning import active_fup_restriction

    if (
        plan is None
        or router is None
        or plan.connection_type != ConnectionType.HOTSPOT
        or getattr(router, "auth_method", None) == RouterAuthMethod.RADIUS
    ):
        return None

    now = datetime.utcnow()

    def _live(row: Customer) -> bool:
        return bool(
            row.mac_address
            and row.status == CustomerStatus.ACTIVE
            and row.expiry
            and has_access_time(row, now)
        )

    if not _live(customer):
        return None

    targets: list[tuple[Customer, DevicePairing | None]] = [(customer, None)]
    if not customer.subscription_owner_id:
        rows = (
            await db.execute(
                select(DevicePairing, Customer)
                .join(Customer, DevicePairing.customer_id == Customer.id)
                .where(
                    DevicePairing.subscription_owner_customer_id == customer.id,
                    DevicePairing.is_subscription_share == True,  # noqa: E712
                    DevicePairing.is_active == True,  # noqa: E712
                )
            )
        ).all()
        targets.extend((shared, pairing) for pairing, shared in rows if _live(shared))

    deliveries = []
    held = 0
    for row, pairing in targets:
        if await active_fup_restriction(db, row.id) is not None:
            held += 1
            continue
        attempt_id = None
        if pairing is not None:
            attempt = await schedule_shared_device_delivery(
                db, shared_customer=row, owner_customer=customer, pairing=pairing, router=router,
            )
            attempt_id = attempt.id
        payload = build_hotspot_payload(
            row, plan, router, comment=f"Plan edit: {(plan.name or '').strip()} | MAC: {row.mac_address}",
        )
        deliveries.append((row.id, payload, attempt_id))
    await db.commit()

    for customer_id, payload, attempt_id in deliveries:
        asyncio.create_task(
            hotspot_provisioning.provision_hotspot_customer(
                customer_id, router.id, payload, "plan_edit", attempt_id,
            )
        )
    logger.info(
        "[PLAN-EDIT] Customer %s moved to plan %s: pushing %d device(s), %d held by FUP",
        customer.id, plan.id, len(deliveries), held,
    )
    return {"pushed": len(deliveries), "held_by_fup": held}


def _split_for_device_limit(rows: list, limit: int) -> tuple[list, list]:
    """Split shared-device rows, given newest first, into (kept, released).

    With room for all of them nothing moves. Otherwise paired devices (TV, console,
    IoT) stay before anything else, newest first within each group: they can't enter
    a code to get back on, and a phone can. The type is read from the row, not
    ``pinned_device_customers``, which skips expired pairings, and a slot's pairing
    has expired whenever a plan has ended.
    """
    if len(rows) <= limit:
        return rows, []
    paired = [row for row in rows if row[0].device_type in PINNED_DEVICE_TYPES]
    others = [row for row in rows if row[0].device_type not in PINNED_DEVICE_TYPES]
    ranked = paired + others
    return ranked[:limit], ranked[limit:]


async def sync_shared_subscription_devices_after_owner_renewal(
    db: AsyncSession,
    *,
    owner_customer: Customer,
    plan: Plan | None,
    defer_router_io: bool = False,
) -> list[dict]:
    """Extend active companion devices to the paying owner's new expiry.

    Only as many devices as the (possibly new) plan allows come back; the rest
    are released so a downgrade from a 5-device plan to a 2-device plan doesn't
    silently keep 4 extra devices online. See ``_split_for_device_limit`` for
    which ones stay.

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
    kept, released = _split_for_device_limit(rows, limit)
    now = datetime.utcnow()
    for pairing, shared_customer, _router in released:
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
    for pairing, shared_customer, router in kept:
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

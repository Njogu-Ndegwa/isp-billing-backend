"""Free-trial plans claimed from the captive portal.

A reseller creates a plan with plan_type=free_trial (price 0) and chooses,
per plan, whether a device may claim it once (trial_once_per_customer=True)
or again each time its previous trial has ended.

Claiming reuses the voucher delivery path: a zero-amount, non-revenue
CustomerPayment extends the customer's expiry, then the router is
provisioned through RADIUS or the direct-API attempt queue. Every claim is
also written to free_trial_claims, which is what the once-only rule checks.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    FreeTrialClaim,
    PaymentMethod,
    Plan,
    PlanType,
    ProvisioningAttemptEntrypoint,
    Router,
    RouterAuthMethod,
    User,
)
from app.services.mikrotik_api import normalize_mac_address
from app.services.plan_cache import plan_model_allows_router
from app.services.reseller_payments import record_customer_payment
from app.services.subscription_sharing import max_shared_users_for_plan, sharing_enabled_for_plan

logger = logging.getLogger(__name__)

TRIAL_ALREADY_USED = "You have already used this free trial."
TRIAL_WHILE_ACTIVE = "You already have active internet. The free trial is for new connections."


def _phone_match_key(phone: Optional[str]) -> Optional[str]:
    """Last 9 digits: the subscriber number in every market we serve, so
    "0712345678", "+254712345678" and "254712345678" are one person.
    Anything shorter is too ambiguous to match on and is ignored."""
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    return digits[-9:] if len(digits) >= 9 else None


def _trial_unavailable_reason(plan: Plan, router: Router, now: datetime) -> Optional[str]:
    if plan.plan_type != PlanType.FREE_TRIAL:
        return "This plan is not a free trial"
    if plan.user_id != router.user_id:
        return "This free trial is not offered on this hotspot"
    if not plan_model_allows_router(plan, router.id):
        return "This free trial is not offered on this hotspot"
    if plan.connection_type != ConnectionType.HOTSPOT:
        return "Free trials are only available on hotspot"
    if plan.is_hidden:
        return "This free trial is not available right now"
    if plan.valid_until and plan.valid_until <= now:
        return "This free trial has ended"
    return None


async def _already_claimed(
    db: AsyncSession, plan_id: int, mac_address: str, phone: Optional[str]
) -> bool:
    match = FreeTrialClaim.mac_address == mac_address
    if phone:
        match = or_(match, FreeTrialClaim.phone == phone)
    claim_id = await db.scalar(
        select(FreeTrialClaim.id)
        .where(FreeTrialClaim.plan_id == plan_id, match)
        .limit(1)
    )
    return claim_id is not None


async def _owner_can_sell(db: AsyncSession, user_id: int) -> bool:
    status = await db.scalar(select(User.subscription_status).where(User.id == user_id))
    if status is None:
        return True
    value = status.value if hasattr(status, "value") else status
    return value in ("active", "trial")


async def get_trial_eligibility(
    db: AsyncSession, router_id: int, mac_address: str
) -> Dict[str, Any]:
    """Free-trial plans on this router and whether this device may claim each.

    Lets the portal hide the trial button for a device that has used it up,
    instead of showing it and failing on tap.
    """
    router = await db.get(Router, router_id)
    if not router:
        return {"success": False, "error": "Router not found"}

    now = datetime.utcnow()
    normalized_mac = normalize_mac_address(mac_address)
    plans = (
        await db.execute(
            select(Plan).where(
                Plan.user_id == router.user_id,
                Plan.plan_type == PlanType.FREE_TRIAL,
            )
        )
    ).scalars().all()

    active_customer = await db.scalar(
        select(Customer.id).where(
            Customer.mac_address == normalized_mac,
            Customer.user_id == router.user_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry > now,
        )
    )

    trials: List[Dict[str, Any]] = []
    for plan in plans:
        if _trial_unavailable_reason(plan, router, now):
            continue
        reason = None
        if active_customer:
            reason = TRIAL_WHILE_ACTIVE
        elif plan.trial_once_per_customer and await _already_claimed(
            db, plan.id, normalized_mac, None
        ):
            reason = TRIAL_ALREADY_USED
        trials.append({
            "plan_id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "trial_once_per_customer": bool(plan.trial_once_per_customer),
            "eligible": reason is None,
            "reason": reason,
        })

    return {"success": True, "router_id": router_id, "trials": trials}


async def claim_free_trial(
    db: AsyncSession,
    plan_id: int,
    mac_address: str,
    router_id: int,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """Grant a free-trial plan to the device and provision it on the router."""
    router = await db.get(Router, router_id)
    if not router:
        return {"success": False, "error": "Router not found"}

    # Lock the plan row so two taps from the same device cannot both pass the
    # once-only check before either claim is written. Held only until the
    # commit below, before any router I/O.
    plan = (
        await db.execute(select(Plan).where(Plan.id == plan_id).with_for_update())
    ).scalar_one_or_none()
    if not plan:
        return {"success": False, "error": "Plan not found"}

    now = datetime.utcnow()
    reason = _trial_unavailable_reason(plan, router, now)
    if reason:
        return {"success": False, "error": reason}
    if not await _owner_can_sell(db, plan.user_id):
        return {
            "success": False,
            "error": "This service is temporarily unavailable. Please contact your ISP.",
            "status_code": 503,
        }

    normalized_mac = normalize_mac_address(mac_address)
    phone_digits = "".join(ch for ch in (phone or "") if ch.isdigit()) or None
    phone_key = _phone_match_key(phone)

    if plan.trial_once_per_customer and await _already_claimed(
        db, plan.id, normalized_mac, phone_key
    ):
        return {"success": False, "error": TRIAL_ALREADY_USED}

    customer = (
        await db.execute(
            select(Customer).where(
                Customer.mac_address == normalized_mac,
                Customer.user_id == plan.user_id,
            )
        )
    ).scalar_one_or_none()

    # A trial is for getting online, not for topping up a paid plan: it would
    # also swap the customer onto the trial's speed for the rest of their time.
    if (
        customer
        and customer.status == CustomerStatus.ACTIVE
        and customer.expiry
        and customer.expiry > now
    ):
        return {"success": False, "error": TRIAL_WHILE_ACTIVE}

    if customer:
        # Assign the relationship, not just plan_id, so the renewal hook in
        # record_customer_payment sees the trial plan rather than a stale one.
        customer.plan = plan
        customer.router_id = router.id
        if phone_digits and not customer.phone:
            customer.phone = phone_digits
    else:
        customer = Customer(
            name="Free Trial",
            phone=phone_digits or "",
            mac_address=normalized_mac,
            status=CustomerStatus.INACTIVE,
            plan=plan,
            user_id=plan.user_id,
            router_id=router.id,
        )
        db.add(customer)
    await db.flush()

    from app.services.voucher_service import _duration_to_days

    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=plan.user_id,
        amount=0.0,
        # Same method vouchers record; the zero amount and counts_as_revenue
        # flag are what mark it free.
        payment_method=PaymentMethod.CASH,
        days_paid_for=_duration_to_days(plan.duration_value, plan.duration_unit.value),
        payment_reference=f"FREE-TRIAL-{plan.id}",
        notes=f"Free trial claimed: {plan.name}",
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
        counts_as_revenue=False,
    )
    await db.flush()

    db.add(FreeTrialClaim(
        plan_id=plan.id,
        user_id=plan.user_id,
        router_id=router.id,
        customer_id=customer.id,
        payment_id=payment.id,
        mac_address=normalized_mac,
        phone=phone_key,
        claimed_at=now,
    ))

    # A trial that covers several devices gets the same multi-use access code
    # a paid plan shows, so the claimer can bring their other devices online
    # by typing it in. Created here, before the commit and any router I/O.
    sharing: Dict[str, Any] = {}
    if sharing_enabled_for_plan(plan):
        from app.api.device_pairing import _format_share_code, get_or_create_access_code

        code_row = await get_or_create_access_code(db, customer)
        sharing = {
            "outcome": "plan_started",
            "sharing_enabled": True,
            "max_devices": max_shared_users_for_plan(plan),
            "access_code": _format_share_code(code_row.code),
        }

    await db.commit()
    await db.refresh(customer)

    logger.info(
        "[FREE TRIAL] plan=%s router=%s mac=%s customer=%s claimed",
        plan.id, router.id, normalized_mac, customer.id,
    )

    from app.services.voucher_service import _provision_direct_api, _provision_radius

    use_radius = getattr(router, "auth_method", None) == RouterAuthMethod.RADIUS
    if use_radius:
        result = await _provision_radius(
            db, customer, plan, router,
            fixed_expiry=customer.expiry,
            message="Free trial started. Use credentials to login.",
        )
    else:
        result = await _provision_direct_api(
            db, customer, plan, router,
            code=f"TRIAL-{plan.id}",
            payment_id=payment.id,
            entrypoint=ProvisioningAttemptEntrypoint.FREE_TRIAL,
            comment=f"Free trial {plan.name} for {normalized_mac}",
            event_label=f"free trial {plan.name}",
            message="Free trial started. Internet access is being provisioned.",
        )
    if result.get("success"):
        result.update(sharing)
    return result

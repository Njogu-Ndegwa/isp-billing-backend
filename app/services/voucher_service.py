import secrets
import uuid
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from sqlalchemy.orm import selectinload

from app.db.models import (
    Voucher, VoucherStatus, Plan, Router, Customer, CustomerStatus,
    PaymentMethod, ProvisioningAttemptEntrypoint, ProvisioningAttemptSource,
    RouterAuthMethod, ConnectionType
)
from app.services.hotspot_provisioning import (
    build_hotspot_payload,
    get_or_create_provisioning_attempt,
    log_provisioning_event,
    provision_hotspot_customer,
    schedule_provisioning_attempt,
    serialize_delivery_attempt,
)
from app.services.reseller_payments import record_customer_payment
from app.services.mikrotik_api import normalize_mac_address

logger = logging.getLogger(__name__)


def generate_voucher_code() -> str:
    """Generate a cryptographically random 8-digit voucher code in XXXX-XXXX format."""
    digits = ''.join(str(secrets.randbelow(10)) for _ in range(8))
    return f"{digits[:4]}-{digits[4:]}"


async def generate_vouchers(
    db: AsyncSession,
    plan_id: int,
    user_id: int,
    quantity: int,
    router_id: Optional[int] = None,
    expires_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Generate a batch of vouchers for a given plan.

    Returns dict with batch_id and list of generated voucher codes.
    """
    plan = await db.get(Plan, plan_id)
    if not plan:
        return {"error": "Plan not found"}
    if plan.user_id != user_id:
        return {"error": "Plan does not belong to this user"}

    if router_id:
        router = await db.get(Router, router_id)
        if not router or router.user_id != user_id:
            return {"error": "Router not found or does not belong to this user"}

    batch_id = str(uuid.uuid4())
    vouchers: List[Dict[str, Any]] = []
    max_retries = 3

    for _ in range(quantity):
        for attempt in range(max_retries):
            code = generate_voucher_code()
            existing = await db.execute(
                select(Voucher.id).where(Voucher.code == code)
            )
            if not existing.scalar_one_or_none():
                break
        else:
            return {"error": "Failed to generate unique code after retries"}

        voucher = Voucher(
            code=code,
            plan_id=plan_id,
            router_id=router_id,
            user_id=user_id,
            status=VoucherStatus.AVAILABLE,
            batch_id=batch_id,
            expires_at=expires_at,
        )
        db.add(voucher)
        vouchers.append({
            "code": code,
            "plan_name": plan.name,
            "price": plan.price,
            "speed": plan.speed,
            "duration": f"{plan.duration_value} {plan.duration_unit.value}",
        })

    await db.commit()

    return {
        "batch_id": batch_id,
        "quantity": len(vouchers),
        "plan_name": plan.name,
        "price": plan.price,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "vouchers": vouchers,
    }


async def verify_voucher(db: AsyncSession, code: str) -> Dict[str, Any]:
    """Verify a voucher code is valid without redeeming it. Returns plan info."""
    code = code.strip().upper() if not code.strip()[0].isdigit() else code.strip()

    result = await db.execute(
        select(Voucher)
        .options(selectinload(Voucher.plan))
        .where(Voucher.code == code)
    )
    voucher = result.scalar_one_or_none()

    if not voucher:
        return {"valid": False, "error": "Voucher code not found"}

    if voucher.status == VoucherStatus.REDEEMED:
        return {"valid": False, "error": "Voucher has already been used"}

    if voucher.status == VoucherStatus.DISABLED:
        return {"valid": False, "error": "Voucher has been disabled"}

    if voucher.status == VoucherStatus.EXPIRED:
        return {"valid": False, "error": "Voucher has expired"}

    if voucher.expires_at and voucher.expires_at <= datetime.utcnow():
        voucher.status = VoucherStatus.EXPIRED
        await db.commit()
        return {"valid": False, "error": "Voucher has expired"}

    plan = voucher.plan
    return {
        "valid": True,
        "code": voucher.code,
        "plan_name": plan.name,
        "price": plan.price,
        "speed": plan.speed,
        "duration": f"{plan.duration_value} {plan.duration_unit.value}",
        "router_id": voucher.router_id,
    }


async def redeem_voucher(
    db: AsyncSession,
    code: str,
    mac_address: str,
    router_id: int,
) -> Dict[str, Any]:
    """
    Redeem a voucher code. Provisions the customer on the router
    using the appropriate method (DIRECT_API or RADIUS).
    """
    code = code.strip()

    result = await db.execute(
        select(Voucher)
        .options(selectinload(Voucher.plan))
        .where(Voucher.code == code)
    )
    voucher = result.scalar_one_or_none()

    if not voucher:
        return {"success": False, "error": "Voucher code not found"}

    if voucher.status != VoucherStatus.AVAILABLE:
        status_messages = {
            VoucherStatus.REDEEMED: "Voucher has already been used",
            VoucherStatus.DISABLED: "Voucher has been disabled",
            VoucherStatus.EXPIRED: "Voucher has expired",
        }
        return {"success": False, "error": status_messages.get(voucher.status, "Voucher is not available")}

    if voucher.expires_at and voucher.expires_at <= datetime.utcnow():
        voucher.status = VoucherStatus.EXPIRED
        await db.commit()
        return {"success": False, "error": "Voucher has expired"}

    if voucher.router_id and voucher.router_id != router_id:
        return {"success": False, "error": "This voucher is not valid for this hotspot"}

    # Load router
    router_result = await db.execute(
        select(Router).where(Router.id == router_id)
    )
    router = router_result.scalar_one_or_none()
    if not router:
        return {"success": False, "error": "Router not found"}

    plan = voucher.plan
    normalized_mac = normalize_mac_address(mac_address)

    # Find or create customer (scoped to reseller to match unique constraint)
    cust_result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.mac_address == normalized_mac, Customer.user_id == voucher.user_id)
    )
    customer = cust_result.scalar_one_or_none()

    if customer:
        customer.plan_id = plan.id
        customer.router_id = router_id
        customer.user_id = voucher.user_id
        await db.flush()
    else:
        customer = Customer(
            name=f"Voucher-{code}",
            phone="",
            mac_address=normalized_mac,
            status=CustomerStatus.INACTIVE,
            plan_id=plan.id,
            user_id=voucher.user_id,
            router_id=router_id,
        )
        db.add(customer)
        await db.flush()

    # Record payment
    days_paid_for = _duration_to_days(plan.duration_value, plan.duration_unit.value)
    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=voucher.user_id,
        amount=float(plan.price),
        payment_method=PaymentMethod.CASH,
        days_paid_for=days_paid_for,
        payment_reference=f"VOUCHER-{code}",
        notes=f"Voucher redemption. Batch: {voucher.batch_id}",
        duration_value=plan.duration_value,
        duration_unit=plan.duration_unit.value,
    )

    # Reload customer after payment recorded (expiry is now set)
    await db.refresh(customer)

    # Mark voucher as redeemed
    voucher.status = VoucherStatus.REDEEMED
    voucher.redeemed_by = customer.id
    voucher.redeemed_at = datetime.utcnow()
    await db.commit()

    # Provision based on connection type and router auth method
    if plan.connection_type == ConnectionType.PPPOE:
        return await _provision_pppoe(db, customer, plan, router, code)

    auth_method = getattr(router, "auth_method", None)
    use_radius = auth_method == RouterAuthMethod.RADIUS if auth_method else False

    if use_radius:
        return await _provision_radius(db, customer, plan, router)
    else:
        return await _provision_direct_api(db, customer, plan, router, code, payment.id)


async def _provision_radius(
    db: AsyncSession,
    customer: Customer,
    plan: Plan,
    router: Router,
) -> Dict[str, Any]:
    """Provision customer via RADIUS."""
    from app.services.radius_provisioning import RadiusProvisioning

    provisioning = RadiusProvisioning(db)
    radius_result = await provisioning.provision_hotspot_user(
        customer_id=customer.id,
        mac_address=customer.mac_address,
        phone=customer.phone,
        plan_speed=plan.speed,
        plan_duration_value=plan.duration_value,
        plan_duration_unit=plan.duration_unit.value,
        router_id=router.id,
        existing_expiry=customer.expiry,
    )

    if radius_result.get("success"):
        customer.status = CustomerStatus.ACTIVE
        customer.expiry = datetime.fromisoformat(radius_result["expiry"])
        customer.pending_update_data = json.dumps({
            "auth_method": "RADIUS",
            "radius_username": radius_result["username"],
            "radius_password": radius_result["password"],
        })
        await db.commit()

        return {
            "success": True,
            "customer_id": customer.id,
            "auth_method": "RADIUS",
            "radius_username": radius_result["username"],
            "radius_password": radius_result["password"],
            "expiry": radius_result["expiry"],
            "plan_name": plan.name,
            "message": "Voucher redeemed. Use credentials to login.",
        }
    else:
        return {
            "success": False,
            "error": radius_result.get("error", "RADIUS provisioning failed"),
        }


async def _provision_direct_api(
    db: AsyncSession,
    customer: Customer,
    plan: Plan,
    router: Router,
    code: str,
    payment_id: int,
) -> Dict[str, Any]:
    """Provision customer via MikroTik direct API (bypass mode)."""
    hotspot_payload = build_hotspot_payload(
        customer,
        plan,
        router,
        comment=f"Voucher {code} redeemed for {customer.name}",
    )
    attempt = await get_or_create_provisioning_attempt(
        db,
        customer_id=customer.id,
        router_id=router.id,
        mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        source_pk=payment_id,
        external_reference=code,
        entrypoint=ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API,
    )
    await schedule_provisioning_attempt(db, attempt)
    await db.commit()

    await log_provisioning_event(
        customer_id=customer.id,
        router_id=router.id,
        mac_address=customer.mac_address,
        action="voucher_direct_api",
        status="scheduled",
        details=f"Queued after voucher {code} redemption for router {router.ip_address}",
        attempt_id=attempt.id,
    )

    asyncio.create_task(
        provision_hotspot_customer(
            customer.id,
            router.id,
            hotspot_payload,
            "voucher_direct_api",
            attempt.id,
        )
    )

    return {
        "success": True,
        "customer_id": customer.id,
        "attempt_id": attempt.id,
        "auth_method": "DIRECT_API",
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "plan_name": plan.name,
        "delivery": serialize_delivery_attempt(attempt),
        "message": "Voucher redeemed. Internet access is being provisioned.",
    }


async def _provision_pppoe(
    db: AsyncSession,
    customer: Customer,
    plan: Plan,
    router: Router,
    code: str,
) -> Dict[str, Any]:
    """Provision customer via PPPoE secret on MikroTik."""
    from app.services.pppoe_provisioning import call_pppoe_provision, build_pppoe_payload

    if not customer.pppoe_username or not customer.pppoe_password:
        return {
            "success": False,
            "error": "Customer does not have PPPoE credentials. Register with PPPoE username/password first.",
        }

    pppoe_payload = build_pppoe_payload(customer, router)
    asyncio.create_task(call_pppoe_provision(pppoe_payload))

    return {
        "success": True,
        "customer_id": customer.id,
        "auth_method": "PPPOE",
        "pppoe_username": customer.pppoe_username,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "plan_name": plan.name,
        "message": "Voucher redeemed. PPPoE access is being provisioned.",
    }


async def expire_stale_vouchers(db: AsyncSession) -> int:
    """Mark all vouchers past their expires_at as EXPIRED. Returns count updated."""
    result = await db.execute(
        update(Voucher)
        .where(
            Voucher.status == VoucherStatus.AVAILABLE,
            Voucher.expires_at != None,
            Voucher.expires_at <= datetime.utcnow(),
        )
        .values(status=VoucherStatus.EXPIRED)
    )
    await db.commit()
    return result.rowcount


def _duration_to_days(value: int, unit: str) -> int:
    unit = unit.upper()
    if unit == "MINUTES":
        return max(1, value // (24 * 60))
    elif unit == "HOURS":
        return max(1, value // 24)
    return value

"""
Companion Device Pairing API

Allows hotspot customers to pair browserless devices (Smart TVs, consoles, IoT)
by entering the device's MAC address from their phone. The phone acts as the
companion that authorizes the TV's MAC on MikroTik via the existing provisioning
pipeline.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DevicePairing,
    DeviceType,
    MpesaTransaction,
    MpesaTransactionStatus,
    PaymentMethod,
    Plan,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    Router,
    RouterAuthMethod,
    User,
    Voucher,
    VoucherStatus,
)
from app.services.hotspot_provisioning import (
    build_hotspot_payload,
    get_or_create_provisioning_attempt,
    get_recent_delivery_attempt_for_customer,
    log_provisioning_event,
    provision_hotspot_customer,
    schedule_provisioning_attempt,
    serialize_delivery_attempt,
)
from app.services.mikrotik_api import MikroTikAPI
from app.services.reseller_payments import record_customer_payment

logger = logging.getLogger(__name__)

router = APIRouter(tags=["device-pairing"])


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------

class DevicePairAndPayRequest(BaseModel):
    device_mac: str = Field(..., description="MAC address of the device to pair (e.g. AA:BB:CC:DD:EE:FF)")
    owner_phone: str = Field(..., description="Phone number of the device owner (for payment / lookup)")
    plan_id: int
    router_id: int
    device_name: Optional[str] = Field(None, description="Friendly name like 'Living Room TV'")
    device_type: str = Field("tv", description="Device type: tv, console, laptop, iot, other")
    payment_method: str = Field("mobile_money", description="mobile_money or cash")
    payment_reference: Optional[str] = None
    owner_name: Optional[str] = None


class DevicePairVoucherRequest(BaseModel):
    device_mac: str
    voucher_code: str
    router_id: int
    device_name: Optional[str] = None
    device_type: str = Field("tv")


class DeviceReconnectRequest(BaseModel):
    device_mac: str
    router_id: int
    owner_phone: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_device_mac(mac: str) -> str | None:
    """
    Validate and normalize a MAC address from user input.
    Accepts: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF
    Returns normalized MAC or None if invalid.
    """
    import re
    clean = re.sub(r'[:\-\.\s]', '', mac.strip().upper())
    if len(clean) != 12 or not re.fullmatch(r'[0-9A-F]{12}', clean):
        return None
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def _device_type_value(dt) -> str:
    """Safely get the string value from a DeviceType that may be enum or plain str."""
    return dt.value if hasattr(dt, "value") else str(dt)


def _parse_device_type(value: str) -> DeviceType:
    try:
        return DeviceType(value.lower())
    except ValueError:
        return DeviceType.OTHER


def _duration_to_days(duration_value: int, duration_unit: str) -> int:
    unit = duration_unit.upper()
    if unit == "MINUTES":
        return max(1, duration_value // 1440)
    if unit == "HOURS":
        return max(1, duration_value // 24)
    return duration_value


async def _validate_router_and_plan(db: AsyncSession, router_id: int, plan_id: int):
    """Load and validate router + plan, return (router, plan, user_id) or raise."""
    router_obj = (await db.execute(select(Router).where(Router.id == router_id))).scalar_one_or_none()
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    user_id = router_obj.user_id
    if user_id:
        owner_sub = (await db.execute(
            select(User.subscription_status).where(User.id == user_id)
        )).one_or_none()
        if owner_sub:
            sub_val = owner_sub[0].value if hasattr(owner_sub[0], "value") else owner_sub[0]
            if sub_val not in ("active", "trial"):
                raise HTTPException(
                    status_code=503,
                    detail="This service is temporarily unavailable. Please contact your ISP.",
                )

    plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    if plan.user_id != user_id:
        raise HTTPException(status_code=400, detail="Plan does not belong to this router's owner")
    if plan.connection_type != ConnectionType.HOTSPOT:
        raise HTTPException(status_code=400, detail="Selected plan is not a hotspot plan")

    return router_obj, plan, user_id


async def _get_or_create_device_customer(
    db: AsyncSession,
    normalized_mac: str,
    user_id: int,
    router_id: int,
    plan_id: int,
    phone: str,
    name: Optional[str],
) -> Customer:
    """Find existing customer by device MAC or create a new one."""
    result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.mac_address == normalized_mac, Customer.user_id == user_id)
    )
    customer = result.scalar_one_or_none()

    if customer:
        customer.plan_id = plan_id
        customer.router_id = router_id
        customer.phone = phone
        if name:
            customer.name = name
        await db.flush()
    else:
        customer_name = name or f"Device {normalized_mac[-8:]}"
        customer = Customer(
            name=customer_name,
            phone=phone,
            mac_address=normalized_mac,
            status=CustomerStatus.INACTIVE,
            plan_id=plan_id,
            user_id=user_id,
            router_id=router_id,
        )
        db.add(customer)
        await db.flush()

    return customer


async def _create_or_update_pairing(
    db: AsyncSession,
    customer_id: int,
    device_mac: str,
    router_id: int,
    plan_id: int,
    device_name: Optional[str],
    device_type: DeviceType,
    expires_at: Optional[datetime] = None,
) -> DevicePairing:
    """Upsert a device pairing record."""
    result = await db.execute(
        select(DevicePairing).where(
            DevicePairing.device_mac == device_mac,
            DevicePairing.router_id == router_id,
        )
    )
    pairing = result.scalar_one_or_none()

    if pairing:
        pairing.customer_id = customer_id
        pairing.plan_id = plan_id
        pairing.device_name = device_name or pairing.device_name
        pairing.device_type = device_type
        pairing.is_active = True
        pairing.expires_at = expires_at
    else:
        pairing = DevicePairing(
            customer_id=customer_id,
            device_mac=device_mac,
            device_name=device_name,
            device_type=device_type,
            router_id=router_id,
            plan_id=plan_id,
            is_active=True,
            expires_at=expires_at,
        )
        db.add(pairing)

    await db.flush()
    return pairing


def _serialize_pairing(p: DevicePairing) -> dict:
    return {
        "id": p.id,
        "customer_id": p.customer_id,
        "device_mac": p.device_mac,
        "device_name": p.device_name,
        "device_type": p.device_type.value if hasattr(p.device_type, "value") else p.device_type,
        "router_id": p.router_id,
        "plan_id": p.plan_id,
        "is_active": p.is_active,
        "provisioned_at": p.provisioned_at.isoformat() if p.provisioned_at else None,
        "expires_at": p.expires_at.isoformat() if p.expires_at else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/public/device/pair-and-pay")
async def pair_device_and_pay(
    request: DevicePairAndPayRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Pair a companion device (TV, console, etc.) and initiate payment.
    The device gets its own plan and Customer record. Works with both
    mobile_money (M-Pesa STK push) and cash payment methods.
    """
    try:
        normalized_mac = _validate_device_mac(request.device_mac)
        if not normalized_mac:
            raise HTTPException(status_code=400, detail="Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF")

        if not request.owner_phone or len(request.owner_phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")

        try:
            payment_method_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            valid = [m.value for m in PaymentMethod]
            raise HTTPException(status_code=400, detail=f"Invalid payment method. Must be one of: {', '.join(valid)}")

        device_type = _parse_device_type(request.device_type)
        router_obj, plan, user_id = await _validate_router_and_plan(db, request.router_id, request.plan_id)

        customer = await _get_or_create_device_customer(
            db, normalized_mac, user_id, request.router_id,
            request.plan_id, request.owner_phone, request.owner_name,
        )

        pairing = await _create_or_update_pairing(
            db, customer.id, normalized_mac, request.router_id,
            request.plan_id, request.device_name, device_type,
        )

        if payment_method_enum == PaymentMethod.MOBILE_MONEY:
            from app.services.mpesa import initiate_stk_push
            from app.services.payment_gateway import resolve_router_payment_method, initiate_customer_payment

            reference = f"DEVICE-{customer.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

            owner_info = (await db.execute(
                select(User.mpesa_shortcode, User.business_name, User.organization_name)
                .where(User.id == user_id)
            )).one_or_none()
            owner_shortcode = owner_info.mpesa_shortcode if owner_info else None
            account_reference = (owner_info.business_name or owner_info.organization_name) if owner_info else None

            router_pm = await resolve_router_payment_method(db, request.router_id)

            if router_pm:
                gw_result = await initiate_customer_payment(
                    db=db,
                    payment_method=router_pm,
                    customer=customer,
                    router=router_obj,
                    phone=request.owner_phone,
                    amount=float(plan.price),
                    reference=reference,
                    plan_name=plan.name,
                    account_reference=account_reference,
                )
                customer.status = CustomerStatus.PENDING
                await db.commit()
                await db.refresh(customer)
            else:
                stk_response = await initiate_stk_push(
                    phone_number=request.owner_phone,
                    amount=float(plan.price),
                    reference=reference,
                    shortcode=owner_shortcode,
                    account_reference=account_reference,
                )
                mpesa_txn = MpesaTransaction(
                    checkout_request_id=stk_response.checkout_request_id,
                    merchant_request_id=stk_response.merchant_request_id,
                    phone_number=request.owner_phone,
                    amount=float(plan.price),
                    reference=reference,
                    customer_id=customer.id,
                    status=MpesaTransactionStatus.pending,
                )
                db.add(mpesa_txn)
                customer.status = CustomerStatus.PENDING
                await db.commit()
                await db.refresh(customer)

            return {
                "success": True,
                "customer_id": customer.id,
                "pairing_id": pairing.id,
                "device_mac": normalized_mac,
                "device_name": request.device_name,
                "device_type": device_type.value,
                "status": customer.status.value,
                "message": "STK Push sent to phone. Device will be activated after payment.",
            }

        else:
            # Cash or other non-mobile-money methods: provision immediately
            days = _duration_to_days(plan.duration_value, plan.duration_unit.value)
            await record_customer_payment(
                db=db,
                customer_id=customer.id,
                reseller_id=user_id,
                amount=float(plan.price),
                payment_method=payment_method_enum,
                days_paid_for=days,
                payment_reference=request.payment_reference,
                duration_value=plan.duration_value,
                duration_unit=plan.duration_unit.value,
            )
            customer.status = CustomerStatus.ACTIVE
            await db.commit()
            await db.refresh(customer)

            # Trigger provisioning based on router auth method
            auth_method = getattr(router_obj, "auth_method", None)
            use_radius = auth_method == RouterAuthMethod.RADIUS if auth_method else False

            if use_radius:
                from app.services.radius_provisioning import RadiusProvisioning
                provisioning = RadiusProvisioning(db)
                radius_result = await provisioning.provision_hotspot_user(
                    customer_id=customer.id,
                    mac_address=normalized_mac,
                    phone=request.owner_phone,
                    plan_speed=plan.speed,
                    plan_duration_value=plan.duration_value,
                    plan_duration_unit=plan.duration_unit.value,
                    router_id=router_obj.id,
                    existing_expiry=customer.expiry,
                )
                if radius_result.get("success"):
                    customer.expiry = datetime.fromisoformat(radius_result["expiry"])
                    pairing.provisioned_at = datetime.utcnow()
                    pairing.expires_at = customer.expiry
                    await db.commit()
                    return {
                        "success": True,
                        "customer_id": customer.id,
                        "pairing_id": pairing.id,
                        "device_mac": normalized_mac,
                        "device_type": device_type.value,
                        "auth_method": "RADIUS",
                        "radius_username": radius_result.get("username"),
                        "radius_password": radius_result.get("password"),
                        "expiry": radius_result.get("expiry"),
                        "message": "Device paired and provisioned via RADIUS.",
                    }
                else:
                    return {"success": False, "error": radius_result.get("error", "RADIUS provisioning failed")}
            else:
                comment = f"TV/Device: {request.device_name or device_type.value} | MAC: {normalized_mac} | Owner: {request.owner_phone}"
                hotspot_payload = build_hotspot_payload(customer, plan, router_obj, comment=comment)
                attempt = await get_or_create_provisioning_attempt(
                    db,
                    customer_id=customer.id,
                    router_id=router_obj.id,
                    mac_address=normalized_mac,
                    source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                    source_pk=customer.id,
                    external_reference=f"device-pair-{pairing.id}",
                    entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
                )
                await schedule_provisioning_attempt(db, attempt)
                pairing.provisioned_at = datetime.utcnow()
                pairing.expires_at = customer.expiry
                await db.commit()

                await log_provisioning_event(
                    customer_id=customer.id,
                    router_id=router_obj.id,
                    mac_address=normalized_mac,
                    action="device_pairing_provision",
                    status="scheduled",
                    details=f"Device pairing #{pairing.id} for {request.device_name or device_type.value}",
                    attempt_id=attempt.id,
                )

                asyncio.create_task(
                    provision_hotspot_customer(
                        customer.id, router_obj.id, hotspot_payload,
                        "device_pairing", attempt.id,
                    )
                )

                return {
                    "success": True,
                    "customer_id": customer.id,
                    "pairing_id": pairing.id,
                    "device_mac": normalized_mac,
                    "device_type": device_type.value,
                    "attempt_id": attempt.id,
                    "expiry": customer.expiry.isoformat() if customer.expiry else None,
                    "message": "Device paired and provisioning started.",
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in device pair-and-pay")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Device pairing failed: {str(e)}")


@router.post("/api/public/device/pair-voucher")
async def pair_device_with_voucher(
    request: DevicePairVoucherRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Pair a companion device using a voucher code.
    Reuses the existing voucher redemption logic with the device's MAC.
    """
    try:
        normalized_mac = _validate_device_mac(request.device_mac)
        if not normalized_mac:
            raise HTTPException(status_code=400, detail="Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF")
        device_type = _parse_device_type(request.device_type)

        from app.services.voucher_service import voucher_lookup_candidates
        candidates = voucher_lookup_candidates(request.voucher_code)
        if not candidates:
            raise HTTPException(status_code=400, detail="Voucher code is required")
        result = await db.execute(
            select(Voucher).options(selectinload(Voucher.plan)).where(Voucher.code.in_(candidates))
        )
        voucher = result.scalar_one_or_none()

        if not voucher:
            raise HTTPException(status_code=404, detail="Voucher code not found")
        code = voucher.code
        if voucher.status != VoucherStatus.AVAILABLE:
            status_msgs = {
                VoucherStatus.REDEEMED: "Voucher has already been used",
                VoucherStatus.DISABLED: "Voucher has been disabled",
                VoucherStatus.EXPIRED: "Voucher has expired",
            }
            raise HTTPException(status_code=400, detail=status_msgs.get(voucher.status, "Voucher is not available"))
        if voucher.expires_at and voucher.expires_at <= datetime.utcnow():
            voucher.status = VoucherStatus.EXPIRED
            await db.commit()
            raise HTTPException(status_code=400, detail="Voucher has expired")
        if voucher.router_id and voucher.router_id != request.router_id:
            raise HTTPException(status_code=400, detail="This voucher is not valid for this hotspot")

        router_obj = (await db.execute(select(Router).where(Router.id == request.router_id))).scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")

        plan = voucher.plan

        customer = await _get_or_create_device_customer(
            db, normalized_mac, voucher.user_id, request.router_id,
            plan.id, "", request.device_name,
        )

        pairing = await _create_or_update_pairing(
            db, customer.id, normalized_mac, request.router_id,
            plan.id, request.device_name, device_type,
        )

        # Record payment
        days = _duration_to_days(plan.duration_value, plan.duration_unit.value)
        payment = await record_customer_payment(
            db=db,
            customer_id=customer.id,
            reseller_id=voucher.user_id,
            amount=float(plan.price),
            payment_method=PaymentMethod.CASH,
            days_paid_for=days,
            payment_reference=f"VOUCHER-{code}",
            notes=f"Device pairing voucher. Batch: {voucher.batch_id}",
            duration_value=plan.duration_value,
            duration_unit=plan.duration_unit.value,
        )
        await db.refresh(customer)

        # Mark voucher redeemed
        voucher.status = VoucherStatus.REDEEMED
        voucher.redeemed_by = customer.id
        voucher.redeemed_at = datetime.utcnow()
        await db.commit()

        # Provision
        auth_method = getattr(router_obj, "auth_method", None)
        use_radius = auth_method == RouterAuthMethod.RADIUS if auth_method else False

        if use_radius:
            from app.services.radius_provisioning import RadiusProvisioning
            provisioning = RadiusProvisioning(db)
            radius_result = await provisioning.provision_hotspot_user(
                customer_id=customer.id,
                mac_address=normalized_mac,
                phone=customer.phone,
                plan_speed=plan.speed,
                plan_duration_value=plan.duration_value,
                plan_duration_unit=plan.duration_unit.value,
                router_id=router_obj.id,
                existing_expiry=customer.expiry,
            )
            if radius_result.get("success"):
                customer.expiry = datetime.fromisoformat(radius_result["expiry"])
                pairing.provisioned_at = datetime.utcnow()
                pairing.expires_at = customer.expiry
                await db.commit()
                return {
                    "success": True,
                    "customer_id": customer.id,
                    "pairing_id": pairing.id,
                    "device_mac": normalized_mac,
                    "auth_method": "RADIUS",
                    "radius_username": radius_result.get("username"),
                    "radius_password": radius_result.get("password"),
                    "message": "Device paired with voucher via RADIUS.",
                }
            return {"success": False, "error": radius_result.get("error", "RADIUS provisioning failed")}
        else:
            comment = f"TV/Device: {request.device_name or device_type.value} | Voucher: {code} | MAC: {normalized_mac}"
            hotspot_payload = build_hotspot_payload(customer, plan, router_obj, comment=comment)
            attempt = await get_or_create_provisioning_attempt(
                db,
                customer_id=customer.id,
                router_id=router_obj.id,
                mac_address=normalized_mac,
                source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                source_pk=payment.id,
                external_reference=code,
                entrypoint=ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API,
            )
            await schedule_provisioning_attempt(db, attempt)
            pairing.provisioned_at = datetime.utcnow()
            pairing.expires_at = customer.expiry
            await db.commit()

            await log_provisioning_event(
                customer_id=customer.id,
                router_id=router_obj.id,
                mac_address=normalized_mac,
                action="device_pairing_voucher",
                status="scheduled",
                details=f"Device pairing #{pairing.id} via voucher {code}",
                attempt_id=attempt.id,
            )

            asyncio.create_task(
                provision_hotspot_customer(
                    customer.id, router_obj.id, hotspot_payload,
                    "device_pairing_voucher", attempt.id,
                )
            )

            return {
                "success": True,
                "customer_id": customer.id,
                "pairing_id": pairing.id,
                "device_mac": normalized_mac,
                "device_type": device_type.value,
                "attempt_id": attempt.id,
                "plan_name": plan.name,
                "expiry": customer.expiry.isoformat() if customer.expiry else None,
                "message": "Device paired with voucher. Provisioning started.",
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in device pair-voucher")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Device voucher pairing failed: {str(e)}")


@router.get("/api/public/device/status/{router_id}/{mac}")
async def get_device_status(
    router_id: int,
    mac: str,
    db: AsyncSession = Depends(get_db),
):
    """Check the pairing and provisioning status of a device."""
    try:
        normalized_mac = _validate_device_mac(mac)
        if not normalized_mac:
            raise HTTPException(status_code=400, detail="Invalid MAC address format")

        pairing_result = await db.execute(
            select(DevicePairing)
            .where(DevicePairing.device_mac == normalized_mac, DevicePairing.router_id == router_id)
        )
        pairing = pairing_result.scalar_one_or_none()

        if not pairing:
            return {"paired": False, "message": "Device is not paired on this router"}

        # Get the customer record for delivery status
        customer = (await db.execute(
            select(Customer).options(selectinload(Customer.plan))
            .where(Customer.id == pairing.customer_id)
        )).scalar_one_or_none()

        attempt = None
        if customer:
            attempt = await get_recent_delivery_attempt_for_customer(db, customer.id)

        return {
            "paired": True,
            "pairing": _serialize_pairing(pairing),
            "customer": {
                "id": customer.id,
                "name": customer.name,
                "status": customer.status.value,
                "expiry": customer.expiry.isoformat() if customer.expiry else None,
                "plan_name": customer.plan.name if customer.plan else None,
            } if customer else None,
            "delivery": serialize_delivery_attempt(attempt),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error getting device status")
        raise HTTPException(status_code=500, detail=f"Failed to get device status: {str(e)}")


@router.get("/api/public/device/paired/{router_id}/{phone}")
async def list_paired_devices(
    router_id: int,
    phone: str,
    db: AsyncSession = Depends(get_db),
):
    """List all paired devices for a phone number on a specific router."""
    try:
        # Find all customers with this phone under this router's reseller
        router_obj = (await db.execute(select(Router).where(Router.id == router_id))).scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")

        # Get device pairings where the customer's phone matches
        result = await db.execute(
            select(DevicePairing)
            .join(Customer, DevicePairing.customer_id == Customer.id)
            .where(
                Customer.phone == phone,
                DevicePairing.router_id == router_id,
                DevicePairing.is_active == True,
            )
            .order_by(DevicePairing.created_at.desc())
        )
        pairings = result.scalars().all()

        return {
            "phone": phone,
            "router_id": router_id,
            "devices": [_serialize_pairing(p) for p in pairings],
            "count": len(pairings),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error listing paired devices")
        raise HTTPException(status_code=500, detail=f"Failed to list devices: {str(e)}")


@router.delete("/api/public/device/unpair/{pairing_id}")
async def unpair_device(
    pairing_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Deactivate a paired device. Marks pairing as inactive and removes
    the hotspot user + ip-binding from MikroTik.
    """
    try:
        pairing = (await db.execute(
            select(DevicePairing).where(DevicePairing.id == pairing_id)
        )).scalar_one_or_none()

        if not pairing:
            raise HTTPException(status_code=404, detail="Pairing not found")

        if not pairing.is_active:
            return {"success": True, "message": "Device is already unpaired"}

        pairing.is_active = False
        await db.flush()

        # Try to remove from MikroTik (sync API, must run off event loop)
        router_obj = (await db.execute(select(Router).where(Router.id == pairing.router_id))).scalar_one_or_none()
        removal_result = None
        if router_obj:
            def _remove_device_from_router_sync() -> str:
                username = pairing.device_mac.replace(":", "")
                api = MikroTikAPI(
                    router_obj.ip_address, router_obj.username,
                    router_obj.password, router_obj.port,
                    timeout=15, connect_timeout=5,
                )
                if not api.connect():
                    return "router_unreachable"
                try:
                    users = api.send_command("/ip/hotspot/user/print")
                    if users.get("success") and users.get("data"):
                        for u in users["data"]:
                            if u.get("name", "").upper() == username.upper():
                                api.send_command("/ip/hotspot/user/remove", {".id": u[".id"]})
                                break

                    bindings = api.send_command("/ip/hotspot/ip-binding/print")
                    if bindings.get("success") and bindings.get("data"):
                        mac_normalized = pairing.device_mac.upper()
                        for b in bindings["data"]:
                            binding_mac = b.get("mac-address", "").upper()
                            if binding_mac == mac_normalized:
                                api.send_command("/ip/hotspot/ip-binding/remove", {".id": b[".id"]})
                                break

                    return "removed_from_router"
                finally:
                    api.disconnect()

            try:
                removal_result = await asyncio.to_thread(_remove_device_from_router_sync)
            except Exception as ex:
                logger.warning("Failed to remove device %s from router: %s", pairing.device_mac, ex)
                removal_result = f"removal_error: {str(ex)}"

        await db.commit()

        return {
            "success": True,
            "pairing_id": pairing_id,
            "device_mac": pairing.device_mac,
            "router_cleanup": removal_result,
            "message": "Device unpaired successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error unpairing device")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to unpair device: {str(e)}")


@router.post("/api/public/device/reconnect")
async def reconnect_device(
    request: DeviceReconnectRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Re-provision a paired device. Useful when the TV loses access
    but still has an active subscription.
    """
    try:
        normalized_mac = _validate_device_mac(request.device_mac)
        if not normalized_mac:
            raise HTTPException(status_code=400, detail="Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF")

        pairing = (await db.execute(
            select(DevicePairing).where(
                DevicePairing.device_mac == normalized_mac,
                DevicePairing.router_id == request.router_id,
                DevicePairing.is_active == True,
            )
        )).scalar_one_or_none()

        if not pairing:
            raise HTTPException(status_code=404, detail="No active pairing found for this device on this router")

        customer = (await db.execute(
            select(Customer).options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == pairing.customer_id)
        )).scalar_one_or_none()

        if not customer:
            raise HTTPException(status_code=404, detail="Customer record not found")

        # Verify ownership
        if customer.phone != request.owner_phone:
            raise HTTPException(status_code=403, detail="Phone number does not match the device owner")

        if customer.status != CustomerStatus.ACTIVE:
            raise HTTPException(status_code=400, detail="Customer subscription is not active. Please purchase a new plan.")

        if customer.expiry and customer.expiry < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Subscription has expired. Please purchase a new plan.")

        router_obj = (await db.execute(select(Router).where(Router.id == request.router_id))).scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")

        plan = customer.plan
        if not plan:
            raise HTTPException(status_code=400, detail="No plan associated with this device")

        auth_method = getattr(router_obj, "auth_method", None)
        use_radius = auth_method == RouterAuthMethod.RADIUS if auth_method else False

        if use_radius:
            from app.services.radius_provisioning import RadiusProvisioning
            provisioning = RadiusProvisioning(db)
            radius_result = await provisioning.provision_hotspot_user(
                customer_id=customer.id,
                mac_address=normalized_mac,
                phone=customer.phone,
                plan_speed=plan.speed,
                plan_duration_value=plan.duration_value,
                plan_duration_unit=plan.duration_unit.value,
                router_id=router_obj.id,
                existing_expiry=customer.expiry,
            )
            if radius_result.get("success"):
                return {
                    "success": True,
                    "customer_id": customer.id,
                    "device_mac": normalized_mac,
                    "auth_method": "RADIUS",
                    "radius_username": radius_result.get("username"),
                    "radius_password": radius_result.get("password"),
                    "message": "Device reconnected via RADIUS.",
                }
            return {"success": False, "error": radius_result.get("error", "RADIUS reconnection failed")}
        else:
            comment = f"Reconnect: {pairing.device_name or _device_type_value(pairing.device_type)} | MAC: {normalized_mac}"
            hotspot_payload = build_hotspot_payload(customer, plan, router_obj, comment=comment)

            await log_provisioning_event(
                customer_id=customer.id,
                router_id=router_obj.id,
                mac_address=normalized_mac,
                action="device_reconnect",
                status="started",
                details=f"Device reconnect for pairing #{pairing.id}",
            )

            asyncio.create_task(
                provision_hotspot_customer(
                    customer.id, router_obj.id, hotspot_payload,
                    "device_reconnect",
                )
            )

            return {
                "success": True,
                "customer_id": customer.id,
                "device_mac": normalized_mac,
                "device_name": pairing.device_name,
                "message": "Device reconnection started. It should come online shortly.",
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error reconnecting device")
        raise HTTPException(status_code=500, detail=f"Device reconnection failed: {str(e)}")

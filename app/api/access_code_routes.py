"""One code per purchase, valid on every device the plan covers.

A customer types the same code on each device they want online:

* a voucher (unused vouchers start the plan; redeemed ones add devices),
* the access code shown after an M-Pesa payment, or
* the M-Pesa receipt of that payment.

The plan's ``max_shared_users`` caps how many devices can hold it at once.
At the cap, the new device is refused and shown the plan's devices so the
owner can remove one; nobody is kicked automatically. The same code is the
only credential that can list or remove the plan's devices.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.device_pairing import (
    ACCESS_CODE_FRESH_VOUCHER,
    ACCESS_CODE_ONE_TIME_SHARE,
    DeviceLimitReached,
    ShareSubscriptionCodeRedeemRequest,
    _owner_from_access_code_or_401,
    _parse_device_type,
    _share_subscription_for_owner,
    _validate_device_mac,
    disconnect_shared_pairing,
    list_subscription_devices,
    load_access_code_owner,
    redeem_share_subscription_code,
    release_main_device,
    resolve_access_code,
    shareable_code_for_owner,
)
from app.db.database import get_db
from app.db.models import Customer, CustomerStatus, Router
from app.services.code_attempt_limiter import check_code_attempts, record_code_failure
from app.services.mikrotik_api import normalize_mac_address
from app.services.router_helpers import get_router_by_id
from app.services.subscription_sharing import (
    max_devices_for_customer,
    sharing_enabled_for_customer,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["access-code"])

# Values the portal falls back to when the router didn't pass the client MAC.
# Provisioning one of these would burn a device slot on a device that isn't real.
PLACEHOLDER_MACS = {"AA:BB:CC:DD:EE:FF", "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


class AccessCodeRedeemRequest(BaseModel):
    code: str = Field(..., description="Voucher, access code, or M-Pesa receipt")
    router_id: int
    mac_address: str = Field(..., description="MAC of the device that should get online")
    device_name: Optional[str] = None
    device_type: str = Field("other")


class AccessCodeDevicesRequest(BaseModel):
    code: str
    router_id: int
    mac_address: Optional[str] = Field(None, description="Requesting device, to mark it in the list")


class AccessCodeDisconnectRequest(BaseModel):
    code: str
    router_id: int
    pairing_id: Optional[int] = None
    main_device: bool = False
    mac_address: Optional[str] = None


def _plan_summary(owner: Customer) -> dict:
    plan = owner.plan
    return {
        "plan_name": plan.name if plan else None,
        "expires_at": owner.expiry.isoformat() if owner.expiry else None,
        "sharing_enabled": sharing_enabled_for_customer(owner, plan),
        "max_devices": max_devices_for_customer(owner, plan),
    }


def _optional_mac(value: Optional[str]) -> Optional[str]:
    return _validate_device_mac(value) if value else None


async def redeem_code_on_device(
    db: AsyncSession,
    *,
    code: str,
    router_obj: Router,
    normalized_mac: str,
    background_tasks: BackgroundTasks,
    device_name: Optional[str] = None,
    device_type: str = "other",
) -> dict:
    """Put the plan behind ``code`` on this device. Raises HTTPException."""
    from app.api.public_routes import restore_customer_on_device

    router_id = router_obj.id
    if normalized_mac in PLACEHOLDER_MACS:
        raise HTTPException(
            status_code=400,
            detail="We couldn't identify this device. Reconnect to the WiFi and open the login page again.",
        )

    resolved = await resolve_access_code(db, code=code, router_id=router_id)
    if resolved is None:
        record_code_failure(router_id, normalized_mac)
        raise HTTPException(status_code=404, detail="We couldn't find that code. Check it and try again.")
    if resolved.error:
        raise HTTPException(status_code=400, detail=resolved.error)

    if resolved.kind == ACCESS_CODE_FRESH_VOUCHER:
        from app.services.voucher_service import redeem_voucher

        voucher_code = resolved.voucher.code
        result = await redeem_voucher(db, voucher_code, normalized_mac, router_id)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Redemption failed"))
        owner = await db.get(Customer, result.get("customer_id")) if result.get("customer_id") else None
        if owner:
            await db.refresh(owner, ["plan"])
        return {
            **result,
            **(_plan_summary(owner) if owner else {}),
            "outcome": "plan_started",
            "access_code": voucher_code,
        }

    if resolved.kind == ACCESS_CODE_ONE_TIME_SHARE:
        result = await redeem_share_subscription_code(
            ShareSubscriptionCodeRedeemRequest(
                code=code,
                router_id=router_id,
                device_mac=normalized_mac,
                device_name=device_name,
                device_type=device_type,
            ),
            db,
        )
        return {**result, "outcome": "device_added"}

    owner = await load_access_code_owner(
        db,
        owner_customer_id=resolved.owner_customer_id,
        router_id=router_id,
    )
    summary = _plan_summary(owner)
    owner_mac = normalize_mac_address(owner.mac_address) if owner.mac_address else None

    lookup_key = f"code:{resolved.kind}"

    # The plan's own device, or a plan not bound to a device yet.
    if owner_mac is None or owner_mac == normalized_mac:
        result = await restore_customer_on_device(
            db,
            customer=owner,
            router_obj=router_obj,
            normalized_mac=normalized_mac,
            lookup_key=lookup_key,
            background_tasks=background_tasks,
        )
        return {**result, **summary, "outcome": "main_device"}

    # A single-device purchase belongs to the device it is bound to. Entered on
    # another device it is only moved when its own device is not in use (a
    # phone whose randomized MAC rotated, a replaced phone); see
    # app/services/device_entitlements.py. If this device already holds its
    # own purchase on the same number, that one is restored instead.
    if not summary["sharing_enabled"]:
        own = await _own_purchase_on_device(
            db, owner=owner, router_id=router_id, normalized_mac=normalized_mac,
        )
        if own is not None:
            await db.refresh(own, ["plan"])
            result = await restore_customer_on_device(
                db,
                customer=own,
                router_obj=router_obj,
                normalized_mac=normalized_mac,
                lookup_key=lookup_key,
                background_tasks=background_tasks,
            )
            return {**result, **_plan_summary(own), "outcome": "main_device"}

        from app.api.public_routes import _move_idle_purchase_or_refuse

        result = await _move_idle_purchase_or_refuse(
            db,
            candidates=[owner],
            router_obj=router_obj,
            normalized_mac=normalized_mac,
            lookup_key=lookup_key,
            background_tasks=background_tasks,
        )
        return {**result, **summary, "outcome": "main_device"}

    return await add_device_to_owner_plan(
        db,
        owner=owner,
        router_id=router_id,
        normalized_mac=normalized_mac,
        device_type=device_type,
        device_name=device_name,
        summary=summary,
    )


async def _own_purchase_on_device(
    db: AsyncSession,
    *,
    owner: Customer,
    router_id: int,
    normalized_mac: str,
) -> Optional[Customer]:
    """A live purchase on the owner's number that is bound to this device."""
    from app.services.customer_grace import access_floor, has_access_time

    now = datetime.utcnow()
    rows = (
        await db.execute(
            select(Customer).where(
                Customer.phone == owner.phone,
                Customer.router_id == router_id,
                Customer.id != owner.id,
                Customer.subscription_owner_id.is_(None),
                Customer.status == CustomerStatus.ACTIVE,
                Customer.expiry.isnot(None),
                Customer.expiry > access_floor(now),
                Customer.mac_address.isnot(None),
            )
        )
    ).scalars().all()
    for row in rows:
        if normalize_mac_address(row.mac_address) == normalized_mac and has_access_time(row, now):
            return row
    return None


async def add_device_to_owner_plan(
    db: AsyncSession,
    *,
    owner: Customer,
    router_id: int,
    normalized_mac: str,
    device_type: str = "other",
    device_name: Optional[str] = None,
    summary: Optional[dict] = None,
) -> dict:
    """Add ``normalized_mac`` as another device on ``owner``'s plan.

    Shared by the code path above and phone-number reconnect. When every slot
    is taken this raises 409 ``device_limit_reached`` with the plan's devices,
    which the captive portal shows so the customer can remove one.
    """
    summary = summary if summary is not None else _plan_summary(owner)
    owner_id = owner.id
    try:
        result = await _share_subscription_for_owner(
            db,
            owner=owner,
            router_id=router_id,
            normalized_mac=normalized_mac,
            device_type=_parse_device_type(device_type),
            device_name=device_name,
            device_owner_phone=None,
            device_owner_name=None,
        )
    except DeviceLimitReached as exc:
        await db.rollback()
        owner = await load_access_code_owner(db, owner_customer_id=owner_id, router_id=router_id)
        devices = await list_subscription_devices(db, owner=owner, current_mac=normalized_mac)
        raise HTTPException(
            status_code=409,
            detail={
                "error": "device_limit_reached",
                "message": (
                    f"This plan is already in use on {exc.max_shared_users} devices. "
                    "Remove one to connect this device."
                ),
                "max_devices": exc.max_shared_users,
                "devices": devices,
            },
        )

    return {
        **result,
        **summary,
        "outcome": "device_added",
        "message": "You're connected. This device now shares the plan.",
    }


@router.post("/api/public/access-code/redeem")
async def redeem_access_code(
    request: AccessCodeRedeemRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Enter a voucher / access code / M-Pesa receipt on this device."""
    normalized_mac = _validate_device_mac(request.mac_address or "")
    if not normalized_mac:
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    if not (request.code or "").strip():
        raise HTTPException(status_code=400, detail="Please enter your code")

    check_code_attempts(request.router_id, normalized_mac)
    router_obj = await get_router_by_id(db, request.router_id)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found")

    try:
        return await redeem_code_on_device(
            db,
            code=request.code,
            router_obj=router_obj,
            normalized_mac=normalized_mac,
            background_tasks=background_tasks,
            device_name=request.device_name,
            device_type=request.device_type,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[ACCESS-CODE] Redeem failed on router %s", request.router_id)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Could not connect this device: {e}")


@router.post("/api/public/access-code/devices")
async def list_access_code_devices(
    request: AccessCodeDevicesRequest,
    db: AsyncSession = Depends(get_db),
):
    """List the devices using a plan. The code itself is the credential."""
    current_mac = _optional_mac(request.mac_address)
    owner, resolved = await _owner_from_access_code_or_401(
        db,
        access_code=request.code,
        router_id=request.router_id,
        device_key=current_mac,
    )
    devices = await list_subscription_devices(db, owner=owner, current_mac=current_mac)
    share_code = await shareable_code_for_owner(db, owner=owner, resolved=resolved)
    summary = _plan_summary(owner)
    await db.commit()
    return {
        "success": True,
        **summary,
        "share_code": share_code,
        "devices": devices,
        "device_count": len(devices),
        "available_devices": max(0, summary["max_devices"] - len(devices)),
    }


@router.post("/api/public/access-code/disconnect")
async def disconnect_access_code_device(
    request: AccessCodeDisconnectRequest,
    db: AsyncSession = Depends(get_db),
):
    """Remove one device from a plan so another can use the slot."""
    current_mac = _optional_mac(request.mac_address)
    owner, _resolved = await _owner_from_access_code_or_401(
        db,
        access_code=request.code,
        router_id=request.router_id,
        device_key=current_mac,
    )
    try:
        if request.main_device:
            return await release_main_device(db, owner=owner)
        if request.pairing_id is None:
            raise HTTPException(status_code=400, detail="Choose a device to remove")
        return await disconnect_shared_pairing(
            db,
            owner=owner,
            router_id=request.router_id,
            pairing_id=request.pairing_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[ACCESS-CODE] Disconnect failed on router %s", request.router_id)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Could not remove the device: {e}")

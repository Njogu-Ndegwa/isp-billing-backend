"""Devices on one customer's subscription, for the reseller dashboard.

A hotspot customer is one device (one MAC). Extra devices are companion
``Customer`` rows pointing at the paying owner through
``subscription_owner_id``, each with a ``DevicePairing`` (see
``app/api/device_pairing.py``). Until now only the customer could add or remove
them, from the captive portal with an access code. These endpoints let the
reseller do the same from the customer page, list every device with its live
state, and give one customer more (or fewer) devices than their plan allows.

Router I/O follows Database Session Discipline: the session is committed
before any RouterOS call, and nothing is held open across it.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.access_code_routes import add_device_to_owner_plan
from app.api.device_pairing import (
    _validate_device_mac,
    disconnect_shared_pairing,
    list_subscription_devices,
)
from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    FupAction,
    RouterAuthMethod,
    UserRole,
)
from app.services.auth import get_current_user, verify_token
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.services import realtime_state
from app.services.fup import apply_throttle
from app.services.pppoe_provisioning import (
    active_fup_restriction,
    build_pppoe_payload,
    call_pppoe_provision,
)
from app.services.router_concurrency import run_with_guard
from app.services.subscription_sharing import (
    max_devices_for_customer,
    max_shared_users_for_plan,
)
from app.services.usage_tracking import pooled_period_usage_bytes

logger = logging.getLogger(__name__)

router = APIRouter(tags=["customer-devices"])

# Reseller-set per-customer ceiling; the plan form already caps plans at 50.
MAX_DEVICES_OVERRIDE_LIMIT = 50
_LIVE_ACQUIRE_TIMEOUT_SECONDS = 3.0


class AddDeviceRequest(BaseModel):
    mac_address: str
    device_name: Optional[str] = Field(default=None, max_length=100)
    device_type: str = "other"


class DeviceLimitRequest(BaseModel):
    # None clears the override so the plan's allowance applies again.
    max_devices: Optional[int] = Field(default=None, ge=1, le=MAX_DEVICES_OVERRIDE_LIMIT)


def _mb(value: int) -> float:
    return round((value or 0) / (1024 * 1024), 2)


async def _load_owner_scoped(db: AsyncSession, customer_id: int, user) -> Customer:
    """The paying customer behind ``customer_id`` (itself, or its owner)."""
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == customer_id)
    )
    if user.role != UserRole.ADMIN:
        stmt = stmt.where(Customer.user_id == user.id)
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not accessible")
    if customer.subscription_owner_id:
        owner = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .where(Customer.id == customer.subscription_owner_id)
            )
        ).scalar_one_or_none()
        if owner:
            return owner
    return customer


def _require_hotspot(owner: Customer) -> None:
    plan = owner.plan
    if not plan or plan.connection_type != ConnectionType.HOTSPOT:
        raise HTTPException(
            status_code=400,
            detail="Devices are managed here for hotspot customers. PPPoE devices are listed under Connection.",
        )


def _hotspot_hosts_for_macs_sync(router_info: dict, macs: list[str]) -> dict:
    """Read the router's hotspot host entry for each MAC (one query per MAC)."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=10, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        hosts: dict[str, dict] = {}
        for mac in macs:
            result = api.send_command_optimized(
                "/ip/hotspot/host/print",
                proplist=["mac-address", "address", "authorized", "bypassed", "uptime", "idle-time"],
                query=f"?mac-address={mac}",
            )
            if not result.get("success"):
                return {"error": result.get("error") or "host lookup failed"}
            for row in result.get("data", []):
                row_mac = normalize_mac_address(row.get("mac-address", ""))
                if row_mac:
                    hosts[row_mac] = row
        return {"success": True, "hosts": hosts}
    except Exception as exc:  # router I/O must never fail the page
        logger.warning("Device host lookup failed on %s: %s", router_info.get("ip"), exc)
        return {"error": str(exc)}
    finally:
        api.disconnect()


def _live_from_push(router_id: int, mac: str) -> Optional[dict]:
    device = realtime_state.get_device_live(router_id, mac)
    if device is None:
        return None
    return {
        "online": device.online,
        "ip": device.ip or None,
        "uptime": device.uptime or None,
        "idle_time": device.idle_time or None,
        "rate_down_bps": device.rate_down_bps,
        "rate_up_bps": device.rate_up_bps,
        "source": "push",
    }


def _live_from_host(row: Optional[dict]) -> dict:
    if not row:
        return {"online": False, "ip": None, "uptime": None, "idle_time": None,
                "rate_down_bps": None, "rate_up_bps": None, "source": "router"}
    authorized = str(row.get("authorized", "")).lower() == "true"
    bypassed = str(row.get("bypassed", "")).lower() == "true"
    return {
        "online": authorized or bypassed,
        "ip": row.get("address") or None,
        "uptime": row.get("uptime") or None,
        "idle_time": row.get("idle-time") or None,
        "rate_down_bps": None,
        "rate_up_bps": None,
        "source": "router",
    }


async def _devices_payload(db: AsyncSession, owner: Customer, *, live: bool = True) -> dict:
    plan = owner.plan
    devices = await list_subscription_devices(db, owner=owner)

    # Device rows carry MACs; map them to their customer rows for usage.
    macs = [d["device_mac"] for d in devices]
    customer_by_mac: dict[str, Customer] = {}
    if macs:
        rows = (
            await db.execute(
                select(Customer).where(
                    Customer.user_id == owner.user_id,
                    Customer.mac_address.in_(macs),
                )
            )
        ).scalars().all()
        customer_by_mac = {normalize_mac_address(c.mac_address): c for c in rows if c.mac_address}

    # Every device's open usage period in one query (latest wins per customer).
    device_ids = {c.id for c in customer_by_mac.values()} | {owner.id}
    open_periods: dict[int, CustomerUsagePeriod] = {}
    for period in (
        await db.execute(
            select(CustomerUsagePeriod)
            .where(
                CustomerUsagePeriod.customer_id.in_(device_ids),
                CustomerUsagePeriod.closed_at.is_(None),
            )
            .order_by(CustomerUsagePeriod.period_start.asc())
        )
    ).scalars().all():
        open_periods[period.customer_id] = period

    for device in devices:
        device_customer = customer_by_mac.get(device["device_mac"])
        device["customer_id"] = device_customer.id if device_customer else None
        period = open_periods.get(device_customer.id) if device_customer else None
        device["period_usage_mb"] = _mb(period.total_bytes) if period else None
        device["live"] = None

    owner_period = open_periods.get(owner.id)
    pooled_mb = _mb(await pooled_period_usage_bytes(db, owner, owner_period)) if owner_period else None

    router_obj = owner.router
    router_id = owner.router_id
    use_radius = bool(router_obj and router_obj.auth_method == RouterAuthMethod.RADIUS)
    router_info = (
        {
            "ip": router_obj.ip_address,
            "username": router_obj.username,
            "password": router_obj.password,
            "port": router_obj.port,
        }
        if router_obj and not use_radius
        else None
    )
    payload = {
        "owner_customer_id": owner.id,
        "owner_name": owner.name,
        "router_id": router_id,
        "plan_name": plan.name if plan else None,
        "plan_max_devices": max_shared_users_for_plan(plan),
        "max_devices_override": owner.max_devices_override,
        "max_devices": max_devices_for_customer(owner, plan),
        "subscription_active": bool(
            owner.status == CustomerStatus.ACTIVE
            and owner.expiry
            and owner.expiry > datetime.utcnow()
        ),
        "expiry": owner.expiry.isoformat() if owner.expiry else None,
        "pooled_usage_mb": pooled_mb,
        "live_source": None,
        "live_error": None,
        "devices": devices,
    }
    await db.commit()  # nothing held open across router I/O below

    if not live or not devices or not router_id:
        return payload

    if realtime_state.get_router_live(router_id) is not None:
        for device in devices:
            device["live"] = _live_from_push(router_id, device["device_mac"])
        payload["live_source"] = "push"
        return payload

    if router_info is None:
        return payload
    result = await run_with_guard(
        router_id,
        _hotspot_hosts_for_macs_sync,
        router_info,
        [d["device_mac"] for d in devices],
        acquire_timeout_seconds=_LIVE_ACQUIRE_TIMEOUT_SECONDS,
        timeout_seconds=20,
    )
    if result.get("success"):
        hosts = result.get("hosts", {})
        for device in devices:
            device["live"] = _live_from_host(hosts.get(device["device_mac"]))
        payload["live_source"] = "router"
    else:
        payload["live_error"] = result.get("error") or "Router did not answer"
    return payload


@router.get("/api/customers/{customer_id}/devices")
async def list_customer_devices(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Every device on the customer's subscription, with live state."""
    user = await get_current_user(token, db)
    owner = await _load_owner_scoped(db, customer_id, user)
    _require_hotspot(owner)
    return await _devices_payload(db, owner)


@router.post("/api/customers/{customer_id}/devices")
async def add_customer_device(
    customer_id: int,
    body: AddDeviceRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Add a device (by MAC) to the customer's plan from the dashboard."""
    user = await get_current_user(token, db)
    owner = await _load_owner_scoped(db, customer_id, user)
    _require_hotspot(owner)

    normalized_mac = _validate_device_mac(body.mac_address or "")
    if not normalized_mac:
        raise HTTPException(status_code=400, detail="Enter a valid MAC address, e.g. AA:BB:CC:DD:EE:FF")
    if owner.mac_address and normalize_mac_address(owner.mac_address) == normalized_mac:
        raise HTTPException(status_code=400, detail="That is already this customer's main device")
    if not (owner.status == CustomerStatus.ACTIVE and owner.expiry and owner.expiry > datetime.utcnow()):
        raise HTTPException(
            status_code=400,
            detail="The customer's plan is not active. Record a payment first, then add devices.",
        )
    if max_devices_for_customer(owner, owner.plan) < 2:
        raise HTTPException(
            status_code=400,
            detail="This customer's plan allows 1 device. Raise their device limit first.",
        )

    result = await add_device_to_owner_plan(
        db,
        owner=owner,
        router_id=owner.router_id,
        normalized_mac=normalized_mac,
        device_type=body.device_type,
        device_name=(body.device_name or "").strip() or None,
    )
    return {
        "success": True,
        "message": "Device added. It connects as soon as the router has it.",
        "customer_id": result.get("customer_id"),
        "pairing_id": result.get("pairing_id"),
        "device_mac": normalized_mac,
    }


@router.delete("/api/customers/{customer_id}/devices/{pairing_id}")
async def remove_customer_device(
    customer_id: int,
    pairing_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Take one extra device off the customer's plan and off the router."""
    user = await get_current_user(token, db)
    owner = await _load_owner_scoped(db, customer_id, user)
    _require_hotspot(owner)
    return await disconnect_shared_pairing(
        db, owner=owner, router_id=owner.router_id, pairing_id=pairing_id,
    )


@router.put("/api/customers/{customer_id}/device-limit")
async def set_customer_device_limit(
    customer_id: int,
    body: DeviceLimitRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Give this one customer a different number of devices than their plan.

    Lowering the limit below the devices already added does not kick anyone
    now; the extras are released at the next renewal, newest first, exactly
    as when a plan's allowance shrinks.
    """
    user = await get_current_user(token, db)
    owner = await _load_owner_scoped(db, customer_id, user)
    owner.max_devices_override = body.max_devices
    response = {
        "success": True,
        "owner_customer_id": owner.id,
        "max_devices_override": owner.max_devices_override,
        "max_devices": max_devices_for_customer(owner, owner.plan),
        "plan_max_devices": max_shared_users_for_plan(owner.plan),
        "router_update": None,
    }

    # PPPoE: the limit lives on the router (the secret's profile), so apply it
    # now for a paying customer. Their devices reconnect once to pick it up.
    pppoe_payload = None
    fup_hold = None
    if (
        owner.plan
        and owner.plan.connection_type == ConnectionType.PPPOE
        and owner.pppoe_username
        and owner.pppoe_password
        and owner.router is not None
        and owner.status == CustomerStatus.ACTIVE
    ):
        # Re-provisioning would put the secret back on its normal profile and
        # quietly lift a FUP throttle or block applied this period.
        fup_hold = await active_fup_restriction(db, owner.id)
        if fup_hold is None:
            pppoe_payload = build_pppoe_payload(owner, owner.router)
            # Down to one device on a shared-speed plan: the login leaves the
            # shared queue for a normal per-session one.
            if pppoe_payload.get("shared_speed"):
                pppoe_payload["clear_shared_speed_queue"] = True
    await db.commit()

    if fup_hold == FupAction.THROTTLE:
        # Re-apply the throttle: its profile carries the new device limit.
        result = await apply_throttle(db, owner, owner.plan)
        response["router_update"] = "failed" if result.get("error") else "applied"
    elif fup_hold == FupAction.BLOCK:
        # Blocked over the cap: leave the router alone; renewal applies it.
        response["router_update"] = "deferred"
    elif pppoe_payload is not None:
        result = await call_pppoe_provision(pppoe_payload)
        response["router_update"] = "applied" if result and result.get("success") else "failed"
    return response

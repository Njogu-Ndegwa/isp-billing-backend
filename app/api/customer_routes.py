from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, text, and_, or_
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timedelta
import asyncio
import re
import secrets
import string

from app.db.database import get_db
from app.db.models import (
    Router, Customer, Plan, CustomerStatus, ConnectionType,
    CustomerPayment, PaymentMethod, PaymentStatus, DurationUnit,
    Payment, CustomerRating, ProvisioningLog, MpesaTransaction,
    UserBandwidthUsage, Voucher, CustomerUsagePeriod, UsageCapWatchState,
    ProvisioningAttempt, ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource, DevicePairing, ReconnectionAttempt,
    FapshiTransaction, ZenoPayTransaction, MtnMomoTransaction,
    CustomerUsageBucket, C2BTransaction, UnmatchedC2BPayment, SmsMessage,
)
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.pppoe_provisioning import (
    call_pppoe_provision, call_pppoe_remove, provision_pppoe_customer,
    build_pppoe_payload, build_pppoe_remove_payload,
)
from app.services.hotspot_provisioning import (
    build_hotspot_payload,
    get_or_create_provisioning_attempt,
    schedule_provisioning_attempt,
)
from app.services.account_numbers import generate_account_number
from app.services.customer_grace import (
    MAX_GRACE_MINUTES,
    effective_expiry,
    grace_fields,
    has_access_time,
    normalize_grace_minutes,
    renewal_expiry,
)
from app.services.customer_events import record_customer_event
from app.services.mikrotik_api import normalize_mac_address
from app.services.static_ip import (
    INVALID_STATIC_IP_MESSAGE,
    customer_should_have_access,
    inspect_static_customer,
    normalize_pin_mac,
    normalize_static_ip,
    static_ips_in_use,
    provision_static_customer,
    remove_static_customer_from_router,
)

import logging

logger = logging.getLogger(__name__)

# Strong references to detached grace-restore tasks (asyncio keeps only weak ones).
_grace_restore_tasks: set[asyncio.Task] = set()


def _generated_pppoe_username(phone: str) -> Optional[str]:
    """Default PPPoE username for a phone number: ``pppoe_`` + its digits.

    Only digits are kept, so a phone pasted with a tab, newline, dash,
    bracket or "+" can never leak whitespace or punctuation into the router
    login. Returns None when the phone has no digits at all.
    """
    digits = re.sub(r"\D", "", phone or "")
    return f"pppoe_{digits}" if digits else None


async def _pppoe_username_taken(
    db: AsyncSession, username: str, exclude_customer_id: Optional[int] = None
) -> bool:
    """True if any customer already uses this PPPoE username.

    There is no unique constraint on the column, so duplicates can exist;
    ``.first()`` keeps the check a clean yes/no instead of raising
    MultipleResultsFound (a 500) when they do.
    """
    stmt = select(Customer.id).where(Customer.pppoe_username == username)
    if exclude_customer_id is not None:
        stmt = stmt.where(Customer.id != exclude_customer_id)
    result = await db.execute(stmt.limit(1))
    return result.first() is not None


def _generate_pppoe_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _normalize_pin_mac(value: Optional[str]) -> Optional[str]:
    try:
        return normalize_pin_mac(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _validate_static_ip(
    db: AsyncSession, raw_ip: Optional[str], router_id: Optional[int], exclude_customer_id: Optional[int] = None,
) -> str:
    """A static-IP plan needs a valid, unused IPv4 on its router."""
    ip = normalize_static_ip(raw_ip)
    if not ip:
        raise HTTPException(status_code=400, detail=INVALID_STATIC_IP_MESSAGE)
    taken = (await static_ips_in_use(db, router_id, exclude_customer_id)).get(ip)
    if taken is not None:
        raise HTTPException(
            status_code=409,
            detail=f"{ip} is already assigned to {taken[1] or 'another customer'} on this router",
        )
    return ip


# Fields an edit can change, as shown in the customer audit log. Passwords are
# never written to the log, only the fact that one changed.
_AUDITED_FIELDS = (
    ("name", "name"), ("phone", "phone"), ("plan_id", "plan"), ("router_id", "router"),
    ("mac_address", "MAC"), ("pppoe_username", "PPPoE username"),
    ("static_ip", "static IP"), ("expiry", "expiry"),
)


def _audit_snapshot(customer) -> dict:
    snap = {field: getattr(customer, field) for field, _ in _AUDITED_FIELDS}
    snap["pppoe_password"] = customer.pppoe_password
    return snap


def _audit_changes(before: dict, after: dict, names: dict) -> tuple[list[str], dict]:
    """Human summary plus a {field: [old, new]} map of what an edit changed."""
    def show(field, value):
        if value is None or value == "":
            return "(none)"
        if field in ("plan_id", "router_id"):
            return names.get((field, value)) or f"#{value}"
        if isinstance(value, datetime):
            # Shown to resellers, who read every other time in EAT.
            from app.core.local_time import to_local
            return to_local(value).strftime("%Y-%m-%d %H:%M EAT")
        return str(value)

    parts, changes = [], {}
    for field, label in _AUDITED_FIELDS:
        old, new = before.get(field), after.get(field)
        if old != new:
            parts.append(f"{label} {show(field, old)} -> {show(field, new)}")
            changes[field] = [show(field, old), show(field, new)]
    if before.get("pppoe_password") != after.get("pppoe_password"):
        parts.append("PPPoE password changed")
        changes["pppoe_password"] = ["***", "***"]
    return parts, changes


# ---------------------------------------------------------------------------
# Customer vs. visitor tiering (data hygiene, presentation-only)
#
# Many `customers` rows are devices/people who never paid (portal signups,
# abandoned STK pushes, location captures). To reduce reseller confusion the
# list endpoints expose a computed `has_paid` flag and a `tier` label
# ("customer" if they ever paid or currently hold paid time, else "visitor").
# This is purely additive: no schema change, no row mutation, and no effect
# on revenue/financial calculations.
# ---------------------------------------------------------------------------

VALID_CUSTOMER_TIERS = {"all", "customer", "visitor"}


def _has_paid_condition(now: datetime):
    """SQL boolean expression: this customer has at least one COMPLETED
    customer_payments row OR currently-active paid time (expiry in the
    future). Evaluated in the same SELECT as the customer list — one query,
    no per-row lookups (small DB pool; see Database Session Discipline)."""
    completed_payment_exists = (
        select(CustomerPayment.id)
        .where(
            CustomerPayment.customer_id == Customer.id,
            CustomerPayment.status == PaymentStatus.COMPLETED,
        )
        .exists()
    )
    return or_(
        completed_payment_exists,
        and_(Customer.expiry.isnot(None), Customer.expiry > now),
    )


def _validate_tier(tier: Optional[str]) -> str:
    normalized = (tier or "all").lower()
    if normalized not in VALID_CUSTOMER_TIERS:
        raise HTTPException(
            status_code=400,
            detail="Invalid tier filter; expected one of: all, customer, visitor",
        )
    return normalized


router = APIRouter(tags=["customers"])


class CustomerRegisterRequest(BaseModel):
    name: str
    phone: str
    plan_id: int
    router_id: int
    mac_address: Optional[str] = None
    pppoe_username: Optional[str] = None
    pppoe_password: Optional[str] = None
    static_ip: Optional[str] = None
    # Static-IP plans: the device MAC to pin the IP to (optional; learned
    # automatically the first time the device is seen while paid up).
    static_mac: Optional[str] = None


class UpdateLocationRequest(BaseModel):
    latitude: float
    longitude: float


@router.post("/api/customers/register")
async def register_customer_api(
    request: CustomerRegisterRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Register a new customer"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id, Plan.user_id == user.id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Validate router exists
        router_stmt = select(Router).where(Router.id == request.router_id, Router.user_id == user.id)
        router_result = await db.execute(router_stmt)
        router_obj = router_result.scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")
        
        static_ip = request.static_ip
        static_mac = None
        mac_address = request.mac_address
        if plan.connection_type == ConnectionType.STATIC_IP:
            static_ip = await _validate_static_ip(db, request.static_ip, request.router_id)
            # A static customer must never carry the hotspot identity column:
            # every hotspot payment/cleanup path keys on it.
            static_mac = _normalize_pin_mac(request.static_mac or request.mac_address)
            mac_address = None

        # Check if customer with MAC already exists
        if mac_address:
            existing_customer_stmt = select(Customer).where(Customer.mac_address == mac_address)
            existing_result = await db.execute(existing_customer_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Customer with this MAC address already exists")
        
        phone = request.phone.strip()
        pppoe_username = request.pppoe_username.strip() if request.pppoe_username else None
        pppoe_password = request.pppoe_password

        if plan.connection_type == ConnectionType.PPPOE:
            if not pppoe_username:
                pppoe_username = _generated_pppoe_username(phone)
                if not pppoe_username:
                    raise HTTPException(
                        status_code=400,
                        detail="Enter a PPPoE username, or a phone number with digits to generate one",
                    )
            if not pppoe_password:
                pppoe_password = _generate_pppoe_password()

            if await _pppoe_username_taken(db, pppoe_username):
                raise HTTPException(
                    status_code=409,
                    detail=f"PPPoE username '{pppoe_username}' already exists"
                )

        account_number = await generate_account_number(db)

        # Create customer
        customer = Customer(
            name=request.name,
            phone=phone,
            mac_address=mac_address,
            pppoe_username=pppoe_username,
            pppoe_password=pppoe_password,
            static_ip=static_ip,
            static_mac=static_mac,
            status=CustomerStatus.INACTIVE,
            plan_id=request.plan_id,
            user_id=user.id,
            router_id=request.router_id,
            account_number=account_number,
        )

        db.add(customer)
        await db.commit()
        await db.refresh(customer)

        logger.info(
            f"Customer registered: {customer.id} (account_number={customer.account_number}) "
            f"by user {user.id}"
        )
        await record_customer_event(
            customer.id, "customer_created",
            f"Customer registered on plan {plan.name}, router {router_obj.name}",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )

        if customer.pppoe_username:
            # Opt-in login-details SMS; checks the reseller's settings itself
            # and runs after this request's transaction is committed.
            from app.services.customer_notifications import spawn_welcome_message

            spawn_welcome_message(customer.id)

        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "pppoe_username": customer.pppoe_username,
            "static_ip": customer.static_ip,
            "static_mac": customer.static_mac,
            "status": customer.status.value,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "user_id": customer.user_id,
            "account_number": customer.account_number,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "created_at": customer.created_at.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering customer: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register customer: {str(e)}")


class CustomerEditRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    plan_id: Optional[int] = None
    router_id: Optional[int] = None
    mac_address: Optional[str] = None
    pppoe_username: Optional[str] = None
    pppoe_password: Optional[str] = None
    static_ip: Optional[str] = None
    static_mac: Optional[str] = None
    expiry: Optional[datetime] = None


@router.put("/api/customers/{customer_id}")
async def edit_customer(
    customer_id: int,
    request: CustomerEditRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Edit an existing customer's details including hotspot/PPPoE fields."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        target_plan = customer.plan
        if request.plan_id is not None:
            plan_stmt = select(Plan).where(Plan.id == request.plan_id, Plan.user_id == user.id)
            plan_result = await db.execute(plan_stmt)
            target_plan = plan_result.scalar_one_or_none()
            if not target_plan:
                raise HTTPException(status_code=404, detail="Plan not found")

        if request.router_id is not None:
            router_stmt = select(Router).where(Router.id == request.router_id, Router.user_id == user.id)
            router_result = await db.execute(router_stmt)
            if not router_result.scalar_one_or_none():
                raise HTTPException(status_code=404, detail="Router not found")

        if request.mac_address is not None and request.mac_address != customer.mac_address:
            mac_stmt = select(Customer).where(
                Customer.mac_address == request.mac_address,
                Customer.user_id == user.id,
                Customer.id != customer_id,
            )
            mac_result = await db.execute(mac_stmt)
            if mac_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Another customer with this MAC address already exists")

        normalized_pppoe_username = (
            request.pppoe_username.strip()
            if request.pppoe_username is not None
            else None
        )
        normalized_pppoe_password = (
            request.pppoe_password.strip()
            if request.pppoe_password is not None
            else None
        )
        target_is_pppoe = bool(
            target_plan and target_plan.connection_type == ConnectionType.PPPOE
        )

        if target_is_pppoe and request.pppoe_username is not None and not normalized_pppoe_username:
            raise HTTPException(status_code=400, detail="PPPoE username cannot be blank")
        if target_is_pppoe and request.pppoe_password is not None and not normalized_pppoe_password:
            raise HTTPException(status_code=400, detail="PPPoE password cannot be blank")

        if (
            request.pppoe_username is not None
            and normalized_pppoe_username
            and normalized_pppoe_username != customer.pppoe_username
        ):
            if await _pppoe_username_taken(
                db, normalized_pppoe_username, exclude_customer_id=customer_id
            ):
                raise HTTPException(
                    status_code=409,
                    detail=f"PPPoE username '{normalized_pppoe_username}' already exists",
                )

        was_static = bool(customer.plan and customer.plan.connection_type == ConnectionType.STATIC_IP)
        target_is_static = bool(target_plan and target_plan.connection_type == ConnectionType.STATIC_IP)
        old_static_ip = normalize_static_ip(customer.static_ip)
        old_static_mac = customer.static_mac
        old_static_router = customer.router
        if was_static != target_is_static:
            raise HTTPException(status_code=400, detail="Changing to or from Static IP requires deleting the old customer first, so the old router access is removed safely.")
        if target_is_static:
            target_router_id = request.router_id if request.router_id is not None else customer.router_id
            if (
                request.static_ip is not None
                or not was_static
                or target_router_id != customer.router_id
            ):
                request.static_ip = await _validate_static_ip(
                    db, request.static_ip if request.static_ip is not None else customer.static_ip,
                    target_router_id, exclude_customer_id=customer.id,
                )
            if request.mac_address is not None:
                # The form's MAC field means "pin to this device" for statics.
                request.static_mac = request.mac_address
                request.mac_address = None
            if request.static_mac is not None:
                request.static_mac = _normalize_pin_mac(request.static_mac) or ""

        if target_is_static and request.static_mac == "":
            await db.commit()
            cleared = await provision_static_customer(customer.id, action="static_ip_pin", clear_pin=True)
            if not cleared.get("success"):
                raise HTTPException(status_code=503, detail="Could not reset the device pin on the router; the saved pin was kept.")

        audit_before = _audit_snapshot(customer)
        if was_static and old_static_ip and old_static_router is not None and (
            (request.router_id is not None and request.router_id != customer.router_id)
            or (request.static_ip is not None and request.static_ip != old_static_ip)
        ):
            old_creds = _router_creds(old_static_router)
            await db.commit()
            cleanup = await remove_static_customer_from_router(old_creds, old_static_ip)
            if not cleanup.get("success"):
                raise HTTPException(status_code=503, detail="Could not remove the old static-IP access; the customer was not moved. " + str(cleanup.get("error")))
        old_pppoe_username = customer.pppoe_username
        old_pppoe_password = customer.pppoe_password
        old_router_id = customer.router_id
        old_plan_id = customer.plan_id
        pppoe_changed = False
        pppoe_location_changed = False

        update_fields = request.model_dump(exclude_none=True)
        if "phone" in update_fields:
            update_fields["phone"] = update_fields["phone"].strip()
        if request.pppoe_username is not None:
            update_fields["pppoe_username"] = normalized_pppoe_username or None
        if request.pppoe_password is not None:
            update_fields["pppoe_password"] = normalized_pppoe_password or None
        if "expiry" in update_fields and update_fields["expiry"] is not None:
            update_fields["expiry"] = update_fields["expiry"].replace(tzinfo=None)
        if update_fields.get("static_mac") == "":
            update_fields["static_mac"] = None  # cleared: re-learn on next sighting
        for field, value in update_fields.items():
            setattr(customer, field, value)
        if target_is_static and not was_static:
            customer.mac_address = None

        if customer.pppoe_username and customer.status == CustomerStatus.ACTIVE:
            pppoe_changed = (
                customer.pppoe_username != old_pppoe_username
                or customer.pppoe_password != old_pppoe_password
                or customer.router_id != old_router_id
                or customer.plan_id != old_plan_id
            )
            pppoe_location_changed = (
                customer.pppoe_username != old_pppoe_username
                or customer.router_id != old_router_id
            )

        await db.commit()
        await db.refresh(customer, attribute_names=["plan", "router"])

        audit_after = _audit_snapshot(customer)
        names = {}
        if audit_before["plan_id"] != audit_after["plan_id"]:
            for plan_row in (await db.execute(select(Plan.id, Plan.name).where(
                    Plan.id.in_([audit_before["plan_id"], audit_after["plan_id"]])))).all():
                names[("plan_id", plan_row.id)] = plan_row.name
        if audit_before["router_id"] != audit_after["router_id"]:
            for router_row in (await db.execute(select(Router.id, Router.name).where(
                    Router.id.in_([audit_before["router_id"], audit_after["router_id"]])))).all():
                names[("router_id", router_row.id)] = router_row.name
        await db.commit()
        audit_parts, audit_diff = _audit_changes(audit_before, audit_after, names)
        if audit_parts:
            await record_customer_event(
                customer.id, "customer_updated", "Edited: " + "; ".join(audit_parts),
                actor=user, user_id=customer.user_id, router_id=customer.router_id,
                details={"changes": audit_diff},
            )

        if "expiry" in update_fields and not customer.pppoe_username and not target_is_static:
            # A router that removes its own expired customers holds the
            # deadline in the binding: move it later if the edit extended it.
            from app.services.expiry_tag_sync import schedule_expiry_tag_sync

            schedule_expiry_tag_sync([customer.id], "admin expiry edit")

        provision_status = None
        if (
            pppoe_changed
            and customer.router
            and customer.plan
            and customer.plan.connection_type == ConnectionType.PPPOE
        ):
            remove_payload = None
            if pppoe_location_changed and old_pppoe_username and old_router_id:
                try:
                    old_router_stmt = select(Router).where(Router.id == old_router_id)
                    old_router_result = await db.execute(old_router_stmt)
                    old_router_obj = old_router_result.scalar_one_or_none()
                    if old_router_obj:
                        remove_payload = build_pppoe_remove_payload(customer, old_router_obj)
                        remove_payload["pppoe_username"] = old_pppoe_username
                except Exception as e:
                    logger.warning(f"Failed to prepare old PPPoE secret removal during edit: {e}")

            pppoe_payload = build_pppoe_payload(customer, customer.router)
            await db.commit()
            if remove_payload:
                try:
                    await call_pppoe_remove(remove_payload)
                except Exception as e:
                    logger.warning(f"Failed to remove old PPPoE secret during edit: {e}")
            provision_result = await call_pppoe_provision(pppoe_payload)
            provision_status = "ok" if provision_result and provision_result.get("success") else "failed"

        static_status = None
        if was_static or target_is_static:
            await db.commit()
            static_status = await _sync_static_after_edit(
                customer, was_static, target_is_static,
                old_ip=old_static_ip, old_router=old_static_router,
                pin_cleared=bool(old_static_mac) and not customer.static_mac,
            )

        return {
            "success": True,
            "customer": {
                "id": customer.id,
                "name": customer.name,
                "phone": customer.phone,
                "mac_address": customer.mac_address,
                "pppoe_username": customer.pppoe_username,
                "pppoe_password": customer.pppoe_password,
                "static_ip": customer.static_ip,
                "static_mac": customer.static_mac,
                "status": customer.status.value,
                "plan_id": customer.plan_id,
                "router_id": customer.router_id,
                "expiry": customer.expiry.isoformat() if customer.expiry else None,
                "created_at": customer.created_at.isoformat() if customer.created_at else None,
                "plan": {
                    "id": customer.plan.id,
                    "name": customer.plan.name,
                    "price": customer.plan.price,
                    "connection_type": customer.plan.connection_type.value if customer.plan.connection_type else None,
                } if customer.plan else None,
                "router": {
                    "id": customer.router.id,
                    "name": customer.router.name,
                } if customer.router else None,
            },
            "pppoe_reprovisioned": provision_status,
            "static_reprovisioned": static_status,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to edit customer: {str(e)}")


def _router_creds(router_obj: Optional[Router]) -> Optional[dict]:
    if router_obj is None:
        return None
    return {
        "id": router_obj.id, "name": router_obj.name, "ip": router_obj.ip_address,
        "username": router_obj.username, "password": router_obj.password,
        "port": router_obj.port or 8728,
    }


async def _sync_static_after_edit(
    customer: Customer,
    was_static: bool,
    target_is_static: bool,
    *,
    old_ip: Optional[str],
    old_router: Optional[Router],
    pin_cleared: bool,
) -> Optional[str]:
    """Push a static customer's edit to the router (no DB session is held here)."""
    try:
        if was_static and not target_is_static:
            if old_ip and old_router is not None:
                result = await remove_static_customer_from_router(_router_creds(old_router), old_ip)
                return "ok" if result.get("success") else "failed"
            return None
        if customer.router is None:
            return None
        moved = old_router is not None and old_router.id != customer.router_id
        result = await provision_static_customer(
            customer.id,
            action="static_ip_edit",
            clear_pin=pin_cleared,
            old_ip=old_ip if (was_static and old_ip) else None,
            old_router=_router_creds(old_router) if (was_static and moved) else None,
        )
        return "ok" if result.get("success") else "failed"
    except Exception as exc:
        logger.warning("Static-IP re-sync after editing customer %s failed: %s", customer.id, exc)
        return "failed"


@router.delete("/api/customers/{customer_id}")
async def delete_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Delete a customer and all related data.

    PPPoE customers must be removed from the router before the DB row is
    deleted. If RouterOS cleanup fails, the customer is kept so the cleanup can
    be retried instead of leaving an orphaned online secret.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        customer_name = customer.name
        deprovision_result = None

        if customer.pppoe_username:
            if not customer.router:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Cannot delete PPPoE customer before router cleanup because "
                        "the customer has no router assigned. Cleanup the router "
                        "secret first or restore the router assignment."
                    ),
                )

            payload = build_pppoe_remove_payload(customer, customer.router)
            await db.commit()
            remove_result = await call_pppoe_remove(payload)
            if not remove_result or remove_result.get("error"):
                error = remove_result.get("error") if remove_result else "Unknown PPPoE cleanup error"
                logger.warning(
                    "Refusing to delete customer %s because PPPoE cleanup failed: %s",
                    customer_id,
                    error,
                )
                status_code = 503 if "connect" in error.lower() else 502
                raise HTTPException(
                    status_code=status_code,
                    detail=f"Failed to remove PPPoE user from MikroTik; customer was not deleted: {error}",
                )
            deprovision_result = "ok"

        static_ip = normalize_static_ip(customer.static_ip)
        if (
            customer.plan
            and customer.plan.connection_type == ConnectionType.STATIC_IP
            and static_ip
            and customer.router
        ):
            # Same rule as PPPoE: never delete the row while the router still
            # gives this IP free internet.
            creds = _router_creds(customer.router)
            await db.commit()
            remove_result = await remove_static_customer_from_router(creds, static_ip)
            if not remove_result or remove_result.get("error"):
                error = (remove_result or {}).get("error") or "Unknown router cleanup error"
                status_code = 503 if "connect" in error.lower() else 502
                raise HTTPException(
                    status_code=status_code,
                    detail=f"Failed to remove the static IP from MikroTik; customer was not deleted: {error}",
                )
            deprovision_result = "ok"

        # -----------------------------------------------------------------
        # Snapshot the customer name into every payment row BEFORE we null
        # out the FK, so the history UI can still show who paid.
        # -----------------------------------------------------------------
        await db.execute(
            update(CustomerPayment)
            .where(
                CustomerPayment.customer_id == customer_id,
                CustomerPayment.customer_name == None,  # noqa: E711
            )
            .values(customer_name=customer.name)
        )

        # -----------------------------------------------------------------
        # Clean up child rows before deleting the parent.
        # Rules:
        #   • Operational rows (RADIUS, bandwidth, usage periods,
        #     provisioning logs, device pairings, reconnections, ratings)
        #     — DELETE: no audit value.
        #   • CustomerPayment — SET customer_id = NULL: this is the
        #     financial ledger used by balance calculations; preserving
        #     these rows keeps total_revenue and unpaid_balance correct.
        #   • MpesaTransaction / ZenoPay / MtnMomo raw event logs — DELETE:
        #     the transactions list query filters on "customer_id IS NULL"
        #     which is visible to all users, so nulling these out would
        #     leak data across resellers. Balance is covered by
        #     CustomerPayment, so deleting these is safe.
        #   • Legacy Payment rows — NOT NULL column, deprecated, DELETE.
        # -----------------------------------------------------------------
        await db.execute(
            update(Voucher).where(Voucher.redeemed_by == customer_id).values(redeemed_by=None)
        )
        await db.execute(text(
            "DELETE FROM radius_check WHERE customer_id = :cid"
        ).bindparams(cid=customer_id))
        await db.execute(text(
            "DELETE FROM radius_reply WHERE customer_id = :cid"
        ).bindparams(cid=customer_id))
        await db.execute(delete(CustomerRating).where(CustomerRating.customer_id == customer_id))
        await db.execute(delete(UserBandwidthUsage).where(UserBandwidthUsage.customer_id == customer_id))
        await db.execute(delete(CustomerUsagePeriod).where(CustomerUsagePeriod.customer_id == customer_id))
        await db.execute(delete(CustomerUsageBucket).where(CustomerUsageBucket.customer_id == customer_id))
        await db.execute(delete(UsageCapWatchState).where(UsageCapWatchState.customer_id == customer_id))
        await db.execute(delete(ProvisioningLog).where(ProvisioningLog.customer_id == customer_id))
        await db.execute(delete(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == customer_id))
        await db.execute(delete(DevicePairing).where(DevicePairing.customer_id == customer_id))
        await db.execute(delete(ReconnectionAttempt).where(ReconnectionAttempt.customer_id == customer_id))

        # Reseller-scoped records (matched_reseller_id / assigned_reseller_id /
        # user_id): keep them, drop only the link to the deleted customer.
        await db.execute(
            update(C2BTransaction)
            .where(C2BTransaction.matched_customer_id == customer_id)
            .values(matched_customer_id=None)
        )
        await db.execute(
            update(UnmatchedC2BPayment)
            .where(UnmatchedC2BPayment.resolution_customer_id == customer_id)
            .values(resolution_customer_id=None)
        )
        await db.execute(update(SmsMessage).where(SmsMessage.customer_id == customer_id).values(customer_id=None))

        # CustomerPayment: NULL out customer FK to preserve revenue history.
        # Balance calculations read CustomerPayment, so this keeps all totals intact.
        await db.execute(
            update(CustomerPayment)
            .where(CustomerPayment.customer_id == customer_id)
            .values(customer_id=None)
        )

        # MpesaTransaction / ZenoPay / MtnMomo: DELETE these raw event-log tables.
        # Reason: the transactions list query uses "customer_id IS NULL" as a
        # catch-all that is visible to every authenticated user — setting NULL
        # would expose this customer's history to other resellers. Financial
        # accuracy is already fully covered by the CustomerPayment rows above.
        await db.execute(delete(MpesaTransaction).where(MpesaTransaction.customer_id == customer_id))
        await db.execute(delete(ZenoPayTransaction).where(ZenoPayTransaction.customer_id == customer_id))
        await db.execute(delete(MtnMomoTransaction).where(MtnMomoTransaction.customer_id == customer_id))
        await db.execute(delete(FapshiTransaction).where(FapshiTransaction.customer_id == customer_id))

        # Legacy table — NOT NULL column, table is deprecated, safe to delete
        await db.execute(delete(Payment).where(Payment.customer_id == customer_id))

        # Delete the customer first, then flush so the upcoming count queries
        # from update_reseller_financials already see N-1 customers.
        await db.delete(customer)
        await db.flush()

        from app.services.reseller_payments import update_reseller_financials
        await update_reseller_financials(db, user.id)

        await db.commit()

        logger.info(f"Customer {customer_id} ({customer_name}) deleted by user {user.id}")
        await record_customer_event(
            customer_id, "customer_deleted", f"Customer '{customer_name}' deleted",
            actor=user, user_id=user.id,
            details={"pppoe_deprovisioned": deprovision_result},
        )

        return {
            "success": True,
            "message": f"Customer '{customer_name}' deleted successfully",
            "customer_id": customer_id,
            "pppoe_deprovisioned": deprovision_result,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete customer: {str(e)}")


class CustomerGraceRequest(BaseModel):
    # 0 removes the grace period.
    grace_period_minutes: int = Field(..., ge=0, le=MAX_GRACE_MINUTES)


async def _restore_customer_access(customer_id: int) -> None:
    """Put a customer whose grace reopened their access back on the router.

    Runs detached after the grant has committed. The DB is read in one short
    session and released before any RouterOS I/O. Failures are logged only:
    the customer is ACTIVE again, so the check-in delivery and the normal
    retry machinery still bring the router in line.
    """
    from app.db.database import async_session

    try:
        async with async_session() as db:
            customer = (
                await db.execute(
                    select(Customer)
                    .options(selectinload(Customer.plan), selectinload(Customer.router))
                    .where(Customer.id == customer_id)
                )
            ).scalar_one_or_none()
            if (
                customer is None
                or customer.status != CustomerStatus.ACTIVE
                or not has_access_time(customer, datetime.utcnow())
                or customer.router is None
                or customer.plan is None
            ):
                await db.commit()
                return
            router_id = customer.router.id
            is_pppoe = customer.plan.connection_type == ConnectionType.PPPOE
            if is_pppoe and customer.pppoe_username:
                payload = build_pppoe_payload(customer, customer.router)
            elif not is_pppoe and customer.mac_address:
                payload = build_hotspot_payload(
                    customer, customer.plan, customer.router,
                    f"CID:{customer.id}|grace-period-restore",
                )
            else:
                await db.commit()
                return
            await db.commit()

        if is_pppoe:
            result = await provision_pppoe_customer(
                customer_id=customer_id,
                router_id=router_id,
                pppoe_payload=payload,
                action="grace_period_restore",
            )
        else:
            from app.services.hotspot_provisioning import provision_hotspot_customer

            result = await provision_hotspot_customer(
                customer_id, router_id, payload, "grace_period_restore",
            )
        if not (isinstance(result, dict) and result.get("success")):
            logger.warning(
                "[GRACE] Restore for customer %s did not complete: %s",
                customer_id,
                (result or {}).get("error") if isinstance(result, dict) else result,
            )
    except Exception:
        logger.exception("[GRACE] Restore for customer %s failed", customer_id)


@router.put("/api/customers/{customer_id}/grace-period")
async def set_customer_grace_period(
    customer_id: int,
    request: CustomerGraceRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Set a customer's standing grace period.

    Access is cut at expiry + grace instead of at expiry; the paid expiry is
    not changed. Companion devices sharing this customer's subscription get the
    same grace. If the new grace reopens access for a customer already cut
    off, they are reactivated and put back on the router.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    customer = (
        await db.execute(
            select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    minutes = normalize_grace_minutes(request.grace_period_minutes)
    now = datetime.utcnow()
    companions = (
        await db.execute(
            select(Customer).where(
                Customer.subscription_owner_id == customer.id,
                Customer.user_id == user.id,
            )
        )
    ).scalars().all()

    restore_ids: list[int] = []
    for row in [customer, *companions]:
        row.grace_period_minutes = minutes
        # Reopen access cut off at the old deadline. PENDING rows have not
        # been delivered yet and are left to their own flow.
        if (
            row.status == CustomerStatus.INACTIVE
            and row.expiry is not None
            and has_access_time(row, now)
            and (row.mac_address or row.pppoe_username)
        ):
            row.status = CustomerStatus.ACTIVE
            restore_ids.append(row.id)
    await db.commit()

    # Routers that remove their own expired customers hold the deadline in
    # the binding; move it later when the grace extended access.
    tag_ids = [row.id for row in [customer, *companions] if not row.pppoe_username]
    if tag_ids:
        from app.services.expiry_tag_sync import schedule_expiry_tag_sync

        schedule_expiry_tag_sync(tag_ids, "grace period change")
    for restore_id in restore_ids:
        task = asyncio.create_task(_restore_customer_access(restore_id))
        _grace_restore_tasks.add(task)
        task.add_done_callback(_grace_restore_tasks.discard)

    logger.info(
        "[GRACE] Reseller %s set grace %s min on customer %s (+%d companion(s)); restored %s",
        user.id, minutes, customer.id, len(companions), restore_ids,
    )
    eff = effective_expiry(customer)
    return {
        "success": True,
        "customer_id": customer.id,
        "status": customer.status.value,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        **grace_fields(customer, now),
        "access_until": eff.isoformat() if eff else None,
        "restored": customer.id in restore_ids,
        "companions_updated": len(companions),
    }


@router.get("/api/customers")
async def get_customers_api(
    router_id: Optional[int] = None,
    tier: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all customers for the authenticated user, optionally filtered by router.

    `tier` (optional, default "all") filters by payment history:
    "customer" = has at least one completed payment or currently-active paid
    time; "visitor" = never paid. Each item also carries computed `has_paid`
    and `tier` fields.
    """
    tier_filter = _validate_tier(tier)
    try:
        user = await get_current_user(token, db)

        now = datetime.utcnow()
        has_paid = _has_paid_condition(now)

        stmt = (
            select(Customer, has_paid.label("has_paid"))
            .where(Customer.user_id == user.id)
            .options(
                selectinload(Customer.plan),
                selectinload(Customer.router)
            )
        )
        if router_id is not None:
            stmt = stmt.where(Customer.router_id == router_id)
        if tier_filter == "customer":
            stmt = stmt.where(has_paid)
        elif tier_filter == "visitor":
            stmt = stmt.where(~has_paid)
        result = await db.execute(stmt)
        rows = result.all()

        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "pppoe_username": c.pppoe_username,
                "pppoe_password": c.pppoe_password,
                "static_ip": c.static_ip,
                "static_mac": c.static_mac,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "plan_id": c.plan_id,
                "router_id": c.router_id,
                "account_number": c.account_number,
                "wallet_credit_kes": c.wallet_credit_kes,
                **grace_fields(c, now),
                "subscription_owner_id": c.subscription_owner_id,
                "has_paid": bool(c_has_paid),
                "tier": "customer" if c_has_paid else "visitor",
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price,
                    "connection_type": c.plan.connection_type.value if c.plan.connection_type else None
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c, c_has_paid in rows
        ]
    except Exception as e:
        logger.error(f"Error fetching customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch customers")


@router.get("/api/customers/active")
async def get_active_customers(
    router_id: Optional[int] = None,
    tier: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all currently active guests, optionally filtered by router.

    `tier` (optional, default "all") filters by payment history exactly like
    `/api/customers`; each item carries computed `has_paid` and `tier`.
    """
    tier_filter = _validate_tier(tier)
    try:
        user = await get_current_user(token, db)

        now = datetime.utcnow()
        has_paid = _has_paid_condition(now)

        stmt = select(Customer, has_paid.label("has_paid")).where(
            Customer.user_id == user.id,
            Customer.status == CustomerStatus.ACTIVE
        ).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).order_by(Customer.expiry)
        if router_id is not None:
            stmt = stmt.where(Customer.router_id == router_id)
        if tier_filter == "customer":
            stmt = stmt.where(has_paid)
        elif tier_filter == "visitor":
            stmt = stmt.where(~has_paid)

        result = await db.execute(stmt)
        rows = result.all()

        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "pppoe_username": c.pppoe_username,
                "pppoe_password": c.pppoe_password,
                "static_ip": c.static_ip,
                "static_mac": c.static_mac,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "hours_remaining": (c.expiry - now).total_seconds() / 3600 if c.expiry and c.expiry > now else 0,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "plan_id": c.plan_id,
                "router_id": c.router_id,
                "account_number": c.account_number,
                "wallet_credit_kes": c.wallet_credit_kes,
                **grace_fields(c, now),
                "has_paid": bool(c_has_paid),
                "tier": "customer" if c_has_paid else "visitor",
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price,
                    "connection_type": c.plan.connection_type.value if c.plan.connection_type else None
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c, c_has_paid in rows
        ]
    except Exception as e:
        logger.error(f"Error fetching active customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch active customers")


@router.get("/api/customers/{customer_id}")
async def get_customer_detail(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get a single customer by ID."""
    try:
        user = await get_current_user(token, db)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "pppoe_username": customer.pppoe_username,
            "pppoe_password": customer.pppoe_password,
            "static_ip": customer.static_ip,
            "static_mac": customer.static_mac,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "account_number": customer.account_number,
            "wallet_credit_kes": customer.wallet_credit_kes,
            **grace_fields(customer, datetime.utcnow()),
            "subscription_owner_id": customer.subscription_owner_id,
            "plan": {
                "id": customer.plan.id,
                "name": customer.plan.name,
                "price": customer.plan.price,
                "connection_type": customer.plan.connection_type.value if customer.plan.connection_type else None,
            } if customer.plan else None,
            "router": {
                "id": customer.router.id,
                "name": customer.router.name,
            } if customer.router else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch customer")


@router.post("/api/customers/{customer_id}/location")
async def update_customer_location(
    customer_id: int,
    request: UpdateLocationRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Update customer location (lat/long) - for use when staff/technician is at customer premises
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        stmt = select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        customer.latitude = request.latitude
        customer.longitude = request.longitude
        customer.location_captured_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "success": True,
            "message": "Location updated successfully",
            "customer_id": customer_id,
            "latitude": request.latitude,
            "longitude": request.longitude
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating customer location: {e}")
        raise HTTPException(status_code=500, detail="Failed to update location")


# =========================================================================
# PPPoE MANAGEMENT ENDPOINTS
# =========================================================================

class ActivatePPPoERequest(BaseModel):
    payment_method: str = "cash"
    payment_reference: Optional[str] = None
    notes: Optional[str] = None


@router.post("/api/customers/{customer_id}/activate-pppoe")
async def activate_pppoe_customer(
    customer_id: int,
    request: ActivatePPPoERequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Activate a PPPoE customer: record payment, set ACTIVE with expiry,
    and provision PPPoE secret on the MikroTik router.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        if not customer.pppoe_username or not customer.pppoe_password:
            raise HTTPException(status_code=400, detail="Customer does not have PPPoE credentials")

        if not customer.plan:
            raise HTTPException(status_code=400, detail="Customer has no plan assigned")

        if not customer.router:
            raise HTTPException(status_code=400, detail="Customer has no router assigned")

        plan = customer.plan

        duration_unit = plan.duration_unit.value.upper()
        duration_value = plan.duration_value
        if duration_unit == "MINUTES":
            expiry_delta = timedelta(minutes=duration_value)
            days_paid_for = max(1, duration_value // (24 * 60))
        elif duration_unit == "HOURS":
            expiry_delta = timedelta(hours=duration_value)
            days_paid_for = max(1, duration_value // 24)
        else:
            expiry_delta = timedelta(days=duration_value)
            days_paid_for = duration_value

        now = datetime.utcnow()
        # An active customer (paid time or grace) keeps their billing date.
        if customer.status == CustomerStatus.ACTIVE:
            customer.expiry = renewal_expiry(customer, now, expiry_delta)
        else:
            customer.expiry = now + expiry_delta

        customer.status = CustomerStatus.ACTIVE

        try:
            pm_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            pm_enum = PaymentMethod.CASH

        payment = CustomerPayment(
            customer_id=customer.id,
            reseller_id=user.id,
            plan_id=plan.id,
            amount=float(plan.price),
            payment_method=pm_enum,
            payment_reference=request.payment_reference,
            days_paid_for=days_paid_for,
            status=PaymentStatus.COMPLETED,
            notes=request.notes or f"PPPoE activation via admin",
            customer_name=customer.name,
        )
        db.add(payment)

        try:
            from app.services.usage_tracking import on_renewal

            await on_renewal(db, customer, plan=plan, now=now)
        except Exception as renew_err:
            logger.error(
                f"[USAGE] on_renewal failed in PPPoE activation for customer {customer.id}: {renew_err}"
            )

        await db.commit()
        await db.refresh(customer, attribute_names=["plan", "router"])

        attempt = await get_or_create_provisioning_attempt(
            db,
            customer_id=customer.id,
            router_id=customer.router.id if customer.router else None,
            mac_address=None,
            source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
            source_pk=payment.id,
            external_reference=request.payment_reference,
            entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        )
        await schedule_provisioning_attempt(db, attempt)
        await db.commit()

        pppoe_payload = build_pppoe_payload(customer, customer.router)
        provision_result = await provision_pppoe_customer(
            customer_id=customer.id,
            router_id=customer.router.id,
            pppoe_payload=pppoe_payload,
            action="pppoe_activation",
            attempt_id=attempt.id,
        )
        provision_succeeded = bool(provision_result and provision_result.get("success"))
        delivery = provision_result.get("delivery") if provision_result else None
        await record_customer_event(
            customer.id, "pppoe_activated",
            f"PPPoE activated on {plan.name} until {customer.expiry:%Y-%m-%d %H:%M} UTC "
            f"({request.payment_method}); router "
            + ("updated" if provision_succeeded else
               f"not updated yet: {(provision_result or {}).get('error') or 'will retry'}"),
            severity="info" if provision_succeeded else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
            details={"payment_id": payment.id, "reference": request.payment_reference,
                     "provision_result": "ok" if provision_succeeded else "retry_pending"},
        )

        return {
            "success": True,
            "customer_id": customer.id,
            "pppoe_username": customer.pppoe_username,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_name": plan.name,
            "provision_result": "ok" if provision_succeeded else "retry_pending",
            "provision_error": provision_result.get("error") if provision_result else None,
            "delivery": delivery,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating PPPoE customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to activate PPPoE customer: {str(e)}")


@router.post("/api/customers/{customer_id}/deactivate-pppoe")
async def deactivate_pppoe_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Deactivate a PPPoE customer: disconnect session, remove secret
    from router, and set customer to INACTIVE.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        if not customer.pppoe_username:
            raise HTTPException(status_code=400, detail="Customer does not have PPPoE credentials")

        remove_result = None
        if customer.router:
            payload = build_pppoe_remove_payload(customer, customer.router)
            await db.commit()
            remove_result = await call_pppoe_remove(payload)
            if not remove_result or not remove_result.get("success"):
                error = (
                    remove_result.get("error") or "Router cleanup did not confirm success"
                    if isinstance(remove_result, dict)
                    else "PPPoE removal returned no result"
                )
                logger.error(
                    "Refusing to deactivate PPPoE customer %s because router "
                    "enforcement failed: %s",
                    customer_id,
                    error,
                )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Failed to disconnect this customer from the router; "
                        "customer status was not changed. Please retry. "
                        f"Router error: {error}"
                    ),
                )

        customer.status = CustomerStatus.INACTIVE
        if remove_result and remove_result.get("success"):
            db.add(ProvisioningLog(
                customer_id=customer.id,
                router_id=customer.router_id,
                action="pppoe_deactivation",
                status="success",
                details="Manual deactivation confirmed session and secret absent",
            ))
        await db.commit()
        await record_customer_event(
            customer.id, "pppoe_deactivated",
            "PPPoE deactivated: session disconnected and secret removed from the router",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )

        return {
            "success": True,
            "customer_id": customer.id,
            "status": customer.status.value,
            "remove_result": "ok" if remove_result and remove_result.get("success") else "failed",
            "remove_error": remove_result.get("error") if remove_result else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating PPPoE customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to deactivate PPPoE customer: {str(e)}")


# =========================================================================
# STATIC-IP MANAGEMENT ENDPOINTS
# =========================================================================

class StaticPinRequest(BaseModel):
    # A MAC pins the IP to that device; null/empty clears the pin so the next
    # device seen while the customer is paid up is learned instead.
    mac: Optional[str] = None


async def _load_static_customer(db: AsyncSession, customer_id: int, user) -> Customer:
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == customer_id, Customer.user_id == user.id)
    )
    customer = (await db.execute(stmt)).scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not customer.plan or customer.plan.connection_type != ConnectionType.STATIC_IP:
        raise HTTPException(status_code=400, detail="Customer is not on a static-IP plan")
    if not normalize_static_ip(customer.static_ip):
        raise HTTPException(status_code=400, detail="Customer has no valid static IP")
    if not customer.router:
        raise HTTPException(status_code=400, detail="Customer has no router assigned")
    return customer


def _static_result(result: dict) -> dict:
    return {
        "router_result": "ok" if result.get("success") else "failed",
        "router_error": result.get("error"),
        "changes": result.get("changes") or [],
        "gateway_ok": result.get("gateway_ok"),
        "pinned_mac": result.get("pinned_mac"),
        "observed_mac": result.get("observed_mac"),
        "mac_mismatch": bool(result.get("mac_mismatch")),
    }


@router.post("/api/customers/{customer_id}/activate-static")
async def activate_static_customer(
    customer_id: int,
    request: ActivatePPPoERequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Record a payment for a static-IP customer and open their access on the router."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        customer = await _load_static_customer(db, customer_id, user)
        plan = customer.plan

        duration_unit = plan.duration_unit.value.upper()
        duration_value = plan.duration_value
        if duration_unit == "MINUTES":
            expiry_delta = timedelta(minutes=duration_value)
            days_paid_for = max(1, duration_value // (24 * 60))
        elif duration_unit == "HOURS":
            expiry_delta = timedelta(hours=duration_value)
            days_paid_for = max(1, duration_value // 24)
        else:
            expiry_delta = timedelta(days=duration_value)
            days_paid_for = duration_value

        now = datetime.utcnow()
        # An active customer (paid time or grace) keeps their billing date.
        if customer.status == CustomerStatus.ACTIVE:
            customer.expiry = renewal_expiry(customer, now, expiry_delta)
        else:
            customer.expiry = now + expiry_delta
        customer.status = CustomerStatus.ACTIVE

        try:
            pm_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            pm_enum = PaymentMethod.CASH

        payment = CustomerPayment(
            customer_id=customer.id,
            reseller_id=user.id,
            plan_id=plan.id,
            amount=float(plan.price),
            payment_method=pm_enum,
            payment_reference=request.payment_reference,
            days_paid_for=days_paid_for,
            status=PaymentStatus.COMPLETED,
            notes=request.notes or "Static IP activation via admin",
            customer_name=customer.name,
        )
        db.add(payment)
        try:
            from app.services.usage_tracking import on_renewal

            await on_renewal(db, customer, plan=plan, now=now)
        except Exception as renew_err:
            logger.error(
                f"[USAGE] on_renewal failed in static activation for customer {customer.id}: {renew_err}"
            )
        await db.commit()
        expiry = customer.expiry

        result = await provision_static_customer(customer.id, action="static_ip_activation")
        ok = bool(result.get("success"))
        await record_customer_event(
            customer.id, "static_ip_activated",
            f"Static IP {customer.static_ip} activated on {plan.name} until {expiry:%Y-%m-%d %H:%M} UTC "
            f"({request.payment_method}); router "
            + ("updated" if ok else f"not updated yet: {result.get('error') or 'will retry'}"),
            severity="info" if ok else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
            details={"payment_id": payment.id, "reference": request.payment_reference},
        )
        return {
            "success": True,
            "customer_id": customer.id,
            "status": CustomerStatus.ACTIVE.value,
            "expiry": expiry.isoformat() if expiry else None,
            "plan_name": plan.name,
            # The enforcement job re-applies within minutes if this failed.
            "provision_result": "ok" if ok else "retry_pending",
            "provision_error": result.get("error"),
            **_static_result(result),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating static-IP customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to activate static-IP customer: {str(e)}")


@router.post("/api/customers/{customer_id}/suspend-static")
async def suspend_static_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Cut a static-IP customer's access now (router first; status only after it confirms)."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        customer = await _load_static_customer(db, customer_id, user)
        await db.commit()

        result = await provision_static_customer(
            customer.id, action="static_ip_suspend", force_enabled=False,
        )
        if not result.get("success"):
            raise HTTPException(
                status_code=503,
                detail=(
                    "Failed to suspend this customer on the router; status was not changed. "
                    f"Please retry. Router error: {result.get('error')}"
                ),
            )
        customer.status = CustomerStatus.INACTIVE
        db.add(ProvisioningLog(
            customer_id=customer.id, router_id=customer.router_id, action="static_ip_deactivation",
            status="success", details="Manual suspension: static-IP binding disabled on the router",
        ))
        await db.commit()
        await record_customer_event(
            customer.id, "static_ip_suspended",
            f"Static IP {customer.static_ip} suspended: the device now sees the payment page",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )
        return {"success": True, "customer_id": customer.id, "status": customer.status.value,
                **_static_result(result)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error suspending static-IP customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to suspend static-IP customer: {str(e)}")


@router.post("/api/customers/{customer_id}/resume-static")
async def resume_static_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Restore a suspended, unexpired subscription without recording a payment."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = await _load_static_customer(db, customer_id, user)
    if customer.expiry is None or not has_access_time(customer, datetime.utcnow()):
        raise HTTPException(status_code=400, detail="The subscription has expired. Record a payment or set the correct expiry before resuming.")
    customer.status = CustomerStatus.ACTIVE
    await db.commit()
    result = await provision_static_customer(customer.id, action="static_ip_resume")
    await record_customer_event(customer.id, "static_ip_resumed", "Static-IP subscription resumed; expiry unchanged and no payment recorded.",
                                actor=user, user_id=user.id, router_id=customer.router_id)
    return {"success": bool(result.get("success")), "customer_id": customer.id,
            "status": customer.status.value, **_static_result(result)}


@router.post("/api/customers/{customer_id}/static/sync")
async def sync_static_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Re-apply this customer's static-IP setup (access, speed, pin) to the router now."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = await _load_static_customer(db, customer_id, user)
    await db.commit()
    result = await provision_static_customer(customer.id, action="static_ip_sync")
    return {"success": bool(result.get("success")), "customer_id": customer.id,
            "access": result.get("access"), **_static_result(result)}


@router.post("/api/customers/{customer_id}/static/pin")
async def pin_static_customer(
    customer_id: int,
    request: StaticPinRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Pin the static IP to a device MAC, or clear the pin to re-learn it."""
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    customer = await _load_static_customer(db, customer_id, user)
    new_mac = _normalize_pin_mac(request.mac)
    old_mac = customer.static_mac
    if new_mac is not None:
        customer.static_mac = new_mac
    await db.commit()
    result = await provision_static_customer(
        customer.id, action="static_ip_pin", clear_pin=new_mac is None,
    )
    if new_mac is None:
        if not result.get("success"):
            raise HTTPException(status_code=503, detail="Could not clear the device pin on the router. The saved pin was kept; retry when the router is reachable.")
        customer.static_mac = None
        await db.commit()
    await record_customer_event(
        customer.id, "static_mac_pinned" if new_mac else "static_mac_cleared",
        (f"Static IP {customer.static_ip} pinned to {new_mac}" if new_mac else
         f"MAC pin cleared for {customer.static_ip}; the next device seen while paid up will be pinned"),
        actor=user, user_id=user.id, router_id=customer.router_id,
        details={"old_mac": old_mac, "new_mac": new_mac},
    )
    return {"success": bool(result.get("success")), "customer_id": customer.id,
            "static_mac": new_mac, **_static_result(result)}


@router.get("/api/customers/{customer_id}/static/status")
async def static_customer_status(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Live router view of a static-IP customer: access, speed queue, pin, device."""
    user = await get_current_user(token, db)
    customer = await _load_static_customer(db, customer_id, user)
    expected_access = customer_should_have_access(customer)
    info = {
        "customer_id": customer.id,
        "static_ip": normalize_static_ip(customer.static_ip),
        "static_mac": customer.static_mac,
        "status": customer.status.value,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "expected_access": "enabled" if expected_access else "suspended",
        "plan_speed": customer.plan.speed,
        "router_id": customer.router_id,
        "router_name": customer.router.name,
    }
    await db.commit()
    router_state = await inspect_static_customer(customer.id)
    binding = router_state.get("binding") or {}
    actual_access = (
        None if router_state.get("error")
        else "enabled" if binding.get("enabled") else "suspended"
    )
    return {
        **info,
        "router": router_state,
        "actual_access": actual_access,
        "in_sync": actual_access == info["expected_access"] and bool(router_state.get("queue")),
    }


@router.get("/api/customers/{customer_id}/pppoe-credentials")
async def get_pppoe_credentials(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get PPPoE credentials for a customer (admin use -- to give to customer)."""
    try:
        user = await get_current_user(token, db)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        if not customer.pppoe_username:
            raise HTTPException(status_code=400, detail="Customer does not have PPPoE credentials")

        await db.commit()
        await record_customer_event(
            customer.id, "credentials_viewed", "PPPoE username and password viewed",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )

        return {
            "customer_id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "pppoe_username": customer.pppoe_username,
            "pppoe_password": customer.pppoe_password,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_name": customer.plan.name if customer.plan else None,
            "router_name": customer.router.name if customer.router else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting PPPoE credentials for customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get PPPoE credentials")


@router.post("/api/customers/{customer_id}/regenerate-pppoe-password")
async def regenerate_pppoe_password(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Generate a new PPPoE password for the customer.
    Updates the database and the PPPoE secret on the router (if active).
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        if not customer.pppoe_username:
            raise HTTPException(status_code=400, detail="Customer does not have PPPoE credentials")

        new_password = _generate_pppoe_password()
        customer.pppoe_password = new_password
        await db.commit()

        router_updated = False
        if customer.status == CustomerStatus.ACTIVE and customer.router and customer.plan:
            pppoe_payload = build_pppoe_payload(customer, customer.router)
            await db.commit()
            provision_result = await call_pppoe_provision(pppoe_payload)
            router_updated = bool(provision_result and provision_result.get("success"))

        await record_customer_event(
            customer.id, "pppoe_password_regenerated",
            "New PPPoE password generated"
            + ("; router updated" if router_updated else
               "; router not updated (customer inactive or router unreachable)"),
            severity="info" if router_updated or customer.status != CustomerStatus.ACTIVE else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )

        return {
            "success": True,
            "customer_id": customer.id,
            "pppoe_username": customer.pppoe_username,
            "pppoe_password": new_password,
            "router_updated": router_updated,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating PPPoE password for customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to regenerate PPPoE password")

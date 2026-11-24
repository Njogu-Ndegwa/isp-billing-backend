from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, text, and_, or_, func
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import StatementError
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated, Literal, Optional
from datetime import datetime, timedelta
import asyncio
import re
import secrets
import string

from app.db.database import get_db
from app.db.models import (
    RouterAuthMethod,
    Router, Customer, Plan, CustomerStatus, ConnectionType,
    CustomerPayment, PaymentMethod, PaymentStatus, DurationUnit,
    Payment, CustomerRating, ProvisioningLog, MpesaTransaction,
    UserBandwidthUsage, Voucher, CustomerUsagePeriod, UsageCapWatchState,
    ProvisioningAttempt, ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource, DevicePairing, ReconnectionAttempt,
    FapshiTransaction, ZenoPayTransaction, MtnMomoTransaction,
    CustomerUsageBucket, C2BTransaction, UnmatchedC2BPayment, SmsMessage,
    PlanType,
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
from app.services.customer_events import actor_label, record_customer_event
from app.services.pppoe_device_lock import lock_fields as pppoe_lock_fields
from app.services.customer_profile import (
    AUDITED_PROFILE_FIELDS,
    CHANGED_ONLY_PROFILE_FIELDS,
    NATIONAL_ID_SEARCH_MIN,
    PROFILE_FIELDS,
    clean_location,
    clean_profile_updates,
    location_fields,
    location_updates,
    normalize_id_query,
    profile_fields,
)
from app.services.customer_pause import (
    PauseError,
    pause_customer,
    pause_fields,
    resume_customer,
)
from app.services.mikrotik_api import normalize_mac_address
from app.services import deleted_customer_cleanup
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


def _error_text(exc: Exception) -> str:
    """An exception as text for a log line / error detail, without the SQL
    parameters SQLAlchemy appends to database errors: those carry the
    customer's national ID and other register details, which never go to logs."""
    if isinstance(exc, StatementError):
        return f"{type(exc).__name__}: {exc.orig}"
    return str(exc)


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
    *AUDITED_PROFILE_FIELDS,
)


def _audit_snapshot(customer) -> dict:
    snap = {field: getattr(customer, field) for field, _ in _AUDITED_FIELDS}
    snap["pppoe_password"] = customer.pppoe_password
    for field, _ in CHANGED_ONLY_PROFILE_FIELDS:
        snap[field] = getattr(customer, field)
    snap["location"] = (customer.latitude, customer.longitude)
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
    # Personal data / free text: the log says that it changed, never the value.
    for field, label in CHANGED_ONLY_PROFILE_FIELDS:
        if before.get(field) != after.get(field):
            parts.append(f"{label} changed")
            changes[field] = ["***", "***"]
    # A home location: say whether it was set, changed or removed, not where.
    old_loc, new_loc = before.get("location"), after.get("location")
    if old_loc != new_loc:
        had = old_loc is not None and old_loc[0] is not None
        has = new_loc is not None and new_loc[0] is not None
        parts.append("location " + ("changed" if had and has else "set" if has else "removed"))
        changes["location"] = ["***" if had else "(none)", "***" if has else "(none)"]
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


async def _payment_paybills(db: AsyncSession, user, router_ids) -> dict:
    """{router_id: paybill} customers on each router should pay into.

    Same rule as the expiry reminders and the M-Pesa prompt
    (customer_expiry_notifications.resolve_paybills): the reseller's own
    C2B-registered paybill, else the platform paybill (settings.MPESA_SHORTCODE)
    when the money is platform-collected, else None (settles straight to the
    reseller with no account-number paybill we can match, or outside Kenya).
    One lookup per distinct router, not per customer. A display field, so a
    failure here returns {} instead of failing the customer list.
    """
    from app.services.customer_expiry_notifications import resolve_paybills
    from app.services.customer_pay_by_mpesa import matchable_paybills

    try:
        paybills = await resolve_paybills(db, user, set(router_ids) or {None})
        # Only a paybill the C2B handler would match for this reseller.
        return await matchable_paybills(db, user.id, paybills)
    except Exception:
        logger.exception("Could not resolve payment paybills for user %s", getattr(user, "id", None))
        return {}


async def _pay_by_mpesa_map(db: AsyncSession, customers, paybills: dict) -> dict:
    """{customer_id: Pay by M-Pesa card} (paybill, account, amount or why not)."""
    from app.services.customer_pay_by_mpesa import pay_by_mpesa, pending_plans

    customers = list(customers)
    try:
        plans = await pending_plans(db, customers)
    except Exception:
        logger.exception("Could not load pending plans for the Pay by M-Pesa card")
        plans = {}
    return {c.id: pay_by_mpesa(c, paybills.get(c.router_id), plans) for c in customers}


router = APIRouter(tags=["customers"])


# Which fields go with which kind of plan, as the dashboard's register form shows
# them: a hotspot customer's device MAC, a PPPoE login, a static IP. The kind is the
# picked plan's connection type ("plan_id.connection_type"), published in the schema
# so a form shows only the fields of the plan chosen.
_CUSTOMER_FIELDS_FOR = {"x-fields-for": {"plan_id.connection_type": {
    "hotspot": ["mac_address"],
    # a PPPoE customer may have a fixed address too (its remote address), as on the classic page
    "pppoe": ["pppoe_username", "pppoe_password", "activate_paid_until", "static_ip"],
    "static_ip": ["static_ip", "static_mac"],
}}}
# On an edit "" clears a profile field (None keeps it): what an emptied form field sends.
_CUSTOMER_CLEAR = {"x-clear": {k: "" for k in (
    "national_id", "email", "alt_phone", "address_line", "building", "installation_date", "notes", "static_mac")}}
_INSTALL_DATE = {"format": "date"}  # "2026-11-11": a date picker in the assistant's form


class CustomerRegisterRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra=_CUSTOMER_FIELDS_FOR)

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
    # Register details (all optional; see app/services/customer_profile.py).
    # On an edit, leaving a field out keeps it and "" clears it.
    national_id: Optional[str] = None
    email: Optional[str] = None
    alt_phone: Optional[str] = None
    address_line: Optional[str] = None
    building: Optional[str] = None
    installation_date: Optional[str] = Field(None, json_schema_extra=_INSTALL_DATE)
    notes: Optional[str] = None
    # Install location: both or neither (app/services/customer_profile.py).
    latitude: Optional[float] = Field(None, description="Where the customer is (install location): pick it on the map.", json_schema_extra={"x-geo": "lat"})
    longitude: Optional[float] = Field(None, json_schema_extra={"x-geo": "lng"})


class UpdateLocationRequest(BaseModel):
    latitude: float = Field(..., json_schema_extra={"x-geo": "lat"})
    longitude: float = Field(..., json_schema_extra={"x-geo": "lng"})


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
        profile = clean_profile_updates(request.model_dump(include=set(PROFILE_FIELDS)))
        profile.update(location_updates(request.latitude, request.longitude))
        
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
            # Router default "lock new PPPoE customers to their first device".
            pppoe_device_lock=bool(
                pppoe_username and getattr(router_obj, "pppoe_lock_new_customers", False)
            ),
            **profile,
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
            "created_at": customer.created_at.isoformat(),
            **profile_fields(customer, reveal_national_id=True),
            **location_fields(customer),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering customer: {_error_text(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register customer: {_error_text(e)}")


class CustomerEditRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={**_CUSTOMER_FIELDS_FOR, **_CUSTOMER_CLEAR})

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
    # PPPoE only: "Activate now - already paid until <expiry>". Turns an
    # INACTIVE customer ACTIVE until the expiry on the form and puts them on
    # the router, WITHOUT recording money: for customers migrated from another
    # system who already paid there. Never implied by editing the expiry.
    activate_paid_until: bool = False
    # Register details (all optional; see app/services/customer_profile.py).
    # On an edit, leaving a field out keeps it and "" clears it.
    national_id: Optional[str] = None
    email: Optional[str] = None
    alt_phone: Optional[str] = None
    address_line: Optional[str] = None
    building: Optional[str] = None
    installation_date: Optional[str] = Field(None, json_schema_extra=_INSTALL_DATE)
    notes: Optional[str] = None
    # Install location: send both to set it, neither to keep it, or
    # clear_location=true to remove it.
    latitude: Optional[float] = Field(None, description="Where the customer is (install location): pick it on the map.", json_schema_extra={"x-geo": "lat"})
    longitude: Optional[float] = Field(None, json_schema_extra={"x-geo": "lng"})
    clear_location: bool = False


# Furthest ahead "already paid until" may reach: a year's subscription plus a
# margin, so a mistyped year cannot hand out free access for decades.
PAID_UNTIL_MAX_AHEAD = timedelta(days=400)


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

        # Before anything touches a router: a bad email must not leave half an edit.
        profile_updates = clean_profile_updates(request.model_dump(include=set(PROFILE_FIELDS)))
        profile_updates.update(location_updates(
            request.latitude, request.longitude,
            clear=request.clear_location, current=customer,
        ))

        if customer.paused_at is not None and (
            request.activate_paid_until
            or (
                request.expiry is not None
                and (
                    customer.expiry is None
                    or abs((request.expiry.replace(tzinfo=None) - customer.expiry).total_seconds()) > 60
                )
            )
        ):
            # A paused customer's expiry is frozen and their paid time is held
            # separately; an edited expiry would be silently overwritten on
            # resume (or stacked on top of it).
            raise HTTPException(
                status_code=409,
                detail="This customer is paused. Resume them first, then change the expiry.",
            )

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

        activating = bool(request.activate_paid_until)
        if activating:
            _validate_paid_until_activation(
                customer,
                request,
                target_is_pppoe=target_is_pppoe,
                pppoe_username=(
                    normalized_pppoe_username
                    if request.pppoe_username is not None
                    else customer.pppoe_username
                ),
                pppoe_password=(
                    normalized_pppoe_password
                    if request.pppoe_password is not None
                    else customer.pppoe_password
                ),
            )

        was_static =bool(customer.plan and customer.plan.connection_type == ConnectionType.STATIC_IP)
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

        update_fields = request.model_dump(
            exclude_none=True,
            exclude={"activate_paid_until", "latitude", "longitude", "clear_location", *PROFILE_FIELDS},
        )
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
        for field, value in profile_updates.items():
            setattr(customer, field, value)
        if target_is_static and not was_static:
            customer.mac_address = None

        activation_payment = None
        if activating:
            # Same transaction as the edit: the customer turns ACTIVE until the
            # expiry on the form, and the ledger gets a zero, non-revenue row
            # saying no money was collected (the free-trial / compensation
            # pattern). The row is also the source the delivery attempt hangs
            # off, so the PPPoE retry worker can finish the job.
            activation_now = datetime.utcnow()
            customer.status = CustomerStatus.ACTIVE
            activation_payment = CustomerPayment(
                customer_id=customer.id,
                reseller_id=user.id,
                plan_id=target_plan.id if target_plan else None,
                amount=0.0,
                payment_method=PaymentMethod.OTHER,
                payment_reference=f"PAID-UNTIL-{customer.id}",
                days_paid_for=max(
                    1, -(-int((customer.expiry - activation_now).total_seconds()) // 86400)
                ),
                status=PaymentStatus.COMPLETED,
                notes=(
                    "No payment collected: activated as already paid until "
                    f"{customer.expiry:%Y-%m-%d %H:%M} UTC (migrated customer)"
                ),
                customer_name=customer.name,
                counts_as_revenue=False,
            )
            db.add(activation_payment)
            try:
                from app.services.usage_tracking import on_renewal

                await on_renewal(db, customer, plan=target_plan, now=activation_now)
            except Exception as renew_err:
                logger.error(
                    f"[USAGE] on_renewal failed in paid-until activation for customer {customer.id}: {renew_err}"
                )

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

        shared_devices_changed: list[int] = []
        if ("expiry" in update_fields or "plan_id" in update_fields) and not customer.subscription_owner_id:
            # Every device on a shared plan runs on the owner's expiry and plan.
            from app.services.subscription_sharing import carry_owner_edit_to_shared_devices

            shared_devices_changed = await carry_owner_edit_to_shared_devices(
                db, owner_customer=customer
            )

        cap_raised_customer_ids: list[int] = []
        if customer.plan_id != old_plan_id and target_plan:
            from app.services.subscription_sharing import raise_open_caps_after_plan_edit

            cap_raised_customer_ids = await raise_open_caps_after_plan_edit(
                db, customer=customer, plan=target_plan
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

            schedule_expiry_tag_sync([customer.id, *shared_devices_changed], "admin expiry edit")

        plan_push = None
        if customer.plan_id != old_plan_id and customer.plan and not customer.pppoe_username:
            old_speed = (
                await db.execute(select(Plan.speed).where(Plan.id == old_plan_id))
            ).scalar_one_or_none()
            if old_speed != customer.plan.speed:
                # Without this the customer stays on the old speed until the next
                # fleet queue sync, while the dashboard already shows the new plan.
                from app.services.subscription_sharing import push_plan_edit_to_router

                plan_push = await push_plan_edit_to_router(
                    db, customer=customer, plan=customer.plan, router=customer.router,
                )
            await db.commit()

        provision_status = None
        provision_error = None
        if (
            customer.status == CustomerStatus.ACTIVE
            and customer.pppoe_username
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

            await db.commit()
            if remove_payload:
                try:
                    await call_pppoe_remove(remove_payload)
                except Exception as e:
                    logger.warning(f"Failed to remove old PPPoE secret during edit: {e}")
            if activating:
                delivered = await _deliver_paid_until_activation(db, customer, activation_payment, user)
            else:
                # Every save of an ACTIVE PPPoE customer makes sure the router
                # has their secret (the customer page says "Re-save the
                # customer to provision it again"), through the attempt path
                # so an unreachable router is retried. Only a real login
                # change reconnects the customer's devices. A real change on a
                # customer FUP is holding down also has to settle that hold, or
                # the write gives them full speed for the rest of the period.
                from app.services.pppoe_resync import push_active_pppoe_customer

                delivered = await push_active_pppoe_customer(
                    customer.id,
                    action="pppoe_edit" if pppoe_changed else "pppoe_resave",
                    disconnect=pppoe_changed,
                    skip_if_fup_restricted=not pppoe_changed,
                    settle_fup_hold=pppoe_changed,
                )
                delivered = {
                    "provision_result": delivered.get("result"),
                    "provision_error": delivered.get("error"),
                }
            provision_status = delivered.get("provision_result")
            if provision_status in ("not_eligible", "fup_restricted"):
                provision_status = None
            provision_error = delivered.get("provision_error")

        static_status = None
        if was_static or target_is_static:
            await db.commit()
            static_status = await _sync_static_after_edit(
                customer, was_static, target_is_static,
                old_ip=old_static_ip, old_router=old_static_router,
                pin_cleared=bool(old_static_mac) and not customer.static_mac,
            )

        if cap_raised_customer_ids:
            # After the router pushes above: a device they held for FUP gets the new
            # plan's speed from this lift, so nobody drops twice.
            from app.services.fup import lift_restrictions_after_cap_raise

            asyncio.create_task(lift_restrictions_after_cap_raise(cap_raised_customer_ids))

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
                **profile_fields(customer, reveal_national_id=True),
                **location_fields(customer),
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
            # ok | retry_pending (router not updated yet, retried automatically)
            # | in_progress | failed | None (nothing to push)
            "pppoe_reprovisioned": provision_status,
            "pppoe_provision_error": provision_error,
            "activated_paid_until": activating,
            "static_reprovisioned": static_status,
            # {"pushed": n, "held_by_fup": n} when a hotspot plan edit changed the speed.
            "plan_push": plan_push,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing customer {customer_id}: {_error_text(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to edit customer: {_error_text(e)}")


def _validate_paid_until_activation(
    customer: Customer,
    request: "CustomerEditRequest",
    *,
    target_is_pppoe: bool,
    pppoe_username: Optional[str],
    pppoe_password: Optional[str],
) -> None:
    """Refuse an "already paid until" activation before anything is changed."""
    if not target_is_pppoe:
        raise HTTPException(
            status_code=400,
            detail="Only PPPoE customers can be activated as already paid.",
        )
    if customer.status == CustomerStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="This customer is already active.")
    paid_until = (
        request.expiry.replace(tzinfo=None) if request.expiry is not None else customer.expiry
    )
    now = datetime.utcnow()
    if paid_until is None or paid_until <= now:
        raise HTTPException(
            status_code=400,
            detail=(
                "Set the expiry to the date the customer has already paid until "
                "(a future date), then activate."
            ),
        )
    if paid_until > now + PAID_UNTIL_MAX_AHEAD:
        raise HTTPException(
            status_code=400,
            detail="That expiry is more than 400 days away. Check the year and try again.",
        )
    if not pppoe_username or not pppoe_password:
        raise HTTPException(
            status_code=400,
            detail="Set a PPPoE username and password before activating.",
        )
    if request.router_id is None and customer.router_id is None:
        raise HTTPException(status_code=400, detail="Assign a router before activating.")


async def _deliver_paid_until_activation(
    db: AsyncSession,
    customer: Customer,
    payment: CustomerPayment,
    user,
) -> dict:
    """Put a just-activated "already paid until" customer on their router.

    Same delivery as activate-pppoe: a provisioning attempt sourced from the
    (zero, non-revenue) payment row, so a failed push is retried by the PPPoE
    retry worker instead of leaving the customer off the router.
    """
    attempt = await get_or_create_provisioning_attempt(
        db,
        customer_id=customer.id,
        router_id=customer.router.id,
        mac_address=None,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        source_pk=payment.id,
        external_reference=payment.payment_reference,
        entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
    )
    await schedule_provisioning_attempt(db, attempt)
    pppoe_payload = build_pppoe_payload(customer, customer.router)
    attempt_id = attempt.id
    plan_name = customer.plan.name if customer.plan else "plan"
    expiry = customer.expiry
    await db.commit()

    provision_result = await provision_pppoe_customer(
        customer_id=customer.id,
        router_id=customer.router.id,
        pppoe_payload=pppoe_payload,
        action="pppoe_activation",
        attempt_id=attempt_id,
    )
    ok = bool(provision_result and provision_result.get("success"))
    error = (provision_result or {}).get("error")
    await record_customer_event(
        customer.id, "pppoe_activated",
        f"PPPoE activated on {plan_name} as already paid until {expiry:%Y-%m-%d %H:%M} UTC "
        "(no payment recorded); router "
        + ("updated" if ok else f"not updated yet: {error or 'will retry'}"),
        severity="info" if ok else "warning",
        actor=user, user_id=user.id, router_id=customer.router_id,
        details={
            "payment_id": payment.id,
            "paid_until": expiry.isoformat() if expiry else None,
            "counts_as_revenue": False,
            "provision_result": "ok" if ok else "retry_pending",
        },
    )
    return {
        "provision_result": "ok" if ok else "retry_pending",
        "provision_error": None if ok else error,
        "delivery": (provision_result or {}).get("delivery"),
    }


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
    """Delete a customer and all related data, including their shared devices.

    PPPoE customers must be removed from the router before the DB row is
    deleted. If RouterOS cleanup fails, the customer is kept so the cleanup can
    be retried instead of leaving an orphaned online secret.

    Devices sharing this customer's plan run on it and could never renew again,
    so they go too. Their router access is removed after the rows are gone.

    A hotspot customer's user, ip-binding and session are removed from the
    router once the row is gone. An unreachable router does not block the
    delete: the cleanup is queued and retried (``deleted_customer_cleanup``).
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)

    hotspot_target = await _load_hotspot_cleanup_target(db, customer_id, user.id)
    shared_devices = await _load_shared_devices(db, customer_id, user.id)
    response = await _delete_customer_row(customer_id, db, user)

    removed_ids: list[int] = []
    for device in shared_devices:
        await _delete_customer_row(device["id"], db, user)
        removed_ids.append(device["id"])
    pending = await _remove_shared_devices_from_routers(db, shared_devices)
    if pending:
        await deleted_customer_cleanup.queue_for_retry(
            [d["target"] for d in shared_devices if d["mac"] in pending and d["target"]],
            "shared device router cleanup failed at delete",
        )

    router_cleanup = await deleted_customer_cleanup.remove_deleted_customer_from_router(
        hotspot_target
    )

    if removed_ids:
        logger.info(
            "Customer %s deleted with %d shared device(s) %s; router cleanup pending for %s",
            customer_id, len(removed_ids), removed_ids, pending,
        )
    return {
        **response,
        "router_cleanup": router_cleanup,
        "shared_devices_removed": len(removed_ids),
        "shared_devices_router_pending": pending,
    }


async def _load_hotspot_cleanup_target(db: AsyncSession, customer_id: int, user_id: int):
    """Router cleanup data for a hotspot customer, read before its row is deleted."""
    customer = (
        await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user_id)
        )
    ).scalar_one_or_none()
    target = deleted_customer_cleanup.cleanup_target(customer) if customer else None
    await db.commit()
    return target


async def _load_shared_devices(db: AsyncSession, owner_id: int, user_id: int) -> list[dict]:
    """Plain data for the devices on ``owner_id``'s plan, safe to use after commit."""
    from app.api.device_pairing import _router_cleanup_info

    rows = (
        await db.execute(
            select(Customer)
            .options(selectinload(Customer.router), selectinload(Customer.plan))
            .where(Customer.subscription_owner_id == owner_id, Customer.user_id == user_id)
            .order_by(Customer.id)
        )
    ).scalars().all()
    devices = []
    for row in rows:
        auth_value, router_info = _router_cleanup_info(row.router) if row.router else (None, None)
        devices.append({
            "id": row.id,
            "mac": normalize_mac_address(row.mac_address) if row.mac_address else None,
            "router_id": row.router_id,
            "auth": auth_value,
            "router_info": router_info,
            "target": deleted_customer_cleanup.cleanup_target(row),
        })
    await db.commit()
    return devices


async def _remove_shared_devices_from_routers(db: AsyncSession, devices: list[dict]) -> list[str]:
    """Best effort, with nothing held open. Returns the MACs still on a router.

    A router that fails is not retried for its other devices, so one dead tunnel
    can't hold the request up once per device.
    """
    from app.api.device_pairing import (
        _delete_radius_shared_device_entries,
        _remove_shared_device_from_direct_router_sync,
    )

    pending: list[str] = []
    failed_routers: set[int] = set()
    radius_cleaned = False
    for device in devices:
        mac = device["mac"]
        if not mac:
            continue
        if device["auth"] == RouterAuthMethod.RADIUS.value:
            await _delete_radius_shared_device_entries(db, mac)
            radius_cleaned = True
            continue
        if not device["router_info"]:
            continue
        if device["router_id"] in failed_routers:
            pending.append(mac)
            continue
        try:
            result = await asyncio.to_thread(
                _remove_shared_device_from_direct_router_sync, device["router_info"], mac,
            )
        except Exception as exc:
            result = {"success": False, "error": str(exc)}
        if not result.get("success"):
            logger.warning(
                "Could not remove shared device %s from router %s: %s",
                mac, device["router_id"], result.get("error"),
            )
            failed_routers.add(device["router_id"])
            pending.append(mac)
    if radius_cleaned:
        await db.commit()
    return pending


async def _delete_customer_row(customer_id: int, db: AsyncSession, user) -> dict:
    """Delete one customer row and its child rows."""
    try:
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
        # Remove operational records. Payment records are retained.
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
            .values(customer_id=None, router_id=func.coalesce(CustomerPayment.router_id, customer.router_id))
        )

        # M-Pesa attempts need an explicit owner once their live customer is gone.
        await db.execute(
            update(MpesaTransaction).where(MpesaTransaction.customer_id == customer_id)
            .values(
                customer_id=None,
                reseller_id=func.coalesce(MpesaTransaction.reseller_id, user.id),
                router_id=func.coalesce(MpesaTransaction.router_id, customer.router_id),
                updated_at=MpesaTransaction.updated_at,
            )
        )
        # Other gateways already carry ownership. Detach only the customer link
        # and keep the original provider timestamps and transaction payload.
        await db.execute(update(ZenoPayTransaction).where(ZenoPayTransaction.customer_id == customer_id)
                         .values(customer_id=None, updated_at=ZenoPayTransaction.updated_at))
        await db.execute(update(MtnMomoTransaction).where(MtnMomoTransaction.customer_id == customer_id)
                         .values(customer_id=None, updated_at=MtnMomoTransaction.updated_at))
        await db.execute(update(FapshiTransaction).where(FapshiTransaction.customer_id == customer_id)
                         .values(customer_id=None, updated_at=FapshiTransaction.updated_at))
        await db.execute(update(Payment).where(Payment.customer_id == customer_id).values(customer_id=None))

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


# Paging for the customer lists. Without page/per_page the endpoints keep
# returning the full plain array (older clients rely on it). With both, they
# return one page plus totals, so a dashboard that only needs a count no longer
# downloads every customer (2-3 MB for a large reseller).
CUSTOMER_LIST_MAX_PER_PAGE = 500


def _wants_page(page: Optional[int], per_page: Optional[int]) -> bool:
    return page is not None and per_page is not None


async def _count_rows(db: AsyncSession, conditions) -> int:
    return (await db.execute(select(func.count(Customer.id)).where(*conditions))).scalar_one()


def _page_envelope(items: list, page: int, per_page: int, total: int) -> dict:
    return {
        "data": items,
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": max(1, -(-total // per_page)),
    }


async def _online_condition(db: AsyncSession, user, online: bool):
    """Who is connected right now, from the routers' live reports (no RouterOS calls):
    the same answer as the Customers page's Online filter."""
    from app.api.usage_routes import _live_for, _live_router_ids_for

    router_ids = await _live_router_ids_for(db, user)
    if not router_ids:
        return Customer.id.in_([])   # no live router: nobody can be said to be on or off
    on_live = (await db.execute(
        select(Customer).options(selectinload(Customer.plan))
        .where(Customer.user_id == user.id, Customer.router_id.in_(router_ids))
    )).scalars().all()
    ids = [c.id for c in on_live if ((live := _live_for(c)) is not None and live.online) == online]
    return Customer.id.in_(ids)


async def _online_coverage(db: AsyncSession, user, router_id: Optional[int]) -> dict:
    """Which of the caller's routers the online filter covers (live reporting) and which it cannot."""
    from app.api.usage_routes import _live_router_ids_for

    live = set(await _live_router_ids_for(db, user))
    stmt = select(Router.id, Router.name).where(Router.user_id == user.id).order_by(Router.id)
    if router_id is not None:
        stmt = stmt.where(Router.id == router_id)
    mine = (await db.execute(stmt)).all()
    not_live = [{"id": rid, "name": name} for rid, name in mine if rid not in live]
    out: dict = {"live_router_ids": sorted(rid for rid, _ in mine if rid in live), "not_live_routers": not_live}
    if not_live:
        out["coverage_note"] = (
            "Who is online is known only on routers on live reporting. Not covered here: "
            + ", ".join(f"{r['name']} (#{r['id']})" for r in not_live[:10])
            + ". For those, read GET /api/hotspot/{id}/users and GET /api/pppoe/{id}/users.")
    return out


def _list_filters(status, connection_type, overdue, search, now) -> list:
    """The narrowing the Customers list can do on the server, so a question like
    "my active customers" gets only those (an unknown filter used to be ignored
    and the whole list came back)."""
    out = []
    if status:
        out.append(Customer.status == CustomerStatus(status))
    has_login = and_(Customer.pppoe_username.isnot(None), Customer.pppoe_username != "")
    has_ip = and_(Customer.static_ip.isnot(None), Customer.static_ip != "")
    if connection_type == "pppoe":
        out.append(has_login)
    elif connection_type == "static_ip":
        out.append(and_(has_ip, ~has_login))
    elif connection_type == "hotspot":
        out.append(and_(~has_login, ~has_ip))
    if overdue is not None:
        ran_out = and_(Customer.expiry.isnot(None), Customer.expiry <= now, Customer.paused_at.is_(None))
        out.append(ran_out if overdue else ~ran_out)
    text_q = (search or "").strip()
    if text_q:
        like = f"%{text_q}%"
        options = [Customer.name.ilike(like), Customer.account_number.ilike(like), Customer.pppoe_username.ilike(like),
                   Customer.phone.ilike(like)]
        digits = "".join(ch for ch in text_q if ch.isdigit())
        if len(digits) >= 6:
            # 0712..., 254712..., +254 712...: the last nine digits are the number
            options.append(Customer.phone.ilike(f"%{digits[-9:]}%"))
        out.append(or_(*options))
    return out


async def _did_you_mean(db: AsyncSession, conditions: list, search: str) -> list[dict]:
    """Close matches for a search that found no one, best first: a short read of four
    columns of this reseller's customers (capped), scored in memory."""
    from app.services import customer_fuzzy

    pool = (await db.execute(
        select(Customer.id, Customer.name, Customer.phone, Customer.account_number)
        .where(*conditions).order_by(Customer.id).limit(customer_fuzzy.MAX_POOL)
    )).all()
    close = customer_fuzzy.close_matches(search, pool)
    if not close:
        return []
    by_id = {r.id: r for r in pool}
    statuses = dict((await db.execute(
        select(Customer.id, Customer.status).where(Customer.id.in_([m["id"] for m in close]))
    )).all())
    return [{"id": m["id"], "name": by_id[m["id"]].name, "phone": by_id[m["id"]].phone,
             "account_number": by_id[m["id"]].account_number,
             "status": getattr(statuses.get(m["id"]), "value", None),
             "matched_on": m["matched_on"], "score": m["score"]} for m in close]


@router.get("/api/customers")
async def get_customers_api(
    router_id: Optional[int] = None,
    tier: Optional[str] = None,
    status: Annotated[Optional[Literal["active", "inactive", "pending"]],
                      Query(description="Only customers with this status")] = None,
    connection_type: Annotated[Optional[Literal["hotspot", "pppoe", "static_ip"]],
                               Query(description="Only hotspot, PPPoE or static-IP customers")] = None,
    overdue: Annotated[Optional[bool],
                       Query(description="true: only those whose paid time has run out (paused ones excluded); false: leave them out")] = None,
    search: Annotated[Optional[str],
                      Query(max_length=80, description="Name, phone, account number or PPPoE username contains this")] = None,
    plan_id: Annotated[Optional[int], Query(description="Only customers on this plan")] = None,
    expires: Annotated[Optional[Literal["today", "tomorrow", "next_7_days", "past_7_days"]],
                       Query(description=("Only customers whose paid time ends then: today or tomorrow (calendar days "
                                          "in the reseller's timezone; today includes earlier today), next_7_days, "
                                          "or past_7_days (ran out in the last 7 days). Paused ones are left out."))] = None,
    online: Annotated[Optional[bool],
                      Query(description=("true: only customers connected right now; false: only those not connected. "
                                         "Covers routers on live reporting; customers on other routers are left out."))] = None,
    page: Annotated[Optional[int], Query(ge=1)] = None,
    per_page: Annotated[Optional[int], Query(ge=1, le=CUSTOMER_LIST_MAX_PER_PAGE)] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all customers for the authenticated user, optionally filtered by router.

    `status`, `connection_type`, `overdue` and `search` narrow the list (all
    optional, combined with AND).

    `tier` (optional, default "all") filters by payment history:
    "customer" = has at least one completed payment or currently-active paid
    time; "visitor" = never paid. Each item also carries computed `has_paid`
    and `tier` fields.

    With both `page` and `per_page`, returns one page (ordered by id) as
    `{data, page, per_page, total, total_pages}`; otherwise the full array.

    When `search` matches no one, close matches by name, phone (one digit off) or
    account number come back as `{data: [], total: 0, did_you_mean: [...]}`
    (best first). They are not results: offer them ("Did you mean Amina?").
    """
    tier_filter = _validate_tier(tier)
    try:
        user = await get_current_user(token, db)

        now = datetime.utcnow()
        has_paid = _has_paid_condition(now)

        conditions = [Customer.user_id == user.id]
        if router_id is not None:
            conditions.append(Customer.router_id == router_id)
        if tier_filter == "customer":
            conditions.append(has_paid)
        elif tier_filter == "visitor":
            conditions.append(~has_paid)
        conditions.extend(_list_filters(status, connection_type, overdue, None, now))
        if plan_id is not None:
            conditions.append(Customer.plan_id == plan_id)
        if expires:
            from app.services.markets import reseller_market
            from app.services.sms_dispatch import expiry_between, expiry_window
            conditions.extend(expiry_between(*expiry_window(expires, now, reseller_market(user).timezone)))
        if online is not None:
            conditions.append(await _online_condition(db, user, online))
        base = list(conditions)   # everything but the search, for close matches
        conditions.extend(_list_filters(None, None, None, search, now))
        stmt = (
            select(Customer, has_paid.label("has_paid"))
            .where(*conditions)
            .options(
                selectinload(Customer.plan),
                selectinload(Customer.router)
            )
        )
        paged = _wants_page(page, per_page)
        total = None
        if paged:
            total = await _count_rows(db, conditions)
            stmt = stmt.order_by(Customer.id).offset((page - 1) * per_page).limit(per_page)
        result = await db.execute(stmt)
        rows = result.all()
        paybills = await _payment_paybills(db, user, {c.router_id for c, _ in rows})
        pay_cards = await _pay_by_mpesa_map(db, (c for c, _ in rows), paybills)

        items = [
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
                "payment_paybill": paybills.get(c.router_id),
                "pay_by_mpesa": pay_cards[c.id],
                "wallet_credit_kes": c.wallet_credit_kes,
                **grace_fields(c, now),
                **pause_fields(c),
                **profile_fields(c, reveal_national_id=False),
                "subscription_owner_id": c.subscription_owner_id,
                "has_paid": bool(c_has_paid),
                "tier": "customer" if c_has_paid else "visitor",
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price,
                    "connection_type": c.plan.connection_type.value if c.plan.connection_type else None,
                    "speed": c.plan.speed,
                    "data_cap_mb": c.plan.data_cap_mb,
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c, c_has_paid in rows
        ]
        out = _page_envelope(items, page, per_page, total) if paged else items
        if online is not None:
            # say which routers the online filter could and could not see, so "who is online"
            # never reads as "nobody" on a router that is not on live reporting
            out = {**(out if paged else {"data": items, "total": len(items)}),
                   **await _online_coverage(db, user, router_id)}
        if (search or "").strip() and not items and not total:
            # nothing contains it: offer close matches (one wrong letter or digit) beside the
            # empty result, among the same customers the other filters allow
            close = await _did_you_mean(db, base, search)
            if close:
                out = {**(out if paged else {"data": [], "total": 0}), "did_you_mean": close}
        return out
    except Exception as e:
        logger.error(f"Error fetching customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch customers")


@router.get("/api/customers/active")
async def get_active_customers(
    router_id: Optional[int] = None,
    tier: Optional[str] = None,
    expires_within_hours: Annotated[Optional[int], Query(ge=1, le=24 * 366)] = None,
    page: Annotated[Optional[int], Query(ge=1)] = None,
    per_page: Annotated[Optional[int], Query(ge=1, le=CUSTOMER_LIST_MAX_PER_PAGE)] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all currently active guests, optionally filtered by router.

    `tier` (optional, default "all") filters by payment history exactly like
    `/api/customers`; each item carries computed `has_paid` and `tier`.

    `expires_within_hours` (optional) keeps only those whose paid time ends within
    that many hours from now, e.g. 72 for "who runs out in the next 3 days".

    With both `page` and `per_page`, returns one page (soonest expiry first)
    as `{data, page, per_page, total, total_pages}`; otherwise the full array.
    """
    tier_filter = _validate_tier(tier)
    try:
        user = await get_current_user(token, db)

        now = datetime.utcnow()
        has_paid = _has_paid_condition(now)

        conditions = [
            Customer.user_id == user.id,
            Customer.status == CustomerStatus.ACTIVE,
        ]
        if router_id is not None:
            conditions.append(Customer.router_id == router_id)
        if expires_within_hours is not None:
            conditions.append(Customer.expiry <= now + timedelta(hours=expires_within_hours))
        if tier_filter == "customer":
            conditions.append(has_paid)
        elif tier_filter == "visitor":
            conditions.append(~has_paid)
        stmt = select(Customer, has_paid.label("has_paid")).where(*conditions).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).order_by(Customer.expiry, Customer.id)
        paged = _wants_page(page, per_page)
        total = None
        if paged:
            total = await _count_rows(db, conditions)
            stmt = stmt.offset((page - 1) * per_page).limit(per_page)

        result = await db.execute(stmt)
        rows = result.all()
        paybills = await _payment_paybills(db, user, {c.router_id for c, _ in rows})
        pay_cards = await _pay_by_mpesa_map(db, (c for c, _ in rows), paybills)

        items = [
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
                "payment_paybill": paybills.get(c.router_id),
                "pay_by_mpesa": pay_cards[c.id],
                "wallet_credit_kes": c.wallet_credit_kes,
                **grace_fields(c, now),
                **pause_fields(c),
                **profile_fields(c, reveal_national_id=False),
                "has_paid": bool(c_has_paid),
                "tier": "customer" if c_has_paid else "visitor",
                "plan": {
                    "id": c.plan.id,
                    "name": c.plan.name,
                    "price": c.plan.price,
                    "connection_type": c.plan.connection_type.value if c.plan.connection_type else None,
                    "speed": c.plan.speed,
                    "data_cap_mb": c.plan.data_cap_mb,
                } if c.plan else None,
                "router": {
                    "id": c.router.id,
                    "name": c.router.name
                } if c.router else None
            }
            for c, c_has_paid in rows
        ]
        return _page_envelope(items, page, per_page, total) if paged else items
    except Exception as e:
        logger.error(f"Error fetching active customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch active customers")


@router.get("/api/customers/national-id-matches")
async def national_id_matches(
    q: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """IDs of this reseller's customers whose national ID / passport number
    contains ``q`` (compared on letters and digits only, any case).

    The customer list carries the number masked, so the admin search asks here
    instead. Returns customer ids only, never the numbers. A ``q`` shorter than
    NATIONAL_ID_SEARCH_MIN characters matches nothing.
    """
    user = await get_current_user(token, db)
    needle = normalize_id_query(q)
    if len(needle) < NATIONAL_ID_SEARCH_MIN:
        return {"customer_ids": []}
    # Stored numbers are upper case already (clean_national_id); strip the
    # separators the same way the query was stripped.
    stored = func.replace(func.replace(func.replace(Customer.national_id, " ", ""), "-", ""), "/", "")
    rows = await db.execute(
        select(Customer.id)
        .where(
            Customer.user_id == user.id,
            Customer.national_id.isnot(None),
            stored.contains(needle, autoescape=True),
        )
        .order_by(Customer.id)
        .limit(500)
    )
    return {"customer_ids": [row[0] for row in rows.all()]}


def _phone_key(phone: Optional[str]) -> Optional[str]:
    """Last 9 digits, the same key the admin's customer page matches phones on."""
    digits = re.sub(r"\D", "", phone or "")
    return digits[-9:] if len(digits) >= 9 else None


@router.get("/api/customers/{customer_id}/related")
async def get_related_customers(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """The few accounts linked to one customer, for its detail page.

    Returns the subscription owner, the companions it covers, and other
    accounts with the same phone number (last 9 digits), each as
    {id, name, mac_address, phone, subscription_owner_id}. The page used to
    download the whole customer list (2-3 MB for a large reseller) to find
    these. Scoped exactly like GET /api/customers.
    """
    user = await get_current_user(token, db)
    customer = (await db.execute(
        select(Customer).where(Customer.id == customer_id, Customer.user_id == user.id)
    )).scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    rows = (await db.execute(
        select(Customer.id, Customer.name, Customer.mac_address, Customer.phone, Customer.subscription_owner_id)
        .where(Customer.user_id == user.id, Customer.id != customer.id)
        .order_by(Customer.id)
    )).all()
    await db.commit()

    key = _phone_key(customer.phone)
    related = [
        {"id": r.id, "name": r.name, "mac_address": r.mac_address, "phone": r.phone,
         "subscription_owner_id": r.subscription_owner_id}
        for r in rows
        if r.id == customer.subscription_owner_id
        or r.subscription_owner_id == customer.id
        or (key is not None and _phone_key(r.phone) == key)
    ]
    return {"customers": related}


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
        paybills = await _payment_paybills(db, user, {customer.router_id})
        pay_cards = await _pay_by_mpesa_map(db, [customer], paybills)

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
            "payment_paybill": paybills.get(customer.router_id),
            "pay_by_mpesa": pay_cards[customer.id],
            "wallet_credit_kes": customer.wallet_credit_kes,
            **grace_fields(customer, datetime.utcnow()),
            **pause_fields(customer),
            **pppoe_lock_fields(customer),
            **profile_fields(customer, reveal_national_id=True),
            **location_fields(customer),
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

        lat, lng = clean_location(request.latitude, request.longitude)
        customer.latitude = lat
        customer.longitude = lng
        customer.location_captured_at = datetime.utcnow()
        
        await db.commit()
        
        return {
            "success": True,
            "message": "Location updated successfully",
            "customer_id": customer_id,
            "latitude": lat,
            "longitude": lng,
            "location_captured_at": customer.location_captured_at.isoformat(),
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
    # cash / other / bank_transfer / card record money taken outside the
    # system. "none" activates without recording any payment (a free month,
    # a comp, money already recorded elsewhere): see NO_PAYMENT below.
    payment_method: str = Field(
        "cash",
        description="cash: cash received; other: paid outside the system; none: activate without payment (free, a comp, a test).",
        json_schema_extra={"enum": ["cash", "other", "none"]},
    )
    payment_reference: Optional[str] = None
    notes: Optional[str] = None
    # Record another payment even though the customer is already active or
    # paid moments ago. The admin UI only sends this after the reseller has
    # seen the 409 below and confirmed.
    force: bool = False


# A manual activation records money the reseller took outside the system.
# mobile_money is deliberately absent: it is how M-Pesa/C2B rows are stored,
# the transaction ledger treats those rows as twins of an M-Pesa record and
# hides them, and the admin M-Pesa totals count them. A hand-entered
# "M-Pesa" row would be a revenue row with no M-Pesa receipt behind it.
MANUAL_ACTIVATION_PAYMENT_METHODS = {
    "cash": PaymentMethod.CASH,
    "other": PaymentMethod.OTHER,
    "bank_transfer": PaymentMethod.BANK_TRANSFER,
    "card": PaymentMethod.CARD,
}

# "Activate without payment": the customer gets the plan's period but no
# money is recorded. The ledger gets the same zero-amount, non-revenue row
# the paid-until activation writes (PUT /api/customers/{id} with
# activate_paid_until), so revenue, the dashboard, the transactions totals
# and the subscription charge (all filter counts_as_revenue) never see it.
NO_PAYMENT = "none"


def is_no_payment_activation(value: Optional[str]) -> bool:
    return (value or "").strip().lower() == NO_PAYMENT


def is_free_trial_plan(plan: Optional[Plan]) -> bool:
    return plan is not None and plan.plan_type == PlanType.FREE_TRIAL


def manual_activation_ledger_row(
    customer: Customer,
    plan: Plan,
    user,
    request: "ActivatePPPoERequest",
    *,
    no_payment: bool,
    pm_enum: PaymentMethod,
    days_paid_for: int,
    default_note: str,
) -> CustomerPayment:
    """The customer_payments row behind a manual activation.

    It is also the source the provisioning attempt hangs off, so a no-payment
    activation still gets one (amount 0, not revenue)."""
    if no_payment:
        # A free-trial plan is labelled like a portal trial claim (the ledger
        # reads the FREE-TRIAL- prefix as source "free_trial").
        free_trial = is_free_trial_plan(plan)
        default_reference = (
            f"FREE-TRIAL-{plan.id}" if free_trial else f"NO-PAYMENT-{customer.id}"
        )
        return CustomerPayment(
            customer_id=customer.id,
            reseller_id=user.id,
            plan_id=plan.id,
            amount=0.0,
            payment_method=PaymentMethod.OTHER,
            payment_reference=request.payment_reference or default_reference,
            days_paid_for=days_paid_for,
            status=PaymentStatus.COMPLETED,
            notes=(
                ("Free trial: no payment collected" if free_trial
                 else "No payment collected: activated without payment")
                + (f" ({request.notes})" if request.notes else "")
            ),
            customer_name=customer.name,
            counts_as_revenue=False,
        )
    return CustomerPayment(
        customer_id=customer.id,
        reseller_id=user.id,
        plan_id=plan.id,
        amount=float(plan.price),
        payment_method=pm_enum,
        payment_reference=request.payment_reference,
        days_paid_for=days_paid_for,
        status=PaymentStatus.COMPLETED,
        notes=request.notes or default_note,
        customer_name=customer.name,
    )


def manual_activation_event_text(
    user, pm_enum: PaymentMethod, *, no_payment: bool, forced: bool, free_trial: bool = False,
) -> str:
    confirmed = ", confirmed although already active/paid" if forced else ""
    if free_trial:
        return f"free trial, no payment, by {actor_label(user) or 'the reseller'}{confirmed}"
    if no_payment:
        return f"without payment by {actor_label(user) or 'the reseller'}{confirmed}"
    return f"{pm_enum.value}{confirmed}"


# A payment completed this recently means the customer was just activated
# (C2B, STK or another manual activation) and a second activation is almost
# certainly a stale screen or a double click.
RECENT_PAYMENT_WINDOW = timedelta(minutes=10)


def manual_activation_payment_method(value: Optional[str]) -> PaymentMethod:
    """Map the activation form's payment method, refusing values that would
    be stored as something else ("mpesa" and "voucher" used to be saved
    silently as CASH)."""
    key = (value or "cash").strip().lower()
    method = MANUAL_ACTIVATION_PAYMENT_METHODS.get(key)
    if method is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{value}' is not a valid payment method for a manual activation. "
                "Use 'cash' (cash received), 'other' (paid outside the system) "
                "or 'none' (activate without recording a payment). "
                "M-Pesa payments to your paybill or till activate the customer automatically."
            ),
        )
    return method


async def manual_activation_conflict(
    db: AsyncSession, customer: Customer, now: datetime, *, no_payment: bool = False
) -> Optional[dict]:
    """Why activating ``customer`` again now would double-renew them, or None.

    Two signals: paid time still running (status ACTIVE with expiry in the
    future; grace does not count, a customer in grace genuinely owes), or a
    completed payment in the last few minutes.
    """
    active_until = (
        customer.expiry
        if customer.status == CustomerStatus.ACTIVE
        and customer.expiry is not None
        and customer.expiry > now
        else None
    )
    recent = (
        await db.execute(
            select(
                CustomerPayment.payment_date,
                CustomerPayment.amount,
                CustomerPayment.payment_method,
            )
            .where(
                CustomerPayment.customer_id == customer.id,
                CustomerPayment.status == PaymentStatus.COMPLETED,
                CustomerPayment.payment_date >= now - RECENT_PAYMENT_WINDOW,
            )
            .order_by(CustomerPayment.payment_date.desc())
            .limit(1)
        )
    ).first()
    if active_until is None and recent is None:
        return None

    again = (
        "Activating again adds another period without recording a payment."
        if no_payment
        else "Activating again records another payment and adds another period."
    )
    if recent is not None:
        code = "customer_already_paid"
        happened = (
            "already paid" if float(recent.amount or 0) else "was activated without payment"
        )
        message = (
            f"This customer {happened} at {recent.payment_date:%Y-%m-%d %H:%M} UTC"
            + (f" and is active until {active_until:%Y-%m-%d %H:%M} UTC" if active_until else "")
            + f". {again}"
        )
    else:
        code = "customer_already_active"
        message = (
            f"This customer is already active until {active_until:%Y-%m-%d %H:%M} UTC. "
            + again
        )
    method = recent.payment_method if recent is not None else None
    return {
        "code": code,
        "message": message,
        "customer_id": customer.id,
        "status": customer.status.value if customer.status else None,
        "expiry": customer.expiry.isoformat() if customer.expiry else None,
        "last_payment_at": recent.payment_date.isoformat() if recent is not None else None,
        "last_payment_amount": float(recent.amount) if recent is not None else None,
        "last_payment_method": getattr(method, "value", method),
    }


async def refuse_duplicate_manual_activation(
    db: AsyncSession,
    customer: Customer,
    request: "ActivatePPPoERequest",
    now: datetime,
    *,
    no_payment: Optional[bool] = None,
) -> bool:
    """Raise 409 when this activation would double-renew, unless forced.
    Returns True when the reseller confirmed past a conflict (for the audit trail)."""
    if no_payment is None:
        no_payment = is_no_payment_activation(request.payment_method)
    conflict = await manual_activation_conflict(db, customer, now, no_payment=no_payment)
    if conflict is None:
        return False
    if not request.force:
        raise HTTPException(status_code=409, detail=conflict)
    logger.warning(
        "Manual activation of customer %s forced past %s (expiry %s, last payment %s)",
        customer.id, conflict["code"], conflict["expiry"], conflict["last_payment_at"],
    )
    return True


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
        # A free-trial plan costs nothing, so activating a customer on it never
        # records a payment, whatever method the form sent: the ledger gets the
        # zero, non-revenue row, like a trial claimed on the hotspot portal.
        no_payment = (
            is_no_payment_activation(request.payment_method) or is_free_trial_plan(plan)
        )
        pm_enum = (
            PaymentMethod.OTHER if no_payment
            else manual_activation_payment_method(request.payment_method)
        )
        now = datetime.utcnow()
        forced = await refuse_duplicate_manual_activation(
            db, customer, request, now, no_payment=no_payment,
        )

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

        # An active customer (paid time or grace) keeps their billing date.
        if customer.status == CustomerStatus.ACTIVE:
            customer.expiry = renewal_expiry(customer, now, expiry_delta)
        else:
            customer.expiry = now + expiry_delta

        customer.status = CustomerStatus.ACTIVE

        payment = manual_activation_ledger_row(
            customer, plan, user, request, no_payment=no_payment, pm_enum=pm_enum,
            days_paid_for=days_paid_for, default_note="PPPoE activation via admin",
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
            f"({manual_activation_event_text(user, pm_enum, no_payment=no_payment, forced=forced, free_trial=is_free_trial_plan(plan))}); router "
            + ("updated" if provision_succeeded else
               f"not updated yet: {(provision_result or {}).get('error') or 'will retry'}"),
            severity="info" if provision_succeeded else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
            details={"payment_id": payment.id, "reference": payment.payment_reference,
                     "provision_result": "ok" if provision_succeeded else "retry_pending",
                     "forced": forced, "no_payment": no_payment,
                     "free_trial": is_free_trial_plan(plan)},
        )

        return {
            "success": True,
            "customer_id": customer.id,
            "pppoe_username": customer.pppoe_username,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_name": plan.name,
            "payment_recorded": not no_payment,
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
        router_removal_pending = False
        if customer.router:
            payload = build_pppoe_remove_payload(customer, customer.router)
            # The safety net (reconcile_inactive_pppoe_access_background) only
            # covers direct-API routers.
            deferrable = customer.router.auth_method != RouterAuthMethod.RADIUS
            await db.commit()
            remove_result = await call_pppoe_remove(payload)
            if not remove_result or not remove_result.get("success"):
                error = (
                    remove_result.get("error") or "Router cleanup did not confirm success"
                    if isinstance(remove_result, dict)
                    else "PPPoE removal returned no result"
                )
            if (
                deferrable
                and isinstance(remove_result, dict)
                and remove_result.get("error") == "Failed to connect to router"
            ):
                # Router unreachable (CR-1123-B8): deactivate in billing now. The
                # inactive-PPPoE safety net removes the secret and any session
                # once the router is back, then records the success log that
                # stops it repeating; until then there is no success log here.
                router_removal_pending = True
                logger.warning(
                    "PPPoE customer %s deactivated while router %s is unreachable; "
                    "router removal deferred to the inactive-PPPoE safety net",
                    customer_id,
                    customer.router_id,
                )
            elif not remove_result or not remove_result.get("success"):
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
        elif router_removal_pending:
            db.add(ProvisioningLog(
                customer_id=customer.id,
                router_id=customer.router_id,
                action="pppoe_deactivation",
                status="pending",
                details=(
                    "Manual deactivation while the router was unreachable; the "
                    "inactive-PPPoE safety net removes the secret when it is back"
                ),
            ))
        await db.commit()
        await record_customer_event(
            customer.id, "pppoe_deactivated",
            (
                "PPPoE deactivated in Bitwave; the router was unreachable, so the "
                "secret and session are removed when it is back online"
                if router_removal_pending
                else "PPPoE deactivated: session disconnected and secret removed from the router"
            ),
            severity="warning" if router_removal_pending else "info",
            actor=user, user_id=user.id, router_id=customer.router_id,
        )

        if router_removal_pending:
            message = (
                "The customer is deactivated in Bitwave. Their router is offline right "
                "now, so their PPPoE login will be removed from the router automatically "
                "when it is back online. Nothing else needs to be done."
            )
        elif remove_result:
            message = "The customer is deactivated and removed from the router."
        else:
            message = "The customer is deactivated in Bitwave."
        return {
            "success": True,
            "customer_id": customer.id,
            "status": customer.status.value,
            "remove_result": (
                "pending" if router_removal_pending
                else "ok" if remove_result and remove_result.get("success") else "failed"
            ),
            "remove_error": remove_result.get("error") if remove_result else None,
            "router_removal_pending": router_removal_pending,
            "message": message,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating PPPoE customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to deactivate PPPoE customer: {str(e)}")


# =========================================================================
# PAUSE / RESUME (PPPoE and static IP) -- app/services/customer_pause.py
# =========================================================================

class PauseCustomerRequest(BaseModel):
    # Optional: resume automatically at this time (UTC if no timezone given).
    resume_at: Optional[datetime] = None


def _require_customers_manage() -> None:
    """Staff need ``customers.manage`` to pause/resume.

    Works with or without the staff-roles change (#272): when it is not
    deployed there are no staff sessions and this is a no-op. Its route map
    is deny-by-default, so staff also need the two pause/resume routes listed
    there under ``customers.manage``.
    """
    try:
        from app.services.staff_access import require_permission
    except ImportError:
        return
    require_permission("customers.manage")


def _pause_http_error(exc: PauseError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/api/customers/{customer_id}/pause")
async def pause_customer_api(
    customer_id: int,
    request: Optional[PauseCustomerRequest] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Pause a PPPoE or static-IP customer and keep their remaining paid time.

    The router is updated first (PPPoE: secret removed and session dropped;
    static IP: access suspended); the pause is recorded only after the router
    confirms. Pausing an already paused customer changes nothing.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    _require_customers_manage()
    await db.commit()
    try:
        return await pause_customer(
            customer_id, actor=user, resume_at=request.resume_at if request else None,
        )
    except PauseError as exc:
        raise _pause_http_error(exc)


@router.post("/api/customers/{customer_id}/resume")
async def resume_customer_api(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Resume a paused customer: new expiry = now + the paused time, router back on.

    Same username and password, so the customer's device just dials again.
    """
    user = await get_current_user(token, db)
    enforce_active_subscription(user)
    _require_customers_manage()
    await db.commit()
    try:
        return await resume_customer(customer_id, actor=user)
    except PauseError as exc:
        raise _pause_http_error(exc)


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


@router.post("/api/customers/{customer_id}/activate-hotspot")
async def activate_hotspot_customer(
    customer_id: int,
    request: ActivatePPPoERequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Give a hotspot customer their plan's time without an M-Pesa payment: cash or money
    taken outside the system, or no payment at all (payment_method "none": a free
    period, a comp, a test). Sets ACTIVE with the plan's expiry and lets the customer's
    device (its MAC) onto the router, exactly as a paid hotspot purchase does. The
    customer needs a device MAC and a router; register them first if they are new.
    """
    from app.services.hotspot_provisioning import log_provisioning_event, provision_hotspot_customer

    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id, Customer.user_id == user.id)
        )
        customer = (await db.execute(stmt)).scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        if not customer.plan:
            raise HTTPException(status_code=400, detail="Customer has no plan assigned")
        if customer.plan.connection_type in (ConnectionType.PPPOE, ConnectionType.STATIC_IP):
            raise HTTPException(status_code=400, detail="This customer is not on a hotspot plan: use activate-pppoe or activate-static")
        if not customer.mac_address:
            raise HTTPException(status_code=400, detail="Customer has no device MAC address: add the phone or device MAC first")
        if not customer.router:
            raise HTTPException(status_code=400, detail="Customer has no router assigned")

        plan = customer.plan
        no_payment = is_no_payment_activation(request.payment_method) or is_free_trial_plan(plan)
        pm_enum = PaymentMethod.OTHER if no_payment else manual_activation_payment_method(request.payment_method)
        now = datetime.utcnow()
        forced = await refuse_duplicate_manual_activation(db, customer, request, now, no_payment=no_payment)

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

        # An active customer (paid time or grace) keeps their billing date.
        if customer.status == CustomerStatus.ACTIVE:
            customer.expiry = renewal_expiry(customer, now, expiry_delta)
        else:
            customer.expiry = now + expiry_delta
        customer.status = CustomerStatus.ACTIVE

        payment = manual_activation_ledger_row(
            customer, plan, user, request, no_payment=no_payment, pm_enum=pm_enum,
            days_paid_for=days_paid_for, default_note="Hotspot activation via admin",
        )
        db.add(payment)
        try:
            from app.services.usage_tracking import on_renewal

            await on_renewal(db, customer, plan=plan, now=now)
        except Exception as renew_err:
            logger.error(f"[USAGE] on_renewal failed in hotspot activation for customer {customer.id}: {renew_err}")

        await db.commit()
        await db.refresh(customer, attribute_names=["plan", "router"])

        router_obj = customer.router
        attempt = await get_or_create_provisioning_attempt(
            db,
            customer_id=customer.id,
            router_id=router_obj.id,
            mac_address=customer.mac_address,
            source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
            source_pk=payment.id,
            external_reference=request.payment_reference,
            entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        )
        await schedule_provisioning_attempt(db, attempt)
        await db.commit()
        await log_provisioning_event(
            customer_id=customer.id, router_id=router_obj.id, mac_address=customer.mac_address,
            action="hotspot_payment", status="scheduled",
            details="Manual hotspot activation from the dashboard", attempt_id=attempt.id,
        )

        hotspot_payload = build_hotspot_payload(customer, plan, router_obj, comment=f"Activated for {customer.name}")
        provision_result = await provision_hotspot_customer(
            customer.id, router_obj.id, hotspot_payload, "hotspot_payment", attempt.id,
        )
        provision_succeeded = bool(provision_result and provision_result.get("success"))
        await record_customer_event(
            customer.id, "hotspot_activated",
            f"Hotspot activated on {plan.name} until {customer.expiry:%Y-%m-%d %H:%M} UTC "
            f"({manual_activation_event_text(user, pm_enum, no_payment=no_payment, forced=forced, free_trial=is_free_trial_plan(plan))}); router "
            + ("updated" if provision_succeeded else
               f"not updated yet: {(provision_result or {}).get('error') or 'will retry'}"),
            severity="info" if provision_succeeded else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
            details={"payment_id": payment.id, "reference": payment.payment_reference,
                     "provision_result": "ok" if provision_succeeded else "retry_pending",
                     "forced": forced, "no_payment": no_payment, "free_trial": is_free_trial_plan(plan)},
        )
        return {
            "success": True,
            "customer_id": customer.id,
            "mac_address": customer.mac_address,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_name": plan.name,
            "payment_recorded": not no_payment,
            "provision_result": "ok" if provision_succeeded else "retry_pending",
            "provision_error": provision_result.get("error") if provision_result else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Hotspot activation failed for customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail="Hotspot activation failed")


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
        no_payment = is_no_payment_activation(request.payment_method)
        pm_enum = (
            PaymentMethod.OTHER if no_payment
            else manual_activation_payment_method(request.payment_method)
        )
        now = datetime.utcnow()
        forced = await refuse_duplicate_manual_activation(db, customer, request, now)

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

        # An active customer (paid time or grace) keeps their billing date.
        if customer.status == CustomerStatus.ACTIVE:
            customer.expiry = renewal_expiry(customer, now, expiry_delta)
        else:
            customer.expiry = now + expiry_delta
        customer.status = CustomerStatus.ACTIVE

        payment = manual_activation_ledger_row(
            customer, plan, user, request, no_payment=no_payment, pm_enum=pm_enum,
            days_paid_for=days_paid_for, default_note="Static IP activation via admin",
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
            f"({manual_activation_event_text(user, pm_enum, no_payment=no_payment, forced=forced)}); router "
            + ("updated" if ok else f"not updated yet: {result.get('error') or 'will retry'}"),
            severity="info" if ok else "warning",
            actor=user, user_id=user.id, router_id=customer.router_id,
            details={"payment_id": payment.id, "reference": payment.payment_reference,
                     "forced": forced, "no_payment": no_payment},
        )
        return {
            "success": True,
            "customer_id": customer.id,
            "status": CustomerStatus.ACTIVE.value,
            "expiry": expiry.isoformat() if expiry else None,
            "plan_name": plan.name,
            "payment_recorded": not no_payment,
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
    """Live router view of a static-IP customer: access, speed queue, pin, device.

    actual_access / in_sync say whether the router lets the customer through.
    device_online says whether their device answers the router right now (its ARP
    entry, traffic on the queue); device_note says why not. "Is X offline" is
    device_online, never access: access can be enabled while the device is off.
    """
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
    device = router_state.get("device") or {}
    return {
        **info,
        "router": router_state,
        "actual_access": actual_access,
        "in_sync": actual_access == info["expected_access"] and bool(router_state.get("queue")),
        "device_online": None if router_state.get("error") or not device else device.get("online"),
        "device_note": (
            "unknown: the router could not be read" if router_state.get("error") or not device
            else "the device answers the router" if device.get("online")
            else device.get("reason") or "the device is not answering the router"
        ),
    }


@router.get("/api/customers/{customer_id}/pppoe-credentials")
async def get_pppoe_credentials(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """A PPPoE customer's login: the username and password typed into their own router, plus the
    MikroTik it dials and the ports PPPoE runs on there. The reseller gives this to the customer."""
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
            "router_id": customer.router_id,
            # the router ports the customer's own router plugs into (its WAN port to one of these)
            "pppoe_ports": list(customer.router.pppoe_ports or []) if customer.router else [],
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

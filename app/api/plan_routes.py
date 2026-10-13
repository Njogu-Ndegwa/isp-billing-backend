from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, case, or_
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import asyncio
import json

from app.db.database import get_db
from app.db.models import (
    Plan, Customer, CustomerStatus, ConnectionType, DurationUnit, CustomerPayment, PlanType, Router, FupAction,
    CustomerUsagePeriod, Voucher, VoucherStatus, DevicePairing,
    MpesaTransaction, MpesaTransactionStatus, ZenoPayTransaction, ZenoPayTransactionStatus,
    MtnMomoTransaction, MtnMomoTransactionStatus, FapshiTransaction, FapshiTransactionStatus,
)
from app.services.auth import verify_token, get_current_user
from app.services.plan_cache import (
    get_plans_cached,
    invalidate_plan_cache,
    normalize_router_ids,
    plan_allows_router,
)
from app.services.subscription import enforce_active_subscription
from app.services.payment_plan import payment_plan_id
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["plans"])

VALID_PLAN_TYPES = [pt.value for pt in PlanType]
VALID_FUP_ACTIONS = [a.value for a in FupAction]
MAX_SHARED_USERS_LIMIT = 50


def _parse_fup_action(value: Optional[str]) -> Optional[FupAction]:
    if value is None or value == "":
        return None
    if value.lower() not in VALID_FUP_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid fup_action. Must be one of: {', '.join(VALID_FUP_ACTIONS)}",
        )
    return FupAction(value.lower())


async def _loosen_open_period_caps(db: AsyncSession, plan_id: int, new_cap_mb: Optional[int]) -> int:
    """Carry a removed or raised plan cap into customers' open usage periods.

    Periods snapshot the cap when they open, so without this a reseller who
    lifts a cap still sees their customers throttled until each one renews.
    Only ever loosens: a lowered cap still waits for the next period. The cap
    sampler then lifts any throttle that is no longer over the cap.
    """
    customer_ids = select(Customer.id).where(Customer.plan_id == plan_id)
    conditions = [
        CustomerUsagePeriod.customer_id.in_(customer_ids),
        CustomerUsagePeriod.closed_at.is_(None),
        CustomerUsagePeriod.cap_mb_snapshot.isnot(None),
    ]
    if new_cap_mb is not None:
        conditions.append(CustomerUsagePeriod.cap_mb_snapshot < new_cap_mb)
    result = await db.execute(
        update(CustomerUsagePeriod)
        .where(*conditions)
        .values(cap_mb_snapshot=new_cap_mb)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount or 0


def _serialize_plan_fup(plan: Plan) -> dict:
    return {
        "data_cap_mb": plan.data_cap_mb,
        "fup_action": plan.fup_action.value if plan.fup_action else None,
        "fup_throttle_profile": plan.fup_throttle_profile,
    }


def _request_fields_set(model: BaseModel) -> set[str]:
    return set(
        getattr(model, "model_fields_set", None)
        or getattr(model, "__fields_set__", set())
    )


def _validate_max_shared_users(value: Optional[int]) -> int:
    if value is None:
        return 1
    if value < 1:
        raise HTTPException(status_code=400, detail="max_shared_users must be at least 1")
    if value > MAX_SHARED_USERS_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"max_shared_users cannot exceed {MAX_SHARED_USERS_LIMIT}",
        )
    return value


def _serialize_plan_sharing(plan: Plan) -> dict:
    max_shared_users = int(plan.max_shared_users or 1)
    return {
        "max_shared_users": max_shared_users,
        "sharing_enabled": max_shared_users > 1,
    }


def _serialize_plan_routers(plan: Plan) -> dict:
    router_ids = normalize_router_ids(getattr(plan, "router_ids", None))
    return {
        "router_ids": router_ids,
        "all_routers": router_ids is None,
    }


def _serialize_plan_trial(plan: Plan) -> dict:
    return {"trial_once_per_customer": bool(plan.trial_once_per_customer)}


def _validate_free_trial_plan(plan: Plan) -> None:
    """Free trials are claimed from the captive portal at no charge, so the
    plan must be free and must be a hotspot plan (PPPoE customers have no
    portal to claim from). Like any hotspot plan, ``max_shared_users`` sets how
    many devices the claimed trial covers."""
    if plan.plan_type != PlanType.FREE_TRIAL:
        return
    if plan.price:
        raise HTTPException(status_code=400, detail="A free trial plan must have a price of 0")
    if plan.connection_type != ConnectionType.HOTSPOT:
        raise HTTPException(status_code=400, detail="Free trial plans are only available for hotspot")


async def _validate_router_scope(
    db: AsyncSession,
    user_id: int,
    router_ids,
) -> Optional[List[int]]:
    """Validate a requested per-router plan scope and return it normalised.

    None/[] both mean "every router this reseller owns" — the default. Anything
    else must reference routers the caller actually owns, otherwise a typo would
    silently hide the plan from the whole fleet.
    """
    normalized = normalize_router_ids(router_ids)
    if normalized is None:
        return None

    owned_result = await db.execute(
        select(Router.id).where(Router.user_id == user_id, Router.id.in_(normalized))
    )
    owned = {row[0] for row in owned_result}
    unknown = [rid for rid in normalized if rid not in owned]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unknown router(s) for this account: "
                f"{', '.join(str(r) for r in unknown)}"
            ),
        )
    return normalized


class PlanCreateRequest(BaseModel):
    name: str
    speed: str
    price: int
    duration_value: int
    duration_unit: str
    connection_type: str
    router_profile: Optional[str] = None
    plan_type: Optional[str] = "regular"
    is_hidden: Optional[bool] = False
    badge_text: Optional[str] = None
    original_price: Optional[int] = None
    valid_until: Optional[str] = None
    data_cap_mb: Optional[int] = None
    fup_action: Optional[str] = None
    fup_throttle_profile: Optional[str] = None
    max_shared_users: Optional[int] = 1
    # Omit or send null/[] to offer the plan on every router the reseller owns.
    router_ids: Optional[List[int]] = None
    # Free-trial plans only: True = each device may claim it once,
    # False = it may claim again once its previous trial has ended.
    trial_once_per_customer: Optional[bool] = True


class PlanUpdateRequest(BaseModel):
    name: Optional[str] = None
    speed: Optional[str] = None
    price: Optional[int] = None
    duration_value: Optional[int] = None
    duration_unit: Optional[str] = None
    connection_type: Optional[str] = None
    router_profile: Optional[str] = None
    plan_type: Optional[str] = None
    is_hidden: Optional[bool] = None
    badge_text: Optional[str] = None
    original_price: Optional[int] = None
    valid_until: Optional[str] = None
    data_cap_mb: Optional[int] = None
    fup_action: Optional[str] = None
    fup_throttle_profile: Optional[str] = None
    max_shared_users: Optional[int] = None
    # Send null/[] to revert the plan to "all routers". Only applied when the
    # field is actually present in the request body.
    router_ids: Optional[List[int]] = None
    trial_once_per_customer: Optional[bool] = None


@router.post("/api/plans/create")
async def create_plan_api(
    request: PlanCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new internet plan"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        
        # Validate price and duration
        if request.price < 0:
            raise HTTPException(status_code=400, detail="Price cannot be negative")
        if request.duration_value < 1:
            raise HTTPException(status_code=400, detail="Duration value must be at least 1")
        
        # Validate connection type
        try:
            connection_type_enum = ConnectionType(request.connection_type.lower())
        except ValueError:
            valid_types = [ct.value for ct in ConnectionType]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid connection type. Must be one of: {', '.join(valid_types)}"
            )
        
        # Validate duration unit
        try:
            duration_unit_enum = DurationUnit(request.duration_unit.upper())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid duration unit. Must be 'DAYS' or 'HOURS'"
            )
        
        # Validate plan_type
        plan_type_enum = PlanType.REGULAR
        if request.plan_type:
            if request.plan_type.lower() not in VALID_PLAN_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid plan_type. Must be one of: {', '.join(VALID_PLAN_TYPES)}"
                )
            plan_type_enum = PlanType(request.plan_type.lower())

        # Parse valid_until if provided
        valid_until_dt = None
        if request.valid_until:
            try:
                valid_until_dt = datetime.fromisoformat(request.valid_until.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid valid_until format. Use ISO 8601.")

        # Check for duplicate plan name
        existing_plan_stmt = select(Plan).filter(
            Plan.name == request.name,
            Plan.user_id == user.id
        )
        existing_result = await db.execute(existing_plan_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Plan with this name already exists")
        
        fup_action_enum = _parse_fup_action(request.fup_action)
        if request.data_cap_mb is not None and request.data_cap_mb < 0:
            raise HTTPException(status_code=400, detail="data_cap_mb cannot be negative")
        max_shared_users = _validate_max_shared_users(request.max_shared_users)
        scoped_router_ids = await _validate_router_scope(db, user.id, request.router_ids)

        plan = Plan(
            name=request.name,
            speed=request.speed,
            price=request.price,
            duration_value=request.duration_value,
            duration_unit=duration_unit_enum,
            connection_type=connection_type_enum,
            user_id=user.id,
            router_profile=request.router_profile,
            plan_type=plan_type_enum,
            is_hidden=request.is_hidden or False,
            badge_text=request.badge_text,
            original_price=request.original_price,
            valid_until=valid_until_dt,
            data_cap_mb=request.data_cap_mb,
            fup_action=fup_action_enum,
            fup_throttle_profile=request.fup_throttle_profile,
            max_shared_users=max_shared_users,
            router_ids=scoped_router_ids,
            trial_once_per_customer=(
                request.trial_once_per_customer
                if request.trial_once_per_customer is not None
                else True
            ),
        )
        _validate_free_trial_plan(plan)

        db.add(plan)
        await db.commit()
        await db.refresh(plan)
        
        await invalidate_plan_cache()
        
        logger.info(f"Plan created: {plan.id} (type={plan.plan_type.value}) by user {user.id}")
        
        return {
            "id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "price": plan.price,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "connection_type": plan.connection_type.value,
            "router_profile": plan.router_profile,
            "user_id": plan.user_id,
            "plan_type": plan.plan_type.value,
            "is_hidden": plan.is_hidden,
            "badge_text": plan.badge_text,
            "original_price": plan.original_price,
            "valid_until": plan.valid_until.isoformat() if plan.valid_until else None,
            "created_at": plan.created_at.isoformat(),
            **_serialize_plan_fup(plan),
            **_serialize_plan_sharing(plan),
            **_serialize_plan_routers(plan),
            **_serialize_plan_trial(plan),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create plan: {str(e)}")


@router.get("/api/plans")
async def get_plans_api(
    connection_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all plans for the authenticated user with optional connection_type filter - CACHED.
    Admin/reseller sees all plans including hidden ones."""
    try:
        user = await get_current_user(token, db)
        return await get_plans_cached(db, user.id, connection_type, include_hidden=True)
    except Exception as e:
        logger.error(f"Error fetching plans: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch plans")


@router.get("/api/plans/by-router/{router_id}")
async def get_plans_for_router_api(
    router_id: int,
    connection_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Plans offered on one of the caller's routers, including hidden ones.

    Backs the "Plans on this router" panel on the Routers page. Includes both
    plans scoped to this router and fleet-wide plans, flagged so the UI can tell
    them apart.
    """
    try:
        user = await get_current_user(token, db)

        router_result = await db.execute(
            select(Router).where(Router.id == router_id, Router.user_id == user.id)
        )
        router_obj = router_result.scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or does not belong to you")

        all_plans = await get_plans_cached(db, user.id, connection_type, include_hidden=True)
        offered = [p for p in all_plans if plan_allows_router(p, router_id)]

        return {
            "router_id": router_id,
            "router_name": router_obj.name,
            "emergency_active": bool(router_obj.emergency_active),
            "plans": [
                {**p, "scoped_to_this_router": p.get("router_ids") is not None}
                for p in offered
            ],
            "total_plans": len(all_plans),
            "offered_here": len(offered),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching plans for router {router_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch plans for router")


@router.put("/api/plans/{plan_id}")
async def update_plan_api(
    plan_id: int,
    request: PlanUpdateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Update an existing plan"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        stmt = select(Plan).where(Plan.id == plan_id, Plan.user_id == user.id)
        result = await db.execute(stmt)
        plan = result.scalar_one_or_none()
        
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        if request.name is not None:
            plan.name = request.name
        previous_speed = plan.speed
        if request.speed is not None:
            plan.speed = request.speed
        if request.price is not None:
            plan.price = request.price
        if request.duration_value is not None:
            plan.duration_value = request.duration_value
        if request.duration_unit is not None:
            try:
                plan.duration_unit = DurationUnit(request.duration_unit.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid duration_unit. Must be MINUTES, HOURS, or DAYS")
        if request.connection_type is not None:
            try:
                plan.connection_type = ConnectionType(request.connection_type.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid connection_type")
        if request.router_profile is not None:
            plan.router_profile = request.router_profile
        if request.plan_type is not None:
            if request.plan_type.lower() not in VALID_PLAN_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid plan_type. Must be one of: {', '.join(VALID_PLAN_TYPES)}"
                )
            plan.plan_type = PlanType(request.plan_type.lower())
        if request.is_hidden is not None:
            plan.is_hidden = request.is_hidden
        if request.badge_text is not None:
            plan.badge_text = request.badge_text if request.badge_text != "" else None
        if request.original_price is not None:
            plan.original_price = request.original_price
        if request.valid_until is not None:
            try:
                plan.valid_until = datetime.fromisoformat(request.valid_until.replace('Z', '+00:00')) if request.valid_until != "" else None
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid valid_until format. Use ISO 8601.")
        fields_set = _request_fields_set(request)
        if "data_cap_mb" in fields_set:
            if request.data_cap_mb is not None and request.data_cap_mb < 0:
                raise HTTPException(status_code=400, detail="data_cap_mb cannot be negative")
            plan.data_cap_mb = (
                request.data_cap_mb
                if request.data_cap_mb is not None and request.data_cap_mb > 0
                else None
            )
            loosened = await _loosen_open_period_caps(db, plan.id, plan.data_cap_mb)
            if loosened:
                logger.info(
                    f"Plan {plan_id}: cap now {plan.data_cap_mb} MB, "
                    f"loosened {loosened} open usage period(s)"
                )
        if "fup_action" in fields_set:
            plan.fup_action = _parse_fup_action(request.fup_action)
        if "fup_throttle_profile" in fields_set:
            plan.fup_throttle_profile = request.fup_throttle_profile if request.fup_throttle_profile else None
        previous_max_devices = int(plan.max_shared_users or 1)
        if request.max_shared_users is not None:
            plan.max_shared_users = _validate_max_shared_users(request.max_shared_users)
        is_pppoe = plan.connection_type == ConnectionType.PPPOE
        pppoe_speed_changed = is_pppoe and (plan.speed or "") != (previous_speed or "")
        pppoe_devices_changed = is_pppoe and int(plan.max_shared_users or 1) != previous_max_devices
        if "router_ids" in fields_set:
            plan.router_ids = await _validate_router_scope(db, user.id, request.router_ids)
        if request.trial_once_per_customer is not None:
            plan.trial_once_per_customer = request.trial_once_per_customer
        _validate_free_trial_plan(plan)

        await db.commit()
        await db.refresh(plan)
        await invalidate_plan_cache()

        if pppoe_speed_changed or pppoe_devices_changed:
            # A PPPoE customer's speed and device count live on their router
            # (the PPP profile); push them in the background, never on this
            # request, or customers keep the old ones until they pay again.
            from app.services.pppoe_provisioning import reprovision_plan_pppoe_customers

            asyncio.create_task(
                reprovision_plan_pppoe_customers(plan.id, speed_changed=pppoe_speed_changed)
            )

        logger.info(f"Plan {plan_id} updated: type={plan.plan_type.value}, hidden={plan.is_hidden}")
        
        return {
            "id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "price": plan.price,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "connection_type": plan.connection_type.value,
            "router_profile": plan.router_profile,
            "plan_type": plan.plan_type.value,
            "is_hidden": plan.is_hidden,
            "badge_text": plan.badge_text,
            "original_price": plan.original_price,
            "valid_until": plan.valid_until.isoformat() if plan.valid_until else None,
            **_serialize_plan_fup(plan),
            **_serialize_plan_sharing(plan),
            **_serialize_plan_routers(plan),
            **_serialize_plan_trial(plan),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update plan: {str(e)}")


# A pending M-Pesa payment is still reconciled (and can complete) for this long
# before it is expired — see reconcile_pending_transactions in mpesa_transactions.
IN_FLIGHT_PAYMENT_WINDOW = timedelta(hours=2)

# (transaction model, statuses that mean "customer may still be charged")
_IN_FLIGHT_PAYMENT_SOURCES = (
    (MpesaTransaction, (MpesaTransactionStatus.pending,)),
    (ZenoPayTransaction, (ZenoPayTransactionStatus.PENDING,)),
    (MtnMomoTransaction, (MtnMomoTransactionStatus.PENDING,)),
    (FapshiTransaction, (FapshiTransactionStatus.CREATED, FapshiTransactionStatus.PENDING)),
)


def _pending_plan_id(data) -> Optional[int]:
    """Plan an existing customer is switching to while their payment is pending."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return None
    if isinstance(data, dict):
        try:
            return int(data["plan_id"])
        except (KeyError, TypeError, ValueError):
            return None
    return None


async def _count_in_flight_payments(db: AsyncSession, plan_id: int, owner_id: int) -> int:
    """Payments for this plan that the provider may still confirm.

    On confirmation the plan is read from the customer's pending_update_data or
    plan_id (M-Pesa also snapshots it on the transaction). If the plan is
    deleted in between, the customer is charged but never provisioned.
    """
    cutoff = datetime.utcnow() - IN_FLIGHT_PAYMENT_WINDOW
    count = 0

    for model, statuses in _IN_FLIGHT_PAYMENT_SOURCES:
        snapshot = getattr(model, "plan_id", None)
        owned = Customer.user_id == owner_id
        stmt = (
            select(Customer.plan_id, Customer.pending_update_data, snapshot if snapshot is not None else model.id)
            .select_from(model)
            .outerjoin(Customer, Customer.id == model.customer_id)
            .where(
                model.status.in_(statuses),
                model.created_at > cutoff,
                or_(owned, snapshot == plan_id) if snapshot is not None else owned,
            )
        )
        for customer_plan_id, pending_data, snapshot_plan_id in (await db.execute(stmt)).all():
            # Mirrors the confirmation: the pending plan wins, else the current one
            pending_plan_id = _pending_plan_id(pending_data)
            charged_plan_id = pending_plan_id if pending_plan_id is not None else customer_plan_id
            if charged_plan_id == plan_id or (snapshot is not None and snapshot_plan_id == plan_id):
                count += 1

    return count

@router.delete("/api/plans/{plan_id}")
async def delete_plan(
    plan_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Delete a plan (only if no active customers using it)"""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        
        # Check if plan exists
        plan_stmt = select(Plan).where(Plan.id == plan_id, Plan.user_id == user.id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Check for active customers using this plan
        active_stmt = select(func.count(Customer.id)).where(
            Customer.plan_id == plan_id,
            Customer.status == CustomerStatus.ACTIVE
        )
        active_result = await db.execute(active_stmt)
        active_count = active_result.scalar()
        
        if active_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete plan. {active_count} active customer(s) are using this plan"
            )
        
        in_flight = await _count_in_flight_payments(db, plan_id, user.id)
        if in_flight > 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Cannot delete plan. {in_flight} customer payment(s) for this plan are still being confirmed. "
                    "Hide the plan now and try deleting it again later"
                )
            )

        # Unused vouchers may already be printed and sold; deleting the plan
        # would make them unredeemable, so the reseller must disable them first.
        unused_stmt = select(func.count(Voucher.id)).where(
            Voucher.plan_id == plan_id,
            Voucher.status == VoucherStatus.AVAILABLE
        )
        unused_count = (await db.execute(unused_stmt)).scalar()

        if unused_count > 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Cannot delete plan. {unused_count} unused voucher(s) still exist for this plan. "
                    "Disable them first, or hide the plan instead"
                )
            )

        # Detach history rows (inactive/expired customers, used vouchers, paired
        # devices) so they survive the plan instead of blocking the delete
        for model in (Customer, Voucher, DevicePairing):
            await db.execute(
                update(model).where(model.plan_id == plan_id).values(plan_id=None)
            )
        
        await db.delete(plan)
        await db.commit()
        
        # Invalidate plan cache after deletion
        await invalidate_plan_cache()
        
        return {
            "success": True,
            "message": f"Plan '{plan.name}' deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete plan: {str(e)}")


@router.get("/api/plans/performance")
async def get_plan_performance(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get performance metrics for each plan
    
    Shows:
    - Total sales per plan, and how many customers made them
    - Revenue per plan
    - Average revenue per sale
    - Current active customers per plan
    """
    try:
        user = await get_current_user(token, db)
        
        # The period's payments, each tagged with the plan it bought (not the
        # customer's current plan). Filtering here rather than on the outer
        # query keeps plans with no sales in the period in the result.
        payments = select(
            CustomerPayment.id,
            CustomerPayment.customer_id,
            CustomerPayment.amount,
            CustomerPayment.counts_as_revenue,
            payment_plan_id().label('plan_id'),
        ).outerjoin(
            Customer, CustomerPayment.customer_id == Customer.id
        ).where(
            CustomerPayment.reseller_id == user.id
        )

        # Apply date filters if provided
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            payments = payments.where(CustomerPayment.created_at >= start_dt)

        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if 'T' not in end_date:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            payments = payments.where(CustomerPayment.created_at <= end_dt)

        payments = payments.subquery()

        stmt = select(
            Plan.id,
            Plan.name,
            Plan.price,
            Plan.duration_value,
            Plan.duration_unit,
            func.count(payments.c.customer_id.distinct()).label('total_customers'),
            func.count(payments.c.id).label('total_sales'),
            # Count every sale, but exclude compensation vouchers
            # (counts_as_revenue=False) from the revenue amount.
            func.sum(
                case(
                    (payments.c.counts_as_revenue == True, payments.c.amount),
                    else_=0,
                )
            ).label('total_revenue')
        ).outerjoin(
            payments, payments.c.plan_id == Plan.id
        ).where(
            Plan.user_id == user.id
        ).group_by(Plan.id, Plan.name, Plan.price, Plan.duration_value, Plan.duration_unit)
        
        result = await db.execute(stmt)
        
        # Get active customers per plan
        active_stmt = select(
            Plan.id,
            func.count(Customer.id).label('active_count')
        ).join(
            Customer, Customer.plan_id == Plan.id
        ).where(
            Plan.user_id == user.id,
            Customer.status == CustomerStatus.ACTIVE
        ).group_by(Plan.id)
        
        active_result = await db.execute(active_stmt)
        active_counts = {row.id: row.active_count for row in active_result}
        
        plans = []
        for row in result:
            total_revenue = float(row.total_revenue or 0)
            total_sales = row.total_sales or 0
            avg_revenue = total_revenue / total_sales if total_sales > 0 else 0
            
            plans.append({
                "plan_id": row.id,
                "plan_name": row.name,
                "plan_price": row.price,
                "duration": f"{row.duration_value} {row.duration_unit.lower()}",
                "total_customers": row.total_customers,
                "total_sales": total_sales,
                "total_revenue": total_revenue,
                "average_revenue_per_sale": round(avg_revenue, 2),
                "active_customers": active_counts.get(row.id, 0)
            })
        
        return {
            "plans": plans,
            "period": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching plan performance: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch plan performance: {str(e)}")


class EmergencyActivateRequest(BaseModel):
    router_id: int
    message: Optional[str] = None


class EmergencyDeactivateRequest(BaseModel):
    router_id: int


@router.post("/api/plans/activate-emergency")
async def activate_emergency_mode(
    request: EmergencyActivateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Activate emergency mode on a specific router.

    Only this router's flag is written. Which plans the portal then offers is
    decided per router at read time (see select_portal_plans), so turning
    emergency on here no longer changes what the reseller's other routers show.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = select(Router).where(Router.id == request.router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or does not belong to you")

        router_obj.emergency_active = True
        router_obj.emergency_message = request.message

        emergency_available = await db.scalar(
            select(func.count(Plan.id)).where(
                Plan.user_id == user.id,
                Plan.plan_type == PlanType.EMERGENCY,
            )
        )

        await db.commit()
        await invalidate_plan_cache()

        logger.info(
            f"Emergency mode activated on router {request.router_id} by user {user.id}: "
            f"{emergency_available} emergency plan(s) available for this router"
        )

        return {
            "success": True,
            "message": "Emergency mode activated",
            "router_id": request.router_id,
            "emergency_message": request.message,
            "emergency_plans_available": emergency_available or 0,
            # Kept for existing dashboard clients. Emergency mode no longer edits
            # plan rows, so nothing is hidden fleet-wide any more.
            "regular_plans_hidden": 0,
            "emergency_plans_shown": emergency_available or 0,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating emergency mode: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to activate emergency mode: {str(e)}")


@router.post("/api/plans/deactivate-emergency")
async def deactivate_emergency_mode(
    request: EmergencyDeactivateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Deactivate emergency mode on a specific router.

    Clears this router's flag only. It also repairs the one side effect the old
    fleet-wide implementation left behind: that version hid EVERY regular plan
    when emergency was switched on anywhere, so a reseller who was mid-emergency
    at upgrade time would otherwise be left with an empty portal on their other
    routers. The repair is deliberately narrow — it runs only when every regular
    plan is hidden (the signature of the old mass update) and no other router is
    still in emergency mode, so a plan the reseller hid by hand stays hidden.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)

        stmt = select(Router).where(Router.id == request.router_id, Router.user_id == user.id)
        result = await db.execute(stmt)
        router_obj = result.scalar_one_or_none()
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found or does not belong to you")

        router_obj.emergency_active = False
        router_obj.emergency_message = None

        still_in_emergency = await db.scalar(
            select(func.count(Router.id)).where(
                Router.user_id == user.id,
                Router.id != request.router_id,
                Router.emergency_active == True,
            )
        )
        regular_total = await db.scalar(
            select(func.count(Plan.id)).where(
                Plan.user_id == user.id, Plan.plan_type == PlanType.REGULAR
            )
        )
        regular_hidden = await db.scalar(
            select(func.count(Plan.id)).where(
                Plan.user_id == user.id,
                Plan.plan_type == PlanType.REGULAR,
                Plan.is_hidden == True,
            )
        )

        restored = 0
        if not still_in_emergency and regular_total and regular_hidden == regular_total:
            restore_result = await db.execute(
                update(Plan)
                .where(Plan.user_id == user.id, Plan.plan_type == PlanType.REGULAR)
                .values(is_hidden=False)
            )
            restored = restore_result.rowcount

        await db.commit()
        await invalidate_plan_cache()

        logger.info(
            f"Emergency mode deactivated on router {request.router_id} by user {user.id}: "
            f"{restored} regular plan(s) un-hidden by legacy repair"
        )

        return {
            "success": True,
            "message": "Emergency mode deactivated. Regular plans restored.",
            "router_id": request.router_id,
            "regular_plans_shown": restored,
            # Emergency plans are now excluded per router at read time instead of
            # being hidden fleet-wide, so nothing is written here.
            "emergency_plans_hidden": 0,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating emergency mode: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to deactivate emergency mode: {str(e)}")

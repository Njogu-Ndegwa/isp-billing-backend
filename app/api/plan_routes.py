from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Plan, Customer, CustomerStatus, ConnectionType, DurationUnit, CustomerPayment, PlanType, Router, FupAction
from app.services.auth import verify_token, get_current_user
from app.services.plan_cache import get_plans_cached, invalidate_plan_cache
from app.services.subscription import enforce_active_subscription
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["plans"])

VALID_PLAN_TYPES = [pt.value for pt in PlanType]
VALID_FUP_ACTIONS = [a.value for a in FupAction]


def _parse_fup_action(value: Optional[str]) -> Optional[FupAction]:
    if value is None or value == "":
        return None
    if value.lower() not in VALID_FUP_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid fup_action. Must be one of: {', '.join(VALID_FUP_ACTIONS)}",
        )
    return FupAction(value.lower())


def _serialize_plan_fup(plan: Plan) -> dict:
    return {
        "data_cap_mb": plan.data_cap_mb,
        "fup_action": plan.fup_action.value if plan.fup_action else None,
        "fup_throttle_profile": plan.fup_throttle_profile,
    }


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
        )
        
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
        if request.data_cap_mb is not None:
            if request.data_cap_mb < 0:
                raise HTTPException(status_code=400, detail="data_cap_mb cannot be negative")
            plan.data_cap_mb = request.data_cap_mb if request.data_cap_mb > 0 else None
        if request.fup_action is not None:
            plan.fup_action = _parse_fup_action(request.fup_action)
        if request.fup_throttle_profile is not None:
            plan.fup_throttle_profile = request.fup_throttle_profile if request.fup_throttle_profile != "" else None

        await db.commit()
        await db.refresh(plan)
        await invalidate_plan_cache()
        
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
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating plan: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update plan: {str(e)}")


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
        
        # Set plan_id to NULL for inactive/expired customers
        await db.execute(
            update(Customer).where(Customer.plan_id == plan_id).values(plan_id=None)
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
    - Total sales per plan
    - Revenue per plan
    - Average revenue per sale
    - Current active customers per plan
    """
    try:
        user = await get_current_user(token, db)
        
        # Base query for plan performance
        stmt = select(
            Plan.id,
            Plan.name,
            Plan.price,
            Plan.duration_value,
            Plan.duration_unit,
            func.count(Customer.id.distinct()).label('total_customers'),
            func.count(CustomerPayment.id).label('total_sales'),
            func.sum(CustomerPayment.amount).label('total_revenue')
        ).outerjoin(
            Customer, Customer.plan_id == Plan.id
        ).outerjoin(
            CustomerPayment, CustomerPayment.customer_id == Customer.id
        ).where(
            Plan.user_id == user.id
        )
        
        # Apply date filters if provided
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            stmt = stmt.where(CustomerPayment.created_at >= start_dt)
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if 'T' not in end_date:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            stmt = stmt.where(CustomerPayment.created_at <= end_dt)
        
        stmt = stmt.group_by(Plan.id, Plan.name, Plan.price, Plan.duration_value, Plan.duration_unit)
        
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
    """Activate emergency mode on a specific router: persist the flag and message,
    then hide all REGULAR plans and show all EMERGENCY plans for this user."""
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

        hidden_result = await db.execute(
            update(Plan)
            .where(Plan.user_id == user.id, Plan.plan_type == PlanType.REGULAR)
            .values(is_hidden=True)
        )
        shown_result = await db.execute(
            update(Plan)
            .where(Plan.user_id == user.id, Plan.plan_type == PlanType.EMERGENCY)
            .values(is_hidden=False)
        )

        await db.commit()
        await invalidate_plan_cache()

        logger.info(f"Emergency mode activated on router {request.router_id} by user {user.id}: {hidden_result.rowcount} regular hidden, {shown_result.rowcount} emergency shown")

        return {
            "success": True,
            "message": "Emergency mode activated",
            "router_id": request.router_id,
            "emergency_message": request.message,
            "regular_plans_hidden": hidden_result.rowcount,
            "emergency_plans_shown": shown_result.rowcount,
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
    """Deactivate emergency mode on a specific router: clear the flag and message,
    then show all REGULAR plans and hide all EMERGENCY plans for this user."""
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

        shown_result = await db.execute(
            update(Plan)
            .where(Plan.user_id == user.id, Plan.plan_type == PlanType.REGULAR)
            .values(is_hidden=False)
        )
        hidden_result = await db.execute(
            update(Plan)
            .where(Plan.user_id == user.id, Plan.plan_type == PlanType.EMERGENCY)
            .values(is_hidden=True)
        )

        await db.commit()
        await invalidate_plan_cache()

        logger.info(f"Emergency mode deactivated on router {request.router_id} by user {user.id}: {shown_result.rowcount} regular shown, {hidden_result.rowcount} emergency hidden")

        return {
            "success": True,
            "message": "Emergency mode deactivated. Regular plans restored.",
            "router_id": request.router_id,
            "regular_plans_shown": shown_result.rowcount,
            "emergency_plans_hidden": hidden_result.rowcount,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating emergency mode: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to deactivate emergency mode: {str(e)}")

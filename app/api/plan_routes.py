from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Plan, Customer, CustomerStatus, ConnectionType, DurationUnit, CustomerPayment
from app.services.auth import verify_token, get_current_user
from app.services.plan_cache import get_plans_cached, invalidate_plan_cache
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["plans"])


class PlanCreateRequest(BaseModel):
    name: str
    speed: str
    price: int
    duration_value: int
    duration_unit: str
    connection_type: str
    router_profile: Optional[str] = None


class PlanUpdateRequest(BaseModel):
    name: Optional[str] = None
    speed: Optional[str] = None
    price: Optional[int] = None
    duration_value: Optional[int] = None
    duration_unit: Optional[str] = None
    connection_type: Optional[str] = None
    router_profile: Optional[str] = None


@router.post("/api/plans/create")
async def create_plan_api(
    request: PlanCreateRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Create a new internet plan"""
    try:
        user = await get_current_user(token, db)
        
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
        
        # Check for duplicate plan name
        existing_plan_stmt = select(Plan).filter(
            Plan.name == request.name,
            Plan.user_id == user.id
        )
        existing_result = await db.execute(existing_plan_stmt)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Plan with this name already exists")
        
        # Create new plan
        plan = Plan(
            name=request.name,
            speed=request.speed,
            price=request.price,
            duration_value=request.duration_value,
            duration_unit=duration_unit_enum,
            connection_type=connection_type_enum,
            user_id=user.id,
            router_profile=request.router_profile
        )
        
        db.add(plan)
        await db.commit()
        await db.refresh(plan)
        
        # Invalidate plan cache after creating new plan
        await invalidate_plan_cache()
        
        logger.info(f"Plan created: {plan.id} by user {user.id}")
        
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
            "created_at": plan.created_at.isoformat()
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
    """Get all plans for the authenticated user with optional connection_type filter - CACHED"""
    try:
        user = await get_current_user(token, db)
        return await get_plans_cached(db, user.id, connection_type)
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
        stmt = select(Plan).where(Plan.id == plan_id, Plan.user_id == user.id)
        result = await db.execute(stmt)
        plan = result.scalar_one_or_none()
        
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        
        # Update fields if provided
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
        
        await db.commit()
        await db.refresh(plan)
        await invalidate_plan_cache()
        
        logger.info(f"Plan {plan_id} updated: duration_value={plan.duration_value}, duration_unit={plan.duration_unit.value}")
        
        return {
            "id": plan.id,
            "name": plan.name,
            "speed": plan.speed,
            "price": plan.price,
            "duration_value": plan.duration_value,
            "duration_unit": plan.duration_unit.value,
            "connection_type": plan.connection_type.value,
            "router_profile": plan.router_profile
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

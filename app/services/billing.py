from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from app.db.models import Customer, Plan, CustomerPayment, Router, CustomerStatus, ConnectionType, PaymentStatus, PaymentMethod
# from app.services.mikrotik_api import provision_customer_to_router
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

async def get_customers_by_user(db: AsyncSession, user_id: int, role: str):
    """
    Fetch customers for a user, filtered by user_id for resellers.
    """
    stmt = select(Customer).options(joinedload(Customer.plan))
    if role != "admin":
        stmt = stmt.filter(Customer.user_id == user_id)
    result = await db.execute(stmt)
    return result.scalars().unique().all()

async def get_plans_by_user(db: AsyncSession, user_id: int, role: str):
    """
    Fetch plans for a user, filtered by user_id for resellers.
    """
    stmt = select(Plan)
    if role != "admin":
        stmt = stmt.filter(Plan.user_id == user_id)
    result = await db.execute(stmt)
    return result.scalars().all()

async def create_plan(db: AsyncSession, name: str, speed: str, price: float, duration_days: int, connection_type: ConnectionType, user_id: int, router_profile: str = None):
    """
    Create a new plan for a user.
    """
    plan = Plan(
        name=name,
        speed=speed,
        price=price,
        duration_days=duration_days,
        connection_type=connection_type,
        user_id=user_id,
        router_profile=router_profile,
        created_at=datetime.utcnow()
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)
    return plan

async def register_customer(
    db: AsyncSession,
    name: str,
    phone: str,
    plan_id: int,
    user_id: Optional[int],
    connection_type: ConnectionType,
    connection_details: str,
    router_id: int,
    pppoe_password: str = None
):
    """
    Register a new customer for a reseller.
    """
    stmt = select(Plan).filter(Plan.id == plan_id)
    if user_id:
        stmt = stmt.filter(Plan.user_id == user_id)
    result = await db.execute(stmt)
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found or not accessible")

    stmt = select(Router).filter(Router.id == router_id)
    if user_id:
        stmt = stmt.filter(Router.user_id == user_id)
    result = await db.execute(stmt)
    router = result.scalar_one_or_none()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    customer = Customer(
        name=name,
        phone=phone,
        user_id=user_id,
        plan_id=plan_id,
        router_id=router_id,
        status=CustomerStatus.INACTIVE,
        created_at=datetime.utcnow()
    )
    if connection_type == ConnectionType.HOTSPOT:
        customer.mac_address = connection_details
    elif connection_type == ConnectionType.PPPOE:
        customer.pppoe_username = connection_details
        customer.pppoe_password = pppoe_password or phone
    elif connection_type == ConnectionType.STATIC_IP:
        customer.static_ip = connection_details
    else:
        raise HTTPException(status_code=400, detail="Invalid connection type")

    db.add(customer)
    await db.commit()
    await db.refresh(customer)
    return customer

async def make_payment(
    db: AsyncSession,
    customer_id: int,
    amount: float,
    days_paid_for: int,
    user_id: Optional[int],
    payment_method: str = "cash",
    payment_reference: str = None
):
    """
    Record a payment for a customer and update their status/expiry.
    NOTE: This function now ONLY handles payment and does NOT do router provisioning.
    Router provisioning should be handled separately to avoid transaction rollbacks.
    """
    stmt = select(Customer).options(joinedload(Customer.plan))
    if user_id:
        stmt = stmt.filter(Customer.user_id == user_id)
    stmt = stmt.filter(Customer.id == customer_id)
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not accessible")

    payment = CustomerPayment(
        customer_id=customer_id,
        reseller_id=user_id,
        amount=amount,
        payment_method=PaymentMethod(payment_method.lower()),
        payment_reference=payment_reference,
        payment_date=datetime.utcnow(),
        days_paid_for=days_paid_for,
        status=PaymentStatus.COMPLETED
    )
    db.add(payment)

    # Update customer status and expiry
    customer.status = CustomerStatus.ACTIVE
    customer.expiry = datetime.utcnow() + timedelta(days=days_paid_for)
    db.add(customer)

    # Commit the payment and customer update
    await db.commit()

    # Note: Router provisioning is now handled separately
    # This ensures payment is never lost due to router connection issues
    
    return payment

async def make_payment_with_provisioning(
    db: AsyncSession,
    customer_id: int,
    amount: float,
    days_paid_for: int,
    user_id: Optional[int],
    payment_method: str = "cash",
    payment_reference: str = None
):
    """
    Record a payment for a customer and attempt router provisioning.
    This is a convenience function that combines payment and provisioning
    but handles provisioning failures gracefully.
    """
    # First, process the payment (this will always succeed if data is valid)
    payment = await make_payment(
        db, customer_id, amount, days_paid_for, user_id, payment_method, payment_reference
    )
    
    # Get the customer data for provisioning
    stmt = select(Customer).options(joinedload(Customer.plan)).filter(Customer.id == customer_id)
    result = await db.execute(stmt)
    customer = result.scalar_one()
    
    # Attempt router provisioning separately
    provisioning_success = False
    provisioning_error = None
    
    if customer.router_id:
        try:
            await provision_customer_to_router(
                db, customer_id=customer.id, router_id=customer.router_id, plan_id=customer.plan_id
            )
            provisioning_success = True
            logger.info(f"Successfully provisioned customer {customer_id} to router {customer.router_id}")
        except Exception as e:
            provisioning_error = str(e)
            logger.error(f"Failed to provision customer {customer_id} to router {customer.router_id}: {e}")
            
            # Update customer status to indicate provisioning is needed
            customer.status = CustomerStatus.PENDING  # or create a PROVISIONING_PENDING status
            await db.commit()
    else:
        logger.warning(f"No router assigned for customer {customer_id}, skipping provisioning")
    
    # Return payment info along with provisioning status
    return {
        "payment": payment,
        "provisioning_success": provisioning_success,
        "provisioning_error": provisioning_error
    }

async def provision_customer_after_payment(
    db: AsyncSession,
    customer_id: int,
    user_id: Optional[int] = None
):
    """
    Attempt to provision a customer to their router after payment has been processed.
    This is useful for retry scenarios or manual provisioning.
    """
    stmt = select(Customer).options(joinedload(Customer.plan))
    if user_id:
        stmt = stmt.filter(Customer.user_id == user_id)
    stmt = stmt.filter(Customer.id == customer_id)
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()
    
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not accessible")
    
    if not customer.router_id:
        raise HTTPException(status_code=400, detail="No router assigned to customer")
    
    try:
        await provision_customer_to_router(
            db, customer_id=customer.id, router_id=customer.router_id, plan_id=customer.plan_id
        )
        
        # Update customer status to active if provisioning succeeds
        customer.status = CustomerStatus.ACTIVE
        await db.commit()
        
        return {"success": True, "message": "Customer successfully provisioned"}
    except Exception as e:
        logger.error(f"Failed to provision customer {customer_id}: {e}")
        return {"success": False, "error": str(e)}
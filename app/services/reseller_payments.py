from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from fastapi import HTTPException
from app.db.models import Customer, CustomerPayment, ResellerFinancials, Payment, PaymentMethod, CustomerStatus, PaymentStatus

async def record_customer_payment(
    db: AsyncSession,
    customer_id: int,
    reseller_id: int,
    amount: float,
    payment_method: PaymentMethod,
    days_paid_for: int,
    payment_reference: str = None,
    notes: str = None
) -> CustomerPayment:
    """Record a payment made by customer to reseller"""
    
    stmt = select(Customer).where(
        Customer.id == customer_id,
        Customer.user_id == reseller_id
    )
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()
    
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not owned by reseller")
    
    payment = CustomerPayment(
        customer_id=customer_id,
        reseller_id=reseller_id,
        amount=amount,
        payment_method=payment_method,
        payment_reference=payment_reference,
        days_paid_for=days_paid_for,
        notes=notes
    )
    
    db.add(payment)
    
    if customer.expiry:
        customer.expiry = customer.expiry + timedelta(days=days_paid_for)
    else:
        customer.expiry = datetime.utcnow() + timedelta(days=days_paid_for)
    
    customer.status = CustomerStatus.ACTIVE
    
    existing_payment = Payment(
        customer_id=customer_id,
        amount=int(amount),
        days_paid_for=days_paid_for
    )
    db.add(existing_payment)
    
    await update_reseller_financials(db, reseller_id)
    
    await db.commit()
    await db.refresh(payment)
    
    return payment

async def update_reseller_financials(db: AsyncSession, reseller_id: int):
    """Update reseller's financial summary"""
    
    stmt = select(ResellerFinancials).where(ResellerFinancials.user_id == reseller_id)
    result = await db.execute(stmt)
    financials = result.scalar_one_or_none()
    
    if not financials:
        financials = ResellerFinancials(user_id=reseller_id)
        db.add(financials)
    
    total_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
        CustomerPayment.reseller_id == reseller_id,
        CustomerPayment.status == PaymentStatus.COMPLETED
    )
    total_revenue_result = await db.execute(total_revenue_stmt)
    total_revenue = total_revenue_result.scalar() or 0
    
    total_customers_stmt = select(func.count(Customer.id)).where(
        Customer.user_id == reseller_id
    )
    total_customers_result = await db.execute(total_customers_stmt)
    total_customers = total_customers_result.scalar() or 0
    
    active_customers_stmt = select(func.count(Customer.id)).where(
        Customer.user_id == reseller_id,
        Customer.status == CustomerStatus.ACTIVE
    )
    active_customers_result = await db.execute(active_customers_stmt)
    active_customers = active_customers_result.scalar() or 0
    
    last_payment_stmt = select(func.max(CustomerPayment.payment_date)).where(
        CustomerPayment.reseller_id == reseller_id
    )
    last_payment_result = await db.execute(last_payment_stmt)
    last_payment_date = last_payment_result.scalar()
    
    financials.total_revenue = total_revenue
    financials.total_customers = total_customers
    financials.active_customers = active_customers
    financials.last_payment_date = last_payment_date
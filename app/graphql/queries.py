from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from fastapi import HTTPException
from app.db.models import User, Customer, Plan, CustomerPayment, Subscription, UserRole, CustomerStatus, PaymentStatus, PaymentMethod, Router, ProvisioningLog, ResellerFinancials, ConnectionType
from app.core.deps import get_current_user
from app.services.billing import get_customers_by_user, get_plans_by_user
from app.graphql.types import UserType, CustomerType, PlanType, DashboardMetricsType, PlanMetricsType, CustomerPaymentType, ResellerFinancialSummary, PaymentSummary, RouterType, ProvisioningLogType
from app.core.decorators import require_role
import strawberry
import logging

logger = logging.getLogger(__name__)

def safe_log_error(message: str, error: Exception, user_id: Optional[int] = None):
    """Safely log errors without causing additional failures"""
    try:
        logger.error(f"{message} - User ID: {user_id} - Error: {str(error)}")
    except Exception:
        pass  # Don't let logging errors break the application

@strawberry.type
class Query:
    @strawberry.field
    async def me(self, info) -> UserType:
        """Get current user information with error handling"""
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            return UserType(
                id=user.user_code,
                email=None,  # Explicitly set to None since CurrentUser has no email
                role=user.role,
                organization_name=user.organization_name,
                user_code=user.user_code
            )
        except HTTPException:
            raise
        except Exception as e:
            safe_log_error("Failed to fetch user information", e)
            raise HTTPException(status_code=500, detail="Failed to retrieve user information")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def my_customers(self, info) -> List[CustomerType]:
        """Get user's customers with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching customers for user_id: {user.user_id}, role: {user.role}")
            
            # Validate user has proper permissions
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view customers")
            
            customers = await get_customers_by_user(db, user.user_id, user.role)
            
            if customers is None:
                customers = []
            
            customer_list = []
            for c in customers:
                try:
                    # Handle potential None values gracefully
                    plan_data = None
                    if c.plan:
                        plan_data = PlanType(
                            id=c.plan.id,
                            name=c.plan.name or "Unknown Plan",
                            speed=c.plan.speed or 0,
                            price=c.plan.price or 0.0,
                            duration_value=c.plan.duration_value or 0,
                            duration_unit=c.plan.duration_unit.value if c.plan.duration_unit else "HOURS",
                            connection_type=c.plan.connection_type.value if c.plan.connection_type else "HOTSPOT"
                        )
                    
                    customer_data = CustomerType(
                        id=c.id,
                        name=c.name or "Unknown Customer",
                        phone=c.phone,
                        mac_address=c.mac_address,
                        pppoe_username=c.pppoe_username,
                        static_ip=c.static_ip,
                        status=c.status.value if c.status else "INACTIVE",
                        expiry=c.expiry.timestamp() if c.expiry else None,
                        plan=plan_data
                    )
                    customer_list.append(customer_data)
                except Exception as e:
                    safe_log_error(f"Error processing customer {c.id}", e, user.user_id)
                    # Continue with other customers instead of failing completely
                    continue
            
            return customer_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching customers", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching customers")
        except Exception as e:
            safe_log_error("Unexpected error while fetching customers", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve customers")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def my_plans(self, info) -> List[PlanType]:
        """Get user's plans with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching plans for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view plans")
            
            plans = await get_plans_by_user(db, user.user_id, user.role)
            
            if plans is None:
                plans = []
            
            plan_list = []
            for p in plans:
                try:
                    plan_data = PlanType(
                        id=p.id,
                        name=p.name or "Unknown Plan",
                        speed=p.speed or 0,
                        price=p.price or 0.0,
                        duration_value=p.duration_value or 0,
                        duration_unit=p.duration_unit.value if p.duration_unit else "HOURS",
                        connection_type=p.connection_type.value if p.connection_type else "HOTSPOT"
                    )
                    plan_list.append(plan_data)
                except Exception as e:
                    safe_log_error(f"Error processing plan {p.id}", e, user.user_id)
                    continue
            
            return plan_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching plans", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching plans")
        except Exception as e:
            safe_log_error("Unexpected error while fetching plans", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve plans")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def dashboard_metrics(self, info) -> DashboardMetricsType:
        """Get dashboard metrics with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching dashboard metrics for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view dashboard metrics")
            
            # Build base queries
            total_customers_stmt = select(func.count()).select_from(Customer)
            active_customers_stmt = select(func.count()).select_from(Customer).filter(Customer.status == CustomerStatus.ACTIVE)
            inactive_customers_stmt = select(func.count()).select_from(Customer).filter(Customer.status == CustomerStatus.INACTIVE)
            total_revenue_stmt = select(func.sum(CustomerPayment.amount)).join(Customer)
            expiring_soon_stmt = select(func.count()).select_from(Customer).filter(
                Customer.status == CustomerStatus.ACTIVE,
                Customer.expiry <= datetime.utcnow() + timedelta(days=7),
                Customer.expiry >= datetime.utcnow()
            )
            subscription_stmt = select(Subscription).filter(Subscription.is_active == True)
            
            # Apply user-specific filters for non-admin users
            if user.role != "admin":
                total_customers_stmt = total_customers_stmt.filter(Customer.user_id == user.user_id)
                active_customers_stmt = active_customers_stmt.filter(Customer.user_id == user.user_id)
                inactive_customers_stmt = inactive_customers_stmt.filter(Customer.user_id == user.user_id)
                total_revenue_stmt = total_revenue_stmt.filter(Customer.user_id == user.user_id)
                expiring_soon_stmt = expiring_soon_stmt.filter(Customer.user_id == user.user_id)
                subscription_stmt = subscription_stmt.filter(Subscription.user_id == user.user_id)
            
            # Execute queries with error handling for each
            metrics = {
                'total_customers': 0,
                'active_customers': 0,
                'inactive_customers': 0,
                'total_revenue': 0.0,
                'expiring_soon': 0,
                'subscription_days_left': 0
            }
            
            try:
                total_customers = (await db.execute(total_customers_stmt)).scalar() or 0
                metrics['total_customers'] = total_customers
            except Exception as e:
                safe_log_error("Error fetching total customers count", e, user.user_id)
            
            try:
                active_customers = (await db.execute(active_customers_stmt)).scalar() or 0
                metrics['active_customers'] = active_customers
            except Exception as e:
                safe_log_error("Error fetching active customers count", e, user.user_id)
            
            try:
                inactive_customers = (await db.execute(inactive_customers_stmt)).scalar() or 0
                metrics['inactive_customers'] = inactive_customers
            except Exception as e:
                safe_log_error("Error fetching inactive customers count", e, user.user_id)
            
            try:
                total_revenue = (await db.execute(total_revenue_stmt)).scalar() or 0
                metrics['total_revenue'] = float(total_revenue)
            except Exception as e:
                safe_log_error("Error fetching total revenue", e, user.user_id)
            
            try:
                expiring_soon = (await db.execute(expiring_soon_stmt)).scalar() or 0
                metrics['expiring_soon'] = expiring_soon
            except Exception as e:
                safe_log_error("Error fetching expiring soon count", e, user.user_id)
            
            try:
                subscription = (await db.execute(subscription_stmt)).scalar_one_or_none()
                if subscription and subscription.expires_on:
                    days_left = max(0, (subscription.expires_on - datetime.utcnow()).days)
                    metrics['subscription_days_left'] = days_left
            except Exception as e:
                safe_log_error("Error fetching subscription info", e, user.user_id)
            
            return DashboardMetricsType(
                total_customers=metrics['total_customers'],
                active_customers=metrics['active_customers'],
                inactive_customers=metrics['inactive_customers'],
                total_revenue=metrics['total_revenue'],
                expiring_soon=metrics['expiring_soon'],
                subscription_days_left=metrics['subscription_days_left']
            )
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching dashboard metrics", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching dashboard metrics")
        except Exception as e:
            safe_log_error("Unexpected error while fetching dashboard metrics", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve dashboard metrics")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def plan_metrics(self, info) -> List[PlanMetricsType]:
        """Get plan metrics with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching plan metrics for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view plan metrics")
            
            stmt = (
                select(
                    Plan.id,
                    Plan.name,
                    func.count(Customer.id).label("customer_count"),
                    func.coalesce(func.sum(CustomerPayment.amount), 0).label("total_revenue")
                )
                .outerjoin(Customer, Customer.plan_id == Plan.id)
                .outerjoin(CustomerPayment, CustomerPayment.customer_id == Customer.id)
            )
            
            if user.role != "admin":
                stmt = stmt.filter(Plan.user_id == user.user_id)
            
            stmt = stmt.group_by(Plan.id, Plan.name)
            
            results = (await db.execute(stmt)).all()
            
            metrics_list = []
            for result in results:
                try:
                    metrics = PlanMetricsType(
                        plan_id=result.id,
                        plan_name=result.name or "Unknown Plan",
                        customer_count=result.customer_count or 0,
                        total_revenue=float(result.total_revenue or 0)
                    )
                    metrics_list.append(metrics)
                except Exception as e:
                    safe_log_error(f"Error processing plan metrics for plan {result.id}", e, user.user_id)
                    continue
            
            return metrics_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching plan metrics", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching plan metrics")
        except Exception as e:
            safe_log_error("Unexpected error while fetching plan metrics", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve plan metrics")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def my_routers(self, info) -> List[RouterType]:
        """Get user's routers with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching routers for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view routers")
            
            stmt = select(Router)
            if user.role != "admin":
                stmt = stmt.filter(Router.user_id == user.user_id)
            
            result = await db.execute(stmt)
            routers = result.scalars().all()
            
            router_list = []
            for r in routers:
                try:
                    router_data = RouterType(
                        id=r.id,
                        name=r.name or "Unknown Router",
                        ip_address=r.ip_address or "0.0.0.0",
                        port=r.port or 0
                    )
                    router_list.append(router_data)
                except Exception as e:
                    safe_log_error(f"Error processing router {r.id}", e, user.user_id)
                    continue
            
            return router_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching routers", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching routers")
        except Exception as e:
            safe_log_error("Unexpected error while fetching routers", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve routers")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def my_provisioning_logs(self, info, limit: int = 50, offset: int = 0) -> List[ProvisioningLogType]:
        """Get provisioning logs with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching provisioning logs for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view provisioning logs")
            
            # Validate pagination parameters
            if limit < 1 or limit > 1000:
                raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
            if offset < 0:
                raise HTTPException(status_code=400, detail="Offset must be non-negative")
            
            stmt = select(ProvisioningLog).join(Router)
            if user.role != "admin":
                stmt = stmt.filter(Router.user_id == user.user_id)
            
            stmt = stmt.order_by(ProvisioningLog.log_date.desc()).limit(limit).offset(offset)
            
            result = await db.execute(stmt)
            logs = result.scalars().all()
            
            log_list = []
            for log in logs:
                try:
                    log_data = ProvisioningLogType(
                        id=log.id,
                        router_id=log.router_id,
                        customer_id=log.customer_id,
                        action=log.action or "Unknown Action",
                        status=log.status or "Unknown Status",
                        details=log.details,
                        mac_address=log.mac_address,
                        log_date=log.log_date.isoformat() if log.log_date else datetime.utcnow().isoformat()
                    )
                    log_list.append(log_data)
                except Exception as e:
                    safe_log_error(f"Error processing provisioning log {log.id}", e, user.user_id)
                    continue
            
            return log_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching provisioning logs", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching provisioning logs")
        except Exception as e:
            safe_log_error("Unexpected error while fetching provisioning logs", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve provisioning logs")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def my_payments(
        self, 
        info, 
        limit: int = 50, 
        offset: int = 0,
        customer_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        payment_method: Optional[str] = None
    ) -> List[CustomerPaymentType]:
        """Get payments with comprehensive error handling and validation"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching payments for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view payments")
            
            # Validate pagination parameters
            if limit < 1 or limit > 1000:
                raise HTTPException(status_code=400, detail="Limit must be between 1 and 1000")
            if offset < 0:
                raise HTTPException(status_code=400, detail="Offset must be non-negative")
            
            # Validate customer_id
            if customer_id is not None and customer_id <= 0:
                raise HTTPException(status_code=400, detail="Customer ID must be a positive integer")
            
            # Validate and parse dates
            start_dt = None
            end_dt = None
            
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    # Convert to offset-naive by removing tzinfo
                    start_dt = start_dt.replace(tzinfo=None)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid start_date format. Use ISO format")
            
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    # Convert to offset-naive by removing tzinfo
                    end_dt = end_dt.replace(tzinfo=None)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid end_date format. Use ISO format")
            
            if start_dt and end_dt and start_dt > end_dt:
                raise HTTPException(status_code=400, detail="Start date cannot be after end date")
            
            # Build query
            stmt = select(CustomerPayment).options(
                joinedload(CustomerPayment.customer)
            ).where(CustomerPayment.reseller_id == user.user_id)
            
            # Apply filters
            if customer_id:
                stmt = stmt.where(CustomerPayment.customer_id == customer_id)
            
            if start_dt:
                stmt = stmt.where(CustomerPayment.payment_date >= start_dt)
            
            if end_dt:
                stmt = stmt.where(CustomerPayment.payment_date <= end_dt)
            
            if payment_method:
                try:
                    # Match case-insensitively with lowercase enum values
                    method_enum = None
                    for method in PaymentMethod:
                        if method.value.lower() == payment_method.lower():
                            method_enum = method
                            break
                    if method_enum is None:
                        valid_methods = [method.value for method in PaymentMethod]
                        raise ValueError(f"Invalid payment method: {payment_method}")
                    stmt = stmt.where(CustomerPayment.payment_method == method_enum)
                except ValueError as e:
                    valid_methods = [method.value for method in PaymentMethod]
                    raise HTTPException(
                        status_code=400,
                        detail=f"{str(e)}. Valid options are: {', '.join(valid_methods)}"
                    )
            
            stmt = stmt.order_by(CustomerPayment.payment_date.desc()).limit(limit).offset(offset)
            
            result = await db.execute(stmt)
            payments = result.scalars().all()
            
            payment_list = []
            for payment in payments:
                try:
                    customer_name = "Unknown Customer"
                    if payment.customer and payment.customer.name:
                        customer_name = payment.customer.name
                    
                    payment_data = CustomerPaymentType(
                        id=payment.id,
                        customer_id=payment.customer_id,
                        customer_name=customer_name,
                        amount=float(payment.amount or 0),
                        payment_method=payment.payment_method.value if payment.payment_method else "UNKNOWN",
                        payment_reference=payment.payment_reference,
                        payment_date=payment.payment_date.isoformat() if payment.payment_date else datetime.utcnow().isoformat(),
                        days_paid_for=payment.days_paid_for or 0,
                        status=payment.status.value if payment.status else "UNKNOWN",
                        notes=payment.notes
                    )
                    payment_list.append(payment_data)
                except Exception as e:
                    safe_log_error(f"Error processing payment {payment.id}", e, user.user_id)
                    continue
            
            return payment_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching payments", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching payments")
        except Exception as e:
            safe_log_error("Unexpected error while fetching payments", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve payments")
    @strawberry.field
    @require_role(["admin", "reseller"])
    async def financial_summary(self, info) -> ResellerFinancialSummary:
        """Get financial summary with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching financial summary for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view financial summary")
            
            # Default values in case of errors
            default_summary = ResellerFinancialSummary(
                total_revenue=0.0,
                total_customers=0,
                active_customers=0,
                last_payment_date=None,
                monthly_revenue=0.0,
                this_month_customers=0
            )
            
            try:
                # Get reseller financials
                stmt = select(ResellerFinancials).where(ResellerFinancials.user_id == user.user_id)
                result = await db.execute(stmt)
                financials = result.scalar_one_or_none()
            except Exception as e:
                safe_log_error("Error fetching reseller financials", e, user.user_id)
                financials = None
            
            # Calculate monthly metrics
            current_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            monthly_revenue = 0.0
            monthly_customers = 0
            
            try:
                monthly_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.payment_date >= current_month_start,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                monthly_result = await db.execute(monthly_revenue_stmt)
                monthly_revenue = float(monthly_result.scalar() or 0)
            except Exception as e:
                safe_log_error("Error fetching monthly revenue", e, user.user_id)
            
            try:
                monthly_customers_stmt = select(func.count(func.distinct(CustomerPayment.customer_id))).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.payment_date >= current_month_start,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                monthly_customers_result = await db.execute(monthly_customers_stmt)
                monthly_customers = monthly_customers_result.scalar() or 0
            except Exception as e:
                safe_log_error("Error fetching monthly customers count", e, user.user_id)
            
            if not financials:
                return ResellerFinancialSummary(
                    total_revenue=0.0,
                    total_customers=0,
                    active_customers=0,
                    last_payment_date=None,
                    monthly_revenue=monthly_revenue,
                    this_month_customers=monthly_customers
                )
            
            return ResellerFinancialSummary(
                total_revenue=float(financials.total_revenue or 0),
                total_customers=financials.total_customers or 0,
                active_customers=financials.active_customers or 0,
                last_payment_date=financials.last_payment_date.isoformat() if financials.last_payment_date else None,
                monthly_revenue=monthly_revenue,
                this_month_customers=monthly_customers
            )
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching financial summary", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching financial summary")
        except Exception as e:
            safe_log_error("Unexpected error while fetching financial summary", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve financial summary")

    @strawberry.field
    @require_role(["admin", "reseller"])
    async def payment_summary(self, info) -> PaymentSummary:
        """Get payment summary with comprehensive error handling"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            user = await get_current_user(info.context["user"])
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            logger.info(f"Fetching payment summary for user_id: {user.user_id}, role: {user.role}")
            
            if user.role not in ["admin", "reseller"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions to view payment summary")
            
            now = datetime.utcnow()
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = today_start - timedelta(days=now.weekday())
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Initialize default values
            summary_data = {
                'today_total': 0.0,
                'today_count': 0,
                'week_total': 0.0,
                'week_count': 0,
                'month_total': 0.0,
                'month_count': 0,
                'total_amount': 0.0
            }
            
            # Today's payments
            try:
                today_stmt = select(
                    func.sum(CustomerPayment.amount), 
                    func.count(CustomerPayment.id)
                ).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.payment_date >= today_start,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                today_result = await db.execute(today_stmt)
                today_data = today_result.first()
                summary_data['today_total'] = float(today_data[0] or 0)
                summary_data['today_count'] = today_data[1] or 0
            except Exception as e:
                safe_log_error("Error fetching today's payment summary", e, user.user_id)
            
            # This week's payments
            try:
                week_stmt = select(
                    func.sum(CustomerPayment.amount), 
                    func.count(CustomerPayment.id)
                ).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.payment_date >= week_start,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                week_result = await db.execute(week_stmt)
                week_data = week_result.first()
                summary_data['week_total'] = float(week_data[0] or 0)
                summary_data['week_count'] = week_data[1] or 0
            except Exception as e:
                safe_log_error("Error fetching this week's payment summary", e, user.user_id)
            
            # This month's payments
            try:
                month_stmt = select(
                    func.sum(CustomerPayment.amount), 
                    func.count(CustomerPayment.id)
                ).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.payment_date >= month_start,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                month_result = await db.execute(month_stmt)
                month_data = month_result.first()
                summary_data['month_total'] = float(month_data[0] or 0)
                summary_data['month_count'] = month_data[1] or 0
            except Exception as e:
                safe_log_error("Error fetching this month's payment summary", e, user.user_id)
            
            # Total payments
            try:
                total_stmt = select(func.sum(CustomerPayment.amount)).where(
                    CustomerPayment.reseller_id == user.user_id,
                    CustomerPayment.status == PaymentStatus.COMPLETED
                )
                total_result = await db.execute(total_stmt)
                summary_data['total_amount'] = float(total_result.scalar() or 0)
            except Exception as e:
                safe_log_error("Error fetching total payment amount", e, user.user_id)
            
            return PaymentSummary(
                today=summary_data['today_total'],
                this_week=summary_data['week_total'],
                this_month=summary_data['month_total'],
                total=summary_data['total_amount'],
                today_count=summary_data['today_count'],
                week_count=summary_data['week_count'],
                month_count=summary_data['month_count']
            )
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error("Database error while fetching payment summary", e, getattr(user, 'user_id', None))
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching payment summary")
        except Exception as e:
            safe_log_error("Unexpected error while fetching payment summary", e, getattr(user, 'user_id', None))
            raise HTTPException(status_code=500, detail="Failed to retrieve payment summary")

    @strawberry.field
    async def my_plans_by_router(self, info, router_id: int) -> List[PlanType]:
        """Get plans by router ID for guest users via captive portal"""
        db: AsyncSession = info.context.get("db")
        if not db:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        try:
            logger.info(f"Fetching plans for router_id: {router_id}")
            
            # Validate router_id
            if router_id <= 0:
                raise HTTPException(status_code=400, detail="Router ID must be a positive integer")
            
            # Fetch the router to verify its existence
            try:
                router_stmt = select(Router).where(Router.id == router_id)
                router_result = await db.execute(router_stmt)
                router = router_result.scalar_one_or_none()
                
                if not router:
                    raise HTTPException(status_code=404, detail="Router not found")
                    
            except HTTPException:
                raise
            except Exception as e:
                safe_log_error(f"Error fetching router {router_id}", e)
                raise HTTPException(status_code=500, detail="Failed to fetch router information")
            
            # Fetch all HOTSPOT plans for the router's user_id
            try:
                plans_stmt = select(Plan).where(
                    Plan.user_id == router.user_id,
                    Plan.connection_type == ConnectionType.HOTSPOT
                )
                plans_result = await db.execute(plans_stmt)
                plans = plans_result.scalars().all()
            except Exception as e:
                safe_log_error(f"Error fetching plans for router {router_id}", e)
                raise HTTPException(status_code=500, detail="Failed to fetch plans")
            
            # Map plans to PlanType with error handling for each plan
            plan_list = []
            for p in plans:
                try:
                    plan_data = PlanType(
                        id=p.id,
                        name=p.name or "Unknown Plan",
                        speed=p.speed or 0,
                        price=p.price or 0.0,
                        duration_value=p.duration_value or 0,
                        duration_unit=p.duration_unit.value if p.duration_unit else "HOURS",
                        connection_type=p.connection_type.value if p.connection_type else "HOTSPOT"
                    )
                    plan_list.append(plan_data)
                except Exception as e:
                    safe_log_error(f"Error processing plan {p.id} for router {router_id}", e)
                    continue
            
            return plan_list
            
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            safe_log_error(f"Database error while fetching plans for router {router_id}", e)
            await db.rollback()
            raise HTTPException(status_code=500, detail="Database error occurred while fetching plans")
        except Exception as e:
            safe_log_error(f"Unexpected error while fetching plans for router {router_id}", e)
            raise HTTPException(status_code=500, detail="Failed to retrieve plans")
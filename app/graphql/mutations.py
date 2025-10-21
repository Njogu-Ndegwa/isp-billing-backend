import strawberry
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from app.db.models import (
    Customer, User, UserRole, ConnectionType, CustomerStatus, PaymentMethod, 
    CustomerPayment, Payment, Router, Plan, ProvisioningLog, MpesaTransactionStatus, DurationUnit
)
from app.services.auth import create_user, authenticate_user
from app.services.billing import register_customer, make_payment, create_plan
from app.services.subscription import create_subscription
from app.services.mpesa_transactions import save_mpesa_transaction, link_transaction_to_customer, update_mpesa_transaction_status
from app.graphql.types import UserType, CustomerType, PlanType, SubscriptionType, CustomerPaymentType, RouterType
from app.core.deps import get_current_user
from app.core.decorators import require_role
from app.services.reseller_payments import record_customer_payment
from app.services.mpesa import initiate_stk_push
import logging
import asyncio

logger = logging.getLogger(__name__)

@strawberry.type
class Mutation:
    @strawberry.type
    class PaymentResponse:
        message: str
        
    @strawberry.type
    class PaymentInitiationResponse:
        message: str
        checkout_request_id: str
        customer_id: int
        status: str

    @strawberry.mutation
    async def register_user(self, info, email: str, password: str, role: str, organization_name: str) -> UserType:
        db: AsyncSession = info.context["db"]
        
        try:
            # Validate role
            try:
                role_enum = UserRole(role.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'reseller'")
            
            # Check if admin exists for non-admin registrations
            stmt = select(User).filter(User.role == UserRole.ADMIN.value).limit(1)
            result = await db.execute(stmt)
            admin_exists = result.scalar_one_or_none() is not None
            
            if role_enum != UserRole.ADMIN and not admin_exists:
                raise HTTPException(status_code=403, detail="First user must be an admin")
            
            # Check if user already exists
            existing_user_stmt = select(User).filter(User.email == email.lower())
            existing_result = await db.execute(existing_user_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="User with this email already exists")
            
            user = await create_user(db, email, password, role_enum, organization_name)
            return UserType(
                id=user.id,
                email=user.email,
                role=user.role,
                organization_name=user.organization_name,
                user_code=user.user_code
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to register user {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to register user. Please try again.")

    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def register_customer(self, info, name: str, phone: str, plan_id: int, connection_details: str, connection_type: str, router_id: int, pppoe_password: Optional[str] = None) -> CustomerType:
        db: AsyncSession = info.context["db"]
        
        try:
            user = await get_current_user(info.context["user"])
            
            # Validate connection type
            try:
                connection_type_enum = ConnectionType(connection_type.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid connection type. Must be 'hotspot', 'pppoe', or 'static'")
            
            # Validate plan exists
            plan_stmt = select(Plan).where(Plan.id == plan_id)
            plan_result = await db.execute(plan_stmt)
            if not plan_result.scalar_one_or_none():
                raise HTTPException(status_code=404, detail="Plan not found")
            
            # Validate router exists
            router_stmt = select(Router).where(Router.id == router_id)
            router_result = await db.execute(router_stmt)
            if not router_result.scalar_one_or_none():
                raise HTTPException(status_code=404, detail="Router not found")
            
            # Check for duplicate MAC address (for hotspot connections)
            if connection_type_enum == ConnectionType.HOTSPOT:
                existing_customer_stmt = select(Customer).where(Customer.mac_address == connection_details)
                existing_result = await db.execute(existing_customer_stmt)
                if existing_result.scalar_one_or_none():
                    raise HTTPException(status_code=409, detail="A customer with this MAC address already exists")
            
            customer = await register_customer(db, name, phone, plan_id, user.user_id, connection_type_enum, connection_details, router_id, pppoe_password)
            
            # Fetch customer with plan details
            stmt = select(Customer).options(selectinload(Customer.plan)).where(Customer.id == customer.id)
            result = await db.execute(stmt)
            customer_with_plan = result.scalar_one()
            
            return CustomerType(
                id=customer_with_plan.id,
                name=customer_with_plan.name,
                phone=customer_with_plan.phone,
                mac_address=customer_with_plan.mac_address,
                pppoe_username=customer_with_plan.pppoe_username,
                static_ip=customer_with_plan.static_ip,
                status=customer_with_plan.status.value,
                expiry=customer_with_plan.expiry.timestamp() if customer_with_plan.expiry else None,
                plan=PlanType(
                    id=customer_with_plan.plan.id,
                    name=customer_with_plan.plan.name,
                    speed=customer_with_plan.plan.speed,
                    price=customer_with_plan.plan.price,
                    duration_value=customer_with_plan.plan.duration_value,
                    duration_unit=customer_with_plan.plan.duration_unit.value,
                    connection_type=customer_with_plan.plan.connection_type.value
                ) if customer_with_plan.plan else None
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except IntegrityError as e:
            await db.rollback()
            if "customers_mac_address_key" in str(e):
                raise HTTPException(status_code=409, detail="A customer with this MAC address already exists")
            elif "customers_phone_key" in str(e):
                raise HTTPException(status_code=409, detail="A customer with this phone number already exists")
            elif "customers_pppoe_username_key" in str(e):
                raise HTTPException(status_code=409, detail="A customer with this PPPoE username already exists")
            else:
                logger.error(f"Database integrity error while registering customer: {str(e)}")
                raise HTTPException(status_code=409, detail="Customer registration failed due to duplicate data")
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to register customer {name}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to register customer. Please try again.")
    
    @strawberry.mutation
    async def register_hotspot_and_pay(
        self, info,
        phone: str,
        plan_id: int,
        mac_address: str,
        router_id: int,
        name: Optional[str] = None,
        payment_method: str = "cash",
        payment_reference: Optional[str] = None
    ) -> CustomerType:
        db: AsyncSession = info.context["db"]

        try:
            # Validate payment method
            try:
                payment_method_enum = PaymentMethod(payment_method.lower())
            except ValueError:
                valid_methods = [method.value for method in PaymentMethod]
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
                )

            # Validate router exists and get user_id
            router_stmt = select(Router).where(Router.id == router_id)
            router_result = await db.execute(router_stmt)
            router = router_result.scalar_one_or_none()
            if not router:
                raise HTTPException(status_code=404, detail="Router not found")
            user_id = router.user_id

            # Validate plan exists
            plan_stmt = select(Plan).filter(Plan.id == plan_id)
            plan_result = await db.execute(plan_stmt)
            plan = plan_result.scalar_one_or_none()
            if not plan:
                raise HTTPException(status_code=404, detail="Plan not found")

            # Validate phone number format (basic validation)
            if not phone or len(phone.strip()) < 10:
                raise HTTPException(status_code=400, detail="Invalid phone number format")

            # Check if customer exists by MAC
            customer_stmt = select(Customer).where(Customer.mac_address == mac_address)
            customer_result = await db.execute(customer_stmt)
            existing_customer = customer_result.scalar_one_or_none()

            if existing_customer:
                # Store intended change in pending_update_data
                pending_data = {
                    "requested_at": datetime.utcnow().isoformat(),
                    "plan_id": plan_id,
                    "plan_name": plan.name,
                    "duration_value": plan.duration_value,
                    "duration_unit": plan.duration_unit.value,
                    "payment_method": payment_method_enum.value,
                    "router_id": router_id,
                    "phone": phone,
                    "name": name,
                    "requested_by_user_id": user_id
                }
                existing_customer.pending_update_data = pending_data
                existing_customer.status = CustomerStatus.PENDING if payment_method_enum == PaymentMethod.MOBILE_MONEY else CustomerStatus.ACTIVE
                if name:
                    existing_customer.name = name
                existing_customer.phone = phone
                customer = existing_customer
                await db.commit()
                await db.refresh(customer)
            else:
                # Create a new customer
                customer = await register_customer(
                    db, name, phone, plan_id, user_id,
                    ConnectionType.HOTSPOT, mac_address, router_id, None
                )

            use_microservice = True

            if payment_method_enum == PaymentMethod.MOBILE_MONEY:
                try:
                    reference = f"HOTSPOT-{customer.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    await initiate_stk_push(
                        phone_number=phone,
                        amount=float(plan.price),
                        reference=reference,
                        user_id=user_id,
                        mac_address=mac_address,
                        use_microservice=use_microservice
                    )
                    customer.status = CustomerStatus.PENDING
                    await db.commit()
                    logger.info(f"Payment initiated for customer {customer.id} ({mac_address}) [microservice={use_microservice}]")
                except Exception as e:
                    await db.rollback()
                    logger.error(f"Payment initiation failed for customer {customer.id}: {str(e)}")
                    customer.status = CustomerStatus.INACTIVE
                    await db.commit()
                    raise HTTPException(status_code=400, detail=f"Mobile money payment initiation failed: {str(e)}")
            else:
                # For cash payments, process immediately
                try:
                    await record_customer_payment(
                        db, customer.id, user_id, float(plan.price),
                        payment_method_enum, plan.duration_value, payment_reference
                    )
                    customer.status = CustomerStatus.ACTIVE
                    await db.commit()
                except Exception as e:
                    await db.rollback()
                    logger.error(f"Cash payment processing failed for customer {customer.id}: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")

            # Return customer with plan info
            stmt = select(Customer).options(selectinload(Customer.plan)).where(Customer.id == customer.id)
            result = await db.execute(stmt)
            customer_with_plan = result.scalar_one()

            return CustomerType(
                id=customer_with_plan.id,
                name=customer_with_plan.name,
                phone=customer_with_plan.phone,
                mac_address=customer_with_plan.mac_address,
                pppoe_username=customer_with_plan.pppoe_username,
                static_ip=customer_with_plan.static_ip,
                status=customer_with_plan.status.value,
                expiry=customer_with_plan.expiry.timestamp() if customer_with_plan.expiry else None,
                plan=PlanType(
                    id=customer_with_plan.plan.id,
                    name=customer_with_plan.plan.name,
                    speed=customer_with_plan.plan.speed,
                    price=customer_with_plan.plan.price,
                    duration_value=customer_with_plan.plan.duration_value,
                    duration_unit=customer_with_plan.plan.duration_unit.value,
                    connection_type=customer_with_plan.plan.connection_type.value
                ) if customer_with_plan.plan else None
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except IntegrityError as e:
            await db.rollback()
            if "customers_mac_address_key" in str(e):
                raise HTTPException(status_code=409, detail="A customer with this MAC address already exists")
            else:
                logger.error(f"Database integrity error in register_hotspot_and_pay: {str(e)}")
                raise HTTPException(status_code=409, detail="Registration failed due to duplicate data")
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to register hotspot customer: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to register customer. Please try again.")
        
    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def delete_plan(self, info, plan_id: int) -> bool:
        db: AsyncSession = info.context["db"]
        user = await get_current_user(info.context["user"])
        
        stmt = select(Plan).filter(Plan.id == plan_id, Plan.user_id == user.user_id)
        result = await db.execute(stmt)
        plan = result.scalar_one_or_none()

        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")

        try:
            await db.delete(plan)
            await db.commit()
            return True
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to delete plan {plan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to delete plan")

  
    @strawberry.mutation
    async def initiate_mpesa_payment(self, info, customer_id: int, amount: float, phone: str) -> PaymentInitiationResponse:
        """
        Initiate M-Pesa payment for existing customer
        """
        db: AsyncSession = info.context["db"]
        
        try:
            # Validate input parameters
            if amount <= 0:
                raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
            
            if not phone or len(phone.strip()) < 10:
                raise HTTPException(status_code=400, detail="Invalid phone number format")
            
            # Validate customer exists
            stmt = select(Customer).where(Customer.id == customer_id)
            result = await db.execute(stmt)
            customer = result.scalar_one_or_none()
            if not customer:
                raise HTTPException(status_code=404, detail="Customer not found")
            
            reference = f"PAYMENT-{customer_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            stk_response = await initiate_stk_push(
                phone_number=phone,
                amount=amount,
                reference=reference
            )
            
            if not stk_response:
                raise HTTPException(status_code=400, detail="Failed to initiate mobile money payment. Please try again.")
            
            # Save transaction to database without customer_id
            transaction = await save_mpesa_transaction(
                db=db,
                checkout_request_id=stk_response.checkout_request_id,
                phone_number=phone,
                amount=amount,
                reference=reference,
                merchant_request_id=stk_response.merchant_request_id
            )
            
            # Link transaction to customer using separate function
            await link_transaction_to_customer(
                db=db,
                checkout_request_id=stk_response.checkout_request_id,
                customer_id=customer_id
            )
            
            logger.info(f"STK Push initiated for customer {customer_id}, checkout_request_id: {stk_response.checkout_request_id}")
            
            return PaymentInitiationResponse(
                message="Mobile money payment initiated successfully. Please check your phone to complete payment.",
                checkout_request_id=stk_response.checkout_request_id,
                customer_id=customer_id,
                status="PENDING"
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"STK Push initiation failed for customer {customer_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Mobile money payment initiation failed. Please try again.")

    async def _provision_customer_to_router(self, db: AsyncSession, customer: Customer, router_id: int, mac_address: str, plan: Plan) -> bool:
        """
        Helper method to provision customer to router
        """
        try:
            from app.services.mikrotik import provision_customer_to_router
            provisioning_success = await provision_customer_to_router(
                router_id=router_id,
                customer_id=customer.id,
                mac_address=mac_address,
                plan_profile=plan.router_profile or plan.name
            )
            
            if provisioning_success:
                # Log successful provisioning
                log_entry = ProvisioningLog(
                    customer_id=customer.id,
                    router_id=router_id,
                    mac_address=mac_address,
                    action="AUTO_PROVISION",
                    status="SUCCESS",
                    details="Successfully provisioned after payment confirmation",
                    log_date=datetime.utcnow()
                )
                db.add(log_entry)
                return True
            else:
                raise Exception("Router provisioning returned False")
                
        except Exception as provision_error:
            await log_provisioning_failure(
                db, customer.id, router_id, mac_address, str(provision_error)
            )
            logger.error(f"Router provisioning failed for customer {customer.id}: {provision_error}")
            return False

    @strawberry.mutation
    @require_role(["admin"])
    async def manually_provision_customer(self, info, customer_id: int) -> CustomerType:
        db: AsyncSession = info.context["db"]
        
        try:
            stmt = select(Customer).options(selectinload(Customer.plan)).where(Customer.id == customer_id)
            result = await db.execute(stmt)
            customer = result.scalar_one_or_none()
            
            if not customer:
                raise HTTPException(status_code=404, detail="Customer not found")
            
            if not customer.plan:
                raise HTTPException(status_code=400, detail="Customer has no plan assigned")
            
            from app.services.mikrotik import provision_customer_to_router
            success = await provision_customer_to_router(
                router_id=customer.router_id,
                customer_id=customer.id,
                mac_address=customer.mac_address,
                plan_profile=customer.plan.router_profile or customer.plan.name
            )
            
            if success:
                customer.status = CustomerStatus.ACTIVE
                await db.commit()
                
                log_entry = ProvisioningLog(
                    customer_id=customer.id,
                    router_id=customer.router_id,
                    mac_address=customer.mac_address,
                    action="MANUAL_PROVISION",
                    status="SUCCESS",
                    details="Successfully provisioned via admin interface",
                    log_date=datetime.utcnow()
                )
                db.add(log_entry)
                await db.commit()
            else:
                raise HTTPException(status_code=500, detail="Failed to provision customer to router")
                
            stmt = select(Customer).options(selectinload(Customer.plan)).where(Customer.id == customer_id)
            result = await db.execute(stmt)
            customer_with_plan = result.scalar_one()
            
            return CustomerType(
                id=customer_with_plan.id,
                name=customer_with_plan.name,
                phone=customer_with_plan.phone,
                mac_address=customer_with_plan.mac_address,
                pppoe_username=customer_with_plan.pppoe_username,
                static_ip=customer_with_plan.static_ip,
                status=customer_with_plan.status.value,
                expiry=customer_with_plan.expiry.timestamp() if customer_with_plan.expiry else None,
                plan=PlanType(
                    id=customer_with_plan.plan.id,
                    name=customer_with_plan.plan.name,
                    speed=customer_with_plan.plan.speed,
                    price=customer_with_plan.plan.price,
                    duration_value=customer_with_plan.plan.duration_value,
                    duration_unit=customer_with_plan.plan.duration_unit.value,
                    connection_type=customer_with_plan.plan.connection_type.value
                ) if customer_with_plan.plan else None
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            log_entry = ProvisioningLog(
                customer_id=customer_id,
                router_id=customer.router_id if customer else None,
                mac_address=customer.mac_address if customer else None,
                action="MANUAL_PROVISION",
                status="FAILED",
                error=str(e)[:255],
                details="Manual provisioning attempt failed",
                log_date=datetime.utcnow()
            )
            db.add(log_entry)
            await db.commit()
            
            logger.error(f"Manual provisioning failed for customer {customer_id}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Manual provisioning failed: {str(e)}")

    @strawberry.mutation
    async def create_admin(self, info, email: str, password: str, organization_name: str) -> UserType:
        db: AsyncSession = info.context["db"]
        
        try:
            # Check if user already exists
            existing_user_stmt = select(User).filter(User.email == email.lower())
            existing_result = await db.execute(existing_user_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="User with this email already exists")
            
            user = await create_user(db, email, password, UserRole.ADMIN, organization_name)
            return UserType(
                id=user.id,
                email=user.email,
                role=user.role,
                organization_name=user.organization_name,
                user_code=user.user_code
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create admin user {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create admin user. Please try again.")

    @strawberry.mutation
    @require_role(["admin"])
    async def create_router(self, info, name: str, ip_address: str, username: str, password: str, port: int) -> RouterType:
        db: AsyncSession = info.context["db"]
        
        try:
            user = await get_current_user(info.context["user"])
            
            # Validate port number
            if port < 1 or port > 65535:
                raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")
            
            # Check for duplicate router name or IP
            existing_router_stmt = select(Router).filter(
                (Router.name == name) | (Router.ip_address == ip_address)
            )
            existing_result = await db.execute(existing_router_stmt)
            existing_router = existing_result.scalar_one_or_none()
            
            if existing_router:
                if existing_router.name == name:
                    raise HTTPException(status_code=409, detail="A router with this name already exists")
                else:
                    raise HTTPException(status_code=409, detail="A router with this IP address already exists")
            
            router = Router(
                user_id=user.user_id,
                name=name,
                ip_address=ip_address,
                username=username,
                password=password,
                port=port,
                created_at=datetime.utcnow()
            )
            
            db.add(router)
            await db.commit()
            await db.refresh(router)
            
            return RouterType(
                id=router.id,
                name=router.name,
                ip_address=router.ip_address,
                port=router.port
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except IntegrityError as e:
            await db.rollback()
            if "routers_name_key" in str(e):
                raise HTTPException(status_code=409, detail="A router with this name already exists")
            elif "routers_ip_address_key" in str(e):
                raise HTTPException(status_code=409, detail="A router with this IP address already exists")
            else:
                logger.error(f"Database integrity error while creating router: {str(e)}")
                raise HTTPException(status_code=409, detail="Router creation failed due to duplicate data")
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create router {name}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create router. Please try again.")

    @strawberry.mutation
    async def create_reseller(self, info, email: str, password: str, organization_name: str) -> UserType:
        db: AsyncSession = info.context["db"]
        
        try:
            # Check if admin exists
            stmt = select(User).filter(User.role == UserRole.ADMIN.value).limit(1)
            result = await db.execute(stmt)
            admin_exists = result.scalar_one_or_none() is not None
            if not admin_exists:
                raise HTTPException(status_code=403, detail="At least one admin must exist before creating resellers")
            
            # Check if user already exists
            existing_user_stmt = select(User).filter(User.email == email.lower())
            existing_result = await db.execute(existing_user_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="User with this email already exists")
            
            user = await create_user(db, email, password, UserRole.RESELLER, organization_name)
            return UserType(
                id=user.id,
                email=user.email,
                role=user.role,
                organization_name=user.organization_name,
                user_code=user.user_code
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create reseller {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create reseller. Please try again.")

    @strawberry.mutation
    async def login(self, info, email: str, password: str) -> str:
        db: AsyncSession = info.context["db"]
        
        try:
            if not email or not password:
                raise HTTPException(status_code=400, detail="Email and password are required")
            
            auth_result = await authenticate_user(db, email, password)
            return auth_result["access_token"]
            
        except HTTPException as e:
            if e.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            raise
        except Exception as e:
            logger.error(f"Login failed for {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Login failed. Please try again.")

    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def create_plan(
        self,
        info,
        name: str,
        speed: str,
        price: int,
        duration_value: int,
        duration_unit: str,
        connection_type: str,
        router_profile: Optional[str] = None
    ) -> PlanType:
        db: AsyncSession = info.context["db"]
        
        try:
            user = await get_current_user(info.context["user"])

            # Validate input parameters
            if price < 0:
                raise HTTPException(status_code=400, detail="Price cannot be negative")
            
            if duration_value < 1:
                raise HTTPException(status_code=400, detail="Duration value must be at least 1")

            # Validate the connection type
            try:
                connection_type_enum = ConnectionType(connection_type.lower())
            except ValueError:
                valid_types = [ct.value for ct in ConnectionType]
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid connection type. Must be one of: {', '.join(valid_types)}"
                )
            
            # Validate the duration unit
            try:
                duration_unit_enum = DurationUnit(duration_unit.upper())
            except ValueError:
                valid_units = [du.value for du in DurationUnit]
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid duration unit. Must be one of: {', '.join(valid_units)}"
                )

            # Check for duplicate plan name
            existing_plan_stmt = select(Plan).filter(Plan.name == name, Plan.user_id == user.user_id)
            existing_result = await db.execute(existing_plan_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="A plan with this name already exists")

            plan = Plan(
                name=name,
                speed=speed,
                price=price,
                duration_value=duration_value,
                duration_unit=duration_unit_enum,
                connection_type=connection_type_enum,
                user_id=user.user_id,
                router_profile=router_profile,
                created_at=datetime.utcnow()
            )
            
            db.add(plan)
            await db.commit()
            await db.refresh(plan)

            return PlanType(
                id=plan.id,
                name=plan.name,
                speed=plan.speed,
                price=plan.price,
                duration_value=plan.duration_value,
                duration_unit=plan.duration_unit.value,
                connection_type=plan.connection_type.value
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except IntegrityError as e:
            await db.rollback()
            if "plans_name_key" in str(e) or "unique" in str(e).lower():
                raise HTTPException(status_code=409, detail="A plan with this name already exists")
            else:
                logger.error(f"Database integrity error while creating plan: {str(e)}")
                raise HTTPException(status_code=409, detail="Plan creation failed due to duplicate data")
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create plan {name}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create plan. Please try again.")

    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def make_payment(self, info, customer_id: int, amount: int, days_paid_for: int, payment_method: str = "cash", payment_reference: Optional[str] = None) -> PaymentResponse:
        db: AsyncSession = info.context["db"]
        
        try:
            # Get current user with proper error handling
            user = None
            try:
                user = await get_current_user(info.context["user"])
            except HTTPException as auth_error:
                if auth_error.status_code == 401:
                    raise HTTPException(status_code=401, detail="Authentication required to make payments")
                raise auth_error
            
            # Validate input parameters
            if amount <= 0:
                raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
            
            if days_paid_for <= 0:
                raise HTTPException(status_code=400, detail="Days paid for must be greater than 0")
            
            # Validate payment method
            try:
                payment_method_enum = PaymentMethod(payment_method.lower())
            except ValueError:
                valid_methods = [method.value for method in PaymentMethod]
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
                )
            
            # Verify customer exists
            stmt = select(Customer).where(Customer.id == customer_id)
            result = await db.execute(stmt)
            customer = result.scalar_one_or_none()
            if not customer:
                raise HTTPException(status_code=404, detail="Customer not found")
            
            # Check authorization for resellers
            if user and user.role == UserRole.RESELLER and customer.user_id != user.user_id:
                raise HTTPException(status_code=403, detail="You can only make payments for your own customers")
            
            # Process payment
            payment = await record_customer_payment(
                db, customer_id, user.user_id if user else None, 
                float(amount), payment_method_enum, days_paid_for, payment_reference
            )
            
            return PaymentResponse(
                message=f"Payment of {amount} recorded successfully for customer {customer.name}"
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process payment for customer {customer_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Payment processing failed. Please try again.")

    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def record_payment(self, info, customer_id: int, amount: float, payment_method: str, days_paid_for: int, payment_reference: Optional[str] = None, notes: Optional[str] = None) -> CustomerPaymentType:
        db: AsyncSession = info.context["db"]
        
        try:
            # Validate input parameters
            if amount <= 0:
                raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
            
            if days_paid_for <= 0:
                raise HTTPException(status_code=400, detail="Days paid for must be greater than 0")
            
            # Validate payment method
            try:
                payment_method_enum = PaymentMethod(payment_method.lower())
            except ValueError:
                valid_methods = [method.value for method in PaymentMethod]
                raise HTTPException(
                    status_code=400, 
                    detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
                )
            
            # Verify customer exists
            stmt = select(Customer).where(Customer.id == customer_id)
            result = await db.execute(stmt)
            customer = result.scalar_one_or_none()
            if not customer:
                raise HTTPException(status_code=404, detail="Customer not found")
            
            # Process payment
            payment = await record_customer_payment(
                db, customer_id, customer.user_id, amount, 
                payment_method_enum, days_paid_for, payment_reference, notes
            )
            
            # Refresh to get customer relationship
            await db.refresh(payment, ["customer"])
            
            return CustomerPaymentType(
                id=payment.id,
                customer_id=payment.customer_id,
                customer_name=payment.customer.name,
                amount=payment.amount,
                payment_method=payment.payment_method.value,
                payment_reference=payment.payment_reference,
                payment_date=payment.payment_date.isoformat(),
                days_paid_for=payment.days_paid_for,
                status=payment.status.value,
                notes=payment.notes
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to record payment for customer {customer_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to record payment. Please try again.")

    @strawberry.mutation
    @require_role(["admin", "reseller"])
    async def pay_subscription(self, info, months: int) -> SubscriptionType:
        db: AsyncSession = info.context["db"]
        
        try:
            user = await get_current_user(info.context["user"])
            
            # Validate input
            if months <= 0:
                raise HTTPException(status_code=400, detail="Subscription months must be greater than 0")
            
            if months > 12:
                raise HTTPException(status_code=400, detail="Maximum subscription period is 12 months")
            
            # Create subscription
            subscription = await create_subscription(db, user.user_id, months)
            
            return SubscriptionType(
                id=subscription.id,
                is_active=subscription.is_active,
                paid_on=subscription.paid_on.isoformat(),
                expires_on=subscription.expires_on.isoformat() if subscription.expires_on else None,
                plan_type=subscription.plan_type,
                cost=subscription.cost
            )
            
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to process subscription payment for user {user.user_id if user else 'unknown'}: {str(e)}")
            raise HTTPException(status_code=500, detail="Subscription payment failed. Please try again.")


    async def log_provisioning_failure(db: AsyncSession, customer_id: int, router_id: int, 
                                    mac_address: str, error_message: str):
        """
        Log provisioning failure in the ProvisioningLog table with proper error handling
        """
        try:
            log_entry = ProvisioningLog(
                customer_id=customer_id,
                router_id=router_id,
                mac_address=mac_address,
                action="AUTO_PROVISION",
                status="FAILED",
                error=error_message[:255] if error_message else "Unknown error",  # Truncate if too long
                details=f"Automatic provisioning failed during registration: {error_message}"[:500],
                log_date=datetime.utcnow()
            )
            db.add(log_entry)
            await db.commit()
        except Exception as log_error:
            logger.error(f"Failed to log provisioning failure: {str(log_error)}")
            # Don't raise here as this is just logging - we don't want to fail the main operation
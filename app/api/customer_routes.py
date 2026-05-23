from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, text
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import secrets
import string

from app.db.database import get_db
from app.db.models import (
    Router, Customer, Plan, CustomerStatus, ConnectionType,
    CustomerPayment, PaymentMethod, PaymentStatus, DurationUnit,
    Payment, CustomerRating, ProvisioningLog, MpesaTransaction,
    UserBandwidthUsage, Voucher, CustomerUsagePeriod,
    ProvisioningAttempt, DevicePairing, ReconnectionAttempt,
    ZenoPayTransaction, MtnMomoTransaction,
)
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.pppoe_provisioning import (
    call_pppoe_provision, call_pppoe_remove,
    build_pppoe_payload, build_pppoe_remove_payload,
)

import logging

logger = logging.getLogger(__name__)


def _generate_pppoe_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

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
        
        # Check if customer with MAC already exists
        if request.mac_address:
            existing_customer_stmt = select(Customer).where(Customer.mac_address == request.mac_address)
            existing_result = await db.execute(existing_customer_stmt)
            if existing_result.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Customer with this MAC address already exists")
        
        pppoe_username = request.pppoe_username
        pppoe_password = request.pppoe_password

        if plan.connection_type == ConnectionType.PPPOE:
            if not pppoe_username:
                clean_phone = request.phone.replace("+", "").replace(" ", "")
                pppoe_username = f"pppoe_{clean_phone}"
            if not pppoe_password:
                pppoe_password = _generate_pppoe_password()

            existing_pppoe = select(Customer).where(Customer.pppoe_username == pppoe_username)
            existing_pppoe_result = await db.execute(existing_pppoe)
            if existing_pppoe_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=409,
                    detail=f"PPPoE username '{pppoe_username}' already exists"
                )

        # Create customer
        customer = Customer(
            name=request.name,
            phone=request.phone,
            mac_address=request.mac_address,
            pppoe_username=pppoe_username,
            pppoe_password=pppoe_password,
            static_ip=request.static_ip,
            status=CustomerStatus.INACTIVE,
            plan_id=request.plan_id,
            user_id=user.id,
            router_id=request.router_id
        )
        
        db.add(customer)
        await db.commit()
        await db.refresh(customer)
        
        logger.info(f"Customer registered: {customer.id} by user {user.id}")
        
        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "pppoe_username": customer.pppoe_username,
            "static_ip": customer.static_ip,
            "status": customer.status.value,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "user_id": customer.user_id,
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

        if request.plan_id is not None:
            plan_stmt = select(Plan).where(Plan.id == request.plan_id, Plan.user_id == user.id)
            plan_result = await db.execute(plan_stmt)
            if not plan_result.scalar_one_or_none():
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

        if request.pppoe_username is not None and request.pppoe_username != customer.pppoe_username:
            pppoe_stmt = select(Customer).where(
                Customer.pppoe_username == request.pppoe_username,
                Customer.id != customer_id,
            )
            pppoe_result = await db.execute(pppoe_stmt)
            if pppoe_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=409,
                    detail=f"PPPoE username '{request.pppoe_username}' already exists",
                )

        old_pppoe_username = customer.pppoe_username
        old_pppoe_password = customer.pppoe_password
        old_router_id = customer.router_id
        pppoe_changed = False

        update_fields = request.model_dump(exclude_none=True)
        if "expiry" in update_fields and update_fields["expiry"] is not None:
            update_fields["expiry"] = update_fields["expiry"].replace(tzinfo=None)
        for field, value in update_fields.items():
            setattr(customer, field, value)

        if customer.pppoe_username and customer.status == CustomerStatus.ACTIVE:
            pppoe_changed = (
                customer.pppoe_username != old_pppoe_username
                or customer.pppoe_password != old_pppoe_password
                or customer.router_id != old_router_id
            )

        await db.commit()
        await db.refresh(customer, attribute_names=["plan", "router"])

        provision_status = None
        if pppoe_changed and customer.router and customer.plan:
            if old_pppoe_username and old_router_id:
                try:
                    old_router_stmt = select(Router).where(Router.id == old_router_id)
                    old_router_result = await db.execute(old_router_stmt)
                    old_router_obj = old_router_result.scalar_one_or_none()
                    if old_router_obj:
                        remove_payload = build_pppoe_remove_payload(customer, old_router_obj)
                        remove_payload["pppoe_username"] = old_pppoe_username
                        await call_pppoe_remove(remove_payload)
                except Exception as e:
                    logger.warning(f"Failed to remove old PPPoE secret during edit: {e}")

            pppoe_payload = build_pppoe_payload(customer, customer.router)
            provision_result = await call_pppoe_provision(pppoe_payload)
            provision_status = "ok" if provision_result and provision_result.get("success") else "failed"

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
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error editing customer {customer_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to edit customer: {str(e)}")


@router.delete("/api/customers/{customer_id}")
async def delete_customer(
    customer_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Delete a customer and all related data. Removes PPPoE secret from router if active."""
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

        if customer.status == CustomerStatus.ACTIVE and customer.pppoe_username and customer.router:
            try:
                payload = build_pppoe_remove_payload(customer, customer.router)
                remove_result = await call_pppoe_remove(payload)
                deprovision_result = "ok" if remove_result and remove_result.get("success") else "failed"
            except Exception as e:
                logger.warning(f"Failed to remove PPPoE secret for customer {customer_id} during delete: {e}")
                deprovision_result = "failed"

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
        await db.execute(delete(ProvisioningLog).where(ProvisioningLog.customer_id == customer_id))
        await db.execute(delete(ProvisioningAttempt).where(ProvisioningAttempt.customer_id == customer_id))
        await db.execute(delete(DevicePairing).where(DevicePairing.customer_id == customer_id))
        await db.execute(delete(ReconnectionAttempt).where(ReconnectionAttempt.customer_id == customer_id))

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


@router.get("/api/customers")
async def get_customers_api(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all customers for the authenticated user, optionally filtered by router."""
    try:
        user = await get_current_user(token, db)
        
        stmt = select(Customer).where(Customer.user_id == user.id).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        )
        if router_id is not None:
            stmt = stmt.where(Customer.router_id == router_id)
        result = await db.execute(stmt)
        customers = result.scalars().all()
        
        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "pppoe_username": c.pppoe_username,
                "pppoe_password": c.pppoe_password,
                "static_ip": c.static_ip,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "plan_id": c.plan_id,
                "router_id": c.router_id,
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
            for c in customers
        ]
    except Exception as e:
        logger.error(f"Error fetching customers: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch customers")


@router.get("/api/customers/active")
async def get_active_customers(
    router_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Get all currently active guests, optionally filtered by router."""
    try:
        user = await get_current_user(token, db)
        stmt = select(Customer).where(
            Customer.user_id == user.id,
            Customer.status == CustomerStatus.ACTIVE
        ).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).order_by(Customer.expiry)
        if router_id is not None:
            stmt = stmt.where(Customer.router_id == router_id)
        
        result = await db.execute(stmt)
        customers = result.scalars().all()
        
        now = datetime.utcnow()
        
        return [
            {
                "id": c.id,
                "name": c.name,
                "phone": c.phone,
                "mac_address": c.mac_address,
                "pppoe_username": c.pppoe_username,
                "pppoe_password": c.pppoe_password,
                "static_ip": c.static_ip,
                "status": c.status.value,
                "expiry": c.expiry.isoformat() if c.expiry else None,
                "hours_remaining": (c.expiry - now).total_seconds() / 3600 if c.expiry and c.expiry > now else 0,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "plan_id": c.plan_id,
                "router_id": c.router_id,
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
            for c in customers
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
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "created_at": customer.created_at.isoformat() if customer.created_at else None,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
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
        if customer.status == CustomerStatus.ACTIVE and customer.expiry and customer.expiry > now:
            customer.expiry = customer.expiry + expiry_delta
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
        await db.refresh(customer)

        pppoe_payload = build_pppoe_payload(customer, customer.router)
        provision_result = await call_pppoe_provision(pppoe_payload)

        return {
            "success": True,
            "customer_id": customer.id,
            "pppoe_username": customer.pppoe_username,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_name": plan.name,
            "provision_result": "ok" if provision_result and provision_result.get("success") else "failed",
            "provision_error": provision_result.get("error") if provision_result else None,
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
            remove_result = await call_pppoe_remove(payload)

        customer.status = CustomerStatus.INACTIVE
        await db.commit()

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
            provision_result = await call_pppoe_provision(pppoe_payload)
            router_updated = bool(provision_result and provision_result.get("success"))

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

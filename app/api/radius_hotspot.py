"""
RADIUS Hotspot Flow Endpoints
==============================

These endpoints replicate the existing hotspot captive portal → pay → get internet flow,
but use RADIUS authentication instead of direct MikroTik API calls.

COMPLETELY SEPARATE from existing endpoints. Does not modify or call any existing code.

Flow:
1. User connects to hotspot → MikroTik redirects to captive portal
2. Frontend detects this is a RADIUS router (via /api/radius/routers/{id}/status)
3. Frontend calls POST /api/radius/hotspot/register-and-pay
4. M-Pesa STK push sent → callback goes to /api/radius/mpesa/callback (NOT the existing callback)
5. Callback creates RADIUS user with bandwidth + session timeout
6. Frontend polls GET /api/radius/hotspot/payment-status/{customer_id}
7. When status=ACTIVE, response includes RADIUS credentials (username + password)
8. Frontend auto-redirects to: http://<hotspot-gateway>/login?username=X&password=Y
9. MikroTik sends auth to FreeRADIUS → user gets online with rate limit + session timeout

Key differences from existing flow:
- Uses separate M-Pesa callback URL (doesn't touch existing callback)
- Provisions via RADIUS tables instead of MikroTik API
- Returns credentials so frontend can auto-login the user
- No IP binding bypass, no simple queues - RADIUS handles everything
"""

import json
import logging
import base64
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field

from app.db.database import get_db
from app.db.models import (
    Customer, Plan, Router, CustomerStatus,
    MpesaTransaction, MpesaTransactionStatus,
    PaymentMethod, CustomerPayment
)
from app.config import settings
from app.services.radius_provisioning import RadiusProvisioning
from app.services.radius_service import parse_speed_to_radius_format, calculate_session_timeout

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/radius", tags=["RADIUS Hotspot"])


# ============================================================================
# Pydantic Models
# ============================================================================

class RadiusHotspotPaymentRequest(BaseModel):
    """Request to register and pay for hotspot access on a RADIUS-enabled router"""
    mac_address: str = Field(..., description="Client MAC address")
    phone: str = Field(..., description="Phone number for M-Pesa payment")
    plan_id: int = Field(..., description="Plan ID to subscribe to")
    router_id: int = Field(..., description="Router ID (must be RADIUS-enabled)")
    name: Optional[str] = Field(None, description="Customer name (optional)")
    payment_method: str = Field("mobile_money", description="Payment method: mobile_money or cash")
    payment_reference: Optional[str] = Field(None, description="Reference for cash payments")


class RadiusPaymentStatusResponse(BaseModel):
    """Payment status with RADIUS credentials when ready"""
    customer_id: int
    status: str
    plan_name: Optional[str] = None
    expiry: Optional[str] = None
    # RADIUS-specific fields - only populated when status is ACTIVE
    auth_method: str = "RADIUS"
    radius_username: Optional[str] = None
    radius_password: Optional[str] = None
    message: Optional[str] = None


# ============================================================================
# Hotspot Registration + Payment (RADIUS version)
# ============================================================================

@router.post("/hotspot/register-and-pay")
async def radius_register_and_pay(
    request: RadiusHotspotPaymentRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a hotspot user and initiate payment for a RADIUS-enabled router.

    This is the RADIUS equivalent of /api/hotspot/register-and-pay.
    It uses a SEPARATE M-Pesa callback URL so it doesn't interfere with
    the existing payment flow.
    """
    try:
        # Validate payment method
        try:
            payment_method_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            valid_methods = [method.value for method in PaymentMethod]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
            )

        # Validate router exists and is RADIUS-enabled
        router_result = await db.execute(
            select(Router).where(Router.id == request.router_id)
        )
        db_router = router_result.scalar_one_or_none()
        if not db_router:
            raise HTTPException(status_code=404, detail="Router not found")

        if db_router.auth_method != 'RADIUS':
            raise HTTPException(
                status_code=400,
                detail="This router is not configured for RADIUS. Use the standard /api/hotspot/register-and-pay endpoint."
            )

        user_id = db_router.user_id

        # Validate plan exists
        plan_result = await db.execute(
            select(Plan).where(Plan.id == request.plan_id)
        )
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")

        # Validate phone number
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")

        # Check if customer exists by MAC
        customer_result = await db.execute(
            select(Customer).options(
                selectinload(Customer.plan),
                selectinload(Customer.router)
            ).where(Customer.mac_address == request.mac_address)
        )
        existing_customer = customer_result.scalar_one_or_none()

        if existing_customer:
            # Store pending update data with RADIUS flag
            pending_data = {
                "requested_at": datetime.utcnow().isoformat(),
                "plan_id": request.plan_id,
                "plan_name": plan.name,
                "duration_value": plan.duration_value,
                "duration_unit": plan.duration_unit.value,
                "speed": plan.speed,
                "payment_method": payment_method_enum.value,
                "router_id": request.router_id,
                "phone": request.phone,
                "name": request.name,
                "requested_by_user_id": user_id,
                "auth_method": "RADIUS"  # Flag for RADIUS provisioning
            }
            existing_customer.pending_update_data = json.dumps(pending_data)
            existing_customer.status = (
                CustomerStatus.PENDING if payment_method_enum == PaymentMethod.MOBILE_MONEY
                else CustomerStatus.ACTIVE
            )
            existing_customer.router_id = request.router_id
            existing_customer.plan_id = request.plan_id
            if request.name:
                existing_customer.name = request.name
            existing_customer.phone = request.phone
            customer = existing_customer
            await db.flush()
        else:
            # Create new customer
            customer_name = request.name if request.name else f"Guest {request.phone[-4:]}"
            customer = Customer(
                name=customer_name,
                phone=request.phone,
                mac_address=request.mac_address,
                status=CustomerStatus.INACTIVE,
                plan_id=request.plan_id,
                user_id=user_id,
                router_id=request.router_id
            )
            db.add(customer)
            await db.flush()

        if payment_method_enum == PaymentMethod.MOBILE_MONEY:
            # Initiate STK push with RADIUS-specific callback URL
            try:
                reference = f"RADIUS-{customer.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

                stk_response = await _initiate_radius_stk_push(
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference
                )

                # Store transaction
                mpesa_txn = MpesaTransaction(
                    checkout_request_id=stk_response['checkout_request_id'],
                    merchant_request_id=stk_response['merchant_request_id'],
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference,
                    customer_id=customer.id,
                    status=MpesaTransactionStatus.pending
                )
                db.add(mpesa_txn)
                await db.flush()

                customer.status = CustomerStatus.PENDING
                await db.commit()
                await db.refresh(customer)

                logger.info(f"[RADIUS] STK Push initiated for customer {customer.id} ({request.mac_address})")

            except Exception as e:
                customer_id = getattr(customer, "id", None)
                await db.rollback()
                logger.exception("RADIUS payment initiation failed for customer %s", customer_id)
                raise HTTPException(
                    status_code=400,
                    detail=f"Mobile money payment initiation failed: {str(e)}"
                )
        else:
            # Cash payment - provision immediately via RADIUS
            try:
                from app.services.reseller_payments import record_customer_payment
                await record_customer_payment(
                    db, customer.id, user_id, float(plan.price),
                    payment_method_enum, plan.duration_value, request.payment_reference
                )

                # Provision RADIUS user immediately
                provisioning = RadiusProvisioning(db)
                radius_result = await provisioning.provision_hotspot_user(
                    customer_id=customer.id,
                    mac_address=customer.mac_address,
                    phone=customer.phone,
                    plan_speed=plan.speed,
                    plan_duration_value=plan.duration_value,
                    plan_duration_unit=plan.duration_unit.value,
                    router_id=request.router_id,
                    existing_expiry=customer.expiry
                )

                if radius_result['success']:
                    # Update customer status and expiry
                    customer.status = CustomerStatus.ACTIVE
                    customer.expiry = datetime.fromisoformat(radius_result['expiry'])
                    customer.pending_update_data = json.dumps({
                        "auth_method": "RADIUS",
                        "radius_username": radius_result['username'],
                        "radius_password": radius_result['password']
                    })
                    await db.commit()
                else:
                    raise Exception(radius_result.get('error', 'RADIUS provisioning failed'))

            except Exception as e:
                await db.rollback()
                logger.error(f"Cash payment processing failed for customer {customer.id}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")

        return {
            "id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "mac_address": customer.mac_address,
            "status": customer.status.value,
            "plan_id": customer.plan_id,
            "router_id": customer.router_id,
            "auth_method": "RADIUS",
            "message": (
                "STK Push sent to phone"
                if payment_method_enum == PaymentMethod.MOBILE_MONEY
                else "Payment recorded, RADIUS user created"
            ),
            # For cash payments, include credentials immediately
            **(
                {
                    "radius_username": radius_result['username'],
                    "radius_password": radius_result['password']
                }
                if payment_method_enum != PaymentMethod.MOBILE_MONEY and radius_result.get('success')
                else {}
            )
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in RADIUS hotspot registration")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register: {str(e)}")


# ============================================================================
# M-Pesa Callback for RADIUS payments (SEPARATE from existing callback)
# ============================================================================

@router.post("/mpesa/callback")
async def radius_mpesa_callback(payload: dict, db: AsyncSession = Depends(get_db)):
    """
    Handle M-Pesa STK Push callback for RADIUS payments.

    This is a COMPLETELY SEPARATE callback from /api/mpesa/callback.
    It only handles payments initiated via /api/radius/hotspot/register-and-pay.

    After successful payment, it provisions the user via RADIUS instead of
    direct MikroTik API calls.
    """
    try:
        body = payload.get("Body", {})
        stk_callback = body.get("stkCallback", {})
        checkout_request_id = stk_callback.get("CheckoutRequestID")
        result_code = stk_callback.get("ResultCode")

        logger.info(f"[RADIUS CALLBACK] Received for {checkout_request_id}, result: {result_code}")

        if not checkout_request_id:
            return {"ResultCode": 1, "ResultDesc": "Missing CheckoutRequestID"}

        # Find the transaction
        txn_result = await db.execute(
            select(MpesaTransaction).where(
                MpesaTransaction.checkout_request_id == checkout_request_id
            )
        )
        mpesa_txn = txn_result.scalar_one_or_none()

        if not mpesa_txn:
            logger.error(f"[RADIUS CALLBACK] Transaction not found: {checkout_request_id}")
            return {"ResultCode": 1, "ResultDesc": "Transaction not found"}

        if mpesa_txn.status != MpesaTransactionStatus.pending:
            logger.warning(f"[RADIUS CALLBACK] Duplicate callback for {checkout_request_id}")
            return {"ResultCode": 0, "ResultDesc": "Already processed"}

        customer_id = mpesa_txn.customer_id
        if not customer_id:
            logger.error(f"[RADIUS CALLBACK] No customer_id for transaction {checkout_request_id}")
            return {"ResultCode": 1, "ResultDesc": "No customer linked"}

        # Load customer with plan and router
        customer_result = await db.execute(
            select(Customer).options(
                selectinload(Customer.plan),
                selectinload(Customer.router)
            ).where(Customer.id == customer_id)
        )
        customer = customer_result.scalar_one_or_none()

        if not customer:
            logger.error(f"[RADIUS CALLBACK] Customer {customer_id} not found")
            return {"ResultCode": 1, "ResultDesc": "Customer not found"}

        if result_code == 0:
            # Payment successful
            logger.info(f"[RADIUS CALLBACK] Payment CONFIRMED for customer {customer.id}")

            # Extract M-Pesa metadata
            callback_metadata = stk_callback.get("CallbackMetadata", {})
            items = callback_metadata.get("Item", [])
            receipt_number = None
            amount = None
            for item in items:
                if item.get("Name") == "MpesaReceiptNumber":
                    receipt_number = item.get("Value")
                elif item.get("Name") == "Amount":
                    amount = item.get("Value")

            # Update transaction status
            mpesa_txn.status = MpesaTransactionStatus.completed
            mpesa_txn.mpesa_receipt_number = receipt_number

            # Determine plan (check for pending plan change)
            pending_data = None
            if customer.pending_update_data:
                try:
                    pending_data = (
                        json.loads(customer.pending_update_data)
                        if isinstance(customer.pending_update_data, str)
                        else customer.pending_update_data
                    )
                except (json.JSONDecodeError, TypeError):
                    pending_data = None

            if pending_data and pending_data.get("plan_id"):
                plan_result = await db.execute(
                    select(Plan).where(Plan.id == pending_data["plan_id"])
                )
                plan = plan_result.scalar_one_or_none() or customer.plan
                if plan:
                    customer.plan_id = plan.id
            else:
                plan = customer.plan

            if not plan:
                logger.error(f"[RADIUS CALLBACK] No plan for customer {customer.id}")
                return {"ResultCode": 1, "ResultDesc": "No plan found"}

            duration_value = plan.duration_value
            duration_unit = plan.duration_unit.value.upper()

            # Record payment
            from app.services.reseller_payments import record_customer_payment

            if duration_unit == "MINUTES":
                days_paid_for = max(1, duration_value // (24 * 60))
            elif duration_unit == "HOURS":
                days_paid_for = max(1, duration_value // 24)
            else:
                days_paid_for = duration_value

            payment = await record_customer_payment(
                db=db,
                customer_id=customer.id,
                reseller_id=customer.user_id,
                amount=float(amount or mpesa_txn.amount),
                payment_method=PaymentMethod.MOBILE_MONEY,
                days_paid_for=days_paid_for,
                payment_reference=receipt_number,
                notes=f"RADIUS M-Pesa STK Push. TX: {checkout_request_id}",
                duration_value=duration_value,
                duration_unit=duration_unit
            )

            logger.info(f"[RADIUS CALLBACK] Payment recorded: ID {payment.id}")

            # Provision via RADIUS
            provisioning = RadiusProvisioning(db)
            radius_result = await provisioning.provision_hotspot_user(
                customer_id=customer.id,
                mac_address=customer.mac_address,
                phone=customer.phone,
                plan_speed=plan.speed,
                plan_duration_value=duration_value,
                plan_duration_unit=duration_unit,
                router_id=customer.router_id,
                existing_expiry=customer.expiry
            )

            if radius_result['success']:
                customer.status = CustomerStatus.ACTIVE
                customer.expiry = datetime.fromisoformat(radius_result['expiry'])
                # Store credentials so payment-status endpoint can return them
                customer.pending_update_data = json.dumps({
                    "auth_method": "RADIUS",
                    "radius_username": radius_result['username'],
                    "radius_password": radius_result['password'],
                    "provisioned_at": datetime.utcnow().isoformat()
                })
                await db.commit()
                logger.info(f"[RADIUS CALLBACK] User provisioned: {radius_result['username']}")
            else:
                logger.error(f"[RADIUS CALLBACK] Provisioning failed: {radius_result.get('error')}")
                customer.status = CustomerStatus.ACTIVE  # Payment was successful even if provisioning failed
                customer.expiry = datetime.utcnow() + timedelta(
                    **{duration_unit.lower(): duration_value}
                )
                await db.commit()

            return {"ResultCode": 0, "ResultDesc": "RADIUS payment processed successfully"}

        else:
            # Payment failed
            logger.info(f"[RADIUS CALLBACK] Payment FAILED for customer {customer.id}")
            mpesa_txn.status = MpesaTransactionStatus.failed
            customer.status = CustomerStatus.INACTIVE
            await db.commit()
            return {"ResultCode": 0, "ResultDesc": "Payment failed"}

    except Exception as e:
        logger.error(f"[RADIUS CALLBACK] Error: {str(e)}")
        return {"ResultCode": 1, "ResultDesc": f"Error: {str(e)}"}


# ============================================================================
# Payment Status (with RADIUS credentials)
# ============================================================================

@router.get("/hotspot/payment-status/{customer_id}", response_model=RadiusPaymentStatusResponse)
async def radius_payment_status(
    customer_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get payment status for a RADIUS hotspot customer.

    When payment is complete and RADIUS user is provisioned, this returns
    the credentials needed to auto-login to the MikroTik hotspot.

    The frontend should:
    1. Poll this endpoint every 2-3 seconds after initiating payment
    2. When status becomes "active", build the MikroTik login URL using
       the `gw` parameter from the original captive portal redirect AND
       the returned credentials:
       http://<gw>/login?username=<radius_username>&password=<radius_password>

    IMPORTANT: The gateway address (`gw`) comes from the initial MikroTik
    redirect to your captive portal (the $(hostname) variable). Do NOT use
    the router's management IP from the database - clients can't reach that.
    The frontend already has the correct gateway from the URL parameters.
    """
    try:
        result = await db.execute(
            select(Customer).options(
                selectinload(Customer.plan),
                selectinload(Customer.router)
            ).where(Customer.id == customer_id)
        )
        customer = result.scalar_one_or_none()

        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        # Parse stored RADIUS credentials from pending_update_data
        radius_username = None
        radius_password = None
        auth_method = "RADIUS"

        if customer.pending_update_data:
            try:
                pending = (
                    json.loads(customer.pending_update_data)
                    if isinstance(customer.pending_update_data, str)
                    else customer.pending_update_data
                )
                if pending.get("auth_method") == "RADIUS":
                    radius_username = pending.get("radius_username")
                    radius_password = pending.get("radius_password")
            except (json.JSONDecodeError, TypeError):
                pass

        return RadiusPaymentStatusResponse(
            customer_id=customer.id,
            status=customer.status.value,
            plan_name=customer.plan.name if customer.plan else None,
            expiry=customer.expiry.isoformat() if customer.expiry else None,
            auth_method=auth_method,
            radius_username=radius_username if customer.status == CustomerStatus.ACTIVE else None,
            radius_password=radius_password if customer.status == CustomerStatus.ACTIVE else None,
            message=(
                "Payment confirmed. Use credentials to login."
                if customer.status == CustomerStatus.ACTIVE and radius_username
                else "Waiting for payment confirmation..."
                if customer.status == CustomerStatus.PENDING
                else "Payment not yet initiated"
            )
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting RADIUS payment status for customer {customer_id}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")


# ============================================================================
# M-Pesa STK Push Helper (separate from existing mpesa.py)
# ============================================================================

async def _initiate_radius_stk_push(
    phone_number: str,
    amount: float,
    reference: str
) -> dict:
    """
    Initiate M-Pesa STK Push with RADIUS-specific callback URL.

    This is a standalone function that doesn't modify or depend on the
    existing mpesa.py initiate_stk_push function. It uses the same
    M-Pesa credentials but points the callback to /api/radius/mpesa/callback.
    """
    import httpx

    # Get access token (same credentials as existing)
    credentials = f"{settings.MPESA_CONSUMER_KEY}:{settings.MPESA_CONSUMER_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )

    async with httpx.AsyncClient() as client:
        # Get token
        token_response = await client.get(
            f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
            headers={"Authorization": f"Basic {encoded_credentials}"}
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        # Build RADIUS callback URL
        # Append /radius to the existing callback base URL
        existing_callback = settings.MPESA_CALLBACK_URL  # e.g., "https://your-server.com/api/mpesa/callback"
        # Extract base URL (everything before /api/mpesa/callback)
        if "/api/mpesa/callback" in existing_callback:
            callback_base = existing_callback.replace("/api/mpesa/callback", "")
        elif "/api/" in existing_callback:
            callback_base = existing_callback.rsplit("/api/", 1)[0]
        else:
            callback_base = existing_callback.rstrip("/")

        radius_callback_url = f"{callback_base}/api/radius/mpesa/callback"

        logger.info(f"[RADIUS] Using callback URL: {radius_callback_url}")

        # Initiate STK push
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(
            f"{settings.MPESA_SHORTCODE}{settings.MPESA_PASSKEY}{timestamp}".encode()
        ).decode()

        payload = {
            "BusinessShortCode": settings.MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": settings.MPESA_SHORTCODE,
            "PhoneNumber": phone_number,
            "CallBackURL": radius_callback_url,
            "AccountReference": reference,
            "TransactionDesc": "RADIUS Hotspot Payment"
        }

        response = await client.post(
            f"{base_url}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )

        if response.status_code != 200:
            logger.error(f"[RADIUS] M-Pesa API Error {response.status_code}: {response.text}")

        response.raise_for_status()
        result = response.json()
        logger.info(f"[RADIUS] STK Push initiated: {result}")

        return {
            'checkout_request_id': result["CheckoutRequestID"],
            'merchant_request_id': result["MerchantRequestID"]
        }

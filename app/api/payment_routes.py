from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from app.db.database import get_db
from app.db.models import (
    Router, Customer, Plan, MpesaTransaction, MpesaTransactionStatus,
    CustomerStatus, CustomerPayment, ConnectionType, User,
)
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address
from app.services.mpesa_transactions import update_mpesa_transaction_status
from app.services.billing import make_payment
from app.config import settings
import logging
import json
import asyncio
import time

logger = logging.getLogger(__name__)

router = APIRouter(tags=["payments"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class HotspotPaymentRequest(BaseModel):
    phone: str
    plan_id: int
    mac_address: str
    router_id: int
    name: Optional[str] = None
    payment_method: str = "mobile_money"  # mobile_money or cash
    payment_reference: Optional[str] = None


class InitiateMpesaPaymentRequest(BaseModel):
    customer_id: int
    amount: float
    phone: str


# ---------------------------------------------------------------------------
# MikroTik bypass helpers (used by the callback)
# ---------------------------------------------------------------------------

def _call_mikrotik_bypass_sync(hotspot_payload: dict) -> dict:
    """
    Synchronous function to provision customer on MikroTik.
    Runs in thread pool to not block async event loop.
    CRITICAL: This runs after payment - must not block other customers from paying!
    """
    import time
    
    router_ip = hotspot_payload.get("router_ip", settings.MIKROTIK_HOST)
    router_username = hotspot_payload.get("router_username", settings.MIKROTIK_USERNAME)
    router_password = hotspot_payload.get("router_password", settings.MIKROTIK_PASSWORD)
    router_port = hotspot_payload.get("router_port", settings.MIKROTIK_PORT)
    
    logger.info(f"[THREAD] Connecting to MikroTik router at {router_ip}:{router_port}")
    
    api = MikroTikAPI(
        router_ip,
        router_username,
        router_password,
        router_port,
        timeout=15,
        connect_timeout=5
    )

    if not api.connect():
        logger.error(f"[THREAD] Failed to connect to MikroTik router at {router_ip}")
        return {"error": "Failed to connect"}

    try:
        result = api.add_customer_bypass_mode(
            hotspot_payload["mac_address"],
            hotspot_payload["username"],
            hotspot_payload["password"],
            hotspot_payload["time_limit"],
            hotspot_payload["bandwidth_limit"],
            hotspot_payload["comment"],
            router_ip,
            router_username,
            router_password
        )

        logger.info(f"[THREAD] MikroTik API Response: {json.dumps(result, indent=2)}")
        
        # If queue wasn't created (client not connected), retry after delay
        queue_result = result.get("queue_result", {})
        if queue_result and queue_result.get("pending"):
            logger.info(f"[THREAD] Queue pending for {hotspot_payload['mac_address']}, will retry in 5 seconds...")
            time.sleep(5)  # Sync sleep in thread pool is fine
            
            if not api.connected:
                api.connect()
            
            if api.connected:
                normalized_mac = normalize_mac_address(hotspot_payload["mac_address"])
                username = normalized_mac.replace(":", "")
                rate_limit = api._parse_speed_to_mikrotik(hotspot_payload["bandwidth_limit"])
                
                client_ip = api.get_client_ip_by_mac(normalized_mac)
                
                if client_ip:
                    retry_result = api.send_command("/queue/simple/add", {
                        "name": f"plan_{username}",
                        "target": f"{client_ip}/32",
                        "max-limit": rate_limit,
                        "comment": f"MAC:{hotspot_payload['mac_address']}|Plan rate limit"
                    })
                    if retry_result.get("error") and "already have" in retry_result.get("error", "").lower():
                        queues_result = api.get_simple_queues_minimal()
                        if queues_result.get("success") and queues_result.get("data"):
                            for queue_item in queues_result["data"]:
                                if str(queue_item.get("name", "")).lower() == f"plan_{username}".lower() and queue_item.get(".id"):
                                    retry_result = api.send_command("/queue/simple/set", {
                                        "numbers": queue_item[".id"],
                                        "target": f"{client_ip}/32",
                                        "max-limit": rate_limit,
                                        "disabled": "no"
                                    })
                                    break
                    bypass_result = api.ensure_queue_fasttrack_bypass([client_ip])
                    if bypass_result.get("error"):
                        logger.warning(
                            f"[THREAD] Queue exists but FastTrack bypass setup failed for {client_ip}: {bypass_result.get('error')}"
                        )
                    logger.info(f"[THREAD] Queue created for {username} -> {client_ip}: {retry_result}")
                else:
                    logger.warning(f"[THREAD] Still no IP for {hotspot_payload['mac_address']} - queue will be synced later")
        
        return result
    finally:
        api.disconnect()


async def call_mikrotik_bypass(hotspot_payload: dict):
    """
    Async wrapper that runs MikroTik bypass provisioning in a thread pool.
    CRITICAL: Runs in thread pool so it doesn't block payment processing for other customers!
    NOTE: Does NOT use mikrotik_lock -- provisioning creates its own connection and
    must never be blocked behind slow background sync/cleanup jobs. A paying customer
    should get internet immediately, not wait 2+ minutes for a sync job to finish.
    """
    try:
        result = await asyncio.to_thread(_call_mikrotik_bypass_sync, hotspot_payload)
        if result and result.get("error"):
            logger.error(f"MikroTik bypass failed: {result['error']}")
    except Exception as e:
        logger.error(f"Error while processing MikroTik bypass: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/mpesa/callback")
async def mpesa_direct_callback(payload: dict, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Handle standard M-Pesa STK Push callback"""
    logger.info(f"--- M-Pesa Direct Callback Received: {json.dumps(payload, indent=2)}")
    
    try:
        # Extract M-Pesa callback data
        body = payload.get("Body", {})
        stk_callback = body.get("stkCallback", {})
        
        checkout_request_id = stk_callback.get("CheckoutRequestID")
        merchant_request_id = stk_callback.get("MerchantRequestID")
        result_code = stk_callback.get("ResultCode")
        result_desc = stk_callback.get("ResultDesc")
        
        if not checkout_request_id:
            logger.error("Missing CheckoutRequestID in callback")
            return {"ResultCode": 1, "ResultDesc": "Missing CheckoutRequestID"}
        
        # Look up transaction
        from app.db.models import MpesaTransaction, MpesaTransactionStatus
        stmt = select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_request_id)
        result = await db.execute(stmt)
        mpesa_txn = result.scalar_one_or_none()
        
        if not mpesa_txn:
            logger.error(f"Transaction not found for CheckoutRequestID: {checkout_request_id}")
            return {"ResultCode": 1, "ResultDesc": "Transaction not found"}
        
        # DUPLICATE CALLBACK PROTECTION: Skip if already processed
        if mpesa_txn.status in (MpesaTransactionStatus.completed, MpesaTransactionStatus.failed):
            logger.warning(f"Duplicate callback ignored for {checkout_request_id} - status: {mpesa_txn.status.value}")
            return {"ResultCode": 0, "ResultDesc": "Already processed"}
        
        # Extract callback metadata
        callback_metadata = stk_callback.get("CallbackMetadata", {})
        items = callback_metadata.get("Item", [])
        
        receipt_number = None
        amount = None
        phone_number = None
        
        for item in items:
            name = item.get("Name")
            if name == "MpesaReceiptNumber":
                receipt_number = item.get("Value")
            elif name == "Amount":
                amount = item.get("Value")
            elif name == "PhoneNumber":
                phone_number = item.get("Value")
        
        # Update transaction status and always store result details
        from app.db.models import FailureSource
        mpesa_txn.result_code = str(result_code) if result_code is not None else None
        mpesa_txn.result_desc = result_desc
        
        if result_code == 0:
            mpesa_txn.status = MpesaTransactionStatus.completed
            mpesa_txn.mpesa_receipt_number = receipt_number
            mpesa_txn.failure_source = None  # Success - no failure
            status = "completed"
        else:
            mpesa_txn.status = MpesaTransactionStatus.failed
            mpesa_txn.failure_source = FailureSource.CLIENT
            status = "failed"
            logger.warning(f"Transaction {checkout_request_id} failed (client): code={result_code}, desc={result_desc}")
        
        mpesa_txn.updated_at = datetime.utcnow()
        await db.commit()
        
        # Get customer via transaction
        customer_id = mpesa_txn.customer_id
        stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id)
        )
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            logger.error(f"Customer {customer_id} not found")
            return {"ResultCode": 1, "ResultDesc": "Customer not found"}
        
        # Process payment similar to lipay callback
        if status == "completed":
            logger.info(f"PAYMENT CONFIRMED for customer {customer.id}")
            
            # Record payment
            from app.services.reseller_payments import record_customer_payment
            from app.db.models import PaymentMethod
            
            # Check for pending plan change (customer paying for a different plan)
            pending_data = None
            if customer.pending_update_data:
                try:
                    pending_data = json.loads(customer.pending_update_data) if isinstance(customer.pending_update_data, str) else customer.pending_update_data
                except (json.JSONDecodeError, TypeError):
                    pending_data = None
            
            # Use pending plan data if available, otherwise use customer's current plan
            if pending_data and pending_data.get("plan_id"):
                # Fetch the plan they're actually paying for
                pending_plan_stmt = select(Plan).where(Plan.id == pending_data["plan_id"])
                pending_plan_result = await db.execute(pending_plan_stmt)
                plan = pending_plan_result.scalar_one_or_none() or customer.plan
                
                # Update customer's plan_id to the new plan
                if plan:
                    customer.plan_id = plan.id
                    logger.info(f"[PLAN] Updated customer {customer.id} plan_id to {plan.id} ({plan.name})")
            else:
                plan = customer.plan
            
            duration_value = plan.duration_value if plan else 1
            duration_unit = plan.duration_unit.value.upper() if plan else "DAYS"
            
            logger.info(f"[PLAN DEBUG] Customer {customer.id} - Plan: {plan.name if plan else 'None'}, "
                       f"duration_value: {duration_value}, duration_unit: {duration_unit}")
            
            # Clear pending_update_data after applying
            customer.pending_update_data = None
            
            # Calculate days_paid_for for financial tracking (minimum 1 day)
            if duration_unit == "MINUTES":
                days_paid_for = max(1, duration_value // (24 * 60))  # minutes to days
            elif duration_unit == "HOURS":
                days_paid_for = max(1, duration_value // 24)  # hours to days
            else:  # DAYS
                days_paid_for = duration_value
            
            payment = await record_customer_payment(
                db=db,
                customer_id=customer.id,
                reseller_id=customer.user_id,
                amount=float(amount or mpesa_txn.amount),
                payment_method=PaymentMethod.MOBILE_MONEY,
                days_paid_for=days_paid_for,
                payment_reference=receipt_number,
                notes=f"M-Pesa STK Push. TX: {checkout_request_id}",
                duration_value=duration_value,
                duration_unit=duration_unit
            )
            
            logger.info(f"[AUDIT] Payment recorded: ID {payment.id}, Amount: {amount}, Days: {days_paid_for}")
            
            # Provision to MikroTik if hotspot
            if customer.mac_address and customer.router:
                router = customer.router
                
                # Convert duration to MikroTik format (m=minutes, h=hours, d=days)
                duration_unit = plan.duration_unit.value.upper()
                if duration_unit == "MINUTES":
                    time_limit = f"{int(duration_value)}m"
                elif duration_unit == "HOURS":
                    time_limit = f"{int(duration_value)}h"
                elif duration_unit == "DAYS":
                    time_limit = f"{int(duration_value)}d"
                else:
                    time_limit = f"{int(duration_value)}h"  # Default to hours
                
                hotspot_payload = {
                    "mac_address": customer.mac_address,
                    "username": customer.mac_address.replace(":", ""),
                    "password": customer.mac_address.replace(":", ""),
                    "time_limit": time_limit,
                    "bandwidth_limit": f"{plan.speed}",
                    "comment": f"Payment successful for {customer.name}",
                    "router_ip": router.ip_address,
                    "router_username": router.username,
                    "router_password": router.password,
                    "router_port": router.port,
                }
                logger.info(f"Prepared MikroTik Payload for customer {customer.id} -> Router: {router.ip_address}")
                background_tasks.add_task(call_mikrotik_bypass, hotspot_payload)
            
            return {"ResultCode": 0, "ResultDesc": "Payment processed successfully"}
        
        else:
            logger.info(f"Payment failed for customer {customer.id}")
            customer.status = CustomerStatus.INACTIVE
            await db.commit()
            return {"ResultCode": 0, "ResultDesc": "Payment failed"}
            
    except Exception as e:
        logger.error(f"Error processing M-Pesa callback: {str(e)}")
        # Try to record the server-side failure on the transaction
        try:
            from app.db.models import FailureSource
            if checkout_request_id:
                async with db.begin():
                    fail_stmt = select(MpesaTransaction).where(
                        MpesaTransaction.checkout_request_id == checkout_request_id
                    )
                    fail_result = await db.execute(fail_stmt)
                    fail_txn = fail_result.scalar_one_or_none()
                    if fail_txn and fail_txn.status == MpesaTransactionStatus.pending:
                        fail_txn.status = MpesaTransactionStatus.failed
                        fail_txn.failure_source = FailureSource.SERVER
                        fail_txn.result_code = "SERVER_ERROR"
                        fail_txn.result_desc = f"Server error during callback processing: {str(e)[:450]}"
                        fail_txn.updated_at = datetime.utcnow()
        except Exception as inner_e:
            logger.error(f"Failed to record server error on transaction: {str(inner_e)}")
        return {"ResultCode": 1, "ResultDesc": f"Error: {str(e)}"}


@router.post("/api/mpesa/initiate-payment")
async def initiate_mpesa_payment_api(
    request: InitiateMpesaPaymentRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Initiate M-Pesa payment for existing customer"""
    current_user = await get_current_user(token, db)
    try:
        from app.services.mpesa import initiate_stk_push
        from app.services.mpesa_transactions import save_mpesa_transaction, link_transaction_to_customer
        
        # Validate input parameters
        if request.amount <= 0:
            raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
        
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")
        
        # Validate customer exists
        stmt = select(Customer).where(Customer.id == request.customer_id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        # Get the owner's shortcode for STK push
        owner_shortcode = None
        if customer.user_id:
            owner_result = await db.execute(select(User.mpesa_shortcode).where(User.id == customer.user_id))
            owner_shortcode = owner_result.scalar_one_or_none()
        
        reference = f"PAYMENT-{request.customer_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        try:
            stk_response = await initiate_stk_push(
                phone_number=request.phone,
                amount=request.amount,
                reference=reference,
                user_id=customer.user_id,
                mac_address=customer.mac_address,
                shortcode=owner_shortcode
            )
        except Exception as stk_error:
            # STK push failed - record the failure so we can track M-Pesa API issues
            from app.db.models import FailureSource
            failed_txn = MpesaTransaction(
                checkout_request_id=f"FAILED-{reference}",
                phone_number=request.phone,
                amount=request.amount,
                reference=reference,
                customer_id=request.customer_id,
                status=MpesaTransactionStatus.failed,
                failure_source=FailureSource.MPESA_API,
                result_code="STK_PUSH_FAILED",
                result_desc=f"STK Push initiation failed: {str(stk_error)[:450]}",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(failed_txn)
            await db.commit()
            logger.error(f"STK Push failed for customer {request.customer_id}: {str(stk_error)}")
            raise HTTPException(status_code=500, detail=f"Failed to initiate payment: {str(stk_error)}")
        
        if not stk_response:
            raise HTTPException(status_code=400, detail="Failed to initiate mobile money payment. Please try again.")
        
        # Save transaction to database
        transaction = await save_mpesa_transaction(
            db=db,
            checkout_request_id=stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            phone_number=request.phone,
            amount=request.amount,
            reference=reference,
            merchant_request_id=stk_response.get("merchantRequestId") or stk_response.get("merchant_request_id")
        )
        
        # Link transaction to customer
        await link_transaction_to_customer(
            db=db,
            checkout_request_id=stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            customer_id=request.customer_id
        )
        
        logger.info(f"STK Push initiated for customer {request.customer_id}, checkout_request_id: {stk_response.get('checkoutRequestId')}")
        
        return {
            "message": "Mobile money payment initiated successfully. Please check your phone to complete payment.",
            "checkout_request_id": stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            "customer_id": request.customer_id,
            "status": "PENDING"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error initiating M-Pesa payment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate payment: {str(e)}")


@router.post("/api/hotspot/register-and-pay")
async def register_hotspot_and_pay_api(
    request: HotspotPaymentRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register guest hotspot user and initiate payment"""
    try:
        from app.services.mpesa import initiate_stk_push
        from app.services.reseller_payments import record_customer_payment
        from app.db.models import PaymentMethod
        
        # Validate payment method
        try:
            payment_method_enum = PaymentMethod(request.payment_method.lower())
        except ValueError:
            valid_methods = [method.value for method in PaymentMethod]
            raise HTTPException(
                status_code=400,
                detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}"
            )
        
        # Validate router exists and get user_id
        router_stmt = select(Router).where(Router.id == request.router_id)
        router_result = await db.execute(router_stmt)
        router = router_result.scalar_one_or_none()
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        user_id = router.user_id
        
        # Get the owner's shortcode for STK push
        owner_shortcode = None
        if user_id:
            owner_sc_result = await db.execute(select(User.mpesa_shortcode).where(User.id == user_id))
            owner_shortcode = owner_sc_result.scalar_one_or_none()
        
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        # Validate phone number
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")

        # Check if customer exists by MAC
        customer_stmt = select(Customer).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).where(Customer.mac_address == request.mac_address)
        customer_result = await db.execute(customer_stmt)
        existing_customer = customer_result.scalar_one_or_none()
        if existing_customer:
            # Store intended change in pending_update_data
            pending_data = {
                "requested_at": datetime.utcnow().isoformat(),
                "plan_id": request.plan_id,
                "plan_name": plan.name,
                "duration_value": plan.duration_value,
                "duration_unit": plan.duration_unit.value,
                "payment_method": payment_method_enum.value,
                "router_id": request.router_id,
                "phone": request.phone,
                "name": request.name,
                "requested_by_user_id": user_id
            }
            existing_customer.pending_update_data = json.dumps(pending_data)
            existing_customer.status = CustomerStatus.PENDING if payment_method_enum == PaymentMethod.MOBILE_MONEY else CustomerStatus.ACTIVE
            existing_customer.router_id = request.router_id  # Update router_id
            existing_customer.plan_id = request.plan_id      # Update plan_id
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
            reference = f"HOTSPOT-{customer.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            
            try:
                # Initiate STK push and get response
                stk_response = await initiate_stk_push(
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference,
                    shortcode=owner_shortcode
                )
                
                # Store transaction mapping for callback lookup
                from app.db.models import MpesaTransaction, MpesaTransactionStatus
                mpesa_txn = MpesaTransaction(
                    checkout_request_id=stk_response.checkout_request_id,
                    merchant_request_id=stk_response.merchant_request_id,
                    phone_number=request.phone,
                    amount=float(plan.price),
                    reference=reference,
                    customer_id=customer.id,
                    status=MpesaTransactionStatus.pending
                )
                db.add(mpesa_txn)
                await db.flush()
                
                # Now update status and commit
                customer.status = CustomerStatus.PENDING
                await db.commit()
                await db.refresh(customer)
                
                logger.info(f"STK Push initiated for customer {customer.id} ({request.mac_address})")
            except Exception as e:
                customer_id = getattr(customer, "id", None)
                await db.rollback()
                logger.exception("Payment initiation failed for customer %s", customer_id)
                
                # Record the STK push failure so we can track M-Pesa API issues
                try:
                    from app.db.models import FailureSource
                    failed_txn = MpesaTransaction(
                        checkout_request_id=f"FAILED-{reference}",
                        phone_number=request.phone,
                        amount=float(plan.price),
                        reference=reference,
                        customer_id=customer_id,
                        status=MpesaTransactionStatus.failed,
                        failure_source=FailureSource.MPESA_API,
                        result_code="STK_PUSH_FAILED",
                        result_desc=f"STK Push initiation failed: {str(e)[:450]}",
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    db.add(failed_txn)
                    await db.commit()
                except Exception as record_err:
                    logger.error(f"Failed to record STK push failure: {str(record_err)}")
                
                raise HTTPException(status_code=400, detail=f"Mobile money payment initiation failed: {str(e)}")
        else:
            # For cash payments, process immediately
            try:
                await record_customer_payment(
                    db, customer.id, user_id, float(plan.price),
                    payment_method_enum, plan.duration_value, request.payment_reference
                )
                customer.status = CustomerStatus.ACTIVE
                await db.commit()
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
            "message": "STK Push sent to phone" if payment_method_enum == PaymentMethod.MOBILE_MONEY else "Payment recorded successfully"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in hotspot registration and payment")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to register and initiate payment: {str(e)}")


@router.get("/api/hotspot/payment-status/{customerId}")
async def get_payment_status(
    customerId: int,
    db: AsyncSession = Depends(get_db)
):
    """Get payment status for a customer"""
    try:
        stmt = select(Customer).options(
            selectinload(Customer.plan)
        ).where(Customer.id == customerId)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        return {
            "customer_id": customer.id,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_id": customer.plan_id,
            "plan_name": customer.plan.name if customer.plan else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting payment status for customer {customerId}")
        raise HTTPException(status_code=500, detail=f"Failed to get payment status: {str(e)}")


@router.get("/api/mpesa/transactions")
async def get_mpesa_transactions(
    router_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get M-Pesa transactions with filters
    
    Query Parameters:
    - router_id: Filter by specific router (optional)
    - start_date: Start date (ISO format: 2025-10-20 or 2025-10-20T10:30:00)
    - end_date: End date (ISO format: 2025-10-21 or 2025-10-21T23:59:59)
    - status: Filter by status (pending, completed, failed, expired)
    """
    try:
        user = await get_current_user(token, db)
        # Build base query joining transactions with customers and routers
        stmt = select(MpesaTransaction, Customer, Router, Plan).join(
            Customer, MpesaTransaction.customer_id == Customer.id, isouter=True
        ).join(
            Router, Customer.router_id == Router.id, isouter=True
        ).join(
            Plan, Customer.plan_id == Plan.id, isouter=True
        ).where(
            (Customer.user_id == user.id) | (MpesaTransaction.customer_id == None)
        )
        
        # Apply router filter
        if router_id:
            stmt = stmt.where(Router.id == router_id)
        
        # Apply date range filter
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                stmt = stmt.where(MpesaTransaction.created_at >= start_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                # If only date provided, set to end of day
                if 'T' not in end_date:
                    end_dt = end_dt.replace(hour=23, minute=59, second=59)
                stmt = stmt.where(MpesaTransaction.created_at <= end_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
        
        # Apply status filter
        if status:
            try:
                status_enum = MpesaTransactionStatus(status.lower())
                stmt = stmt.where(MpesaTransaction.status == status_enum)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: pending, completed, failed, expired")
        
        # Order by most recent first
        stmt = stmt.order_by(MpesaTransaction.created_at.desc())
        
        result = await db.execute(stmt)
        transactions = result.all()
        
        return [
            {
                "transaction_id": tx.id,
                "checkout_request_id": tx.checkout_request_id,
                "phone_number": tx.phone_number,
                "amount": float(tx.amount),
                "reference": tx.reference,
                "lipay_tx_no": tx.lipay_tx_no,
                "status": tx.status.value,
                "mpesa_receipt_number": tx.mpesa_receipt_number,
                "result_code": tx.result_code,
                "result_desc": tx.result_desc,
                "failure_source": tx.failure_source.value if tx.failure_source else None,
                "transaction_date": tx.transaction_date.isoformat() if tx.transaction_date else None,
                "created_at": tx.created_at.isoformat(),
                "customer": {
                    "id": customer.id,
                    "name": customer.name,
                    "phone": customer.phone,
                    "mac_address": customer.mac_address,
                    "status": customer.status.value
                } if customer else None,
                "router": {
                    "id": router.id,
                    "name": router.name,
                    "ip_address": router.ip_address
                } if router else None,
                "plan": {
                    "id": plan.id,
                    "name": plan.name,
                    "price": plan.price,
                    "duration_value": plan.duration_value,
                    "duration_unit": plan.duration_unit.value
                } if plan else None
            }
            for tx, customer, router, plan in transactions
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching M-Pesa transactions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch transactions: {str(e)}")


@router.get("/api/mpesa/transactions/summary")
async def get_mpesa_transactions_summary(
    router_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get M-Pesa transactions summary with statistics
    
    Returns:
    - Total transactions
    - Total amount
    - Breakdown by status
    - Breakdown by router (if applicable)
    """
    try:
        user = await get_current_user(token, db)
        from sqlalchemy import func
        
        # Build base query
        stmt = select(MpesaTransaction, Customer, Router).join(
            Customer, MpesaTransaction.customer_id == Customer.id, isouter=True
        ).join(
            Router, Customer.router_id == Router.id, isouter=True
        ).where(
            (Customer.user_id == user.id) | (MpesaTransaction.customer_id == None)
        )
        
        # Apply filters
        if router_id:
            stmt = stmt.where(Router.id == router_id)
        
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            stmt = stmt.where(MpesaTransaction.created_at >= start_dt)
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if 'T' not in end_date:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
            stmt = stmt.where(MpesaTransaction.created_at <= end_dt)
        
        result = await db.execute(stmt)
        transactions = result.all()
        
        # Calculate statistics
        total_transactions = len(transactions)
        total_amount = sum(float(tx.amount) for tx, _, _ in transactions)
        
        # Breakdown by status
        status_breakdown = {}
        for tx, _, _ in transactions:
            status = tx.status.value
            if status not in status_breakdown:
                status_breakdown[status] = {"count": 0, "amount": 0}
            status_breakdown[status]["count"] += 1
            status_breakdown[status]["amount"] += float(tx.amount)
        
        # Breakdown by router
        router_breakdown = {}
        for tx, customer, router in transactions:
            if router:
                router_name = router.name
                if router_name not in router_breakdown:
                    router_breakdown[router_name] = {"count": 0, "amount": 0, "router_id": router.id}
                router_breakdown[router_name]["count"] += 1
                router_breakdown[router_name]["amount"] += float(tx.amount)
        
        return {
            "total_transactions": total_transactions,
            "total_amount": total_amount,
            "status_breakdown": status_breakdown,
            "router_breakdown": router_breakdown,
            "period": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching transaction summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch summary: {str(e)}")


@router.get("/api/mpesa/transactions/failed")
async def get_failed_mpesa_transactions(
    router_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get failed and expired M-Pesa transactions with failure reasons.
    
    Helps diagnose why payments are failing so you can take action.
    
    Query Parameters:
    - router_id: Filter by specific router (optional)
    - start_date: Start date (ISO format: 2025-10-20)
    - end_date: End date (ISO format: 2025-10-21)
    
    Returns:
    - List of failed/expired transactions with result_code, result_desc
    - Summary breakdown of failure reasons
    """
    try:
        user = await get_current_user(token, db)
        from sqlalchemy import func
        
        # Build query for failed + expired transactions
        stmt = select(MpesaTransaction, Customer, Router, Plan).join(
            Customer, MpesaTransaction.customer_id == Customer.id, isouter=True
        ).join(
            Router, Customer.router_id == Router.id, isouter=True
        ).join(
            Plan, Customer.plan_id == Plan.id, isouter=True
        ).where(
            (Customer.user_id == user.id) | (MpesaTransaction.customer_id == None)
        ).where(
            MpesaTransaction.status.in_([MpesaTransactionStatus.failed, MpesaTransactionStatus.expired])
        )
        
        # Apply filters
        if router_id:
            stmt = stmt.where(Router.id == router_id)
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                stmt = stmt.where(MpesaTransaction.created_at >= start_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format. Use ISO format (YYYY-MM-DD)")
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                if 'T' not in end_date:
                    end_dt = end_dt.replace(hour=23, minute=59, second=59)
                stmt = stmt.where(MpesaTransaction.created_at <= end_dt)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format. Use ISO format (YYYY-MM-DD)")
        
        stmt = stmt.order_by(MpesaTransaction.created_at.desc())
        
        result = await db.execute(stmt)
        transactions = result.all()
        
        # Build failure source breakdown (client vs server vs mpesa_api vs timeout)
        source_breakdown = {}
        for tx, _, _, _ in transactions:
            source = tx.failure_source.value if tx.failure_source else "unknown"
            if source not in source_breakdown:
                source_breakdown[source] = {"count": 0, "total_amount": 0}
            source_breakdown[source]["count"] += 1
            source_breakdown[source]["total_amount"] += float(tx.amount)
        
        # Build failure reason breakdown
        failure_reasons = {}
        for tx, _, _, _ in transactions:
            reason = tx.result_desc or "Unknown (no failure reason recorded)"
            if reason not in failure_reasons:
                failure_reasons[reason] = {
                    "count": 0, "result_code": tx.result_code, "total_amount": 0,
                    "failure_source": tx.failure_source.value if tx.failure_source else "unknown"
                }
            failure_reasons[reason]["count"] += 1
            failure_reasons[reason]["total_amount"] += float(tx.amount)
        
        # Sort reasons by count descending
        sorted_reasons = sorted(failure_reasons.items(), key=lambda x: x[1]["count"], reverse=True)
        failure_summary = [
            {
                "reason": reason,
                "result_code": data["result_code"],
                "failure_source": data["failure_source"],
                "count": data["count"],
                "total_amount_lost": data["total_amount"]
            }
            for reason, data in sorted_reasons
        ]
        
        # Build transaction list
        failed_transactions = [
            {
                "transaction_id": tx.id,
                "checkout_request_id": tx.checkout_request_id,
                "phone_number": tx.phone_number,
                "amount": float(tx.amount),
                "reference": tx.reference,
                "status": tx.status.value,
                "failure_source": tx.failure_source.value if tx.failure_source else None,
                "result_code": tx.result_code,
                "result_desc": tx.result_desc,
                "created_at": tx.created_at.isoformat(),
                "updated_at": tx.updated_at.isoformat() if tx.updated_at else None,
                "customer": {
                    "id": customer.id,
                    "name": customer.name,
                    "phone": customer.phone,
                    "mac_address": customer.mac_address,
                    "status": customer.status.value
                } if customer else None,
                "router": {
                    "id": router.id,
                    "name": router.name,
                    "ip_address": router.ip_address
                } if router else None,
                "plan": {
                    "id": plan.id,
                    "name": plan.name,
                    "price": plan.price,
                } if plan else None
            }
            for tx, customer, router, plan in transactions
        ]
        
        return {
            "total_failed": len(transactions),
            "total_amount_lost": sum(float(tx.amount) for tx, _, _, _ in transactions),
            "source_breakdown": source_breakdown,
            "failure_summary": failure_summary,
            "transactions": failed_transactions
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching failed transactions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch failed transactions: {str(e)}")

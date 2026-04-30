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
    CustomerStatus, CustomerPayment, ConnectionType, User, PaymentMethod,
    ProvisioningAttemptEntrypoint, ProvisioningAttemptSource,
)
from app.services.auth import verify_token, get_current_user
from app.services.subscription import enforce_active_subscription
from app.services.hotspot_provisioning import (
    build_hotspot_payload,
    get_or_create_provisioning_attempt,
    get_recent_delivery_attempt_for_customer,
    load_delivery_attempts_by_source,
    log_provisioning_event,
    provision_hotspot_customer,
    schedule_provisioning_attempt,
    serialize_delivery_attempt,
)
from app.services.mpesa_transactions import update_mpesa_transaction_status
from app.services.billing import make_payment
from app.services.pppoe_provisioning import call_pppoe_provision, build_pppoe_payload
import logging
import json

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


def _router_auth_value(router: Optional[Router]) -> Optional[str]:
    auth_method = getattr(router, "auth_method", None)
    if auth_method is None:
        return None
    return auth_method.value if hasattr(auth_method, "value") else str(auth_method)


def _manual_provision_support(
    payment_method: str,
    status: str,
    customer: Optional[Customer],
    router_obj: Optional[Router],
    plan: Optional[Plan],
) -> tuple[bool, Optional[str]]:
    if payment_method == PaymentMethod.MOBILE_MONEY.value:
        if status not in (
            MpesaTransactionStatus.completed.value,
            MpesaTransactionStatus.pending.value,
        ):
            return False, "Only completed or pending mobile money transactions can be manually provisioned"
    elif status != "completed":
        return False, "Only completed transactions can be manually provisioned"

    if not customer:
        return False, "Transaction has no linked customer"
    if not router_obj:
        return False, "Customer has no router assigned"
    if not plan:
        return False, "Customer has no plan assigned"
    if _router_auth_value(router_obj) == "RADIUS":
        return False, "Manual provisioning is disabled for RADIUS routers"
    if plan.connection_type != ConnectionType.HOTSPOT:
        return False, "Only direct hotspot transactions are supported"
    if not customer.mac_address:
        return False, "Customer has no MAC address"

    return True, None


def _calculate_days_paid_for(duration_value: int, duration_unit: str) -> int:
    if duration_unit == "MINUTES":
        return max(1, duration_value // (24 * 60))
    if duration_unit == "HOURS":
        return max(1, duration_value // 24)
    return duration_value


async def _resolve_customer_payment_plan(
    db: AsyncSession,
    customer: Customer,
) -> tuple[Optional[Plan], int, str]:
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
        pending_plan_stmt = select(Plan).where(Plan.id == pending_data["plan_id"])
        pending_plan_result = await db.execute(pending_plan_stmt)
        plan = pending_plan_result.scalar_one_or_none() or customer.plan
        if plan:
            customer.plan_id = plan.id
            customer.plan = plan
    else:
        plan = customer.plan

    duration_value = plan.duration_value if plan else 1
    duration_unit = plan.duration_unit.value.upper() if plan else "DAYS"
    customer.pending_update_data = None
    await db.flush()
    return plan, duration_value, duration_unit


async def _finalize_pending_mobile_money_transaction(
    db: AsyncSession,
    tx: MpesaTransaction,
    customer: Customer,
    actor_user_id: int,
) -> tuple[Plan, CustomerPayment]:
    from app.services.reseller_payments import record_customer_payment

    plan, duration_value, duration_unit = await _resolve_customer_payment_plan(db, customer)
    if not plan:
        raise HTTPException(status_code=400, detail="Customer has no plan assigned")

    days_paid_for = _calculate_days_paid_for(duration_value, duration_unit)
    reference = tx.mpesa_receipt_number or tx.checkout_request_id

    tx.status = MpesaTransactionStatus.completed
    tx.failure_source = None
    tx.result_code = tx.result_code or "MANUAL_COMPLETED"
    tx.result_desc = (
        tx.result_desc
        or f"Manually marked completed and provisioned by user {actor_user_id}"
    )
    tx.updated_at = datetime.utcnow()

    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=customer.user_id,
        amount=float(tx.amount),
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=days_paid_for,
        payment_reference=reference,
        notes=f"Manual completion from pending M-Pesa TX: {tx.checkout_request_id}",
        duration_value=duration_value,
        duration_unit=duration_unit,
    )
    await db.refresh(customer)
    return plan, payment


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/mpesa/callback")
async def mpesa_direct_callback(payload: dict, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Handle standard M-Pesa STK Push callback"""
    logger.info(f"--- M-Pesa Direct Callback Received: {json.dumps(payload, indent=2)}")
    
    from app.db.models import MpesaTransaction, MpesaTransactionStatus, FailureSource
    checkout_request_id = None
    
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
        stmt = select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_request_id)
        result = await db.execute(stmt)
        mpesa_txn = result.scalar_one_or_none()
        
        if not mpesa_txn:
            # --- Orphan payment recovery ---
            # If Safaricom processed the STK push but we never recorded the transaction
            # (e.g. httpx timeout reading their response), try to match by phone number.
            cb_metadata = stk_callback.get("CallbackMetadata", {})
            cb_items = cb_metadata.get("Item", [])
            cb_phone = cb_amount = cb_receipt = None
            for item in cb_items:
                name = item.get("Name")
                if name == "PhoneNumber":
                    cb_phone = str(item.get("Value"))
                elif name == "Amount":
                    cb_amount = item.get("Value")
                elif name == "MpesaReceiptNumber":
                    cb_receipt = item.get("Value")

            if result_code == 0 and cb_phone and cb_amount:
                logger.warning(
                    f"[RECOVERY] Transaction not found for {checkout_request_id} "
                    f"but payment SUCCEEDED (phone={cb_phone}, amount={cb_amount}, receipt={cb_receipt}). "
                    f"Attempting recovery..."
                )
                phone_variants = [cb_phone]
                if cb_phone.startswith("254"):
                    phone_variants.append("0" + cb_phone[3:])
                    phone_variants.append("+" + cb_phone)
                elif cb_phone.startswith("+254"):
                    phone_variants.append("0" + cb_phone[4:])
                    phone_variants.append(cb_phone[1:])
                elif cb_phone.startswith("0"):
                    phone_variants.append("254" + cb_phone[1:])
                    phone_variants.append("+254" + cb_phone[1:])

                customer_stmt = (
                    select(Customer)
                    .options(selectinload(Customer.plan), selectinload(Customer.router))
                    .where(
                        Customer.phone.in_(phone_variants),
                        Customer.status.in_([CustomerStatus.PENDING, CustomerStatus.INACTIVE]),
                    )
                    .order_by(Customer.created_at.desc())
                    .limit(1)
                )
                cust_result = await db.execute(customer_stmt)
                orphan_customer = cust_result.scalar_one_or_none()

                if orphan_customer:
                    logger.info(
                        f"[RECOVERY] Matched orphan payment to customer {orphan_customer.id} "
                        f"({orphan_customer.name}, phone={cb_phone})"
                    )
                    mpesa_txn = MpesaTransaction(
                        checkout_request_id=checkout_request_id,
                        merchant_request_id=merchant_request_id,
                        phone_number=cb_phone,
                        amount=float(cb_amount),
                        reference=f"RECOVERED-{checkout_request_id}",
                        customer_id=orphan_customer.id,
                        status=MpesaTransactionStatus.pending,
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow(),
                    )
                    db.add(mpesa_txn)
                    await db.flush()
                else:
                    logger.error(
                        f"[RECOVERY] No matching customer for orphan payment "
                        f"(phone={cb_phone}, amount={cb_amount}, receipt={cb_receipt}). "
                        f"Manual reconciliation required."
                    )
                    return {"ResultCode": 0, "ResultDesc": "Payment received - manual reconciliation needed"}
            else:
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
            
            # Provision based on connection type
            if customer.plan and customer.plan.connection_type == ConnectionType.PPPOE:
                if customer.pppoe_username and customer.router:
                    pppoe_payload = build_pppoe_payload(customer, customer.router)
                    logger.info(f"Prepared PPPoE Payload for customer {customer.id} -> Router: {customer.router.ip_address}")
                    background_tasks.add_task(call_pppoe_provision, pppoe_payload)
                else:
                    logger.error(
                        "[CALLBACK] Skipping PPPoE provisioning for customer %s - "
                        "missing pppoe_username or router (router_id=%s, username=%s)",
                        customer.id,
                        customer.router_id,
                        customer.pppoe_username,
                    )
            elif customer.mac_address and customer.router:
                router_obj = customer.router
                hotspot_payload = build_hotspot_payload(
                    customer,
                    plan,
                    router_obj,
                    comment=f"Payment successful for {customer.name}",
                )
                attempt = await get_or_create_provisioning_attempt(
                    db,
                    customer_id=customer.id,
                    router_id=router_obj.id,
                    mac_address=customer.mac_address,
                    source_table=ProvisioningAttemptSource.MPESA_TRANSACTION,
                    source_pk=mpesa_txn.id,
                    external_reference=checkout_request_id,
                    entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
                )
                await schedule_provisioning_attempt(db, attempt)
                await db.commit()
                logger.info(f"Prepared MikroTik Payload for customer {customer.id} -> Router: {router_obj.ip_address}")
                await log_provisioning_event(
                    customer_id=customer.id,
                    router_id=router_obj.id,
                    mac_address=customer.mac_address,
                    action="hotspot_payment",
                    status="scheduled",
                    details=f"Queued after M-Pesa callback for router {router_obj.ip_address}",
                    attempt_id=attempt.id,
                )
                background_tasks.add_task(
                    provision_hotspot_customer,
                    customer.id,
                    router_obj.id,
                    hotspot_payload,
                    "hotspot_payment",
                    attempt.id,
                )
            else:
                logger.error(
                    "[CALLBACK] Skipping hotspot provisioning for customer %s - "
                    "missing mac_address or router (router_id=%s, mac_address=%s)",
                    customer.id,
                    customer.router_id,
                    customer.mac_address,
                )
            
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
    """Initiate payment for existing customer. Routes through the correct gateway
    based on the customer's router payment method configuration."""
    current_user = await get_current_user(token, db)
    enforce_active_subscription(current_user)
    try:
        from app.services.mpesa import initiate_stk_push
        from app.services.mpesa_transactions import save_mpesa_transaction, link_transaction_to_customer
        from app.services.payment_gateway import resolve_router_payment_method, initiate_customer_payment
        
        if request.amount <= 0:
            raise HTTPException(status_code=400, detail="Payment amount must be greater than 0")
        
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")
        
        stmt = select(Customer).options(
            selectinload(Customer.plan), selectinload(Customer.router)
        ).where(Customer.id == request.customer_id)
        result = await db.execute(stmt)
        customer = result.scalar_one_or_none()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        reference = f"PAYMENT-{request.customer_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Look up the reseller's display name for the STK push prompt
        account_reference = None
        if customer.user_id:
            owner_name_result = await db.execute(
                select(User.business_name, User.organization_name).where(User.id == customer.user_id)
            )
            owner_row = owner_name_result.one_or_none()
            if owner_row:
                account_reference = owner_row.business_name or owner_row.organization_name

        # Check if the customer's router has a configured payment method
        payment_method = None
        if customer.router_id:
            payment_method = await resolve_router_payment_method(db, customer.router_id)

        if payment_method:
            # --- New path: use configured payment method ---
            try:
                gw_result = await initiate_customer_payment(
                    db=db,
                    payment_method=payment_method,
                    customer=customer,
                    router=customer.router,
                    phone=request.phone,
                    amount=request.amount,
                    reference=reference,
                    plan_name=customer.plan.name if customer.plan else "",
                    account_reference=account_reference,
                )
            except Exception as gw_error:
                logger.error(f"Payment gateway failed for customer {request.customer_id}: {gw_error}")
                raise HTTPException(status_code=500, detail=f"Failed to initiate payment: {str(gw_error)}")

            customer.status = CustomerStatus.PENDING
            await db.commit()

            resp = {
                "message": "Payment initiated successfully. Please check your phone to complete payment.",
                "customer_id": request.customer_id,
                "status": "PENDING",
                "gateway": gw_result.get("gateway"),
            }
            if gw_result.get("checkout_request_id"):
                resp["checkout_request_id"] = gw_result["checkout_request_id"]
            if gw_result.get("order_id"):
                resp["order_id"] = gw_result["order_id"]
            if gw_result.get("reference_id"):
                resp["reference_id"] = gw_result["reference_id"]
            return resp

        # --- Legacy path: use system M-Pesa credentials ---
        owner_shortcode = None
        if customer.user_id:
            owner_result = await db.execute(select(User.mpesa_shortcode).where(User.id == customer.user_id))
            owner_shortcode = owner_result.scalar_one_or_none()
        
        try:
            stk_response = await initiate_stk_push(
                phone_number=request.phone,
                amount=request.amount,
                reference=reference,
                user_id=customer.user_id,
                mac_address=customer.mac_address,
                shortcode=owner_shortcode,
                account_reference=account_reference,
            )
        except Exception as stk_error:
            from app.db.models import FailureSource
            await db.rollback()
            try:
                from app.db.database import AsyncSessionLocal
                async with AsyncSessionLocal() as fresh_db:
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
                    fresh_db.add(failed_txn)
                    await fresh_db.commit()
            except Exception as record_err:
                logger.error(f"Failed to record STK push failure: {str(record_err)}")
            logger.error(f"STK Push failed for customer {request.customer_id}: {str(stk_error)}")
            raise HTTPException(status_code=500, detail=f"Failed to initiate payment: {str(stk_error)}")
        
        if not stk_response:
            raise HTTPException(status_code=400, detail="Failed to initiate mobile money payment. Please try again.")
        
        transaction = await save_mpesa_transaction(
            db=db,
            checkout_request_id=stk_response.get("checkoutRequestId") or stk_response.get("checkout_request_id"),
            phone_number=request.phone,
            amount=request.amount,
            reference=reference,
            merchant_request_id=stk_response.get("merchantRequestId") or stk_response.get("merchant_request_id")
        )
        
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
    from app.db.models import MpesaTransaction, MpesaTransactionStatus, FailureSource
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

        # Block payments if the reseller's subscription is suspended
        if user_id:
            from app.db.models import SubscriptionStatus
            owner_sub_result = await db.execute(
                select(User.subscription_status).where(User.id == user_id)
            )
            owner_sub_row = owner_sub_result.one_or_none()
            if owner_sub_row:
                sub_val = owner_sub_row[0]
                if hasattr(sub_val, 'value'):
                    sub_val = sub_val.value
                if sub_val not in ("active", "trial"):
                    raise HTTPException(
                        status_code=503,
                        detail="This service is temporarily unavailable. Please contact your ISP."
                    )
        
        # Get the owner's shortcode and display name for STK push
        owner_shortcode = None
        account_reference = None
        if user_id:
            owner_info_result = await db.execute(
                select(User.mpesa_shortcode, User.business_name, User.organization_name)
                .where(User.id == user_id)
            )
            owner_info = owner_info_result.one_or_none()
            if owner_info:
                owner_shortcode = owner_info.mpesa_shortcode
                account_reference = owner_info.business_name or owner_info.organization_name
        
        # Validate plan exists
        plan_stmt = select(Plan).where(Plan.id == request.plan_id)
        plan_result = await db.execute(plan_stmt)
        plan = plan_result.scalar_one_or_none()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        if plan.user_id != user_id:
            raise HTTPException(status_code=400, detail="Selected plan does not belong to this router")
        if plan.connection_type != ConnectionType.HOTSPOT:
            logger.warning(
                "[HOTSPOT PAY] Rejected non-hotspot plan %s (%s) for router %s",
                plan.id,
                plan.connection_type.value if plan.connection_type else None,
                request.router_id,
            )
            raise HTTPException(status_code=400, detail="Selected plan is not a hotspot plan")
        # Validate phone number
        if not request.phone or len(request.phone.strip()) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number format")

        # Check if customer exists by MAC under this reseller
        customer_stmt = select(Customer).options(
            selectinload(Customer.plan),
            selectinload(Customer.router)
        ).where(
            Customer.mac_address == request.mac_address,
            Customer.user_id == user_id,
        )
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

            # Check if router has a configured payment method
            from app.services.payment_gateway import resolve_router_payment_method, initiate_customer_payment
            router_pm = await resolve_router_payment_method(db, request.router_id)

            if router_pm:
                # --- New path: use configured payment method ---
                try:
                    gw_result = await initiate_customer_payment(
                        db=db,
                        payment_method=router_pm,
                        customer=customer,
                        router=router,
                        phone=request.phone,
                        amount=float(plan.price),
                        reference=reference,
                        plan_name=plan.name,
                        account_reference=account_reference,
                    )
                    customer.status = CustomerStatus.PENDING
                    await db.commit()
                    await db.refresh(customer)
                    logger.info(
                        "Payment initiated via %s for customer %s (%s)",
                        gw_result.get("gateway"), customer.id, request.mac_address,
                    )
                except Exception as e:
                    customer_id = getattr(customer, "id", None)
                    await db.rollback()
                    logger.exception("Payment gateway failed for customer %s", customer_id)
                    raise HTTPException(
                        status_code=400,
                        detail=f"Payment initiation failed: {str(e)}",
                    )
            else:
                # --- Legacy path: use system M-Pesa credentials ---
                try:
                    stk_response = await initiate_stk_push(
                        phone_number=request.phone,
                        amount=float(plan.price),
                        reference=reference,
                        shortcode=owner_shortcode,
                        account_reference=account_reference,
                    )
                    
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
                    
                    customer.status = CustomerStatus.PENDING
                    await db.commit()
                    await db.refresh(customer)
                    
                    logger.info(f"STK Push initiated for customer {customer.id} ({request.mac_address})")
                except Exception as e:
                    customer_id = getattr(customer, "id", None)
                    await db.rollback()
                    logger.exception("Payment initiation failed for customer %s", customer_id)
                    
                    try:
                        from app.db.database import AsyncSessionLocal
                        async with AsyncSessionLocal() as fresh_db:
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
                            fresh_db.add(failed_txn)
                            await fresh_db.commit()
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

        attempt = await get_recent_delivery_attempt_for_customer(db, customer.id)
        
        return {
            "customer_id": customer.id,
            "status": customer.status.value,
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "plan_id": customer.plan_id,
            "plan_name": customer.plan.name if customer.plan else None,
            "delivery": serialize_delivery_attempt(attempt),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting payment status for customer {customerId}")
        raise HTTPException(status_code=500, detail=f"Failed to get payment status: {str(e)}")


@router.get("/api/mpesa/transactions")
async def get_mpesa_transactions(
    router_id: Optional[int] = None,
    payment_method: Optional[str] = None,
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get all transactions (M-Pesa, voucher, cash, etc.) with filters.

    Merges two sources:
    - mpesa_transactions (includes pending/failed M-Pesa)
    - customer_payments where payment_method != mobile_money (voucher, cash, etc.)

    Query Parameters:
    - router_id: Filter by specific router (optional)
    - payment_method: Filter by type -- mobile_money, voucher, cash, card, etc. (optional)
    - date: Exact date filter (YYYY-MM-DD) -- returns transactions for that day only (optional)
    - start_date: Range start (ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS) (optional)
    - end_date: Range end (ISO format) (optional)
    - status: Filter by status -- completed, pending, failed, expired (optional)
    - limit: Max results per page (default 200)
    - offset: Skip first N results for pagination (default 0)
    """
    try:
        user = await get_current_user(token, db)

        # Parse date filters once
        date_start = None
        date_end = None
        if date:
            try:
                date_start = datetime.strptime(date, "%Y-%m-%d")
                date_end = date_start.replace(hour=23, minute=59, second=59)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
        else:
            if start_date:
                try:
                    date_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid start_date format")
            if end_date:
                try:
                    date_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    if "T" not in end_date:
                        date_end = date_end.replace(hour=23, minute=59, second=59)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid end_date format")

        results = []
        mpesa_source_ids = []
        customer_payment_source_ids = []
        want_mpesa = payment_method in (None, "mobile_money")
        want_other = payment_method != "mobile_money"

        # --- Query 1: M-Pesa transactions (preserves pending/failed/expired) ---
        if want_mpesa:
            mpesa_stmt = (
                select(MpesaTransaction, Customer, Router, Plan)
                .join(Customer, MpesaTransaction.customer_id == Customer.id, isouter=True)
                .join(Router, Customer.router_id == Router.id, isouter=True)
                .join(Plan, Customer.plan_id == Plan.id, isouter=True)
                .where(
                    (Customer.user_id == user.id) | (MpesaTransaction.customer_id == None)
                )
            )
            if router_id:
                mpesa_stmt = mpesa_stmt.where(Router.id == router_id)
            if date_start:
                mpesa_stmt = mpesa_stmt.where(MpesaTransaction.created_at >= date_start)
            if date_end:
                mpesa_stmt = mpesa_stmt.where(MpesaTransaction.created_at <= date_end)
            if status:
                try:
                    mpesa_status = MpesaTransactionStatus(status.lower())
                    mpesa_stmt = mpesa_stmt.where(MpesaTransaction.status == mpesa_status)
                except ValueError:
                    pass

            mpesa_rows = (await db.execute(mpesa_stmt)).all()

            for tx, customer, rtr, plan in mpesa_rows:
                manual_supported, manual_reason = _manual_provision_support(
                    PaymentMethod.MOBILE_MONEY.value,
                    tx.status.value,
                    customer,
                    rtr,
                    plan,
                )
                results.append({
                    "transaction_id": tx.id,
                    "checkout_request_id": tx.checkout_request_id,
                    "phone_number": tx.phone_number,
                    "amount": float(tx.amount),
                    "reference": tx.reference,
                    "lipay_tx_no": tx.lipay_tx_no,
                    "status": tx.status.value,
                    "payment_method": "mobile_money",
                    "payment_reference": tx.mpesa_receipt_number,
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
                        "status": customer.status.value,
                    } if customer else None,
                    "router": {
                        "id": rtr.id,
                        "name": rtr.name,
                        "ip_address": rtr.ip_address,
                        "auth_method": _router_auth_value(rtr),
                    } if rtr else None,
                    "plan": {
                        "id": plan.id,
                        "name": plan.name,
                        "price": plan.price,
                        "duration_value": plan.duration_value,
                        "duration_unit": plan.duration_unit.value,
                        "connection_type": plan.connection_type.value if plan.connection_type else None,
                    } if plan else None,
                    "manual_provision_supported": manual_supported,
                    "manual_provision_reason": manual_reason,
                    "_delivery_source_table": ProvisioningAttemptSource.MPESA_TRANSACTION.value,
                    "_delivery_source_pk": tx.id,
                })
                mpesa_source_ids.append(tx.id)

        # --- Query 2: Non-M-Pesa payments (voucher, cash, etc.) ---
        # Outer-join Customer so that payments whose customer was later deleted
        # (customer_id SET NULL) are still included in the ledger.
        if want_other:
            cp_stmt = (
                select(CustomerPayment, Customer, Router, Plan)
                .outerjoin(Customer, CustomerPayment.customer_id == Customer.id)
                .outerjoin(Router, Customer.router_id == Router.id)
                .outerjoin(Plan, Customer.plan_id == Plan.id)
                .where(
                    CustomerPayment.reseller_id == user.id,
                    CustomerPayment.payment_method != PaymentMethod.MOBILE_MONEY,
                )
            )
            if payment_method and payment_method != "mobile_money":
                try:
                    pm_enum = PaymentMethod(payment_method.lower())
                    cp_stmt = cp_stmt.where(CustomerPayment.payment_method == pm_enum)
                except ValueError:
                    valid = [m.value for m in PaymentMethod]
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid payment_method. Must be one of: {', '.join(valid)}",
                    )
            if router_id:
                cp_stmt = cp_stmt.where(Customer.router_id == router_id)
            if date_start:
                cp_stmt = cp_stmt.where(CustomerPayment.created_at >= date_start)
            if date_end:
                cp_stmt = cp_stmt.where(CustomerPayment.created_at <= date_end)
            if status:
                if status.lower() in ("failed", "expired"):
                    pass
                else:
                    from app.db.models import PaymentStatus
                    try:
                        cp_status = PaymentStatus(status.lower())
                        cp_stmt = cp_stmt.where(CustomerPayment.status == cp_status)
                    except ValueError:
                        pass

            cp_rows = (await db.execute(cp_stmt)).all()

            for pay, customer, rtr, plan in cp_rows:
                payment_status = "completed" if pay.status and pay.status.value == "completed" else (pay.status.value if pay.status else "completed")
                manual_supported, manual_reason = _manual_provision_support(
                    pay.payment_method.value,
                    payment_status,
                    customer,
                    rtr,
                    plan,
                )
                # When the customer was deleted, customer is None but
                # pay.customer_name holds the name snapshot from deletion time.
                display_name = (customer.name if customer else None) or pay.customer_name or "Deleted customer"
                results.append({
                    "transaction_id": pay.id,
                    "checkout_request_id": None,
                    "phone_number": customer.phone if customer else None,
                    "amount": float(pay.amount),
                    "reference": pay.payment_reference,
                    "lipay_tx_no": pay.lipay_tx_no,
                    "status": payment_status,
                    "payment_method": pay.payment_method.value,
                    "payment_reference": pay.payment_reference,
                    "mpesa_receipt_number": None,
                    "result_code": None,
                    "result_desc": None,
                    "failure_source": None,
                    "transaction_date": pay.payment_date.isoformat() if pay.payment_date else None,
                    "created_at": pay.created_at.isoformat() if pay.created_at else None,
                    "customer": {
                        "id": customer.id,
                        "name": customer.name,
                        "phone": customer.phone,
                        "mac_address": customer.mac_address,
                        "status": customer.status.value,
                    } if customer else {
                        "id": None,
                        "name": display_name,
                        "phone": None,
                        "mac_address": None,
                        "status": "deleted",
                    },
                    "router": {
                        "id": rtr.id,
                        "name": rtr.name,
                        "ip_address": rtr.ip_address,
                        "auth_method": _router_auth_value(rtr),
                    } if rtr else None,
                    "plan": {
                        "id": plan.id,
                        "name": plan.name,
                        "price": plan.price,
                        "duration_value": plan.duration_value,
                        "duration_unit": plan.duration_unit.value,
                        "connection_type": plan.connection_type.value if plan.connection_type else None,
                    } if plan else None,
                    "manual_provision_supported": manual_supported,
                    "manual_provision_reason": manual_reason,
                    "_delivery_source_table": ProvisioningAttemptSource.CUSTOMER_PAYMENT.value,
                    "_delivery_source_pk": pay.id,
                })
                customer_payment_source_ids.append(pay.id)

        attempt_map = await load_delivery_attempts_by_source(
            db,
            mpesa_ids=mpesa_source_ids,
            customer_payment_ids=customer_payment_source_ids,
        )

        for row in results:
            source_key = (row.get("_delivery_source_table"), row.get("_delivery_source_pk"))
            row["delivery"] = serialize_delivery_attempt(attempt_map.get(source_key))
            row.pop("_delivery_source_table", None)
            row.pop("_delivery_source_pk", None)

        # Merge and sort by date descending, then paginate
        results.sort(key=lambda r: r["created_at"] or "", reverse=True)
        paginated = results[offset: offset + min(limit, 500)]

        return paginated

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch transactions: {str(e)}")


@router.post("/api/transactions/{payment_method}/{transaction_id}/manual-provision")
async def manual_provision_transaction(
    payment_method: str,
    transaction_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """
    Manually re-run direct hotspot provisioning for a specific transaction.

    Intended for use from the transactions table when payment succeeded but
    router provisioning needs to be replayed.
    """
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        method = payment_method.lower()

        customer = None
        router_obj = None
        plan = None
        reference = None
        tx_status = None
        source_table = None
        source_pk = None

        if method == PaymentMethod.MOBILE_MONEY.value:
            stmt = (
                select(MpesaTransaction, Customer, Router, Plan)
                .join(Customer, MpesaTransaction.customer_id == Customer.id)
                .join(Router, Customer.router_id == Router.id, isouter=True)
                .join(Plan, Customer.plan_id == Plan.id, isouter=True)
                .where(
                    MpesaTransaction.id == transaction_id,
                    Customer.user_id == user.id,
                )
            )
            row = (await db.execute(stmt)).one_or_none()
            if not row:
                raise HTTPException(status_code=404, detail="Transaction not found")

            tx, customer, router_obj, plan = row
            tx_status = tx.status.value
            reference = tx.mpesa_receipt_number or tx.reference or tx.checkout_request_id
            source_table = ProvisioningAttemptSource.MPESA_TRANSACTION
            source_pk = tx.id
        else:
            try:
                pm_enum = PaymentMethod(method)
            except ValueError:
                valid_methods = [m.value for m in PaymentMethod]
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid payment method. Must be one of: {', '.join(valid_methods)}",
                )

            stmt = (
                select(CustomerPayment, Customer, Router, Plan)
                .join(Customer, CustomerPayment.customer_id == Customer.id)
                .outerjoin(Router, Customer.router_id == Router.id)
                .outerjoin(Plan, Customer.plan_id == Plan.id)
                .where(
                    CustomerPayment.id == transaction_id,
                    CustomerPayment.reseller_id == user.id,
                    CustomerPayment.payment_method == pm_enum,
                )
            )
            row = (await db.execute(stmt)).one_or_none()
            if not row:
                raise HTTPException(status_code=404, detail="Transaction not found")

            pay, customer, router_obj, plan = row
            tx_status = pay.status.value if pay.status else "completed"
            reference = pay.payment_reference or f"{pm_enum.value}-{pay.id}"
            source_table = ProvisioningAttemptSource.CUSTOMER_PAYMENT
            source_pk = pay.id

        supported, reason = _manual_provision_support(method, tx_status, customer, router_obj, plan)
        if not supported:
            raise HTTPException(status_code=400, detail=reason or "Manual provisioning is not supported for this transaction")

        payment_record = None
        if method == PaymentMethod.MOBILE_MONEY.value and tx_status == MpesaTransactionStatus.pending.value:
            plan, payment_record = await _finalize_pending_mobile_money_transaction(
                db,
                tx,
                customer,
                user.id,
            )
            tx_status = MpesaTransactionStatus.completed.value
            reference = tx.mpesa_receipt_number or tx.checkout_request_id

        hotspot_payload = build_hotspot_payload(
            customer,
            plan,
            router_obj,
            comment=f"Manual provisioning for transaction {transaction_id}",
        )
        attempt = await get_or_create_provisioning_attempt(
            db,
            customer_id=customer.id,
            router_id=router_obj.id,
            mac_address=customer.mac_address,
            source_table=source_table,
            source_pk=source_pk,
            external_reference=reference,
            entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        )
        await schedule_provisioning_attempt(db, attempt)
        await db.commit()
        await log_provisioning_event(
            customer_id=customer.id,
            router_id=router_obj.id,
            mac_address=customer.mac_address,
            action="manual_transaction_provision",
            status="scheduled",
            details=f"Manual provisioning requested by user {user.id} for transaction {transaction_id}",
            attempt_id=attempt.id,
        )
        result = await provision_hotspot_customer(
            customer.id,
            router_obj.id,
            hotspot_payload,
            "manual_transaction_provision",
            attempt.id,
        )

        return {
            "success": result.get("success", False),
            "payment_method": method,
            "transaction_id": transaction_id,
            "reference": reference,
            "transaction_status": tx_status,
            "customer_id": customer.id,
            "router_id": router_obj.id,
            "router_name": router_obj.name,
            "payment_id": payment_record.id if payment_record else None,
            "attempt_id": attempt.id,
            "delivery": result.get("delivery"),
            "provisioning_error": result.get("provisioning_error"),
            "provisioning_result": result,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error manually provisioning transaction {transaction_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to manually provision transaction: {str(e)}")


@router.get("/api/mpesa/transactions/summary")
async def get_mpesa_transactions_summary(
    router_id: Optional[int] = None,
    payment_method: Optional[str] = None,
    date: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    """
    Get transactions summary with statistics.

    Uses the same two-query merge as the main transactions endpoint so
    numbers stay consistent.

    Query Parameters:
    - router_id, payment_method, date, start_date, end_date (same as /transactions)

    Returns:
    - total_transactions, total_amount
    - status_breakdown (completed / pending / failed / expired)
    - method_breakdown (mobile_money / voucher / cash / ...)
    - router_breakdown
    """
    try:
        user = await get_current_user(token, db)

        date_start = None
        date_end = None
        if date:
            try:
                date_start = datetime.strptime(date, "%Y-%m-%d")
                date_end = date_start.replace(hour=23, minute=59, second=59)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
        else:
            if start_date:
                date_start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            if end_date:
                date_end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                if "T" not in end_date:
                    date_end = date_end.replace(hour=23, minute=59, second=59)

        rows = []
        want_mpesa = payment_method in (None, "mobile_money")
        want_other = payment_method != "mobile_money"

        if want_mpesa:
            mpesa_stmt = (
                select(MpesaTransaction, Customer, Router)
                .join(Customer, MpesaTransaction.customer_id == Customer.id, isouter=True)
                .join(Router, Customer.router_id == Router.id, isouter=True)
                .where(
                    (Customer.user_id == user.id) | (MpesaTransaction.customer_id == None)
                )
            )
            if router_id:
                mpesa_stmt = mpesa_stmt.where(Router.id == router_id)
            if date_start:
                mpesa_stmt = mpesa_stmt.where(MpesaTransaction.created_at >= date_start)
            if date_end:
                mpesa_stmt = mpesa_stmt.where(MpesaTransaction.created_at <= date_end)

            for tx, customer, rtr in (await db.execute(mpesa_stmt)).all():
                rows.append({
                    "amount": float(tx.amount),
                    "status": tx.status.value,
                    "method": "mobile_money",
                    "router_name": rtr.name if rtr else None,
                    "router_id": rtr.id if rtr else None,
                })

        if want_other:
            cp_stmt = (
                select(CustomerPayment, Customer, Router)
                .outerjoin(Customer, CustomerPayment.customer_id == Customer.id)
                .outerjoin(Router, Customer.router_id == Router.id)
                .where(
                    CustomerPayment.reseller_id == user.id,
                    CustomerPayment.payment_method != PaymentMethod.MOBILE_MONEY,
                )
            )
            if payment_method and payment_method != "mobile_money":
                try:
                    pm_enum = PaymentMethod(payment_method.lower())
                    cp_stmt = cp_stmt.where(CustomerPayment.payment_method == pm_enum)
                except ValueError:
                    pass
            if router_id:
                cp_stmt = cp_stmt.where(Customer.router_id == router_id)
            if date_start:
                cp_stmt = cp_stmt.where(CustomerPayment.created_at >= date_start)
            if date_end:
                cp_stmt = cp_stmt.where(CustomerPayment.created_at <= date_end)

            for pay, customer, rtr in (await db.execute(cp_stmt)).all():
                rows.append({
                    "amount": float(pay.amount),
                    "status": pay.status.value if pay.status else "completed",
                    "method": pay.payment_method.value,
                    "router_name": rtr.name if rtr else None,
                    "router_id": rtr.id if rtr else None,
                })

        total_transactions = len(rows)
        total_amount = sum(r["amount"] for r in rows)

        status_breakdown: dict = {}
        for r in rows:
            s = r["status"]
            if s not in status_breakdown:
                status_breakdown[s] = {"count": 0, "amount": 0}
            status_breakdown[s]["count"] += 1
            status_breakdown[s]["amount"] += r["amount"]

        method_breakdown: dict = {}
        for r in rows:
            m = r["method"]
            if m not in method_breakdown:
                method_breakdown[m] = {"count": 0, "amount": 0}
            method_breakdown[m]["count"] += 1
            method_breakdown[m]["amount"] += r["amount"]

        router_breakdown: dict = {}
        for r in rows:
            if r["router_name"]:
                rname = r["router_name"]
                if rname not in router_breakdown:
                    router_breakdown[rname] = {"count": 0, "amount": 0, "router_id": r["router_id"]}
                router_breakdown[rname]["count"] += 1
                router_breakdown[rname]["amount"] += r["amount"]

        return {
            "total_transactions": total_transactions,
            "total_amount": total_amount,
            "status_breakdown": status_breakdown,
            "method_breakdown": method_breakdown,
            "router_breakdown": router_breakdown,
            "period": {
                "date": date,
                "start_date": start_date,
                "end_date": end_date,
            },
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



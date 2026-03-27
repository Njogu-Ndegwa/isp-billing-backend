from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from app.db.models import (
    MpesaTransaction, MpesaTransactionStatus, FailureSource,
    Customer, Plan, CustomerStatus, ConnectionType, PaymentMethod,
    ProvisioningAttemptEntrypoint, ProvisioningAttemptSource,
)
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)

async def save_mpesa_transaction(
    db: AsyncSession, 
    checkout_request_id: str, 
    phone_number: str, 
    amount: float, 
    reference: str,
    merchant_request_id: str = None
) -> MpesaTransaction:
    """
    Save a new M-Pesa transaction to the database.
    """
    try:
        transaction = MpesaTransaction(
            checkout_request_id=checkout_request_id,
            phone_number=phone_number,
            amount=amount,
            reference=reference,
            merchant_request_id=merchant_request_id,
            status=MpesaTransactionStatus.pending,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(transaction)
        await db.commit()
        await db.refresh(transaction)
        logger.info(f"Saved M-Pesa transaction: {checkout_request_id}")
        return transaction
    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Failed to save M-Pesa transaction: {str(e)}")
        raise ValueError(f"Transaction with checkout_request_id {checkout_request_id} already exists")
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error saving M-Pesa transaction: {str(e)}")
        raise

async def get_mpesa_transaction_by_checkout_id(
    db: AsyncSession, 
    checkout_request_id: str
) -> Optional[MpesaTransaction]:
    """
    Retrieve an M-Pesa transaction by checkout_request_id.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.checkout_request_id == checkout_request_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception as e:
        logger.error(f"Error retrieving M-Pesa transaction {checkout_request_id}: {str(e)}")
        raise

async def update_mpesa_transaction_status(
    db: AsyncSession, 
    checkout_request_id: str, 
    status: MpesaTransactionStatus, 
    receipt_number: str = None,
    result_code: str = None,
    result_desc: str = None,
    failure_source: FailureSource = None
) -> bool:
    """
    Update the status of an M-Pesa transaction.
    
    Args:
        db: Database session
        checkout_request_id: The checkout request ID
        status: New status of the transaction
        receipt_number: M-Pesa receipt number (for successful transactions)
        result_code: Result code from M-Pesa callback
        result_desc: Result description from M-Pesa callback
        failure_source: Where the failure originated (client, mpesa_api, server, timeout)
    """
    try:
        values = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if receipt_number:
            values["mpesa_receipt_number"] = receipt_number
            values["transaction_date"] = datetime.utcnow()
            
        if result_code:
            values["result_code"] = result_code
            
        if result_desc:
            values["result_desc"] = result_desc
        
        if failure_source:
            values["failure_source"] = failure_source

        stmt = update(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == checkout_request_id
        ).values(**values)
        
        result = await db.execute(stmt)
        await db.commit()
        
        if result.rowcount == 0:
            logger.warning(f"No transaction found with checkout_request_id {checkout_request_id}")
            return False
            
        logger.info(f"Updated M-Pesa transaction status: {checkout_request_id} to {status.value}")
        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating M-Pesa transaction status {checkout_request_id}: {str(e)}")
        raise

async def get_pending_mpesa_transactions(
    db: AsyncSession
) -> List[MpesaTransaction]:
    """
    Retrieve all pending M-Pesa transactions.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.status == MpesaTransactionStatus.pending)
        result = await db.execute(stmt)
        return result.scalars().all()
    except Exception as e:
        logger.error(f"Error retrieving pending M-Pesa transactions: {str(e)}")
        raise

async def link_transaction_to_customer(
    db: AsyncSession, 
    checkout_request_id: str, 
    customer_id: int
) -> bool:
    """
    Link an M-Pesa transaction to a customer.
    """
    try:
        stmt = update(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == checkout_request_id
        ).values(
            customer_id=customer_id,
            updated_at=datetime.utcnow()
        )
        result = await db.execute(stmt)
        await db.commit()
        
        if result.rowcount == 0:
            logger.warning(f"No transaction found with checkout_request_id {checkout_request_id}")
            return False
            
        logger.info(f"Linked M-Pesa transaction {checkout_request_id} to customer {customer_id}")
        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Error linking M-Pesa transaction {checkout_request_id} to customer {customer_id}: {str(e)}")
        raise

async def mark_transaction_as_expired(
    db: AsyncSession, 
    checkout_request_id: str
) -> bool:
    """
    Mark a transaction as expired (for timeout scenarios).
    """
    return await update_mpesa_transaction_status(
        db=db,
        checkout_request_id=checkout_request_id,
        status=MpesaTransactionStatus.expired,
        result_code="TIMEOUT",
        result_desc="Transaction expired due to timeout",
        failure_source=FailureSource.TIMEOUT
    )

async def get_transaction_by_receipt_number(
    db: AsyncSession,
    receipt_number: str
) -> Optional[MpesaTransaction]:
    """
    Retrieve a transaction by M-Pesa receipt number.
    """
    try:
        stmt = select(MpesaTransaction).where(MpesaTransaction.mpesa_receipt_number == receipt_number)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    except Exception as e:
        logger.error(f"Error retrieving transaction by receipt number {receipt_number}: {str(e)}")
        raise


# ---------------------------------------------------------------------------
# Background reconciliation job
# ---------------------------------------------------------------------------

_reconcile_running = False

async def reconcile_pending_mpesa_transactions():
    """
    Periodically queries Safaricom for pending M-Pesa transactions and resolves
    them (complete / fail / expire). Triggered by the APScheduler.
    """
    global _reconcile_running
    if _reconcile_running:
        logger.debug("[RECONCILE] Previous run still active, skipping")
        return
    _reconcile_running = True

    try:
        from app.db.database import async_session
        from app.services.mpesa import query_stk_push_status, get_access_token
        from app.services.reseller_payments import record_customer_payment
        from app.services.hotspot_provisioning import (
            build_hotspot_payload,
            get_or_create_provisioning_attempt,
            log_provisioning_event,
            provision_hotspot_customer,
            schedule_provisioning_attempt,
        )
        from app.services.pppoe_provisioning import call_pppoe_provision, build_pppoe_payload

        now = datetime.utcnow()
        query_min_age = timedelta(minutes=2)
        expire_threshold = timedelta(hours=2)

        async with async_session() as db:
            stmt = (
                select(MpesaTransaction)
                .where(
                    MpesaTransaction.status == MpesaTransactionStatus.pending,
                    MpesaTransaction.created_at < now - query_min_age,
                    ~MpesaTransaction.checkout_request_id.startswith("FAILED-"),
                )
                .order_by(MpesaTransaction.created_at.asc())
                .limit(50)
            )
            result = await db.execute(stmt)
            pending_txns: List[MpesaTransaction] = list(result.scalars().all())

        if not pending_txns:
            return

        # Phase 1: expire everything older than the threshold (no API calls)
        to_query: List[MpesaTransaction] = []
        expired_count = 0
        for txn in pending_txns:
            age = now - txn.created_at
            if age > expire_threshold:
                try:
                    async with async_session() as db:
                        await mark_transaction_as_expired(db, txn.checkout_request_id)
                    expired_count += 1
                    logger.info(
                        "[RECONCILE] Expired stale transaction %s (age: %s)",
                        txn.checkout_request_id, age,
                    )
                except Exception as exp_err:
                    logger.warning("[RECONCILE] Failed to expire %s: %s", txn.checkout_request_id, exp_err)
            else:
                to_query.append(txn)

        if expired_count:
            logger.info("[RECONCILE] Expired %d stale transactions", expired_count)

        if not to_query:
            return

        # Phase 2: query Safaricom for fresh transactions (newest first)
        to_query.sort(key=lambda t: t.created_at, reverse=True)
        to_query = to_query[:15]

        logger.info("[RECONCILE] Querying Safaricom for %d pending transactions", len(to_query))

        # Fetch one OAuth token for the entire batch
        try:
            access_token = await get_access_token()
        except Exception as token_err:
            logger.warning("[RECONCILE] Cannot get Safaricom token, aborting batch: %s", token_err)
            return

        consecutive_failures = 0
        max_consecutive_failures = 3

        for txn in to_query:
            if consecutive_failures >= max_consecutive_failures:
                logger.warning(
                    "[RECONCILE] %d consecutive Safaricom failures, aborting remaining queries",
                    consecutive_failures,
                )
                break

            try:
                stk_result = await query_stk_push_status(txn.checkout_request_id, access_token=access_token)
                consecutive_failures = 0
            except Exception as query_err:
                consecutive_failures += 1
                logger.warning(
                    "[RECONCILE] Could not query Safaricom for %s (%d/%d failures): %s",
                    txn.checkout_request_id, consecutive_failures, max_consecutive_failures, query_err,
                )
                await asyncio.sleep(3)
                continue

            result_code = stk_result["result_code"]
            result_desc = stk_result["result_desc"]

            if result_code == 0:
                await _handle_successful_reconciliation(
                    txn, result_desc,
                    record_customer_payment,
                    build_hotspot_payload,
                    get_or_create_provisioning_attempt,
                    log_provisioning_event,
                    provision_hotspot_customer,
                    schedule_provisioning_attempt,
                    call_pppoe_provision,
                    build_pppoe_payload,
                )
            elif result_code == -1:
                logger.debug(
                    "[RECONCILE] %s still processing at Safaricom, will retry later",
                    txn.checkout_request_id,
                )
            else:
                async with async_session() as db:
                    await update_mpesa_transaction_status(
                        db,
                        txn.checkout_request_id,
                        MpesaTransactionStatus.failed,
                        result_code=str(result_code),
                        result_desc=result_desc,
                        failure_source=FailureSource.CLIENT,
                    )
                logger.info(
                    "[RECONCILE] Marked %s as failed (code=%s, desc=%s)",
                    txn.checkout_request_id, result_code, result_desc,
                )

            await asyncio.sleep(2)

    except Exception as outer_err:
        logger.exception("[RECONCILE] Reconciliation job failed: %s", outer_err)
    finally:
        _reconcile_running = False


async def _handle_successful_reconciliation(
    txn: MpesaTransaction,
    result_desc: str,
    record_customer_payment,
    build_hotspot_payload,
    get_or_create_provisioning_attempt,
    log_provisioning_event,
    provision_hotspot_customer,
    schedule_provisioning_attempt,
    call_pppoe_provision,
    build_pppoe_payload,
):
    """Complete a transaction that Safaricom confirms as paid, then provision."""
    from app.db.database import async_session
    import json

    async with async_session() as db:
        # Re-fetch the transaction inside this session (avoid detached instance)
        stmt = select(MpesaTransaction).where(
            MpesaTransaction.checkout_request_id == txn.checkout_request_id
        )
        res = await db.execute(stmt)
        mpesa_txn = res.scalar_one_or_none()
        if not mpesa_txn or mpesa_txn.status != MpesaTransactionStatus.pending:
            return

        mpesa_txn.status = MpesaTransactionStatus.completed
        mpesa_txn.result_code = "0"
        mpesa_txn.result_desc = result_desc
        mpesa_txn.failure_source = None
        mpesa_txn.updated_at = datetime.utcnow()
        await db.commit()

        logger.info(
            "[RECONCILE] Marked %s as completed via STK Query",
            txn.checkout_request_id,
        )

        # --- Load customer with plan and router ---
        customer_id = mpesa_txn.customer_id
        if not customer_id:
            logger.warning("[RECONCILE] Transaction %s has no customer_id, skipping provisioning", txn.checkout_request_id)
            return

        cust_stmt = (
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id)
        )
        cust_result = await db.execute(cust_stmt)
        customer = cust_result.scalar_one_or_none()
        if not customer:
            logger.error("[RECONCILE] Customer %s not found for transaction %s", customer_id, txn.checkout_request_id)
            return

        # --- Handle pending plan change ---
        pending_data = None
        if customer.pending_update_data:
            try:
                pending_data = json.loads(customer.pending_update_data) if isinstance(customer.pending_update_data, str) else customer.pending_update_data
            except (json.JSONDecodeError, TypeError):
                pending_data = None

        if pending_data and pending_data.get("plan_id"):
            pending_plan_stmt = select(Plan).where(Plan.id == pending_data["plan_id"])
            pending_plan_result = await db.execute(pending_plan_stmt)
            plan = pending_plan_result.scalar_one_or_none() or customer.plan
            if plan:
                customer.plan_id = plan.id
                logger.info("[RECONCILE] Updated customer %s plan_id to %s", customer.id, plan.id)
        else:
            plan = customer.plan

        if not plan:
            logger.error("[RECONCILE] Customer %s has no plan, cannot provision", customer.id)
            return

        customer.pending_update_data = None

        duration_value = plan.duration_value
        duration_unit = plan.duration_unit.value.upper()

        if duration_unit == "MINUTES":
            days_paid_for = max(1, duration_value // (24 * 60))
        elif duration_unit == "HOURS":
            days_paid_for = max(1, duration_value // 24)
        else:
            days_paid_for = duration_value

        # Record the payment
        payment = await record_customer_payment(
            db=db,
            customer_id=customer.id,
            reseller_id=customer.user_id,
            amount=float(mpesa_txn.amount),
            payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=days_paid_for,
            payment_reference=mpesa_txn.mpesa_receipt_number,
            notes=f"M-Pesa reconciliation. TX: {txn.checkout_request_id}",
            duration_value=duration_value,
            duration_unit=duration_unit,
        )
        logger.info("[RECONCILE] Payment recorded: ID %s for customer %s", payment.id, customer.id)

        # --- Provision the customer ---
        if customer.plan and customer.plan.connection_type == ConnectionType.PPPOE:
            if customer.pppoe_username and customer.router:
                pppoe_payload = build_pppoe_payload(customer, customer.router)
                await call_pppoe_provision(pppoe_payload)
            else:
                logger.error(
                    "[RECONCILE] Skipping PPPoE provisioning for customer %s - "
                    "missing pppoe_username or router",
                    customer.id,
                )
        elif customer.mac_address and customer.router:
            router_obj = customer.router
            hotspot_payload = build_hotspot_payload(
                customer, plan, router_obj,
                comment=f"Reconciled payment for {customer.name}",
            )
            attempt = await get_or_create_provisioning_attempt(
                db,
                customer_id=customer.id,
                router_id=router_obj.id,
                mac_address=customer.mac_address,
                source_table=ProvisioningAttemptSource.MPESA_TRANSACTION,
                source_pk=mpesa_txn.id,
                external_reference=mpesa_txn.checkout_request_id,
                entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_RECONCILIATION,
            )
            await schedule_provisioning_attempt(db, attempt)
            await db.commit()
            await log_provisioning_event(
                customer_id=customer.id,
                router_id=router_obj.id,
                mac_address=customer.mac_address,
                action="hotspot_reconciliation",
                status="scheduled",
                details=f"Queued after M-Pesa reconciliation for router {router_obj.ip_address}",
                attempt_id=attempt.id,
            )
            await provision_hotspot_customer(
                customer.id,
                router_obj.id,
                hotspot_payload,
                "hotspot_reconciliation",
                attempt.id,
            )
        else:
            logger.error(
                "[RECONCILE] Skipping provisioning for customer %s - "
                "missing mac_address or router",
                customer.id,
            )

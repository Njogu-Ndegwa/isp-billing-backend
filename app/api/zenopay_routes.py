"""
ZenoPay webhook and payment endpoints.

Handles asynchronous payment notifications from ZenoPay (Tanzania) and
provides order status querying.
"""

import json
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    PaymentMethod,
    Plan,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    ZenoPayTransaction,
    ZenoPayTransactionStatus,
)
from app.services.payment_gateway import decrypt_credential
from app.services.zenopay import validate_zenopay_webhook

logger = logging.getLogger(__name__)

router = APIRouter(tags=["zenopay"])


@router.post("/api/zenopay/webhook/{reseller_id}")
async def zenopay_webhook(
    reseller_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle ZenoPay payment webhook.

    Per ZenoPay docs, webhooks are **only triggered when payment_status
    changes to COMPLETED**.  FAILED payments do NOT trigger a webhook —
    those are detected via the order-status polling endpoint instead.

    ZenoPay sends a POST with x-api-key header and a JSON body containing
    order_id, payment_status, and reference.
    The reseller_id in the URL lets us look up the correct API key for verification.
    """
    payload = await request.json()
    logger.info(
        "[ZENOPAY WEBHOOK] Received for reseller %s: %s",
        reseller_id, json.dumps(payload, default=str),
    )

    order_id = payload.get("order_id")
    payment_status = payload.get("payment_status", "").upper()
    reference = payload.get("reference")

    if not order_id:
        logger.error("[ZENOPAY WEBHOOK] Missing order_id in payload")
        return {"status": "error", "message": "Missing order_id"}

    # Look up the transaction
    txn_result = await db.execute(
        select(ZenoPayTransaction).where(
            ZenoPayTransaction.order_id == order_id,
            ZenoPayTransaction.reseller_id == reseller_id,
        )
    )
    txn = txn_result.scalar_one_or_none()
    if not txn:
        logger.error("[ZENOPAY WEBHOOK] Transaction not found: %s", order_id)
        return {"status": "error", "message": "Transaction not found"}

    if txn.status != ZenoPayTransactionStatus.PENDING:
        logger.warning("[ZENOPAY WEBHOOK] Already processed: %s", order_id)
        return {"status": "received"}

    # Verify webhook authenticity against the reseller's stored API key
    pm_result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.user_id == reseller_id,
            ResellerPaymentMethod.method_type == ResellerPaymentMethodType.ZENOPAY,
            ResellerPaymentMethod.is_active == True,
        )
    )
    pm = pm_result.scalar_one_or_none()
    if pm and pm.zenopay_api_key_encrypted:
        expected_key = decrypt_credential(pm.zenopay_api_key_encrypted)
        if not validate_zenopay_webhook(dict(request.headers), expected_key):
            logger.warning("[ZENOPAY WEBHOOK] Invalid API key for reseller %s", reseller_id)
            return {"status": "error", "message": "Unauthorized"}

    txn.reference = reference
    txn.channel = payload.get("payment_method") or payload.get("channel")

    if payment_status == "COMPLETED":
        txn.status = ZenoPayTransactionStatus.COMPLETED
        txn.updated_at = datetime.utcnow()

        customer_id = txn.customer_id
        if not customer_id:
            logger.error("[ZENOPAY WEBHOOK] No customer linked to order %s", order_id)
            await db.commit()
            return {"status": "received"}

        customer_result = await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == customer_id)
        )
        customer = customer_result.scalar_one_or_none()
        if not customer:
            logger.error("[ZENOPAY WEBHOOK] Customer %s not found", customer_id)
            await db.commit()
            return {"status": "received"}

        logger.info("[ZENOPAY WEBHOOK] Payment CONFIRMED for customer %s", customer.id)

        # Resolve the plan (check pending_update_data for plan changes)
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
            logger.error("[ZENOPAY WEBHOOK] No plan for customer %s", customer.id)
            await db.commit()
            return {"status": "received"}

        duration_value = plan.duration_value
        duration_unit = plan.duration_unit.value.upper()

        if duration_unit == "MINUTES":
            days_paid_for = max(1, duration_value // (24 * 60))
        elif duration_unit == "HOURS":
            days_paid_for = max(1, duration_value // 24)
        else:
            days_paid_for = duration_value

        # Record payment
        from app.services.reseller_payments import record_customer_payment

        payment = await record_customer_payment(
            db=db,
            customer_id=customer.id,
            reseller_id=customer.user_id,
            amount=float(txn.amount),
            payment_method=PaymentMethod.MOBILE_MONEY,
            days_paid_for=days_paid_for,
            payment_reference=f"ZENO-{reference or order_id}",
            notes=f"ZenoPay payment. Order: {order_id}",
            duration_value=duration_value,
            duration_unit=duration_unit,
        )

        customer.pending_update_data = None
        logger.info("[ZENOPAY WEBHOOK] Payment recorded: ID %s", payment.id)

        # Provision based on connection type
        if customer.plan and customer.router:
            if customer.plan.connection_type == ConnectionType.PPPOE:
                if customer.pppoe_username:
                    from app.services.pppoe_provisioning import call_pppoe_provision, build_pppoe_payload
                    pppoe_payload = build_pppoe_payload(customer, customer.router)
                    # Fire-and-forget is not available here without BackgroundTasks,
                    # but the payment is already recorded. Provisioning happens on next poll.
                    logger.info("[ZENOPAY WEBHOOK] PPPoE provisioning queued for customer %s", customer.id)
            elif customer.mac_address:
                from app.services.hotspot_provisioning import (
                    build_hotspot_payload,
                    log_provisioning_event,
                    provision_hotspot_customer,
                )
                hotspot_payload = build_hotspot_payload(
                    customer, plan, customer.router,
                    comment=f"ZenoPay payment for {customer.name}",
                )
                await log_provisioning_event(
                    customer_id=customer.id,
                    router_id=customer.router.id,
                    mac_address=customer.mac_address,
                    action="zenopay_payment",
                    status="scheduled",
                    details=f"Queued after ZenoPay webhook for order {order_id}",
                )
                await provision_hotspot_customer(
                    customer.id,
                    customer.router.id,
                    hotspot_payload,
                    "zenopay_payment",
                )

        await db.commit()
        return {"status": "received"}

    elif payment_status == "FAILED":
        txn.status = ZenoPayTransactionStatus.FAILED
        txn.updated_at = datetime.utcnow()

        if txn.customer_id:
            cust_result = await db.execute(
                select(Customer).where(Customer.id == txn.customer_id)
            )
            cust = cust_result.scalar_one_or_none()
            if cust and cust.status == CustomerStatus.PENDING:
                cust.status = CustomerStatus.INACTIVE

        await db.commit()
        logger.info("[ZENOPAY WEBHOOK] Payment FAILED for order %s", order_id)
        return {"status": "received"}

    else:
        logger.info("[ZENOPAY WEBHOOK] Unhandled status %s for order %s", payment_status, order_id)
        await db.commit()
        return {"status": "received"}


@router.get("/api/zenopay/order-status/{order_id}")
async def get_zenopay_order_status(
    order_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Check the status of a ZenoPay transaction.  Used by frontends polling
    for payment completion (similar to /api/hotspot/payment-status).

    Because ZenoPay webhooks only fire on COMPLETED, this endpoint actively
    polls the ZenoPay order-status API when our local record is still
    PENDING so the frontend can discover FAILED payments too.
    """
    result = await db.execute(
        select(ZenoPayTransaction).where(ZenoPayTransaction.order_id == order_id)
    )
    txn = result.scalar_one_or_none()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    # If still pending, ask ZenoPay for the latest status
    if txn.status == ZenoPayTransactionStatus.PENDING:
        await _sync_zenopay_status(db, txn)

    customer = None
    if txn.customer_id:
        cust_result = await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan))
            .where(Customer.id == txn.customer_id)
        )
        customer = cust_result.scalar_one_or_none()

    return {
        "order_id": txn.order_id,
        "status": txn.status.value if hasattr(txn.status, "value") else txn.status,
        "amount": float(txn.amount),
        "reference": txn.reference,
        "channel": txn.channel,
        "customer_id": txn.customer_id,
        "customer_status": customer.status.value if customer else None,
        "plan_name": customer.plan.name if customer and customer.plan else None,
        "expiry": customer.expiry.isoformat() if customer and customer.expiry else None,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
    }


async def _sync_zenopay_status(db: AsyncSession, txn: ZenoPayTransaction):
    """Poll ZenoPay's order-status API and update our local record if changed."""
    pm_result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.user_id == txn.reseller_id,
            ResellerPaymentMethod.method_type == ResellerPaymentMethodType.ZENOPAY,
            ResellerPaymentMethod.is_active == True,
        )
    )
    pm = pm_result.scalar_one_or_none()
    if not pm or not pm.zenopay_api_key_encrypted:
        return

    try:
        from app.services.zenopay import check_zenopay_order_status

        api_key = decrypt_credential(pm.zenopay_api_key_encrypted)
        order_data = await check_zenopay_order_status(api_key, txn.order_id)

        remote_status = (order_data.get("payment_status") or "").upper()
        if not remote_status:
            return

        if remote_status == "COMPLETED" and txn.status == ZenoPayTransactionStatus.PENDING:
            txn.status = ZenoPayTransactionStatus.COMPLETED
            txn.reference = order_data.get("reference") or txn.reference
            txn.channel = order_data.get("channel") or txn.channel
            txn.updated_at = datetime.utcnow()
            await db.commit()
            logger.info("[ZENOPAY POLL] Order %s now COMPLETED", txn.order_id)

        elif remote_status == "FAILED" and txn.status == ZenoPayTransactionStatus.PENDING:
            txn.status = ZenoPayTransactionStatus.FAILED
            txn.updated_at = datetime.utcnow()

            if txn.customer_id:
                cust_result = await db.execute(
                    select(Customer).where(Customer.id == txn.customer_id)
                )
                cust = cust_result.scalar_one_or_none()
                if cust and cust.status == CustomerStatus.PENDING:
                    cust.status = CustomerStatus.INACTIVE

            await db.commit()
            logger.info("[ZENOPAY POLL] Order %s now FAILED", txn.order_id)

    except Exception as e:
        logger.warning("[ZENOPAY POLL] Failed to check status for %s: %s", txn.order_id, e)

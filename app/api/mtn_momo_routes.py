"""
MTN MoMo webhook and status endpoints.

Handles the asynchronous side of the MTN Collection / RequestToPay flow:

    * ``POST /api/mtn-momo/callback/{reseller_id}`` — URL we advertise to MTN
      via ``X-Callback-Url``.  MTN POSTs here once the payment reaches a final
      state (SUCCESSFUL or FAILED).  The body is minimal and not retried, so we
      re-GET the authoritative status from MTN before taking action.

    * ``GET /api/mtn-momo/status/{reference_id}`` — polling endpoint used by
      frontends while the STK-style prompt is outstanding.  If the local
      record is still PENDING we ask MTN for the latest status and persist it.

Both paths funnel SUCCESSFUL payments through the same helper so customer
payment recording + hotspot/PPPoE provisioning happens exactly once.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    MtnMomoTransaction,
    MtnMomoTransactionStatus,
    PaymentMethod,
    Plan,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
)
from app.services.payment_gateway import decrypt_credential

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mtn-momo"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_active_mtn_method(
    db: AsyncSession, reseller_id: int
) -> ResellerPaymentMethod | None:
    """Return the reseller's active MTN MoMo payment method, or None."""
    result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.user_id == reseller_id,
            ResellerPaymentMethod.method_type == ResellerPaymentMethodType.MTN_MOMO,
            ResellerPaymentMethod.is_active == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none()


async def _fetch_mtn_status(
    txn: MtnMomoTransaction, pm: ResellerPaymentMethod
) -> dict | None:
    """
    Ask MTN for the authoritative status of ``txn`` using ``pm``'s credentials.

    Returns the parsed JSON dict or ``None`` on failure (logged).
    """
    from app.services.mtn_momo import check_request_to_pay_status

    try:
        api_key = decrypt_credential(pm.mtn_api_key_encrypted)
        subscription_key = decrypt_credential(pm.mtn_subscription_key_encrypted)
    except Exception as exc:
        logger.error("[MTN MOMO] Failed to decrypt credentials for reseller %s: %s", pm.user_id, exc)
        return None

    try:
        return await check_request_to_pay_status(
            txn.reference_id,
            target_environment=txn.target_environment or pm.mtn_target_environment,
            base_url=pm.mtn_base_url or "https://sandbox.momodeveloper.mtn.com",
            api_user=pm.mtn_api_user,
            api_key=api_key,
            subscription_key=subscription_key,
        )
    except Exception as exc:
        logger.warning(
            "[MTN MOMO] Status lookup failed for %s: %s", txn.reference_id, exc
        )
        return None


async def _apply_remote_status(
    db: AsyncSession,
    txn: MtnMomoTransaction,
    remote: dict,
) -> None:
    """
    Promote a local PENDING transaction to SUCCESSFUL / FAILED based on the
    authoritative payload from MTN.  Triggers recording + provisioning when
    appropriate.  Idempotent — no-ops if ``txn`` is already final.
    """
    if txn.status != MtnMomoTransactionStatus.PENDING:
        return

    remote_status = (remote.get("status") or "").upper()
    reason = remote.get("reason") or {}
    if isinstance(reason, str):
        # Some MTN responses stringify ``reason``; keep it in the message field.
        reason_code, reason_message = None, reason
    else:
        reason_code = reason.get("code")
        reason_message = reason.get("message")

    if remote_status == "SUCCESSFUL":
        txn.status = MtnMomoTransactionStatus.SUCCESSFUL
        txn.financial_transaction_id = remote.get("financialTransactionId")
        txn.reason_code = reason_code
        txn.reason_message = reason_message
        txn.updated_at = datetime.utcnow()
        await _record_successful_payment(db, txn)

    elif remote_status == "FAILED":
        txn.status = MtnMomoTransactionStatus.FAILED
        txn.reason_code = reason_code
        txn.reason_message = reason_message
        txn.updated_at = datetime.utcnow()

        if txn.customer_id:
            cust_result = await db.execute(
                select(Customer).where(Customer.id == txn.customer_id)
            )
            cust = cust_result.scalar_one_or_none()
            if cust and cust.status == CustomerStatus.PENDING:
                cust.status = CustomerStatus.INACTIVE

        logger.info(
            "[MTN MOMO] Payment FAILED for reference %s (reason=%s)",
            txn.reference_id, reason_code or reason_message,
        )

    # PENDING or unknown status: leave the row untouched.


async def _record_successful_payment(
    db: AsyncSession, txn: MtnMomoTransaction
) -> None:
    """
    On SUCCESSFUL payment: update the customer plan (if a pending plan change
    is queued), record a customer payment, and trigger hotspot / PPPoE
    provisioning.  Mirrors ``zenopay_routes._sync_zenopay_status`` success path.
    """
    if not txn.customer_id:
        logger.error("[MTN MOMO] No customer linked to reference %s", txn.reference_id)
        return

    customer_result = await db.execute(
        select(Customer)
        .options(selectinload(Customer.plan), selectinload(Customer.router))
        .where(Customer.id == txn.customer_id)
    )
    customer = customer_result.scalar_one_or_none()
    if not customer:
        logger.error("[MTN MOMO] Customer %s not found for reference %s",
                     txn.customer_id, txn.reference_id)
        return

    # Resolve the plan (respect pending plan-change data, same as ZenoPay handler)
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
        logger.error("[MTN MOMO] No plan for customer %s (reference %s)",
                     customer.id, txn.reference_id)
        return

    duration_value = plan.duration_value
    duration_unit = plan.duration_unit.value.upper()

    if duration_unit == "MINUTES":
        days_paid_for = max(1, duration_value // (24 * 60))
    elif duration_unit == "HOURS":
        days_paid_for = max(1, duration_value // 24)
    else:
        days_paid_for = duration_value

    from app.services.reseller_payments import record_customer_payment

    payment_reference = (
        f"MTN-{txn.financial_transaction_id}"
        if txn.financial_transaction_id
        else f"MTN-{txn.reference_id}"
    )

    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=customer.user_id,
        amount=float(txn.amount),
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=days_paid_for,
        payment_reference=payment_reference,
        notes=f"MTN MoMo payment. Reference: {txn.reference_id}",
        duration_value=duration_value,
        duration_unit=duration_unit,
    )

    customer.pending_update_data = None
    logger.info("[MTN MOMO] Payment recorded: id=%s (reference %s)",
                payment.id, txn.reference_id)

    # Provisioning dispatch — same split as the ZenoPay handler.
    if customer.plan and customer.router:
        if customer.plan.connection_type == ConnectionType.PPPOE:
            if customer.pppoe_username:
                logger.info(
                    "[MTN MOMO] PPPoE provisioning queued for customer %s",
                    customer.id,
                )
        elif customer.mac_address:
            from app.services.hotspot_provisioning import (
                build_hotspot_payload,
                log_provisioning_event,
                provision_hotspot_customer,
            )
            hotspot_payload = build_hotspot_payload(
                customer, plan, customer.router,
                comment=f"MTN MoMo payment for {customer.name}",
            )
            await log_provisioning_event(
                customer_id=customer.id,
                router_id=customer.router.id,
                mac_address=customer.mac_address,
                action="mtn_momo_payment",
                status="scheduled",
                details=f"Queued after MTN MoMo callback for reference {txn.reference_id}",
            )
            await provision_hotspot_customer(
                customer.id,
                customer.router.id,
                hotspot_payload,
                "mtn_momo_payment",
            )


# ---------------------------------------------------------------------------
# Callback (webhook)
# ---------------------------------------------------------------------------

@router.post("/api/mtn-momo/callback/{reseller_id}")
async def mtn_momo_callback(
    reseller_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Receive MTN's final-state notification.

    MTN does not retry callbacks and the body is minimal, so our contract is:

        1. Parse the payload to find ``referenceId`` (falling back to common
           aliases MTN uses: ``reference_id``, ``externalId``).
        2. Look up the local transaction for this reseller.
        3. Re-GET the authoritative status from MTN and apply it.

    Returns ``{"status": "received"}`` on all happy paths so MTN stops pinging.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    logger.info(
        "[MTN MOMO CALLBACK] Received for reseller %s: %s",
        reseller_id, json.dumps(payload, default=str),
    )

    # MTN's callback body is documented to include ``externalId`` but *not*
    # ``referenceId`` — it correlates via the reference we generated.  Some
    # deployments also expose ``X-Reference-Id`` as a response / callback
    # header, so we check that first.  Finally, we accept a ``referenceId``
    # field in the body for older / proxied gateways that do include it.
    reference_id = (
        request.headers.get("X-Reference-Id")
        or payload.get("referenceId")
        or payload.get("reference_id")
    )
    external_id = payload.get("externalId") or payload.get("external_id")

    if not reference_id and not external_id:
        logger.error("[MTN MOMO CALLBACK] Missing reference id / external id in payload")
        return {"status": "error", "message": "Missing referenceId/externalId"}

    query = select(MtnMomoTransaction).where(
        MtnMomoTransaction.reseller_id == reseller_id
    )
    if reference_id:
        query = query.where(MtnMomoTransaction.reference_id == reference_id)
    else:
        query = query.where(MtnMomoTransaction.external_id == external_id)

    txn_result = await db.execute(query)
    txn = txn_result.scalar_one_or_none()
    if not txn:
        logger.error(
            "[MTN MOMO CALLBACK] Transaction not found for reseller %s (ref=%s, ext=%s)",
            reseller_id, reference_id, external_id,
        )
        return {"status": "error", "message": "Transaction not found"}

    if txn.status != MtnMomoTransactionStatus.PENDING:
        logger.info(
            "[MTN MOMO CALLBACK] Already final for %s (status=%s), ignoring",
            reference_id, txn.status,
        )
        return {"status": "received"}

    pm = await _get_active_mtn_method(db, reseller_id)
    if not pm:
        logger.error(
            "[MTN MOMO CALLBACK] No active MTN method for reseller %s", reseller_id
        )
        return {"status": "error", "message": "Unknown reseller"}

    remote = await _fetch_mtn_status(txn, pm)
    if remote is None:
        # Fall back to the callback body alone — some MTN operators include
        # ``status`` directly in the POST.  Better than silently dropping.
        remote = {"status": payload.get("status"), "reason": payload.get("reason")}

    await _apply_remote_status(db, txn, remote)
    await db.commit()
    return {"status": "received"}


# ---------------------------------------------------------------------------
# Status (polling endpoint)
# ---------------------------------------------------------------------------

@router.get("/api/mtn-momo/status/{reference_id}")
async def get_mtn_momo_status(
    reference_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Return the current state of an MTN MoMo transaction.

    Actively polls MTN when the local record is still PENDING so frontends can
    discover FAILED payments even though MTN's callback fires only once.
    """
    result = await db.execute(
        select(MtnMomoTransaction).where(
            MtnMomoTransaction.reference_id == reference_id
        )
    )
    txn = result.scalar_one_or_none()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if txn.status == MtnMomoTransactionStatus.PENDING:
        pm = await _get_active_mtn_method(db, txn.reseller_id)
        if pm:
            remote = await _fetch_mtn_status(txn, pm)
            if remote:
                await _apply_remote_status(db, txn, remote)
                await db.commit()

    customer = None
    if txn.customer_id:
        cust_result = await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan))
            .where(Customer.id == txn.customer_id)
        )
        customer = cust_result.scalar_one_or_none()

    return {
        "reference_id": txn.reference_id,
        "external_id": txn.external_id,
        "status": txn.status.value if hasattr(txn.status, "value") else txn.status,
        "amount": float(txn.amount),
        "currency": txn.currency,
        "phone": txn.phone,
        "financial_transaction_id": txn.financial_transaction_id,
        "reason_code": txn.reason_code,
        "reason_message": txn.reason_message,
        "target_environment": txn.target_environment,
        "customer_id": txn.customer_id,
        "customer_status": customer.status.value if customer else None,
        "plan_name": customer.plan.name if customer and customer.plan else None,
        "expiry": customer.expiry.isoformat() if customer and customer.expiry else None,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
        "updated_at": txn.updated_at.isoformat() if txn.updated_at else None,
    }

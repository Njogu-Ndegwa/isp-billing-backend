"""Fapshi webhook and captive-portal status reconciliation endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import (
    CollectionMode,
    ConnectionType,
    Customer,
    FapshiTransaction,
    FapshiTransactionStatus,
    PaymentMethod,
    Plan,
    ResellerPaymentMethod,
    RouterAuthMethod,
)
from app.services.billing import apply_failed_payment_customer_status
from app.services.payment_gateway import decrypt_credential

logger = logging.getLogger(__name__)
router = APIRouter(tags=["fapshi"])

_FINAL_STATUSES = {
    FapshiTransactionStatus.SUCCESSFUL,
    FapshiTransactionStatus.FAILED,
    FapshiTransactionStatus.EXPIRED,
}
_PORTAL_RECONCILIATION_INTERVAL = timedelta(seconds=10)


def _parse_provider_datetime(value: object) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
        # The rest of this codebase stores naive UTC datetimes.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _validate_remote_transaction(txn: FapshiTransaction, remote: dict) -> None:
    """Reject a status response that does not describe our local transaction."""
    remote_trans_id = str(remote.get("transId") or "")
    if txn.trans_id and remote_trans_id != txn.trans_id:
        raise ValueError("Fapshi transaction ID mismatch")

    remote_external_id = remote.get("externalId")
    if remote_external_id and str(remote_external_id) != txn.external_id:
        raise ValueError("Fapshi external transaction ID mismatch")

    try:
        remote_amount = Decimal(str(remote.get("amount")))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("Fapshi status response has an invalid amount") from exc
    if remote_amount != Decimal(str(txn.amount)):
        raise ValueError("Fapshi transaction amount mismatch")

    trans_type = str(remote.get("transType") or "").lower()
    if trans_type and trans_type != "collection":
        raise ValueError("Fapshi status response is not a collection")


async def _fetch_authoritative_status(
    db: AsyncSession,
    txn: FapshiTransaction,
    *,
    provider_trans_id: str | None = None,
) -> dict:
    """Snapshot credentials, release DB, then query Fapshi."""
    pm_result = await db.execute(
        select(ResellerPaymentMethod).where(
            ResellerPaymentMethod.id == txn.payment_method_id
        )
    )
    pm = pm_result.scalar_one_or_none()
    if not pm or not pm.fapshi_api_user or not pm.fapshi_api_key_encrypted:
        raise RuntimeError("Fapshi credentials are unavailable for this transaction")

    api_user = pm.fapshi_api_user
    api_key = decrypt_credential(pm.fapshi_api_key_encrypted)
    environment = txn.environment or pm.fapshi_environment or "sandbox"
    trans_id = provider_trans_id or txn.trans_id
    if not trans_id:
        raise RuntimeError("Fapshi transaction ID is not available yet")

    # Never pin a pooled database connection across provider I/O.
    txn_id = txn.id
    await db.commit()

    from app.services.fapshi import get_payment_status

    remote = await get_payment_status(
        api_user=api_user,
        api_key=api_key,
        environment=environment,
        trans_id=trans_id,
    )

    refreshed = (
        await db.execute(
            select(FapshiTransaction).where(FapshiTransaction.id == txn_id)
        )
    ).scalar_one()
    _validate_remote_transaction(refreshed, remote)
    return remote


async def _record_successful_payment(
    db: AsyncSession,
    txn: FapshiTransaction,
) -> None:
    if not txn.customer_id:
        logger.error("[FAPSHI] No customer linked to transaction %s", txn.trans_id)
        return

    customer = (
        await db.execute(
            select(Customer)
            .options(selectinload(Customer.plan), selectinload(Customer.router))
            .where(Customer.id == txn.customer_id)
        )
    ).scalar_one_or_none()
    if not customer:
        logger.error("[FAPSHI] Customer %s not found", txn.customer_id)
        return

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

    plan = customer.plan
    if pending_data and pending_data.get("plan_id"):
        requested_plan = (
            await db.execute(
                select(Plan).where(Plan.id == pending_data["plan_id"])
            )
        ).scalar_one_or_none()
        if requested_plan:
            plan = requested_plan
            customer.plan_id = requested_plan.id
            customer.plan = requested_plan

    if not plan:
        raise RuntimeError(f"No plan found for Fapshi customer {customer.id}")

    duration_value = plan.duration_value
    duration_unit = plan.duration_unit.value.upper()
    if duration_unit == "MINUTES":
        days_paid_for = max(1, duration_value // (24 * 60))
    elif duration_unit == "HOURS":
        days_paid_for = max(1, duration_value // 24)
    else:
        days_paid_for = duration_value

    customer.pending_update_data = None
    await db.flush()

    from app.services.reseller_payments import record_customer_payment

    payment_reference = (
        f"FAPSHI-{txn.financial_transaction_id}"
        if txn.financial_transaction_id
        else f"FAPSHI-{txn.trans_id}"
    )
    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=customer.user_id,
        amount=float(txn.amount),
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=days_paid_for,
        payment_reference=payment_reference,
        notes=f"Fapshi payment. Transaction: {txn.trans_id}",
        duration_value=duration_value,
        duration_unit=duration_unit,
        collection_mode=CollectionMode.DIRECT,
    )

    # RADIUS routers need credentials in the customer status response. This is
    # database-backed provisioning, so complete it before returning success.
    router_auth_method = getattr(customer.router, "auth_method", None) if customer.router else None
    router_auth_value = (
        router_auth_method.value
        if hasattr(router_auth_method, "value")
        else router_auth_method
    )
    if (
        router_auth_value == RouterAuthMethod.RADIUS.value
        and customer.mac_address
        and customer.router
    ):
        from app.services.radius_provisioning import RadiusProvisioning

        radius_result = await RadiusProvisioning(db).provision_hotspot_user(
            customer_id=customer.id,
            mac_address=customer.mac_address,
            phone=customer.phone,
            plan_speed=plan.speed,
            plan_duration_value=duration_value,
            plan_duration_unit=duration_unit,
            router_id=customer.router.id,
            fixed_expiry=customer.expiry,
        )
        if radius_result.get("success"):
            customer.pending_update_data = json.dumps({
                "auth_method": "RADIUS",
                "radius_username": radius_result["username"],
                "radius_password": radius_result["password"],
                "provisioned_at": datetime.utcnow().isoformat(),
            })
            await db.commit()
        else:
            logger.error(
                "[FAPSHI] RADIUS provisioning failed for customer %s: %s",
                customer.id,
                radius_result.get("error"),
            )
        return

    # record_customer_payment committed and refreshed the paid customer. Build
    # immutable router payloads now, then perform all RouterOS I/O in tasks.
    pppoe_payload = None
    hotspot_payload = None
    hotspot_context = None
    if customer.router:
        if plan.connection_type == ConnectionType.PPPOE and customer.pppoe_username:
            from app.services.pppoe_provisioning import build_pppoe_payload

            pppoe_payload = build_pppoe_payload(customer, customer.router)
        elif customer.mac_address:
            from app.services.hotspot_provisioning import build_hotspot_payload

            hotspot_payload = build_hotspot_payload(
                customer,
                plan,
                customer.router,
                comment=f"Fapshi payment for {customer.name}",
            )
            hotspot_context = {
                "customer_id": customer.id,
                "router_id": customer.router.id,
                "mac_address": customer.mac_address,
                "trans_id": txn.trans_id,
            }

    if pppoe_payload:
        from app.services.pppoe_provisioning import call_pppoe_provision

        asyncio.create_task(call_pppoe_provision(pppoe_payload))

    if hotspot_payload and hotspot_context:
        from app.services.hotspot_provisioning import (
            log_provisioning_event,
            provision_hotspot_customer,
        )

        async def _provision_hotspot_after_fapshi():
            await log_provisioning_event(
                customer_id=hotspot_context["customer_id"],
                router_id=hotspot_context["router_id"],
                mac_address=hotspot_context["mac_address"],
                action="fapshi_payment",
                status="scheduled",
                details=(
                    "Queued after Fapshi confirmation for transaction "
                    f"{hotspot_context['trans_id']}"
                ),
            )
            await provision_hotspot_customer(
                hotspot_context["customer_id"],
                hotspot_context["router_id"],
                hotspot_payload,
                "fapshi_payment",
            )

        asyncio.create_task(_provision_hotspot_after_fapshi())


async def _apply_remote_status(
    db: AsyncSession,
    transaction_id: int,
    remote: dict,
) -> FapshiTransaction:
    """Apply one authoritative response under a row lock."""
    txn = (
        await db.execute(
            select(FapshiTransaction)
            .where(FapshiTransaction.id == transaction_id)
            .with_for_update()
        )
    ).scalar_one()

    if txn.status in _FINAL_STATUSES:
        return txn

    remote_status = str(remote.get("status") or "").upper()
    status_map = {
        "CREATED": FapshiTransactionStatus.CREATED,
        "PENDING": FapshiTransactionStatus.PENDING,
        "SUCCESSFUL": FapshiTransactionStatus.SUCCESSFUL,
        "FAILED": FapshiTransactionStatus.FAILED,
        "EXPIRED": FapshiTransactionStatus.EXPIRED,
    }
    mapped = status_map.get(remote_status)
    if mapped is None:
        logger.warning("[FAPSHI] Unknown status %r for %s", remote_status, txn.trans_id)
        return txn

    txn.trans_id = txn.trans_id or remote.get("transId")
    txn.medium = remote.get("medium") or txn.medium
    txn.financial_transaction_id = (
        remote.get("financialTransId") or txn.financial_transaction_id
    )
    txn.failure_reason = remote.get("reason") or txn.failure_reason
    txn.updated_at = datetime.utcnow()

    if mapped == FapshiTransactionStatus.SUCCESSFUL:
        txn.status = mapped
        txn.confirmed_at = _parse_provider_datetime(remote.get("dateConfirmed")) or datetime.utcnow()
        await _record_successful_payment(db, txn)
        await db.commit()
    elif mapped in {FapshiTransactionStatus.FAILED, FapshiTransactionStatus.EXPIRED}:
        txn.status = mapped
        if txn.customer_id:
            customer = (
                await db.execute(
                    select(Customer).where(Customer.id == txn.customer_id)
                )
            ).scalar_one_or_none()
            if customer:
                apply_failed_payment_customer_status(customer)
        await db.commit()
    else:
        txn.status = mapped
        await db.commit()

    return txn


def _serialize_transaction(txn: FapshiTransaction) -> dict:
    return {
        "trans_id": txn.trans_id,
        "external_id": txn.external_id,
        "status": txn.status.value if hasattr(txn.status, "value") else txn.status,
        "amount": float(txn.amount),
        "currency": "XAF",
        "phone": txn.phone,
        "medium": txn.medium,
        "financial_transaction_id": txn.financial_transaction_id,
        "failure_reason": txn.failure_reason,
        "customer_id": txn.customer_id,
        "environment": txn.environment,
        "created_at": txn.created_at.isoformat() if txn.created_at else None,
        "updated_at": txn.updated_at.isoformat() if txn.updated_at else None,
        "confirmed_at": txn.confirmed_at.isoformat() if txn.confirmed_at else None,
    }


async def kick_pending_fapshi_check(customer_id: int) -> None:
    """Background reconciliation used by the provider-agnostic portal poll."""
    from app.db import database as database_module

    async with database_module.async_session() as db:
        txn = (
            await db.execute(
                select(FapshiTransaction)
                .where(
                    FapshiTransaction.customer_id == customer_id,
                    FapshiTransaction.status.in_([
                        FapshiTransactionStatus.CREATED,
                        FapshiTransactionStatus.PENDING,
                    ]),
                    FapshiTransaction.trans_id.isnot(None),
                )
                .order_by(FapshiTransaction.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if not txn:
            return
        if (
            txn.updated_at
            and datetime.utcnow() - txn.updated_at < _PORTAL_RECONCILIATION_INTERVAL
        ):
            return

        try:
            transaction_id = txn.id
            remote = await _fetch_authoritative_status(db, txn)
            await _apply_remote_status(db, transaction_id, remote)
        except Exception as exc:
            await db.rollback()
            logger.warning(
                "[FAPSHI PORTAL POLL] Reconciliation failed for customer %s: %s",
                customer_id,
                exc,
            )


@router.post("/api/fapshi/webhook")
async def fapshi_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Receive Fapshi notifications, then re-query Fapshi before acting."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    trans_id = payload.get("transId")
    external_id = payload.get("externalId")
    if not trans_id and not external_id:
        return {"status": "error", "message": "Missing transId/externalId"}

    lookup_conditions = []
    if trans_id:
        lookup_conditions.append(FapshiTransaction.trans_id == trans_id)
    if external_id:
        lookup_conditions.append(FapshiTransaction.external_id == external_id)
    txn = (
        await db.execute(
            select(FapshiTransaction).where(or_(*lookup_conditions))
        )
    ).scalar_one_or_none()
    if not txn:
        logger.error("[FAPSHI WEBHOOK] Unknown transaction %s / %s", trans_id, external_id)
        return {"status": "error", "message": "Transaction not found"}
    if txn.status in _FINAL_STATUSES:
        return {"status": "received"}

    try:
        remote = await _fetch_authoritative_status(
            db, txn, provider_trans_id=trans_id
        )
        await _apply_remote_status(db, txn.id, remote)
    except Exception as exc:
        await db.rollback()
        logger.exception("[FAPSHI WEBHOOK] Reconciliation failed for %s", trans_id)
        raise HTTPException(status_code=502, detail=f"Fapshi reconciliation failed: {exc}")
    return {"status": "received"}


@router.get("/api/fapshi/status/{trans_id}")
async def get_fapshi_status(
    trans_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Poll Fapshi and expose a captive-portal-friendly local status."""
    txn = (
        await db.execute(
            select(FapshiTransaction).where(FapshiTransaction.trans_id == trans_id)
        )
    ).scalar_one_or_none()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if txn.status not in _FINAL_STATUSES:
        try:
            transaction_id = txn.id
            remote = await _fetch_authoritative_status(db, txn)
            txn = await _apply_remote_status(db, transaction_id, remote)
        except Exception as exc:
            await db.rollback()
            logger.warning("[FAPSHI POLL] Status lookup failed for %s: %s", trans_id, exc)

    # Refresh after completion because record_customer_payment commits in the
    # same session and may have updated related customer state.
    txn = (
        await db.execute(
            select(FapshiTransaction).where(FapshiTransaction.id == txn.id)
        )
    ).scalar_one()
    response = _serialize_transaction(txn)
    if txn.customer_id:
        customer = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan))
                .where(Customer.id == txn.customer_id)
            )
        ).scalar_one_or_none()
        response.update({
            "customer_status": customer.status.value if customer else None,
            "plan_name": customer.plan.name if customer and customer.plan else None,
            "expiry": customer.expiry.isoformat() if customer and customer.expiry else None,
        })
    return response

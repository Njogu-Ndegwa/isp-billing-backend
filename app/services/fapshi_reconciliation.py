"""Durable Fapshi confirmation, atomic credit, and restart-safe delivery.

All callers share a persisted provider-query lease/rate limit. A provider
SUCCESSFUL response is not local success until the purchased contract, ledger,
entitlement and delivery attempt have committed together.
"""
from __future__ import annotations

import json
import logging
import uuid
import time
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import selectinload

from app.db import database
from app.db.models import (
    CollectionMode, ConnectionType, Customer, CustomerPayment,
    CustomerUsagePeriod, FapshiTransaction, FapshiTransactionStatus,
    PaymentMethod, PaymentStatus, Plan, ProvisioningAttempt, Router,
    ProvisioningAttemptEntrypoint, ProvisioningAttemptSource,
    ProvisioningState, ResellerPaymentMethod, RouterAuthMethod,
)

logger = logging.getLogger(__name__)
FINAL_STATUSES = {FapshiTransactionStatus.SUCCESSFUL,
                  FapshiTransactionStatus.FAILED, FapshiTransactionStatus.EXPIRED}
QUERY_INTERVAL = timedelta(seconds=15)  # below Fapshi's 6/min/transId limit
LEASE_TIME = timedelta(minutes=5)
MAX_AGE = timedelta(days=7)
MAX_ATTEMPTS = 720
BATCH_SIZE = 10


def _json_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def plan_contract(plan):
    # Compare purchased service terms; cosmetic labels/badges are not entitlement.
    fields = ("id", "user_id", "price", "duration_value", "duration_unit",
              "connection_type", "speed", "router_profile", "plan_type",
              "data_cap_mb", "fup_action", "fup_throttle_profile", "fup_period",
              "max_shared_users", "router_ids", "trial_once_per_customer")
    return {key: _json_value(getattr(plan, key)) for key in fields}


def non_fapshi_attempt_clause():
    """Fapshi retries must pass its immutable target guard, not today's plan.

    Existing provisioning functions still own attempt/result persistence. Other
    retry workers must not compete with the persisted Fapshi lease.
    """
    return ~select(FapshiTransaction.id).where(
        ProvisioningAttempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT,
        FapshiTransaction.customer_payment_id == ProvisioningAttempt.source_pk,
    ).exists()


async def _latest_payment_id(db, customer_id):
    return await db.scalar(select(func.max(CustomerPayment.id)).where(
        CustomerPayment.customer_id == customer_id,
        CustomerPayment.status == PaymentStatus.COMPLETED,
    ))


def _target_baseline(customer):
    # Payer phone/name are deliberately not target-device identity.
    return {key: _json_value(getattr(customer, key)) for key in (
        "user_id", "plan_id", "router_id", "expiry", "mac_address", "pppoe_username",
        "static_ip", "subscription_owner_id", "paused_at",
    )}


async def capture_purchase_snapshot(db, customer, *, amount):
    pending = customer.pending_update_data
    if isinstance(pending, str):
        pending = json.loads(pending)
    selected_id = (pending or {}).get("plan_id") or customer.plan_id
    plan = await db.scalar(select(Plan).where(
        Plan.id == selected_id, Plan.user_id == customer.user_id,
    ))
    owned_router = await db.scalar(select(Router.id).where(
        Router.id == customer.router_id, Router.user_id == customer.user_id,
    ))
    if not plan or not owned_router:
        raise ValueError("Fapshi purchase requires an owned plan and router")
    if plan.duration_unit.value not in {"MINUTES", "HOURS", "DAYS"} or plan.duration_value <= 0:
        raise ValueError("Unsupported Fapshi purchase duration")
    previous_period_id = await db.scalar(select(CustomerUsagePeriod.id).where(
        CustomerUsagePeriod.customer_id == customer.id,
        CustomerUsagePeriod.closed_at.is_(None),
    ).order_by(CustomerUsagePeriod.id.desc()).limit(1))
    return {
        "version": 1, "reseller_id": customer.user_id,
        "customer_id": customer.id, "provider_amount": str(amount),
        "provider_user_id": f"customer-{customer.id}",
        "plan": plan_contract(plan), "baseline": _target_baseline(customer),
        "latest_payment_id": await _latest_payment_id(db, customer.id),
        "previous_usage_period_id": previous_period_id,
    }


def validate_remote_transaction(txn, remote, *, provider_trans_id=None):
    if not isinstance(remote, dict):
        raise ValueError("invalid_provider_response")
    expected_id = txn.trans_id or provider_trans_id
    if not expected_id or remote.get("transId") != expected_id:
        raise ValueError("transaction_id_mismatch")
    if remote.get("externalId") != txn.external_id:
        raise ValueError("external_id_mismatch")
    if str(remote.get("transType") or "").lower() != "collection":
        raise ValueError("transaction_type_mismatch")
    try:
        amount = Decimal(str(remote.get("amount")))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("invalid_provider_amount") from exc
    if not amount.is_finite() or amount != Decimal(str(txn.amount)):
        raise ValueError("amount_mismatch")
    snapshot = txn.purchase_snapshot or {}
    if snapshot and amount != Decimal(snapshot["provider_amount"]):
        raise ValueError("purchase_amount_mismatch")
    if remote.get("userId") is not None and remote["userId"] != f"customer-{txn.customer_id}":
        raise ValueError("provider_customer_mismatch")


async def _review_reason(db, txn, customer, plan):
    snap = txn.purchase_snapshot
    if not snap or snap.get("version") != 1:
        return "legacy_purchase_snapshot_missing"
    if (not customer or customer.user_id != txn.reseller_id
            or snap["customer_id"] != customer.id
            or snap["reseller_id"] != customer.user_id):
        return "customer_owner_changed"
    if _target_baseline(customer) != snap["baseline"]:
        return "customer_entitlement_or_target_changed"
    if await _latest_payment_id(db, customer.id) != snap["latest_payment_id"]:
        return "later_payment_or_voucher"
    if not plan or plan.user_id != txn.reseller_id or plan_contract(plan) != snap["plan"]:
        return "purchased_plan_changed"
    return None


async def apply_remote_status(db, transaction_id, remote, *, token=None, provider_trans_id=None):
    txn = await db.scalar(select(FapshiTransaction).where(
        FapshiTransaction.id == transaction_id,
    ).with_for_update().execution_options(populate_existing=True))
    if not txn or txn.status in FINAL_STATUSES:
        return txn
    if token is not None and txn.check_lease_token != token:
        return txn
    validate_remote_transaction(txn, remote, provider_trans_id=provider_trans_id)
    status = str(remote.get("status") or "").upper()
    mapping = {item.value.upper(): item for item in FapshiTransactionStatus}
    if status not in mapping:
        raise ValueError("unknown_provider_status")
    txn.trans_id = txn.trans_id or remote["transId"]
    txn.provider_status = status
    txn.updated_at = datetime.utcnow()
    txn.last_check_error = None
    if status == "SUCCESSFUL":
        customer = await db.scalar(select(Customer).where(
            Customer.id == txn.customer_id,
        ).with_for_update().execution_options(populate_existing=True))
        snap = txn.purchase_snapshot or {}
        plan = await db.scalar(select(Plan).where(Plan.id == snap.get("plan", {}).get("id")))
        reason = await _review_reason(db, txn, customer, plan)
        if reason:
            txn.review_reason = reason
            await db.commit()
            return txn
        customer.plan_id = plan.id
        customer.plan = plan
        customer.pending_update_data = None
        await db.flush()
        from app.services.reseller_payments import record_customer_payment
        from app.services.hotspot_provisioning import (
            get_or_create_provisioning_attempt, schedule_provisioning_attempt,
        )
        contract = snap["plan"]
        value, unit = contract["duration_value"], contract["duration_unit"]
        days = max(1, value // (1440 if unit == "MINUTES" else 24)) if unit != "DAYS" else value
        financial_id = remote.get("financialTransId")
        reference = f"FAPSHI-{financial_id or txn.trans_id}"
        payment = await record_customer_payment(
            db, customer.id, txn.reseller_id, float(txn.amount),
            PaymentMethod.MOBILE_MONEY, days, payment_reference=reference,
            notes="Fapshi authoritative confirmation", duration_value=value,
            duration_unit=unit, collection_mode=CollectionMode.DIRECT,
            commit=False, defer_router_io=True,
        )
        attempt = await get_or_create_provisioning_attempt(
            db, customer_id=customer.id, router_id=customer.router_id,
            mac_address=customer.mac_address,
            source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
            source_pk=payment.id, external_reference=txn.trans_id,
            entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
        )
        await schedule_provisioning_attempt(db, attempt)
        txn.customer_payment_id = payment.id
        txn.applied_expiry = customer.expiry
        # Expected post-credit target includes detaching a prior shared device.
        snap = dict(snap, delivery_baseline=_target_baseline(customer))
        txn.purchase_snapshot = snap
        txn.financial_transaction_id = financial_id
        txn.medium = remote.get("medium")
        txn.fulfillment_pending = True
        txn.status = FapshiTransactionStatus.SUCCESSFUL
        from app.api.fapshi_routes import _parse_provider_datetime
        txn.confirmed_at = _parse_provider_datetime(remote.get("dateConfirmed")) or datetime.utcnow()
    else:
        # A failed attempt is not authority to revoke another paid entitlement.
        txn.status = mapping[status]
    await db.commit()
    return txn


async def _claim(transaction_id):
    now = datetime.utcnow()
    token = uuid.uuid4().hex
    async with database.async_session() as db:
        result = await db.execute(update(FapshiTransaction).where(
            FapshiTransaction.id == transaction_id,
            FapshiTransaction.review_reason.is_(None),
            or_(FapshiTransaction.status.notin_(list(FINAL_STATUSES)),
                FapshiTransaction.fulfillment_pending.is_(True)),
            or_(FapshiTransaction.next_check_at.is_(None), FapshiTransaction.next_check_at <= now),
            or_(FapshiTransaction.check_lease_until.is_(None), FapshiTransaction.check_lease_until <= now),
        ).values(check_lease_token=token, check_lease_until=now + LEASE_TIME,
                 next_check_at=now + QUERY_INTERVAL,
                 check_attempts=FapshiTransaction.check_attempts + 1))
        await db.commit()
        return token if result.rowcount == 1 else None


async def _finish(transaction_id, token, *, error=None):
    async with database.async_session() as db:
        txn = await db.scalar(select(FapshiTransaction).where(
            FapshiTransaction.id == transaction_id,
            FapshiTransaction.check_lease_token == token,
        ).with_for_update())
        if txn:
            txn.check_lease_until = None
            txn.check_lease_token = None
            if error:
                # Persist bounded diagnostic codes, never provider body/credentials.
                txn.last_check_error = error
            if error or txn.status not in FINAL_STATUSES or txn.fulfillment_pending:
                # Pending confirmations also back off: bounded requests over days,
                # not an exhausted budget after a few minutes with no browser.
                delay = min(900, 15 * 2 ** min(max(txn.check_attempts - 1, 0), 6))
                txn.next_check_at = datetime.utcnow() + timedelta(seconds=delay)
            await db.commit()


async def _delivery_is_current(db, txn, customer):
    snap = txn.purchase_snapshot or {}
    return bool(customer and snap.get("delivery_baseline")
        and _target_baseline(customer) == snap["delivery_baseline"]
        and customer.user_id == txn.reseller_id
        and customer.plan and plan_contract(customer.plan) == snap["plan"]
        and customer.expiry == txn.applied_expiry
        and customer.expiry > datetime.utcnow()
        and await _latest_payment_id(db, customer.id) == txn.customer_payment_id)


async def deliver_confirmed_payment(transaction_id, *, token=None):
    """Existing durable attempt plus Fapshi pending flag survive process exit."""
    async with database.async_session() as db:
        txn = await db.get(FapshiTransaction, transaction_id)
        if (not txn or not txn.fulfillment_pending or not txn.customer_payment_id
                or (token is not None and txn.check_lease_token != token)):
            return
        customer = await db.scalar(select(Customer).options(
            selectinload(Customer.plan), selectinload(Customer.router),
        ).where(Customer.id == txn.customer_id))
        if not await _delivery_is_current(db, txn, customer):
            txn.review_reason = "entitlement_changed_before_delivery"
            await db.commit()
            return
        attempt = await db.scalar(select(ProvisioningAttempt).where(
            ProvisioningAttempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT,
            ProvisioningAttempt.source_pk == txn.customer_payment_id,
        ))
        if not customer.router or not attempt:
            raise RuntimeError("delivery_target_missing")
        previous = await db.get(CustomerUsagePeriod, txn.purchase_snapshot.get("previous_usage_period_id")) if txn.purchase_snapshot.get("previous_usage_period_id") else None
        if previous and previous.fup_triggered_at and not previous.fup_reverted_at:
            from app.services.fup import restore_normal_profile
            # This helper releases its own DB transaction before router I/O;
            # no ledger/customer/provider row locks remain here.
            restored = await restore_normal_profile(db, customer, customer.plan)
            if restored.get("error"):
                raise RuntimeError("fup_restore_pending")
            previous.fup_reverted_at = datetime.utcnow()
        plan, router = customer.plan, customer.router
        args = dict(customer_id=customer.id, router_id=router.id, attempt_id=attempt.id)
        if router.auth_method == RouterAuthMethod.RADIUS and customer.mac_address:
            from app.services.radius_provisioning import RadiusProvisioning
            # RADIUS is DB-backed; no provider/RouterOS I/O in this branch.
            result = await RadiusProvisioning(db).provision_hotspot_user(
                customer_id=customer.id, mac_address=customer.mac_address,
                phone=customer.phone, plan_speed=plan.speed,
                plan_duration_value=plan.duration_value,
                plan_duration_unit=plan.duration_unit.value,
                router_id=router.id, fixed_expiry=customer.expiry,
            )
            if not result.get("success"):
                raise RuntimeError("radius_delivery_pending")
            customer.pending_update_data = json.dumps({
                "auth_method": "RADIUS", "radius_username": result["username"],
                "radius_password": result["password"],
            })
            attempt.provisioning_state = ProvisioningState.ROUTER_UPDATED
            txn.fulfillment_pending = False
            await db.commit()
            return
        if plan.connection_type == ConnectionType.PPPOE:
            from app.services.pppoe_provisioning import build_pppoe_payload, provision_pppoe_customer
            payload = build_pppoe_payload(customer, router)
            deliver = provision_pppoe_customer
            args["pppoe_payload"] = payload
        elif plan.connection_type == ConnectionType.STATIC_IP:
            # Static provisioning has no durable customer_payment attempt contract
            # and re-loads a mutable target. Preserve the credited entitlement but
            # require explicit review rather than claim asynchronous delivery.
            txn.review_reason = "static_delivery_requires_review"
            await db.commit()
            return
        elif customer.mac_address:
            from app.services.hotspot_provisioning import build_hotspot_payload, provision_hotspot_customer
            args["hotspot_payload"] = build_hotspot_payload(customer, plan, router, comment="Fapshi confirmed payment")
            deliver = provision_hotspot_customer
        else:
            raise RuntimeError("delivery_identity_missing")
        await db.commit()
    result = await deliver(**args, action="fapshi_payment")
    if not result or not result.get("success"):
        raise RuntimeError("router_delivery_pending")
    async with database.async_session() as db:
        txn = await db.scalar(select(FapshiTransaction).where(
            FapshiTransaction.id == transaction_id).with_for_update())
        if token is not None and txn.check_lease_token != token:
            return
        customer = await db.scalar(select(Customer).options(selectinload(Customer.plan)).where(
            Customer.id == txn.customer_id).with_for_update(of=Customer))
        if await _delivery_is_current(db, txn, customer):
            txn.fulfillment_pending = False
        else:
            txn.review_reason = "entitlement_changed_during_delivery"
        await db.commit()


async def reconcile_transaction(transaction_id, *, provider_trans_id=None):
    token = await _claim(transaction_id)
    if not token:
        return
    error = None
    try:
        async with database.async_session() as db:
            txn = await db.get(FapshiTransaction, transaction_id)
            if (datetime.utcnow() - txn.created_at > MAX_AGE or txn.check_attempts > MAX_ATTEMPTS):
                txn.review_reason = ("delivery_window_exhausted" if txn.customer_payment_id
                                     else "reconciliation_window_exhausted")
                await db.commit()
                return
            if txn.customer_payment_id:
                needs_query = False
            else:
                needs_query = True
                pm = await db.get(ResellerPaymentMethod, txn.payment_method_id)
                if (not pm or pm.user_id != txn.reseller_id
                        or not pm.fapshi_api_user or not pm.fapshi_api_key_encrypted):
                    raise RuntimeError("credentials_unavailable")
                from app.services.payment_gateway import decrypt_credential
                credentials = dict(api_user=pm.fapshi_api_user,
                    api_key=decrypt_credential(pm.fapshi_api_key_encrypted),
                    environment=txn.environment, trans_id=txn.trans_id or provider_trans_id)
                if not credentials["trans_id"]:
                    txn.review_reason = "initiation_outcome_unknown"
                    await db.commit()
                    return
            await db.commit()
        if needs_query:
            from app.services.fapshi import get_payment_status
            remote = await get_payment_status(**credentials)
            async with database.async_session() as db:
                await apply_remote_status(db, transaction_id, remote, token=token,
                                          provider_trans_id=provider_trans_id)
        await deliver_confirmed_payment(transaction_id, token=token)
    except Exception as exc:
        error = (str(exc) if isinstance(exc, (ValueError, RuntimeError))
                 and str(exc) in {"credentials_unavailable", "delivery_target_missing",
                    "delivery_identity_missing", "fup_restore_pending", "radius_delivery_pending",
                    "router_delivery_pending", "transaction_id_mismatch", "external_id_mismatch",
                    "transaction_type_mismatch", "invalid_provider_amount", "amount_mismatch",
                    "purchase_amount_mismatch", "provider_customer_mismatch", "unknown_provider_status",
                    "invalid_provider_response"} else "provider_or_reconciliation_error")
        logger.warning("Fapshi reconciliation deferred for local transaction %s (%s)", transaction_id, error)
    finally:
        await _finish(transaction_id, token, error=error)


async def recheck_pending_fapshi_background():
    """Small persisted due queue; no DB transaction across external calls."""
    now = datetime.utcnow()
    async with database.async_session() as db:
        ids = (await db.scalars(select(FapshiTransaction.id).where(
            FapshiTransaction.review_reason.is_(None),
            or_(FapshiTransaction.status.in_([FapshiTransactionStatus.CREATED,
                                             FapshiTransactionStatus.PENDING]),
                FapshiTransaction.fulfillment_pending.is_(True)),
            or_(FapshiTransaction.next_check_at.is_(None), FapshiTransaction.next_check_at <= now),
            or_(FapshiTransaction.check_lease_until.is_(None), FapshiTransaction.check_lease_until <= now),
        ).order_by(FapshiTransaction.next_check_at.asc().nullsfirst(), FapshiTransaction.id)
          .limit(BATCH_SIZE))).all()
        await db.commit()
    started = time.monotonic()
    for transaction_id in ids:
        if time.monotonic() - started >= 45:
            break  # remaining persisted rows stay due for the next tick
        await reconcile_transaction(transaction_id)

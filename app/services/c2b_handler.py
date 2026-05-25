"""
M-Pesa C2B Paybill handler.

Receives Safaricom Confirmation + Validation webhook payloads, resolves the
receiving paybill to a reseller scope, looks the customer up by their
account_number, applies the amount (with wallet credit), and queues PPPoE
provisioning. Mirrors the existing STK callback chain in
app/api/payment_routes.py:399-411 — uses the same record_customer_payment
+ build_pppoe_payload + call_pppoe_provision contract so the same
provisioning code paths apply.

Scope this iteration: PPPoE only. Hotspot C2B is deferred (the captive
portal STK flow already handles hotspot).

Idempotency: trans_id is the unique anchor — Safaricom retries confirmation
on network errors and we must never double-credit a customer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.config import settings
from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    ConnectionType,
    Customer,
    PaymentMethod,
    ResellerPaymentMethod,
    UnmatchedC2BPayment,
    UnmatchedC2BReason,
    User,
)
from app.services.account_numbers import is_valid_account_number
from app.services.pppoe_provisioning import (
    build_pppoe_payload,
    call_pppoe_provision,
)
from app.services.reseller_payments import record_customer_payment


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Safaricom response shapes (per Daraja docs)
# ---------------------------------------------------------------------------

ACCEPT_RESPONSE = {"ResultCode": "0", "ResultDesc": "Accepted"}
SUCCESS_RESPONSE = {"ResultCode": "0", "ResultDesc": "Success"}

# https://developer.safaricom.co.ke/c2b — Validation URL rejection codes
REJECT_INVALID_ACCOUNT = {"ResultCode": "C2B00012", "ResultDesc": "Invalid Account Number"}
REJECT_INVALID_AMOUNT = {"ResultCode": "C2B00013", "ResultDesc": "Invalid Amount"}


# ---------------------------------------------------------------------------
# Payload parsing
# ---------------------------------------------------------------------------


class C2BPayloadFields:
    """Strongly-typed view of a parsed Safaricom payload."""
    def __init__(
        self,
        trans_id: str,
        bill_ref_number: str,
        trans_amount: float,
        msisdn: Optional[str],
        business_shortcode: Optional[str],
    ):
        self.trans_id = trans_id
        self.bill_ref_number = bill_ref_number
        self.trans_amount = trans_amount
        self.msisdn = msisdn
        self.business_shortcode = business_shortcode


def parse_c2b_payload(payload: dict) -> Optional[C2BPayloadFields]:
    """Pull the fields we care about. Returns None if essentials missing.

    Safaricom payload field names are PascalCase. Amount arrives as a string
    in production; convert defensively.
    """
    try:
        trans_id = str(payload.get("TransID") or "").strip()
        if not trans_id:
            return None
        bill_ref = str(payload.get("BillRefNumber") or "").strip()
        raw_amount = payload.get("TransAmount")
        if raw_amount is None or raw_amount == "":
            return None
        amount = float(raw_amount)
        msisdn = payload.get("MSISDN")
        if msisdn is not None:
            msisdn = str(msisdn)
        shortcode = payload.get("BusinessShortCode")
        if shortcode is not None:
            shortcode = str(shortcode)
        return C2BPayloadFields(trans_id, bill_ref, amount, msisdn, shortcode)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Paybill resolution
# ---------------------------------------------------------------------------


async def _resolve_reseller_from_shortcode(
    db: AsyncSession, shortcode: Optional[str]
) -> Tuple[Optional[int], bool]:
    """Return (reseller_id, is_platform_paybill).

    - If shortcode matches settings.MPESA_SHORTCODE -> platform; reseller is
      determined later from the customer lookup. Returns (None, True).
    - Else look up a ResellerPaymentMethod with that shortcode; if found,
      returns (pm.user_id, False).
    - Else returns (None, False) — caller should mark REJECTED.
    """
    if not shortcode:
        return (None, False)

    if shortcode == settings.MPESA_SHORTCODE:
        return (None, True)

    stmt = select(ResellerPaymentMethod).where(
        ResellerPaymentMethod.mpesa_shortcode == shortcode,
        ResellerPaymentMethod.is_active.is_(True),
    )
    pm = (await db.execute(stmt)).scalar_one_or_none()
    if pm:
        return (pm.user_id, False)
    return (None, False)


# ---------------------------------------------------------------------------
# Customer lookup
# ---------------------------------------------------------------------------


async def _lookup_customer(
    db: AsyncSession,
    bill_ref_number: str,
    *,
    restrict_to_reseller_id: Optional[int],
) -> Optional[Customer]:
    """Find a customer by account_number, optionally scoped to a reseller.

    Loads plan + router eagerly because the caller will need them for
    provisioning and amount math.
    """
    stmt = (
        select(Customer)
        .options(joinedload(Customer.plan), joinedload(Customer.router))
        .where(Customer.account_number == bill_ref_number)
    )
    if restrict_to_reseller_id is not None:
        stmt = stmt.where(Customer.user_id == restrict_to_reseller_id)
    return (await db.execute(stmt)).scalar_one_or_none()


# ---------------------------------------------------------------------------
# Confirmation handler
# ---------------------------------------------------------------------------


async def handle_confirmation(
    payload: dict,
    db: AsyncSession,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """Process a Safaricom C2B confirmation. Always returns Safaricom's
    expected SUCCESS_RESPONSE shape — Safaricom requires 200 to mark the
    payment as posted; we never tell them to retry from this handler."""
    fields = parse_c2b_payload(payload)
    if fields is None:
        logger.warning("[C2B] Malformed confirmation payload, ignoring: %r", payload)
        return SUCCESS_RESPONSE

    # 1. Idempotency
    existing = (
        await db.execute(
            select(C2BTransaction).where(C2BTransaction.trans_id == fields.trans_id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        logger.info(
            "[C2B] Duplicate confirmation for trans_id=%s (was status=%s) — no-op",
            fields.trans_id, existing.status,
        )
        return SUCCESS_RESPONSE

    # 2. Resolve paybill -> reseller scope
    resolved_reseller_id, is_platform = await _resolve_reseller_from_shortcode(
        db, fields.business_shortcode
    )

    if not is_platform and resolved_reseller_id is None:
        # Unknown receiving paybill — Safaricom sent us a confirmation for a
        # shortcode we don't own. Archive + return 200; nothing to provision.
        await _archive(
            db, fields,
            status=C2BTransactionStatus.REJECTED,
            matched_customer=None,
            matched_reseller_id=None,
        )
        await db.commit()
        logger.warning(
            "[C2B] Rejected: unknown BusinessShortCode=%r, trans_id=%s",
            fields.business_shortcode, fields.trans_id,
        )
        return SUCCESS_RESPONSE

    # 3. Validate Luhn before DB lookup
    if not is_valid_account_number(fields.bill_ref_number):
        txn = await _archive(
            db, fields,
            status=C2BTransactionStatus.UNMATCHED,
            matched_customer=None,
            matched_reseller_id=resolved_reseller_id,
        )
        await _bucket_unmatched(
            db, txn,
            reason=UnmatchedC2BReason.INVALID_LUHN,
            assigned_reseller_id=resolved_reseller_id,
        )
        await db.commit()
        logger.info(
            "[C2B] Invalid Luhn for BillRefNumber=%r (trans_id=%s)",
            fields.bill_ref_number, fields.trans_id,
        )
        return SUCCESS_RESPONSE

    # 4. Customer lookup
    customer = await _lookup_customer(
        db, fields.bill_ref_number,
        restrict_to_reseller_id=resolved_reseller_id if not is_platform else None,
    )

    if customer is None:
        # Couldn't match. Was the account number valid but belongs to another
        # reseller? Or unknown entirely?
        unscoped = await _lookup_customer(db, fields.bill_ref_number, restrict_to_reseller_id=None)
        reason = (
            UnmatchedC2BReason.WRONG_RESELLER
            if (unscoped is not None and resolved_reseller_id is not None)
            else UnmatchedC2BReason.UNKNOWN_ACCOUNT
        )
        txn = await _archive(
            db, fields,
            status=C2BTransactionStatus.UNMATCHED,
            matched_customer=None,
            matched_reseller_id=resolved_reseller_id,
        )
        await _bucket_unmatched(
            db, txn,
            reason=reason,
            assigned_reseller_id=resolved_reseller_id,
        )
        await db.commit()
        logger.info(
            "[C2B] Unmatched (%s) for account=%s, trans_id=%s",
            reason.value, fields.bill_ref_number, fields.trans_id,
        )
        return SUCCESS_RESPONSE

    # 5. Amount logic — wallet credit applies first, overage is replaced
    plan_price = float(customer.plan.price) if customer.plan else 0.0
    effective_amount = fields.trans_amount + float(customer.wallet_credit_kes or 0)

    if plan_price > 0 and effective_amount < plan_price:
        # Not enough even with wallet. Don't activate; bucket for human triage.
        txn = await _archive(
            db, fields,
            status=C2BTransactionStatus.UNMATCHED,
            matched_customer=customer,
            matched_reseller_id=customer.user_id,
        )
        await _bucket_unmatched(
            db, txn,
            reason=UnmatchedC2BReason.AMOUNT_TOO_LOW,
            assigned_reseller_id=customer.user_id,
        )
        await db.commit()
        logger.info(
            "[C2B] Amount too low: paid %.2f + wallet %.2f < plan %.2f (trans_id=%s)",
            fields.trans_amount, customer.wallet_credit_kes or 0, plan_price, fields.trans_id,
        )
        return SUCCESS_RESPONSE

    # 6. Activate: extend expiry, record payment, update wallet
    plan_duration_value = customer.plan.duration_value
    plan_duration_unit = customer.plan.duration_unit.value.upper()

    if plan_duration_unit == "MINUTES":
        days_paid_for = max(1, plan_duration_value // (24 * 60))
    elif plan_duration_unit == "HOURS":
        days_paid_for = max(1, plan_duration_value // 24)
    else:  # DAYS
        days_paid_for = plan_duration_value

    await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=customer.user_id,
        amount=fields.trans_amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=days_paid_for,
        payment_reference=fields.trans_id,
        notes=f"M-Pesa C2B Paybill (shortcode {fields.business_shortcode})",
        duration_value=plan_duration_value,
        duration_unit=plan_duration_unit,
    )

    # Wallet replacement: effective_amount was made up of (paid + old_wallet).
    # We applied plan_price to grant the period; the remainder is the new wallet.
    new_wallet = int(round(effective_amount - plan_price)) if plan_price > 0 else 0
    customer.wallet_credit_kes = max(0, new_wallet)

    await _archive(
        db, fields,
        status=C2BTransactionStatus.PROCESSED,
        matched_customer=customer,
        matched_reseller_id=customer.user_id,
    )
    await db.commit()

    logger.info(
        "[C2B] Processed: customer=%s, paid=%.2f, plan_price=%.2f, new_wallet=%d (trans_id=%s)",
        customer.id, fields.trans_amount, plan_price, customer.wallet_credit_kes, fields.trans_id,
    )

    # 7. Provision (PPPoE only)
    if (
        customer.plan
        and customer.plan.connection_type == ConnectionType.PPPOE
        and customer.pppoe_username
        and customer.router
    ):
        if background_tasks is not None:
            payload_dict = build_pppoe_payload(customer, customer.router)
            background_tasks.add_task(call_pppoe_provision, payload_dict)
            logger.info(
                "[C2B] Queued PPPoE provisioning for customer %s on router %s",
                customer.id, customer.router.ip_address,
            )
        else:
            logger.warning(
                "[C2B] No BackgroundTasks available; skipping provisioning queue for customer %s",
                customer.id,
            )
    else:
        # Hotspot or missing prerequisites — payment is recorded but we don't
        # auto-provision. Same behavior as the STK callback in payment_routes.
        logger.info(
            "[C2B] Skipping auto-provisioning for customer %s "
            "(connection_type=%s, pppoe_username=%s, router_id=%s)",
            customer.id,
            customer.plan.connection_type.value if customer.plan and customer.plan.connection_type else None,
            customer.pppoe_username,
            customer.router_id,
        )

    return SUCCESS_RESPONSE


# ---------------------------------------------------------------------------
# Validation handler
# ---------------------------------------------------------------------------


async def handle_validation(payload: dict, db: AsyncSession) -> dict:
    """Optional pre-payment check Safaricom can fire before debiting the customer.

    Returns ACCEPT_RESPONSE if BillRefNumber is a valid Luhn-checked account
    number that maps to an existing customer; otherwise REJECT_INVALID_ACCOUNT.
    Safaricom uses the reject ResultCode to tell the customer their account
    number is wrong before any money moves.
    """
    fields = parse_c2b_payload(payload)
    if fields is None or not fields.bill_ref_number:
        return REJECT_INVALID_ACCOUNT
    if not is_valid_account_number(fields.bill_ref_number):
        return REJECT_INVALID_ACCOUNT

    resolved_reseller_id, is_platform = await _resolve_reseller_from_shortcode(
        db, fields.business_shortcode
    )

    customer = await _lookup_customer(
        db, fields.bill_ref_number,
        restrict_to_reseller_id=resolved_reseller_id if not is_platform else None,
    )
    if customer is None:
        return REJECT_INVALID_ACCOUNT
    return ACCEPT_RESPONSE


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _archive(
    db: AsyncSession,
    fields: C2BPayloadFields,
    *,
    status: C2BTransactionStatus,
    matched_customer: Optional[Customer],
    matched_reseller_id: Optional[int],
) -> C2BTransaction:
    txn = C2BTransaction(
        trans_id=fields.trans_id,
        bill_ref_number=fields.bill_ref_number or None,
        trans_amount=fields.trans_amount,
        msisdn=fields.msisdn,
        business_shortcode=fields.business_shortcode,
        payload_json=None,  # raw stored at the route level for full audit
        status=status,
        matched_customer_id=matched_customer.id if matched_customer else None,
        matched_reseller_id=matched_reseller_id,
        received_at=datetime.utcnow(),
        processed_at=datetime.utcnow() if status != C2BTransactionStatus.UNMATCHED else None,
    )
    db.add(txn)
    await db.flush()  # need txn.id for UnmatchedC2BPayment FK
    return txn


async def _bucket_unmatched(
    db: AsyncSession,
    c2b_txn: C2BTransaction,
    *,
    reason: UnmatchedC2BReason,
    assigned_reseller_id: Optional[int],
) -> UnmatchedC2BPayment:
    row = UnmatchedC2BPayment(
        c2b_transaction_id=c2b_txn.id,
        reason=reason,
        assigned_reseller_id=assigned_reseller_id,
    )
    db.add(row)
    return row

"""
Central payment orchestrator.

Resolves which payment gateway to use for a given router and dispatches
payment initiation to the correct provider (M-Pesa direct, M-Pesa system,
ZenoPay, or legacy).
"""

import base64
import hashlib
import logging
import uuid
from datetime import datetime
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.models import (
    CollectionMode,
    Customer,
    MpesaTransaction,
    MpesaTransactionStatus,
    MtnMomoTransaction,
    MtnMomoTransactionStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    Router,
    User,
    ZenoPayTransaction,
    ZenoPayTransactionStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Credential encryption helpers
# ---------------------------------------------------------------------------

def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    return Fernet(_derive_fernet_key(settings.SECRET_KEY))


def encrypt_credential(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt_credential(token: str) -> str:
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        logger.error("Failed to decrypt credential – key may have changed")
        raise ValueError("Unable to decrypt stored credential")


def mask_credential(value: Optional[str], visible_chars: int = 4) -> Optional[str]:
    if not value:
        return None
    if len(value) <= visible_chars:
        return "*" * len(value)
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


# ---------------------------------------------------------------------------
# Payment method resolution
# ---------------------------------------------------------------------------

async def resolve_router_payment_method(
    db: AsyncSession,
    router_id: int,
) -> Optional[ResellerPaymentMethod]:
    """Return the active payment method assigned to a router, or None for legacy."""
    stmt = (
        select(Router)
        .options(selectinload(Router.assigned_payment_method))
        .where(Router.id == router_id)
    )
    result = await db.execute(stmt)
    router = result.scalar_one_or_none()
    if not router or not router.payment_method_id:
        return None
    pm = router.assigned_payment_method
    if pm and pm.is_active:
        return pm
    return None


async def get_reseller_payment_methods(
    db: AsyncSession,
    user_id: int,
    active_only: bool = True,
) -> list[ResellerPaymentMethod]:
    stmt = select(ResellerPaymentMethod).where(
        ResellerPaymentMethod.user_id == user_id
    )
    if active_only:
        stmt = stmt.where(ResellerPaymentMethod.is_active == True)
    stmt = stmt.order_by(ResellerPaymentMethod.created_at.desc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Unified payment initiation
# ---------------------------------------------------------------------------

async def initiate_customer_payment(
    db: AsyncSession,
    payment_method: ResellerPaymentMethod,
    customer: Customer,
    router: Router,
    phone: str,
    amount: float,
    reference: str,
    plan_name: str = "",
    account_reference: Optional[str] = None,
) -> dict:
    """
    Dispatch payment to the correct gateway based on the router's payment method.

    Returns a dict with at least:
      - gateway: str ("mpesa" | "zenopay")
      - collection_mode: CollectionMode
      - ... plus gateway-specific fields (checkout_request_id, order_id, etc.)
    """
    method_type = payment_method.method_type
    if isinstance(method_type, str):
        method_type = ResellerPaymentMethodType(method_type)

    if method_type == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS:
        return await _initiate_mpesa_with_reseller_keys(
            db, payment_method, customer, phone, amount, reference,
            account_reference=account_reference,
        )

    if method_type in (
        ResellerPaymentMethodType.MPESA_PAYBILL,
        ResellerPaymentMethodType.BANK_ACCOUNT,
    ):
        return await _initiate_mpesa_system_collected(
            db, payment_method, customer, phone, amount, reference,
            account_reference=account_reference,
        )

    if method_type == ResellerPaymentMethodType.ZENOPAY:
        return await _initiate_zenopay(
            db, payment_method, customer, phone, amount, reference, plan_name,
        )

    if method_type == ResellerPaymentMethodType.MTN_MOMO:
        return await _initiate_mtn_momo(
            db, payment_method, customer, phone, amount, reference, plan_name,
        )

    raise ValueError(f"Unsupported payment method type: {method_type}")


# ---------------------------------------------------------------------------
# M-Pesa with reseller's own API keys (direct collection)
# ---------------------------------------------------------------------------

async def _initiate_mpesa_with_reseller_keys(
    db: AsyncSession,
    pm: ResellerPaymentMethod,
    customer: Customer,
    phone: str,
    amount: float,
    reference: str,
    account_reference: Optional[str] = None,
) -> dict:
    from app.services.mpesa import initiate_stk_push_direct

    consumer_key = decrypt_credential(pm.mpesa_consumer_key_encrypted)
    consumer_secret = decrypt_credential(pm.mpesa_consumer_secret_encrypted)
    passkey = decrypt_credential(pm.mpesa_passkey_encrypted)
    shortcode = pm.mpesa_shortcode

    stk_response = await initiate_stk_push_direct(
        phone_number=phone,
        amount=amount,
        reference=reference,
        shortcode=shortcode,
        passkey=passkey,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        account_reference=account_reference,
    )

    mpesa_txn = MpesaTransaction(
        checkout_request_id=stk_response.checkout_request_id,
        merchant_request_id=stk_response.merchant_request_id,
        phone_number=phone,
        amount=float(amount),
        reference=reference,
        customer_id=customer.id,
        status=MpesaTransactionStatus.pending,
    )
    db.add(mpesa_txn)
    await db.flush()

    return {
        "gateway": "mpesa",
        "collection_mode": CollectionMode.DIRECT,
        "checkout_request_id": stk_response.checkout_request_id,
        "merchant_request_id": stk_response.merchant_request_id,
    }


# ---------------------------------------------------------------------------
# M-Pesa with system credentials (admin collects, pays reseller manually)
# ---------------------------------------------------------------------------

async def _initiate_mpesa_system_collected(
    db: AsyncSession,
    pm: ResellerPaymentMethod,
    customer: Customer,
    phone: str,
    amount: float,
    reference: str,
    account_reference: Optional[str] = None,
) -> dict:
    from app.services.mpesa import initiate_stk_push_direct

    stk_response = await initiate_stk_push_direct(
        phone_number=phone,
        amount=amount,
        reference=reference,
        account_reference=account_reference,
    )

    mpesa_txn = MpesaTransaction(
        checkout_request_id=stk_response.checkout_request_id,
        merchant_request_id=stk_response.merchant_request_id,
        phone_number=phone,
        amount=float(amount),
        reference=reference,
        customer_id=customer.id,
        status=MpesaTransactionStatus.pending,
    )
    db.add(mpesa_txn)
    await db.flush()

    return {
        "gateway": "mpesa",
        "collection_mode": CollectionMode.SYSTEM_COLLECTED,
        "checkout_request_id": stk_response.checkout_request_id,
        "merchant_request_id": stk_response.merchant_request_id,
    }


# ---------------------------------------------------------------------------
# ZenoPay (Tanzania)
# ---------------------------------------------------------------------------

async def _initiate_zenopay(
    db: AsyncSession,
    pm: ResellerPaymentMethod,
    customer: Customer,
    phone: str,
    amount: float,
    reference: str,
    plan_name: str = "",
) -> dict:
    from app.services.zenopay import initiate_zenopay_payment

    api_key = decrypt_credential(pm.zenopay_api_key_encrypted)
    order_id = str(uuid.uuid4())

    webhook_url = (
        f"{settings.MPESA_CALLBACK_URL.rsplit('/api/', 1)[0]}"
        f"/api/zenopay/webhook/{pm.user_id}"
    )

    reseller_result = await db.execute(
        select(User.email).where(User.id == pm.user_id)
    )
    reseller_email = reseller_result.scalar_one_or_none() or "noreply@example.com"

    result = await initiate_zenopay_payment(
        api_key=api_key,
        order_id=order_id,
        phone=phone,
        amount=amount,
        name=customer.name or f"Customer {customer.id}",
        email=reseller_email,
        webhook_url=webhook_url,
    )

    zeno_txn = ZenoPayTransaction(
        order_id=order_id,
        reseller_id=pm.user_id,
        customer_id=customer.id,
        amount=amount,
        buyer_phone=phone,
        buyer_name=customer.name,
        status=ZenoPayTransactionStatus.PENDING,
    )
    db.add(zeno_txn)
    await db.flush()

    return {
        "gateway": "zenopay",
        "collection_mode": CollectionMode.DIRECT,
        "order_id": order_id,
        "zenopay_result": result,
    }


# ---------------------------------------------------------------------------
# MTN Mobile Money (Collection / RequestToPay)
# ---------------------------------------------------------------------------

def _build_mtn_callback_url(reseller_id: int) -> Optional[str]:
    """
    Derive a public callback URL from the existing M-Pesa callback host.

    We reuse ``MPESA_CALLBACK_URL`` (e.g. ``https://host/api/mpesa/callback``)
    as the base, same trick ZenoPay uses.  Returns ``None`` if the base URL
    is unset or not a full URL (MTN accepts no callback — polling still works).
    """
    base = settings.MPESA_CALLBACK_URL or ""
    if "/api/" not in base:
        return None
    host = base.rsplit("/api/", 1)[0]
    return f"{host}/api/mtn-momo/callback/{reseller_id}"


async def _initiate_mtn_momo(
    db: AsyncSession,
    pm: ResellerPaymentMethod,
    customer: Customer,
    phone: str,
    amount: float,
    reference: str,
    plan_name: str = "",
) -> dict:
    from app.services.mtn_momo import initiate_request_to_pay, normalize_msisdn

    missing = []
    if not pm.mtn_api_user:
        missing.append("mtn_api_user")
    if not pm.mtn_api_key_encrypted:
        missing.append("mtn_api_key")
    if not pm.mtn_subscription_key_encrypted:
        missing.append("mtn_subscription_key")
    if not pm.mtn_target_environment:
        missing.append("mtn_target_environment")
    if not pm.mtn_currency:
        missing.append("mtn_currency")
    if missing:
        raise ValueError(
            f"MTN MoMo payment method is missing required fields: {', '.join(missing)}"
        )

    api_key = decrypt_credential(pm.mtn_api_key_encrypted)
    subscription_key = decrypt_credential(pm.mtn_subscription_key_encrypted)
    base_url = pm.mtn_base_url or "https://sandbox.momodeveloper.mtn.com"

    reference_id = str(uuid.uuid4())
    external_id = reference  # keep human-readable ref for reconciliation
    normalized_phone = normalize_msisdn(phone)

    callback_url = _build_mtn_callback_url(pm.user_id)

    payer_message = (
        f"Payment for {plan_name}" if plan_name else f"Payment for {customer.name or 'service'}"
    )[:160]
    payee_note = f"Ref {reference}"[:160]

    # Persist the PENDING row first so a fast webhook cannot race us.
    txn = MtnMomoTransaction(
        reference_id=reference_id,
        external_id=external_id,
        reseller_id=pm.user_id,
        customer_id=customer.id,
        amount=amount,
        currency=pm.mtn_currency,
        phone=normalized_phone,
        status=MtnMomoTransactionStatus.PENDING,
        target_environment=pm.mtn_target_environment,
        payer_message=payer_message,
        payee_note=payee_note,
    )
    db.add(txn)
    await db.flush()

    try:
        await initiate_request_to_pay(
            reference_id=reference_id,
            amount=amount,
            currency=pm.mtn_currency,
            phone=normalized_phone,
            external_id=external_id,
            payer_message=payer_message,
            payee_note=payee_note,
            target_environment=pm.mtn_target_environment,
            base_url=base_url,
            api_user=pm.mtn_api_user,
            api_key=api_key,
            subscription_key=subscription_key,
            callback_url=callback_url,
        )
    except Exception:
        # Undo the provisional row so we don't leave orphaned PENDINGs on bad calls.
        await db.delete(txn)
        await db.flush()
        raise

    return {
        "gateway": "mtn_momo",
        "collection_mode": CollectionMode.DIRECT,
        "reference_id": reference_id,
        "callback_url": callback_url,
    }

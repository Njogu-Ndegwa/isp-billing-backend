"""
M-Pesa B2B (Business-to-Business) payout service.

Handles automated and manual payouts from the system paybill to resellers'
paybill numbers or bank accounts via the Safaricom B2B API.
"""

import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import AsyncSessionLocal
from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    ResellerFinancials,
    ResellerPayout,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    ResellerTransactionCharge,
    User,
    UserRole,
)

logger = logging.getLogger(__name__)

SAFARICOM_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=15.0, pool=5.0)

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"

# ---------------------------------------------------------------------------
# Business Bouquet Tariff – fee paid by sender (business), receiver pays 0
# Source: Safaricom M-Pesa Paybill Charges & Transaction Values
# ---------------------------------------------------------------------------
BUSINESS_BOUQUET_TARIFF = [
    (1,      49,     0),
    (50,     100,    0),
    (101,    500,    5),
    (501,    1_000,  10),
    (1_001,  1_500,  15),
    (1_501,  2_500,  20),
    (2_501,  3_500,  25),
    (3_501,  5_000,  34),
    (5_001,  7_500,  42),
    (7_501,  10_000, 48),
    (10_001, 15_000, 57),
    (15_001, 20_000, 62),
    (20_001, 25_000, 67),
    (25_001, 30_000, 72),
    (30_001, 35_000, 83),
    (35_001, 40_000, 99),
    (40_001, 45_000, 103),
    (45_001, 50_000, 108),
    (50_001, 70_000, 108),
    (70_001, 250_000, 108),
]

# Kadogo surcharge on sub-100 B2B amounts
KADOGO_TIERS = [
    (1,  49,  1),
    (50, 100, 2),
]


def get_b2b_fee(amount: float) -> int:
    """Return the Safaricom Business Bouquet fee for a given payout amount."""
    amt = int(amount)
    for low, high, fee in BUSINESS_BOUQUET_TARIFF:
        if low <= amt <= high:
            return fee
    if amt > 250_000:
        return 108
    return 0


def get_kadogo_surcharge(amount: float) -> int:
    """Return the Kadogo surcharge for sub-KES-100 amounts."""
    amt = int(amount)
    for low, high, surcharge in KADOGO_TIERS:
        if low <= amt <= high:
            return surcharge
    return 0


# ---------------------------------------------------------------------------
# Security Credential generation
# ---------------------------------------------------------------------------

def _load_certificate_pem() -> Optional[bytes]:
    """Load the appropriate Safaricom certificate based on environment."""
    cert_name = (
        "ProductionCertificate.cer"
        if settings.MPESA_ENVIRONMENT == "production"
        else "SandboxCertificate.cer"
    )
    cert_path = CERTS_DIR / cert_name
    if cert_path.exists():
        return cert_path.read_bytes()
    return None


def generate_security_credential() -> str:
    """
    Return the SecurityCredential for B2B API calls.

    Priority:
    1. Pre-encrypted credential from env (MPESA_B2B_SECURITY_CREDENTIAL)
    2. Runtime encryption of MPESA_B2B_INITIATOR_PASSWORD using Safaricom cert
    """
    if settings.MPESA_B2B_SECURITY_CREDENTIAL:
        return settings.MPESA_B2B_SECURITY_CREDENTIAL

    password = settings.MPESA_B2B_INITIATOR_PASSWORD
    if not password:
        raise ValueError(
            "Either MPESA_B2B_SECURITY_CREDENTIAL or MPESA_B2B_INITIATOR_PASSWORD must be set"
        )

    cert_data = _load_certificate_pem()
    if not cert_data:
        raise FileNotFoundError(
            f"Safaricom certificate not found in {CERTS_DIR}. "
            "Download from https://developer.safaricom.co.ke/APIs/GettingStarted "
            "or set MPESA_B2B_SECURITY_CREDENTIAL directly."
        )

    from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.backends import default_backend

    try:
        cert = load_der_x509_certificate(cert_data, default_backend())
    except Exception:
        cert = load_pem_x509_certificate(cert_data, default_backend())

    public_key = cert.public_key()
    encrypted = public_key.encrypt(password.encode(), PKCS1v15())
    return base64.b64encode(encrypted).decode()


# ---------------------------------------------------------------------------
# B2B API call
# ---------------------------------------------------------------------------

async def _get_access_token() -> str:
    """Get OAuth token using system M-Pesa credentials."""
    credentials = f"{settings.MPESA_CONSUMER_KEY}:{settings.MPESA_CONSUMER_SECRET}"
    encoded = base64.b64encode(credentials.encode()).decode()

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )

    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        response = await client.get(
            f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
            headers={"Authorization": f"Basic {encoded}"},
        )
        response.raise_for_status()
        return response.json()["access_token"]


async def initiate_b2b_payment(
    db: AsyncSession,
    reseller_id: int,
    amount: float,
    party_b: str,
    account_reference: str,
    remarks: str = "Reseller payout",
    fee: float = 0,
    triggered_by: str = "manual",
) -> B2BTransaction:
    """
    Initiate a B2B payment via Safaricom API and persist a pending transaction.

    Args:
        amount: The total balance being paid out (fee is calculated on this).
        party_b: Destination paybill/shortcode.
        account_reference: Account number at the destination.
        fee: The Safaricom fee that will be deducted (for record-keeping).
    """
    net_amount = int(amount - fee)
    if net_amount <= 0:
        raise ValueError(f"Net payout amount must be positive (amount={amount}, fee={fee})")

    access_token = await _get_access_token()
    security_credential = generate_security_credential()

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )

    party_a = settings.MPESA_SHORTCODE
    result_url = settings.MPESA_B2B_RESULT_URL or (
        f"{settings.MPESA_CALLBACK_URL.rsplit('/api/', 1)[0]}/api/mpesa/b2b/result"
    )
    timeout_url = settings.MPESA_B2B_TIMEOUT_URL or (
        f"{settings.MPESA_CALLBACK_URL.rsplit('/api/', 1)[0]}/api/mpesa/b2b/timeout"
    )

    payload = {
        "Initiator": settings.MPESA_B2B_INITIATOR_NAME,
        "SecurityCredential": security_credential,
        "CommandID": "BusinessPayBill",
        "SenderIdentifierType": "4",
        "RecieverIdentifierType": "4",
        "Amount": str(net_amount),
        "PartyA": party_a,
        "PartyB": party_b,
        "AccountReference": account_reference[:13],
        "Remarks": remarks[:100],
        "QueueTimeOutURL": timeout_url,
        "ResultURL": result_url,
    }

    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        response = await client.post(
            f"{base_url}/mpesa/b2b/v1/paymentrequest",
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )

    try:
        response_data = response.json()
    except Exception:
        logger.error(
            "B2B API returned non-JSON response (HTTP %s) for reseller %s: %s",
            response.status_code, reseller_id, response.text[:500],
        )
        raise RuntimeError(f"Safaricom B2B API error: HTTP {response.status_code}")

    logger.info("B2B API response for reseller %s: %s", reseller_id, response_data)

    conversation_id = response_data.get("ConversationID")
    originator_id = response_data.get("OriginatorConversationID")

    response_code = response_data.get("ResponseCode", "")
    if str(response_code) != "0":
        txn = B2BTransaction(
            reseller_id=reseller_id,
            conversation_id=conversation_id,
            originator_conversation_id=originator_id,
            amount=amount,
            fee=fee,
            net_amount=net_amount,
            party_a=party_a,
            party_b=party_b,
            account_reference=account_reference,
            remarks=remarks,
            status=B2BTransactionStatus.FAILED,
            result_code=str(response_code),
            result_desc=response_data.get("ResponseDescription", ""),
            triggered_by=triggered_by,
        )
        db.add(txn)
        await db.flush()
        return txn

    txn = B2BTransaction(
        reseller_id=reseller_id,
        conversation_id=conversation_id,
        originator_conversation_id=originator_id,
        amount=amount,
        fee=fee,
        net_amount=net_amount,
        party_a=party_a,
        party_b=party_b,
        account_reference=account_reference,
        remarks=remarks,
        status=B2BTransactionStatus.PENDING,
        triggered_by=triggered_by,
    )
    db.add(txn)
    await db.flush()
    return txn


# ---------------------------------------------------------------------------
# Callback processing
# ---------------------------------------------------------------------------

async def process_b2b_result(db: AsyncSession, result_body: dict) -> Optional[B2BTransaction]:
    """
    Process a B2B result callback from Safaricom.
    On success, auto-creates ResellerPayout + ResellerTransactionCharge.
    """
    result = result_body.get("Result", result_body)
    conversation_id = result.get("ConversationID")
    originator_id = result.get("OriginatorConversationID")
    result_code = result.get("ResultCode")
    result_desc = result.get("ResultDesc", "")
    transaction_id = result.get("TransactionID")

    stmt = select(B2BTransaction).where(
        B2BTransaction.conversation_id == conversation_id
    )
    row = await db.execute(stmt)
    txn = row.scalar_one_or_none()

    if not txn:
        if originator_id:
            stmt2 = select(B2BTransaction).where(
                B2BTransaction.originator_conversation_id == originator_id
            )
            row2 = await db.execute(stmt2)
            txn = row2.scalar_one_or_none()

    if not txn:
        logger.warning("B2B callback for unknown conversation_id=%s", conversation_id)
        return None

    if txn.status != B2BTransactionStatus.PENDING:
        logger.info("B2B transaction %s already in state %s, ignoring callback", txn.id, txn.status)
        return txn

    txn.result_code = str(result_code)
    txn.result_desc = result_desc
    txn.transaction_id = transaction_id

    if str(result_code) == "0":
        txn.status = B2BTransactionStatus.COMPLETED
        txn.completed_at = datetime.utcnow()

        payout = ResellerPayout(
            reseller_id=txn.reseller_id,
            amount=txn.net_amount,
            payment_method="mpesa_b2b",
            reference=transaction_id or conversation_id,
            notes=f"Auto B2B payout via {txn.party_b} (acc: {txn.account_reference})",
        )
        db.add(payout)
        await db.flush()
        txn.payout_id = payout.id

        if txn.fee > 0:
            admin_result = await db.execute(
                select(User.id).where(User.role == UserRole.ADMIN).limit(1)
            )
            admin_id = admin_result.scalar_one_or_none() or txn.reseller_id

            charge = ResellerTransactionCharge(
                reseller_id=txn.reseller_id,
                amount=txn.fee,
                description=f"M-Pesa B2B transfer fee (KES {int(txn.net_amount)} to {txn.party_b})",
                reference=transaction_id or conversation_id,
                created_by=admin_id,
            )
            db.add(charge)
            await db.flush()
            txn.charge_id = charge.id

        logger.info(
            "B2B payout completed: reseller=%s net=%s fee=%s ref=%s",
            txn.reseller_id, txn.net_amount, txn.fee, transaction_id,
        )
    else:
        txn.status = B2BTransactionStatus.FAILED
        logger.warning(
            "B2B payout failed: reseller=%s code=%s desc=%s",
            txn.reseller_id, result_code, result_desc,
        )

    await db.flush()
    return txn


async def process_b2b_timeout(db: AsyncSession, body: dict) -> Optional[B2BTransaction]:
    """Mark a B2B transaction as timed out for retry on next daily run."""
    result = body.get("Result", body)
    conversation_id = result.get("ConversationID")
    originator_id = result.get("OriginatorConversationID")

    stmt = select(B2BTransaction)
    if conversation_id:
        stmt = stmt.where(B2BTransaction.conversation_id == conversation_id)
    elif originator_id:
        stmt = stmt.where(B2BTransaction.originator_conversation_id == originator_id)
    else:
        return None

    row = await db.execute(stmt)
    txn = row.scalar_one_or_none()
    if not txn or txn.status != B2BTransactionStatus.PENDING:
        return txn

    txn.status = B2BTransactionStatus.TIMEOUT
    txn.result_desc = result.get("ResultDesc", "Queue timeout")
    await db.flush()
    logger.warning("B2B transaction %s timed out for reseller %s", txn.id, txn.reseller_id)
    return txn


# ---------------------------------------------------------------------------
# Balance calculation (mirrors admin_reseller_routes logic)
# ---------------------------------------------------------------------------

MPESA_FILTER = CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY


async def _mpesa_revenue(db: AsyncSession, reseller_id: int) -> float:
    stmt = select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
        CustomerPayment.reseller_id == reseller_id, MPESA_FILTER
    )
    return float((await db.execute(stmt)).scalar())


async def _total_payouts(db: AsyncSession, reseller_id: int) -> float:
    stmt = select(func.coalesce(func.sum(ResellerPayout.amount), 0)).where(
        ResellerPayout.reseller_id == reseller_id
    )
    return float((await db.execute(stmt)).scalar())


async def _total_charges(db: AsyncSession, reseller_id: int) -> float:
    stmt = select(func.coalesce(func.sum(ResellerTransactionCharge.amount), 0)).where(
        ResellerTransactionCharge.reseller_id == reseller_id
    )
    return float((await db.execute(stmt)).scalar())


async def _balance_correction(db: AsyncSession, reseller_id: int) -> float:
    """Return the stored one-time balance correction for this reseller (0 if none)."""
    stmt = select(ResellerFinancials.balance_correction).where(
        ResellerFinancials.user_id == reseller_id
    )
    val = (await db.execute(stmt)).scalar_one_or_none()
    return float(val or 0)


async def get_unpaid_balance(db: AsyncSession, reseller_id: int) -> float:
    mpesa_rev = await _mpesa_revenue(db, reseller_id)
    paid = await _total_payouts(db, reseller_id)
    charges = await _total_charges(db, reseller_id)
    correction = await _balance_correction(db, reseller_id)
    return round(mpesa_rev + correction - paid - charges, 2)


async def _monthly_b2b_count(db: AsyncSession, reseller_id: int) -> int:
    """Count B2B transactions this calendar month for Kadogo surcharge tracking."""
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    stmt = select(func.count(B2BTransaction.id)).where(
        B2BTransaction.reseller_id == reseller_id,
        B2BTransaction.created_at >= month_start,
    )
    return int((await db.execute(stmt)).scalar())


# ---------------------------------------------------------------------------
# Payment method resolution
# ---------------------------------------------------------------------------

B2B_ELIGIBLE_TYPES = [
    ResellerPaymentMethodType.BANK_ACCOUNT,
    ResellerPaymentMethodType.MPESA_PAYBILL,
]


async def resolve_b2b_payment_method(
    db: AsyncSession, reseller_id: int
) -> Optional[ResellerPaymentMethod]:
    """
    Find the best B2B-eligible payment method for a reseller.
    1. First active bank_account or mpesa_paybill method
    2. Fallback: if exactly one B2B-eligible method exists (even inactive), use it
    """
    active_stmt = (
        select(ResellerPaymentMethod)
        .where(
            ResellerPaymentMethod.user_id == reseller_id,
            ResellerPaymentMethod.is_active == True,
            ResellerPaymentMethod.method_type.in_(B2B_ELIGIBLE_TYPES),
        )
        .limit(1)
    )
    pm = (await db.execute(active_stmt)).scalar_one_or_none()
    if pm:
        return pm

    all_stmt = (
        select(ResellerPaymentMethod)
        .where(
            ResellerPaymentMethod.user_id == reseller_id,
            ResellerPaymentMethod.method_type.in_(B2B_ELIGIBLE_TYPES),
        )
    )
    all_methods = (await db.execute(all_stmt)).scalars().all()
    if len(all_methods) == 1:
        return all_methods[0]

    return None


# ---------------------------------------------------------------------------
# Single-reseller payout (used by both manual trigger and daily job)
# ---------------------------------------------------------------------------

async def payout_reseller(
    db: AsyncSession,
    reseller_id: int,
    payment_method: ResellerPaymentMethod,
    balance: Optional[float] = None,
    triggered_by: str = "manual",
) -> B2BTransaction:
    """
    Pay out a single reseller via B2B.
    Calculates fee, determines PartyB/AccountReference from their payment method.
    """
    if balance is None:
        balance = await get_unpaid_balance(db, reseller_id)

    if balance < 1:
        raise ValueError("Balance must be at least KES 1")

    method_type = payment_method.method_type
    if isinstance(method_type, str):
        method_type = ResellerPaymentMethodType(method_type)

    if method_type == ResellerPaymentMethodType.BANK_ACCOUNT:
        party_b = payment_method.bank_paybill_number
        account_ref = payment_method.bank_account_number or ""
    elif method_type == ResellerPaymentMethodType.MPESA_PAYBILL:
        party_b = payment_method.mpesa_paybill_number
        reseller = await db.get(User, reseller_id)
        account_ref = (reseller.organization_name or reseller.email)[:13] if reseller else ""
    else:
        raise ValueError(f"Payment method type {method_type} not eligible for B2B payout")

    if not party_b:
        raise ValueError("Payment method has no destination paybill number configured")

    # Safaricom charges based on the net amount sent; we need:
    #   net + safaricom_fee(net) == balance
    # At most tier boundaries a single correction finds the right fee.
    # At narrow "gap zones" (e.g. 101-105, 506-510) no exact solution
    # exists — we skip the payout and let the balance accumulate.
    fee = get_b2b_fee(balance)
    net = int(balance - fee)
    actual_fee = get_b2b_fee(net)
    if actual_fee != fee:
        fee = actual_fee
        net = int(balance - fee)
        if get_b2b_fee(net) != fee:
            fee = get_b2b_fee(balance)

    if balance <= 100:
        fee += get_kadogo_surcharge(balance - fee)

    txn = await initiate_b2b_payment(
        db=db,
        reseller_id=reseller_id,
        amount=balance,
        party_b=party_b,
        account_reference=account_ref,
        remarks=f"Payout to {payment_method.label}",
        fee=fee,
        triggered_by=triggered_by,
    )
    return txn


# ---------------------------------------------------------------------------
# Daily scheduled payout job
# ---------------------------------------------------------------------------

async def run_daily_payouts():
    """
    Scheduled job: pay out all eligible resellers via B2B.
    Only runs for system-collected resellers (MPESA_PAYBILL, BANK_ACCOUNT).
    """
    if not settings.MPESA_B2B_DAILY_PAYOUT_ENABLED:
        return

    if not settings.MPESA_B2B_INITIATOR_NAME:
        logger.warning("B2B daily payouts enabled but MPESA_B2B_INITIATOR_NAME not set, skipping")
        return

    logger.info("Starting daily B2B payout run")
    paid_count = 0
    skip_count = 0
    fail_count = 0

    async with AsyncSessionLocal() as db:
        resellers_stmt = select(User).where(User.role == UserRole.RESELLER)
        resellers = (await db.execute(resellers_stmt)).scalars().all()

        for reseller in resellers:
            try:
                balance = await get_unpaid_balance(db, reseller.id)
                if balance < 1:
                    skip_count += 1
                    continue

                today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                existing_today = await db.execute(
                    select(func.count(B2BTransaction.id)).where(
                        B2BTransaction.reseller_id == reseller.id,
                        B2BTransaction.created_at >= today_start,
                        B2BTransaction.triggered_by == "scheduled",
                        B2BTransaction.status.in_([
                            B2BTransactionStatus.PENDING,
                            B2BTransactionStatus.COMPLETED,
                        ]),
                    )
                )
                if existing_today.scalar() > 0:
                    logger.info("Reseller %s already has a scheduled B2B tx today, skipping", reseller.id)
                    skip_count += 1
                    continue

                pm = await resolve_b2b_payment_method(db, reseller.id)
                if not pm:
                    skip_count += 1
                    continue

                txn = await payout_reseller(db, reseller.id, pm, balance, triggered_by="scheduled")
                await db.commit()

                if txn.status == B2BTransactionStatus.PENDING:
                    paid_count += 1
                    logger.info(
                        "B2B payout initiated: reseller=%s amount=%s net=%s fee=%s -> %s",
                        reseller.id, txn.amount, txn.net_amount, txn.fee, txn.party_b,
                    )
                else:
                    fail_count += 1

            except Exception as e:
                fail_count += 1
                logger.error("B2B payout failed for reseller %s: %s", reseller.id, e)
                await db.rollback()

    logger.info(
        "Daily B2B payout run complete: initiated=%d skipped=%d failed=%d",
        paid_count, skip_count, fail_count,
    )

"""
M-Pesa B2B (Business-to-Business) payout service.

Handles automated and manual payouts from the system paybill to resellers'
paybill numbers or bank accounts via the Safaricom B2B API.
"""

import asyncio
import base64
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
from sqlalchemy import func, or_, select, text
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
SUBSCRIPTION_OWNER_TRIGGER = "subscription_owner"
# triggered_by value for self-service withdrawals from the Account Statement
# page (vs "manual" = admin-triggered, "scheduled" = nightly job).
RESELLER_TRIGGER = "reseller"


class PayoutInFlightError(Exception):
    """Another payout for this reseller is initiating or awaiting a verdict.

    Raised by initiate_b2b_payment's atomic guard. Callers must treat it as
    "do not send" — the other payout covers (or may cover) the balance."""


# In-process per-reseller payout guard. Lets initiators fail fast instead of
# queueing behind a Safaricom call. This is a UX layer only — the authoritative
# double-spend guard is the committed write-ahead intent row plus the advisory
# lock inside initiate_b2b_payment, which also holds across multiple workers.
_payout_locks: dict[int, asyncio.Lock] = {}


def payout_lock(reseller_id: int) -> asyncio.Lock:
    lock = _payout_locks.get(reseller_id)
    if lock is None:
        lock = _payout_locks[reseller_id] = asyncio.Lock()
    return lock


# Arbitrary but stable namespace for pg advisory locks guarding B2B initiation.
_PAYOUT_ADVISORY_CLASS = 0xB2B


async def _try_payout_advisory_lock(db: AsyncSession, reseller_id: int) -> bool:
    """Cross-process serialization of payout initiation.

    Takes a Postgres transaction-scoped advisory lock — held until the
    caller's current transaction commits or rolls back, so it exactly spans
    the unresolved-check + intent-insert and never a network call. On
    non-Postgres engines (tests) it is a no-op; the in-process lock still
    guards there."""
    bind = getattr(db, "bind", None)
    if bind is None or bind.dialect.name != "postgresql":
        return True
    result = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(:cls, :rid)"),
        {"cls": _PAYOUT_ADVISORY_CLASS, "rid": reseller_id},
    )
    return bool(result.scalar())

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"


def _provider_id_or_none(value: object) -> Optional[str]:
    """Normalize absent Safaricom identifiers so unique indexes can allow repeats."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None

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


def compute_fee_breakdown(balance: float) -> tuple[int, int, int]:
    """Return (total_fee, kadogo_surcharge, net) for paying out `balance`.

    Safaricom charges based on the net amount sent; we need
    ``net + safaricom_fee(net) == balance``. At most tier boundaries a single
    correction finds the right fee; at narrow "gap zones" (e.g. 101-105,
    506-510) no exact solution exists and we fall back to the fee for the
    gross balance.
    """
    fee = get_b2b_fee(balance)
    net = int(balance - fee)
    actual_fee = get_b2b_fee(net)
    if actual_fee != fee:
        fee = actual_fee
        net = int(balance - fee)
        if get_b2b_fee(net) != fee:
            fee = get_b2b_fee(balance)

    kadogo = 0
    if balance <= 100:
        kadogo = get_kadogo_surcharge(balance - fee)
        fee += kadogo

    return fee, kadogo, int(balance - fee)


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
    command_id: str = "BusinessPayBill",
) -> B2BTransaction:
    """
    Initiate a B2B payment via Safaricom API and persist the transaction.

    Double-spend safety — write-ahead intent:

    1. A PENDING intent row is committed BEFORE any network I/O, in the same
       short transaction as a per-reseller advisory lock and an
       unresolved-transaction re-check. From that commit on, every other
       payout path (nightly job, admin trigger, self-withdrawal — any worker,
       even after a restart) is blocked by has_unresolved_b2b().
    2. The Safaricom call then happens with no DB transaction open.
    3. The synchronous ack settles the intent: ResponseCode 0 records the
       conversation ids (row stays PENDING for the result callback); a
       rejection or a definitely-not-sent error marks it FAILED, releasing
       the balance. An AMBIGUOUS failure (request may have reached Safaricom
       but no ack parsed) leaves the intent PENDING with no conversation id:
       money may be moving, so the reseller stays blocked until the row is
       manually reconciled against the M-Pesa org statement. Uncertainty
       never releases money (2026-07-18 incident).

    Args:
        amount: The total balance being paid out (fee is calculated on this).
        party_b: Destination paybill/shortcode or till number.
        account_reference: Account number at the destination (paybill only).
        fee: The Safaricom fee that will be deducted (for record-keeping).
        command_id: "BusinessPayBill" (paybill/bank, receiver type 4) or
            "BusinessBuyGoods" (merchant till, receiver type 2 — tills have
            no accounts, so AccountReference is omitted from the payload).

    Raises PayoutInFlightError if another payout for this reseller is
    initiating or unresolved. Commits the caller's session.
    """
    net_amount = int(amount - fee)
    if net_amount <= 0:
        raise ValueError(f"Net payout amount must be positive (amount={amount}, fee={fee})")

    party_a = settings.MPESA_SHORTCODE

    # ── Phase 1: committed write-ahead intent, atomically guarded ──────────
    if not await _try_payout_advisory_lock(db, reseller_id):
        raise PayoutInFlightError(
            f"Another payout for reseller {reseller_id} is being initiated right now"
        )
    if await has_unresolved_b2b(db, reseller_id):
        raise PayoutInFlightError(
            f"Reseller {reseller_id} has an unresolved B2B transaction"
        )

    txn = B2BTransaction(
        reseller_id=reseller_id,
        conversation_id=None,
        originator_conversation_id=None,
        amount=amount,
        fee=fee,
        net_amount=net_amount,
        party_a=party_a,
        party_b=party_b,
        account_reference=account_reference,
        command_id=command_id,
        remarks=remarks,
        status=B2BTransactionStatus.PENDING,
        triggered_by=triggered_by,
    )
    db.add(txn)
    # Intent becomes visible to every other payout path; advisory lock released.
    await db.commit()

    # ── Phase 2: network I/O with no DB transaction open ───────────────────
    try:
        access_token = await _get_access_token()
        security_credential = generate_security_credential()
    except Exception as e:
        # Nothing was sent — safe to release the balance.
        await _settle_intent_failed(db, txn, f"failed before send: {e}")
        raise

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )
    result_url = settings.MPESA_B2B_RESULT_URL or (
        f"{settings.MPESA_CALLBACK_URL.rsplit('/api/', 1)[0]}/api/mpesa/b2b/result"
    )
    timeout_url = settings.MPESA_B2B_TIMEOUT_URL or (
        f"{settings.MPESA_CALLBACK_URL.rsplit('/api/', 1)[0]}/api/mpesa/b2b/timeout"
    )

    payload = {
        "Initiator": settings.MPESA_B2B_INITIATOR_NAME,
        "SecurityCredential": security_credential,
        "CommandID": command_id,
        "SenderIdentifierType": "4",
        # Receiver identifier type 2 = merchant till, 4 = org shortcode.
        # Sending type 4 to a till is exactly the SFC_IC0003 "Receiver party
        # is invalid" failure that till-number resellers hit nightly.
        "RecieverIdentifierType": "2" if command_id == "BusinessBuyGoods" else "4",
        "Amount": str(net_amount),
        "PartyA": party_a,
        "PartyB": party_b,
        "Remarks": remarks[:100],
        "QueueTimeOutURL": timeout_url,
        "ResultURL": result_url,
    }
    if command_id != "BusinessBuyGoods":
        # AccountReference can be a bank account number. Never truncate an
        # identifier here; a shortened value can point to a different account.
        # Tills have no accounts — Safaricom chokes on unexpected/empty
        # fields (cf. the empty-TransactionID all-empty-ack quirk), so the
        # key is omitted entirely for BusinessBuyGoods.
        payload["AccountReference"] = account_reference

    try:
        async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
            response = await client.post(
                f"{base_url}/mpesa/b2b/v1/paymentrequest",
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
        # The request never reached Safaricom — safe to release the balance.
        await _settle_intent_failed(db, txn, f"connect error, not sent: {e}")
        raise RuntimeError(f"Safaricom B2B unreachable: {e}")
    except Exception as e:
        # Sent (or possibly sent) but no ack — money MAY be moving. Keep the
        # intent PENDING: with no Safaricom ids the reconciliation job cannot
        # query it, so it blocks this reseller's payouts until manually
        # reconciled against the org portal statement. That is deliberate.
        await _annotate_intent(db, txn, f"no ack from Safaricom: {e}")
        logger.error(
            "B2B send for txn %s (reseller %s) got no ack — left PENDING for "
            "manual reconciliation: %s", txn.id, reseller_id, e,
        )
        raise RuntimeError(f"Safaricom B2B call failed after send: {e}")

    try:
        response_data = response.json()
    except Exception:
        # An HTTP response arrived but not the API's JSON (e.g. a gateway
        # error page). Whether the payment was queued is unknowable here —
        # same conservative treatment as a lost ack.
        await _annotate_intent(db, txn, f"non-JSON ack, HTTP {response.status_code}")
        logger.error(
            "B2B API returned non-JSON response (HTTP %s) for txn %s reseller %s — "
            "left PENDING for manual reconciliation: %s",
            response.status_code, txn.id, reseller_id, response.text[:500],
        )
        raise RuntimeError(f"Safaricom B2B API error: HTTP {response.status_code}")

    logger.info("B2B API response for reseller %s: %s", reseller_id, response_data)

    # ── Phase 3: settle the intent from the synchronous ack ────────────────
    txn.conversation_id = _provider_id_or_none(response_data.get("ConversationID"))
    txn.originator_conversation_id = _provider_id_or_none(
        response_data.get("OriginatorConversationID")
    )

    response_code = response_data.get("ResponseCode", "")
    if str(response_code) != "0":
        txn.status = B2BTransactionStatus.FAILED
        txn.result_code = str(response_code)
        txn.result_desc = response_data.get("ResponseDescription", "")

    await db.commit()
    return txn


async def _settle_intent_failed(db: AsyncSession, txn: B2BTransaction, desc: str) -> None:
    """Mark a write-ahead intent FAILED (money definitely never left).

    A failure here leaves the row PENDING — over-blocking, which is the safe
    direction — so it must never mask the original send error."""
    try:
        txn.status = B2BTransactionStatus.FAILED
        txn.result_desc = desc[:500]
        await db.commit()
    except Exception as e:
        logger.error("Could not settle failed B2B intent %s: %s", txn.id, e)


async def _annotate_intent(db: AsyncSession, txn: B2BTransaction, desc: str) -> None:
    """Record why an intent is stuck PENDING; the status itself stays PENDING."""
    try:
        txn.result_desc = desc[:500]
        await db.commit()
    except Exception as e:
        logger.error("Could not annotate B2B intent %s: %s", txn.id, e)


# ---------------------------------------------------------------------------
# Callback processing
# ---------------------------------------------------------------------------

async def _settle_completed_transaction(
    db: AsyncSession, txn: B2BTransaction, transaction_id: Optional[str]
) -> None:
    """Mark a transaction completed and create its payout + fee charge rows.

    Shared by the Safaricom result callback and the transaction-status
    reconciliation path — the ledger must end up identical whichever way we
    learn that the money moved.
    """
    txn.status = B2BTransactionStatus.COMPLETED
    txn.completed_at = datetime.utcnow()
    if transaction_id:
        txn.transaction_id = transaction_id

    if txn.triggered_by == SUBSCRIPTION_OWNER_TRIGGER:
        logger.info(
            "Subscription owner B2B transfer completed: owner=%s net=%s fee=%s ref=%s",
            txn.reseller_id, txn.net_amount, txn.fee, transaction_id,
        )
        await db.flush()
        return

    reference = transaction_id or txn.conversation_id or f"B2B-{txn.id}"
    payout = ResellerPayout(
        reseller_id=txn.reseller_id,
        amount=txn.net_amount,
        payment_method="mpesa_b2b",
        reference=reference,
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
            reference=reference,
            created_by=admin_id,
        )
        db.add(charge)
        await db.flush()
        txn.charge_id = charge.id

    logger.info(
        "B2B payout completed: reseller=%s net=%s fee=%s ref=%s",
        txn.reseller_id, txn.net_amount, txn.fee, transaction_id,
    )


async def process_b2b_result(db: AsyncSession, result_body: dict) -> Optional[B2BTransaction]:
    """
    Process a B2B result callback from Safaricom.
    On success, auto-creates ResellerPayout + ResellerTransactionCharge.
    """
    result = result_body.get("Result", result_body)
    conversation_id = _provider_id_or_none(result.get("ConversationID"))
    originator_id = _provider_id_or_none(result.get("OriginatorConversationID"))
    result_code = result.get("ResultCode")
    result_desc = result.get("ResultDesc", "")
    transaction_id = _provider_id_or_none(result.get("TransactionID"))

    txn = None
    if conversation_id:
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
        logger.warning(
            "B2B callback for unknown conversation_id=%s originator_id=%s",
            conversation_id, originator_id,
        )
        return None

    if txn.status != B2BTransactionStatus.PENDING:
        logger.info("B2B transaction %s already in state %s, ignoring callback", txn.id, txn.status)
        return txn

    txn.result_code = str(result_code)
    txn.result_desc = result_desc
    txn.transaction_id = transaction_id

    if str(result_code) == "0":
        await _settle_completed_transaction(db, txn, transaction_id)
    else:
        txn.status = B2BTransactionStatus.FAILED
        logger.warning(
            "B2B payout failed: reseller=%s code=%s desc=%s",
            txn.reseller_id, result_code, result_desc,
        )

    await db.flush()
    return txn


async def process_b2b_timeout(db: AsyncSession, body: dict) -> Optional[B2BTransaction]:
    """Mark a B2B transaction as timed out. A timeout is NOT a verdict — the
    money may still have moved — so the transaction stays unresolved (blocking
    further payouts to that reseller) until the status reconciliation job gets
    a definitive answer from Safaricom."""
    result = body.get("Result", body)
    conversation_id = _provider_id_or_none(result.get("ConversationID"))
    originator_id = _provider_id_or_none(result.get("OriginatorConversationID"))

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
# In-flight guard
# ---------------------------------------------------------------------------

# Statuses where money may have moved but we don't have Safaricom's verdict
# yet. A transaction in one of these states — of ANY age and ANY trigger —
# must block further payouts to that reseller: the 2026-07-18 incident was
# Safaricom losing result callbacks, leaving sent money invisible to the
# balance and every later payout a duplicate.
UNRESOLVED_STATUSES = [B2BTransactionStatus.PENDING, B2BTransactionStatus.TIMEOUT]


async def has_unresolved_b2b(db: AsyncSession, reseller_id: int) -> bool:
    """True if the reseller has a B2B transaction whose outcome is unknown."""
    stmt = select(func.count(B2BTransaction.id)).where(
        B2BTransaction.reseller_id == reseller_id,
        B2BTransaction.status.in_(UNRESOLVED_STATUSES),
    )
    return int((await db.execute(stmt)).scalar()) > 0


# ---------------------------------------------------------------------------
# Transaction-status reconciliation (never trust callback silence)
# ---------------------------------------------------------------------------

STATUS_QUERY_MIN_AGE = timedelta(minutes=5)
STATUS_QUERY_BATCH_LIMIT = 20

# Prefix written onto a stuck transaction once Safaricom's status index no
# longer knows it (stale 2033). Rows carrying it are excluded from further
# automatic queries — they can only be closed from the admin B2B view after
# checking the org/bank statement. Without this marker + exclusion, any-age
# blocking plus a bounded query window used to deadlock resellers forever
# (found live on rid 10, txns 710/711, 2026-07-19).
MANUAL_REVIEW_MARKER = "Needs manual statement review"

# Corroborating-evidence rule for stale zombies (Dennis, 2026-07-19): a stale
# 2033 alone is ambiguous, but if this many balance payouts to the SAME
# reseller have completed and reconciled SINCE the zombie was created, the
# ledger has been re-validated repeatedly with the zombie counted as unpaid —
# combined with the missing result callback and missing status record, treat
# it as never processed and auto-fail (reseller stays owed, payouts unblock).
# The residual risk is a bounded, weeks-old, one-time overpayment if the
# statement would have shown it after all — accepted over deadlocking active
# resellers on ancient uncertainty. Zombies WITHOUT that history still go to
# manual review: a reseller whose payouts stopped right at the zombie is
# exactly the case where it may have landed.
STALE_ZOMBIE_CORROBORATION_MIN = 2


async def _completed_payouts_since(db: AsyncSession, reseller_id: int, after: datetime) -> int:
    """Count completed balance payouts to this reseller created after `after`."""
    stmt = select(func.count(B2BTransaction.id)).where(
        B2BTransaction.reseller_id == reseller_id,
        B2BTransaction.status == B2BTransactionStatus.COMPLETED,
        B2BTransaction.triggered_by.in_(BALANCE_PAYOUT_TRIGGERS),
        B2BTransaction.created_at > after,
    )
    return int((await db.execute(stmt)).scalar())


def _stale_zombie_autofail_desc(later_count: int) -> str:
    return (
        f"Auto-failed stale unresolved payout: Safaricom has no record "
        f"(2033), the result callback never arrived, and {later_count} later "
        f"payouts to this reseller completed and reconciled since. Treated "
        f"as never processed; reseller stays owed."
    )[:500]

# Correlates a status query's ConversationID (from Safaricom's ack) to our
# B2B transaction id, because the async status result carries the QUERY's
# ids, not the original transaction's. In-memory on purpose: if the app
# restarts before the result arrives, the next reconciliation tick simply
# re-queries — the loop converges even when status results themselves get lost.
_status_query_map: dict[str, int] = {}
_STATUS_QUERY_MAP_MAX = 500


def _remember_status_query(conversation_id: Optional[str], txn_id: int) -> None:
    if not conversation_id:
        return
    if len(_status_query_map) >= _STATUS_QUERY_MAP_MAX:
        _status_query_map.pop(next(iter(_status_query_map)))
    _status_query_map[conversation_id] = txn_id


async def query_b2b_transaction_status(
    txn_id: int,
    originator_conversation_id: Optional[str],
    transaction_id: Optional[str],
) -> bool:
    """Ask Safaricom what happened to a B2B transaction (async result via
    callback). Returns True if the query was accepted. No DB access here —
    callers must not hold a session across this network call."""
    if not (transaction_id or originator_conversation_id):
        logger.warning(
            "B2B status query for txn %s impossible: no receipt or originator id", txn_id
        )
        return False

    access_token = await _get_access_token()
    security_credential = generate_security_credential()

    base_url = (
        "https://api.safaricom.co.ke"
        if settings.MPESA_ENVIRONMENT == "production"
        else "https://sandbox.safaricom.co.ke"
    )
    callback_base = settings.MPESA_CALLBACK_URL.rsplit("/api/", 1)[0]
    result_url = settings.MPESA_B2B_STATUS_RESULT_URL or (
        f"{callback_base}/api/mpesa/b2b/status-result"
    )
    timeout_url = settings.MPESA_B2B_STATUS_TIMEOUT_URL or (
        f"{callback_base}/api/mpesa/b2b/status-timeout"
    )

    payload = {
        "Initiator": settings.MPESA_B2B_INITIATOR_NAME,
        "SecurityCredential": security_credential,
        "CommandID": "TransactionStatusQuery",
        "PartyA": settings.MPESA_SHORTCODE,
        "IdentifierType": "4",
        "Remarks": f"Status check b2b txn {txn_id}",
        "Occasion": str(txn_id),
        "ResultURL": result_url,
        "QueueTimeOutURL": timeout_url,
    }
    # Query by M-Pesa receipt when we have one; otherwise by the original
    # transaction's OriginatorConversationID (the lost-callback case).
    # Send exactly one of the two: including TransactionID as an empty string
    # alongside the conversation id makes Safaricom return an all-empty ack
    # (observed live on txn 1029, 2026-07-18). And the status API names the
    # field "OriginalConversationID" — NOT "OriginatorConversationID" as the
    # payment ack does (their 400.002.02 error spells out the expected name).
    if transaction_id:
        payload["TransactionID"] = transaction_id
    else:
        payload["OriginalConversationID"] = originator_conversation_id

    async with httpx.AsyncClient(timeout=SAFARICOM_TIMEOUT) as client:
        response = await client.post(
            f"{base_url}/mpesa/transactionstatus/v1/query",
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
        )

    try:
        data = response.json()
    except Exception:
        logger.error(
            "B2B status query for txn %s: non-JSON response HTTP %s: %s",
            txn_id, response.status_code, response.text[:300],
        )
        return False

    if str(data.get("ResponseCode", "")) != "0":
        logger.warning("B2B status query for txn %s rejected: %s", txn_id, data)
        return False

    _remember_status_query(_provider_id_or_none(data.get("ConversationID")), txn_id)
    _remember_status_query(
        _provider_id_or_none(data.get("OriginatorConversationID")), txn_id
    )
    logger.info("B2B status query accepted for txn %s", txn_id)
    return True


def _result_parameters(result: dict) -> dict:
    """Flatten Safaricom's ResultParameters list into a {Key: Value} dict."""
    params = {}
    container = result.get("ResultParameters") or {}
    items = container.get("ResultParameter") or []
    if isinstance(items, dict):
        items = [items]
    for item in items:
        key = item.get("Key")
        if key is not None:
            params[str(key)] = item.get("Value")
    return params


async def process_b2b_status_result(db: AsyncSession, body: dict) -> Optional[B2BTransaction]:
    """Settle a pending/timeout B2B transaction from a status-query result.

    Safety posture: only a definitive Safaricom verdict changes state.
    "Completed" → settle exactly like the normal result callback;
    an explicit failed/cancelled status → mark failed (reseller stays owed);
    anything ambiguous → leave the transaction unresolved, which keeps the
    reseller blocked from further payouts. Uncertainty never releases money.
    """
    result = body.get("Result", body)
    query_conv_id = _provider_id_or_none(result.get("ConversationID"))
    query_orig_id = _provider_id_or_none(result.get("OriginatorConversationID"))

    txn_id = _status_query_map.get(query_conv_id or "") or _status_query_map.get(
        query_orig_id or ""
    )
    if txn_id is None:
        # Map lost (restart) or unknown query — the reconciliation tick will
        # re-query; nothing settles without correlation.
        logger.warning(
            "B2B status result with no matching query (conv=%s orig=%s), ignoring",
            query_conv_id, query_orig_id,
        )
        return None

    txn = await db.get(B2BTransaction, txn_id)
    if not txn:
        return None
    if txn.status not in UNRESOLVED_STATUSES:
        logger.info(
            "B2B status result for txn %s already in state %s, ignoring", txn.id, txn.status
        )
        return txn

    result_code = str(result.get("ResultCode", ""))
    result_desc = result.get("ResultDesc", "")
    if result_code != "0":
        # Code 2033 = "receipt cannot be found by the specified
        # OriginatorConversationID" (verified live on txn 1029, 2026-07-18):
        # Safaricom has no record of the transaction, i.e. the payment was
        # never processed and its failure callback was lost. Definitive for a
        # FRESH transaction — mark failed so the reseller stays owed and the
        # next run pays them. For old transactions 2033 could also mean the
        # id aged out of their status index, so those stay blocked for manual
        # statement review; wrongly failing a real payment re-creates the
        # exact double-pay this module exists to prevent.
        fresh = txn.created_at and txn.created_at >= datetime.utcnow() - timedelta(hours=48)
        if result_code == "2033" and fresh:
            txn.status = B2BTransactionStatus.FAILED
            txn.result_code = result_code
            txn.result_desc = (
                f"Status query: no record at Safaricom — payment never "
                f"processed ({result_desc})"
            )[:500]
            await db.flush()
            logger.warning(
                "B2B txn %s marked failed via status query (2033 not found): reseller=%s",
                txn.id, txn.reseller_id,
            )
            return txn

        if result_code == "2033":
            # Old transaction that Safaricom's status index no longer knows:
            # could be never-processed OR a real payment that aged out. Decide
            # by corroborating evidence (see STALE_ZOMBIE_CORROBORATION_MIN)
            # instead of blocking an actively-transacting reseller forever.
            later = await _completed_payouts_since(db, txn.reseller_id, txn.created_at)
            if later >= STALE_ZOMBIE_CORROBORATION_MIN:
                txn.status = B2BTransactionStatus.FAILED
                txn.result_code = result_code
                txn.result_desc = _stale_zombie_autofail_desc(later)
                await db.flush()
                logger.warning(
                    "B2B txn %s auto-failed (stale 2033 + %d later reconciled "
                    "payouts): reseller=%s unblocked",
                    txn.id, later, txn.reseller_id,
                )
                return txn

            txn.result_desc = (
                f"{MANUAL_REVIEW_MARKER}: Safaricom has no record (2033) but "
                f"the transaction is too old to auto-fail and this reseller "
                f"has no later reconciled payouts to corroborate it. Verify "
                f"it on the M-Pesa org/bank statement, then resolve it as "
                f"completed (with its receipt) or failed."
            )[:500]
            await db.flush()
            logger.error(
                "B2B txn %s (reseller %s) flagged for manual statement review "
                "(stale 2033, no corroborating payouts) — payouts stay blocked "
                "until resolved",
                txn.id, txn.reseller_id,
            )
            return txn

        # Any other query failure (bad credentials, API trouble). Do NOT guess
        # an outcome — log loudly and leave the txn unresolved/blocked for the
        # next tick or manual review.
        logger.error(
            "B2B status query for txn %s returned code=%s desc=%s — leaving unresolved",
            txn.id, result_code, result_desc,
        )
        return txn

    params = _result_parameters(result)
    status_text = str(
        params.get("TransactionStatus") or params.get("Transaction Status") or ""
    ).strip().lower()
    receipt = _provider_id_or_none(
        params.get("ReceiptNo") or params.get("Receipt No") or result.get("TransactionID")
    )

    if status_text == "completed":
        txn.result_code = "0"
        txn.result_desc = f"Reconciled via transaction status query: {result_desc}"[:500]
        await _settle_completed_transaction(db, txn, receipt)
        logger.warning(
            "B2B txn %s settled via status query (callback was lost): reseller=%s net=%s ref=%s",
            txn.id, txn.reseller_id, txn.net_amount, receipt,
        )
    elif status_text in ("failed", "cancelled", "declined", "expired"):
        txn.status = B2BTransactionStatus.FAILED
        txn.result_code = result_code
        txn.result_desc = (
            f"Reconciled via transaction status query: {status_text} — "
            f"{params.get('TransactionReason') or result_desc}"
        )[:500]
        logger.warning(
            "B2B txn %s marked failed via status query: reseller=%s reason=%s",
            txn.id, txn.reseller_id, txn.result_desc,
        )
    else:
        logger.error(
            "B2B status query for txn %s returned unrecognized TransactionStatus=%r "
            "— leaving unresolved", txn.id, status_text,
        )
        return txn

    await db.flush()
    return txn


async def run_b2b_status_reconciliation():
    """Scheduled job: query Safaricom for every B2B transaction stuck without
    a verdict, so a lost callback can never leave sent money unrecorded
    (2026-07-18 incident: 15 lost callbacks → KES 12,713 double-paid)."""
    if not settings.MPESA_B2B_INITIATOR_NAME:
        return

    from app.db.database import db_pool_snapshot

    level = (db_pool_snapshot().get("pressure") or {}).get("level")
    if level in ("warning", "critical"):
        logger.info("B2B status reconciliation skipped: DB pool pressure %s", level)
        return

    now = datetime.utcnow()

    # First, retro-apply the corroborating-evidence rule to rows already
    # flagged for manual review: their 2033 verdict is recorded, so no new
    # Safaricom call is needed — a reseller who has kept getting reconciled
    # payouts since the zombie was created gets unblocked here. DB-only work
    # in one short session.
    async with AsyncSessionLocal() as db:
        flagged = (await db.execute(
            select(B2BTransaction).where(
                B2BTransaction.status.in_(UNRESOLVED_STATUSES),
                B2BTransaction.result_desc.startswith(MANUAL_REVIEW_MARKER),
            )
        )).scalars().all()
        for txn in flagged:
            later = await _completed_payouts_since(db, txn.reseller_id, txn.created_at)
            if later >= STALE_ZOMBIE_CORROBORATION_MIN:
                txn.status = B2BTransactionStatus.FAILED
                txn.result_code = "2033"
                txn.result_desc = _stale_zombie_autofail_desc(later)
                logger.warning(
                    "B2B txn %s auto-failed from manual-review backlog "
                    "(stale 2033 + %d later reconciled payouts): reseller=%s unblocked",
                    txn.id, later, txn.reseller_id,
                )
        await db.commit()

    # Short session: read the stale list, release, THEN talk to Safaricom.
    async with AsyncSessionLocal() as db:
        stmt = (
            select(
                B2BTransaction.id,
                B2BTransaction.originator_conversation_id,
                B2BTransaction.transaction_id,
            )
            .where(
                B2BTransaction.status.in_(UNRESOLVED_STATUSES),
                B2BTransaction.created_at <= now - STATUS_QUERY_MIN_AGE,
                # ANY age: the in-flight guard blocks on any-age unresolved
                # txns, so the query window must reach just as far — a bounded
                # window deadlocked resellers with old zombies (rid 10,
                # 2026-07-19). Rows already flagged for manual statement
                # review are the one exception; re-querying them is pointless.
                or_(
                    B2BTransaction.result_desc.is_(None),
                    ~B2BTransaction.result_desc.startswith(MANUAL_REVIEW_MARKER),
                ),
            )
            .order_by(B2BTransaction.created_at)
            .limit(STATUS_QUERY_BATCH_LIMIT)
        )
        stale = list((await db.execute(stmt)).all())

    if not stale:
        return

    logger.warning("B2B status reconciliation: %d unresolved transaction(s)", len(stale))
    for txn_id, originator_id, receipt in stale:
        try:
            await query_b2b_transaction_status(txn_id, originator_id, receipt)
        except Exception as e:
            logger.error("B2B status query failed for txn %s: %s", txn_id, e)


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


# ---------------------------------------------------------------------------
# Payout schedule (per-reseller frequency)
# ---------------------------------------------------------------------------

PAYOUT_FREQUENCY_MANUAL = "manual"
PAYOUT_FREQUENCY_CUSTOM = "custom"
DEFAULT_PAYOUT_FREQUENCY = "daily"

# Minimum gap (hours) between automatic payouts, per frequency. Each window
# sits ~4h short of the nominal period for the same reason the daily window
# is 20h, not 24h: the job fires at 23:59 UTC and the previous cycle's
# transaction lands slightly AFTER the period boundary — a full-length window
# would count it and skip a legitimately-due reseller (2026-07-15 incident).
PAYOUT_FREQUENCY_WINDOWS_HOURS = {
    "daily": 20,
    "weekly": 7 * 24 - 4,
    "monthly": 30 * 24 - 4,
}

VALID_PAYOUT_FREQUENCIES = tuple(PAYOUT_FREQUENCY_WINDOWS_HOURS) + (
    PAYOUT_FREQUENCY_CUSTOM,
    PAYOUT_FREQUENCY_MANUAL,
)

MIN_CUSTOM_INTERVAL_DAYS = 1
MAX_CUSTOM_INTERVAL_DAYS = 90


def custom_window_hours(interval_days: int) -> int:
    """Dedupe window for a custom every-N-days schedule (never below daily's 20h)."""
    return max(20, interval_days * 24 - 4)


# Balance payouts count toward the weekly/monthly/custom gate no matter who
# fired them; subscription_owner B2B traffic is a different money flow entirely.
BALANCE_PAYOUT_TRIGGERS = ["scheduled", "manual", RESELLER_TRIGGER]


async def get_payout_schedule(db: AsyncSession, reseller_id: int) -> tuple[str, Optional[int]]:
    """Return (frequency, custom_interval_days). Falls back to ('daily', None)
    when unset or when a 'custom' row has no usable interval."""
    row = (await db.execute(
        select(
            ResellerFinancials.payout_frequency,
            ResellerFinancials.payout_interval_days,
        ).where(ResellerFinancials.user_id == reseller_id)
    )).first()
    freq = row.payout_frequency if row else None
    if freq not in VALID_PAYOUT_FREQUENCIES:
        return DEFAULT_PAYOUT_FREQUENCY, None
    if freq == PAYOUT_FREQUENCY_CUSTOM:
        interval = row.payout_interval_days
        if not interval or not (
            MIN_CUSTOM_INTERVAL_DAYS <= interval <= MAX_CUSTOM_INTERVAL_DAYS
        ):
            return DEFAULT_PAYOUT_FREQUENCY, None
        return freq, int(interval)
    return freq, None


async def get_payout_frequency(db: AsyncSession, reseller_id: int) -> str:
    """Return the reseller's configured payout frequency ('daily' if unset)."""
    frequency, _ = await get_payout_schedule(db, reseller_id)
    return frequency


async def set_payout_frequency(
    db: AsyncSession,
    reseller_id: int,
    frequency: str,
    interval_days: Optional[int] = None,
) -> None:
    """Upsert the reseller's payout schedule onto their financials row."""
    if frequency not in VALID_PAYOUT_FREQUENCIES:
        raise ValueError(f"Invalid payout frequency: {frequency}")
    if frequency == PAYOUT_FREQUENCY_CUSTOM:
        if not interval_days or not (
            MIN_CUSTOM_INTERVAL_DAYS <= int(interval_days) <= MAX_CUSTOM_INTERVAL_DAYS
        ):
            raise ValueError(
                f"Custom schedule needs an interval between "
                f"{MIN_CUSTOM_INTERVAL_DAYS} and {MAX_CUSTOM_INTERVAL_DAYS} days"
            )
        interval_days = int(interval_days)
    else:
        interval_days = None
    stmt = select(ResellerFinancials).where(ResellerFinancials.user_id == reseller_id)
    fin = (await db.execute(stmt)).scalar_one_or_none()
    if fin:
        fin.payout_frequency = frequency
        if interval_days is not None:
            fin.payout_interval_days = interval_days
    else:
        db.add(ResellerFinancials(
            user_id=reseller_id,
            payout_frequency=frequency,
            payout_interval_days=interval_days,
        ))
    await db.flush()


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
    ResellerPaymentMethodType.MPESA_TILL,
]


async def resolve_b2b_payment_method(
    db: AsyncSession, reseller_id: int
) -> Optional[ResellerPaymentMethod]:
    """
    Find the best B2B-eligible payment method for a reseller.
    1. First active bank_account, mpesa_paybill, or mpesa_till method
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

    command_id = "BusinessPayBill"
    if method_type == ResellerPaymentMethodType.BANK_ACCOUNT:
        party_b = payment_method.bank_paybill_number
        account_ref = payment_method.bank_account_number or ""
    elif method_type == ResellerPaymentMethodType.MPESA_PAYBILL:
        party_b = payment_method.mpesa_paybill_number
        reseller = await db.get(User, reseller_id)
        account_ref = (reseller.organization_name or reseller.email)[:13] if reseller else ""
    elif method_type == ResellerPaymentMethodType.MPESA_TILL:
        # Buy Goods merchant till: different receiver type, no account.
        party_b = payment_method.mpesa_till_number
        account_ref = ""
        command_id = "BusinessBuyGoods"
    else:
        raise ValueError(f"Payment method type {method_type} not eligible for B2B payout")

    if not party_b:
        raise ValueError("Payment method has no destination paybill/till number configured")

    fee, _, _ = compute_fee_breakdown(balance)

    txn = await initiate_b2b_payment(
        db=db,
        reseller_id=reseller_id,
        amount=balance,
        party_b=party_b,
        account_reference=account_ref,
        remarks=f"Payout to {payment_method.label}",
        fee=fee,
        triggered_by=triggered_by,
        command_id=command_id,
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

    # Dedupe windows: anchor them ONCE at run start, as rolling windows (one
    # per payout frequency). The run fires at 23:59 UTC and crosses midnight
    # mid-loop. The old calendar-day window ("created_at >= today 00:00"),
    # recomputed per reseller, made the pre-midnight minute count the PREVIOUS
    # night's post-midnight payouts as "already paid today" and mass-skip
    # resellers who were legitimately owed (2026-07-15 incident: 3 initiated,
    # everyone else silently skipped). Each window sits a few hours short of
    # its nominal period so the previous cycle's slightly-late transaction
    # stays outside it.
    run_anchor = datetime.utcnow()
    dedupe_windows = {
        freq: run_anchor - timedelta(hours=hours)
        for freq, hours in PAYOUT_FREQUENCY_WINDOWS_HOURS.items()
    }

    # Snapshot plain ids first: one reseller's failure must never poison the
    # ORM state (or session) used for the resellers that follow. A rollback
    # expires every object in the session, and touching an expired attribute
    # on an AsyncSession raises — which is how a single mid-run failure used
    # to kill the whole job (2026-06-09 incident).
    async with AsyncSessionLocal() as db:
        resellers_stmt = select(User.id).where(User.role == UserRole.RESELLER)
        reseller_ids = list((await db.execute(resellers_stmt)).scalars().all())

    for reseller_id in reseller_ids:
        try:
            # Share the per-reseller payout guard with the manual/self-service
            # endpoints so the job never races a withdrawal happening right now.
            lock = payout_lock(reseller_id)
            if lock.locked():
                skip_count += 1
                continue

            # Fresh short session per reseller: a failure (or aborted
            # transaction) for one reseller cannot leak into the next.
            async with lock:
                async with AsyncSessionLocal() as db:
                    frequency, interval_days = await get_payout_schedule(db, reseller_id)
                    if frequency == PAYOUT_FREQUENCY_MANUAL:
                        # Reseller opted out of automatic payouts; they withdraw
                        # themselves from the Account Statement page.
                        skip_count += 1
                        continue

                    # Unresolved payment of ANY age (any trigger) = money may
                    # be in flight with no verdict. Sending again is how the
                    # 2026-07-18 double-pays happened — block until the status
                    # reconciliation job settles it. Checked BEFORE the balance
                    # read: a pending payout completing in between would leave
                    # a stale, overstated balance.
                    if await has_unresolved_b2b(db, reseller_id):
                        logger.warning(
                            "Reseller %s has an unresolved (pending/timeout) B2B tx, "
                            "skipping until reconciled",
                            reseller_id,
                        )
                        skip_count += 1
                        continue

                    balance = await get_unpaid_balance(db, reseller_id)
                    # KES 1 can never net positive after the KES 1 Kadogo fee —
                    # skip quietly instead of raising a spurious "failed".
                    if balance < 2:
                        skip_count += 1
                        continue

                    if frequency == PAYOUT_FREQUENCY_CUSTOM:
                        window_start = run_anchor - timedelta(
                            hours=custom_window_hours(interval_days)
                        )
                    else:
                        window_start = dedupe_windows[frequency]

                    dedupe_filters = [
                        B2BTransaction.reseller_id == reseller_id,
                        B2BTransaction.created_at >= window_start,
                        B2BTransaction.status.in_([
                            B2BTransactionStatus.PENDING,
                            B2BTransactionStatus.COMPLETED,
                        ]),
                    ]
                    if frequency == DEFAULT_PAYOUT_FREQUENCY:
                        # Daily keeps its historical semantics: only a scheduled
                        # payout blocks tonight's run — an admin/self payout made
                        # earlier today does not stop the remaining balance.
                        dedupe_filters.append(B2BTransaction.triggered_by == "scheduled")
                    else:
                        # Weekly/monthly/custom express "how often I want cash":
                        # ANY balance payout inside the window restarts the clock,
                        # including admin-manual and reseller self-withdrawals.
                        dedupe_filters.append(
                            B2BTransaction.triggered_by.in_(BALANCE_PAYOUT_TRIGGERS)
                        )

                    existing_recent = await db.execute(
                        select(func.count(B2BTransaction.id)).where(*dedupe_filters)
                    )
                    if existing_recent.scalar() > 0:
                        logger.info(
                            "Reseller %s already has a B2B tx inside their %s payout window, skipping",
                            reseller_id, frequency,
                        )
                        skip_count += 1
                        continue

                    pm = await resolve_b2b_payment_method(db, reseller_id)
                    if not pm:
                        skip_count += 1
                        continue

                    try:
                        txn = await payout_reseller(
                            db, reseller_id, pm, balance, triggered_by="scheduled"
                        )
                    except PayoutInFlightError:
                        # Another initiator won the race between our check and
                        # the send — that payout covers the balance.
                        skip_count += 1
                        continue
                    await db.commit()

                    if txn.status == B2BTransactionStatus.PENDING:
                        paid_count += 1
                        logger.info(
                            "B2B payout initiated: reseller=%s amount=%s net=%s fee=%s -> %s",
                            reseller_id, txn.amount, txn.net_amount, txn.fee, txn.party_b,
                        )
                    else:
                        fail_count += 1

        except Exception as e:
            fail_count += 1
            # reseller_id is a plain int — safe to log even after a DB error.
            logger.error("B2B payout failed for reseller %s: %s", reseller_id, e)

    logger.info(
        "Daily B2B payout run complete: initiated=%d skipped=%d failed=%d",
        paid_count, skip_count, fail_count,
    )

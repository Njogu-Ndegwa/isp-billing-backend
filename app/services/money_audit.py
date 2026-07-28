"""Read-only money-consistency auditor.

Query helpers that surface ledger anomalies for an ops report (and for the
future Payments Clerk agent). Every function:

  * is a pure SELECT — never writes, never commits;
  * takes the caller's AsyncSession and returns plain list[dict] row
    summaries (JSON-serializable);
  * must be called from a SHORT-lived session. Do not hold the session
    across router/M-Pesa/httpx I/O afterwards — open, audit, close
    (Database Session Discipline, AGENTS.md).

No schema changes: everything is derived from existing tables.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    B2BTransaction,
    B2BTransactionStatus,
    C2BTransaction,
    CollectionMode,
    CustomerPayment,
    MpesaTransaction,
    PaymentMethod,
    ResellerPayout,
)

logger = logging.getLogger(__name__)

# ResellerPayout.payment_method stamped by the automated B2B settlement path
# (mpesa_b2b._settle_completed_transaction). Manual admin payouts recorded via
# POST /api/admin/resellers/{id}/payouts carry whatever method the admin typed
# ("mpesa", "bank", ...) and legitimately have no B2BTransaction.
B2B_AUTO_PAYOUT_METHOD = "mpesa_b2b"

# Statuses where Safaricom has not given a verdict — money may or may not have
# moved. Mirrors mpesa_b2b.UNRESOLVED_STATUSES (kept local so this module only
# imports models, not the full B2B service with its httpx/crypto stack).
_UNRESOLVED_B2B_STATUSES = (
    B2BTransactionStatus.PENDING,
    B2BTransactionStatus.TIMEOUT,
)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _age_hours(dt: datetime | None, now: datetime) -> float | None:
    if not dt:
        return None
    return round((now - dt).total_seconds() / 3600.0, 1)


async def find_orphan_payouts(db: AsyncSession) -> list[dict]:
    """ResellerPayout ledger rows that claim to be automated B2B settlements
    but have NO completed B2BTransaction backing them.

    An automated payout row is only ever written by
    ``mpesa_b2b._settle_completed_transaction`` — atomically with flipping its
    B2BTransaction to COMPLETED and linking ``txn.payout_id``. A
    ``payment_method='mpesa_b2b'`` payout without such a transaction means the
    ledger says money was sent that no settled provider call corroborates
    (e.g. a crashed settlement, a deleted/rolled-back transaction row, or a
    manual entry impersonating the automated path).

    Limitations (documented on purpose):
      * Manual admin payouts (any other payment_method) are OUT of scope —
        they have no B2BTransaction by design.
      * Match key is ``B2BTransaction.payout_id`` (FK), not the free-text
        ``reference`` column; a completed transaction that lost its payout_id
        link will flag the payout even though money moved — that still
        deserves human eyes.
    """
    now = datetime.utcnow()
    backing_txn = exists(
        select(B2BTransaction.id).where(
            B2BTransaction.payout_id == ResellerPayout.id,
            B2BTransaction.status == B2BTransactionStatus.COMPLETED,
        )
    )
    rows = (
        (
            await db.execute(
                select(ResellerPayout)
                .where(
                    ResellerPayout.payment_method == B2B_AUTO_PAYOUT_METHOD,
                    ~backing_txn,
                )
                .order_by(ResellerPayout.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "payout_id": p.id,
            "reseller_id": p.reseller_id,
            "amount": p.amount,
            "payment_method": p.payment_method,
            "reference": p.reference,
            "created_at": _iso(p.created_at),
            "age_hours": _age_hours(p.created_at, now),
            "reason": "payout claims mpesa_b2b but no COMPLETED B2BTransaction links to it",
        }
        for p in rows
    ]


async def find_phantom_customer_payments(db: AsyncSession) -> list[dict]:
    """SYSTEM-collected mobile-money CustomerPayment rows with no provider
    record backing them.

    These rows feed the payout balance (mpesa_b2b.PAYOUT_REVENUE_FILTERS), so
    a phantom here is money the platform will PAY OUT without ever having
    received it.

    Match keys — derived from how each recorder actually writes rows:
      * C2B paths (app/services/c2b_handler.py, manual attribution in
        app/api/c2b_routes.py) are the ONLY writers that stamp
        ``collection_mode=SYSTEM_COLLECTED``; both set
        ``payment_reference = C2BTransaction.trans_id``.
      * Defensively, an STK-shaped reference is also accepted:
        ``MpesaTransaction.mpesa_receipt_number`` or
        ``MpesaTransaction.checkout_request_id`` equal to the reference
        (payment_routes records STK payments with the receipt number, the
        manual-completion path may fall back to the checkout id).

    Limitations (documented on purpose):
      * Rows with ``collection_mode`` NULL are NOT audited: STK-callback and
        legacy rows are NULL, but so are manual mobile-money entries typed in
        by resellers (arbitrary/absent references) — auditing NULL would
        flood the report with false positives.
      * ``collection_mode=DIRECT`` rows are the reseller's own paybill money,
        excluded from the payout balance, so they are out of scope here.
      * Matching is by reference string only; it does not cross-check the
        amount against the provider row.
    """
    now = datetime.utcnow()
    c2b_match = exists(
        select(C2BTransaction.id).where(
            C2BTransaction.trans_id == CustomerPayment.payment_reference
        )
    )
    stk_match = exists(
        select(MpesaTransaction.id).where(
            or_(
                MpesaTransaction.mpesa_receipt_number == CustomerPayment.payment_reference,
                MpesaTransaction.checkout_request_id == CustomerPayment.payment_reference,
            )
        )
    )
    rows = (
        (
            await db.execute(
                select(CustomerPayment)
                .where(
                    CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY,
                    CustomerPayment.collection_mode == CollectionMode.SYSTEM_COLLECTED,
                    or_(
                        CustomerPayment.payment_reference.is_(None),
                        and_(~c2b_match, ~stk_match),
                    ),
                )
                .order_by(CustomerPayment.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "payment_id": p.id,
            "customer_id": p.customer_id,
            "reseller_id": p.reseller_id,
            "amount": p.amount,
            "payment_reference": p.payment_reference,
            "created_at": _iso(p.created_at),
            "age_hours": _age_hours(p.created_at, now),
            "reason": (
                "system-collected mobile-money payment has no payment_reference"
                if p.payment_reference is None
                else "no C2BTransaction/MpesaTransaction matches payment_reference"
            ),
        }
        for p in rows
    ]


async def find_unsettled_pending_b2b(
    db: AsyncSession, older_than_hours: float = 24.0
) -> list[dict]:
    """B2BTransaction rows stuck without a Safaricom verdict (PENDING or
    TIMEOUT) for longer than *older_than_hours*.

    These block ALL further payouts to their reseller (mpesa_b2b
    UNRESOLVED_STATUSES in-flight guard) and represent money that may or may
    not have left the platform — exactly the 2026-07-18 lost-callback shape.
    The status-reconciliation job should resolve them; anything old enough to
    show up here has slipped through it and needs ops attention.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=older_than_hours)
    rows = (
        (
            await db.execute(
                select(B2BTransaction)
                .where(
                    B2BTransaction.status.in_(_UNRESOLVED_B2B_STATUSES),
                    B2BTransaction.created_at < cutoff,
                )
                .order_by(B2BTransaction.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "b2b_transaction_id": t.id,
            "reseller_id": t.reseller_id,
            "amount": t.amount,
            "net_amount": t.net_amount,
            "status": t.status.value if hasattr(t.status, "value") else t.status,
            "conversation_id": t.conversation_id,
            "originator_conversation_id": t.originator_conversation_id,
            "result_desc": t.result_desc,
            "triggered_by": t.triggered_by,
            "created_at": _iso(t.created_at),
            "age_hours": _age_hours(t.created_at, now),
            "reason": f"unresolved for more than {older_than_hours}h — blocks this reseller's payouts",
        }
        for t in rows
    ]


async def run_money_audit(db: AsyncSession, older_than_hours: float = 24.0) -> dict:
    """Convenience aggregate for an ops report. Read-only."""
    orphans = await find_orphan_payouts(db)
    phantoms = await find_phantom_customer_payments(db)
    unsettled = await find_unsettled_pending_b2b(db, older_than_hours)
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "orphan_payouts": orphans,
        "phantom_customer_payments": phantoms,
        "unsettled_pending_b2b": unsettled,
        "counts": {
            "orphan_payouts": len(orphans),
            "phantom_customer_payments": len(phantoms),
            "unsettled_pending_b2b": len(unsettled),
        },
    }

"""Direct settlement: customer M-Pesa payments land in the reseller's account.

The platform's own Daraja app still raises the STK push — BusinessShortCode
and Password are the system paybill's — but PartyB is the reseller's payout
destination: the same paybill, till or bank account (bank paybill +
AccountReference) that the scheduled B2B payout would have sent the money to
(``mpesa_b2b.payout_destination``). The money never sits on the system
paybill, so there is nothing to pay out and no B2B fee.

Proven live on 2026-09-28 from production (ResultCode 0 on each): two
reseller paybills, and Equity 247247 with a 13-digit account number as
AccountReference (Safaricom documents a 12-character limit but accepted 13).
Buy Goods tills were not yet proven live; a rejected push falls back to
platform collection (see ``payment_gateway``), so a till Safaricom refuses
still gets a working prompt.

Known trade-offs:
  * The PIN prompt names the system paybill (the signing shortcode), not the
    reseller — only the AccountReference is ours to set.
  * Refunds/reversals are the reseller's to make; the platform never holds
    the money.

Accounting: rows are stamped ``CollectionMode.DIRECT``, which the payout
engine already excludes from the unpaid balance (``PAYOUT_REVENUE_FILTERS``),
so direct money is never paid out a second time. Subscription invoices count
every completed payment regardless of collection mode, so platform billing is
unchanged.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    CollectionMode,
    CustomerPayment,
    PaymentMethod,
    PaymentStatus,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    User,
)

logger = logging.getLogger(__name__)

SETTLEMENT_PLATFORM = "platform"
SETTLEMENT_DIRECT = "direct"
VALID_SETTLEMENT_MODES = (SETTLEMENT_PLATFORM, SETTLEMENT_DIRECT)

# Method types whose destination an STK push can pay straight into — the
# same set the B2B payout can pay (mpesa_b2b.B2B_ELIGIBLE_TYPES).
DIRECT_ELIGIBLE_TYPES = (
    ResellerPaymentMethodType.BANK_ACCOUNT,
    ResellerPaymentMethodType.MPESA_PAYBILL,
    ResellerPaymentMethodType.MPESA_TILL,
)


@dataclass(frozen=True)
class DirectDestination:
    party_b: str
    transaction_type: str  # CustomerPayBillOnline | CustomerBuyGoodsOnline
    # None = keep the caller's display reference (the reseller's name).
    account_reference: Optional[str]


def _method_type(pm: ResellerPaymentMethod) -> ResellerPaymentMethodType:
    mt = pm.method_type
    return ResellerPaymentMethodType(mt) if isinstance(mt, str) else mt


def normalize_settlement_mode(value: Optional[str]) -> str:
    return value if value in VALID_SETTLEMENT_MODES else SETTLEMENT_PLATFORM


async def get_settlement_mode(db: AsyncSession, reseller_id: int) -> str:
    value = (await db.execute(
        select(User.settlement_mode).where(User.id == reseller_id)
    )).scalar_one_or_none()
    return normalize_settlement_mode(value)


async def set_settlement_mode(db: AsyncSession, reseller_id: int, mode: str) -> None:
    if mode not in VALID_SETTLEMENT_MODES:
        raise ValueError(
            f"settlement_mode must be one of: {', '.join(VALID_SETTLEMENT_MODES)}"
        )
    user = await db.get(User, reseller_id)
    if user is None:
        raise ValueError("Reseller not found")
    user.settlement_mode = mode
    await db.flush()


def direct_destination(
    pm: ResellerPaymentMethod, reseller: Optional[User]
) -> Optional[DirectDestination]:
    """Where an STK push should pay for this method, or None if it can't.

    Mirrors the B2B payout destination exactly. A bank method with no
    account number is refused: the bank could not credit anyone and the
    money would sit in its suspense account.
    """
    from app.services.mpesa_b2b import payout_destination

    mt = _method_type(pm)
    if mt not in DIRECT_ELIGIBLE_TYPES:
        return None
    try:
        party_b, account_ref, _command_id = payout_destination(pm, reseller)
    except ValueError:
        return None

    if mt == ResellerPaymentMethodType.BANK_ACCOUNT:
        if not account_ref.strip():
            return None
        return DirectDestination(party_b, "CustomerPayBillOnline", account_ref.strip())
    if mt == ResellerPaymentMethodType.MPESA_TILL:
        return DirectDestination(party_b, "CustomerBuyGoodsOnline", None)
    return DirectDestination(party_b, "CustomerPayBillOnline", account_ref or None)


async def resolve_direct_destination(
    db: AsyncSession, pm: ResellerPaymentMethod
) -> Optional[DirectDestination]:
    """The destination for a payment on ``pm`` if its owner settles directly."""
    if _method_type(pm) not in DIRECT_ELIGIBLE_TYPES:
        return None
    owner = await db.get(User, pm.user_id)
    if owner is None or normalize_settlement_mode(owner.settlement_mode) != SETTLEMENT_DIRECT:
        return None
    return direct_destination(pm, owner)


async def default_direct_method(
    db: AsyncSession, reseller_id: int
) -> Optional[ResellerPaymentMethod]:
    """Payout method used for a direct-settling reseller's routers that have
    no method assigned (the legacy path). Only an ACTIVE eligible method
    qualifies — unlike the B2B resolver, never an inactive one — and only
    when the reseller has opted into direct settlement."""
    if await get_settlement_mode(db, reseller_id) != SETTLEMENT_DIRECT:
        return None
    from app.services.mpesa_b2b import resolve_b2b_payment_method

    pm = await resolve_b2b_payment_method(db, reseller_id)
    if pm is None or not pm.is_active:
        return None
    return pm


async def direct_received_total(
    db: AsyncSession, reseller_id: int, days: int = 30
) -> float:
    """M-Pesa customer payments that went straight to the reseller."""
    since = datetime.utcnow() - timedelta(days=days)
    total = (await db.execute(
        select(func.coalesce(func.sum(CustomerPayment.amount), 0)).where(
            CustomerPayment.reseller_id == reseller_id,
            CustomerPayment.payment_method == PaymentMethod.MOBILE_MONEY,
            CustomerPayment.status == PaymentStatus.COMPLETED,
            CustomerPayment.collection_mode == CollectionMode.DIRECT,
            CustomerPayment.created_at >= since,
        )
    )).scalar()
    return round(float(total or 0), 2)

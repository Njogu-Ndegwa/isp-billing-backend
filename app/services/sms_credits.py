"""SMS credit balance + ledger operations.

All functions take a session and mutate within the caller's transaction
(caller commits). They never perform network I/O.
"""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    SmsCreditAccount,
    SmsCreditTransaction,
    SmsCreditTxnKind,
)


async def get_or_create_account(db: AsyncSession, user_id: int) -> SmsCreditAccount:
    acct = (await db.execute(
        select(SmsCreditAccount).where(SmsCreditAccount.user_id == user_id)
    )).scalar_one_or_none()
    if acct is None:
        acct = SmsCreditAccount(user_id=user_id, balance=0)
        db.add(acct)
        await db.flush()
    return acct


async def _ledger(db, user_id, change, balance_after, kind, reference, note):
    db.add(SmsCreditTransaction(
        user_id=user_id, change=change, balance_after=balance_after,
        kind=kind, reference=reference, note=note,
    ))


async def grant(db: AsyncSession, user_id: int, amount: int,
                kind: SmsCreditTxnKind = SmsCreditTxnKind.PURCHASE,
                reference: Optional[str] = None, note: Optional[str] = None) -> int:
    """Add credits (purchase / admin grant). Returns new balance."""
    if amount <= 0:
        raise ValueError("grant amount must be positive")
    acct = await get_or_create_account(db, user_id)
    acct.balance += amount
    if kind == SmsCreditTxnKind.PURCHASE:
        acct.total_purchased += amount
    await db.flush()
    await _ledger(db, user_id, amount, acct.balance, kind, reference, note)
    return acct.balance


async def try_deduct(db: AsyncSession, user_id: int, amount: int,
                     reference: Optional[str] = None,
                     note: Optional[str] = None) -> bool:
    """Deduct credits for a send. Returns False (no change) if insufficient."""
    if amount <= 0:
        return True
    acct = await get_or_create_account(db, user_id)
    if acct.balance < amount:
        return False
    acct.balance -= amount
    acct.total_spent += amount
    await db.flush()
    await _ledger(db, user_id, -amount, acct.balance,
                  SmsCreditTxnKind.SEND_DEBIT, reference, note)
    return True


async def refund(db: AsyncSession, user_id: int, amount: int,
                 reference: Optional[str] = None,
                 note: Optional[str] = None) -> int:
    """Return credits for failed recipients. Returns new balance."""
    if amount <= 0:
        return (await get_or_create_account(db, user_id)).balance
    acct = await get_or_create_account(db, user_id)
    acct.balance += amount
    # total_spent is NET of refunds — it should reflect only credits for
    # messages that actually went out. Refunds are for FAILED recipients,
    # so they reduce the lifetime "spent" stat (clamped at zero).
    acct.total_spent = max(0, acct.total_spent - amount)
    await db.flush()
    await _ledger(db, user_id, amount, acct.balance,
                  SmsCreditTxnKind.REFUND, reference, note)
    return acct.balance


async def adjust(db: AsyncSession, user_id: int, delta: int,
                 note: Optional[str] = None) -> int:
    """Admin manual adjustment (can be +/-). Clamps at zero. Returns new balance."""
    acct = await get_or_create_account(db, user_id)
    acct.balance = max(0, acct.balance + delta)
    if delta > 0:
        acct.total_purchased += delta
    await db.flush()
    await _ledger(db, user_id, delta, acct.balance,
                  SmsCreditTxnKind.ADMIN_ADJUSTMENT, None, note)
    return acct.balance

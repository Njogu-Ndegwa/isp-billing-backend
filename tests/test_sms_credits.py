import pytest

from app.db.models import SmsCreditTransaction, SmsCreditTxnKind
from app.services import sms_credits
from tests.factories import make_reseller, make_sms_account


@pytest.mark.asyncio
async def test_get_or_create_account_starts_at_zero(db):
    r = await make_reseller(db)
    acct = await sms_credits.get_or_create_account(db, r.id)
    await db.commit()
    assert acct.balance == 0


@pytest.mark.asyncio
async def test_grant_increases_balance_and_writes_ledger(db):
    r = await make_reseller(db)
    await sms_credits.grant(db, r.id, 100, SmsCreditTxnKind.PURCHASE, reference="SMS-1")
    await db.commit()
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 100
    assert acct.total_purchased == 100
    rows = (await db.execute(SmsCreditTransaction.__table__.select())).fetchall()
    assert len(rows) == 1
    assert rows[0].change == 100
    assert rows[0].balance_after == 100


@pytest.mark.asyncio
async def test_deduct_requires_sufficient_balance(db):
    r = await make_reseller(db)
    await make_sms_account(db, r, balance=5)
    ok = await sms_credits.try_deduct(db, r.id, 10, reference="C-1")
    await db.commit()
    assert ok is False
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 5


@pytest.mark.asyncio
async def test_deduct_then_refund(db):
    r = await make_reseller(db)
    await make_sms_account(db, r, balance=10)
    ok = await sms_credits.try_deduct(db, r.id, 8, reference="C-2")
    await db.commit()
    assert ok is True
    await sms_credits.refund(db, r.id, 3, reference="C-2")
    await db.commit()
    acct = await sms_credits.get_or_create_account(db, r.id)
    assert acct.balance == 5
    assert acct.total_spent == 8


@pytest.mark.asyncio
async def test_admin_adjust_can_grant_and_clamps_at_zero(db):
    r = await make_reseller(db)
    await make_sms_account(db, r, balance=2)
    bal = await sms_credits.adjust(db, r.id, 10, note="promo")
    await db.commit()
    assert bal == 12
    bal = await sms_credits.adjust(db, r.id, -100, note="correction")
    await db.commit()
    assert bal == 0      # clamped, never negative

"""
Retire historical STK echoes sitting in unmatched_c2b_payments.

Before the STK-echo guard in app/services/c2b_handler.py, every STK push on a
paybill with C2B URLs registered also produced an unmatched C2B row (the C2B
copy of the same receipt, BillRefNumber = the business name, so it failed the
Luhn check). Those rows are not real unmatched payments: the STK callback
already credited the customer. This module finds open unmatched rows whose
TransID is already recorded as an STK receipt or a customer payment and
retires them through the same retire_c2b_stk_echo() the live path uses
(status STK_ECHO, unmatched row resolved with note 'stk_echo', no payment, no
wallet change).

Dry-run by default. Driven by scripts/backfill_c2b_stk_echoes.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from sqlalchemy import exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    C2BTransaction,
    C2BTransactionStatus,
    CustomerPayment,
    MpesaTransaction,
    UnmatchedC2BPayment,
)
from app.services.c2b_handler import find_recorded_receipt, retire_c2b_stk_echo

DEFAULT_BATCH_SIZE = 500


@dataclass
class EchoBackfillReport:
    dry_run: bool
    open_unmatched_in_scope: int = 0
    echo_candidates: int = 0
    via_mpesa_receipt: int = 0
    via_customer_payment_only: int = 0
    by_assigned_reseller: list = field(default_factory=list)  # [(reseller_id|None, count)]
    retired: int = 0
    skipped: int = 0
    remaining: int = 0
    sample: list = field(default_factory=list)  # [(unmatched_id, trans_id)]


def _mpesa_hit():
    return exists().where(MpesaTransaction.mpesa_receipt_number == C2BTransaction.trans_id)


def _payment_hit():
    return exists().where(CustomerPayment.payment_reference == C2BTransaction.trans_id)


def _scope(
    stmt,
    *,
    reseller_id: Optional[int],
    platform_only: bool,
    unmatched_ids: Optional[Iterable[int]],
):
    stmt = stmt.where(
        UnmatchedC2BPayment.resolved_at.is_(None),
        C2BTransaction.status == C2BTransactionStatus.UNMATCHED,
    )
    if reseller_id is not None:
        stmt = stmt.where(UnmatchedC2BPayment.assigned_reseller_id == reseller_id)
    if platform_only:
        stmt = stmt.where(UnmatchedC2BPayment.assigned_reseller_id.is_(None))
    if unmatched_ids:
        stmt = stmt.where(UnmatchedC2BPayment.id.in_(list(unmatched_ids)))
    return stmt


def _base(*cols):
    return select(*cols).select_from(UnmatchedC2BPayment).join(
        C2BTransaction, C2BTransaction.id == UnmatchedC2BPayment.c2b_transaction_id
    )


async def backfill_stk_echoes(
    db: AsyncSession,
    *,
    dry_run: bool = True,
    reseller_id: Optional[int] = None,
    platform_only: bool = False,
    unmatched_ids: Optional[Iterable[int]] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    limit: Optional[int] = None,
) -> EchoBackfillReport:
    unmatched_ids = list(unmatched_ids) if unmatched_ids else None
    scope = dict(reseller_id=reseller_id, platform_only=platform_only, unmatched_ids=unmatched_ids)
    report = EchoBackfillReport(dry_run=dry_run)
    is_echo = or_(_mpesa_hit(), _payment_hit())

    report.open_unmatched_in_scope = (
        await db.execute(_scope(_base(func.count(UnmatchedC2BPayment.id)), **scope))
    ).scalar_one()
    report.echo_candidates = (
        await db.execute(_scope(_base(func.count(UnmatchedC2BPayment.id)), **scope).where(is_echo))
    ).scalar_one()
    report.via_mpesa_receipt = (
        await db.execute(
            _scope(_base(func.count(UnmatchedC2BPayment.id)), **scope).where(_mpesa_hit())
        )
    ).scalar_one()
    report.via_customer_payment_only = report.echo_candidates - report.via_mpesa_receipt
    report.by_assigned_reseller = [
        (r[0], r[1])
        for r in (
            await db.execute(
                _scope(
                    _base(UnmatchedC2BPayment.assigned_reseller_id, func.count(UnmatchedC2BPayment.id)),
                    **scope,
                )
                .where(is_echo)
                .group_by(UnmatchedC2BPayment.assigned_reseller_id)
                .order_by(func.count(UnmatchedC2BPayment.id).desc())
                .limit(20)
            )
        ).all()
    ]
    report.sample = [
        (r[0], r[1])
        for r in (
            await db.execute(
                _scope(_base(UnmatchedC2BPayment.id, C2BTransaction.trans_id), **scope)
                .where(is_echo)
                .order_by(UnmatchedC2BPayment.id.desc())
                .limit(10)
            )
        ).all()
    ]
    await db.commit()  # end the read transaction before any long apply loop

    if dry_run:
        report.remaining = report.echo_candidates
        return report

    budget = limit if limit is not None else report.echo_candidates
    after_id = 0
    while budget > 0:
        rows = (
            await db.execute(
                _scope(_base(UnmatchedC2BPayment.id, C2BTransaction.trans_id), **scope)
                .where(is_echo, UnmatchedC2BPayment.id > after_id)
                .order_by(UnmatchedC2BPayment.id.asc())
                .limit(min(batch_size, budget))
            )
        ).all()
        if not rows:
            break
        for unmatched_id, trans_id in rows:
            after_id = unmatched_id
            owner = await find_recorded_receipt(db, trans_id)
            if owner is None:
                report.skipped += 1
                continue
            if await retire_c2b_stk_echo(
                db, trans_id, customer_id=owner.customer_id, reseller_id=owner.reseller_id,
            ):
                report.retired += 1
            else:
                report.skipped += 1
        budget -= len(rows)
        await db.commit()  # one short transaction per batch

    report.remaining = (
        await db.execute(_scope(_base(func.count(UnmatchedC2BPayment.id)), **scope).where(is_echo))
    ).scalar_one()
    await db.commit()
    return report

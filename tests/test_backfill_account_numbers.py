"""
Tests for the account-number backfill service.

These exercise the SAME code path the CLI uses (the CLI is a thin wrapper
around `backfill_account_numbers`). If these pass, running the script in
production with --apply will do exactly what we asserted here.
"""

import pytest
from sqlalchemy import select

from app.db.models import Customer
from app.services.account_number_backfill import backfill_account_numbers
from app.services.account_numbers import is_valid_account_number
from tests.factories import make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_customers_without_account(db, n: int):
    """Create `n` customers, each with account_number=None and unique MAC."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    out = []
    for i in range(n):
        c = await make_customer(
            db, reseller, plan, router,
            name=f"seed-{i}",
            mac_address=f"AA:BB:CC:DD:{(i // 256):02X}:{(i % 256):02X}",
            pppoe_username=f"seed_{i}",
            account_number=None,
        )
        out.append(c)
    return out


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


async def test_dry_run_reports_count_without_writing(db):
    await _seed_customers_without_account(db, 5)

    report = await backfill_account_numbers(db, dry_run=True)

    assert report.dry_run is True
    assert report.total_missing == 5
    assert report.assigned == 0
    assert report.remaining == 5
    # Sample numbers are generated for the operator to eyeball but not persisted
    assert len(report.sample_assignments) == 5
    for sample in report.sample_assignments:
        assert is_valid_account_number(sample["account_number"])

    # Verify NOTHING was committed
    still_null = (
        await db.execute(select(Customer).where(Customer.account_number.is_(None)))
    ).scalars().all()
    assert len(still_null) == 5


async def test_dry_run_on_empty_db_returns_zero(db):
    report = await backfill_account_numbers(db, dry_run=True)
    assert report.total_missing == 0
    assert report.assigned == 0
    assert report.sample_assignments == []


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


async def test_apply_assigns_all_missing_with_valid_unique_numbers(db, session_factory):
    customers = await _seed_customers_without_account(db, 50)
    ids = [c.id for c in customers]

    report = await backfill_account_numbers(db, dry_run=False, batch_size=10)

    assert report.dry_run is False
    assert report.total_missing == 50
    assert report.assigned == 50
    assert report.errored == 0
    assert report.remaining == 0

    # Read back through a FRESH session — the backfill commits per batch, so
    # stale identity-map state in the test's `db` session may not reflect it.
    async with session_factory() as s:
        rows = (
            await s.execute(select(Customer).where(Customer.id.in_(ids)))
        ).scalars().all()
        assert len(rows) == 50
        numbers = [r.account_number for r in rows]
        # All assigned
        assert all(n is not None for n in numbers)
        # All Luhn-valid
        for n in numbers:
            assert is_valid_account_number(n), f"Invalid account number assigned: {n!r}"
        # All unique
        assert len(set(numbers)) == 50


async def test_apply_is_idempotent(db, session_factory):
    """Re-running after a complete backfill should be a no-op."""
    await _seed_customers_without_account(db, 10)

    first = await backfill_account_numbers(db, dry_run=False)
    assert first.assigned == 10
    assert first.remaining == 0

    # Re-run — nothing to do
    async with session_factory() as s:
        second = await backfill_account_numbers(s, dry_run=False)
        assert second.total_missing == 0
        assert second.assigned == 0


async def test_apply_skips_customers_that_already_have_numbers(db, session_factory):
    """Mixed state: some pre-populated, some null. Backfill only touches nulls."""
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)

    # 3 pre-populated, 5 needing backfill
    pre = []
    for i, acct in enumerate(["10000007", "20000005", "30000003"]):
        c = await make_customer(
            db, reseller, plan, router,
            name=f"pre-{i}",
            mac_address=f"AA:11:22:33:44:{i:02X}",
            pppoe_username=f"pre_{i}",
            account_number=acct,
        )
        pre.append(c)

    needs = []
    for i in range(5):
        c = await make_customer(
            db, reseller, plan, router,
            name=f"need-{i}",
            mac_address=f"BB:11:22:33:44:{i:02X}",
            pppoe_username=f"need_{i}",
            account_number=None,
        )
        needs.append(c)

    report = await backfill_account_numbers(db, dry_run=False)
    assert report.total_missing == 5
    assert report.assigned == 5

    async with session_factory() as s:
        # Pre-existing numbers untouched
        for c in pre:
            row = (await s.execute(select(Customer).where(Customer.id == c.id))).scalar_one()
            assert row.account_number == c.account_number

        # New numbers are valid + distinct from pre-existing
        new_rows = (
            await s.execute(select(Customer).where(Customer.id.in_([c.id for c in needs])))
        ).scalars().all()
        new_numbers = [r.account_number for r in new_rows]
        assert all(is_valid_account_number(n) for n in new_numbers)
        assert set(new_numbers).isdisjoint({c.account_number for c in pre})

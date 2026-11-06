"""
CLI: normalise paybill/till/account numbers already stored on payment methods.

New saves are normalised by the API (app/services/payment_numbers.py). This
puts existing rows through the same normaliser: whitespace removed, dashes
removed from numeric fields. A numeric field with other characters left over
is reported and left as is.

Dry-run by default (prints what would change, writes nothing). Run inside
the app container so it uses the app's DB settings:

    python scripts/normalize_payment_method_numbers.py            # preview all
    python scripts/normalize_payment_method_numbers.py --id 350   # preview one
    python scripts/normalize_payment_method_numbers.py --id 350 --apply

Idempotent: a normalised row has nothing left to change.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app.db.database import AsyncSessionLocal, async_engine  # noqa: E402
from app.db.models import ResellerPaymentMethod  # noqa: E402
from app.services.payment_numbers import NUMBER_FIELDS, InvalidNumber, normalize_number  # noqa: E402


def plan_changes(methods):
    """[(method, {field: (before, after)})] and [(method, field, value)] rejects."""
    changes, rejects = [], []
    for pm in methods:
        diff = {}
        for field in NUMBER_FIELDS:
            before = getattr(pm, field)
            if before is None:
                continue
            try:
                after = normalize_number(field, before)
            except InvalidNumber:
                rejects.append((pm, field, before))
                continue
            if after != before:
                diff[field] = (before, after)
        if diff:
            changes.append((pm, diff))
    return changes, rejects


async def run(method_id=None, apply=False) -> int:
    async with AsyncSessionLocal() as db:
        stmt = select(ResellerPaymentMethod).order_by(ResellerPaymentMethod.id)
        if method_id is not None:
            stmt = stmt.where(ResellerPaymentMethod.id == method_id)
        methods = (await db.execute(stmt)).scalars().all()
        changes, rejects = plan_changes(methods)

        print(f"=== Payment method number normalisation: {'APPLY' if apply else 'DRY-RUN (no writes)'} ===")
        print(f"  methods scanned: {len(methods)}")
        for pm, diff in changes:
            for field, (before, after) in diff.items():
                print(f"  method {pm.id} (reseller {pm.user_id}) {field}: {before!r} -> {after!r}")
        for pm, field, value in rejects:
            print(f"  LEFT AS IS method {pm.id} (reseller {pm.user_id}) {field}: {value!r} is not a number")
        print(f"  methods to change: {len(changes)}")

        if apply and changes:
            for pm, diff in changes:
                for field, (_, after) in diff.items():
                    setattr(pm, field, after)
            await db.commit()
            print(f"  committed {len(changes)} method(s)")
        else:
            await db.rollback()
    await async_engine.dispose()
    return len(changes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--id", type=int, help="only this payment method id")
    parser.add_argument("--apply", action="store_true", help="write the changes")
    args = parser.parse_args()
    asyncio.run(run(method_id=args.id, apply=args.apply))


if __name__ == "__main__":
    main()

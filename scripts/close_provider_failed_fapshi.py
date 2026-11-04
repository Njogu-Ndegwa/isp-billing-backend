"""
CLI: close stuck Fapshi rows that Fapshi itself reports FAILED/EXPIRED.

Rows created before the final provider check existed could be parked as
``reconciliation_window_exhausted`` while still PENDING/CREATED. For each id
given, this re-confirms the status with Fapshi's read-only payment-status call
and, only when Fapshi says FAILED or EXPIRED, marks the local row the same.
Rows Fapshi reports as anything else (e.g. SUCCESSFUL) are left untouched for
manual review. It never credits a customer, moves money or deletes anything.

Dry-run by default. Run inside the app container:

    python scripts/close_provider_failed_fapshi.py --txn-id 11 --txn-id 30
    python scripts/close_provider_failed_fapshi.py --txn-id 11 --txn-id 30 --apply

Idempotent: rows already closed report ``already_final`` and are not touched.
"""

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import async_engine
from app.services.fapshi_reconciliation import close_provider_terminal_rows


async def main(args) -> None:
    try:
        results = await close_provider_terminal_rows(args.txn_id, apply=args.apply)
    finally:
        await async_engine.dispose()
    print(f"=== Fapshi provider-terminal close: {'APPLY' if args.apply else 'DRY-RUN (no writes)'} ===")
    for row in results:
        print(json.dumps(row, default=str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--txn-id", type=int, action="append", required=True,
                        help="local fapshi_transactions.id (repeatable)")
    parser.add_argument("--apply", action="store_true", help="write the closures")
    asyncio.run(main(parser.parse_args()))

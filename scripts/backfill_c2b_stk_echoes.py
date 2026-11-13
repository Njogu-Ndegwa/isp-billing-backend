"""
CLI: retire historical STK echoes from the unmatched C2B list.

An STK echo is the C2B confirmation Safaricom sends for an STK push on a
paybill that has C2B URLs registered. The STK callback already credited the
customer, so the echo is not an unmatched payment. This marks matching
c2b_transactions rows STK_ECHO and resolves their unmatched_c2b_payments row
with note 'stk_echo'. It never creates a payment or changes a wallet.

Dry-run by default (prints counts, writes nothing). Run inside the app
container so it uses the app's DB settings:

    # Preview everything (platform bucket + all resellers)
    python scripts/backfill_c2b_stk_echoes.py

    # Preview / apply one reseller only
    python scripts/backfill_c2b_stk_echoes.py --reseller-id 713
    python scripts/backfill_c2b_stk_echoes.py --reseller-id 713 --apply

    # Specific unmatched rows only
    python scripts/backfill_c2b_stk_echoes.py --unmatched-id 240038 --apply

    # Platform-paybill bucket (assigned_reseller_id IS NULL), in chunks
    python scripts/backfill_c2b_stk_echoes.py --platform-only --apply --limit 20000

Idempotent: retired rows are no longer candidates, so it is safe to re-run.
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import async_engine, AsyncSessionLocal
from app.services.c2b_stk_echo_backfill import DEFAULT_BATCH_SIZE, backfill_stk_echoes


def _print_report(report) -> None:
    mode = "DRY-RUN (no writes)" if report.dry_run else "APPLY"
    print(f"=== C2B STK-echo backfill: {mode} ===")
    print(f"  open unmatched rows in scope:   {report.open_unmatched_in_scope}")
    print(f"  STK echoes among them:          {report.echo_candidates}")
    print(f"    receipt on an STK transaction: {report.via_mpesa_receipt}")
    print(f"    only on a customer payment:    {report.via_customer_payment_only}")
    print(f"  genuine (left alone):           {report.open_unmatched_in_scope - report.echo_candidates}")
    if report.by_assigned_reseller:
        print("  echoes by assigned reseller (top 20; None = platform paybill):")
        for reseller_id, count in report.by_assigned_reseller:
            print(f"    {reseller_id}: {count}")
    if report.sample:
        print("  sample (unmatched_id, trans_id):")
        for unmatched_id, trans_id in report.sample:
            print(f"    {unmatched_id}  {trans_id}")
    if not report.dry_run:
        print(f"  retired:   {report.retired}")
        print(f"  skipped:   {report.skipped}")
    print(f"  remaining: {report.remaining}")


async def main(args) -> None:
    try:
        async with AsyncSessionLocal() as db:
            report = await backfill_stk_echoes(
                db,
                dry_run=not args.apply,
                reseller_id=args.reseller_id,
                platform_only=args.platform_only,
                unmatched_ids=args.unmatched_id,
                batch_size=args.batch_size,
                limit=args.limit,
            )
        _print_report(report)
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retire STK echoes (C2B copies of STK payments) from the unmatched C2B list."
    )
    parser.add_argument("--apply", action="store_true",
                        help="Write changes. Without this flag, runs in DRY-RUN mode (default).")
    parser.add_argument("--reseller-id", type=int, default=None,
                        help="Only rows assigned to this reseller.")
    parser.add_argument("--platform-only", action="store_true",
                        help="Only the platform-paybill bucket (assigned_reseller_id IS NULL).")
    parser.add_argument("--unmatched-id", type=int, action="append", default=None,
                        help="Only this unmatched_c2b_payments id (repeatable).")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
                        help=f"Rows per transaction (default {DEFAULT_BATCH_SIZE}).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Stop after this many candidates (apply mode).")
    args = parser.parse_args()
    if args.reseller_id is not None and args.platform_only:
        parser.error("--reseller-id and --platform-only are mutually exclusive")
    asyncio.run(main(args))

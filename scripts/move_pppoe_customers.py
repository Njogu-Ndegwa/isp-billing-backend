"""
CLI: move PPPoE customers from one router to another without changing billing state.

By default, apply mode first provisions active PPPoE customers on the target
router, then updates customers.router_id and related retry/FUP watcher router
pointers. It does not remove old secrets, activate inactive customers, or
change expiry/payment/account state.

Preview:
    python scripts/move_pppoe_customers.py --source-router-id 12 --target-router-id 34

Apply:
    python scripts/move_pppoe_customers.py --source-router-id 12 --target-router-id 34 --apply
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import AsyncSessionLocal, async_engine
from app.services.pppoe_router_transfer import transfer_pppoe_customers_between_routers


def _print_report(report) -> None:
    mode = "DRY-RUN (no writes)" if report.dry_run else "APPLY"
    move_label = "would_move" if report.dry_run else "moved"
    print(f"=== PPPoE router customer transfer: {mode} ===")
    print(f"  source_router:  {report.source_router_id} {report.source_router_name or ''}".rstrip())
    print(f"  target_router:  {report.target_router_id} {report.target_router_name or ''}".rstrip())
    print(f"  active_only:    {report.active_only}")
    print(f"  selected:       {report.selected}")
    print(f"  {move_label}:     {report.moved}")
    print(f"  active:         {report.active}")
    print(f"  inactive:       {report.inactive}")
    print(f"  pending:        {report.pending}")
    print(f"  no_password:    {report.missing_passwords}")
    print(f"  target_update:  {report.target_provision}")
    print(f"  target_needed:  {report.target_provision_required}")
    print(f"  target_skipped: {report.target_provision_skipped}")
    if not report.dry_run:
        print(f"  target_ok:      {report.target_provisioned}")
        print(f"  target_failed:  {report.target_provision_failed}")
        print(f"  fup_watch_rows: {report.usage_watch_states_updated}")
        print(f"  attempts_rows:  {report.provisioning_attempts_updated}")

    if report.warnings:
        print("  warnings:")
        for warning in report.warnings:
            print(f"    - {warning}")

    if report.errors:
        print("  errors:")
        for error in report.errors:
            print(f"    - {error}")

    if report.target_provision_failures:
        print("  target_failures:")
        for failure in report.target_provision_failures[:50]:
            print(
                "    "
                f"id={failure.get('customer_id')} username={failure.get('pppoe_username')} "
                f"error={failure.get('error')}"
            )
        if len(report.target_provision_failures) > 50:
            print(f"    ... {len(report.target_provision_failures) - 50} more")

    if report.samples:
        print("  samples:")
        for sample in report.samples:
            print(
                "    "
                f"id={sample['customer_id']} username={sample['pppoe_username']} "
                f"status={sample['status']} plan_id={sample['plan_id']} "
                f"speed={sample['plan_speed']} expiry={sample['expiry']} "
                f"password_present={sample['password_present']}"
            )


async def main(args) -> int:
    try:
        async with AsyncSessionLocal() as db:
            report = await transfer_pppoe_customers_between_routers(
                db,
                source_router_id=args.source_router_id,
                target_router_id=args.target_router_id,
                dry_run=not args.apply,
                active_only=args.active_only,
                provision_target=not args.skip_target_provision,
                sample_limit=args.sample_limit,
            )
        _print_report(report)
        if report.errors:
            return 2
        if not args.apply:
            print("\nNo rows were written. Re-run with --apply after reviewing this report.")
        return 0
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Move PPPoE customers from one router to another without changing "
            "status, expiry, payments, plans, passwords, or account numbers."
        )
    )
    parser.add_argument("--source-router-id", type=int, required=True)
    parser.add_argument("--target-router-id", type=int, required=True)
    parser.add_argument(
        "--active-only",
        action="store_true",
        help=(
            "Move only active PPPoE customers. Default moves active, inactive, "
            "and pending PPPoE customers so future renewals use the new router."
        ),
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=10,
        help="Number of sample customers to print in the report.",
    )
    parser.add_argument(
        "--skip-target-provision",
        action="store_true",
        help=(
            "DB-only mode. Do not create/update active PPPoE secrets on the target router "
            "before moving customers."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit changes. Without this flag the command runs a dry-run preview.",
    )

    raise SystemExit(asyncio.run(main(parser.parse_args())))

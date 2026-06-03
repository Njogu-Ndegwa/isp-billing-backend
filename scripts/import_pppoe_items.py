"""
CLI: import/transfer PPPoE customers from an items_export workbook.

The command is DB-only. It maps exported users to an existing reseller/router,
preserves Active vs Expired state, preserves expiry, and stores source metadata
in customers.pending_update_data. It does not connect to MikroTik.

By default it imports customers with no PPPoE password. Later router
provisioning will preserve an existing RouterOS secret password when the secret
already exists; it will not invent or overwrite passwords during transfer.

Preview:
    python scripts/import_pppoe_items.py --file items_export_2026-06-03.xlsx --reseller-id 12 --router-id 34

Apply:
    python scripts/import_pppoe_items.py --file items_export_2026-06-03.xlsx --reseller-id 12 --router-id 34 --create-missing-plans --default-plan-price 1000 --apply
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import AsyncSessionLocal, async_engine
from app.services.pppoe_customer_import import (
    import_pppoe_customers,
    normalize_workbook_rows,
    read_pppoe_workbook,
)


def _print_counts(title: str, counts: dict[str, int]) -> None:
    print(f"{title}:")
    for key in sorted(counts):
        print(f"  {key}: {counts[key]}")


def _print_report(report) -> None:
    mode = "DRY-RUN (no writes)" if report.dry_run else "APPLY"
    print(f"=== PPPoE customer import: {mode} ===")
    print(f"  total_rows:      {report.total_rows}")
    print(f"  created:         {report.created}")
    print(f"  updated:         {report.updated}")
    print(f"  skipped:         {report.skipped}")
    print(f"  missing_phone:   {report.missing_phone}")

    if report.created_plans:
        print("  created_plans:")
        for plan in report.created_plans:
            print(
                f"    id={plan['id']} name={plan['name']} speed={plan['speed']} "
                f"price={plan['price']}"
            )

    if report.plan_mappings:
        print("  plan_mappings:")
        for package in sorted(report.plan_mappings):
            print(f"    {package} -> plan_id={report.plan_mappings[package]}")

    if report.warnings:
        print("  warnings:")
        for warning in report.warnings:
            print(f"    - {warning}")

    if report.errors:
        print("  errors:")
        for error in report.errors[:50]:
            print(f"    - {error}")
        if len(report.errors) > 50:
            print(f"    ... {len(report.errors) - 50} more")

    if report.samples:
        print("  samples:")
        for sample in report.samples:
            print(
                f"    {sample['action']} row={sample['row']} username={sample['username']} "
                f"status={sample['status']} plan_id={sample['plan_id']} "
                f"expiry={sample['expiry']}"
            )


def _parse_package_plan(values: list[str] | None) -> dict[str, int]:
    mappings: dict[str, int] = {}
    for value in values or []:
        if "=" not in value:
            raise ValueError(f"--package-plan must look like Package=PLAN_ID, got '{value}'")
        package, plan_id_raw = value.split("=", 1)
        package = package.strip()
        if not package:
            raise ValueError(f"--package-plan has an empty package name: '{value}'")
        try:
            plan_id = int(plan_id_raw.strip())
        except ValueError as exc:
            raise ValueError(f"--package-plan has invalid plan id: '{value}'") from exc
        mappings[package] = plan_id
    return mappings


async def main(args) -> int:
    if args.create_missing_plans and args.default_plan_price <= 0:
        print(
            "--create-missing-plans requires --default-plan-price with a positive price. "
            "Otherwise transferred clients could land on zero-price plans."
        )
        return 2

    records = read_pppoe_workbook(args.file, sheet_name=args.sheet)
    rows, parse_report = normalize_workbook_rows(
        records,
        source_timezone=args.source_timezone,
        password_column=args.password_column,
        default_password=args.default_password,
        password_from=args.password_from,
    )

    if parse_report.errors:
        _print_counts("Statuses", parse_report.statuses)
        _print_counts("Packages", parse_report.packages)
        print("Parse errors:")
        for error in parse_report.errors[:50]:
            print(f"  - {error}")
        if len(parse_report.errors) > 50:
            print(f"  ... {len(parse_report.errors) - 50} more")
        return 2

    try:
        package_plan_ids = _parse_package_plan(args.package_plan)
        async with AsyncSessionLocal() as db:
            report = await import_pppoe_customers(
                db,
                rows,
                reseller_id=args.reseller_id,
                router_id=args.router_id,
                source_file=str(Path(args.file).name),
                dry_run=not args.apply,
                create_missing_plans=args.create_missing_plans,
                default_plan_price=args.default_plan_price,
                reassign_existing=args.reassign_existing,
                package_plan_ids=package_plan_ids,
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
            "Import/transfer PPPoE customers from an items_export .xlsx workbook. "
            "Passwords are left empty unless a password option is explicitly supplied."
        )
    )
    parser.add_argument("--file", required=True, help="Path to items_export .xlsx")
    parser.add_argument("--sheet", default="Items", help="Workbook sheet name")
    parser.add_argument("--reseller-id", type=int, required=True, help="Target reseller user ID")
    parser.add_argument("--router-id", type=int, required=True, help="Target router ID")
    parser.add_argument(
        "--source-timezone",
        default="Africa/Nairobi",
        help="Timezone used by workbook expiry values before storing as UTC",
    )
    parser.add_argument(
        "--create-missing-plans",
        action="store_true",
        help="Create missing PPPoE plans from package names using parsed speed",
    )
    parser.add_argument(
        "--default-plan-price",
        type=int,
        default=0,
        help="Price for auto-created plans. Existing plans keep their configured price.",
    )
    parser.add_argument(
        "--password-column",
        default=None,
        help="Optional workbook column containing PPPoE passwords. Default: leave passwords empty.",
    )
    parser.add_argument(
        "--default-password",
        default=None,
        help="Optional fixed password for imported rows. Avoid this for existing live secrets.",
    )
    parser.add_argument(
        "--password-from",
        choices=["username", "phone"],
        default=None,
        help="Optional derived password source. Avoid this for existing live secrets.",
    )
    parser.add_argument(
        "--reassign-existing",
        action="store_true",
        help="Move existing matching usernames from another reseller/router to the target.",
    )
    parser.add_argument(
        "--package-plan",
        action="append",
        default=[],
        metavar="PACKAGE=PLAN_ID",
        help=(
            "Explicit package-to-plan mapping. Repeat for package names that "
            "should not be matched by speed or exact name."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit changes. Without this flag the command runs a dry-run preview.",
    )

    raise SystemExit(asyncio.run(main(parser.parse_args())))

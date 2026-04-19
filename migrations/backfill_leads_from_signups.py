"""
Migration: Backfill Lead records for resellers who signed up while the
`leads` table did not yet exist (or while the auto-linking hook was
silently failing).

The actual logic lives in `app.services.lead_backfill` and is shared
with the admin endpoint `POST /api/leads/backfill` so the CLI and the
API always behave identically.

Usage
-----
    # Preview what would happen (no writes)
    python migrations/backfill_leads_from_signups.py --dry-run

    # Run for real, default cutoff (2026-04-16)
    python migrations/backfill_leads_from_signups.py

    # Custom cutoff
    python migrations/backfill_leads_from_signups.py --since 2026-04-10

    # No cutoff — look at every existing reseller
    python migrations/backfill_leads_from_signups.py --since all
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime, date
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import async_engine, AsyncSessionLocal  # type: ignore
from app.services.lead_backfill import backfill_leads


DEFAULT_SINCE = date(2026, 4, 16)


def _print_report(result) -> None:
    print(
        f"Found {result.candidates} reseller(s) to backfill"
        f"{f' since {result.since}' if result.since else ''} "
        f"(owner admin={result.admin_owner_email}, source={result.source_name})."
    )
    print("-" * 72)
    for item in result.items:
        print(
            f"  [{item.signup_date or '????-??-??'}] "
            f"user_id={item.user_id:<5} "
            f"{(item.email or '(no email)'):<40} "
            f"-> stage={item.stage:<18} ({item.reason})"
        )
    print("-" * 72)
    print(result.message)
    if result.stage_counts:
        print("Summary by inferred stage:")
        for stage, count in sorted(result.stage_counts.items()):
            print(f"  {stage:<18} {count}")


async def main(since: Optional[date], dry_run: bool) -> None:
    try:
        async with AsyncSessionLocal() as db:
            result = await backfill_leads(db, since=since, dry_run=dry_run)
            if dry_run:
                await db.rollback()
            else:
                await db.commit()
        _print_report(result)
    finally:
        await async_engine.dispose()


def _parse_since(s: str) -> Optional[date]:
    if s.lower() == "all":
        return None
    return datetime.strptime(s, "%Y-%m-%d").date()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Backfill Lead rows for resellers who signed up before "
                    "the lead-pipeline tables existed or while auto-linking "
                    "was failing."
    )
    parser.add_argument(
        "--since",
        type=_parse_since,
        default=DEFAULT_SINCE,
        help="Only consider resellers whose users.created_at >= this date "
             "(YYYY-MM-DD). Pass 'all' for no cutoff. Default: 2026-04-16.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan without writing to the database.",
    )
    args = parser.parse_args()

    asyncio.run(main(since=args.since, dry_run=args.dry_run))

"""Reprice selected open subscription invoices to the trailing 30-day window.

Dry-run is the default. Pass ``--apply`` only after reviewing the printed
before/after values. Paid and waived invoices are never changed by this tool.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select

from app.db.database import AsyncSessionLocal, async_engine
from app.db.models import InvoiceStatus, SubscriptionInvoice
from app.services.subscription import (
    HOTSPOT_RATE,
    MINIMUM_CHARGE,
    calculate_reseller_charges,
    cap_invoice_period_start,
)


OPEN_STATUSES = (InvoiceStatus.PENDING, InvoiceStatus.OVERDUE)


def repaired_charge_fields(invoice: SubscriptionInvoice, hotspot_revenue: float) -> dict:
    """Reprice hotspot revenue without changing the invoice's PPPoE snapshot."""
    hotspot_charge = round(hotspot_revenue * HOTSPOT_RATE, 2)
    gross_charge = round(hotspot_charge + invoice.pppoe_charge, 2)
    return {
        "hotspot_revenue": hotspot_revenue,
        "hotspot_charge": hotspot_charge,
        "gross_charge": gross_charge,
        "final_charge": max(gross_charge, MINIMUM_CHARGE),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--invoice-id",
        type=int,
        action="append",
        required=True,
        dest="invoice_ids",
        help="Open invoice to inspect or repair. Repeat for multiple invoices.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit the recalculated 30-day periods and charges.",
    )
    return parser.parse_args()


async def run(invoice_ids: list[int], apply: bool) -> list[dict]:
    results = []
    async with AsyncSessionLocal() as db:
        invoices = list((await db.execute(
            select(SubscriptionInvoice)
            .where(SubscriptionInvoice.id.in_(invoice_ids))
            .order_by(SubscriptionInvoice.id)
            .with_for_update()
        )).scalars().all())

        found_ids = {invoice.id for invoice in invoices}
        missing = sorted(set(invoice_ids) - found_ids)
        if missing:
            raise RuntimeError(f"Invoice(s) not found: {missing}")

        for invoice in invoices:
            if invoice.status not in OPEN_STATUSES:
                raise RuntimeError(
                    f"Invoice #{invoice.id} is {invoice.status.value}; only open invoices can be repaired"
                )

            new_start = cap_invoice_period_start(invoice.period_start, invoice.period_end)
            current_window = await calculate_reseller_charges(
                db, invoice.user_id, new_start, invoice.period_end
            )
            charges = repaired_charge_fields(
                invoice, current_window["hotspot_revenue"]
            )
            result = {
                "invoice_id": invoice.id,
                "user_id": invoice.user_id,
                "old_period_start": invoice.period_start.isoformat(),
                "new_period_start": new_start.isoformat(),
                "period_end": invoice.period_end.isoformat(),
                "old_hotspot_revenue": invoice.hotspot_revenue,
                "new_hotspot_revenue": charges["hotspot_revenue"],
                "old_final_charge": invoice.final_charge,
                "new_final_charge": charges["final_charge"],
                "difference": round(invoice.final_charge - charges["final_charge"], 2),
            }
            results.append(result)

            if apply:
                invoice.period_start = new_start
                invoice.hotspot_revenue = charges["hotspot_revenue"]
                invoice.hotspot_charge = charges["hotspot_charge"]
                invoice.gross_charge = charges["gross_charge"]
                invoice.final_charge = charges["final_charge"]

        if apply:
            await db.commit()
        else:
            await db.rollback()

    return results


async def main() -> None:
    args = parse_args()
    try:
        results = await run(args.invoice_ids, args.apply)
        print(json.dumps({"applied": args.apply, "invoices": results}, indent=2))
    finally:
        await async_engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())

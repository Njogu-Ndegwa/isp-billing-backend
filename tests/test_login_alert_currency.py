"""The subscription alert returned at login states amounts in the invoice's
own currency (a USD 10 invoice must never read "KES 10")."""

from datetime import datetime, timedelta

import pytest

from app.db.models import InvoiceStatus, SubscriptionInvoice, SubscriptionStatus
from app.services.subscription import format_money, get_invoice_alert_for_user
from tests.factories import make_reseller


async def _due_soon_invoice(db, reseller, amount, currency):
    due = datetime.utcnow() + timedelta(days=2, hours=12)
    db.add(SubscriptionInvoice(
        user_id=reseller.id, period_start=datetime(2026, 8, 23), period_end=datetime(2026, 9, 18),
        gross_charge=amount, final_charge=amount, currency=currency,
        status=InvoiceStatus.PENDING, due_date=due,
    ))
    await db.commit()


@pytest.mark.asyncio
async def test_usd_invoice_alert_says_usd(db):
    reseller = await make_reseller(db, market_code="CM", subscription_status=SubscriptionStatus.TRIAL,
                                   subscription_expires_at=datetime.utcnow() + timedelta(days=3))
    await _due_soon_invoice(db, reseller, 10.0, "USD")

    alert = await get_invoice_alert_for_user(db, reseller.id)

    assert "USD 10.00" in alert["message"]
    assert "KES" not in alert["message"]
    assert alert["current_invoice"]["currency"] == "USD"


@pytest.mark.asyncio
async def test_kenyan_alert_unchanged(db):
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE,
                                   subscription_expires_at=datetime.utcnow() + timedelta(days=3))
    await _due_soon_invoice(db, reseller, 1500.0, "KES")

    alert = await get_invoice_alert_for_user(db, reseller.id)

    assert "invoice of KES 1,500 is due in 2 days." in alert["message"]


def test_format_money():
    assert format_money(10, "USD") == "USD 10.00"
    assert format_money(1500, "KES") == "KES 1,500"
    assert format_money(159140, "XAF") == "XAF 159,140"
    assert format_money(500, None) == "KES 500"

"""Bitwave earnings vs transaction volume (app/services/platform_earnings.py).

Every income stream gets a fixture of its own, plus the edge cases that make
the numbers lie when they are wrong: waived invoices, refunded / failed /
pending payments, free-trial and no-payment activations (KES 0, not revenue),
SMS credits that were granted or refunded rather than sold, our own reseller
accounts, and the period windows.
"""

from datetime import date, datetime, time, timedelta

import pytest
import pytest_asyncio
import time_machine
from httpx import ASGITransport, AsyncClient

from app.db.models import (
    CollectionMode,
    CustomerPayment,
    InvoiceStatus,
    PaymentMethod,
    PaymentStatus,
    ResellerTransactionCharge,
    ShopOrder,
    ShopOrderPaymentStatus,
    SmsCreditOrder,
    SmsCreditOrderStatus,
    SmsCreditTxnKind,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
)
from app.services import admin_metrics, sms_credits
from app.services import platform_earnings as svc
from app.services.markets import PAYSTACK_PROCESSING_FEE_RATE, kes_per_unit
from tests.factories import make_admin, make_reseller

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def _clear_cache():
    from app.core.cache import cache

    await cache.clear_pattern(svc.PLATFORM_EARNINGS_CACHE_PREFIX)
    yield
    await cache.clear_pattern(svc.PLATFORM_EARNINGS_CACHE_PREFIX)


# Windows are calendar periods-to-date; derive timestamps from them so the
# tests hold on every day of the year (the 1st included).

def _now_in(period: str = "month") -> datetime:
    w = svc.windows_for(period)
    return datetime.combine((w.cur_end - timedelta(days=1)).date(), time(12))


def _prev_in(period: str = "month") -> datetime:
    w = svc.windows_for(period)
    return w.prev_start + timedelta(hours=12)


def _before(period: str = "month") -> datetime:
    w = svc.windows_for(period)
    return w.prev_start - timedelta(days=10)


async def _customer_payment(db, reseller_id, amount, *, at=None,
                            method=PaymentMethod.MOBILE_MONEY,
                            mode=CollectionMode.SYSTEM_COLLECTED,
                            counts_as_revenue=True,
                            status=PaymentStatus.COMPLETED):
    db.add(CustomerPayment(
        customer_id=None, reseller_id=reseller_id, amount=amount,
        payment_method=method, collection_mode=mode, days_paid_for=30,
        counts_as_revenue=counts_as_revenue, status=status,
        created_at=at or _now_in(),
    ))
    await db.commit()


async def _invoice(db, user_id, *, hotspot=0.0, per_user=0.0, final=None,
                   status=InvoiceStatus.PAID, at=None, currency="KES"):
    gross = hotspot + per_user
    created = at or _now_in()
    invoice = SubscriptionInvoice(
        user_id=user_id,
        period_start=created - timedelta(days=30),
        period_end=created,
        hotspot_charge=hotspot,
        pppoe_charge=per_user,
        gross_charge=gross,
        final_charge=gross if final is None else final,
        currency=currency,
        status=status,
        due_date=created + timedelta(days=5),
        created_at=created,
    )
    db.add(invoice)
    await db.commit()
    await db.refresh(invoice)
    return invoice


async def _sub_payment(db, user_id, amount, *, invoice=None, at=None,
                       status=SubscriptionPaymentStatus.COMPLETED,
                       method="mpesa", currency="KES"):
    db.add(SubscriptionPayment(
        invoice_id=invoice.id if invoice else None, user_id=user_id,
        amount=amount, payment_method=method, currency=currency,
        status=status, created_at=at or _now_in(),
    ))
    await db.commit()


async def _sms_order(db, user_id, amount, *, status=SmsCreditOrderStatus.COMPLETED, at=None):
    db.add(SmsCreditOrder(
        user_id=user_id, quantity=amount, unit_price=1, amount=amount,
        phone_number="254700000000", status=status, created_at=at or _now_in(),
    ))
    await db.commit()


# ---------------------------------------------------------------------------
# Transaction volume
# ---------------------------------------------------------------------------

async def test_volume_sums_every_resellers_customer_payments_with_a_split(db):
    a = await make_reseller(db)
    b = await make_reseller(db)
    await _customer_payment(db, a.id, 1_000)  # collected on the system paybill
    await _customer_payment(db, b.id, 400, mode=CollectionMode.DIRECT)
    await _customer_payment(db, b.id, 100, method=PaymentMethod.CASH, mode=None)

    volume = (await svc.compute_platform_earnings(db, "month"))["transaction_volume"]

    assert volume["total"] == 1_500
    assert volume["payments"] == 3
    assert volume["mpesa_platform_collected"] == 1_000
    assert volume["mpesa_direct_settled"] == 400
    assert volume["recorded_manually"] == 100


async def test_volume_excludes_no_payment_activations_and_refunds(db):
    r = await make_reseller(db)
    await _customer_payment(db, r.id, 500)
    # Free trial / "activate without payment" / compensation: KES 0, not revenue.
    await _customer_payment(db, r.id, 0, method=PaymentMethod.CASH, counts_as_revenue=False)
    await _customer_payment(db, r.id, 300, method=PaymentMethod.CASH, counts_as_revenue=False)
    await _customer_payment(db, r.id, 200, status=PaymentStatus.REFUNDED)
    await _customer_payment(db, r.id, 200, status=PaymentStatus.FAILED)

    volume = (await svc.compute_platform_earnings(db, "month"))["transaction_volume"]

    assert volume["total"] == 500
    assert volume["payments"] == 1


async def test_volume_is_not_earnings(db):
    """The whole point: GMV through the platform is not Bitwave's income."""
    r = await make_reseller(db)
    await _customer_payment(db, r.id, 10_000)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["transaction_volume"]["total"] == 10_000
    assert result["earnings"]["total"] == 0
    assert result["take_rate_percent"] == 0


# ---------------------------------------------------------------------------
# Subscription fees (collected)
# ---------------------------------------------------------------------------

def _streams(result):
    return {s["key"]: s["total"] for s in result["earnings"]["streams"]}


async def test_subscription_payment_splits_into_commission_per_user_and_minimum(db):
    r = await make_reseller(db)
    # 3% of 10,000 hotspot = 300, 4 users x 25 = 100, topped up to the 500 minimum.
    inv = await _invoice(db, r.id, hotspot=300, per_user=100, final=500)
    await _sub_payment(db, r.id, 500, invoice=inv)

    result = await svc.compute_platform_earnings(db, "month")
    streams = _streams(result)

    assert streams["subscription_hotspot"] == 300
    assert streams["subscription_per_user"] == 100
    assert streams["subscription_minimum"] == 100
    assert result["earnings"]["subscriptions"] == 500
    assert result["earnings"]["total"] == 500


async def test_flat_fee_invoice_is_all_minimum_fee(db):
    r = await make_reseller(db, market_code="CM")
    inv = await _invoice(db, r.id, final=20, currency="USD")
    await _sub_payment(db, r.id, 20, invoice=inv, currency="USD")

    streams = _streams(await svc.compute_platform_earnings(db, "month"))

    assert streams["subscription_minimum"] == pytest.approx(20 * kes_per_unit("USD"))
    assert streams["subscription_hotspot"] == 0
    assert streams["subscription_per_user"] == 0


async def test_partial_payment_takes_its_share_of_each_line(db):
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=600, per_user=200, final=800)
    await _sub_payment(db, r.id, 400, invoice=inv)

    streams = _streams(await svc.compute_platform_earnings(db, "month"))

    assert streams["subscription_hotspot"] == 300
    assert streams["subscription_per_user"] == 100
    assert streams["subscription_minimum"] == 0


async def test_card_payments_are_counted_net_of_the_processing_fee(db):
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=10, final=10, currency="USD")
    await _sub_payment(db, r.id, 10, invoice=inv, method="card", currency="USD")

    total = (await svc.compute_platform_earnings(db, "month"))["earnings"]["total"]

    assert total == pytest.approx(10 * kes_per_unit("USD") * (1 - PAYSTACK_PROCESSING_FEE_RATE), abs=0.01)


async def test_payment_without_invoice_is_reported_as_unattributed(db):
    r = await make_reseller(db)
    await _sub_payment(db, r.id, 700)

    result = await svc.compute_platform_earnings(db, "month")

    assert _streams(result)["subscription_unattributed"] == 700
    assert result["earnings"]["total"] == 700


async def test_unattributed_line_is_hidden_when_empty(db):
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=50, final=50)
    await _sub_payment(db, r.id, 50, invoice=inv)

    keys = set(_streams(await svc.compute_platform_earnings(db, "month")))

    assert "subscription_unattributed" not in keys
    assert {"subscription_hotspot", "subscription_per_user",
            "subscription_minimum", "sms_credits"} <= keys


async def test_pending_and_failed_subscription_payments_are_not_earnings(db):
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=500, final=500, status=InvoiceStatus.PENDING)
    await _sub_payment(db, r.id, 500, invoice=inv, status=SubscriptionPaymentStatus.PENDING)
    await _sub_payment(db, r.id, 500, invoice=inv, status=SubscriptionPaymentStatus.FAILED)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["total"] == 0
    assert result["invoiced"]["total"] == 500
    assert result["invoiced"]["outstanding"] == 500


# ---------------------------------------------------------------------------
# SMS credit sales
# ---------------------------------------------------------------------------

async def test_completed_sms_orders_are_sales(db):
    r = await make_reseller(db)
    await _sms_order(db, r.id, 250)
    await _sms_order(db, r.id, 100, status=SmsCreditOrderStatus.PENDING)
    await _sms_order(db, r.id, 100, status=SmsCreditOrderStatus.FAILED)
    await _sms_order(db, r.id, 100, status=SmsCreditOrderStatus.EXPIRED)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["sms_credits"] == 250
    assert result["earnings"]["sms_orders"] == 1
    assert _streams(result)["sms_credits"] == 250
    assert result["earnings"]["total"] == 250


async def test_granted_and_refunded_sms_credits_are_not_sales(db):
    r = await make_reseller(db)
    await sms_credits.grant(db, r.id, 500, SmsCreditTxnKind.ADMIN_ADJUSTMENT)
    assert await sms_credits.try_deduct(db, r.id, 100) is True
    await sms_credits.refund(db, r.id, 40)
    await db.commit()

    assert (await svc.compute_platform_earnings(db, "month"))["earnings"]["total"] == 0


# ---------------------------------------------------------------------------
# Invoiced vs collected
# ---------------------------------------------------------------------------

async def test_waived_invoices_are_not_invoiced_earnings(db):
    r = await make_reseller(db)
    await _invoice(db, r.id, hotspot=900, final=900, status=InvoiceStatus.WAIVED)
    await _invoice(db, r.id, hotspot=200, per_user=100, final=500,
                   status=InvoiceStatus.PENDING, at=_now_in() - timedelta(hours=1))

    invoiced = (await svc.compute_platform_earnings(db, "month"))["invoiced"]

    assert invoiced["total"] == 500
    assert invoiced["invoices"] == 1
    assert invoiced["subscription_hotspot"] == 200
    assert invoiced["subscription_per_user"] == 100
    assert invoiced["subscription_minimum"] == 200
    assert invoiced["waived"] == 900
    assert invoiced["waived_invoices"] == 1


async def test_a_partial_payment_on_a_waived_invoice_is_still_collected(db):
    """The cash arrived even though the rest was written off."""
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=800, final=800, status=InvoiceStatus.WAIVED)
    await _sub_payment(db, r.id, 300, invoice=inv)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["total"] == 300
    assert result["invoiced"]["total"] == 0
    assert result["invoiced"]["paid_so_far"] == 0


async def test_invoiced_reports_paid_so_far_and_outstanding(db):
    r = await make_reseller(db)
    inv = await _invoice(db, r.id, hotspot=1_000, final=1_000, status=InvoiceStatus.PENDING,
                         at=_now_in() - timedelta(hours=2))
    await _sub_payment(db, r.id, 600, invoice=inv)

    invoiced = (await svc.compute_platform_earnings(db, "month"))["invoiced"]

    assert invoiced["total"] == 1_000
    assert invoiced["paid_so_far"] == 600
    assert invoiced["outstanding"] == 400


async def test_collected_counts_payments_for_invoices_issued_earlier(db):
    """Cash basis: a late payment is earned when it arrives."""
    r = await make_reseller(db)
    old = await _invoice(db, r.id, hotspot=400, final=400, at=_before())
    await _sub_payment(db, r.id, 400, invoice=old)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["total"] == 400
    assert result["invoiced"]["total"] == 0


# ---------------------------------------------------------------------------
# Own accounts, take rate, what is not counted
# ---------------------------------------------------------------------------

async def test_own_reseller_accounts_are_volume_but_not_earnings(db):
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await admin_metrics.set_own_reseller_ids(db, [mine.id])
    await _customer_payment(db, mine.id, 2_000)
    await _sub_payment(db, mine.id, 500)
    await _sms_order(db, mine.id, 100)
    await _invoice(db, mine.id, hotspot=500, final=500)
    await _sub_payment(db, other.id, 250)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["transaction_volume"]["total"] == 2_000
    assert result["earnings"]["total"] == 250
    assert result["invoiced"]["total"] == 0
    assert [a["id"] for a in result["excluded_own_accounts"]] == [mine.id]


async def test_take_rate_is_earnings_over_volume(db):
    r = await make_reseller(db)
    await _customer_payment(db, r.id, 20_000)
    inv = await _invoice(db, r.id, hotspot=600, final=600)
    await _sub_payment(db, r.id, 600, invoice=inv)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["take_rate_percent"] == 3.0


async def test_take_rate_is_null_without_volume(db):
    r = await make_reseller(db)
    await _sms_order(db, r.id, 100)

    assert (await svc.compute_platform_earnings(db, "month"))["take_rate_percent"] is None


async def test_shop_sales_and_transaction_charges_are_reported_but_not_earnings(db):
    admin = await make_admin(db)
    r = await make_reseller(db)
    db.add(ShopOrder(
        order_number="BW-0001", user_id=r.id, buyer_name="Buyer",
        buyer_phone="254700000000", total_amount=3_500,
        payment_status=ShopOrderPaymentStatus.PAID, created_at=_now_in(),
    ))
    db.add(ShopOrder(
        order_number="BW-0002", user_id=r.id, buyer_name="Buyer",
        buyer_phone="254700000000", total_amount=9_999,
        payment_status=ShopOrderPaymentStatus.UNPAID, created_at=_now_in(),
    ))
    db.add(ResellerTransactionCharge(
        reseller_id=r.id, amount=33, description="M-Pesa B2B transfer fee",
        created_by=admin.id, created_at=_now_in(),
    ))
    await db.commit()

    result = await svc.compute_platform_earnings(db, "month")

    assert result["not_counted"] == {"shop_sales": 3_500, "reseller_transaction_charges": 33}
    assert result["earnings"]["total"] == 0


# ---------------------------------------------------------------------------
# Period windows
# ---------------------------------------------------------------------------

async def test_previous_window_drives_change_percent(db):
    r = await make_reseller(db)
    await _sub_payment(db, r.id, 200, at=_prev_in())
    await _sub_payment(db, r.id, 300)
    await _customer_payment(db, r.id, 1_000, at=_prev_in())
    await _customer_payment(db, r.id, 2_000)

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["total"] == 300
    assert result["earnings"]["previous_total"] == 200
    assert result["earnings"]["change_percent"] == 50.0
    assert result["transaction_volume"]["previous_total"] == 1_000
    assert result["transaction_volume"]["change_percent"] == 100.0


async def test_money_outside_both_windows_is_ignored(db):
    r = await make_reseller(db)
    await _sub_payment(db, r.id, 999, at=_before())
    await _sms_order(db, r.id, 999, at=_before())
    await _customer_payment(db, r.id, 999, at=_before())

    result = await svc.compute_platform_earnings(db, "month")

    assert result["earnings"]["total"] == 0
    assert result["earnings"]["previous_total"] == 0
    assert result["transaction_volume"]["total"] == 0


@pytest.mark.parametrize("chip,period", [("7d", "week"), ("30d", "month"), ("90d", "quarter"), ("1y", "year")])
async def test_dashboard_chips_map_to_calendar_periods(db, chip, period):
    result = await svc.compute_platform_earnings(db, chip)

    assert result["period"] == period
    assert result["start_date"] == svc.windows_for(period).cur_start.date().isoformat()


async def test_unknown_period_falls_back_to_month(db):
    assert (await svc.compute_platform_earnings(db, "decade"))["period"] == "month"


async def test_year_window_includes_earlier_months(db):
    r = await make_reseller(db)
    w = svc.windows_for("year")
    await _sms_order(db, r.id, 120, at=w.cur_start + timedelta(hours=1))

    assert (await svc.compute_platform_earnings(db, "year"))["earnings"]["total"] == 120


@pytest.mark.parametrize("today", [date(2026, 3, 31), date(2026, 10, 31), date(2026, 12, 31)])
async def test_previous_window_never_overlaps_the_current_one(today):
    """On the 31st the previous month is shorter than the elapsed span."""
    with time_machine.travel(datetime.combine(today, time(9)), tick=False):
        for period in admin_metrics.EARNINGS_PERIODS:
            prev_start, prev_end, cur_start, _ = admin_metrics._earnings_windows(period)
            assert prev_start < prev_end <= cur_start, period


async def test_repeat_loads_are_cached(db):
    r = await make_reseller(db)
    await _sms_order(db, r.id, 100)
    first = await svc.compute_platform_earnings(db, "month")
    await _sms_order(db, r.id, 100)

    assert (await svc.compute_platform_earnings(db, "month")) == first


# ---------------------------------------------------------------------------
# Route: admin only
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(engine):
    import main

    async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as c:
        yield c


def _bearer(user) -> dict:
    from app.services.auth import create_access_token

    claims = {
        "sub": str(user.id), "user_code": user.user_code, "user_id": user.id,
        "role": user.role.value, "organization_name": user.organization_name,
    }
    return {"Authorization": f"Bearer {create_access_token(claims, timedelta(minutes=30))}"}


async def test_route_is_admin_only(db, client):
    reseller = await make_reseller(db)

    resp = await client.get("/api/admin/metrics/platform-earnings", headers=_bearer(reseller))

    assert resp.status_code == 403


async def test_route_returns_volume_and_earnings_for_admins(db, client):
    admin = await make_admin(db)
    r = await make_reseller(db)
    await _customer_payment(db, r.id, 5_000)
    await _sms_order(db, r.id, 150)

    resp = await client.get(
        "/api/admin/metrics/platform-earnings?period=30d", headers=_bearer(admin),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["period"] == "month"
    assert body["transaction_volume"]["total"] == 5_000
    assert body["earnings"]["total"] == 150
    assert body["take_rate_percent"] == 3.0

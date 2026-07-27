"""Tests for the combined admin earnings metric.

Covers the two revenue streams the admin actually earns from:
  1. SaaS charges other resellers pay us, split hotspot vs PPPoE by invoice
  2. Gross collections of the reseller accounts the admin runs themselves

TDD order:
  1. own-reseller ID setting round-trips and rejects non-resellers
  2. SaaS payments split pro-rata across the invoice's charge lines
  3. unattributed SaaS payments land in "other" and surface the band
  4. own-account collections form their own stream
  5. our own subscription payments are excluded (paying ourselves isn't income)
  6. compensation vouchers (counts_as_revenue=False) are excluded
  7. window/granularity resolution
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import (
    CustomerPayment,
    PaymentMethod,
    SubscriptionInvoice,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    InvoiceStatus,
)
from app.services import admin_metrics as svc
from tests.factories import make_reseller

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def _clear_earnings_cache():
    """compute_earnings memoises by period, and the cache is process-wide."""
    from app.core.cache import cache

    await cache.clear_pattern(svc.EARNINGS_CACHE_PREFIX)
    yield
    await cache.clear_pattern(svc.EARNINGS_CACHE_PREFIX)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

async def _add_invoice(db, user_id, *, hotspot_charge, pppoe_charge, period_start):
    invoice = SubscriptionInvoice(
        user_id=user_id,
        period_start=period_start,
        period_end=period_start + timedelta(days=30),
        hotspot_charge=hotspot_charge,
        pppoe_charge=pppoe_charge,
        gross_charge=hotspot_charge + pppoe_charge,
        final_charge=hotspot_charge + pppoe_charge,
        status=InvoiceStatus.PAID,
        due_date=period_start + timedelta(days=35),
    )
    db.add(invoice)
    await db.commit()
    await db.refresh(invoice)
    return invoice


async def _add_saas_payment(db, user_id, amount, *, invoice=None, days_ago=1,
                            status=SubscriptionPaymentStatus.COMPLETED):
    payment = SubscriptionPayment(
        invoice_id=invoice.id if invoice else None,
        user_id=user_id,
        amount=amount,
        payment_method="mpesa",
        status=status,
        created_at=datetime.utcnow() - timedelta(days=days_ago),
    )
    db.add(payment)
    await db.commit()
    return payment


async def _add_customer_payment(db, reseller_id, amount, *, days_ago=1,
                                counts_as_revenue=True):
    payment = CustomerPayment(
        customer_id=None,
        reseller_id=reseller_id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=30,
        counts_as_revenue=counts_as_revenue,
        created_at=datetime.utcnow() - timedelta(days=days_ago),
    )
    db.add(payment)
    await db.commit()
    return payment


# ---------------------------------------------------------------------------
# 1. Own-reseller account setting
# ---------------------------------------------------------------------------

async def test_own_reseller_ids_default_to_empty(db):
    assert await svc.get_own_reseller_ids(db) == []


async def test_own_reseller_ids_round_trip(db):
    mine = await make_reseller(db)
    saved, rejected = await svc.set_own_reseller_ids(db, [mine.id])

    assert saved == [mine.id]
    assert rejected == []
    assert await svc.get_own_reseller_ids(db) == [mine.id]


async def test_non_reseller_ids_are_reported_not_swallowed(db):
    """A silently dropped ID looks exactly like "never configured"."""
    mine = await make_reseller(db)
    saved, rejected = await svc.set_own_reseller_ids(db, [mine.id, 999_999])

    assert saved == [mine.id]
    assert rejected == [999_999]


async def test_an_admin_account_is_rejected_as_an_own_reseller(db):
    """The likeliest real cause: picking an account whose role isn't RESELLER."""
    from app.db.models import UserRole

    admin = await make_reseller(db, role=UserRole.ADMIN)
    saved, rejected = await svc.set_own_reseller_ids(db, [admin.id])

    assert saved == []
    assert rejected == [admin.id]


async def test_get_own_reseller_ids_survives_malformed_setting(db):
    from app.services.app_settings import set_setting

    await set_setting(db, svc.OWN_RESELLER_IDS_SETTING, "not-json")
    assert await svc.get_own_reseller_ids(db) == []


# ---------------------------------------------------------------------------
# 2. SaaS stream split
# ---------------------------------------------------------------------------

async def test_saas_payment_splits_pro_rata_across_invoice_charges(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=30, pppoe_charge=70,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["saas_hotspot"] == 30
    assert result["totals"]["saas_pppoe"] == 70
    assert result["totals"]["system"] == 100
    assert result["totals"]["combined"] == 100


async def test_partial_payment_splits_proportionally(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=300, pppoe_charge=100,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    # Only half the invoice paid — each line should take half.
    await _add_saas_payment(db, other.id, 200, invoice=invoice, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["saas_hotspot"] == 150
    assert result["totals"]["saas_pppoe"] == 50


async def test_pending_saas_payments_are_ignored(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=50, pppoe_charge=50,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(
        db, other.id, 100, invoice=invoice, days_ago=2,
        status=SubscriptionPaymentStatus.PENDING,
    )

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["system"] == 0


# ---------------------------------------------------------------------------
# 3. Unattributed SaaS payments
# ---------------------------------------------------------------------------

async def test_payment_without_invoice_falls_to_other_and_shows_band(db):
    other = await make_reseller(db)
    await _add_saas_payment(db, other.id, 500, invoice=None, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["saas_other"] == 500
    assert result["totals"]["system"] == 500
    assert "saas_other" in {s["key"] for s in result["streams"]}


async def test_other_band_is_hidden_when_everything_is_attributed(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=10, pppoe_charge=10,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 20, invoice=invoice, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")

    assert "saas_other" not in {s["key"] for s in result["streams"]}


# ---------------------------------------------------------------------------
# 4-5. Own reseller stream
# ---------------------------------------------------------------------------

async def test_own_account_collections_form_their_own_stream(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, mine.id, 4_500, days_ago=3)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["reseller"] == 4_500
    assert result["totals"]["combined"] == 4_500
    assert result["own_reseller_accounts"][0]["id"] == mine.id


async def test_other_resellers_collections_are_not_our_revenue(db):
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, other.id, 9_000, days_ago=3)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["reseller"] == 0


async def test_our_own_subscription_payments_are_excluded(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    invoice = await _add_invoice(
        db, mine.id, hotspot_charge=100, pppoe_charge=0,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, mine.id, 100, invoice=invoice, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["system"] == 0
    assert result["all_time"]["system"] == 0


async def test_compensation_vouchers_are_excluded_from_own_collections(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, mine.id, 1_000, days_ago=3)
    await _add_customer_payment(db, mine.id, 250, days_ago=3, counts_as_revenue=False)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["reseller"] == 1_000


# ---------------------------------------------------------------------------
# 6. Series shape and windowing
# ---------------------------------------------------------------------------

async def test_series_stacks_streams_into_a_running_total(db):
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=40, pppoe_charge=60,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, days_ago=2)
    await _add_customer_payment(db, mine.id, 900, days_ago=2)

    result = await svc.compute_earnings(db, period="30d")
    populated = [p for p in result["series"] if p["total"] > 0]

    assert len(populated) == 1
    point = populated[0]
    assert point["saas_hotspot"] == 40
    assert point["saas_pppoe"] == 60
    assert point["reseller"] == 900
    assert point["total"] == 1_000
    assert result["series"][-1]["cumulative_total"] == 1_000


async def test_payments_outside_the_window_are_excluded(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=10, pppoe_charge=0,
        period_start=datetime.utcnow() - timedelta(days=90),
    )
    await _add_saas_payment(db, other.id, 10, invoice=invoice, days_ago=45)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["system"] == 0
    # Still counted in the lifetime figure.
    assert result["all_time"]["system"] == 10


async def test_previous_period_drives_change_percent(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=100, pppoe_charge=0,
        period_start=datetime.utcnow() - timedelta(days=60),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, days_ago=40)
    await _add_saas_payment(db, other.id, 150, invoice=invoice, days_ago=5)

    result = await svc.compute_earnings(db, period="30d")

    assert result["totals"]["system"] == 150
    assert result["previous_totals"]["system"] == 100
    assert result["change_percent"]["system"] == 50.0


@pytest.mark.parametrize(
    "period,days,expected_span,expected_granularity",
    [
        ("7d", None, 7, "day"),
        ("30d", None, 30, "day"),
        ("90d", None, 90, "week"),
        ("1y", None, 365, "month"),
        ("30d", 14, 14, "day"),      # explicit days wins over period
        ("7d", 400, 400, "month"),
    ],
)
async def test_window_and_granularity_resolution(
    db, period, days, expected_span, expected_granularity,
):
    result = await svc.compute_earnings(db, period=period, days=days)

    assert result["days"] == expected_span
    assert result["granularity"] == expected_granularity


async def test_custom_day_window_is_clamped(db):
    result = await svc.compute_earnings(db, period="30d", days=5_000)
    assert result["days"] == 1_095


# ---------------------------------------------------------------------------
# 7. Query cost — this runs against a resource-constrained DB
# ---------------------------------------------------------------------------

class _CountingSession:
    """Proxies an AsyncSession, tallying round trips."""

    def __init__(self, inner):
        self._inner = inner
        self.queries = 0

    async def execute(self, *args, **kwargs):
        self.queries += 1
        return await self._inner.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


async def test_a_cold_load_costs_a_bounded_number_of_queries(db):
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=50, pppoe_charge=50,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, days_ago=2)
    await _add_customer_payment(db, mine.id, 500, days_ago=2)

    counting = _CountingSession(db)
    await svc.compute_earnings(counting, period="30d")

    # One aggregate per source covering BOTH windows, two lifetime sums, and
    # the account names. (The settings read goes through db.get, not execute.)
    # Fetching current and previous separately would make it 6.
    assert counting.queries == 5, f"expected 5 queries, got {counting.queries}"


async def test_query_count_does_not_grow_with_the_window(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=50, pppoe_charge=50,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, days_ago=2)

    short = _CountingSession(db)
    await svc.compute_earnings(short, period="7d")
    long_ = _CountingSession(db)
    await svc.compute_earnings(long_, period="1y")

    assert short.queries == long_.queries


async def test_repeat_loads_are_served_from_cache(db):
    other = await make_reseller(db)
    await _add_saas_payment(db, other.id, 100, days_ago=2)

    first = _CountingSession(db)
    await svc.compute_earnings(first, period="30d")
    second = _CountingSession(db)
    await svc.compute_earnings(second, period="30d")

    assert first.queries > 0
    assert second.queries == 0


async def test_changing_accounts_invalidates_the_cache(db):
    mine = await make_reseller(db)
    await _add_customer_payment(db, mine.id, 700, days_ago=2)

    before = await svc.compute_earnings(db, period="30d")
    assert before["totals"]["reseller"] == 0

    await svc.set_own_reseller_ids(db, [mine.id])
    after = await svc.compute_earnings(db, period="30d")

    assert after["totals"]["reseller"] == 700

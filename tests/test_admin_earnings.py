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

import json
from datetime import datetime, time, timedelta

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

# Windows are calendar periods-to-date, so "2 days ago" falls outside this
# month on the 1st. Derive timestamps from the windows under test instead and
# these stay correct on every day of the year.

def _in_current(period: str = "month") -> datetime:
    """Midday today — inside the current window for every period."""
    _, _, _, cur_end = svc._earnings_windows(period)
    return datetime.combine(cur_end - timedelta(days=1), time(12))


def _in_previous(period: str = "month") -> datetime:
    """The previous window is at least a day long, so its start is inside it."""
    prev_start, _, _, _ = svc._earnings_windows(period)
    return datetime.combine(prev_start, time(12))


def _before_both(period: str = "month") -> datetime:
    prev_start, _, _, _ = svc._earnings_windows(period)
    return datetime.combine(prev_start - timedelta(days=10), time(12))


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


async def _add_saas_payment(db, user_id, amount, *, invoice=None, at=None,
                            status=SubscriptionPaymentStatus.COMPLETED):
    payment = SubscriptionPayment(
        invoice_id=invoice.id if invoice else None,
        user_id=user_id,
        amount=amount,
        payment_method="mpesa",
        status=status,
        created_at=at or _in_current(),
    )
    db.add(payment)
    await db.commit()
    return payment


async def _add_customer_payment(db, reseller_id, amount, *, at=None,
                                counts_as_revenue=True):
    payment = CustomerPayment(
        customer_id=None,
        reseller_id=reseller_id,
        amount=amount,
        payment_method=PaymentMethod.MOBILE_MONEY,
        days_paid_for=30,
        counts_as_revenue=counts_as_revenue,
        created_at=at or _in_current(),
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
    await _add_saas_payment(db, other.id, 100, invoice=invoice)

    result = await svc.compute_earnings(db, period="month")

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
    await _add_saas_payment(db, other.id, 200, invoice=invoice)

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["saas_hotspot"] == 150
    assert result["totals"]["saas_pppoe"] == 50


async def test_pending_saas_payments_are_ignored(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=50, pppoe_charge=50,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(
        db, other.id, 100, invoice=invoice,
        status=SubscriptionPaymentStatus.PENDING,
    )

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["system"] == 0


# ---------------------------------------------------------------------------
# 3. Unattributed SaaS payments
# ---------------------------------------------------------------------------

async def test_payment_without_invoice_falls_to_other_and_shows_band(db):
    other = await make_reseller(db)
    await _add_saas_payment(db, other.id, 500, invoice=None)

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["saas_other"] == 500
    assert result["totals"]["system"] == 500
    assert "saas_other" in {s["key"] for s in result["streams"]}


async def test_other_band_is_hidden_when_everything_is_attributed(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=10, pppoe_charge=10,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, other.id, 20, invoice=invoice)

    result = await svc.compute_earnings(db, period="month")

    assert "saas_other" not in {s["key"] for s in result["streams"]}


# ---------------------------------------------------------------------------
# 4-5. Own reseller stream
# ---------------------------------------------------------------------------

async def test_own_account_collections_form_their_own_stream(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, mine.id, 4_500)

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["reseller"] == 4_500
    assert result["totals"]["combined"] == 4_500
    assert result["own_reseller_accounts"][0]["id"] == mine.id


async def test_other_resellers_collections_are_not_our_revenue(db):
    mine = await make_reseller(db)
    other = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, other.id, 9_000)

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["reseller"] == 0


async def test_our_own_subscription_payments_are_excluded(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    invoice = await _add_invoice(
        db, mine.id, hotspot_charge=100, pppoe_charge=0,
        period_start=datetime.utcnow() - timedelta(days=30),
    )
    await _add_saas_payment(db, mine.id, 100, invoice=invoice)

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["system"] == 0
    assert result["all_time"]["system"] == 0


async def test_compensation_vouchers_are_excluded_from_own_collections(db):
    mine = await make_reseller(db)
    await svc.set_own_reseller_ids(db, [mine.id])
    await _add_customer_payment(db, mine.id, 1_000)
    await _add_customer_payment(db, mine.id, 250, counts_as_revenue=False)

    result = await svc.compute_earnings(db, period="month")

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
    await _add_saas_payment(db, other.id, 100, invoice=invoice)
    await _add_customer_payment(db, mine.id, 900)

    result = await svc.compute_earnings(db, period="month")
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
    await _add_saas_payment(db, other.id, 10, invoice=invoice, at=_before_both())

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["system"] == 0
    # Still counted in the lifetime figure.
    assert result["all_time"]["system"] == 10


async def test_previous_period_drives_change_percent(db):
    other = await make_reseller(db)
    invoice = await _add_invoice(
        db, other.id, hotspot_charge=100, pppoe_charge=0,
        period_start=datetime.utcnow() - timedelta(days=60),
    )
    await _add_saas_payment(db, other.id, 100, invoice=invoice, at=_in_previous())
    await _add_saas_payment(db, other.id, 150, invoice=invoice, at=_in_current())

    result = await svc.compute_earnings(db, period="month")

    assert result["totals"]["system"] == 150
    assert result["previous_totals"]["system"] == 100
    assert result["change_percent"]["system"] == 50.0


# ---------------------------------------------------------------------------
# 6b. Calendar windows
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "period,expected_granularity",
    [("week", "day"), ("month", "day"), ("quarter", "week"), ("year", "month")],
)
async def test_granularity_per_period(db, period, expected_granularity):
    result = await svc.compute_earnings(db, period=period)
    assert result["granularity"] == expected_granularity
    assert result["period"] == period


async def test_month_window_starts_on_the_first_not_thirty_days_back(db):
    """"Month" is month-to-date, matching the chip — not a trailing 30 days."""
    result = await svc.compute_earnings(db, period="month")
    today = datetime.utcnow().date()

    assert result["start_date"] == today.replace(day=1).isoformat()
    assert result["end_date"] == today.isoformat()
    assert result["days"] == today.day


async def test_previous_window_is_clipped_to_the_elapsed_span(db):
    """Comparing a part-month against a whole one makes deltas swing with the date."""
    prev_start, prev_end, cur_start, cur_end = svc._earnings_windows("month")

    assert (prev_end - prev_start).days == (cur_end - cur_start).days


async def test_unknown_period_falls_back_to_month(db):
    assert (await svc.compute_earnings(db, period="nonsense"))["period"] == "month"


async def test_comparison_label_names_the_period(db):
    result = await svc.compute_earnings(db, period="month")
    assert result["comparison_label"] == "vs same point last month"


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
    await _add_saas_payment(db, other.id, 100, invoice=invoice)
    await _add_customer_payment(db, mine.id, 500)

    counting = _CountingSession(db)
    await svc.compute_earnings(counting, period="month")

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
    await _add_saas_payment(db, other.id, 100, invoice=invoice)

    short = _CountingSession(db)
    await svc.compute_earnings(short, period="week")
    long_ = _CountingSession(db)
    await svc.compute_earnings(long_, period="year")

    assert short.queries == long_.queries


async def test_repeat_loads_are_served_from_cache(db):
    other = await make_reseller(db)
    await _add_saas_payment(db, other.id, 100)

    first = _CountingSession(db)
    await svc.compute_earnings(first, period="month")
    second = _CountingSession(db)
    await svc.compute_earnings(second, period="month")

    assert first.queries > 0
    assert second.queries == 0


async def test_cache_key_varies_with_the_account_set():
    """`cache` is per-process, so the key must carry the accounts.

    Otherwise a multi-worker deploy (uvicorn --workers) leaves every worker
    that didn't serve the PUT holding the old account list until the TTL runs
    out — a reseller band reading zero for no visible reason.
    """
    a = svc._earnings_cache_key("month", [1])
    b = svc._earnings_cache_key("month", [2])
    none = svc._earnings_cache_key("month", [])

    assert a != b != none
    assert a == svc._earnings_cache_key("month", [1])


async def test_cache_key_space_stays_bounded():
    """InMemoryCache only frees an expired entry when that key is read again,
    so the key space must be finite: four periods per account set."""
    keys = {svc._earnings_cache_key(p, [1]) for p in svc.EARNINGS_PERIODS}
    assert len(keys) == 4


async def test_account_change_is_seen_without_an_explicit_purge(db):
    """Proves the key alone is enough — no reliance on clear_pattern reaching us."""
    from app.services.app_settings import set_setting

    mine = await make_reseller(db)
    await _add_customer_payment(db, mine.id, 1_300)

    assert (await svc.compute_earnings(db, period="month"))["totals"]["reseller"] == 0

    # Write the setting directly, as a worker that never handled the PUT would
    # see it — no cache purge runs in this process.
    await set_setting(db, svc.OWN_RESELLER_IDS_SETTING, json.dumps([mine.id]))

    assert (await svc.compute_earnings(db, period="month"))["totals"]["reseller"] == 1_300


async def test_changing_accounts_invalidates_the_cache(db):
    mine = await make_reseller(db)
    await _add_customer_payment(db, mine.id, 700)

    before = await svc.compute_earnings(db, period="month")
    assert before["totals"]["reseller"] == 0

    await svc.set_own_reseller_ids(db, [mine.id])
    after = await svc.compute_earnings(db, period="month")

    assert after["totals"]["reseller"] == 700

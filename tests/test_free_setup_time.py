"""Admin "Free setup time (7 days)": one press, one account, no bill for 7 days.

Pins each job respecting the window (invoice, reminder, suspension), what happens
when it ends, the audit row and one-use guard, and that it is not a sale.
"""

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

import app.api.subscription_routes as sub_routes
from app.db.database import get_db
from app.db.models import (
    CollectionMode, ConnectionType, CustomerPayment, InvoiceStatus, Lead,
    LeadActivity, LeadStage, PaymentMethod, PaymentStatus,
    SmsMessage, Subscription, SubscriptionExpiryReminder,
    SubscriptionFreeSetupGrant, SubscriptionInvoice, SubscriptionPayment,
    SubscriptionPaymentStatus, SubscriptionStatus,
)
from app.services import admin_metrics
from app.services.auth import verify_token
from app.services.lead_backfill import infer_stage_for_user
from app.services.subscription import (
    FREE_SETUP_DAYS, FreeSetupRefused, MINIMUM_CHARGE, check_overdue_invoices,
    generate_catchup_invoices, generate_monthly_invoices,
    generate_pre_expiry_invoices, grant_free_setup,
)
from app.services.subscription_reminders import (
    EXPIRED_STAGE, reminder_overview, send_due_subscription_reminders,
    send_expiry_reminder,
)
from tests.factories import make_admin, make_customer, make_plan, make_reseller

# 12:00 EAT: outside quiet hours, after that day's 08:00 UTC suspension run.
MIDDAY = datetime(2026, 7, 27, 9, 0)


@pytest.fixture(autouse=True)
def no_provider_calls(monkeypatch):
    """Never reach an SMS provider."""
    import app.services.sms_dispatch as dispatch
    calls = []

    async def _fake(sms_ids, sender_id, **_):
        calls.append(sms_ids)
        return {}

    monkeypatch.setattr(dispatch, "dispatch_admin_sms_messages", _fake)
    return calls


async def _invoice(db, reseller, *, status=InvoiceStatus.OVERDUE, amount=MINIMUM_CHARGE,
                   days_ago=35, due_days_ago=5):
    now = datetime.utcnow()
    invoice = SubscriptionInvoice(
        user_id=reseller.id,
        period_start=now - timedelta(days=days_ago),
        period_end=now - timedelta(days=days_ago - 30),
        final_charge=amount,
        gross_charge=amount,
        currency="KES",
        status=status,
        due_date=now - timedelta(days=due_days_ago),
    )
    db.add(invoice)
    await db.commit()
    return invoice


async def _suspended(db, **overrides):
    """The account this button is for: signed up, never paid, suspended."""
    fields = dict(
        subscription_status=SubscriptionStatus.SUSPENDED,
        subscription_expires_at=datetime.utcnow() - timedelta(days=5),
        created_at=datetime.utcnow() - timedelta(days=60),
        support_phone="+254700000001",
    )
    fields.update(overrides)
    return await make_reseller(db, **fields)


async def _grant_days_ago(db, reseller, admin, days, **kwargs):
    """Press the button as if it happened *days* ago, then commit."""
    grant = await grant_free_setup(
        db, reseller.id, admin, now=datetime.utcnow() - timedelta(days=days), **kwargs)
    await db.commit()
    return grant


async def _invoices(db, reseller, status=None):
    query = select(SubscriptionInvoice).where(SubscriptionInvoice.user_id == reseller.id)
    if status is not None:
        query = query.where(SubscriptionInvoice.status == status)
    return (await db.execute(query)).scalars().all()


# ---------------------------------------------------------------------------
# The press itself
# ---------------------------------------------------------------------------

async def test_press_waives_unpaid_lifts_suspension_and_sets_seven_days(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    db.add(Subscription(user_id=reseller.id, status=SubscriptionStatus.SUSPENDED))
    await db.commit()
    overdue = await _invoice(db, reseller)
    pending = await _invoice(db, reseller, status=InvoiceStatus.PENDING, days_ago=4,
                             due_days_ago=-1, amount=750.0)
    paid = await _invoice(db, reseller, status=InvoiceStatus.PAID, days_ago=70, amount=900.0)

    now = datetime.utcnow()
    grant = await grant_free_setup(db, reseller.id, admin, now=now)
    await db.commit()

    assert overdue.status == InvoiceStatus.WAIVED
    assert pending.status == InvoiceStatus.WAIVED
    assert paid.status == InvoiceStatus.PAID

    assert reseller.subscription_status == SubscriptionStatus.TRIAL
    assert reseller.subscription_expires_at == now + timedelta(days=7)
    assert reseller.free_setup_until == now + timedelta(days=7)
    sub = (await db.execute(
        select(Subscription).where(Subscription.user_id == reseller.id))).scalar_one()
    assert sub.status == SubscriptionStatus.TRIAL
    assert sub.current_period_end == now + timedelta(days=7)

    assert grant.granted_by_id == admin.id
    assert grant.granted_by_email == admin.email
    assert grant.created_at == now
    assert grant.previous_status == "suspended"
    assert grant.new_status == "trial"
    assert grant.is_override is False
    assert [(w["invoice_id"], w["final_charge"], w["balance_waived"], w["currency"])
            for w in grant.waived_invoices] == [
        (overdue.id, MINIMUM_CHARGE, MINIMUM_CHARGE, "KES"),
        (pending.id, 750.0, 750.0, "KES"),
    ]


async def test_seven_days_is_the_owners_number():
    assert FREE_SETUP_DAYS == 7


async def test_part_paid_invoice_is_waived_and_the_money_stays(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    invoice = await _invoice(db, reseller)
    payment = SubscriptionPayment(
        invoice_id=invoice.id, user_id=reseller.id, amount=200.0, payment_method="mpesa",
        payment_reference="ABC123", status=SubscriptionPaymentStatus.COMPLETED,
    )
    db.add(payment)
    await db.commit()

    grant = await grant_free_setup(db, reseller.id, admin)
    await db.commit()

    assert invoice.status == InvoiceStatus.WAIVED
    assert grant.waived_invoices[0]["amount_paid"] == 200.0
    assert grant.waived_invoices[0]["balance_waived"] == MINIMUM_CHARGE - 200.0
    assert payment.status == SubscriptionPaymentStatus.COMPLETED
    assert payment.amount == 200.0
    # They have really paid us, so they go back to active rather than trial.
    assert reseller.subscription_status == SubscriptionStatus.ACTIVE


async def test_other_resellers_are_untouched(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    other = await _suspended(db)
    other_invoice = await _invoice(db, other)

    await grant_free_setup(db, reseller.id, admin)
    await db.commit()

    assert other_invoice.status == InvoiceStatus.OVERDUE
    assert other.subscription_status == SubscriptionStatus.SUSPENDED
    assert other.free_setup_until is None


async def test_no_unpaid_invoice_still_gives_the_window(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)

    now = datetime.utcnow()
    grant = await grant_free_setup(db, reseller.id, admin, now=now)
    await db.commit()

    assert grant.waived_invoices == []
    assert reseller.subscription_status == SubscriptionStatus.TRIAL
    assert reseller.free_setup_until == now + timedelta(days=7)


async def test_already_later_end_date_is_never_shortened(db):
    admin = await make_admin(db)
    later = datetime.utcnow() + timedelta(days=20)
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.ACTIVE, subscription_expires_at=later)

    now = datetime.utcnow()
    grant = await grant_free_setup(db, reseller.id, admin, now=now)
    await db.commit()

    assert reseller.subscription_expires_at == later
    assert grant.new_expires_at == later
    assert reseller.free_setup_until == now + timedelta(days=7)
    assert reseller.subscription_status == SubscriptionStatus.ACTIVE


async def test_trial_with_time_left_stays_on_trial(db):
    admin = await make_admin(db)
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.TRIAL,
        subscription_expires_at=datetime.utcnow() + timedelta(days=2))

    now = datetime.utcnow()
    await grant_free_setup(db, reseller.id, admin, now=now)
    await db.commit()

    assert reseller.subscription_status == SubscriptionStatus.TRIAL
    assert reseller.subscription_expires_at == now + timedelta(days=7)


async def test_inactive_account_is_refused_and_unchanged(db):
    """INACTIVE is set by hand, so it isn't a billing suspension to lift."""
    admin = await make_admin(db)
    reseller = await _suspended(db, subscription_status=SubscriptionStatus.INACTIVE)
    invoice = await _invoice(db, reseller)

    with pytest.raises(FreeSetupRefused) as refused:
        await grant_free_setup(db, reseller.id, admin)
    await db.rollback()

    assert refused.value.status_code == 409
    await db.refresh(invoice)
    await db.refresh(reseller)
    assert invoice.status == InvoiceStatus.OVERDUE
    assert reseller.subscription_status == SubscriptionStatus.INACTIVE
    assert reseller.free_setup_until is None


async def test_failure_part_way_leaves_nothing_behind(db):
    reseller = await _suspended(db)
    invoice = await _invoice(db, reseller)
    old_expiry = reseller.subscription_expires_at

    with pytest.raises(AttributeError):
        # No admin: fails at the audit row, after the invoice and status changed.
        await grant_free_setup(db, reseller.id, None)
    await db.rollback()

    await db.refresh(invoice)
    await db.refresh(reseller)
    assert invoice.status == InvoiceStatus.OVERDUE
    assert reseller.subscription_status == SubscriptionStatus.SUSPENDED
    assert reseller.subscription_expires_at == old_expiry
    assert reseller.free_setup_until is None
    assert (await db.execute(
        select(func.count(SubscriptionFreeSetupGrant.id)))).scalar() == 0


# ---------------------------------------------------------------------------
# One use per account
# ---------------------------------------------------------------------------

async def test_repeat_press_is_refused_and_changes_nothing(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=10)
    await db.refresh(reseller)
    until = reseller.free_setup_until
    admin_email = admin.email
    new_invoice = await _invoice(db, reseller, days_ago=3)

    with pytest.raises(FreeSetupRefused) as refused:
        await grant_free_setup(db, reseller.id, admin)
    await db.rollback()

    assert refused.value.status_code == 409
    assert admin_email in refused.value.detail
    await db.refresh(reseller)
    await db.refresh(new_invoice)
    assert reseller.free_setup_until == until
    assert new_invoice.status == InvoiceStatus.OVERDUE
    assert (await db.execute(
        select(func.count(SubscriptionFreeSetupGrant.id)))).scalar() == 1


async def test_override_needs_a_reason(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=10)

    with pytest.raises(FreeSetupRefused) as refused:
        await grant_free_setup(db, reseller.id, admin, override=True, override_reason="   ")
    await db.rollback()
    assert refused.value.status_code == 400


async def test_override_with_a_reason_gives_another_window_and_says_so(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=10)
    new_invoice = await _invoice(db, reseller, days_ago=3)

    now = datetime.utcnow()
    grant = await grant_free_setup(
        db, reseller.id, admin, override=True, override_reason="Router arrived late", now=now)
    await db.commit()

    assert grant.is_override is True
    assert grant.override_reason == "Router arrived late"
    assert new_invoice.status == InvoiceStatus.WAIVED
    assert reseller.free_setup_until == now + timedelta(days=7)


# ---------------------------------------------------------------------------
# During the window: each job leaves the account alone
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("generate", [
    generate_pre_expiry_invoices, generate_catchup_invoices, generate_monthly_invoices,
])
async def test_no_invoice_during_the_window(db, generate):
    admin = await make_admin(db)
    # Day 3 of 7: the end date is 4 days out, inside the 5-days-before rule.
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=3)
    await db.refresh(reseller)
    assert reseller.subscription_expires_at < datetime.utcnow() + timedelta(days=5)
    # Control: same end date, no window, does get billed by every job.
    control = await make_reseller(
        db, subscription_status=SubscriptionStatus.TRIAL,
        subscription_expires_at=reseller.subscription_expires_at)

    await generate(db)

    assert await _invoices(db, reseller) == []
    assert len(await _invoices(db, control)) == 1


async def test_waived_invoice_is_not_billed_again_on_day_two(db):
    """The bug that made 13 of 14 past waivers come straight back."""
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _invoice(db, reseller)
    await _grant_days_ago(db, reseller, admin, days=2)

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 0
    assert len(await _invoices(db, reseller, InvoiceStatus.WAIVED)) == 1
    assert len(await _invoices(db, reseller)) == 1


async def test_no_suspension_during_the_window(db):
    admin = await make_admin(db)
    trial = await _suspended(db)
    paying = await make_reseller(
        db, subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=datetime.utcnow() + timedelta(days=1))
    await _grant_days_ago(db, trial, admin, days=1)
    await _grant_days_ago(db, paying, admin, days=1)
    # An admin edit puts both end dates in the past: the window still holds.
    past = datetime.utcnow() - timedelta(hours=3)
    trial.subscription_expires_at = past
    paying.subscription_expires_at = past
    # Even an overdue invoice raised some other way doesn't suspend them.
    stray = await _invoice(db, trial, status=InvoiceStatus.PENDING, days_ago=1, due_days_ago=1)
    await db.commit()

    result = await check_overdue_invoices(db)

    assert result["trial_expired"] == 0
    assert result["active_expired"] == 0
    assert result["suspended"] == 0
    await db.refresh(trial)
    await db.refresh(paying)
    await db.refresh(stray)
    assert trial.subscription_status == SubscriptionStatus.TRIAL
    assert paying.subscription_status == SubscriptionStatus.ACTIVE
    assert stray.status == InvoiceStatus.PENDING


async def test_no_reminder_during_the_window(db, no_provider_calls):
    admin = await make_admin(db)
    # MIDDAY is 1.5h before the window and end date finish: every stage is due.
    pressed_at = MIDDAY + timedelta(hours=1, minutes=30) - timedelta(days=FREE_SETUP_DAYS)
    reseller = await _suspended(db, subscription_expires_at=pressed_at)
    await grant_free_setup(db, reseller.id, admin, now=pressed_at)
    await db.commit()
    control = await make_reseller(
        db, subscription_status=SubscriptionStatus.TRIAL,
        subscription_expires_at=reseller.subscription_expires_at,
        support_phone="+254700000002")

    result = await send_due_subscription_reminders(now=MIDDAY)

    assert result["sent"] == 1
    sms = (await db.execute(select(SmsMessage))).scalars().all()
    assert [s.user_id for s in sms] == [control.id]

    # Pressed after a scan listed them: the per-send re-check stops it too.
    assert await send_expiry_reminder(
        reseller.id, "t2", reseller.subscription_expires_at, now=MIDDAY) is None
    # And the admin reminder dashboard doesn't promise one.
    overview = await reminder_overview(db, now=MIDDAY)
    assert [u["reseller_id"] for u in overview["upcoming"]] == [control.id]


async def test_reseller_cannot_raise_an_invoice_during_the_window(db, http, monkeypatch):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=3)
    _auth_as(monkeypatch, reseller)

    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.post("/api/subscription/request-invoice")

    assert resp.status_code == 400
    assert "free setup" in resp.json()["detail"]
    assert await _invoices(db, reseller) == []


# ---------------------------------------------------------------------------
# After the window: normal billing resumes
# ---------------------------------------------------------------------------

async def test_day_eight_invoice_then_suspension(db):
    """06:00 UTC raises the invoice, 08:00 UTC suspends."""
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _invoice(db, reseller)
    await _grant_days_ago(db, reseller, admin, days=FREE_SETUP_DAYS + 1)
    await db.refresh(reseller)
    window_end = reseller.free_setup_until

    await generate_pre_expiry_invoices(db)

    new = await _invoices(db, reseller, InvoiceStatus.PENDING)
    assert len(new) == 1
    assert new[0].final_charge == MINIMUM_CHARGE
    assert new[0].due_date == window_end
    assert new[0].period_start == window_end

    await check_overdue_invoices(db)

    await db.refresh(reseller)
    assert reseller.subscription_status == SubscriptionStatus.SUSPENDED
    await db.refresh(new[0])
    assert new[0].status == InvoiceStatus.OVERDUE


async def test_window_ending_just_before_the_suspension_run_still_gets_invoiced(db):
    """Ends 07:00 UTC: 08:00 suspends first, the next 06:00 run raises the invoice."""
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=FREE_SETUP_DAYS + 1)
    await check_overdue_invoices(db)
    await db.refresh(reseller)
    assert reseller.subscription_status == SubscriptionStatus.SUSPENDED
    assert await _invoices(db, reseller) == []

    result = await generate_pre_expiry_invoices(db)

    assert result["created"] == 1
    assert len(await _invoices(db, reseller, InvoiceStatus.PENDING)) == 1


async def test_suspended_long_after_a_window_is_not_invoiced_again(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=FREE_SETUP_DAYS + 3)
    await check_overdue_invoices(db)

    assert (await generate_pre_expiry_invoices(db))["created"] == 0


async def test_sales_made_during_the_window_are_not_charged(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=FREE_SETUP_DAYS + 1)
    await db.refresh(reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, reseller, plan)

    async def sale(amount, when):
        db.add(CustomerPayment(
            customer_id=customer.id, reseller_id=reseller.id, amount=amount,
            payment_method=PaymentMethod.MOBILE_MONEY, payment_date=when, created_at=when,
            days_paid_for=30, status=PaymentStatus.COMPLETED, counts_as_revenue=True,
            collection_mode=CollectionMode.SYSTEM_COLLECTED,
        ))
        await db.commit()

    # 3% of this alone would be KES 3,000, well over the minimum.
    await sale(100_000.0, reseller.free_setup_until - timedelta(days=2))
    await sale(1_000.0, reseller.free_setup_until + timedelta(hours=1))

    await generate_pre_expiry_invoices(db)

    invoice = (await _invoices(db, reseller, InvoiceStatus.PENDING))[0]
    assert invoice.hotspot_revenue == 1_000.0
    assert invoice.final_charge == MINIMUM_CHARGE


async def test_later_end_date_bills_at_its_usual_time_once_the_window_is_over(db):
    admin = await make_admin(db)
    reseller = await make_reseller(
        db, subscription_status=SubscriptionStatus.ACTIVE,
        subscription_expires_at=datetime.utcnow() + timedelta(days=3))
    await _grant_days_ago(db, reseller, admin, days=FREE_SETUP_DAYS + 1)
    await db.refresh(reseller)
    # Pressed 8 days ago with 11 days left; the end date stayed put.
    assert reseller.subscription_expires_at > reseller.free_setup_until

    assert (await generate_pre_expiry_invoices(db))["created"] == 1
    # Not yet expired, so no suspension: the invoice is due on the end date.
    await check_overdue_invoices(db)
    await db.refresh(reseller)
    assert reseller.subscription_status == SubscriptionStatus.ACTIVE


async def test_reminders_resume_after_the_window(db, no_provider_calls):
    admin = await make_admin(db)
    # Ended 06:00 UTC (09:00 EAT); it is 06:30 UTC, before that day's 08:00 run.
    now = datetime(2026, 7, 27, 6, 30)
    window_end = datetime(2026, 7, 27, 6, 0)
    pressed_at = window_end - timedelta(days=FREE_SETUP_DAYS)
    reseller = await _suspended(db, subscription_expires_at=pressed_at)
    await grant_free_setup(db, reseller.id, admin, now=pressed_at)
    await db.commit()

    assert (await send_due_subscription_reminders(now=now))["sent"] == 1

    reminder = (await db.execute(select(SubscriptionExpiryReminder))).scalar_one()
    assert reminder.stage == "t2"
    sms = (await db.execute(select(SmsMessage))).scalar_one()
    assert "has ended" in sms.body

    # Then the one post-suspension notice, as for anyone else.
    reseller.subscription_status = SubscriptionStatus.SUSPENDED
    await db.commit()
    later = datetime(2026, 7, 27, 9, 0)
    assert (await send_due_subscription_reminders(now=later))["sent"] == 1
    stages = (await db.execute(select(SubscriptionExpiryReminder.stage))).scalars().all()
    assert set(stages) == {"t2", EXPIRED_STAGE}


async def test_startup_trial_reset_cannot_extend_a_used_window():
    """main.py gives expired trials 7 more days on every restart; not these."""
    import pathlib
    source = pathlib.Path(__file__).resolve().parents[1].joinpath("main.py").read_text(
        encoding="utf-8")
    start = source.index('"Reset expired trial dates"')
    assert "free_setup_until IS NULL" in source[start:start + 700]
    # And the column it reads exists by then, ahead of any user read at startup.
    assert source.index("await run_free_setup_column_migration()") < source.index(
        "await run_subscription_migrations()")
    assert source.index("await run_staff_migrations()") < source.index(
        "await run_free_setup_column_migration()")


# ---------------------------------------------------------------------------
# Not a sale
# ---------------------------------------------------------------------------

async def _figures(db):
    now = datetime.utcnow()
    mrr = await admin_metrics.compute_mrr(db)
    conversion = await admin_metrics.compute_trial_conversion(db)
    conversion.pop("calculated_at")
    churn = await admin_metrics.compute_churn(db)
    return {
        "paying_now": await admin_metrics._subscribers_at(db, now, paying_only=True),
        "all_subs_now": await admin_metrics._subscribers_at(db, now, paying_only=False),
        "mrr": mrr["current_mrr"],
        "by_plan": sorted(
            (row["plan_name"], row["reseller_count"], row["mrr"])
            for row in mrr["by_plan"]),
        "conversion": conversion,
        "churned": churn["churned_count"],
        "churn_rate": churn["churn_rate"],
        "reseller_target": await admin_metrics._compute_target_current(db, "reseller_target"),
        "payments": (await db.execute(select(func.count(SubscriptionPayment.id)))).scalar(),
    }


@pytest.mark.parametrize("created_days_ago", [2, 100])
async def test_sales_and_conversion_figures_do_not_move(db, created_days_ago):
    admin = await make_admin(db)
    created = datetime.utcnow() - timedelta(days=created_days_ago)
    reseller = await _suspended(db, created_at=created)
    await _invoice(db, reseller)
    # A real paying reseller and a real trial, so the figures aren't all zero.
    paying = await make_reseller(
        db, subscription_status=SubscriptionStatus.ACTIVE, created_at=created,
        subscription_expires_at=datetime.utcnow() + timedelta(days=20))
    db.add(SubscriptionPayment(
        user_id=paying.id, amount=500.0, payment_method="mpesa", payment_reference="REAL1",
        status=SubscriptionPaymentStatus.COMPLETED,
        created_at=datetime.utcnow() - timedelta(days=1),
    ))
    await make_reseller(
        db, subscription_status=SubscriptionStatus.TRIAL, created_at=created,
        subscription_expires_at=datetime.utcnow() + timedelta(days=4))
    await db.commit()

    before = await _figures(db)
    await grant_free_setup(db, reseller.id, admin)
    await db.commit()
    after = await _figures(db)

    assert after == before


async def test_lead_is_not_marked_paying(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    db.add(Subscription(user_id=reseller.id, status=SubscriptionStatus.SUSPENDED))
    lead = Lead(
        user_id=admin.id, name="Test ISP", email=reseller.email, stage=LeadStage.CHURNED,
        stage_changed_at=datetime.utcnow() - timedelta(days=1), converted_user_id=reseller.id,
    )
    db.add(lead)
    await db.commit()

    await grant_free_setup(db, reseller.id, admin)
    await db.commit()

    await db.refresh(lead)
    assert lead.stage == LeadStage.CHURNED
    assert (await db.execute(select(func.count(LeadActivity.id)))).scalar() == 0
    # The backfill reads status to classify; TRIAL with no payment is not paying.
    stage, _ = await infer_stage_for_user(db, reseller.id)
    assert stage != LeadStage.PAYING


async def test_no_payment_row_is_created(db):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _invoice(db, reseller)

    await grant_free_setup(db, reseller.id, admin)
    await db.commit()

    assert (await db.execute(select(func.count(SubscriptionPayment.id)))).scalar() == 0


# ---------------------------------------------------------------------------
# Route: admin only, and shown on the admin page only
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def http(session_factory):
    application = FastAPI()
    application.include_router(sub_routes.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    return application


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(sub_routes, "get_current_user", _fake)


async def test_route_refuses_a_reseller_and_changes_nothing(db, http, monkeypatch):
    reseller = await _suspended(db)
    invoice = await _invoice(db, reseller)
    _auth_as(monkeypatch, reseller)

    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.post(f"/api/admin/subscriptions/{reseller.id}/free-setup")

    assert resp.status_code == 403
    await db.refresh(invoice)
    await db.refresh(reseller)
    assert invoice.status == InvoiceStatus.OVERDUE
    assert reseller.subscription_status == SubscriptionStatus.SUSPENDED
    assert reseller.free_setup_until is None


async def test_route_needs_a_login(db, session_factory):
    application = FastAPI()
    application.include_router(sub_routes.router)
    reseller = await _suspended(db)

    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://t") as c:
        resp = await c.post(f"/api/admin/subscriptions/{reseller.id}/free-setup")

    assert resp.status_code in (401, 403)
    await db.refresh(reseller)
    assert reseller.free_setup_until is None


async def test_route_grants_then_refuses_repeat_and_the_detail_page_shows_it(db, http, monkeypatch):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _invoice(db, reseller)
    _auth_as(monkeypatch, admin)

    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        first = await c.post(f"/api/admin/subscriptions/{reseller.id}/free-setup")
        repeat = await c.post(f"/api/admin/subscriptions/{reseller.id}/free-setup", json={})
        no_reason = await c.post(
            f"/api/admin/subscriptions/{reseller.id}/free-setup", json={"override": True})
        again = await c.post(
            f"/api/admin/subscriptions/{reseller.id}/free-setup",
            json={"override": True, "override_reason": "Router arrived late"})
        detail = await c.get(f"/api/admin/subscriptions/{reseller.id}")

    assert first.status_code == 200
    assert first.json()["grant"]["waived_invoices"][0]["final_charge"] == MINIMUM_CHARGE
    assert repeat.status_code == 409
    assert no_reason.status_code == 400
    assert again.status_code == 200

    body = detail.json()["free_setup"]
    assert body["active"] is True
    assert [g["is_override"] for g in body["grants"]] == [True, False]
    assert body["grants"][1]["granted_by_email"] == admin.email


async def test_route_unknown_reseller_is_404(db, http, monkeypatch):
    admin = await make_admin(db)
    _auth_as(monkeypatch, admin)

    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.post(f"/api/admin/subscriptions/{admin.id}/free-setup")

    assert resp.status_code == 404


async def test_reseller_summary_does_not_mention_it(db, http, monkeypatch):
    admin = await make_admin(db)
    reseller = await _suspended(db)
    await _grant_days_ago(db, reseller, admin, days=1)
    _auth_as(monkeypatch, reseller)

    async with AsyncClient(transport=ASGITransport(app=http), base_url="http://t") as c:
        resp = await c.get("/api/subscription")

    assert resp.status_code == 200
    assert "free_setup" not in resp.text
    assert resp.json()["status"] == "trial"


"""Compensation voucher type + non-revenue accounting + daily cap."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import (
    CustomerPayment,
    CustomerStatus,
    PaymentMethod,
    ResellerFinancials,
    Voucher,
    VoucherStatus,
    VoucherType,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

pytestmark = pytest.mark.asyncio


async def test_voucher_defaults_to_sale_type(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    voucher = Voucher(
        code="10000001",
        plan_id=plan.id,
        user_id=reseller.id,
        status=VoucherStatus.AVAILABLE,
    )
    db.add(voucher)
    await db.commit()
    await db.refresh(voucher)
    assert voucher.voucher_type == VoucherType.SALE


async def test_payment_defaults_counts_as_revenue_true(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    payment = CustomerPayment(
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=500.0,
        payment_method=PaymentMethod.CASH,
        days_paid_for=30,
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    assert payment.counts_as_revenue is True


async def test_record_payment_can_flag_non_revenue(db):
    from app.services.reseller_payments import record_customer_payment

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, price=500)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    payment = await record_customer_payment(
        db=db,
        customer_id=customer.id,
        reseller_id=reseller.id,
        amount=500.0,
        payment_method=PaymentMethod.CASH,
        days_paid_for=30,
        counts_as_revenue=False,
    )
    assert payment.counts_as_revenue is False


async def test_comp_payment_excluded_from_total_revenue(db):
    from app.services.reseller_payments import record_customer_payment

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, price=500)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    await record_customer_payment(
        db=db, customer_id=customer.id, reseller_id=reseller.id, amount=500.0,
        payment_method=PaymentMethod.CASH, days_paid_for=30, counts_as_revenue=True,
    )
    await record_customer_payment(
        db=db, customer_id=customer.id, reseller_id=reseller.id, amount=500.0,
        payment_method=PaymentMethod.CASH, days_paid_for=30, counts_as_revenue=False,
    )

    fin = (
        await db.execute(select(ResellerFinancials).where(ResellerFinancials.user_id == reseller.id))
    ).scalar_one()
    assert fin.total_revenue == 500.0  # only the revenue-counting payment


async def test_comp_payment_excluded_from_hotspot_charge(db):
    from app.services.reseller_payments import record_customer_payment
    from app.services.subscription import calculate_reseller_charges

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, price=500)  # HOTSPOT by default
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)

    await record_customer_payment(
        db=db, customer_id=customer.id, reseller_id=reseller.id, amount=500.0,
        payment_method=PaymentMethod.CASH, days_paid_for=30, counts_as_revenue=True,
    )
    await record_customer_payment(
        db=db, customer_id=customer.id, reseller_id=reseller.id, amount=500.0,
        payment_method=PaymentMethod.CASH, days_paid_for=30, counts_as_revenue=False,
    )

    period_start = datetime.utcnow() - timedelta(days=1)
    period_end = datetime.utcnow() + timedelta(days=1)
    charges = await calculate_reseller_charges(db, reseller.id, period_start, period_end)

    assert charges["hotspot_revenue"] == 500.0          # comp excluded
    assert charges["hotspot_charge"] == 15.0            # 500 * 0.03


async def test_generate_compensation_sets_type(db):
    from app.services.voucher_service import generate_vouchers

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    result = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=1,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert "error" not in result
    rows = (await db.execute(select(Voucher).where(Voucher.user_id == reseller.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].voucher_type == VoucherType.COMPENSATION


async def test_compensation_daily_limit_blocks_excess(db):
    from app.services.voucher_service import generate_vouchers

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)

    ok = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=10,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert ok["quantity"] == 10

    blocked = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=1,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert "error" in blocked
    assert "compensation" in blocked["error"].lower()


async def test_sale_vouchers_ignore_compensation_cap(db):
    from app.services.voucher_service import generate_vouchers

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    result = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=50,
        voucher_type=VoucherType.SALE,
    )
    assert result["quantity"] == 50


async def test_disabled_comp_frees_daily_count(db):
    from app.services.voucher_service import generate_vouchers

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)

    await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=10,
        voucher_type=VoucherType.COMPENSATION,
    )
    # Disable one comp voucher -> frees one slot of today's count.
    one = (await db.execute(select(Voucher).where(Voucher.user_id == reseller.id))).scalars().first()
    one.status = VoucherStatus.DISABLED
    await db.commit()

    result = await generate_vouchers(
        db=db, plan_id=plan.id, user_id=reseller.id, quantity=1,
        voucher_type=VoucherType.COMPENSATION,
    )
    assert "error" not in result


@pytest.fixture
def no_background_provisioning(monkeypatch):
    from app.services import voucher_service

    async def _fake_provision(*args, **kwargs):
        return {"success": True}

    monkeypatch.setattr(voucher_service, "provision_hotspot_customer", _fake_provision)


async def test_redeem_compensation_voucher_records_non_revenue(db, no_background_provisioning):
    from app.services.voucher_service import redeem_voucher
    from app.db.models import Customer

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=1, price=500)
    router = await make_router(db, reseller)
    voucher = Voucher(
        code="20000002",
        plan_id=plan.id,
        user_id=reseller.id,
        status=VoucherStatus.AVAILABLE,
        voucher_type=VoucherType.COMPENSATION,
    )
    db.add(voucher)
    await db.commit()

    result = await redeem_voucher(db, voucher.code, "AA:BB:CC:DD:EE:01", router.id)
    assert result["success"] is True

    payment = (
        await db.execute(select(CustomerPayment).where(CustomerPayment.reseller_id == reseller.id))
    ).scalar_one()
    assert payment.counts_as_revenue is False

    customer = await db.get(Customer, result["customer_id"])
    assert customer.status == CustomerStatus.ACTIVE
    assert customer.expiry is not None  # provisioning/expiry still happen

    fin = (
        await db.execute(select(ResellerFinancials).where(ResellerFinancials.user_id == reseller.id))
    ).scalar_one()
    assert fin.total_revenue == 0.0  # compensation never counts as revenue

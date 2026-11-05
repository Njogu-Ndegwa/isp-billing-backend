from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from fastapi import HTTPException
from app.db.models import (
    CollectionMode,
    Customer,
    CustomerPayment,
    MpesaTransaction,
    PaymentMethod,
    PaymentStatus,
    Plan,
    ResellerFinancials,
    ResellerPaymentMethod,
    ResellerPaymentMethodType,
    Router,
    CustomerStatus,
)
from app.services.customer_grace import renewal_expiry
import logging

logger = logging.getLogger(__name__)


async def resolve_mpesa_collection_mode(
    db: AsyncSession,
    transaction: MpesaTransaction,
    customer: Customer,
) -> CollectionMode:
    """Return the immutable collection owner for an M-Pesa transaction.

    New transactions snapshot this at initiation. The router lookup is only a
    compatibility fallback for transactions created before that column existed
    or orphan callbacks recovered without their original transaction row.
    """
    if transaction.collection_mode is not None:
        return transaction.collection_mode

    method_type = None
    if customer.router_id:
        result = await db.execute(
            select(ResellerPaymentMethod.method_type)
            .join(Router, Router.payment_method_id == ResellerPaymentMethod.id)
            .where(
                Router.id == customer.router_id,
                ResellerPaymentMethod.is_active == True,
            )
        )
        method_type = result.scalar_one_or_none()

    if method_type == ResellerPaymentMethodType.MPESA_PAYBILL_WITH_KEYS:
        return CollectionMode.DIRECT
    return CollectionMode.SYSTEM_COLLECTED

def _plan_gives_less(new_plan: Plan | None, old_plan: Plan) -> bool:
    """True when ``new_plan`` allows fewer devices or a lower data cap."""
    if new_plan is None:
        return True
    if (new_plan.max_shared_users or 1) < (old_plan.max_shared_users or 1):
        return True
    new_cap, old_cap = new_plan.data_cap_mb, old_plan.data_cap_mb
    return new_cap is not None and (old_cap is None or new_cap < old_cap)


async def record_customer_payment(
    db: AsyncSession,
    customer_id: int,
    reseller_id: int,
    amount: float,
    payment_method: PaymentMethod,
    days_paid_for: int,
    payment_reference: str = None,
    notes: str = None,
    duration_value: int = None,
    duration_unit: str = None,
    collection_mode: CollectionMode = None,
    counts_as_revenue: bool = True,
    commit: bool = True,
    defer_router_io: bool = False,
) -> CustomerPayment:
    """Record a payment made by customer to reseller

    Args:
        duration_value: Override plan duration value (for pending plan changes)
        duration_unit: Override plan duration unit (MINUTES, HOURS, DAYS)
        collection_mode: DIRECT if reseller collected, SYSTEM_COLLECTED if platform collected
    """
    if not commit and not defer_router_io:
        raise ValueError("Atomic payment callers must defer renewal router I/O")
    
    # Load customer with plan to calculate proper expiry
    stmt = select(Customer).options(joinedload(Customer.plan)).where(
        Customer.id == customer_id,
        Customer.user_id == reseller_id
    )
    result = await db.execute(stmt.with_for_update(of=Customer))
    customer = result.scalar_one_or_none()
    
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found or not owned by reseller")

    # Callers set ``customer.plan_id`` to the plan being bought just before
    # calling this (voucher redemption, device-pairing vouchers). If the same
    # session had already loaded ``customer.plan``, the joinedload above does
    # not replace it, so it would still be the PREVIOUS plan: the new usage
    # period then snapshots the old plan's data cap and the shared devices are
    # synced against the old plan's device limit. That throttled the owner of a
    # 200 GB plan at 2 GB for 17 days (router 446, Oct 2026).
    #
    # Only corrected when the new plan gives at least as much. Vouchers refuse a
    # smaller plan on a live group before reaching this point
    # (smaller_voucher_refusal); anything else keeps the old limits for the period.
    if customer.plan_id is not None and (
        customer.plan is None or customer.plan.id != customer.plan_id
    ):
        bought = await db.get(Plan, customer.plan_id)
        if customer.plan is None or not _plan_gives_less(bought, customer.plan):
            customer.plan = bought
        else:
            logger.warning(
                "[PLAN-SWAP] Customer %s bought plan %s on live plan %s with fewer devices or "
                "a lower cap; keeping the old limits for this period",
                customer.id, customer.plan_id, customer.plan.id,
            )

    payment = CustomerPayment(
        customer_id=customer_id,
        reseller_id=reseller_id,
        amount=amount,
        payment_method=payment_method,
        payment_reference=payment_reference,
        days_paid_for=days_paid_for,
        notes=notes,
        customer_name=customer.name,
        # Snapshot the plan being paid for — customer.plan_id is already set
        # to the purchased plan by the time any payment is recorded.
        plan_id=customer.plan_id,
        # Snapshot the earning router for payout attribution, for the same
        # reason: the customer may later be moved to a different site, and the
        # money owed for this payment must not move with them.
        router_id=customer.router_id,
        collection_mode=collection_mode,
        counts_as_revenue=counts_as_revenue,
    )

    db.add(payment)
    
    # Calculate expiry based on provided duration or plan's duration
    now = datetime.utcnow()
    
    # Use explicit duration if provided, otherwise use customer's plan
    if duration_value is not None and duration_unit is not None:
        d_value = duration_value
        d_unit = duration_unit.upper()
    elif customer.plan:
        d_value = customer.plan.duration_value
        d_unit = customer.plan.duration_unit.value.upper()
    else:
        d_value = days_paid_for
        d_unit = "DAYS"
    
    # Calculate time delta based on unit
    if d_unit == "MINUTES":
        time_delta = timedelta(minutes=d_value)
    elif d_unit == "HOURS":
        time_delta = timedelta(hours=d_value)
    elif d_unit == "DAYS":
        time_delta = timedelta(days=d_value)
    else:
        # Fallback to days_paid_for if unit is unknown
        time_delta = timedelta(days=days_paid_for)
    
    # Extend from the paid expiry while the customer still has access (paid
    # time or reseller grace, so grace keeps the billing date); otherwise
    # start from now.
    customer.expiry = renewal_expiry(customer, now, time_delta)
    
    customer.status = CustomerStatus.ACTIVE

    # Renewal hook: roll usage period and lift any FUP throttle/block.
    try:
        from app.services.usage_tracking import on_renewal

        await on_renewal(db, customer, plan=customer.plan, now=now,
                         **({"defer_router_io": True} if defer_router_io else {}))
    except Exception as renew_err:
        if not commit:
            raise
        import logging

        logging.getLogger(__name__).error(
            f"[USAGE] on_renewal failed in reseller payment for customer {customer.id}: {renew_err}"
        )

    if customer.subscription_owner_id:
        # A device that was sharing someone else's plan just paid for its own.
        # Detach it, or the old owner's next renewal would overwrite this
        # customer's expiry with theirs.
        from app.db.models import DevicePairing

        previous_owner_id = customer.subscription_owner_id
        customer.subscription_owner_id = None
        await db.execute(
            update(DevicePairing)
            .where(
                DevicePairing.customer_id == customer.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
            )
            .values(is_active=False, subscription_owner_customer_id=None, is_subscription_share=False)
        )
        logger.info(
            "[SUBSCRIPTION-SHARE] Customer %s paid for its own plan; detached from owner %s",
            customer.id,
            previous_owner_id,
        )

    if not customer.subscription_owner_id:
        try:
            from app.services.subscription_sharing import (
                sync_shared_subscription_devices_after_owner_renewal,
            )

            synced_devices = await sync_shared_subscription_devices_after_owner_renewal(
                db,
                owner_customer=customer,
                plan=customer.plan,
                **({"defer_router_io": True} if defer_router_io else {}),
            )
            if synced_devices:
                logger.info(
                    "[SUBSCRIPTION-SHARE] Synced %d shared device(s) after payment for customer %s",
                    len(synced_devices),
                    customer.id,
                )
        except Exception as share_err:
            if not commit:
                raise
            logger.error(
                "[SUBSCRIPTION-SHARE] Failed to sync shared devices for customer %s: %s",
                customer.id,
                share_err,
            )

    # NOTE: Removed duplicate Payment record creation
    # CustomerPayment is the primary payment record - no need for both

    await db.flush()
    await update_reseller_financials(db, reseller_id)

    if commit:
        await db.commit()
        await db.refresh(payment)
    else:
        # The caller owns the atomic ledger/entitlement/provider transaction.
        # It must defer router I/O, including renewal's FUP restoration.
        await db.flush()

    return payment

async def update_reseller_financials(db: AsyncSession, reseller_id: int):
    """Update reseller's financial summary"""
    
    stmt = select(ResellerFinancials).where(ResellerFinancials.user_id == reseller_id)
    result = await db.execute(stmt)
    financials = result.scalar_one_or_none()
    
    if not financials:
        financials = ResellerFinancials(user_id=reseller_id)
        db.add(financials)
    
    total_revenue_stmt = select(func.sum(CustomerPayment.amount)).where(
        CustomerPayment.reseller_id == reseller_id,
        CustomerPayment.status == PaymentStatus.COMPLETED,
        CustomerPayment.counts_as_revenue == True,
    )
    total_revenue_result = await db.execute(total_revenue_stmt)
    total_revenue = total_revenue_result.scalar() or 0
    
    total_customers_stmt = select(func.count(Customer.id)).where(
        Customer.user_id == reseller_id
    )
    total_customers_result = await db.execute(total_customers_stmt)
    total_customers = total_customers_result.scalar() or 0
    
    active_customers_stmt = select(func.count(Customer.id)).where(
        Customer.user_id == reseller_id,
        Customer.status == CustomerStatus.ACTIVE
    )
    active_customers_result = await db.execute(active_customers_stmt)
    active_customers = active_customers_result.scalar() or 0
    
    last_payment_stmt = select(func.max(CustomerPayment.payment_date)).where(
        CustomerPayment.reseller_id == reseller_id
    )
    last_payment_result = await db.execute(last_payment_stmt)
    last_payment_date = last_payment_result.scalar()
    
    financials.total_revenue = total_revenue
    financials.total_customers = total_customers
    financials.active_customers = active_customers
    financials.last_payment_date = last_payment_date

"""Cascade soft-delete helpers (docs/SOFT_DELETE_PLAN.md).

Every delete flow tombstones with ONE shared timestamp so a parent and all its
children cross the purge-retention cutoff together. Already-tombstoned rows are
never re-stamped (their original deletion time is the audit record and the
purge clock).

What must stay HARD-deleted, always:
  * radius_* rows — FreeRADIUS reads those tables directly; a tombstone would
    still authenticate the customer on the router.
  * Retention prunes (bandwidth snapshots, availability checks, old SMS) —
    they exist to bound table growth.
"""

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession


async def soft_delete_where(
    db: AsyncSession,
    model,
    *criteria,
    when,
    deleted_by: int | None = None,
) -> int:
    """Tombstone all live rows of `model` matching `criteria`. Returns rowcount."""
    result = await db.execute(
        update(model)
        .where(model.deleted_at.is_(None), *criteria)
        .values(deleted_at=when, deleted_by=deleted_by)
    )
    return result.rowcount or 0


import logging
from datetime import datetime

from sqlalchemy import or_, select, text, update

from app.db.models import (
    User, Router, Customer, CustomerPayment, Plan, ResellerFinancials,
    ResellerPayout, ResellerTransactionCharge, Payment, ProvisioningToken,
    Voucher, VoucherStatus, Subscription, SubscriptionInvoice, SubscriptionPayment,
    CustomerRating, UserBandwidthUsage, MpesaTransaction, ProvisioningLog,
    BandwidthSnapshot, RouterLogEntry, RouterAvailabilityCheck,
    ResellerPaymentMethod, B2BTransaction, ZenoPayTransaction, DevicePairing,
    ReconnectionAttempt, ProvisioningAttempt, CustomerUsagePeriod,
    UsageCapWatchState, Lead, LeadActivity, LeadFollowUp, LeadSource,
    MtnMomoTransaction, AccessCredential, PortalSettings, ShopProduct,
    ShopOrder, ShopOrderItem, ShopOrderTracking, SubscriptionShareCode,
    C2BTransaction, UnmatchedC2BPayment, SmsCreditAccount,
    SmsCreditTransaction, SmsCreditOrder, MessageTemplate, SmsCampaign,
    SmsMessage, ResellerInboxMessage,
)

logger = logging.getLogger(__name__)


async def soft_delete_reseller_cascade(db, reseller_id: int, deleted_by: int | None):
    """Tombstone a reseller (User) and ALL associated data, bottom-up.

    Shared by DELETE /api/admin/resellers/{id} and the self-service
    DELETE /api/profile. Commits the transaction. Returns the list of
    best-effort VPN-peer removal failures.
    """
    # ── Phase 1: WireGuard cleanup (best-effort) ──
    tokens_result = await db.execute(
        select(
            ProvisioningToken.id,
            ProvisioningToken.vpn_type,
            ProvisioningToken.l2tp_username,
            ProvisioningToken.wg_public_key,
        ).where(
            ProvisioningToken.user_id == reseller_id,
            ProvisioningToken.wg_public_key.isnot(None),
        )
    )
    vpn_peers = [dict(row) for row in tokens_result.mappings().all()]

    # Release the read transaction before calling the VPN manager.
    await db.commit()

    from app.services.provisioning import remove_wireguard_peer, remove_l2tp_peer

    wg_failures = []
    for tk in vpn_peers:
        try:
            if tk["vpn_type"] == "l2tp" and tk["l2tp_username"]:
                await remove_l2tp_peer(tk["l2tp_username"])
            elif tk["wg_public_key"]:
                await remove_wireguard_peer(tk["wg_public_key"])
        except Exception as e:
            wg_failures.append({"token_id": tk["id"], "error": str(e)})
            logger.warning(f"[DELETE-RESELLER] VPN peer removal failed for token {tk['id']}: {e}")

    # ── Phase 2: DB cascade soft-deletion (bottom-up) ──
    # Every row is tombstoned with ONE shared timestamp (soft delete,
    # docs/SOFT_DELETE_PLAN.md); the purge job hard-deletes the whole set
    # after the retention window. RADIUS rows are still hard-deleted right
    # now (FreeRADIUS reads those tables directly), and cross-reseller
    # references on LIVE rows are still nulled out exactly as before.
    # NOTE: the id-subqueries below run inside UPDATE/DELETE statements,
    # which the soft-delete SELECT filter does not touch — so they keep
    # matching rows tombstoned earlier in this same function.
    deleted_ts = datetime.utcnow()
    customer_ids = select(Customer.id).where(Customer.user_id == reseller_id)
    router_ids = select(Router.id).where(Router.user_id == reseller_id)
    plan_ids = select(Plan.id).where(Plan.user_id == reseller_id)
    campaign_ids = select(SmsCampaign.id).where(SmsCampaign.user_id == reseller_id)
    shop_order_ids = select(ShopOrder.id).where(ShopOrder.user_id == reseller_id)
    shop_product_ids = select(ShopProduct.id).where(ShopProduct.user_id == reseller_id)
    payment_method_ids = select(ResellerPaymentMethod.id).where(
        ResellerPaymentMethod.user_id == reseller_id
    )

    # 1. Null out vouchers.redeemed_by pointing to this reseller's customers
    await db.execute(
        update(Voucher).where(Voucher.redeemed_by.in_(customer_ids)).values(redeemed_by=None)
    )

    # 2-3. RADIUS tables (raw SQL since no ORM models)
    await db.execute(text(
        "DELETE FROM radius_check WHERE customer_id IN (SELECT id FROM customers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))
    await db.execute(text(
        "DELETE FROM radius_reply WHERE customer_id IN (SELECT id FROM customers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))

    # Messaging/SMS tables added after this deleter was first written.
    await soft_delete_where(db, SmsMessage, or_(
        SmsMessage.user_id == reseller_id,
        SmsMessage.customer_id.in_(customer_ids),
        SmsMessage.campaign_id.in_(campaign_ids),
    ), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, SmsCampaign, SmsCampaign.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, MessageTemplate, MessageTemplate.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, SmsCreditOrder, SmsCreditOrder.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, SmsCreditTransaction, SmsCreditTransaction.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, SmsCreditAccount, SmsCreditAccount.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ResellerInboxMessage, or_(
        ResellerInboxMessage.recipient_user_id == reseller_id,
        ResellerInboxMessage.sender_user_id == reseller_id,
    ), when=deleted_ts, deleted_by=deleted_by)

    # Preserve C2B audit rows but remove links to the deleted reseller/customers.
    await db.execute(
        update(C2BTransaction)
        .where(C2BTransaction.matched_customer_id.in_(customer_ids))
        .values(matched_customer_id=None)
    )
    await db.execute(
        update(C2BTransaction)
        .where(C2BTransaction.matched_reseller_id == reseller_id)
        .values(matched_reseller_id=None)
    )
    await db.execute(
        update(UnmatchedC2BPayment)
        .where(UnmatchedC2BPayment.assigned_reseller_id == reseller_id)
        .values(assigned_reseller_id=None)
    )
    await db.execute(
        update(UnmatchedC2BPayment)
        .where(UnmatchedC2BPayment.resolved_by_user_id == reseller_id)
        .values(resolved_by_user_id=None)
    )
    await db.execute(
        update(UnmatchedC2BPayment)
        .where(UnmatchedC2BPayment.resolution_customer_id.in_(customer_ids))
        .values(resolution_customer_id=None)
    )

    # Captive portal/shop data and cross-row shop references.
    await soft_delete_where(db, PortalSettings, PortalSettings.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await db.execute(
        update(ShopOrderTracking)
        .where(ShopOrderTracking.updated_by_user_id == reseller_id)
        .values(updated_by_user_id=None)
    )
    await soft_delete_where(db, ShopOrderTracking, ShopOrderTracking.order_id.in_(shop_order_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ShopOrderItem, ShopOrderItem.order_id.in_(shop_order_ids), when=deleted_ts, deleted_by=deleted_by)
    await db.execute(
        update(ShopOrderItem)
        .where(ShopOrderItem.product_id.in_(shop_product_ids))
        .values(product_id=None)
    )
    await soft_delete_where(db, ShopOrder, ShopOrder.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ShopProduct, ShopProduct.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    await soft_delete_where(db, SubscriptionShareCode, or_(
        SubscriptionShareCode.owner_customer_id.in_(customer_ids),
        SubscriptionShareCode.redeemed_customer_id.in_(customer_ids),
        SubscriptionShareCode.router_id.in_(router_ids),
    ), when=deleted_ts, deleted_by=deleted_by)
    await db.execute(
        update(Customer)
        .where(Customer.subscription_owner_id.in_(customer_ids))
        .values(subscription_owner_id=None)
    )
    await db.execute(
        update(DevicePairing)
        .where(DevicePairing.subscription_owner_customer_id.in_(customer_ids))
        .values(subscription_owner_customer_id=None)
    )
    await soft_delete_where(db, AccessCredential, or_(
        AccessCredential.user_id == reseller_id,
        AccessCredential.router_id.in_(router_ids),
    ), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, MtnMomoTransaction, MtnMomoTransaction.reseller_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, MtnMomoTransaction, MtnMomoTransaction.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 4. Customer ratings
    await soft_delete_where(db, CustomerRating, CustomerRating.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 5. User bandwidth usage
    await soft_delete_where(db, UserBandwidthUsage, UserBandwidthUsage.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 5b. Customer usage periods (NOT NULL customer_id FK — must be deleted
    #     explicitly; SQLAlchemy's default would try to NULL the FK and fail).
    await soft_delete_where(db, CustomerUsagePeriod, CustomerUsagePeriod.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, UsageCapWatchState, or_(
        UsageCapWatchState.customer_id.in_(customer_ids),
        UsageCapWatchState.router_id.in_(router_ids),
    ), when=deleted_ts, deleted_by=deleted_by)

    # 6. Provisioning logs (customer-side + router-side)
    await soft_delete_where(db, ProvisioningLog, ProvisioningLog.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ProvisioningLog, ProvisioningLog.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 6b. Provisioning attempts (references customers and routers; logs point here via attempt_id)
    await soft_delete_where(db, ProvisioningAttempt, ProvisioningAttempt.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ProvisioningAttempt, ProvisioningAttempt.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 7. M-Pesa transactions
    await soft_delete_where(db, MpesaTransaction, MpesaTransaction.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 8. Payments (old table)
    await soft_delete_where(db, Payment, Payment.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 9. Customer payments (delete by both reseller_id and customer_id to
    #    catch cross-reseller references)
    await soft_delete_where(db, CustomerPayment, CustomerPayment.reseller_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, CustomerPayment, CustomerPayment.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 9b. ZenoPay transactions (same cross-reference treatment)
    await soft_delete_where(db, ZenoPayTransaction, ZenoPayTransaction.reseller_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ZenoPayTransaction, ZenoPayTransaction.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)

    # 9c. Device pairings (references customers and routers)
    await soft_delete_where(db, DevicePairing, DevicePairing.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, DevicePairing, DevicePairing.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 9d. Reconnection attempts (references customers and routers; customer_id is nullable)
    await soft_delete_where(db, ReconnectionAttempt, ReconnectionAttempt.customer_id.in_(customer_ids), when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, ReconnectionAttempt, ReconnectionAttempt.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 10. Customers
    await soft_delete_where(db, Customer, Customer.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 11. Bandwidth snapshots
    await soft_delete_where(db, BandwidthSnapshot, BandwidthSnapshot.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 12. Router log entries
    await soft_delete_where(db, RouterLogEntry, RouterLogEntry.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 13. Router availability checks
    await soft_delete_where(db, RouterAvailabilityCheck, RouterAvailabilityCheck.router_id.in_(router_ids), when=deleted_ts, deleted_by=deleted_by)

    # 14. RADIUS NAS (raw SQL, no ORM model)
    await db.execute(text(
        "DELETE FROM radius_nas WHERE router_id IN (SELECT id FROM routers WHERE user_id = :uid)"
    ).bindparams(uid=reseller_id))

    # 15. Provisioning tokens (unlink router_id first, then delete)
    await db.execute(
        update(ProvisioningToken)
        .where(ProvisioningToken.router_id.in_(router_ids))
        .values(router_id=None)
    )
    await soft_delete_where(db, ProvisioningToken, ProvisioningToken.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 16. Vouchers
    await soft_delete_where(db, Voucher, Voucher.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 16b. Null out cross-reseller references: other resellers' customers or
    #       vouchers may point to this reseller's routers/plans.
    await db.execute(
        update(Customer).where(Customer.router_id.in_(router_ids)).values(router_id=None)
    )
    await db.execute(
        update(Customer).where(Customer.plan_id.in_(plan_ids)).values(plan_id=None)
    )
    await db.execute(
        update(Voucher).where(Voucher.router_id.in_(router_ids)).values(router_id=None)
    )
    await soft_delete_where(db, Voucher, Voucher.plan_id.in_(plan_ids), when=deleted_ts, deleted_by=deleted_by)
    await db.execute(
        update(Router).where(Router.payment_method_id.in_(payment_method_ids)).values(payment_method_id=None)
    )

    # 17. Routers
    await soft_delete_where(db, Router, Router.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 18. Plans
    await soft_delete_where(db, Plan, Plan.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 19. Reseller financials
    await soft_delete_where(db, ResellerFinancials, ResellerFinancials.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 20. B2B transactions (must precede payouts/charges due to FK)
    await soft_delete_where(db, B2BTransaction, B2BTransaction.reseller_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 21. Reseller payouts
    await soft_delete_where(db, ResellerPayout, ResellerPayout.reseller_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 21b. Reseller transaction charges
    created_charge_ids = select(ResellerTransactionCharge.id).where(
        ResellerTransactionCharge.created_by == reseller_id
    )
    await db.execute(
        update(B2BTransaction)
        .where(B2BTransaction.charge_id.in_(created_charge_ids))
        .values(charge_id=None)
    )
    await soft_delete_where(db, ResellerTransactionCharge, or_(
        ResellerTransactionCharge.reseller_id == reseller_id,
        ResellerTransactionCharge.created_by == reseller_id,
    ), when=deleted_ts, deleted_by=deleted_by)

    # 21c. Subscription payments (must precede invoices due to FK)
    await soft_delete_where(db, SubscriptionPayment, SubscriptionPayment.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 21d. Subscription invoices
    await soft_delete_where(db, SubscriptionInvoice, SubscriptionInvoice.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 21e. Subscriptions
    await soft_delete_where(db, Subscription, Subscription.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 22. Reseller payment methods
    await soft_delete_where(db, ResellerPaymentMethod, ResellerPaymentMethod.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 22d. CRM / Lead pipeline cleanup
    #   - Drop activities/follow-ups this reseller created on OTHER resellers'
    #     leads (created_by is NOT NULL so we can't null them out).
    #   - Delete this reseller's own leads (lead_activities/lead_follow_ups
    #     cascade via ondelete="CASCADE" on lead_id).
    #   - Null out leads.converted_user_id pointing to this user so we don't
    #     trip the leads_converted_user_id_fkey constraint.
    #   - Delete this reseller's lead sources.
    lead_source_ids = select(LeadSource.id).where(LeadSource.user_id == reseller_id)
    await soft_delete_where(db, LeadActivity, LeadActivity.created_by == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, LeadFollowUp, LeadFollowUp.created_by == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await soft_delete_where(db, Lead, Lead.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)
    await db.execute(
        update(Lead).where(Lead.converted_user_id == reseller_id).values(converted_user_id=None)
    )
    await db.execute(update(Lead).where(Lead.source_id.in_(lead_source_ids)).values(source_id=None))
    await soft_delete_where(db, LeadSource, LeadSource.user_id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    # 23. Null out created_by references from other users
    await db.execute(update(User).where(User.created_by == reseller_id).values(created_by=None))

    # 24. Delete the user row
    await soft_delete_where(db, User, User.id == reseller_id, when=deleted_ts, deleted_by=deleted_by)

    await db.commit()

    return wg_failures

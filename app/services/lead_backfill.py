"""
Backfill Lead records for resellers who exist as users but have no
corresponding row in the lead pipeline.

Useful whenever `try_link_lead_on_registration` silently fails (for
example, because the lead tables were missing, or the import errored,
or a deploy dropped the table) — this lets an admin re-capture every
missed signup in one call.

Exposed both as:
  - CLI:       `migrations/backfill_leads_from_signups.py`
  - Endpoint:  `POST /api/leads/backfill` (admin only)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    User,
    UserRole,
    Subscription,
    SubscriptionStatus,
    SubscriptionPayment,
    SubscriptionPaymentStatus,
    Router,
    Customer,
    Lead,
    LeadActivity,
    LeadActivityType,
    LeadSource,
    LeadStage,
)


@dataclass
class BackfilledLead:
    user_id: int
    email: Optional[str]
    name: str
    stage: str
    reason: str
    signup_date: Optional[str]
    lead_id: Optional[int] = None  # None when dry_run


@dataclass
class BackfillResult:
    since: Optional[str]
    dry_run: bool
    admin_owner_id: Optional[int]
    admin_owner_email: Optional[str]
    source_id: Optional[int]
    source_name: Optional[str]
    candidates: int
    leads_created: int
    stage_counts: dict[str, int] = field(default_factory=dict)
    items: list[BackfilledLead] = field(default_factory=list)
    message: str = ""


async def _pick_admin(db: AsyncSession, prefer_admin_id: Optional[int] = None) -> Optional[User]:
    if prefer_admin_id is not None:
        admin = await db.get(User, prefer_admin_id)
        if admin and admin.role == UserRole.ADMIN:
            return admin
    result = await db.execute(
        select(User)
        .where(User.role == UserRole.ADMIN)
        .order_by(User.id.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _pick_source(db: AsyncSession, admin_id: int) -> Optional[LeadSource]:
    """Prefer an active 'Website' source, fall back to 'Other', then to any
    other active source; re-activate a soft-disabled 'Website' if present;
    create 'Website' only if truly absent.

    ``LeadSource.name`` carries a global UNIQUE constraint, so we MUST NOT
    blindly insert "Website" without first checking for (even inactive)
    rows with that name — doing so would raise IntegrityError.
    """
    # 1) Active Website / Other
    active_result = await db.execute(
        select(LeadSource)
        .where(
            LeadSource.name.in_(["Website", "Other"]),
            LeadSource.is_active.is_(True),
        )
        .order_by(LeadSource.name.asc())
    )
    source = active_result.scalars().first()
    if source:
        return source

    # 2) Inactive Website / Other — re-activate if present (keep same id)
    inactive_result = await db.execute(
        select(LeadSource)
        .where(LeadSource.name.in_(["Website", "Other"]))
        .order_by(LeadSource.name.asc())
    )
    source = inactive_result.scalars().first()
    if source:
        source.is_active = True
        await db.flush()
        return source

    # 3) Any other active source as last-resort fallback
    any_active_result = await db.execute(
        select(LeadSource)
        .where(LeadSource.is_active.is_(True))
        .order_by(LeadSource.id.asc())
        .limit(1)
    )
    source = any_active_result.scalar_one_or_none()
    if source:
        return source

    # 4) Fresh DB — create 'Website'
    source = LeadSource(
        name="Website",
        description="Self-signup from website / marketing",
        is_active=True,
        user_id=admin_id,
    )
    db.add(source)
    await db.flush()
    return source


async def infer_stage_for_user(db: AsyncSession, user_id: int) -> tuple[LeadStage, str]:
    """Return (stage, reason) for a reseller based on observable state.

    Priority (first match wins):
      1. churned              — subscription suspended/inactive AND at least
                                one completed payment ever.
      2. paying               — subscription active, OR has ≥1 completed
                                payment and is NOT currently suspended/inactive.
      3. installation_help    — has ≥1 router OR ≥1 customer record but no
                                paying signal.
      4. signed_up            — registered, none of the above.
    """
    sub_result = await db.execute(
        select(Subscription.status).where(Subscription.user_id == user_id)
    )
    sub_status = sub_result.scalar_one_or_none()

    paid_ever_result = await db.execute(
        select(func.count(SubscriptionPayment.id)).where(
            SubscriptionPayment.user_id == user_id,
            SubscriptionPayment.status == SubscriptionPaymentStatus.COMPLETED,
        )
    )
    paid_ever = (paid_ever_result.scalar() or 0) > 0

    sub_is_suspended_or_inactive = sub_status in (
        SubscriptionStatus.SUSPENDED,
        SubscriptionStatus.INACTIVE,
    )

    if sub_is_suspended_or_inactive and paid_ever:
        return (
            LeadStage.CHURNED,
            f"subscription.status={sub_status.value}, previously paid",
        )

    if sub_status == SubscriptionStatus.ACTIVE or (
        paid_ever and not sub_is_suspended_or_inactive
    ):
        bits = []
        if sub_status == SubscriptionStatus.ACTIVE:
            bits.append("subscription.status=active")
        if paid_ever:
            bits.append("has completed payments")
        return LeadStage.PAYING, ", ".join(bits) or "active subscription"

    router_count = (
        await db.execute(select(func.count(Router.id)).where(Router.user_id == user_id))
    ).scalar() or 0
    customer_count = (
        await db.execute(select(func.count(Customer.id)).where(Customer.user_id == user_id))
    ).scalar() or 0

    if router_count > 0 or customer_count > 0:
        return (
            LeadStage.INSTALLATION_HELP,
            f"{router_count} router(s), {customer_count} customer(s), no paying signal",
        )

    return LeadStage.SIGNED_UP, "registered, no infrastructure or payments yet"


async def backfill_leads(
    db: AsyncSession,
    *,
    since: Optional[date] = None,
    dry_run: bool = False,
    prefer_admin_id: Optional[int] = None,
) -> BackfillResult:
    """Core backfill routine. The caller owns the transaction:
    commit on success / rollback on failure.

    When `dry_run=True`, no rows are written but a full plan is returned.
    """
    admin = await _pick_admin(db, prefer_admin_id=prefer_admin_id)
    if not admin:
        return BackfillResult(
            since=since.isoformat() if since else None,
            dry_run=dry_run,
            admin_owner_id=None,
            admin_owner_email=None,
            source_id=None,
            source_name=None,
            candidates=0,
            leads_created=0,
            message="No admin user found; cannot backfill (lead owner required).",
        )

    source = await _pick_source(db, admin.id)

    already_linked_subq = select(Lead.converted_user_id).where(
        Lead.converted_user_id.is_not(None)
    )

    conditions = [
        User.role == UserRole.RESELLER,
        ~User.id.in_(already_linked_subq),
    ]
    if since is not None:
        conditions.append(
            User.created_at >= datetime.combine(since, datetime.min.time())
        )

    cand_result = await db.execute(
        select(User).where(*conditions).order_by(User.created_at.asc())
    )
    candidates = cand_result.scalars().all()

    result = BackfillResult(
        since=since.isoformat() if since else None,
        dry_run=dry_run,
        admin_owner_id=admin.id,
        admin_owner_email=admin.email,
        source_id=source.id if source else None,
        source_name=source.name if source else None,
        candidates=len(candidates),
        leads_created=0,
    )

    if not candidates:
        result.message = (
            f"No reseller signups need a lead record"
            f"{f' since {since.isoformat()}' if since else ''}."
        )
        return result

    now = datetime.utcnow()

    for user in candidates:
        stage, reason = await infer_stage_for_user(db, user.id)

        email = user.email or ""
        display_name = (
            user.organization_name
            or (email.split("@")[0] if email else f"user-{user.id}")
        )
        phone = getattr(user, "support_phone", None)

        result.stage_counts[stage.value] = result.stage_counts.get(stage.value, 0) + 1

        item = BackfilledLead(
            user_id=user.id,
            email=email or None,
            name=display_name,
            stage=stage.value,
            reason=reason,
            signup_date=user.created_at.date().isoformat() if user.created_at else None,
        )

        if not dry_run:
            lead = Lead(
                user_id=admin.id,
                name=display_name,
                phone=phone,
                email=email or None,
                source_id=source.id if source else None,
                source_detail=(
                    f"Backfilled on {now.date().isoformat()} for pre-existing "
                    f"reseller (signed up before lead capture ran successfully)"
                ),
                stage=stage,
                stage_changed_at=now,
                converted_user_id=user.id,
                created_at=user.created_at or now,
                updated_at=now,
            )
            db.add(lead)
            await db.flush()

            activity = LeadActivity(
                lead_id=lead.id,
                activity_type=LeadActivityType.STAGE_CHANGE,
                description=(
                    f"Backfilled lead for reseller {email or user.id}. "
                    f"Stage inferred from state: {reason}."
                ),
                old_stage=None,
                new_stage=stage.value,
                created_by=admin.id,
                created_at=now,
            )
            db.add(activity)

            item.lead_id = lead.id
            result.leads_created += 1

        result.items.append(item)

    if dry_run:
        result.message = (
            f"Dry run — {len(candidates)} reseller(s) would be backfilled."
        )
    else:
        result.message = (
            f"Backfill complete — {result.leads_created} lead(s) created."
        )

    return result

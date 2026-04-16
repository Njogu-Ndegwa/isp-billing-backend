"""
Automatic lead stage progression.

Called from registration, subscription activation, and subscription
deactivation to keep lead stages in sync with actual reseller lifecycle.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from datetime import datetime
from app.db.models import Lead, LeadSource, LeadActivity, LeadActivityType, LeadStage, User, UserRole
import logging

logger = logging.getLogger(__name__)


async def try_link_lead_on_registration(
    db: AsyncSession, user_id: int, email: str,
    phone: str = None, organization_name: str = None,
):
    """
    When a new reseller registers, check if they match an existing lead
    by email or phone. If found, link the lead and move it to signed_up.

    If no matching lead exists, auto-create one so every reseller is tracked
    in the pipeline (covers direct sign-ups from ads, website, etc.).
    """
    conditions = [Lead.email.ilike(email)]
    if phone:
        conditions.append(Lead.phone == phone)

    result = await db.execute(
        select(Lead).where(
            Lead.converted_user_id.is_(None),
            or_(*conditions),
        ).order_by(Lead.created_at.desc())
        .limit(1)
    )
    lead = result.scalar_one_or_none()

    if lead:
        lead.converted_user_id = user_id
        old_stage = lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage)

        if lead.stage not in (LeadStage.SIGNED_UP, LeadStage.PAYING):
            lead.stage = LeadStage.SIGNED_UP
            lead.stage_changed_at = datetime.utcnow()

            activity = LeadActivity(
                lead_id=lead.id,
                activity_type=LeadActivityType.STAGE_CHANGE,
                description=f"Auto-linked: reseller registered with email {email}",
                old_stage=old_stage,
                new_stage=LeadStage.SIGNED_UP.value,
                created_by=lead.user_id,
            )
            db.add(activity)

        await db.flush()
        logger.info(f"[LEAD] Auto-linked lead {lead.id} ({lead.name}) to user {user_id}")
        return lead

    # No matching lead — auto-create one for this self-signup reseller
    admin_result = await db.execute(
        select(User).where(User.role == UserRole.ADMIN).limit(1)
    )
    admin = admin_result.scalar_one_or_none()
    if not admin:
        logger.warning("[LEAD] No admin user found, cannot auto-create lead")
        return None

    # Try to find the "Website" source, fall back to "Other"
    source_result = await db.execute(
        select(LeadSource).where(
            LeadSource.name.in_(["Website", "Other"]),
            LeadSource.is_active == True,
        ).order_by(LeadSource.name.asc())
    )
    source = source_result.scalars().first()

    lead = Lead(
        user_id=admin.id,
        name=organization_name or email.split("@")[0],
        email=email,
        phone=phone,
        source_id=source.id if source else None,
        source_detail="Self-signup (no prior lead record)",
        stage=LeadStage.SIGNED_UP,
        stage_changed_at=datetime.utcnow(),
        converted_user_id=user_id,
    )
    db.add(lead)
    await db.flush()

    activity = LeadActivity(
        lead_id=lead.id,
        activity_type=LeadActivityType.STAGE_CHANGE,
        description=f"Auto-created: reseller self-registered ({email})",
        new_stage=LeadStage.SIGNED_UP.value,
        created_by=admin.id,
    )
    db.add(activity)
    await db.flush()

    logger.info(f"[LEAD] Auto-created lead {lead.id} for self-signup user {user_id} ({email})")
    return lead


async def advance_lead_to_paying(db: AsyncSession, user_id: int):
    """
    When a reseller's subscription is activated, move their linked lead to 'paying'.
    """
    result = await db.execute(
        select(Lead).where(Lead.converted_user_id == user_id)
    )
    lead = result.scalar_one_or_none()
    if not lead:
        return None

    current_stage = lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage)
    if current_stage == LeadStage.PAYING.value:
        return lead

    if current_stage in (LeadStage.CHURNED.value, LeadStage.LOST.value):
        desc = "Reseller reactivated subscription — moved back to paying"
    else:
        desc = "Reseller subscription activated — auto-advanced to paying"

    lead.stage = LeadStage.PAYING
    lead.stage_changed_at = datetime.utcnow()

    activity = LeadActivity(
        lead_id=lead.id,
        activity_type=LeadActivityType.STAGE_CHANGE,
        description=desc,
        old_stage=current_stage,
        new_stage=LeadStage.PAYING.value,
        created_by=lead.user_id,
    )
    db.add(activity)
    await db.flush()
    logger.info(f"[LEAD] Auto-advanced lead {lead.id} to paying (user {user_id})")
    return lead


async def regress_lead_to_churned(db: AsyncSession, user_id: int):
    """
    When a reseller's subscription is suspended/deactivated, move their
    linked lead to 'churned'.
    """
    result = await db.execute(
        select(Lead).where(Lead.converted_user_id == user_id)
    )
    lead = result.scalar_one_or_none()
    if not lead:
        return None

    current_stage = lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage)
    if current_stage == LeadStage.CHURNED.value:
        return lead

    lead.stage = LeadStage.CHURNED
    lead.stage_changed_at = datetime.utcnow()
    lead.lost_reason = "Subscription suspended/deactivated"

    activity = LeadActivity(
        lead_id=lead.id,
        activity_type=LeadActivityType.STAGE_CHANGE,
        description="Reseller subscription suspended — auto-moved to churned",
        old_stage=current_stage,
        new_stage=LeadStage.CHURNED.value,
        created_by=lead.user_id,
    )
    db.add(activity)
    await db.flush()
    logger.info(f"[LEAD] Auto-regressed lead {lead.id} to churned (user {user_id})")
    return lead

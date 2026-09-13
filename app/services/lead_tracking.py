"""
Automatic lead stage progression.

Called from registration, subscription activation, and subscription
deactivation to keep lead stages in sync with actual reseller lifecycle.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from app.db.models import Lead, LeadSource, LeadActivity, LeadActivityType, LeadStage, User, UserRole
from app.services import attribution as attribution_service
import logging

logger = logging.getLogger(__name__)

# utm_source spellings the marketing site and the ad platforms actually emit,
# mapped to the display name the CRM's managed source list uses.
_CHANNEL_NAMES = {
    "tiktok": "TikTok",
    "tt": "TikTok",
    "google": "Google",
    "googleads": "Google",
    "google_ads": "Google",
    "adwords": "Google",
    "bing": "Bing",
    "facebook": "Facebook",
    "fb": "Facebook",
    "meta": "Facebook",
    "instagram": "Instagram",
    "ig": "Instagram",
    "whatsapp": "WhatsApp",
    "youtube": "YouTube",
    "linkedin": "LinkedIn",
    "twitter": "X",
    "x": "X",
    "referral": "Referral",
}


def _channel_name(details) -> str:
    """Name the CRM source this signup belongs to, e.g. "TikTok Ads".

    Paid and organic are kept apart on purpose. When budget is running, "did
    this reseller come from the TikTok ad or from an organic post?" is the whole
    question, and one shared "TikTok" row cannot answer it.
    """
    raw = (details.get("utm_source") or "").strip().lower()
    base = _CHANNEL_NAMES.get(raw)
    if not base:
        # An unrecognised source is still worth keeping under its own name
        # rather than being flattened into "Website".
        base = raw.replace("_", " ").replace("-", " ").title()[:60]
    if not base:
        return "Website"
    return f"{base} Ads" if attribution_service.is_paid(details) else base


def _source_detail(details) -> str:
    """One-line provenance for the lead card: campaign, creative, landing page."""
    bits = []
    for key, label in (("utm_campaign", "campaign"), ("utm_content", "creative"),
                       ("utm_medium", "medium"), ("utm_term", "term")):
        value = details.get(key)
        if value:
            bits.append(f"{label} {value}")
    landing = details.get("landing_path")
    if landing:
        bits.append(f"landed on {landing}")
    referrer = details.get("referrer")
    if referrer and not bits:
        bits.append(f"referrer {referrer}")
    prefix = "Paid click" if attribution_service.is_paid(details) else "Self-signup"
    return (f"{prefix} — " + ", ".join(bits) if bits else f"{prefix} (no campaign tags)")[:500]


async def _resolve_attributed_source(db: AsyncSession, admin_id: int, details):
    """Find — or add — the managed LeadSource row this signup belongs to.

    The source list is a managed vocabulary, so a channel that starts sending
    real signups earns a row rather than being dropped into "Other" where it
    stops being countable. Returns None to fall back to the old behaviour.
    """
    name = _channel_name(details)[:100]
    if not name:
        return None

    async def _find():
        result = await db.execute(
            select(LeadSource).where(func.lower(LeadSource.name) == name.lower()).limit(1)
        )
        return result.scalar_one_or_none()

    source = await _find()
    if source:
        return source

    # LeadSource.name is unique, so two signups from a brand-new channel at the
    # same moment race here. The savepoint means the loser's IntegrityError
    # costs it the INSERT, not the whole registration transaction.
    try:
        async with db.begin_nested():
            source = LeadSource(
                name=name,
                description="Added automatically from signup attribution",
                is_active=True,
                user_id=admin_id,
            )
            db.add(source)
            await db.flush()
        logger.info(f"[LEAD] Created lead source '{name}' from signup attribution")
        return source
    except IntegrityError:
        return await _find()


async def try_link_lead_on_registration(
    db: AsyncSession, user_id: int, email: str,
    phone: str = None, organization_name: str = None,
    attribution: dict = None,
):
    """
    When a new reseller registers, check if they match an existing lead
    by email or phone. If found, link the lead and move it to signed_up.

    If no matching lead exists, auto-create one so every reseller is tracked
    in the pipeline (covers direct sign-ups from ads, website, etc.).

    `attribution` is the sanitized first-touch payload from the signup. When it
    is present the auto-created lead is filed under the channel it came from
    ("TikTok Ads", "Google Ads") instead of the generic "Website", which is what
    makes signups countable by channel in the pipeline the team already uses.
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

        # This lead already existed, so somebody spoke to them first — their
        # recorded source is the true one and an ad click does not overwrite it.
        # Fill it in only when nobody ever set one.
        if attribution and lead.source_id is None:
            try:
                admin_result = await db.execute(
                    select(User).where(User.role == UserRole.ADMIN).limit(1)
                )
                admin = admin_result.scalar_one_or_none()
                if admin:
                    attributed = await _resolve_attributed_source(db, admin.id, attribution)
                    if attributed:
                        lead.source_id = attributed.id
                        lead.source_detail = _source_detail(attribution)
            except Exception as source_err:
                logger.warning(f"[LEAD] Could not attribute existing lead: {source_err}")

        if lead.stage not in (LeadStage.SIGNED_UP, LeadStage.PAYING):
            lead.stage = LeadStage.SIGNED_UP
            lead.stage_changed_at = datetime.utcnow()

            description = f"Auto-linked: reseller registered with email {email}"
            if attribution:
                description = f"{description} — {_source_detail(attribution)}"

            activity = LeadActivity(
                lead_id=lead.id,
                activity_type=LeadActivityType.STAGE_CHANGE,
                description=description[:2000],
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

    source = None
    if attribution:
        try:
            source = await _resolve_attributed_source(db, admin.id, attribution)
        except Exception as source_err:
            logger.warning(f"[LEAD] Could not attribute new lead: {source_err}")

    if source is None:
        # Untagged signup — the old behaviour: "Website", falling back to "Other"
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
        source_detail=(
            _source_detail(attribution) if attribution
            else "Self-signup (no prior lead record)"
        ),
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

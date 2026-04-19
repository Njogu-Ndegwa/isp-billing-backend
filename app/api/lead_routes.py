from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete, or_
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from app.db.database import get_db
from app.db.models import (
    Lead, LeadSource, LeadActivity, LeadFollowUp,
    LeadStage, LeadActivityType, User, UserRole,
)
from app.services.auth import verify_token, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["leads"])


async def _require_admin(token: dict, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ========================================
# Pydantic schemas
# ========================================

class LeadSourceCreate(BaseModel):
    name: str
    description: Optional[str] = None

class LeadSourceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

class LeadSourceOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    is_active: bool
    created_at: datetime

class LeadCreate(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None
    social_platform: Optional[str] = None
    social_handle: Optional[str] = None
    source_id: Optional[int] = None
    source_detail: Optional[str] = None
    stage: Optional[str] = "new_lead"
    notes: Optional[str] = None
    next_followup_at: Optional[datetime] = None

class LeadUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    social_platform: Optional[str] = None
    social_handle: Optional[str] = None
    source_id: Optional[int] = None
    source_detail: Optional[str] = None
    notes: Optional[str] = None
    next_followup_at: Optional[datetime] = None

class LeadStageUpdate(BaseModel):
    stage: str
    lost_reason: Optional[str] = None
    note: Optional[str] = None

class ActivityCreate(BaseModel):
    activity_type: str
    description: Optional[str] = None

class FollowUpCreate(BaseModel):
    title: str
    due_at: datetime

class LeadConvertRequest(BaseModel):
    email: str
    organization_name: str
    password: str
    business_name: Optional[str] = None
    support_phone: Optional[str] = None


class LeadBackfillRequest(BaseModel):
    """Body for `POST /api/leads/backfill`.

    All fields are optional; defaults backfill every reseller without a
    lead record, no date cutoff, and actually write (no dry run).
    """
    since: Optional[str] = None   # "YYYY-MM-DD" or null / "all"
    dry_run: bool = False


# ========================================
# Lead Sources endpoints
# ========================================

@router.get("/api/leads/sources", response_model=List[LeadSourceOut])
async def list_lead_sources(
    active_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """List all lead sources (for dropdown selection)."""
    await _require_admin(token, db)
    query = select(LeadSource).order_by(LeadSource.name)
    if active_only:
        query = query.where(LeadSource.is_active == True)
    result = await db.execute(query)
    sources = result.scalars().all()
    return [
        LeadSourceOut(
            id=s.id, name=s.name, description=s.description,
            is_active=s.is_active, created_at=s.created_at,
        ) for s in sources
    ]


@router.post("/api/leads/sources", response_model=LeadSourceOut, status_code=201)
async def create_lead_source(
    req: LeadSourceCreate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Add a new lead source."""
    admin = await _require_admin(token, db)
    existing = await db.execute(
        select(LeadSource).where(func.lower(LeadSource.name) == req.name.lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A source with this name already exists")
    source = LeadSource(
        name=req.name,
        description=req.description,
        user_id=admin.id,
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return LeadSourceOut(
        id=source.id, name=source.name, description=source.description,
        is_active=source.is_active, created_at=source.created_at,
    )


@router.put("/api/leads/sources/{source_id}", response_model=LeadSourceOut)
async def update_lead_source(
    source_id: int,
    req: LeadSourceUpdate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Update a lead source."""
    await _require_admin(token, db)
    source = await db.get(LeadSource, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    if req.name is not None:
        dup = await db.execute(
            select(LeadSource).where(
                func.lower(LeadSource.name) == req.name.lower(),
                LeadSource.id != source_id,
            )
        )
        if dup.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A source with this name already exists")
        source.name = req.name
    if req.description is not None:
        source.description = req.description
    if req.is_active is not None:
        source.is_active = req.is_active
    await db.commit()
    await db.refresh(source)
    return LeadSourceOut(
        id=source.id, name=source.name, description=source.description,
        is_active=source.is_active, created_at=source.created_at,
    )


@router.delete("/api/leads/sources/{source_id}")
async def delete_lead_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Deactivate a lead source (soft delete)."""
    await _require_admin(token, db)
    source = await db.get(LeadSource, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    source.is_active = False
    await db.commit()
    return {"detail": "Source deactivated", "id": source_id}


# ========================================
# Lead CRUD endpoints
# ========================================

@router.post("/api/leads", status_code=201)
async def create_lead(
    req: LeadCreate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Create a new lead in the pipeline."""
    admin = await _require_admin(token, db)

    stage_value = req.stage or "new_lead"
    try:
        stage_enum = LeadStage(stage_value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid stage: {stage_value}")

    if req.source_id:
        source = await db.get(LeadSource, req.source_id)
        if not source:
            raise HTTPException(status_code=400, detail="Invalid source_id")

    lead = Lead(
        user_id=admin.id,
        name=req.name,
        phone=req.phone,
        email=req.email,
        social_platform=req.social_platform,
        social_handle=req.social_handle,
        source_id=req.source_id,
        source_detail=req.source_detail,
        stage=stage_enum,
        stage_changed_at=datetime.utcnow(),
        next_followup_at=req.next_followup_at,
        notes=req.notes,
    )
    db.add(lead)
    await db.flush()

    activity = LeadActivity(
        lead_id=lead.id,
        activity_type=LeadActivityType.STAGE_CHANGE,
        description="Lead created",
        new_stage=stage_value,
        created_by=admin.id,
    )
    db.add(activity)
    await db.commit()
    await db.refresh(lead)

    return await _lead_to_dict(lead, db)


@router.post("/api/leads/backfill")
async def backfill_leads_endpoint(
    req: Optional[LeadBackfillRequest] = Body(default=None),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Backfill Lead rows for resellers who never got auto-captured.

    Admin-only manual override for the case where
    `try_link_lead_on_registration` (called on signup) silently failed —
    for example because the lead tables didn't exist yet, or the import
    errored, or a deploy temporarily dropped them. Hits every reseller
    without a matching `leads.converted_user_id` and creates one lead
    each, with the stage inferred from their current state:

      churned              — subscription suspended/inactive AND paid before
      paying               — subscription active OR at least one completed payment
      installation_help    — has routers or customers but no paying signal
      signed_up            — registered, none of the above

    Request body (all optional):
        {
          "since":    "2026-04-16",   // or "all" / null for no cutoff
          "dry_run":  false            // true => preview only, no writes
        }
    """
    from app.services.lead_backfill import backfill_leads
    from dataclasses import asdict

    admin = await _require_admin(token, db)

    body = req or LeadBackfillRequest()

    since_date = None
    if body.since and body.since.lower() != "all":
        try:
            since_date = datetime.strptime(body.since, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="`since` must be in YYYY-MM-DD format, or 'all' / null for no cutoff",
            )

    try:
        result = await backfill_leads(
            db,
            since=since_date,
            dry_run=body.dry_run,
            prefer_admin_id=admin.id,
        )
        if body.dry_run:
            await db.rollback()
        else:
            await db.commit()
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.exception("Lead backfill failed")
        raise HTTPException(status_code=500, detail=f"Backfill failed: {e}")

    return asdict(result)


@router.get("/api/leads")
async def list_leads(
    stage: Optional[str] = None,
    source_id: Optional[int] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """List leads with filters and pagination."""
    admin = await _require_admin(token, db)
    query = select(Lead).where(Lead.user_id == admin.id)

    if stage:
        try:
            stage_enum = LeadStage(stage)
            query = query.where(Lead.stage == stage_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid stage: {stage}")

    if source_id:
        query = query.where(Lead.source_id == source_id)

    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Lead.name.ilike(pattern),
                Lead.phone.ilike(pattern),
                Lead.email.ilike(pattern),
                Lead.social_handle.ilike(pattern),
            )
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    query = (
        query
        .options(selectinload(Lead.source))
        .order_by(Lead.updated_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    result = await db.execute(query)
    leads = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "leads": [_lead_to_summary(l) for l in leads],
    }


@router.get("/api/leads/pipeline/summary")
async def pipeline_summary(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Get counts per stage for Kanban board display."""
    admin = await _require_admin(token, db)
    result = await db.execute(
        select(Lead.stage, func.count(Lead.id))
        .where(Lead.user_id == admin.id)
        .group_by(Lead.stage)
    )
    counts = {row[0].value if hasattr(row[0], 'value') else row[0]: row[1] for row in result.all()}
    all_stages = [s.value for s in LeadStage]
    return {
        "stages": {s: counts.get(s, 0) for s in all_stages},
        "total": sum(counts.values()),
    }


@router.get("/api/leads/pipeline/stats")
async def pipeline_stats(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """
    Comprehensive pipeline analytics: conversion funnel with drop-off
    percentages, leads by source, stale lead detection, and actionable advice.
    """
    admin = await _require_admin(token, db)
    from datetime import timedelta
    now = datetime.utcnow()

    # --- Counts by stage ---
    by_stage_result = await db.execute(
        select(Lead.stage, func.count(Lead.id))
        .where(Lead.user_id == admin.id)
        .group_by(Lead.stage)
    )
    stage_counts = {
        (row[0].value if hasattr(row[0], 'value') else row[0]): row[1]
        for row in by_stage_result.all()
    }
    total = sum(stage_counts.values())

    # --- Counts by source ---
    by_source_result = await db.execute(
        select(LeadSource.name, func.count(Lead.id))
        .join(Lead, Lead.source_id == LeadSource.id)
        .where(Lead.user_id == admin.id)
        .group_by(LeadSource.name)
        .order_by(func.count(Lead.id).desc())
    )
    source_counts = {row[0]: row[1] for row in by_source_result.all()}

    # --- Source-to-paying conversion (which source actually produces paying resellers?) ---
    paying_by_source_result = await db.execute(
        select(LeadSource.name, func.count(Lead.id))
        .join(Lead, Lead.source_id == LeadSource.id)
        .where(
            Lead.user_id == admin.id,
            Lead.stage.in_([LeadStage.PAYING, LeadStage.SIGNED_UP]),
        )
        .group_by(LeadSource.name)
    )
    paying_by_source = {row[0]: row[1] for row in paying_by_source_result.all()}
    source_conversion = {}
    for src, count in source_counts.items():
        converted = paying_by_source.get(src, 0)
        source_conversion[src] = {
            "total": count,
            "converted": converted,
            "conversion_rate": round(converted / count * 100, 1) if count else 0,
        }

    # --- Funnel: how many leads reached each stage or beyond? ---
    # A lead has "reached" a stage if they are currently at-or-past that stage,
    # OR their STAGE_CHANGE history shows they were ever at that stage or
    # beyond (this captures `lost` leads whose current stage doesn't reveal
    # how far they progressed). `churned` counts as having reached `paying`.
    funnel_order = [
        "new_lead", "contacted", "talking", "installation_help",
        "signed_up", "paying",
    ]
    stage_rank = {s: i for i, s in enumerate(funnel_order)}
    paying_rank = stage_rank["paying"]

    history_result = await db.execute(
        select(LeadActivity.lead_id, LeadActivity.new_stage)
        .join(Lead, LeadActivity.lead_id == Lead.id)
        .where(
            Lead.user_id == admin.id,
            LeadActivity.activity_type == LeadActivityType.STAGE_CHANGE,
        )
    )
    max_historical_rank: dict[int, int] = {}
    for lead_id, new_stage in history_result.all():
        if new_stage == "churned":
            r = paying_rank
        else:
            r = stage_rank.get(new_stage)
        if r is None:
            continue  # "lost" or any unknown stage contributes nothing
        if r > max_historical_rank.get(lead_id, -1):
            max_historical_rank[lead_id] = r

    current_result = await db.execute(
        select(Lead.id, Lead.stage).where(Lead.user_id == admin.id)
    )
    reached = {stage: 0 for stage in funnel_order}
    for lead_id, stage in current_result.all():
        stage_val = stage.value if hasattr(stage, "value") else stage
        if stage_val == "churned":
            current_rank = paying_rank
        elif stage_val == "lost":
            current_rank = -1  # current stage contributes nothing; use history
        else:
            current_rank = stage_rank.get(stage_val, -1)
        best_rank = max(current_rank, max_historical_rank.get(lead_id, -1))
        if best_rank < 0:
            continue
        for i in range(best_rank + 1):
            reached[funnel_order[i]] += 1

    # Build funnel steps. `still_in_stage` = currently in this stage (active,
    # not a drop-off). `dropped_off` = leads that reached the PREVIOUS stage
    # but neither progressed to this stage nor are still sitting at the
    # previous stage — i.e. they gave up (went to `lost`) between the two.
    funnel_steps = []
    for i, stage in enumerate(funnel_order):
        reached_here = reached[stage]
        still_here = stage_counts.get(stage, 0)
        pct_of_total = round(reached_here / total * 100, 1) if total else 0.0
        if i == 0:
            dropped = 0
            drop_pct = 0.0
        else:
            prev = funnel_order[i - 1]
            prev_reached = reached[prev]
            prev_still = stage_counts.get(prev, 0)
            dropped = max(prev_reached - reached_here - prev_still, 0)
            drop_pct = round(dropped / prev_reached * 100, 1) if prev_reached else 0.0
        funnel_steps.append({
            "stage": stage,
            "reached": reached_here,
            "percent_of_total": pct_of_total,
            "still_in_stage": still_here,
            "dropped_off": dropped,
            "drop_off_percent": drop_pct,
        })

    # --- Stale leads: sitting in active stages with no update for 7+ days ---
    active_stages = [
        LeadStage.NEW_LEAD, LeadStage.CONTACTED, LeadStage.TALKING,
        LeadStage.INSTALLATION_HELP, LeadStage.SIGNED_UP,
    ]
    stale_cutoff = now - timedelta(days=7)

    stale_result = await db.execute(
        select(Lead)
        .where(
            Lead.user_id == admin.id,
            Lead.stage.in_(active_stages),
            Lead.updated_at < stale_cutoff,
        )
        .order_by(Lead.updated_at.asc())
        .limit(20)
    )
    stale_leads = stale_result.scalars().all()

    stale_count_result = await db.execute(
        select(func.count(Lead.id))
        .where(
            Lead.user_id == admin.id,
            Lead.stage.in_(active_stages),
            Lead.updated_at < stale_cutoff,
        )
    )
    stale_total = stale_count_result.scalar() or 0

    # --- Leads with no follow-up scheduled ---
    no_followup_result = await db.execute(
        select(func.count(Lead.id))
        .where(
            Lead.user_id == admin.id,
            Lead.stage.in_(active_stages),
            Lead.next_followup_at.is_(None),
        )
    )
    no_followup_count = no_followup_result.scalar() or 0

    # --- Overdue follow-ups ---
    overdue_result = await db.execute(
        select(func.count(LeadFollowUp.id))
        .join(Lead, LeadFollowUp.lead_id == Lead.id)
        .where(
            Lead.user_id == admin.id,
            LeadFollowUp.is_completed == False,
            LeadFollowUp.due_at < now,
        )
    )
    overdue_followups = overdue_result.scalar() or 0

    # --- Average days in each active stage ---
    avg_time_in_stage = {}
    for stage_enum in active_stages:
        avg_result = await db.execute(
            select(func.avg(func.extract('epoch', now - Lead.stage_changed_at) / 86400))
            .where(
                Lead.user_id == admin.id,
                Lead.stage == stage_enum,
            )
        )
        avg_days = avg_result.scalar()
        avg_time_in_stage[stage_enum.value] = round(avg_days, 1) if avg_days else 0

    # --- Top-level metrics ---
    paying = stage_counts.get("paying", 0)
    signed_up = stage_counts.get("signed_up", 0)
    lost = stage_counts.get("lost", 0)
    churned = stage_counts.get("churned", 0)
    active_pipeline = sum(stage_counts.get(s, 0) for s in ["new_lead", "contacted", "talking", "installation_help"])

    # --- Build actionable advice ---
    advice = _generate_advice(
        stage_counts, funnel_steps, stale_total, no_followup_count,
        overdue_followups, avg_time_in_stage, source_conversion, total,
    )

    return {
        "total_leads": total,
        "active_pipeline": active_pipeline,
        "conversion_rate": round((paying + signed_up) / total * 100, 1) if total else 0,
        "loss_rate": round((lost + churned) / total * 100, 1) if total else 0,
        "by_stage": stage_counts,
        "by_source": source_conversion,
        "funnel": funnel_steps,
        "avg_days_in_stage": avg_time_in_stage,
        "health": {
            "stale_leads": stale_total,
            "no_followup_scheduled": no_followup_count,
            "overdue_followups": overdue_followups,
            "stale_lead_previews": [
                {
                    "id": l.id,
                    "name": l.name,
                    "stage": l.stage.value if hasattr(l.stage, 'value') else str(l.stage),
                    "days_since_update": (now - l.updated_at).days if l.updated_at else None,
                    "phone": l.phone,
                }
                for l in stale_leads
            ],
        },
        "advice": advice,
    }


def _generate_advice(
    stage_counts: dict,
    funnel_steps: list,
    stale_total: int,
    no_followup_count: int,
    overdue_followups: int,
    avg_time_in_stage: dict,
    source_conversion: dict,
    total: int,
) -> list:
    """Generate actionable advice based on pipeline data."""
    tips = []

    # Tip: stale leads
    if stale_total > 0:
        tips.append({
            "priority": "high",
            "category": "follow_up",
            "title": f"{stale_total} lead(s) have gone cold",
            "detail": (
                f"You have {stale_total} leads in active stages with no update for 7+ days. "
                "These are at high risk of being lost. Reach out today — even a quick "
                "\"Hey, still interested?\" message can re-engage them."
            ),
        })

    # Tip: overdue follow-ups
    if overdue_followups > 0:
        tips.append({
            "priority": "high",
            "category": "follow_up",
            "title": f"{overdue_followups} overdue follow-up(s)",
            "detail": (
                f"You have {overdue_followups} follow-ups past their due date. "
                "Studies show 80% of sales require at least 5 follow-ups, but most "
                "people give up after 1-2. Complete these today."
            ),
        })

    # Tip: no follow-up scheduled
    if no_followup_count > 0:
        tips.append({
            "priority": "medium",
            "category": "follow_up",
            "title": f"{no_followup_count} active lead(s) with no follow-up scheduled",
            "detail": (
                "Every active lead should have a next step. Schedule follow-ups "
                "for these leads so nothing slips through the cracks. "
                "Rule of thumb: follow up within 1 day, 3 days, and 7 days."
            ),
        })

    # Tip: biggest drop-off in funnel. Only flag stages where real losses
    # occurred (leads left the pipeline without progressing); in-progress
    # leads are reported via `still_in_stage` and are not drop-offs.
    biggest_drop = None
    for step in funnel_steps:
        if step.get("dropped_off", 0) > 0 and step["drop_off_percent"] > 0:
            if biggest_drop is None or step["drop_off_percent"] > biggest_drop["drop_off_percent"]:
                biggest_drop = step
    if biggest_drop and biggest_drop["drop_off_percent"] >= 20:
        stage_name = biggest_drop["stage"].replace("_", " ").title()
        tips.append({
            "priority": "high",
            "category": "funnel",
            "title": f"Biggest drop-off: {biggest_drop['drop_off_percent']}% lost before \"{stage_name}\"",
            "detail": _get_stage_specific_advice(biggest_drop["stage"], biggest_drop["drop_off_percent"]),
        })

    # Tip: slow stages
    for stage, avg_days in avg_time_in_stage.items():
        if avg_days > 14 and stage in ("new_lead", "contacted"):
            stage_name = stage.replace("_", " ").title()
            tips.append({
                "priority": "medium",
                "category": "speed",
                "title": f"Leads spend avg {avg_days} days in \"{stage_name}\"",
                "detail": (
                    f"Leads in \"{stage_name}\" are sitting for an average of {avg_days} days. "
                    "Speed matters — responding within 24 hours makes you 7x more likely to "
                    "convert. Try to move leads to the next stage faster."
                ),
            })

    # Tip: best performing source. Only meaningful when we have more than
    # one source to compare — calling the sole source "the best" is noise.
    if source_conversion and len(source_conversion) > 1:
        best_source = max(
            source_conversion.items(),
            key=lambda x: x[1]["conversion_rate"],
        )
        if best_source[1]["conversion_rate"] > 0 and best_source[1]["total"] >= 3:
            tips.append({
                "priority": "low",
                "category": "source",
                "title": f"Best source: {best_source[0]} ({best_source[1]['conversion_rate']}% conversion)",
                "detail": (
                    f"\"{best_source[0]}\" converts at {best_source[1]['conversion_rate']}% "
                    f"({best_source[1]['converted']} of {best_source[1]['total']} leads). "
                    "Consider doubling down on this channel — post more content, "
                    "run promotions, or allocate more time here."
                ),
            })

        worst_sources = [
            (name, data) for name, data in source_conversion.items()
            if data["total"] >= 3 and data["conversion_rate"] == 0
        ]
        if worst_sources:
            names = ", ".join(s[0] for s in worst_sources[:3])
            tips.append({
                "priority": "medium",
                "category": "source",
                "title": f"Zero conversions from: {names}",
                "detail": (
                    f"You have leads from {names} but none have converted. "
                    "Consider whether these channels attract the right audience, "
                    "or if your messaging needs adjustment for those platforms."
                ),
            })

    # Tip: new leads piling up
    new_lead_count = stage_counts.get("new_lead", 0)
    if total > 0 and new_lead_count > 0 and (new_lead_count / total) > 0.4:
        tips.append({
            "priority": "high",
            "category": "action",
            "title": f"{new_lead_count} leads stuck as \"New Lead\" ({round(new_lead_count/total*100)}% of all leads)",
            "detail": (
                "A large portion of your leads haven't been contacted yet. "
                "Block out 30 minutes today to reach out to your newest leads — "
                "the faster you make first contact, the higher your conversion rate."
            ),
        })

    if not tips:
        tips.append({
            "priority": "low",
            "category": "general",
            "title": "Pipeline looks healthy!",
            "detail": (
                "No immediate issues detected. Keep following up consistently, "
                "log your activities, and review this dashboard weekly."
            ),
        })

    tips.sort(key=lambda t: {"high": 0, "medium": 1, "low": 2}[t["priority"]])
    return tips


def _get_stage_specific_advice(stage: str, drop_pct: float) -> str:
    """Return targeted advice based on which funnel stage has the biggest drop-off."""
    advice_map = {
        "contacted": (
            f"{drop_pct}% of your leads drop off before you make contact. "
            "Try responding to DMs/comments within 1 hour. "
            "Set up a quick intro template message you can send immediately."
        ),
        "talking": (
            f"{drop_pct}% of contacted leads don't progress to a real conversation. "
            "Your initial message might not be compelling enough. Try asking a question "
            "rather than pitching — e.g., 'What area are you looking to cover?' gets "
            "people talking."
        ),
        "installation_help": (
            f"{drop_pct}% of leads in conversation don't move to installation. "
            "They may be unsure about the technical side. Create a simple guide or "
            "short video showing how easy setup is. Offer to walk them through it."
        ),
        "signed_up": (
            f"{drop_pct}% of leads getting installation help don't sign up. "
            "The setup process may feel too complex. Simplify onboarding — "
            "can you pre-configure routers? Offer a trial period to reduce risk."
        ),
        "paying": (
            f"{drop_pct}% of signed-up users don't become paying customers. "
            "They've signed up but aren't paying — check if pricing is clear, "
            "if the first invoice is confusing, or if they need a gentle nudge. "
            "A personal call at this stage can close the deal."
        ),
    }
    return advice_map.get(stage, f"{drop_pct}% drop-off at this stage. Review what's blocking leads from progressing.")


@router.get("/api/leads/followups/upcoming")
async def upcoming_followups(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Get all upcoming follow-ups across leads."""
    admin = await _require_admin(token, db)
    from datetime import timedelta
    cutoff = datetime.utcnow() + timedelta(days=days)

    result = await db.execute(
        select(LeadFollowUp)
        .join(Lead, LeadFollowUp.lead_id == Lead.id)
        .where(
            Lead.user_id == admin.id,
            LeadFollowUp.is_completed == False,
            LeadFollowUp.due_at <= cutoff,
        )
        .options(selectinload(LeadFollowUp.lead))
        .order_by(LeadFollowUp.due_at.asc())
    )
    followups = result.scalars().all()

    overdue_now = datetime.utcnow()
    return {
        "followups": [
            {
                "id": f.id,
                "title": f.title,
                "due_at": f.due_at.isoformat(),
                "is_overdue": f.due_at < overdue_now,
                "lead_id": f.lead_id,
                "lead_name": f.lead.name if f.lead else None,
                "lead_stage": f.lead.stage.value if f.lead and hasattr(f.lead.stage, 'value') else str(f.lead.stage) if f.lead else None,
                "created_at": f.created_at.isoformat(),
            }
            for f in followups
        ],
        "total": len(followups),
    }


@router.get("/api/leads/{lead_id}")
async def get_lead(
    lead_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Get full lead detail with activities and follow-ups."""
    admin = await _require_admin(token, db)
    result = await db.execute(
        select(Lead)
        .where(Lead.id == lead_id, Lead.user_id == admin.id)
        .options(
            selectinload(Lead.source),
            selectinload(Lead.activities),
            selectinload(Lead.follow_ups),
        )
    )
    lead = result.scalar_one_or_none()
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    return await _lead_to_dict(lead, db, include_relations=True)


@router.put("/api/leads/{lead_id}")
async def update_lead(
    lead_id: int,
    req: LeadUpdate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Update lead info (not stage — use PATCH stage endpoint for that).
    Send a field as null to clear it. Omit a field to leave it unchanged."""
    admin = await _require_admin(token, db)
    lead = await _get_lead_or_404(lead_id, admin.id, db)

    provided = req.model_fields_set
    if "source_id" in provided and req.source_id is not None:
        source = await db.get(LeadSource, req.source_id)
        if not source:
            raise HTTPException(status_code=400, detail="Invalid source_id")

    for field in ("name", "phone", "email", "social_platform", "social_handle",
                  "source_id", "source_detail", "notes", "next_followup_at"):
        if field in provided:
            setattr(lead, field, getattr(req, field))

    await db.commit()
    await db.refresh(lead)
    return await _lead_to_dict(lead, db)


@router.patch("/api/leads/{lead_id}/stage")
async def update_lead_stage(
    lead_id: int,
    req: LeadStageUpdate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Move a lead to a new pipeline stage."""
    admin = await _require_admin(token, db)
    lead = await _get_lead_or_404(lead_id, admin.id, db)

    try:
        new_stage = LeadStage(req.stage)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid stage: {req.stage}")

    old_stage_value = lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage)
    if old_stage_value == new_stage.value:
        raise HTTPException(status_code=400, detail="Lead is already in this stage")

    lead.stage = new_stage
    lead.stage_changed_at = datetime.utcnow()

    if new_stage in (LeadStage.LOST, LeadStage.CHURNED) and req.lost_reason:
        lead.lost_reason = req.lost_reason

    desc = req.note or f"Stage changed from {old_stage_value} to {new_stage.value}"
    activity = LeadActivity(
        lead_id=lead.id,
        activity_type=LeadActivityType.STAGE_CHANGE,
        description=desc,
        old_stage=old_stage_value,
        new_stage=new_stage.value,
        created_by=admin.id,
    )
    db.add(activity)
    await db.commit()
    await db.refresh(lead)
    return await _lead_to_dict(lead, db)


@router.delete("/api/leads/{lead_id}")
async def delete_lead(
    lead_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Delete a lead and all its activities/follow-ups."""
    admin = await _require_admin(token, db)
    lead = await _get_lead_or_404(lead_id, admin.id, db)
    await db.delete(lead)
    await db.commit()
    return {"detail": "Lead deleted", "id": lead_id}


# ========================================
# Activities endpoints
# ========================================

@router.post("/api/leads/{lead_id}/activities", status_code=201)
async def create_activity(
    lead_id: int,
    req: ActivityCreate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Log an activity (note, call, DM, etc.) on a lead."""
    admin = await _require_admin(token, db)
    await _get_lead_or_404(lead_id, admin.id, db)

    try:
        activity_type = LeadActivityType(req.activity_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid activity_type: {req.activity_type}")

    activity = LeadActivity(
        lead_id=lead_id,
        activity_type=activity_type,
        description=req.description,
        created_by=admin.id,
    )
    db.add(activity)
    await db.commit()
    await db.refresh(activity)
    return {
        "id": activity.id,
        "lead_id": activity.lead_id,
        "activity_type": activity.activity_type.value,
        "description": activity.description,
        "old_stage": activity.old_stage,
        "new_stage": activity.new_stage,
        "created_at": activity.created_at.isoformat(),
    }


@router.get("/api/leads/{lead_id}/activities")
async def list_activities(
    lead_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """List all activities for a lead (newest first)."""
    admin = await _require_admin(token, db)
    await _get_lead_or_404(lead_id, admin.id, db)

    result = await db.execute(
        select(LeadActivity)
        .where(LeadActivity.lead_id == lead_id)
        .order_by(LeadActivity.created_at.desc())
    )
    activities = result.scalars().all()
    return {
        "activities": [
            {
                "id": a.id,
                "activity_type": a.activity_type.value if hasattr(a.activity_type, 'value') else a.activity_type,
                "description": a.description,
                "old_stage": a.old_stage,
                "new_stage": a.new_stage,
                "created_at": a.created_at.isoformat(),
            }
            for a in activities
        ]
    }


# ========================================
# Follow-ups endpoints
# ========================================

@router.post("/api/leads/{lead_id}/followups", status_code=201)
async def create_followup(
    lead_id: int,
    req: FollowUpCreate,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Schedule a follow-up reminder on a lead."""
    admin = await _require_admin(token, db)
    lead = await _get_lead_or_404(lead_id, admin.id, db)

    followup = LeadFollowUp(
        lead_id=lead_id,
        title=req.title,
        due_at=req.due_at,
        created_by=admin.id,
    )
    db.add(followup)

    if not lead.next_followup_at or req.due_at < lead.next_followup_at:
        lead.next_followup_at = req.due_at

    await db.commit()
    await db.refresh(followup)
    return {
        "id": followup.id,
        "lead_id": followup.lead_id,
        "title": followup.title,
        "due_at": followup.due_at.isoformat(),
        "is_completed": followup.is_completed,
        "created_at": followup.created_at.isoformat(),
    }


@router.patch("/api/leads/followups/{followup_id}/complete")
async def complete_followup(
    followup_id: int,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Mark a follow-up as completed."""
    admin = await _require_admin(token, db)

    result = await db.execute(
        select(LeadFollowUp)
        .join(Lead, LeadFollowUp.lead_id == Lead.id)
        .where(LeadFollowUp.id == followup_id, Lead.user_id == admin.id)
        .options(selectinload(LeadFollowUp.lead))
    )
    followup = result.scalar_one_or_none()
    if not followup:
        raise HTTPException(status_code=404, detail="Follow-up not found")

    followup.is_completed = True
    followup.completed_at = datetime.utcnow()

    activity = LeadActivity(
        lead_id=followup.lead_id,
        activity_type=LeadActivityType.FOLLOWUP_COMPLETED,
        description=f"Completed follow-up: {followup.title}",
        created_by=admin.id,
    )
    db.add(activity)

    remaining = await db.execute(
        select(LeadFollowUp)
        .where(
            LeadFollowUp.lead_id == followup.lead_id,
            LeadFollowUp.is_completed == False,
            LeadFollowUp.id != followup_id,
        )
        .order_by(LeadFollowUp.due_at.asc())
        .limit(1)
    )
    next_fu = remaining.scalar_one_or_none()
    lead = followup.lead
    lead.next_followup_at = next_fu.due_at if next_fu else None

    await db.commit()
    return {"detail": "Follow-up completed", "id": followup_id}


# ========================================
# Conversion endpoint
# ========================================

@router.post("/api/leads/{lead_id}/convert")
async def convert_lead(
    lead_id: int,
    req: LeadConvertRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(verify_token),
):
    """Convert a lead into a reseller account."""
    admin = await _require_admin(token, db)
    lead = await _get_lead_or_404(lead_id, admin.id, db)

    if lead.converted_user_id:
        raise HTTPException(status_code=400, detail="Lead has already been converted")

    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    from app.services.auth import create_user
    new_user = await create_user(
        db=db,
        email=req.email,
        password=req.password,
        role=UserRole.RESELLER,
        organization_name=req.organization_name,
        created_by=admin.id,
        business_name=req.business_name,
        support_phone=req.support_phone,
    )

    lead.converted_user_id = new_user.id
    if lead.stage not in (LeadStage.SIGNED_UP, LeadStage.PAYING):
        old_stage = lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage)
        lead.stage = LeadStage.SIGNED_UP
        lead.stage_changed_at = datetime.utcnow()

        activity = LeadActivity(
            lead_id=lead.id,
            activity_type=LeadActivityType.STAGE_CHANGE,
            description=f"Lead converted to reseller account (email: {req.email})",
            old_stage=old_stage,
            new_stage=LeadStage.SIGNED_UP.value,
            created_by=admin.id,
        )
        db.add(activity)

    await db.commit()
    await db.refresh(lead)
    return {
        "detail": "Lead converted to reseller",
        "lead_id": lead.id,
        "new_user_id": new_user.id,
        "new_user_email": new_user.email,
        "new_stage": lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage),
    }


# ========================================
# Helpers
# ========================================

async def _get_lead_or_404(lead_id: int, admin_id: int, db: AsyncSession) -> Lead:
    result = await db.execute(
        select(Lead).where(Lead.id == lead_id, Lead.user_id == admin_id)
    )
    lead = result.scalar_one_or_none()
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    return lead


def _lead_to_summary(lead: Lead) -> dict:
    return {
        "id": lead.id,
        "name": lead.name,
        "phone": lead.phone,
        "email": lead.email,
        "social_platform": lead.social_platform,
        "social_handle": lead.social_handle,
        "source": lead.source.name if lead.source else None,
        "source_id": lead.source_id,
        "stage": lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage),
        "stage_changed_at": lead.stage_changed_at.isoformat() if lead.stage_changed_at else None,
        "next_followup_at": lead.next_followup_at.isoformat() if lead.next_followup_at else None,
        "created_at": lead.created_at.isoformat(),
        "updated_at": lead.updated_at.isoformat() if lead.updated_at else None,
    }


async def _lead_to_dict(lead: Lead, db: AsyncSession, include_relations: bool = False) -> dict:
    source_name = None
    if lead.source_id:
        source = await db.get(LeadSource, lead.source_id)
        source_name = source.name if source else None

    data = {
        "id": lead.id,
        "name": lead.name,
        "phone": lead.phone,
        "email": lead.email,
        "social_platform": lead.social_platform,
        "social_handle": lead.social_handle,
        "source": source_name,
        "source_id": lead.source_id,
        "source_detail": lead.source_detail,
        "stage": lead.stage.value if hasattr(lead.stage, 'value') else str(lead.stage),
        "stage_changed_at": lead.stage_changed_at.isoformat() if lead.stage_changed_at else None,
        "next_followup_at": lead.next_followup_at.isoformat() if lead.next_followup_at else None,
        "notes": lead.notes,
        "converted_user_id": lead.converted_user_id,
        "lost_reason": lead.lost_reason,
        "created_at": lead.created_at.isoformat(),
        "updated_at": lead.updated_at.isoformat() if lead.updated_at else None,
    }

    if include_relations:
        data["activities"] = [
            {
                "id": a.id,
                "activity_type": a.activity_type.value if hasattr(a.activity_type, 'value') else a.activity_type,
                "description": a.description,
                "old_stage": a.old_stage,
                "new_stage": a.new_stage,
                "created_at": a.created_at.isoformat(),
            }
            for a in (lead.activities or [])
        ]
        data["follow_ups"] = [
            {
                "id": f.id,
                "title": f.title,
                "due_at": f.due_at.isoformat(),
                "is_completed": f.is_completed,
                "completed_at": f.completed_at.isoformat() if f.completed_at else None,
                "created_at": f.created_at.isoformat(),
            }
            for f in (lead.follow_ups or [])
        ]

    return data

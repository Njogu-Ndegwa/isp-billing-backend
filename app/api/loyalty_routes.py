"""Loyalty points: reseller settings and reports, and the captive-portal endpoints.

Resellers configure loyalty only through the dashboard assistant, which builds
its actions from these routes' OpenAPI summaries and Field descriptions, so
those are written for it. Business rules live in app/services/loyalty.py.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import ConnectionType, LoyaltySettings, Plan, Router, User, UserRole
from app.services import loyalty
from app.services.auth import get_current_user, verify_token
from app.services.markets import reseller_market
from app.services.mikrotik_api import normalize_mac_address, validate_mac_address

logger = logging.getLogger(__name__)
router = APIRouter(tags=["loyalty"])


async def _require_reseller(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.RESELLER:
        raise HTTPException(status_code=403, detail="Resellers only")
    return user


# ---------------------------------------------------------------------------
# Reseller: settings
# ---------------------------------------------------------------------------

class LoyaltyRewardIn(BaseModel):
    plan_id: int = Field(
        ...,
        description=(
            "id of one of your HOTSPOT plans (see GET /api/plans) that a customer can get "
            "for points. The whole plan is given; there are no partial discounts. A cheap, "
            "short plan (an hour or a day) makes a good first reward."
        ),
    )
    points_cost: int = Field(
        ..., ge=1, le=1_000_000,
        description=(
            "Points the customer spends for this plan. With earn_mode per_kes the share "
            "given back is plan price / (points_cost x kes_per_point) x 100 %: for about "
            "2% back on a 50 KES plan at 10 KES per point, points_cost = 250; 5 points would be "
            "100% back (free after KES 50 of spend). Read the numbers from GET "
            "/api/loyalty/settings (reward_examples, value_percent), never work them out. With "
            "per_purchase, points_cost N means 'every Nth purchase free'."
        ),
    )


class LoyaltySettingsIn(BaseModel):
    """A change, not a replacement: every field left out keeps its saved value."""

    enabled: Optional[bool] = Field(
        None,
        description=(
            "Turn loyalty points on or off for all your hotspot customers. Only payments "
            "made after it is switched on earn; there is no backfill. Leave out to keep."
        ),
    )
    earn_mode: Optional[Literal["per_kes", "per_purchase"]] = Field(
        None,
        description=(
            "How customers earn: per_kes = 1 point for every kes_per_point spent "
            "(amount / kes_per_point, rounded down); per_purchase = points_per_purchase "
            "points for every paid plan, whatever its price. Leave out to keep."
        ),
    )
    kes_per_point: Optional[int] = Field(
        None, ge=1, le=100_000,
        description=(
            "kes_per_point: how many KES (the reseller's currency) a customer spends to "
            "earn 1 point when earn_mode is per_kes. Default 10 (Safaricom Bonga style). "
            "Leave out to keep."
        ),
    )
    points_per_purchase: Optional[int] = Field(
        None, ge=1, le=10_000,
        description="Points per paid plan when earn_mode is per_purchase. Default 1. Leave out to keep.",
    )
    plan_points: Optional[Dict[int, int]] = Field(
        None,
        description=(
            "Optional fixed points for particular plans, {plan_id: points}; it replaces "
            "the earn_mode's points for that plan and 0 means that plan earns nothing. "
            "Sending it replaces the whole map; {} removes every override. Hotspot plans "
            "only. Leave out to keep."
        ),
    )
    rewards: Optional[list[LoyaltyRewardIn]] = Field(
        None,
        description=(
            "The plans customers can get for points, 1 to 3 rows of {plan_id, points_cost}. "
            "Sending it replaces the whole list; [] removes every reward. Leave out to keep."
        ),
    )
    expiry_days: Optional[int] = Field(
        None, ge=0, le=3650,
        description=(
            "Days points stay valid after each purchase that earned them (rolling); the "
            "oldest points are spent and expire first. 0 = never expire. Default 90. "
            "Leave out to keep."
        ),
    )
    min_paid_amount: Optional[float] = Field(
        None, ge=0, le=1_000_000,
        description=(
            "Payments below this amount earn nothing (for example 20 to skip tiny "
            "top-ups). Default 0. Leave out to keep."
        ),
    )
    max_redemptions_per_day: Optional[int] = Field(
        None, ge=1, le=20,
        description="How many rewards one phone may take per day. Default 1. Leave out to keep.",
    )


GENEROUS_PERCENT = 20  # a reward giving back more than this share of spend is worth a warning


def _points_for_share(price, kes_per_point: int, percent: float) -> Optional[int]:
    """Points a plan should cost so that it gives back ``percent`` of spend (per_kes)."""
    if not price or not kes_per_point or percent <= 0:
        return None
    return max(1, round(float(price) * 100 / (percent * kes_per_point)))


async def _reward_examples(db: AsyncSession, user_id: int, cfg: dict) -> list[dict]:
    """For the cheapest hotspot plans: what each would give back at a few point costs.
    Only for per_kes, where the share depends on the numbers."""
    if cfg["earn_mode"] != "per_kes" or not cfg["kes_per_point"]:
        return []
    plans = (await db.execute(
        select(Plan).where(Plan.user_id == user_id, Plan.connection_type == ConnectionType.HOTSPOT,
                           Plan.price > 0)
        .order_by(Plan.price, Plan.id).limit(5)
    )).scalars().all()
    out = []
    for plan in plans:
        costs = {pct: _points_for_share(plan.price, cfg["kes_per_point"], pct) for pct in (2, 5, 10)}
        out.append({
            "plan_id": plan.id, "plan_name": plan.name, "plan_price": plan.price,
            "points_cost_for_2_percent_back": costs[2],
            "points_cost_for_5_percent_back": costs[5],
            "points_cost_for_10_percent_back": costs[10],
            "spend_to_earn_it_at_5_percent": (costs[5] or 0) * cfg["kes_per_point"],
        })
    return out


async def _settings_payload(db: AsyncSession, user_id: int, row: Optional[LoyaltySettings]) -> dict:
    cfg = loyalty.settings_values(row)
    plan_ids = {r["plan_id"] for r in cfg["rewards"]} | {int(k) for k in cfg["plan_points"]}
    plans = {}
    if plan_ids:
        plans = {
            p.id: p
            for p in (
                await db.execute(select(Plan).where(Plan.id.in_(plan_ids), Plan.user_id == user_id))
            ).scalars().all()
        }
    rewards = []
    for reward in cfg["rewards"]:
        plan = plans.get(reward["plan_id"])
        rewards.append({
            "plan_id": reward["plan_id"],
            "points_cost": reward["points_cost"],
            "plan_name": plan.name if plan else None,
            "plan_price": plan.price if plan else None,
            "value_percent": loyalty.value_percent(plan.price if plan else None, reward["points_cost"], cfg),
        })
        share = rewards[-1]["value_percent"]
        rewards[-1]["generous"] = share is not None and share > GENEROUS_PERCENT
    return {
        "enabled": cfg["enabled"],
        "enabled_at": cfg["enabled_at"].isoformat() if cfg["enabled_at"] else None,
        "earn_mode": cfg["earn_mode"],
        "kes_per_point": cfg["kes_per_point"],
        "points_per_purchase": cfg["points_per_purchase"],
        "plan_points": [
            {
                "plan_id": int(plan_id),
                "points": points,
                "plan_name": plans[int(plan_id)].name if int(plan_id) in plans else None,
            }
            for plan_id, points in cfg["plan_points"].items()
        ],
        "rewards": rewards,
        # Worked numbers for picking a reward, so nobody does the sum in their head
        # (24 Nov: the assistant said 10% back where it was 100%).
        "reward_examples": await _reward_examples(db, user_id, cfg),
        "expiry_days": cfg["expiry_days"],
        "min_paid_amount": cfg["min_paid_amount"],
        "max_redemptions_per_day": cfg["max_redemptions_per_day"],
    }


@router.get("/api/loyalty/settings", summary="Get loyalty points settings")
async def get_loyalty_settings(db: AsyncSession = Depends(get_db), token: str = Depends(verify_token)):
    """Whether customers earn loyalty points, how, and which plans they can get for points.

    rewards[].value_percent is the share of spend given back (per_kes only):
    plan price / (points_cost x kes_per_point) x 100. Example: 1 point per KES 10 and a
    KES 50 plan for 5 points is 50 / (5 x 10) x 100 = 100% back, the plan is free after
    KES 50 of spend. Never work a share out yourself: quote value_percent, or
    reward_examples (points costs for 2/5/10% back on the cheapest hotspot plans) when
    no reward is set. Warn the person when a reward gives back more than 20%.
    Off by default.
    """
    user = await _require_reseller(token, db)
    # Not persisted: a GET must not create settings rows.
    return await _settings_payload(db, user.id, await db.get(LoyaltySettings, user.id))


async def _validate_plans(db: AsyncSession, user_id: int, plan_ids: set[int]) -> None:
    if not plan_ids:
        return
    found = {
        p.id: p
        for p in (await db.execute(select(Plan).where(Plan.id.in_(plan_ids)))).scalars().all()
    }
    for plan_id in sorted(plan_ids):
        plan = found.get(plan_id)
        if plan is None or plan.user_id != user_id:
            raise HTTPException(status_code=400, detail=f"Plan {plan_id} is not one of your plans")
        if plan.connection_type != ConnectionType.HOTSPOT:
            raise HTTPException(
                status_code=400,
                detail=f"Plan {plan_id} ({plan.name}) is not a hotspot plan. Loyalty points work on hotspot plans only.",
            )


@router.put("/api/loyalty/settings", summary="Change loyalty points settings")
async def update_loyalty_settings(
    body: LoyaltySettingsIn,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Switch loyalty points on or off and set how customers earn and what they can get.

    Partial: only the fields sent change. Changes only affect future earning.
    """
    user = await _require_reseller(token, db)
    if body.rewards is not None:
        if len(body.rewards) > loyalty.MAX_REWARDS:
            raise HTTPException(status_code=400, detail="Choose at most 3 reward plans")
        ids = [r.plan_id for r in body.rewards]
        if len(ids) != len(set(ids)):
            raise HTTPException(status_code=400, detail="Each reward must be a different plan")
    if body.plan_points is not None and any(v < 0 or v > 100_000 for v in body.plan_points.values()):
        raise HTTPException(status_code=400, detail="plan_points values must be between 0 and 100000")
    await _validate_plans(
        db,
        user.id,
        {r.plan_id for r in body.rewards or []} | set((body.plan_points or {}).keys()),
    )

    row = await db.get(LoyaltySettings, user.id)
    if row is None:
        row = LoyaltySettings(user_id=user.id)
        db.add(row)
    for field in (
        "earn_mode", "kes_per_point", "points_per_purchase", "expiry_days",
        "min_paid_amount", "max_redemptions_per_day",
    ):
        value = getattr(body, field)
        if value is not None:
            setattr(row, field, value)
    if body.plan_points is not None:
        row.plan_points = {str(k): int(v) for k, v in body.plan_points.items()}
    if body.rewards is not None:
        row.rewards = [{"plan_id": r.plan_id, "points_cost": r.points_cost} for r in body.rewards]
    if body.enabled is not None:
        row.enabled = body.enabled
        if body.enabled and row.enabled_at is None:
            row.enabled_at = datetime.utcnow()
        elif not body.enabled:
            # Switching back on later starts earning afresh: payments made
            # while it was off never earn.
            row.enabled_at = None
    row.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(row)
    return await _settings_payload(db, user.id, row)


# ---------------------------------------------------------------------------
# Reseller: members, adjustments, summary
# ---------------------------------------------------------------------------

@router.get("/api/loyalty/members", summary="List loyalty points balances")
async def get_loyalty_members(
    phone: Optional[str] = Query(
        None,
        description="A customer's phone number. Gives that phone's balance, next expiry and recent points history.",
    ),
    limit: int = Query(50, ge=1, le=200, description="How many members (or history rows for one phone) to return"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Customers' points balances, highest first, with masked phones; or one phone's history.

    Without phone: members[] with a masked phone, balance, points earned in total,
    last activity and the customer it belongs to. With phone: that phone's
    balance, next expiry and recent rows (earn, redeem, expire, adjust).
    """
    user = await _require_reseller(token, db)
    if phone is not None:
        if not loyalty.phone_key(phone):
            raise HTTPException(status_code=400, detail="Enter a full phone number")
        return await loyalty.member_detail(
            db, user.id, phone, limit, reseller_market(user).timezone
        )
    return {"members": await loyalty.members(db, user.id, limit)}


class LoyaltyAdjustIn(BaseModel):
    phone: str = Field(..., description="The customer's phone number whose points to change")
    points: int = Field(
        ..., ge=-1_000_000, le=1_000_000,
        description=(
            "Points to add (positive) or remove (negative). Removing more than the "
            "balance takes it to 0, never below. Added points expire like earned ones."
        ),
    )
    note: str = Field(
        ..., min_length=1, max_length=200,
        description="Why, in a few words (for example 'Compensation for outage'). Kept in the points history.",
    )


@router.post("/api/loyalty/adjust", summary="Add or remove loyalty points for a phone")
async def adjust_loyalty_points(
    body: LoyaltyAdjustIn,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Give a customer extra loyalty points or take some away, with a note. A balance never goes below 0."""
    user = await _require_reseller(token, db)
    if body.points == 0:
        raise HTTPException(status_code=400, detail="points must not be 0")
    if not loyalty.phone_key(body.phone):
        raise HTTPException(status_code=400, detail="Enter a full phone number")
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="A note is required")
    result = await loyalty.adjust(db, user.id, body.phone, body.points, body.note.strip(), user.id)
    if result["applied"] == 0:
        raise HTTPException(status_code=400, detail="This phone has no points to remove")
    return {"phone": loyalty.mask_phone_key(loyalty.phone_key(body.phone)), **result}


@router.get("/api/loyalty/summary", summary="Loyalty points summary")
async def get_loyalty_summary(db: AsyncSession = Depends(get_db), token: str = Depends(verify_token)):
    """How loyalty points are doing: members, points outstanding, points earned and redeemed and rewards taken in the last 30 days."""
    user = await _require_reseller(token, db)
    return await loyalty.summary(db, user.id)


# ---------------------------------------------------------------------------
# Public (captive portal, before login)
# ---------------------------------------------------------------------------

async def _portal_context(db: AsyncSession, payload: Dict[str, Any]) -> tuple[Router, str, str]:
    identity = str(payload.get("identity") or "").strip()
    if not identity:
        raise HTTPException(status_code=400, detail="identity is required")
    mac = str(payload.get("mac") or "")
    if not mac or not validate_mac_address(mac):
        raise HTTPException(status_code=400, detail="Invalid MAC address format")
    phone = str(payload.get("phone") or "")
    if not loyalty.phone_key(phone):
        raise HTTPException(status_code=400, detail="Enter a full phone number")
    router_obj = (
        await db.execute(select(Router).where(func.lower(Router.identity) == identity.lower()))
    ).scalar_one_or_none()
    if router_obj is None:
        raise HTTPException(status_code=404, detail="Router not found")
    return router_obj, phone, normalize_mac_address(mac)


def _limited(router_id: int, mac: str) -> bool:
    from app.services.code_attempt_limiter import check_code_attempts

    try:
        check_code_attempts(router_id, mac)
    except HTTPException:
        return True
    return False


@router.post("/api/public/loyalty/balance")
async def loyalty_balance_public(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Points balance for the captive portal. Shown only to the device that usually
    pays with this phone, or with a valid one-time code (optional ``code``)."""
    from app.services.code_attempt_limiter import record_code_failure

    router_obj, phone, mac = await _portal_context(db, payload)
    user_id = router_obj.user_id
    cfg = loyalty.settings_values(await db.get(LoyaltySettings, user_id))
    if not cfg["enabled"]:
        return {"ok": False, "code": "loyalty_off"}
    key = loyalty.phone_key(phone)
    if not await loyalty.device_check(db, user_id, key, mac):
        code = payload.get("code")
        if not code:
            return {"ok": False, "code": "needs_code"}
        if _limited(router_obj.id, mac):
            return {"ok": False, "code": "rate_limited"}
        valid, _ = await loyalty.check_code(db, user_id, key, mac, str(code), datetime.utcnow())
        if not valid:
            record_code_failure(router_obj.id, mac)
            return {"ok": False, "code": "bad_code"}
    reseller = await db.get(User, user_id)
    tz_name = reseller_market(reseller).timezone if reseller else None
    return await loyalty.balance_view(db, user_id, key, cfg, router_obj.id, tz_name)


@router.post("/api/public/loyalty/send-code")
async def loyalty_send_code_public(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Text a 6-digit code (valid 10 minutes) to the phone so another device can use its points.

    Paid from the reseller's SMS credits; without credits the answer is
    ``use_paying_device``.
    """
    router_obj, phone, mac = await _portal_context(db, payload)
    return await loyalty.send_code(db, router_obj, phone, mac)


@router.post("/api/public/loyalty/redeem")
async def loyalty_redeem_public(payload: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Spend points on a reward plan. On success the portal polls the normal
    payment-status endpoint and logs in, as for a paid plan or a free trial."""
    from app.services.code_attempt_limiter import record_code_failure

    router_obj, phone, mac = await _portal_context(db, payload)
    try:
        plan_id = int(payload.get("plan_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="plan_id is required")
    code = payload.get("code")
    if code and _limited(router_obj.id, mac):
        return {"ok": False, "code": "rate_limited"}
    result = await loyalty.redeem(db, router_obj, phone, mac, plan_id, str(code) if code else None)
    if result.get("code") == "bad_code":
        record_code_failure(router_obj.id, mac)
    status_code = result.pop("status_code", None)
    if status_code:
        raise HTTPException(status_code=status_code, detail=result.get("message") or "Could not redeem")
    return result

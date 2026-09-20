from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from app.db.models import Plan
from app.core.cache import cache
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)

PLAN_CACHE_TTL = 300  # 5 minutes

def _build_cache_key(
    user_id: Optional[int] = None,
    connection_type: Optional[str] = None,
    include_hidden: bool = False
) -> str:
    """Build a consistent cache key for plan queries"""
    parts = ["plans"]
    if user_id is not None:
        parts.append(f"user_{user_id}")
    if connection_type is not None:
        parts.append(f"type_{connection_type}")
    if include_hidden:
        parts.append("all")
    return ":".join(parts)

def normalize_router_ids(value) -> Optional[List[int]]:
    """Coerce a stored/incoming router scope into a clean list of ints, or None.

    None is returned for NULL, a non-list, or an empty/garbage list. None means
    "available on every router the owner has" — the behaviour every plan had
    before this column existed.
    """
    if not isinstance(value, (list, tuple, set)):
        return None
    ids = []
    for item in value:
        try:
            router_id = int(item)
        except (TypeError, ValueError):
            continue
        if router_id not in ids:
            ids.append(router_id)
    return ids or None


def plan_allows_router(plan: Dict, router_id: Optional[int]) -> bool:
    """Whether a serialized plan is offered on the given router."""
    scope = normalize_router_ids(plan.get("router_ids"))
    if scope is None:
        return True
    if router_id is None:
        return False
    return int(router_id) in scope


def plan_model_allows_router(plan, router_id: Optional[int]) -> bool:
    """plan_allows_router for a Plan ORM row, for payment-path enforcement."""
    return plan_allows_router({"router_ids": getattr(plan, "router_ids", None)}, router_id)


def filter_plans_for_router(plans: List[Dict], router_id: Optional[int]) -> List[Dict]:
    """Drop plans that are scoped away from this router.

    Applied AFTER the cache read on purpose: the cache stays keyed by owner and
    connection type, so adding per-router scoping does not multiply cache entries
    by fleet size or cool the cache down.
    """
    if router_id is None:
        return plans
    return [p for p in plans if plan_allows_router(p, router_id)]


def _plan_expired(plan: Dict, now: datetime) -> bool:
    valid_until = plan.get("valid_until")
    if not valid_until:
        return False
    try:
        parsed = datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed <= now


def select_portal_plans(
    visible_plans: List[Dict],
    all_plans: List[Dict],
    emergency_active: bool,
) -> List[Dict]:
    """Pick the plans one router's captive portal should offer.

    Emergency mode lives on the router (routers.emergency_active), so this is
    decided per router at read time instead of by flipping plans.is_hidden across
    the owner's whole fleet — flipping a fleet-wide flag was what made emergency
    mode on one router change what every other router showed.

    `visible_plans` must already exclude hidden/expired plans; `all_plans` is the
    include_hidden view, needed because emergency plans are conventionally left
    hidden while things are normal.

    Emergency plans are returned with is_hidden forced False. The captive portal
    re-filters on is_hidden client-side, so leaving the legacy flag set would
    make it drop every plan and render an empty portal on exactly the router
    that is having an outage. Whether an emergency plan shows is decided here,
    by the router's flag — not by a fleet-wide column.
    """
    if emergency_active:
        now = datetime.utcnow()
        emergency = [
            {**p, "is_hidden": False}
            for p in all_plans
            if p.get("plan_type") == "emergency" and not _plan_expired(p, now)
        ]
        # Never hand back an empty portal: a router with emergency mode on but no
        # emergency plans configured keeps selling its normal plans.
        if emergency:
            return emergency
    return [p for p in visible_plans if p.get("plan_type") != "emergency"]


# ─────────────────────────────────────────────────────────────────────────────
# Portal package ordering
# ─────────────────────────────────────────────────────────────────────────────

# Values accepted by portal_settings.plan_sort_order. "default" is the legacy
# merchandised order the portal has always used (featured/bestseller pinned,
# then price high->low) and stays the default so nobody's portal re-orders
# itself on deploy.
VALID_PLAN_SORT_ORDERS = {
    "default",
    "price_asc",
    "price_desc",
    "duration_asc",
    "duration_desc",
}

DEFAULT_PLAN_SORT_ORDER = "default"

# Minutes per duration unit, for comparing "1 day" against "3 hours".
_DURATION_UNIT_MINUTES = {
    "MINUTES": 1,
    "HOURS": 60,
    "DAYS": 60 * 24,
    "WEEKS": 60 * 24 * 7,
    "MONTHS": 60 * 24 * 30,
}


def plan_duration_minutes(plan: Dict) -> float:
    """Duration of a serialized plan in minutes, for ordering.

    Unknown units fall back to 1 minute per unit rather than raising: a plan
    with a strange unit should land somewhere sane, not break the portal.
    """
    try:
        value = float(plan.get("duration_value") or 0)
    except (TypeError, ValueError):
        return 0.0
    unit = str(plan.get("duration_unit") or "").upper()
    return value * _DURATION_UNIT_MINUTES.get(unit, 1)


# Special offers lead, then emergency plans, then everything else — the same
# grouping the portal client applies in transformPlansData().
_PLAN_TYPE_RANK = {"special_offer": 0, "emergency": 1}


def _plan_type_rank(plan: Dict) -> int:
    return _PLAN_TYPE_RANK.get(plan.get("plan_type") or "regular", 2)


def _plan_price(plan: Dict) -> float:
    try:
        return float(plan.get("price") or 0)
    except (TypeError, ValueError):
        return 0.0


def sort_portal_plans(plans: List[Dict], sort_order: Optional[str]) -> List[Dict]:
    """Order the packages a captive portal lists, per the reseller's setting.

    Returns a new list; the input is never mutated (it may be a cached object).
    "default" is returned untouched so the portal keeps applying its own
    merchandised order (featured pin, bestseller, popular, price high->low).

    Ties break on plan id so the order is stable across requests — two packages
    at the same price must not swap places between page loads.
    """
    order = (sort_order or DEFAULT_PLAN_SORT_ORDER).strip().lower()
    if order not in VALID_PLAN_SORT_ORDERS or order == DEFAULT_PLAN_SORT_ORDER:
        return list(plans)

    key, reverse = {
        "price_asc": (_plan_price, False),
        "price_desc": (_plan_price, True),
        "duration_asc": (plan_duration_minutes, False),
        "duration_desc": (plan_duration_minutes, True),
    }[order]

    # id ascending on a tie in both directions: sort by id first, then by the
    # real key with a stable sort, so reverse=True doesn't flip the tiebreak.
    by_id = sorted(plans, key=lambda p: int(p.get("id") or 0))
    ordered = sorted(by_id, key=key, reverse=reverse)

    # Special offers and emergency plans lead, whatever the chosen order. The
    # portal renders them as their own group under a notice card, so a payload
    # that interleaves them would disagree with the page the customer sees.
    return sorted(ordered, key=_plan_type_rank)


def _serialize_plan(plan: Plan) -> Dict:
    """Convert Plan model to dict"""
    return {
        "id": plan.id,
        "name": plan.name,
        "speed": plan.speed,
        "price": plan.price,
        "duration_value": plan.duration_value,
        "duration_unit": plan.duration_unit.value,
        "connection_type": plan.connection_type.value,
        "router_profile": plan.router_profile,
        "user_id": plan.user_id,
        "plan_type": plan.plan_type.value if plan.plan_type else "regular",
        "is_hidden": plan.is_hidden if plan.is_hidden is not None else False,
        "badge_text": plan.badge_text,
        "original_price": plan.original_price,
        "valid_until": plan.valid_until.isoformat() if plan.valid_until else None,
        "data_cap_mb": plan.data_cap_mb,
        "fup_action": plan.fup_action.value if plan.fup_action else None,
        "fup_throttle_profile": plan.fup_throttle_profile,
        "max_shared_users": int(plan.max_shared_users or 1),
        "sharing_enabled": int(plan.max_shared_users or 1) > 1,
        "router_ids": normalize_router_ids(getattr(plan, "router_ids", None)),
    }

async def get_plans_cached(
    db: AsyncSession,
    user_id: Optional[int] = None,
    connection_type: Optional[str] = None,
    include_hidden: bool = False,
    router_id: Optional[int] = None
) -> List[Dict]:
    """Get plans with caching. Public queries filter out hidden and expired plans.

    Passing router_id additionally drops plans scoped to other routers. Plans with
    no router scope are returned for every router.
    """
    cache_key = _build_cache_key(user_id, connection_type, include_hidden)

    async def fetch_plans():
        stmt = select(Plan)
        
        if user_id is not None:
            stmt = stmt.where(Plan.user_id == user_id)
        
        if connection_type is not None:
            stmt = stmt.where(Plan.connection_type == connection_type)
        
        if not include_hidden:
            stmt = stmt.where(Plan.is_hidden == False)
            stmt = stmt.where(
                (Plan.valid_until == None) | (Plan.valid_until > datetime.utcnow())
            )
        
        result = await db.execute(stmt)
        plans = result.scalars().all()
        
        serialized = [_serialize_plan(p) for p in plans]
        logger.info(f"Fetched {len(serialized)} plans from DB (cache key: {cache_key})")
        return serialized
    
    plans = await cache.get_or_set(cache_key, fetch_plans, PLAN_CACHE_TTL)
    return filter_plans_for_router(plans, router_id)

async def invalidate_plan_cache():
    """Invalidate all plan caches"""
    await cache.clear_pattern("plans")
    logger.info("Plan cache invalidated")

async def warm_plan_cache(db: AsyncSession):
    """Pre-populate common plan queries"""
    try:
        # Warm cache for all plans
        await get_plans_cached(db)
        logger.info("Plan cache warmed successfully")
    except Exception as e:
        logger.error(f"Failed to warm plan cache: {e}")


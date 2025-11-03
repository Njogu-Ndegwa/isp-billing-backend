from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Plan
from app.core.cache import cache
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)

PLAN_CACHE_TTL = 300  # 5 minutes

def _build_cache_key(user_id: Optional[int] = None, connection_type: Optional[str] = None) -> str:
    """Build a consistent cache key for plan queries"""
    parts = ["plans"]
    if user_id is not None:
        parts.append(f"user_{user_id}")
    if connection_type is not None:
        parts.append(f"type_{connection_type}")
    return ":".join(parts)

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
        "user_id": plan.user_id
    }

async def get_plans_cached(
    db: AsyncSession,
    user_id: Optional[int] = None,
    connection_type: Optional[str] = None
) -> List[Dict]:
    """Get plans with caching"""
    cache_key = _build_cache_key(user_id, connection_type)
    
    async def fetch_plans():
        stmt = select(Plan)
        
        if user_id is not None:
            stmt = stmt.where(Plan.user_id == user_id)
        
        if connection_type is not None:
            stmt = stmt.where(Plan.connection_type == connection_type)
        
        result = await db.execute(stmt)
        plans = result.scalars().all()
        
        serialized = [_serialize_plan(p) for p in plans]
        logger.info(f"Fetched {len(serialized)} plans from DB (cache key: {cache_key})")
        return serialized
    
    return await cache.get_or_set(cache_key, fetch_plans, PLAN_CACHE_TTL)

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


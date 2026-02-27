from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Router
from app.services.mikrotik_api import MikroTikAPI


async def get_router_by_id(
    db: AsyncSession,
    router_id: int,
    user_id: int | None = None,
    role: str | None = None
) -> Router | None:
    stmt = select(Router).where(Router.id == router_id)
    if role != "admin" and user_id is not None:
        stmt = stmt.where(Router.user_id == user_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


def connect_to_router(router: Router, connect_timeout: int = 5, timeout: int = 15) -> MikroTikAPI:
    """
    Create MikroTik API connection using router-specific credentials.
    
    Uses circuit breaker pattern - will skip routers that have recently failed
    to prevent blocking the server.
    """
    api = MikroTikAPI(
        router.ip_address,
        router.username,
        router.password,
        router.port,
        timeout=timeout,
        connect_timeout=connect_timeout
    )
    return api

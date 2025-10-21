from functools import wraps
from fastapi import HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.deps import get_current_user, CurrentUser, get_db

def require_role(allowed_roles: list[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, info, **kwargs):
            user: CurrentUser = await get_current_user(info.context.get("user"))
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            if user.role not in allowed_roles:
                raise HTTPException(status_code=403, detail=f"Requires one of {allowed_roles} roles")
            return await func(*args, info=info, **kwargs)
        return wrapper
    return decorator

def require_ownership(model, id_field: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, info, db: AsyncSession = Depends(get_db), **kwargs):
            user: CurrentUser = await get_current_user(info.context.get("user"))
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            if user.role == "admin":
                return await func(*args, info=info, db=db, **kwargs)
            entity_id = kwargs.get(id_field)
            if entity_id:
                stmt = select(model).filter(model.id == entity_id, model.user_id == user.user_id)
                result = await db.execute(stmt)
                if not result.scalar_one_or_none():
                    raise HTTPException(status_code=403, detail="Not authorized to access this resource")
            return await func(*args, info=info, db=db, **kwargs)
        return wrapper
    return decorator
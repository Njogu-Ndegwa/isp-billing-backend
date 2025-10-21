from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import ALGORITHM
from app.config import settings
from app.db.database import get_db
from pydantic import BaseModel

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/graphql", auto_error=False)  # Disable auto-error

class CurrentUser(BaseModel):
    user_code: int
    user_id: int
    role: str
    organization_name: str

async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    if not token:
        return None  # Allow unauthenticated access
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_code: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")
        organization_name: str = payload.get("organization_name")
        if not all([user_code, user_id, role, organization_name]):
            raise credentials_exception
        return CurrentUser(
            user_code=int(user_code),
            user_id=int(user_id),
            role=role,
            organization_name=organization_name
        )
    except JWTError:
        raise credentials_exception
    
    
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt, JWTError
from datetime import datetime, timedelta
import random
from passlib.context import CryptContext
from app.db.models import User, UserRole
from app.db.database import get_db
from app.config import settings
from app.core.security import ALGORITHM
import logging

logger = logging.getLogger(__name__)

# OAuth2 scheme for extracting the token from the Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/graphql")  # Matches GraphQL login endpoint

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def generate_unique_user_code(db: AsyncSession) -> int:
    while True:
        user_code = random.randint(100000, 999999)
        stmt = select(1).select_from(User).filter(User.user_code == user_code)
        result = await db.execute(stmt)
        if not result.scalar():
            return user_code

async def create_user(db: AsyncSession, email: str, password: str, role: UserRole, organization_name: str, created_by: int = None):
    hashed_password = pwd_context.hash(password)
    user_code = await generate_unique_user_code(db)
    user = User(
        user_code=user_code,
        email=email,
        password_hash=hashed_password,
        role=role,  # Enum object handles lowercase
        organization_name=organization_name,
        created_by=created_by,
        created_at=datetime.utcnow()
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def authenticate_user(db: AsyncSession, email: str, password: str):
    stmt = select(User).filter(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "user_id": user.id,
            "user_code": user.user_code,
            "role": user.role.value,
            "organization_name": user.organization_name
        },
        expires_delta=access_token_expires
    )
    return {"access_token": access_token}

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Verify JWT token and return decoded payload.
    Raises HTTPException if token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: user_id not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload  # Contains user_id, user_code, role, organization_name, etc.
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    """
    Get current user from JWT token.
    Returns User object from database, ensuring role matches token.
    """
    try:
        payload = await verify_token(token)
        user_id = int(payload["user_id"])
        role = payload["role"]
        stmt = select(User).filter(User.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.role.value != role:
            raise HTTPException(status_code=403, detail="Role mismatch")
        return user
    except Exception as e:
        logger.error(f"Error getting current user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
"""Tiny test-data factories.

Async only — they take an AsyncSession and persist immediately.
Build the minimum row + accept overrides for fields under test.
"""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DurationUnit,
    Plan,
    PlanType,
    Router,
    User,
    UserRole,
)


_SEQ = {"user_code": 1000, "router_port": 8728}


def _next(key: str) -> int:
    _SEQ[key] += 1
    return _SEQ[key]


async def make_reseller(db: AsyncSession, **overrides) -> User:
    defaults = dict(
        user_code=_next("user_code"),
        email=f"reseller{_SEQ['user_code']}@example.com",
        password_hash="not-a-real-hash",
        role=UserRole.RESELLER,
        organization_name="Test ISP",
    )
    defaults.update(overrides)
    user = User(**defaults)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def make_plan(
    db: AsyncSession,
    reseller: User,
    *,
    price: int = 500,
    duration_value: int = 30,
    duration_unit: DurationUnit = DurationUnit.DAYS,
    connection_type: ConnectionType = ConnectionType.HOTSPOT,
    speed: str = "5M/5M",
    **overrides,
) -> Plan:
    defaults = dict(
        name=f"Plan-{duration_value}{duration_unit.value}",
        speed=speed,
        price=price,
        duration_value=duration_value,
        duration_unit=duration_unit,
        connection_type=connection_type,
        user_id=reseller.id,
        plan_type=PlanType.REGULAR,
    )
    defaults.update(overrides)
    plan = Plan(**defaults)
    db.add(plan)
    await db.commit()
    await db.refresh(plan)
    return plan


async def make_router(db: AsyncSession, reseller: User, **overrides) -> Router:
    """Build a Router with whatever required columns exist.

    Schema for Router lives in app/db/models.py — we only set the columns
    actually used by the hotspot pay flow plus FK to the reseller.
    """
    defaults = dict(
        name=f"Router-{_SEQ['router_port']}",
        ip_address="10.0.0.2",
        username="admin",
        password="admin",
        port=_next("router_port"),
        user_id=reseller.id,
    )
    defaults.update(overrides)
    router = Router(**defaults)
    db.add(router)
    await db.commit()
    await db.refresh(router)
    return router


async def make_customer(
    db: AsyncSession,
    reseller: User,
    plan: Plan,
    router: Optional[Router] = None,
    *,
    status: CustomerStatus = CustomerStatus.PENDING,
    expiry: Optional[datetime] = None,
    mac_address: str = "AA:BB:CC:DD:EE:FF",
    phone: str = "254712345678",
    name: str = "Test Customer",
    pppoe_username: Optional[str] = None,
    **overrides,
) -> Customer:
    defaults = dict(
        name=name,
        phone=phone,
        mac_address=mac_address,
        pppoe_username=pppoe_username,
        status=status,
        expiry=expiry,
        plan_id=plan.id,
        user_id=reseller.id,
        router_id=router.id if router else None,
    )
    defaults.update(overrides)
    cust = Customer(**defaults)
    db.add(cust)
    await db.commit()
    await db.refresh(cust)
    return cust

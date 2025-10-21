from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Subscription
from datetime import datetime, timedelta

async def create_subscription(db: AsyncSession, user_id: int, months: int, plan_type: str = "monthly", cost: float = 5000.0):
    stmt = select(Subscription).filter(Subscription.user_id == user_id, Subscription.is_active)
    result = await db.execute(stmt)
    subscription = result.scalar_one_or_none()
    if subscription:
        subscription.expires_on = subscription.expires_on + timedelta(days=months * 30)
        subscription.paid_on = datetime.utcnow()
        subscription.plan_type = plan_type
        subscription.cost = cost
    else:
        subscription = Subscription(
            user_id=user_id,
            is_active=True,
            paid_on=datetime.utcnow(),
            expires_on=datetime.utcnow() + timedelta(days=months * 30),
            plan_type=plan_type,
            cost=cost
        )
        db.add(subscription)
    await db.commit()
    await db.refresh(subscription)
    return subscription
"""What the assistant costs: tokens and an estimated price, per account per day.

Prices are list prices in US dollars per million tokens (miss, cache hit,
output), checked 2026-11-19:
  DeepSeek  https://api-docs.deepseek.com/quick_start/pricing  -- off-peak
            rates below; peak hours (Mon-Fri 01:00-04:00 and 06:00-10:00
            UTC) cost double.
  Anthropic list prices; no peak pricing.
A model not listed is priced as deepseek-flash and the report says so. These
are estimates for deciding pricing, not an invoice: the provider's console
is the bill.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.db import database as db_module
from app.db.models import AssistantUsageDaily

# model -> (input cache miss, input cache hit, output) USD per 1M tokens
PRICES = {
    "deepseek-flash": (0.15, 0.003, 0.60),
    "deepseek-v4-pro": (0.66, 0.022, 1.98),
    "claude-opus-5-5": (4.00, 0.20, 20.00),
    "claude-sonnet-5-5": (2.00, 0.10, 10.00),
    "claude-haiku-5-5": (0.10, 0.01, 0.50),
}
DEFAULT_PRICE_MODEL = "deepseek-flash"


def deepseek_peak(at: datetime) -> bool:
    """DeepSeek charges double Mon-Fri 01:00-04:00 and 06:00-10:00 UTC."""
    return at.weekday() < 5 and (1 <= at.hour < 4 or 6 <= at.hour < 10)


def call_cost_micros(model: str, provider: str, *, input_tokens: int, cache_read_tokens: int,
                     output_tokens: int, at: Optional[datetime] = None) -> int:
    at = at or datetime.utcnow()
    miss, hit, out = PRICES.get(model, PRICES[DEFAULT_PRICE_MODEL])
    usd = (input_tokens * miss + cache_read_tokens * hit + output_tokens * out) / 1_000_000
    if provider != "anthropic" and deepseek_peak(at):
        usd *= 2
    return int(round(usd * 1_000_000))


@dataclass
class TurnUsage:
    model_calls: int = 0
    input_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    cost_usd_micros: int = 0

    def add_call(self, usage, model: str, provider: str) -> None:
        inp = int(getattr(usage, "input_tokens", 0) or 0) + int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
        hit = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        out = int(getattr(usage, "output_tokens", 0) or 0)
        self.model_calls += 1
        self.input_tokens += inp
        self.cache_read_tokens += hit
        self.output_tokens += out
        self.cost_usd_micros += call_cost_micros(model, provider, input_tokens=inp,
                                                 cache_read_tokens=hit, output_tokens=out)


async def record(user_id: int, staff_id: Optional[int], usage: TurnUsage, *, question: bool) -> None:
    """Add one answered turn to today's row for this account. One short session."""
    if usage.model_calls == 0 and not question:
        return
    day = datetime.utcnow().date()
    staff = int(staff_id or 0)
    increments = dict(
        questions=AssistantUsageDaily.questions + (1 if question else 0),
        model_calls=AssistantUsageDaily.model_calls + usage.model_calls,
        input_tokens=AssistantUsageDaily.input_tokens + usage.input_tokens,
        cache_read_tokens=AssistantUsageDaily.cache_read_tokens + usage.cache_read_tokens,
        output_tokens=AssistantUsageDaily.output_tokens + usage.output_tokens,
        cost_usd_micros=AssistantUsageDaily.cost_usd_micros + usage.cost_usd_micros,
        updated_at=datetime.utcnow(),
    )
    where = (AssistantUsageDaily.day == day, AssistantUsageDaily.user_id == user_id,
             AssistantUsageDaily.staff_id == staff)
    for _ in range(2):
        async with db_module.async_session() as db:
            result = await db.execute(update(AssistantUsageDaily).where(*where).values(**increments))
            if (result.rowcount or 0) == 0:
                db.add(AssistantUsageDaily(
                    day=day, user_id=user_id, staff_id=staff, questions=1 if question else 0,
                    model_calls=usage.model_calls, input_tokens=usage.input_tokens,
                    cache_read_tokens=usage.cache_read_tokens, output_tokens=usage.output_tokens,
                    cost_usd_micros=usage.cost_usd_micros, updated_at=datetime.utcnow(),
                ))
            try:
                await db.commit()
                return
            except IntegrityError:  # another turn created today's row first: add to it
                await db.rollback()


async def report(days: int = 30, top: int = 15) -> dict:
    """Daily totals, the busiest accounts, and today / 7-day / 30-day summaries."""
    from app.db.models import User

    days = max(1, min(days, 365))
    today = datetime.utcnow().date()
    since = today - timedelta(days=days - 1)
    async with db_module.async_session() as db:
        daily = (await db.execute(
            select(AssistantUsageDaily.day,
                   func.sum(AssistantUsageDaily.questions), func.count(func.distinct(AssistantUsageDaily.user_id)),
                   func.sum(AssistantUsageDaily.model_calls), func.sum(AssistantUsageDaily.input_tokens),
                   func.sum(AssistantUsageDaily.cache_read_tokens), func.sum(AssistantUsageDaily.output_tokens),
                   func.sum(AssistantUsageDaily.cost_usd_micros))
            .where(AssistantUsageDaily.day >= since)
            .group_by(AssistantUsageDaily.day).order_by(AssistantUsageDaily.day)
        )).all()
        accounts = (await db.execute(
            select(AssistantUsageDaily.user_id, User.organization_name, User.email,
                   func.sum(AssistantUsageDaily.questions), func.sum(AssistantUsageDaily.cost_usd_micros))
            .join(User, User.id == AssistantUsageDaily.user_id, isouter=True)
            .where(AssistantUsageDaily.day >= since)
            .group_by(AssistantUsageDaily.user_id, User.organization_name, User.email)
            .order_by(func.sum(AssistantUsageDaily.cost_usd_micros).desc())
            .limit(top)
        )).all()

        async def window(n: int) -> dict:
            row = (await db.execute(
                select(func.coalesce(func.sum(AssistantUsageDaily.questions), 0),
                       func.count(func.distinct(AssistantUsageDaily.user_id)),
                       func.coalesce(func.sum(AssistantUsageDaily.cost_usd_micros), 0))
                .where(AssistantUsageDaily.day >= today - timedelta(days=n - 1))
            )).one()
            return {"questions": int(row[0]), "accounts": int(row[1]), "cost_usd": round(int(row[2]) / 1e6, 4)}

        summary = {"today": await window(1), "7d": await window(7), "30d": await window(30)}

    def _day(d) -> str:
        return d.isoformat() if isinstance(d, date) else str(d)

    return {
        "summary": summary,
        "days": [{
            "day": _day(r[0]), "questions": int(r[1] or 0), "accounts": int(r[2] or 0),
            "model_calls": int(r[3] or 0), "input_tokens": int(r[4] or 0),
            "cache_read_tokens": int(r[5] or 0), "output_tokens": int(r[6] or 0),
            "cost_usd": round(int(r[7] or 0) / 1e6, 4),
        } for r in daily],
        "top_accounts": [{
            "user_id": r[0], "organization_name": r[1], "email": r[2],
            "questions": int(r[3] or 0), "cost_usd": round(int(r[4] or 0) / 1e6, 4),
        } for r in accounts],
        "note": "Estimated from list prices (DeepSeek peak hours at double). The provider's console is the bill.",
    }

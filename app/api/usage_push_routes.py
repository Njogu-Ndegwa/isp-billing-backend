"""Router-facing usage-push endpoint.

Every other route in this app is called by our own frontend. This one is called
by customer hardware in the field, on a cadence the router picks, from a fleet
that is expected to grow — so the throttle that polling got for free (we decided
when to call) has to be built in here explicitly.

Three protections, in the order they run, cheapest first:

1. **Rate limit per router.** A misconfigured or hostile router cannot pin the
   server by looping. Enforced in memory — it is a throttle, not a fact worth a
   table, and losing it on restart just means one extra push per router.
2. **Load shedding.** When the DB pool is under pressure the endpoint refuses
   with 503 + ``Retry-After`` rather than queueing work that drains it. This is
   safe *because reports are cumulative snapshots, not deltas*: the next push
   carries the same totals, so a dropped push loses nothing. That property is
   what makes push survivable at fleet scale — under load we can simply say no.
3. **Batch cap.** A payload larger than one router could plausibly produce is
   refused before any DB work.

The response carries ``next_push_seconds``, so the cadence is set centrally by
the server and can be tuned without touching a thousand devices.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db.database import async_session, db_pool_snapshot
from app.db.models import Router as RouterModel
from app.services.usage_push import (
    MAX_REPORTS_PER_BATCH,
    UsageReport,
    ingest_usage_reports,
)
from app.services.usage_push_auth import verify_router_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["usage-push"])

# How often a router should report. Sent back on every accepted push so the
# fleet's cadence is a server-side setting, not something baked into 1,000
# scripts. Short enough that a customer sees their usage move within a couple of
# minutes — the "my data hasn't updated" complaint — and long enough that the
# fleet costs little.
DEFAULT_PUSH_INTERVAL_SECONDS = 120

# A router is allowed one accepted push per this window. Set below the interval
# above so a little clock drift or jitter never trips it.
MIN_SECONDS_BETWEEN_PUSHES = 60

# Shed load at the same threshold the background samplers use, so push and the
# background jobs back off together instead of fighting for the last connections.
POOL_PRESSURE_PERCENT = 60

RETRY_AFTER_ON_PRESSURE = 90

# identity -> monotonic timestamp of last accepted push.
_last_push_at: dict[str, float] = {}


def reset_rate_limiter() -> None:
    """Test hook — the limiter is process state, so tests must start clean."""
    _last_push_at.clear()


def _pool_under_pressure() -> bool:
    snapshot = db_pool_snapshot()
    percent = snapshot.get("checked_out_percent")
    try:
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except (TypeError, ValueError):
        return False


class UsageReportIn(BaseModel):
    queue_key: str = Field(max_length=128)
    upload_bytes: int = Field(ge=0)
    download_bytes: int = Field(ge=0)
    final: bool = False
    queue_name: str = Field(default="", max_length=128)
    target_ip: str = Field(default="", max_length=64)
    max_limit: str = Field(default="", max_length=64)


class UsagePushIn(BaseModel):
    identity: str = Field(max_length=128)
    reports: list[UsageReportIn] = Field(default_factory=list)


@router.post("/api/router/usage-push")
async def receive_usage_push(
    payload: UsagePushIn,
    response: Response,
    authorization: Optional[str] = Header(default=None),
):
    identity = (payload.identity or "").strip()
    presented = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()

    # Auth first and identically for every failure mode: a wrong token, a missing
    # token and an unknown identity all return the same 401, so this endpoint
    # cannot be used to enumerate which routers exist.
    if not verify_router_token(identity, presented):
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Refuse an implausible payload before touching the database.
    if len(payload.reports) > MAX_REPORTS_PER_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large; max {MAX_REPORTS_PER_BATCH} reports",
        )

    now = time.monotonic()
    last = _last_push_at.get(identity)
    if last is not None and (now - last) < MIN_SECONDS_BETWEEN_PUSHES:
        retry_after = int(MIN_SECONDS_BETWEEN_PUSHES - (now - last)) + 1
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=429,
            detail="Too many pushes",
            headers={"Retry-After": str(retry_after)},
        )

    # Shedding is safe here and nowhere else in the app: the counters are
    # cumulative, so whatever we drop arrives again in the next push.
    if _pool_under_pressure():
        logger.warning("[USAGE-PUSH] Shedding push from %s: DB pool under pressure", identity)
        raise HTTPException(
            status_code=503,
            detail="Busy, retry later",
            headers={"Retry-After": str(RETRY_AFTER_ON_PRESSURE)},
        )

    async with async_session() as db:
        router_row = (
            await db.execute(
                select(RouterModel).where(RouterModel.identity == identity)
            )
        ).scalar_one_or_none()

    # A valid token for an identity with no router is still 401, not 404 — same
    # reason as above, no enumeration.
    if router_row is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    _last_push_at[identity] = now

    result = await ingest_usage_reports(
        router_row.id,
        [
            UsageReport(
                queue_key=item.queue_key,
                upload_bytes=item.upload_bytes,
                download_bytes=item.download_bytes,
                final=item.final,
                queue_name=item.queue_name,
                target_ip=item.target_ip,
                max_limit=item.max_limit,
            )
            for item in payload.reports
        ],
    )

    if result.over_cap_customer_ids:
        # Enforcement does RouterOS I/O, so it must not run inside this request
        # with anything held. Handing the ids to the existing cap-enforcement
        # path is the remaining wiring; logged for now so the rollout can be
        # observed before enforcement is moved onto this trigger.
        logger.info(
            "[USAGE-PUSH] %s reported %d customer(s) over cap: %s",
            identity, len(result.over_cap_customer_ids), result.over_cap_customer_ids,
        )

    return {
        "accepted": result.accepted,
        "rejected": result.rejected,
        "next_push_seconds": DEFAULT_PUSH_INTERVAL_SECONDS,
    }

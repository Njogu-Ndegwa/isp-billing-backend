"""Router check-in delivery endpoint (pilot) — ``POST /api/router/checkin``.

Called by the fixed applier script on pilot routers, over the same public
Cloudflare hostname as the usage push. See ``app/services/checkin_delivery.py``
for the protocol and why it exists.

Order of work, cheapest first, and never any router I/O:

1. Body size cap + parse (no DB).
2. Token check (HMAC, no DB). Every auth failure is the same 401.
3. Flags: disabled / kill switch -> empty idle frame (no DB).
4. Per-identity rate limit (memory).
5. Router lookup (cached identity -> id; short session on a miss). Unknown
   identity -> 401; router not in the allowlist -> empty idle frame.
6. Pool pressure -> empty frame, unless a customer on this router is paying
   right now or a paid attempt on it is young (never shed the one case the
   channel exists for).
7. One short read of the desired state (session released), then a pure diff.
8. After the reply is decided: if the report shows a paid customer present
   whose provisioning attempt is still undelivered, ONE short write session
   marks it delivered ('checkin' only if the check-in added the binding,
   'observed' if the push had given up; see ``classify_delivery``). It runs as a background task after the
   response is sent, only when there is something to mark, and is skipped
   under pool pressure (the next check-in retries it; it is idempotent).
9. checkin_only routers: a waiting payment whose MAC the report shows already
   bound (renewal while still bound) is handed to the push at once, after
   the reply (the applier cannot update an existing binding). No router I/O
   here: the push is the existing payment path, run as a background task.

Every reply that is not a 400/401 is a well-formed ``BWE1`` frame, so the
router's validator can treat anything else (Cloudflare error page, captive
portal, truncation) as "apply nothing".
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Header, Request
from fastapi.responses import PlainTextResponse

from app.db.database import db_pool_snapshot
from app.services import checkin_delivery as svc
from app.services.usage_push_auth import verify_checkin_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["router-checkin"])

POOL_PRESSURE_PERCENT = 60
MAX_CONCURRENT_CHECKIN_READS = 3
_read_gate = asyncio.Semaphore(MAX_CONCURRENT_CHECKIN_READS)

_HEADERS = {"Cache-Control": "no-store"}


def reset_state() -> None:
    """Test hook."""
    global _read_gate
    _read_gate = asyncio.Semaphore(MAX_CONCURRENT_CHECKIN_READS)
    svc.reset_state()


def _pool_under_pressure() -> bool:
    snapshot = db_pool_snapshot()
    percent = snapshot.get("checked_out_percent")
    try:
        return percent is not None and float(percent) >= POOL_PRESSURE_PERCENT
    except (TypeError, ValueError):
        return False


def _frame(body: str, background: Optional[BackgroundTasks] = None) -> PlainTextResponse:
    return PlainTextResponse(body, headers=_HEADERS, background=background)


async def _hand_off(attempt_ids: list[int]) -> None:
    """Background: wake the push for renewals the check-in cannot deliver.

    Async on purpose: a plain function would run in Starlette's threadpool,
    away from the event loop the push timers live on."""
    try:
        from app.services.hotspot_provisioning import request_renewal_handoffs

        request_renewal_handoffs(attempt_ids)
    except Exception:  # never let this break the channel; the fallback timer remains
        logger.exception("[CHECKIN] renewal hand-off of %s failed", attempt_ids)


async def _record_deliveries(router_id: int, candidates: list) -> None:
    """Background: settle undelivered attempts the report proved delivered."""
    try:
        if _pool_under_pressure():
            return  # idempotent; the next check-in offers it again
        async with _read_gate:
            await svc.record_checkin_deliveries(router_id, candidates)
    except Exception:  # never let bookkeeping break the channel
        logger.exception("[CHECKIN] router %s: recording check-in deliveries failed", router_id)


def _plain(status: int, text: str) -> PlainTextResponse:
    return PlainTextResponse(text + "\n", status_code=status, headers=_HEADERS)


@router.post("/api/router/checkin")
async def router_checkin(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    raw = await request.body()
    try:
        report = svc.parse_checkin_body(raw)
    except svc.BadCheckin as exc:
        return _plain(400, f"bad request: {exc}")

    presented = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if not verify_checkin_token(report.identity, presented):
        return _plain(401, "unauthorized")

    if not svc.checkin_active():
        return _frame(svc.idle_frame())

    if svc.rate_limited(report.identity):
        return _frame(svc.idle_frame(svc.NORMAL_POLL_SECONDS))

    cached = svc._router_cache.get(report.identity)
    under_pressure = _pool_under_pressure()
    if under_pressure and (cached is None or not svc.shed_exempt(cached.id)):
        logger.warning("[CHECKIN] shedding check-in from %s: DB pool under pressure", report.identity)
        return _frame(svc.idle_frame(svc.NORMAL_POLL_SECONDS))

    async with _read_gate:
        router_ref = await svc.resolve_router(report.identity)
        if router_ref is None:
            # Valid token for an identity with no router: same 401, no enumeration.
            return _plain(401, "unauthorized")
        if router_ref.id not in svc.checkin_router_ids():
            return _frame(svc.idle_frame())
        now = datetime.utcnow()
        state = await svc.load_checkin_state(router_ref.id, now)

    decision = svc.decide(
        router=router_ref,
        report=report,
        desired=state.desired,
        undelivered_recent=state.undelivered_recent,
        mode=svc.checkin_mode(),
        now=now,
        pending=state.pending,
    )
    background = None
    candidates = svc.delivery_candidates(report, state.pending, router_ref.id)
    if candidates:
        background = BackgroundTasks()
        background.add_task(_record_deliveries, router_ref.id, candidates)
    handoffs = svc.renewal_handoff_candidates(report, state.pending, router_ref.id)
    if handoffs:
        background = background or BackgroundTasks()
        background.add_task(_hand_off, [p.attempt_id for p in handoffs])
    return _frame(
        svc.render_frame(svc._seq(), decision.lines, decision.next_s, decision.queue_lines),
        background,
    )

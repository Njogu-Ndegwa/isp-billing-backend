"""Guards for the public PPPoE expired page (app/api/pppoe_expired_routes.py).

Those endpoints have no login and can send an M-Pesa prompt, so:

* Rate limits. In-process, like ``code_attempt_limiter``: the app runs as one
  worker. Failed account lookups are capped per caller and per router so the
  page can't be used to test usernames; prompts are capped per customer and per
  target phone so it can't be used to pester someone's phone. The caller's IP is
  only a first line: it can be spoofed, and walled customers of one router
  share its public IP, so the per-router, per-customer and per-phone caps are
  what actually hold.
* A plan picked on the page is only a choice for the prompt it went out with.
  Payment confirmation reads ``customer.pending_update_data`` for ANY payment,
  and this page writes it for anyone who knows a username. So the entry carries
  its amount, and a payment of any other amount drops it: an ignored prompt, or
  one sent by someone else, can't change what the customer's own paybill renews.

Nothing here runs unless the page wrote an entry, and the page answers only for
routers with the switch on.
"""

from __future__ import annotations

import json
import time
from collections import deque
from typing import Any, Optional

from fastapi import HTTPException, Request

from app.services.impersonation import client_ip

PAGE_SOURCE = "pppoe_expired_page"
_PAGE_KEYS = (
    "requested_at", "plan_id", "plan_name", "duration_value", "duration_unit",
    "payment_method", "router_id", "phone", "source", "amount",
)

LOOKUP_WINDOW_SECONDS = 600
MAX_LOOKUP_MISSES_PER_CALLER = 15
# Blocks the page for every customer of the router while it lasts, so it sits
# well above honest typos: only customers with no username in the link type.
MAX_LOOKUP_MISSES_PER_ROUTER = 60

REQUEST_WINDOW_SECONDS = 60
# A page polls 4 to 15 times a minute and one router's walled customers share an
# IP, so this only stops floods.
MAX_REQUESTS_PER_CALLER = 300

PROMPT_MIN_GAP_SECONDS = 15
PROMPT_SHORT_WINDOW_SECONDS = 1800
PROMPT_DAY_SECONDS = 86400
MAX_PROMPTS_PER_CUSTOMER = 5
MAX_PROMPTS_PER_PHONE = 5
MAX_PROMPTS_PER_PHONE_PER_DAY = 15
MAX_PROMPTS_PER_CALLER = 60

_MAX_TRACKED_KEYS = 20000

_hits: dict[tuple, deque] = {}
_prompts_in_flight: set[int] = set()


def reset_limits() -> None:
    """Test hook: the limits are process state."""
    _hits.clear()
    _prompts_in_flight.clear()


def caller_key(request: Request) -> str:
    """The caller's IP. Through the portal's /api/bw proxy, the IP Vercel saw:
    Cloudflare would report Vercel itself, pooling every proxied customer."""
    if request.headers.get("x-bw-proxy"):
        forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if forwarded:
            return forwarded[:64]
    return client_ip(request) or "unknown"


def _count(key: tuple, window: float, now: float) -> int:
    bucket = _hits.get(key)
    if bucket is None:
        return 0
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    if not bucket:
        _hits.pop(key, None)
        return 0
    return len(bucket)


def _record(key: tuple, now: float) -> None:
    if len(_hits) > _MAX_TRACKED_KEYS:
        for stale in list(_hits):
            _count(stale, PROMPT_DAY_SECONDS, now)
    _hits.setdefault(key, deque()).append(now)


def check_request_rate(caller: str) -> None:
    now = time.monotonic()
    key = ("request", caller)
    if _count(key, REQUEST_WINDOW_SECONDS, now) >= MAX_REQUESTS_PER_CALLER:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait a minute and try again.")
    _record(key, now)


def check_lookups(router_id: int, caller: str) -> None:
    """Raise 429 before a lookup once too many recent lookups found nothing."""
    now = time.monotonic()
    if (
        _count(("miss-caller", router_id, caller), LOOKUP_WINDOW_SECONDS, now) >= MAX_LOOKUP_MISSES_PER_CALLER
        or _count(("miss-router", router_id), LOOKUP_WINDOW_SECONDS, now) >= MAX_LOOKUP_MISSES_PER_ROUTER
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect account numbers. Please wait a few minutes and try again.",
        )


def record_lookup_miss(router_id: int, caller: str) -> None:
    now = time.monotonic()
    _record(("miss-caller", router_id, caller), now)
    _record(("miss-router", router_id), now)


def claim_prompt(customer_id: int, phone: str, caller: str) -> None:
    """Admit one prompt or refuse it. Checks and records with no await between
    them, so two requests at once can't both pass; release_prompt ends the claim."""
    now = time.monotonic()
    busy = customer_id in _prompts_in_flight
    bucket = _hits.get(("prompt-customer", customer_id))
    if busy or (bucket and now - bucket[-1] < PROMPT_MIN_GAP_SECONDS):
        raise HTTPException(status_code=409, detail={
            "status": "payment_in_progress",
            "message": "A prompt was just sent. Check your phone, or wait a moment before trying again.",
        })
    if (
        _count(("prompt-customer", customer_id), PROMPT_SHORT_WINDOW_SECONDS, now) >= MAX_PROMPTS_PER_CUSTOMER
        or _count(("prompt-phone", phone), PROMPT_SHORT_WINDOW_SECONDS, now) >= MAX_PROMPTS_PER_PHONE
        or _count(("prompt-phone-day", phone), PROMPT_DAY_SECONDS, now) >= MAX_PROMPTS_PER_PHONE_PER_DAY
        or _count(("prompt-caller", caller), PROMPT_SHORT_WINDOW_SECONDS, now) >= MAX_PROMPTS_PER_CALLER
    ):
        raise HTTPException(
            status_code=429,
            detail="Too many payment prompts. Please wait a while, or pay with the paybill details below.",
        )
    _prompts_in_flight.add(customer_id)
    _record(("prompt-customer", customer_id), now)
    _record(("prompt-phone", phone), now)
    _record(("prompt-phone-day", phone), now)
    _record(("prompt-caller", caller), now)


def release_prompt(customer_id: int) -> None:
    _prompts_in_flight.discard(customer_id)


# ---------------------------------------------------------------------------
# The plan picked on the page
# ---------------------------------------------------------------------------


def _pending(customer: Any) -> Optional[dict]:
    data = customer.pending_update_data
    if not data:
        return None
    try:
        data = json.loads(data) if isinstance(data, str) else data
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def is_page_plan(data: Any) -> bool:
    return isinstance(data, dict) and data.get("source") == PAGE_SOURCE


def set_page_plan(customer: Any, **fields: Any) -> None:
    """Record the plan a prompt went out for, keeping what others stored there
    (an imported customer's metadata lives in this column too)."""
    kept = {k: v for k, v in (_pending(customer) or {}).items() if k not in _PAGE_KEYS}
    customer.pending_update_data = json.dumps({**kept, **fields, "source": PAGE_SOURCE})


def clear_page_plan(customer: Any) -> None:
    """Remove an earlier page choice, and only that: anyone can reach this."""
    data = _pending(customer)
    if not is_page_plan(data):
        return
    kept = {k: v for k, v in data.items() if k not in _PAGE_KEYS}
    customer.pending_update_data = json.dumps(kept) if kept else None


def drop_unpaid_page_plan(customer: Any, paid_amount: Any) -> None:
    """Call before reading pending_update_data for a payment: a page choice only
    counts for a payment of exactly the amount its prompt asked for."""
    data = _pending(customer)
    if not is_page_plan(data):
        return
    try:
        matches = abs(float(paid_amount) - float(data.get("amount"))) < 0.5
    except (TypeError, ValueError):
        matches = False
    if not matches:
        clear_page_plan(customer)

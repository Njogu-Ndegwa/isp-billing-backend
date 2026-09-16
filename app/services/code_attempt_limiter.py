"""In-process throttle for public code / phone lookups on the captive portal.

Access codes, vouchers and phone numbers are the only credential a hotspot
customer has, so the public endpoints that accept them must not allow
unlimited guessing. The app runs as a single worker, so process memory is
enough (the same approach as ``usage_push_routes``).

Only *failed* lookups count: a customer who types a valid code is never slowed
down, however many devices they add.
"""

import time
from collections import deque

from fastapi import HTTPException

WINDOW_SECONDS = 600
MAX_FAILURES_PER_DEVICE = 8
MAX_FAILURES_PER_ROUTER = 60
_MAX_TRACKED_KEYS = 20000

_failures: dict[tuple, deque] = {}


def _recent(key: tuple, now: float) -> deque:
    bucket = _failures.get(key)
    if bucket is None:
        return deque()
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    if not bucket:
        _failures.pop(key, None)
    return bucket


def _evict_stale(now: float) -> None:
    for key in list(_failures):
        _recent(key, now)


def check_code_attempts(router_id: int, device_key: str | None) -> None:
    """Raise 429 when this device or router has too many recent failures."""
    now = time.monotonic()
    device_failures = len(_recent(("device", router_id, (device_key or "").upper()), now))
    router_failures = len(_recent(("router", router_id), now))
    if device_failures >= MAX_FAILURES_PER_DEVICE or router_failures >= MAX_FAILURES_PER_ROUTER:
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect attempts. Please wait a few minutes and try again.",
        )


def record_code_failure(router_id: int, device_key: str | None) -> None:
    now = time.monotonic()
    if len(_failures) > _MAX_TRACKED_KEYS:
        _evict_stale(now)
    for key in (("device", router_id, (device_key or "").upper()), ("router", router_id)):
        _failures.setdefault(key, deque()).append(now)


def reset_code_attempt_limiter() -> None:
    """Test hook — the limiter is process state, so tests must start clean."""
    _failures.clear()

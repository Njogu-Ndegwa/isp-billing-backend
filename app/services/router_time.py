"""Router wall-clock times, turned into true UTC next to the raw value.

A MikroTik writes its log stamps and a PPP secret's ``last-logged-out`` on its
own clock: local time (EAT on most of the fleet), and on some boxes an hour or
more off. Anything downstream that reads "2026-11-23 13:22:15" as UTC puts the
event hours in the future (CR-1123-B3: the assistant told a reseller a session
was cut "at 16:22 EAT, in 1 h").

So wherever the backend reads such a field from a router, it also reads
``/system/clock`` in the same connection and adds ``<field>_utc``: the moment
as ISO UTC ("2026-11-23T11:22:15Z"), worked out from the distance to the
router's own "now", so the router's time zone setting and its drift both drop
out. The raw field is left as it was (the dashboard pages show it). When the
clock could not be read or is not plausible, ``<field>_utc`` is None: the
value is router time and nobody should convert it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from app.services.customer_router_logs import MIN_PLAUSIBLE_YEAR, RouterClock, parse_log_time

logger = logging.getLogger(__name__)

# Fields a router fills from its own clock (API names and raw RouterOS names).
ROUTER_CLOCK_KEYS = frozenset({
    "time",                 # /log rows
    "last_logged_out", "last-logged-out",  # /ppp/secret
    "last_at",              # last matching log line (auth failures)
    "last-link-up-time", "last-link-down-time",  # /interface
    "since",                # /tool/netwatch
    "creation-time", "last-modified",  # /file
})

# A past event can be a little "ahead" from rounding between the two reads.
_FUTURE_SLACK = timedelta(minutes=2)


def utc_key(key: str) -> str:
    """Name of the UTC companion of a router-clock field."""
    return key.replace("-", "_") + "_utc"


def read_router_clock(api: Any, now_utc: Optional[datetime] = None) -> Optional[RouterClock]:
    """The router's clock, read on an open connection. None if it cannot be read."""
    try:
        result = api.send_command("/system/clock/print")
    except Exception as exc:  # the caller's data is still worth returning
        logger.debug("router clock read failed: %s", exc)
        return None
    rows = result.get("data") if isinstance(result, dict) and result.get("success") else None
    if not rows or not isinstance(rows[0], dict) or not rows[0].get("date"):
        return None
    return RouterClock.from_clock_print(rows[0], now_utc or datetime.utcnow())


def router_time_to_utc(raw: Any, clock: Optional[RouterClock]) -> Optional[str]:
    """A router-clock stamp as ISO UTC, or None when it cannot be known."""
    if clock is None or not clock.trusted or clock.fetched_utc is None:
        return None
    text = str(raw or "").strip()
    if not text:
        return None
    local = parse_log_time(text, clock)
    if local is None or local.year < MIN_PLAUSIBLE_YEAR:
        return None
    utc = clock.to_utc(local)
    if utc > clock.fetched_utc + _FUTURE_SLACK:
        return None  # a past event after the router's own "now": not a usable stamp
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp_router_times(data: Any, clock: Optional[RouterClock], keys: frozenset = ROUTER_CLOCK_KEYS) -> Any:
    """Add ``<field>_utc`` next to every router-clock field, in place. Returns *data*."""
    if isinstance(data, list):
        for item in data:
            stamp_router_times(item, clock, keys)
    elif isinstance(data, dict):
        for key in list(data.keys()):
            value = data[key]
            if isinstance(key, str) and key in keys and (value is None or isinstance(value, str)):
                data[utc_key(key)] = router_time_to_utc(value, clock)
            elif isinstance(value, (dict, list)):
                stamp_router_times(value, clock, keys)
    return data

"""Router-side expiry ("reaper") protocol: pure helpers, no I/O.

The router enforces the deadline, the platform decides and records:

1. Provisioning writes the customer's deadline into the ip-binding comment as
   ``EXP:<unix minute, UTC, rounded up>``. A plain integer, so RouterOS 6 and 7
   compare it with no date parsing beyond "what minute is it now".
2. Once a minute the reaper script (``expiry_reaper_script.py``) collects the
   bindings whose deadline has passed and asks the server about them
   (``POST /api/router/expiry-check``). The server answers per MAC:
     R  remove  - still expired in the database;
     K  keep    - renewed, here is the new deadline (renewal paid while the
                  router could not be told);
     X  forget  - no customer of ours has this MAC; stop asking.
3. The router removes what it was told to and reports it on its next call
   (``done=MAC@minute``). Only that report marks the customer INACTIVE and
   writes the ``hotspot_deactivation`` log, so the platform records a removal
   only after the router confirms it.
4. If the server cannot be reached, the router falls back to its own deadline,
   but only when the server has confirmed its clock since the router last booted
   (``C=1``), so a no-RTC board that rebooted into 1970 never mass-removes.

Wire format is deliberately flat text: RouterOS 6 has no JSON parser, and the
script parses the reply with ``:find``/``:pick`` only.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

EXP_TAG = "EXP:"
# The reaper stops asking about a binding once its tag is renamed to this.
FORGOTTEN_TAG = "EXX:"

MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_IDENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

MAX_ITEMS_PER_CALL = 40      # per list; the router's fetch reply must stay small
MAX_BODY_BYTES = 8192
CLOCK_TOLERANCE_MINUTES = 5  # router clock this close to ours counts as trusted
# A reported removal minute is used as the removal time only when it is this
# close to now; otherwise the arrival time is used.
DONE_MINUTE_MAX_SKEW = 60


def expiry_minute(expiry: datetime) -> int:
    """Unix minute (UTC) at or after ``expiry``. Rounded UP: a router asking at
    the tagged minute must never be ahead of the real expiry."""
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return math.ceil(expiry.timestamp() / 60)


def minute_to_datetime(minute: int) -> datetime:
    """Naive UTC datetime for a unix minute (the DB stores naive UTC)."""
    return datetime.fromtimestamp(int(minute) * 60, tz=timezone.utc).replace(tzinfo=None)


def done_time_to_datetime(value: int) -> datetime:
    """When the router says it removed a customer. Scripts report unix
    SECONDS (so removal speed is measurable below a minute); the first pilot
    install reported unix minutes. The two ranges cannot overlap."""
    value = int(value)
    seconds = value if value >= 1_000_000_000 else value * 60
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)


def binding_comment(username: str, expiry: Optional[datetime], now: Optional[datetime] = None) -> str:
    """The ip-binding comment written at provisioning. Keeps the long-standing
    ``USER:`` and ``EXPIRES:DB_MANAGED`` fields (matched elsewhere) and adds the
    reaper's ``EXP:`` deadline when the expiry is known."""
    stamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    parts = [f"USER:{username}", "EXPIRES:DB_MANAGED"]
    if expiry is not None:
        parts.append(f"{EXP_TAG}{expiry_minute(expiry)}")
    parts.append(stamp)
    return "|".join(parts)


def with_exp_tag(comment: str, minute: int) -> str:
    """Set (or replace) the EXP tag in an existing binding comment."""
    comment = comment or ""
    stripped = re.sub(r"\|?(EXP|EXX):\d*", "", comment)
    return f"{stripped}|{EXP_TAG}{int(minute)}" if stripped else f"{EXP_TAG}{int(minute)}"


def normalize_mac(value: str) -> Optional[str]:
    mac = (value or "").strip().upper().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


@dataclass
class ExpiryCheckRequest:
    identity: str
    router_now: Optional[int]
    due: list[str] = field(default_factory=list)
    done: list[tuple[str, Optional[int]]] = field(default_factory=list)


def _split(value: str) -> list[str]:
    return [p for p in (value or "").split(",") if p.strip()]


def parse_request(body: str) -> ExpiryCheckRequest:
    """Parse ``ident=..&now=..&due=MAC,MAC,&done=MAC@min,``. Unparseable
    entries are dropped, never guessed at."""
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("body too large")
    fields: dict[str, str] = {}
    for pair in body.strip().split("&"):
        key, _, value = pair.partition("=")
        fields[key.strip()] = value.strip()
    identity = fields.get("ident", "")
    if not _IDENT_RE.match(identity):
        raise ValueError("bad identity")
    try:
        router_now = int(fields.get("now", ""))
    except ValueError:
        router_now = None

    due: list[str] = []
    for raw in _split(fields.get("due", "")):
        mac = normalize_mac(raw)
        if mac and mac not in due:
            due.append(mac)
    done: list[tuple[str, Optional[int]]] = []
    for raw in _split(fields.get("done", "")):
        mac_part, _, minute_part = raw.partition("@")
        mac = normalize_mac(mac_part)
        if not mac:
            continue
        try:
            minute = int(minute_part)
        except ValueError:
            minute = None
        done.append((mac, minute))
    return ExpiryCheckRequest(identity, router_now, due[:MAX_ITEMS_PER_CALL], done[:MAX_ITEMS_PER_CALL])


def clock_ok(router_now: Optional[int], server_now: datetime) -> bool:
    if router_now is None:
        return False
    return abs(router_now - int(expiry_minute(server_now))) <= CLOCK_TOLERANCE_MINUTES


@dataclass
class CustomerRow:
    customer_id: int
    mac: str
    active: bool
    expiry: Optional[datetime]


def decide(due: Iterable[str], rows: Iterable[CustomerRow], now: datetime) -> tuple[list[str], list[tuple[str, int]], list[str]]:
    """(remove, keep[(mac, new_minute)], forget) for the MACs a router says are due.

    A MAC can have several customer rows on one router (abandoned STK pushes
    leave phantom rows), so the decision is per MAC: any row still ACTIVE with a
    future expiry means "keep, until the latest such expiry". Rows that exist
    but none is paid-up means "remove". No row at all: not ours, forget it.
    """
    by_mac: dict[str, list[CustomerRow]] = {}
    for row in rows:
        by_mac.setdefault(row.mac, []).append(row)
    remove: list[str] = []
    keep: list[tuple[str, int]] = []
    forget: list[str] = []
    for mac in due:
        found = by_mac.get(mac)
        if not found:
            forget.append(mac)
            continue
        live = [r.expiry for r in found if r.active and r.expiry is not None and r.expiry > now]
        if live:
            keep.append((mac, expiry_minute(max(live))))
        elif any(r.active and r.expiry is None for r in found):
            forget.append(mac)  # no deadline to enforce; leave it to the platform
        else:
            remove.append(mac)
    return remove, keep, forget


def render_reply(clock_trusted: bool, remove: list[str], keep: list[tuple[str, int]], forget: list[str]) -> str:
    """``BW1;C=1;R=mac,;K=mac@min,;X=mac,;`` Every segment is always present
    and ends with ``;`` so the script's ``:find`` for the next ``;`` never fails."""
    r = "".join(f"{m}," for m in remove)
    k = "".join(f"{m}@{minute}," for m, minute in keep)
    x = "".join(f"{m}," for m in forget)
    return f"BW1;C={1 if clock_trusted else 0};R={r};K={k};X={x};"

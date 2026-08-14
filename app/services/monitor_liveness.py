"""Honest liveness for the hotspot / PPPoE monitor snapshots.

A monitor snapshot ("who is online, at what speed") is only a statement about
*now* for as long as the router keeps answering. When it stops answering — a
power cut at the site is by far the most common reason — the last snapshot
becomes a statement about the past that the dashboard was still presenting as
the present: every customer kept a pulsing green **Online** pill and their last
observed download/upload rate, indefinitely, while their router sat dark.

Reported by a reseller on 2026-08-14: "stima hakuna stima but inashow bado kuna
active customers and their respective Internet speeds still running".

Two different degraded states get two different answers here, because
conflating them is how the lie got shipped in the first place:

* :func:`clear_live_state` — we *know* the router is unreachable. Nobody behind
  it can be online, so every live field is cleared and the response says so
  (``router_reachable: False``). The roster and cumulative byte counters are
  kept: they are still the best record of who the customers are and what they
  had used by the time the lights went out.
* :func:`mark_snapshot_unverified` — we simply did not ask (DB pool pressure,
  for instance). The router is probably fine, so the last known state is served
  as-is, but flagged ``live: False`` with its age so the UI can say "as of 4m
  ago" instead of implying a live reading.

Both helpers copy their input: the caller's dict is the process-wide response
cache, and mutating it in place would poison the next request.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Optional


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and value:
        return value
    return None


def _rounded(age_seconds: Optional[float]) -> Optional[float]:
    return round(age_seconds, 1) if isinstance(age_seconds, (int, float)) else None


def offline_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """Strip every field that asserts a live session from one monitor user.

    Cumulative ``upload_bytes`` / ``download_bytes`` survive — they are a
    running total, not a claim about the present — as do identity and config
    fields (``username``, ``mac_address``, ``disabled``, ``binding_type``,
    ``max_limit``, ``customer``).
    """
    entry = dict(user)
    entry["online"] = False
    entry["upload_rate"] = "0"
    entry["download_rate"] = "0"
    entry["address"] = None
    entry["uptime"] = None
    # Only clear keys the source payload actually carries, so the hotspot and
    # PPPoE shapes each keep their own contract with the frontend.
    if "online_source" in entry:
        entry["online_source"] = None
    if "idle_time" in entry:
        entry["idle_time"] = None
    if "login_by" in entry:
        entry["login_by"] = ""
    if "authorized" in entry:
        # `authorized` is live hotspot-host state; `bypassed` is an IP-binding,
        # i.e. configuration, and stays.
        entry["authorized"] = False
    return entry


def offline_summary(summary: Optional[Dict[str, Any]], total: int) -> Dict[str, Any]:
    """Rebuild a monitor summary for a router where nobody can be connected."""
    result = dict(summary or {})
    result["total"] = total
    result["online"] = 0
    result["offline"] = total
    result["total_upload_rate_bps"] = 0
    result["total_download_rate_bps"] = 0
    return result


def clear_live_state(
    payload: Dict[str, Any],
    *,
    reason: str,
    age_seconds: Optional[float] = None,
    last_online_at: Any = None,
) -> Dict[str, Any]:
    """Return a copy of a cached snapshot with all liveness claims removed.

    Use when the router is known to be unreachable. ``reason`` is echoed back
    as ``fallback_reason`` (``connect_failed``, ``timeout``,
    ``router_recently_offline``) so the UI can explain itself.
    """
    snapshot = deepcopy(payload)
    users = [offline_user(u) for u in (snapshot.get("users") or [])]
    snapshot["users"] = users
    snapshot["summary"] = offline_summary(snapshot.get("summary"), len(users))
    snapshot.update({
        "cached": True,
        "stale": True,
        "live": False,
        "router_reachable": False,
        "cache_age_seconds": _rounded(age_seconds),
        "fallback_reason": reason,
        "router_last_online_at": _iso(last_online_at),
    })
    return snapshot


def mark_snapshot_unverified(
    payload: Dict[str, Any],
    *,
    reason: str,
    age_seconds: Optional[float] = None,
    last_online_at: Any = None,
) -> Dict[str, Any]:
    """Return a copy of a cached snapshot served without re-checking the router.

    Online flags and rates are preserved — we have no evidence against them —
    but ``live`` is False and the age is attached, so the frontend shows the
    data as a reading from the past rather than a live one.
    """
    snapshot = deepcopy(payload)
    snapshot.update({
        "cached": True,
        "stale": True,
        "live": False,
        "router_reachable": None,
        "cache_age_seconds": _rounded(age_seconds),
        "fallback_reason": reason,
        "router_last_online_at": _iso(last_online_at),
    })
    return snapshot

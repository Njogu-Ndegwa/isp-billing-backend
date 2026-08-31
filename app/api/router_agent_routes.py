"""Authenticated, load-shedding command channel for outbound router agents."""

from __future__ import annotations

import asyncio
from collections import deque
import logging
import random
import re
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import or_, select, update

from app.db.database import async_session, db_pool_snapshot
from app.db.models import AppSetting, Router, RouterCommand
from app.config import settings
from app.services.router_agent_auth import (
    derive_router_agent_token,
    verify_router_agent_token,
)
from app.services.router_agent_script import SCHEDULER_TICK_SECONDS
from app.services.router_agent_commands import (
    ACTIVE_COMMAND_STATES,
    acknowledge_command,
    expire_active_commands,
    has_active_commands,
    next_command_for_router,
)


logger = logging.getLogger(__name__)
router = APIRouter(tags=["router-agent"])

POOL_PRESSURE_PERCENT = 60
MAX_CONCURRENT_POLLS = 32
MIN_SECONDS_BETWEEN_POLLS = 15
HEARTBEAT_PERSIST_SECONDS = 600
CACHE_REFRESH_SECONDS = 30
ROUTER_CACHE_REFRESH_SECONDS = 60
PENDING_CACHE_REFRESH_SECONDS = 30
AGENT_VERSION_MAX_LENGTH = 20

_SETTING_DEFAULTS = {
    "router_agent_enabled": "false",
    "router_agent_pppoe_commands_enabled": "false",
    "router_agent_normal_min_seconds": "90",
    "router_agent_normal_max_seconds": "150",
    "router_agent_degraded_min_seconds": "30",
    "router_agent_degraded_max_seconds": "60",
}

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_BASE_URL_RE = re.compile(r"^https://[A-Za-z0-9._:-]{3,200}$")

_router_cache: dict[str, tuple[int, bool]] = {}
_pending_router_ids: set[int] = set()
_last_poll_at: dict[str, float] = {}
_heartbeat_at: dict[int, float] = {}
_settings_cache: dict[str, str] = dict(_SETTING_DEFAULTS)
_settings_refreshed_at = 0.0
_routers_refreshed_at = 0.0
_pending_refreshed_at = 0.0
_active_polls = 0
_cache_lock = asyncio.Lock()
_poll_counter_lock = asyncio.Lock()
_metrics_started_at = datetime.utcnow()
_metrics: dict[str, int] = {
    "polls_total": 0,
    "polls_idle": 0,
    "polls_command": 0,
    "polls_unauthorized": 0,
    "polls_rate_limited": 0,
    "polls_load_shed": 0,
    "polls_pending_cache_hits": 0,
    "polls_pending_cache_misses": 0,
    "acks_total": 0,
    "acks_applied": 0,
    "acks_failed": 0,
    "active_poll_peak": 0,
}
_poll_latency_ms: deque[float] = deque(maxlen=2048)
_ack_latency_seconds: deque[float] = deque(maxlen=2048)


def _percentile(values: deque[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * percentile)))
    return round(ordered[index], 2)


def router_agent_metrics_snapshot() -> dict:
    """Cheap process-local counters for rollout monitoring."""

    return {
        "started_at": _metrics_started_at.isoformat(),
        **_metrics,
        "active_polls": _active_polls,
        "enabled_router_cache_size": sum(1 for _, enabled in _router_cache.values() if enabled),
        "pending_router_cache_size": len(_pending_router_ids),
        "poll_latency_ms_p50": _percentile(_poll_latency_ms, 0.50),
        "poll_latency_ms_p95": _percentile(_poll_latency_ms, 0.95),
        "poll_latency_ms_max": round(max(_poll_latency_ms), 2) if _poll_latency_ms else None,
        "ack_latency_seconds_p50": _percentile(_ack_latency_seconds, 0.50),
        "ack_latency_seconds_p95": _percentile(_ack_latency_seconds, 0.95),
        "ack_latency_seconds_max": round(max(_ack_latency_seconds), 2) if _ack_latency_seconds else None,
    }


def reset_router_agent_caches() -> None:
    """Test hook and safe process-local cache reset."""

    global _settings_refreshed_at, _routers_refreshed_at, _pending_refreshed_at, _active_polls
    _router_cache.clear()
    _pending_router_ids.clear()
    _last_poll_at.clear()
    _heartbeat_at.clear()
    _settings_cache.clear()
    _settings_cache.update(_SETTING_DEFAULTS)
    _settings_refreshed_at = 0.0
    _routers_refreshed_at = 0.0
    _pending_refreshed_at = 0.0
    _active_polls = 0
    for key in _metrics:
        _metrics[key] = 0
    _poll_latency_ms.clear()
    _ack_latency_seconds.clear()


def note_router_has_pending_command(router_id: int) -> None:
    _pending_router_ids.add(int(router_id))


def _pool_under_pressure() -> bool:
    snapshot = db_pool_snapshot()
    value = snapshot.get("checked_out_percent")
    return isinstance(value, (int, float)) and value >= POOL_PRESSURE_PERCENT


def _setting_bool(name: str) -> bool:
    return _settings_cache.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _setting_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(_settings_cache.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


async def _refresh_settings_if_due(force: bool = False) -> None:
    global _settings_refreshed_at
    now = time.monotonic()
    if not force and now - _settings_refreshed_at < CACHE_REFRESH_SECONDS:
        return
    async with _cache_lock:
        now = time.monotonic()
        if not force and now - _settings_refreshed_at < CACHE_REFRESH_SECONDS:
            return
        async with async_session() as db:
            rows = (
                await db.execute(
                    select(AppSetting.key, AppSetting.value).where(
                        AppSetting.key.in_(tuple(_SETTING_DEFAULTS))
                    )
                )
            ).all()
        _settings_cache.clear()
        _settings_cache.update(_SETTING_DEFAULTS)
        _settings_cache.update({key: value for key, value in rows})
        _settings_refreshed_at = now


async def _refresh_router_cache_if_due(force: bool = False) -> None:
    global _routers_refreshed_at
    now = time.monotonic()
    if not force and now - _routers_refreshed_at < ROUTER_CACHE_REFRESH_SECONDS:
        return
    async with _cache_lock:
        now = time.monotonic()
        if not force and now - _routers_refreshed_at < ROUTER_CACHE_REFRESH_SECONDS:
            return
        async with async_session() as db:
            rows = (
                await db.execute(
                    select(Router.id, Router.identity, Router.router_agent_enabled).where(
                        Router.identity.isnot(None)
                    )
                )
            ).all()
        _router_cache.clear()
        _router_cache.update(
            {
                identity: (router_id, bool(enabled))
                for router_id, identity, enabled in rows
                if identity
            }
        )
        _routers_refreshed_at = now


async def _refresh_pending_cache_if_due(force: bool = False) -> None:
    global _pending_refreshed_at
    now = time.monotonic()
    if not force and now - _pending_refreshed_at < PENDING_CACHE_REFRESH_SECONDS:
        return
    async with _cache_lock:
        now = time.monotonic()
        if not force and now - _pending_refreshed_at < PENDING_CACHE_REFRESH_SECONDS:
            return
        utc_now = datetime.utcnow()
        # The service queues precautionary cleanup for a grant that may have
        # applied before its acknowledgement was lost.
        await expire_active_commands(utc_now)
        async with async_session() as db:
            rows = (
                await db.execute(
                    select(RouterCommand.router_id)
                    .where(
                        RouterCommand.state.in_(ACTIVE_COMMAND_STATES),
                        or_(
                            RouterCommand.expires_at.is_(None),
                            RouterCommand.expires_at > utc_now,
                        ),
                    )
                    .distinct()
                )
            ).all()
        _pending_router_ids.clear()
        _pending_router_ids.update(row[0] for row in rows)
        _pending_refreshed_at = now


async def warm_router_agent_cache() -> None:
    """Warm tiny process caches after the startup migration created the table."""

    await _refresh_settings_if_due(force=True)
    await _refresh_router_cache_if_due(force=True)
    await _refresh_pending_cache_if_due(force=True)


def _presented_token(authorization: Optional[str]) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _next_poll_seconds(tunnel: str) -> int:
    if tunnel == "down":
        low = _setting_int("router_agent_degraded_min_seconds", 30, 20, 300)
        high = _setting_int("router_agent_degraded_max_seconds", 60, low, 600)
    else:
        low = _setting_int("router_agent_normal_min_seconds", 90, 30, 600)
        high = _setting_int("router_agent_normal_max_seconds", 150, low, 900)
    return random.randint(low, high)


def _poll_skip_count(next_poll_seconds: int) -> int:
    """Convert a server delay to fixed local scheduler ticks without polling early."""

    ticks = (
        max(1, int(next_poll_seconds)) + SCHEDULER_TICK_SECONDS - 1
    ) // SCHEDULER_TICK_SECONDS
    return max(0, ticks - 1)


def _poll_skip_directive(next_poll_seconds: int) -> str:
    return (
        ":global bitwavePollSkips\n"
        f":set bitwavePollSkips {_poll_skip_count(next_poll_seconds)}\n"
    )


async def _persist_heartbeat(router_id: int, tunnel: str, version: str) -> None:
    try:
        async with async_session() as db:
            await db.execute(
                update(Router)
                .where(Router.id == router_id)
                .values(
                    agent_last_seen_at=datetime.utcnow(),
                    agent_tunnel_state=tunnel,
                    agent_version=version[:AGENT_VERSION_MAX_LENGTH],
                )
            )
            await db.commit()
    except Exception as exc:
        logger.warning("[ROUTER-AGENT] Heartbeat persist failed for %s: %s", router_id, exc)


def _schedule_heartbeat(
    background_tasks: BackgroundTasks,
    router_id: int,
    tunnel: str,
    version: str,
) -> None:
    now = time.monotonic()
    last = _heartbeat_at.get(router_id)
    if last is not None and now - last < HEARTBEAT_PERSIST_SECONDS:
        return
    _heartbeat_at[router_id] = now
    background_tasks.add_task(_persist_heartbeat, router_id, tunnel, version)


def _response_base_url(request: Request) -> str:
    base = str(getattr(settings, "PROVISION_BASE_URL", "") or request.base_url).rstrip("/")
    if not _BASE_URL_RE.fullmatch(base):
        raise HTTPException(status_code=503, detail="Agent acknowledgement URL unavailable")
    return base


def _command_envelope(
    command: RouterCommand,
    identity: str,
    base_url: str,
    next_poll_seconds: int,
) -> str:
    token = derive_router_agent_token(identity)
    ack = f"{base_url}/api/router/agent/commands/{command.id}/ack?identity={identity}"
    action = command.action_script.rstrip()
    return f"""# BITWAVE-COMMAND {next_poll_seconds} {command.id}
{_poll_skip_directive(next_poll_seconds).rstrip()}
:local bitwaveCommandOk true
:do {{
{action}
}} on-error={{
    :set bitwaveCommandOk false
}}
:if ($bitwaveCommandOk) do={{
    :do {{
        /tool fetch url=\"{ack}&result=applied\" http-method=post http-data=\"\" \\
            http-header-field=\"Authorization: Bearer {token}\" output=none
    }} on-error={{ :log warning \"bitwave-agent: applied but acknowledgement deferred\" }}
}} else={{
    :do {{
        /tool fetch url=\"{ack}&result=failed\" http-method=post http-data=\"\" \\
            http-header-field=\"Authorization: Bearer {token}\" output=none
    }} on-error={{}}
    :log error \"bitwave-agent: command failed; server will retry\"
}}
"""


async def _enter_poll_slot() -> bool:
    global _active_polls
    async with _poll_counter_lock:
        if _active_polls >= MAX_CONCURRENT_POLLS:
            return False
        _active_polls += 1
        _metrics["active_poll_peak"] = max(_metrics["active_poll_peak"], _active_polls)
        return True


async def _leave_poll_slot() -> None:
    global _active_polls
    async with _poll_counter_lock:
        _active_polls = max(0, _active_polls - 1)


@router.get("/api/router/agent/poll", response_class=PlainTextResponse)
async def poll_router_agent(
    request: Request,
    background_tasks: BackgroundTasks,
    identity: str,
    tunnel: str = "unknown",
    version: str = "",
    authorization: Optional[str] = Header(default=None),
):
    started = time.monotonic()
    _metrics["polls_total"] += 1
    identity = identity.strip()
    if not _IDENTITY_RE.fullmatch(identity) or not verify_router_agent_token(
        identity, _presented_token(authorization)
    ):
        _metrics["polls_unauthorized"] += 1
        raise HTTPException(status_code=401, detail="Unauthorized")
    if tunnel not in {"up", "down", "unknown"}:
        tunnel = "unknown"

    now = time.monotonic()
    last = _last_poll_at.get(identity)
    if last is not None and now - last < MIN_SECONDS_BETWEEN_POLLS:
        _metrics["polls_rate_limited"] += 1
        retry_after = int(MIN_SECONDS_BETWEEN_POLLS - (now - last)) + 1
        raise HTTPException(
            status_code=429,
            detail="Too many polls",
            headers={"Retry-After": str(retry_after)},
        )

    if _pool_under_pressure():
        _metrics["polls_load_shed"] += 1
        raise HTTPException(
            status_code=503,
            detail="Busy, retry later",
            headers={"Retry-After": "120"},
        )
    if not await _enter_poll_slot():
        _metrics["polls_load_shed"] += 1
        raise HTTPException(
            status_code=503,
            detail="Agent concurrency limit reached",
            headers={"Retry-After": "60"},
        )

    try:
        await _refresh_settings_if_due()
        if not _setting_bool("router_agent_enabled"):
            raise HTTPException(
                status_code=503,
                detail="Router agent disabled",
                headers={"Retry-After": "300"},
            )
        await _refresh_router_cache_if_due()
        router_info = _router_cache.get(identity)
        if router_info is None or not router_info[1]:
            raise HTTPException(status_code=401, detail="Unauthorized")
        router_id = router_info[0]
        _last_poll_at[identity] = now
        _schedule_heartbeat(background_tasks, router_id, tunnel, version)

        await _refresh_pending_cache_if_due()
        command = None
        if router_id in _pending_router_ids:
            _metrics["polls_pending_cache_hits"] += 1
            command = await next_command_for_router(router_id)
            if command is None and not await has_active_commands(router_id):
                _pending_router_ids.discard(router_id)
        else:
            _metrics["polls_pending_cache_misses"] += 1

        # A queued/in-flight command means the direct path needs help even if
        # the simple tunnel probe happened to answer. Keep repair latency in
        # the 30-60 second band until the outbox is empty.
        next_seconds = _next_poll_seconds(
            "down" if tunnel == "down" or router_id in _pending_router_ids else tunnel
        )
        headers = {
            "Cache-Control": "no-store",
            "X-Next-Poll-Seconds": str(next_seconds),
        }
        if command is None:
            _metrics["polls_idle"] += 1
            return PlainTextResponse(
                f"# BITWAVE-IDLE {next_seconds}\n"
                f"{_poll_skip_directive(next_seconds)}",
                headers=headers,
            )
        _metrics["polls_command"] += 1
        return PlainTextResponse(
            _command_envelope(
                command,
                identity,
                _response_base_url(request),
                next_seconds,
            ),
            headers=headers,
        )
    finally:
        _poll_latency_ms.append((time.monotonic() - started) * 1000)
        await _leave_poll_slot()


@router.post("/api/router/agent/commands/{command_id}/ack")
async def ack_router_command(
    command_id: int,
    identity: str,
    result: str,
    authorization: Optional[str] = Header(default=None),
):
    identity = identity.strip()
    if not _IDENTITY_RE.fullmatch(identity) or not verify_router_agent_token(
        identity, _presented_token(authorization)
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if result not in {"applied", "failed"}:
        raise HTTPException(status_code=422, detail="Invalid acknowledgement result")

    await _refresh_router_cache_if_due()
    router_info = _router_cache.get(identity)
    if router_info is None or not router_info[1]:
        raise HTTPException(status_code=401, detail="Unauthorized")

    _metrics["acks_total"] += 1
    _metrics[f"acks_{result}"] += 1
    command, found = await acknowledge_command(
        router_id=router_info[0],
        command_id=command_id,
        applied=result == "applied",
    )
    if not found or command is None:
        raise HTTPException(status_code=404, detail="Command not found")
    if command.acknowledged_at and command.created_at:
        _ack_latency_seconds.append(
            max(0.0, (command.acknowledged_at - command.created_at).total_seconds())
        )
    if not await has_active_commands(router_info[0]):
        _pending_router_ids.discard(router_info[0])
    else:
        _pending_router_ids.add(router_info[0])
    return {
        "accepted": True,
        "command_id": command.id,
        "state": command.state,
    }

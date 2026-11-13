"""Admin "View as reseller": short-lived, read-only impersonation sessions.

An admin starts a session (POST /api/admin/impersonate/{reseller_id}) and gets
a token that authenticates as the reseller -- same claims as the reseller's own
login -- plus:

    imp_sid  ImpersonationSession.id
    imp_by   the admin's user id
    ro       true

Everything that makes the session safe is enforced here, server side, by the
``enforce_impersonation_read_only`` HTTP middleware:

* the session row must still be open and unexpired, or the request gets
  401 ``impersonation_ended`` (exit revokes the token before its exp);
* any method other than GET/HEAD/OPTIONS gets 403 ``impersonation_read_only``
  unless its path is on ``READ_ONLY_POST_ALLOWLIST`` (POSTs that only read);
* every impersonated request is logged with the session, admin and reseller.

The token's role is the reseller's, so admin-only endpoints reject it too.

DB discipline: the session check is one primary-key read in its own short
session, closed before the request handler runs, and cached in process for
``SESSION_CHECK_TTL_SECONDS`` (an ended session is cached for good).
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from sqlalchemy import select, update

from app.config import settings
from app.core.security import ALGORITHM
from app.db.models import ImpersonationSession

logger = logging.getLogger(__name__)

IMPERSONATION_TTL_MINUTES = 30
SESSION_CHECK_TTL_SECONDS = 30
REASON_MIN_LENGTH = 5
REASON_MAX_LENGTH = 300
USER_AGENT_MAX_LENGTH = 300

END_REASON_EXIT = "exit"
END_REASON_EXPIRED = "expired"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# POST endpoints the reseller dashboard uses purely to READ. Each handler was
# checked for side effects (DB writes, router writes, SMS) before it was added;
# anything that writes stays blocked.
#
# Deliberately NOT here:
#   /api/routers/{id}/load-balancing/preflight -- the router commands are
#       read-only, but the handler records router-availability telemetry (a DB
#       write) and holds the per-router lock while it talks to the live router.
#   /graphql -- not mounted in this app. Were it added, a POST could carry a
#       mutation, so it stays blocked like any other unlisted POST.
READ_ONLY_POST_ALLOWLIST = (
    re.compile(r"/api/impersonation/end"),
    re.compile(r"/api/customers/usage/bulk"),
    re.compile(r"/api/messaging/customer-events/preview"),
    re.compile(r"/api/compensation/outage/preview"),
)

# Let a View-as token reach the start endpoint so the caller gets that
# handler's own 403 "Already viewing as a reseller" -- the handler refuses any
# token carrying imp_sid before it does anything else.
_HANDLER_REFUSES_IMPERSONATION = (
    re.compile(r"/api/admin/impersonate/\d+"),
)

READ_ONLY_DETAIL = (
    "Read-only: you are viewing this reseller's dashboard. Changes are disabled."
)
ENDED_DETAIL = "View-as session ended"

# sid -> (ended, checked_at monotonic seconds)
_session_cache: dict[int, tuple[bool, float]] = {}
_CACHE_MAX_ENTRIES = 1000


def reset_cache() -> None:
    _session_cache.clear()


def mark_session_ended(sid: int) -> None:
    """Revoke ``sid`` in this process immediately (used by /end)."""
    _session_cache[int(sid)] = (True, time.monotonic())


def is_allowlisted(path: str) -> bool:
    return any(p.fullmatch(path) for p in READ_ONLY_POST_ALLOWLIST)


def _write_allowed(path: str) -> bool:
    return is_allowlisted(path) or any(
        p.fullmatch(path) for p in _HANDLER_REFUSES_IMPERSONATION
    )


def iso_utc(dt: datetime) -> str:
    """Naive-UTC datetime -> ISO 8601 with a trailing Z."""
    return dt.replace(tzinfo=None).isoformat() + "Z"


def client_ip(request: Request) -> Optional[str]:
    """Best-effort caller IP behind Cloudflare / the reverse proxy."""
    headers = request.headers
    ip = (
        headers.get("cf-connecting-ip")
        or (headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or headers.get("x-real-ip")
        or (request.client.host if request.client else None)
    )
    return ip[:64] if ip else None


def impersonation_claims(request: Request) -> Optional[dict]:
    """Decoded payload if the request carries a valid View-as token, else None.

    The signature is verified; ``exp`` is not, so an expired View-as token is
    still recognised and answered with ``impersonation_ended`` instead of a
    generic 401. Missing, malformed or ordinary tokens return None and are left
    to the normal auth dependencies.
    """
    auth = request.headers.get("authorization") or ""
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    try:
        payload = jwt.decode(
            token.strip(),
            settings.SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False},
        )
    except JWTError:
        return None
    if not isinstance(payload, dict) or payload.get("imp_sid") is None:
        return None
    try:
        payload["imp_sid"] = int(payload["imp_sid"])
    except (TypeError, ValueError):
        return None
    return payload


def _token_expired(payload: dict) -> bool:
    exp = payload.get("exp")
    try:
        return exp is None or float(exp) <= time.time()
    except (TypeError, ValueError):
        return True


async def _mark_expired_in_db(sid: int) -> None:
    """Best-effort: stamp an expired session as ended, in its own session."""
    from app.core.runtime_mode import shadow_mode_enabled
    from app.db import database as db_module

    if shadow_mode_enabled():
        return
    try:
        async with db_module.async_session() as s:
            await s.execute(
                update(ImpersonationSession)
                .where(
                    ImpersonationSession.id == sid,
                    ImpersonationSession.ended_at.is_(None),
                )
                .values(
                    ended_at=ImpersonationSession.expires_at,
                    end_reason=END_REASON_EXPIRED,
                )
            )
            await s.commit()
    except Exception as exc:  # audit tidy-up only; never fail the request on it
        logger.warning("[view-as sid=%s] could not mark expired: %s", sid, exc)


async def session_ended(sid: int) -> bool:
    """True when the session row is ended, expired or missing.

    One PK read in a short session that is closed before returning; cached for
    SESSION_CHECK_TTL_SECONDS, and forever once ended.
    """
    from app.db import database as db_module

    now_mono = time.monotonic()
    cached = _session_cache.get(sid)
    if cached is not None:
        ended, checked_at = cached
        if ended or now_mono - checked_at < SESSION_CHECK_TTL_SECONDS:
            return ended

    async with db_module.async_session() as s:
        row = (
            await s.execute(
                select(
                    ImpersonationSession.ended_at, ImpersonationSession.expires_at
                ).where(ImpersonationSession.id == sid)
            )
        ).first()

    ended = (
        row is None
        or row.ended_at is not None
        or row.expires_at <= datetime.utcnow()
    )
    if len(_session_cache) >= _CACHE_MAX_ENTRIES:
        _prune_cache(now_mono)
    _session_cache[sid] = (ended, now_mono)
    return ended


def _prune_cache(now_mono: float) -> None:
    stale = [
        sid for sid, (ended, checked_at) in _session_cache.items()
        if now_mono - checked_at >= SESSION_CHECK_TTL_SECONDS
    ]
    for sid in stale:
        _session_cache.pop(sid, None)
    if len(_session_cache) >= _CACHE_MAX_ENTRIES:
        _session_cache.clear()


def _log(payload: dict, method: str, path: str, status: int) -> None:
    logger.info(
        "[view-as sid=%s admin=%s reseller=%s] %s %s -> %s",
        payload.get("imp_sid"),
        payload.get("imp_by"),
        payload.get("user_id"),
        method,
        path,
        status,
    )


async def enforce_impersonation_read_only(request: Request, call_next):
    """HTTP middleware: keeps View-as tokens read-only and revocable."""
    payload = impersonation_claims(request)
    if payload is None:
        return await call_next(request)

    sid = payload["imp_sid"]
    method = request.method.upper()
    path = request.url.path

    if _token_expired(payload):
        if _session_cache.get(sid, (False, 0.0))[0] is False:
            await _mark_expired_in_db(sid)
            mark_session_ended(sid)
        _log(payload, method, path, 401)
        return JSONResponse(
            status_code=401,
            content={"detail": ENDED_DETAIL, "code": "impersonation_ended"},
        )

    try:
        ended = await session_ended(sid)
    except Exception as exc:
        logger.error("[view-as sid=%s] session check failed: %s", sid, exc)
        _log(payload, method, path, 503)
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Could not verify the View-as session. Try again.",
                "code": "impersonation_check_failed",
            },
        )
    if ended:
        _log(payload, method, path, 401)
        return JSONResponse(
            status_code=401,
            content={"detail": ENDED_DETAIL, "code": "impersonation_ended"},
        )

    if method not in SAFE_METHODS and not _write_allowed(path):
        _log(payload, method, path, 403)
        return JSONResponse(
            status_code=403,
            content={"detail": READ_ONLY_DETAIL, "code": "impersonation_read_only"},
        )

    response = await call_next(request)
    _log(payload, method, path, response.status_code)
    return response

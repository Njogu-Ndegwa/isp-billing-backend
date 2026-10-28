"""Staff sub-users: token claims, revocation, permission enforcement, activity log.

How a staff token works
-----------------------
A staff member logs in through the normal /api/auth/login. Their token carries
the OWNER's login claims (user_id, role "reseller", organization_name, ...) so
every existing endpoint keeps scoping data to the owner without a single change,
plus:

    staff_id    ResellerStaff.id
    stv         ResellerStaff.token_version at login
    staff_name  for logs

``enforce_staff_access`` (HTTP middleware, registered in main.py next to the
View-as guard) runs before routing on every request that carries a bearer token:

* staff token -> the staff row must exist, be active, not removed, belong to the
  token's owner, and have ``token_version == stv``, else 401
  ``staff_session_revoked``. Then the route must be allowed by the staff
  member's permissions (app/services/staff_permissions.py, deny by default),
  else 403 ``staff_permission_denied``. Every write -- allowed or refused -- is
  written to ``staff_activity_log``.
* owner/admin token -> ``tv`` (absent = 0) must equal ``users.token_version``,
  else 401 ``session_revoked``. A password change or reset bumps it. Owner
  writes that move money or change where it goes are logged too.
* payment-method / payout / settlement changes by anyone, and withdrawals by
  staff, raise an owner alert (inbox message + SMS when a phone is on file).

A staff token can never reach an admin endpoint: its role is the owner's
("reseller"), and no ``/api/admin/*`` route is in the staff map except the
reseller-facing router remote-access/WebFig ones.

Every request reads the session version from the database, so revocation is
immediate across workers. Browser WebFig sessions carry the same staff version.

DB discipline: the state checks are one primary-key read each, in their own
short session closed before the handler runs; activity rows and alerts are
written after the handler, in their own short sessions, and SMS sending happens
with no session held.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from sqlalchemy import select

from app.config import settings
from app.core.security import ALGORITHM
from app.services import staff_permissions as perms

logger = logging.getLogger(__name__)

# A fresh database read on each request makes revocation immediate across workers.
STATE_TTL_SECONDS = 0
OWNER_TV_TTL_SECONDS = 0
ALERT_SMS_COOLDOWN_SECONDS = 600
_CACHE_MAX_ENTRIES = 5000

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

DENIED_DETAIL = "You don't have permission to do this. Ask the account owner."
STAFF_REVOKED_DETAIL = (
    "Your access was changed by the account owner. Please sign in again."
)
OWNER_REVOKED_DETAIL = "Your session has ended. Please sign in again."


@dataclass(frozen=True)
class StaffContext:
    staff_id: int
    owner_id: int
    name: str
    permissions: frozenset


@dataclass(frozen=True)
class _StaffState:
    owner_id: int
    name: str
    is_active: bool
    deleted: bool
    token_version: int
    permissions: frozenset


_current_staff: contextvars.ContextVar[Optional[StaffContext]] = contextvars.ContextVar(
    "current_staff", default=None
)

# staff_id -> (state or None, checked_at monotonic)
_staff_cache: dict[int, tuple[Optional[_StaffState], float]] = {}
# user_id -> (token_version or None, checked_at monotonic)
_owner_tv_cache: dict[int, tuple[Optional[int], float]] = {}
# owner_id -> monotonic time of the last alert SMS
_last_alert_sms: dict[int, float] = {}
_background_tasks: set = set()


def reset_cache() -> None:
    _staff_cache.clear()
    _owner_tv_cache.clear()
    _last_alert_sms.clear()


def invalidate_staff(staff_id: int) -> None:
    _staff_cache.pop(int(staff_id), None)


def invalidate_owner(user_id: int) -> None:
    _owner_tv_cache.pop(int(user_id), None)


def current_staff() -> Optional[StaffContext]:
    """The staff member behind this request, or None for the owner/admin."""
    return _current_staff.get()


class StaffPermissionDenied(HTTPException):
    """Raised from inside a handler; main.py renders it like the middleware's 403."""

    def __init__(self, permission: Optional[str]):
        super().__init__(status_code=403, detail=DENIED_DETAIL)
        self.permission = permission


def staff_permission_denied_response(exc: "StaffPermissionDenied") -> JSONResponse:
    return _deny(403, "staff_permission_denied", DENIED_DETAIL, permission=exc.permission)


def require_permission(permission: str) -> None:
    """For handlers that need a finer check than the route map (e.g. one field)."""
    staff = current_staff()
    if staff is not None and permission not in staff.permissions:
        raise StaffPermissionDenied(permission)


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def staff_token_claims(staff, owner) -> dict:
    from app.api.auth_routes import login_token_claims

    claims = login_token_claims(owner)
    claims.pop("tv", None)  # staff sessions are revoked by stv, not the owner's tv
    claims.update({
        "staff_id": staff.id,
        "stv": int(staff.token_version or 0),
        "staff_name": staff.name,
    })
    return claims


def bearer_claims(request: Request) -> Optional[dict]:
    """Verified claims of the request's bearer token, or None.

    Missing, malformed and expired tokens return None and are left to the
    endpoint's own auth dependency, which answers with its usual 401.
    """
    auth = request.headers.get("authorization") or ""
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    try:
        payload = jwt.decode(token.strip(), settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    return payload if isinstance(payload, dict) else None


def _int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# State lookups (one PK read, own short session, cached)
# ---------------------------------------------------------------------------

def _prune(cache: dict, ttl: float, now_mono: float) -> None:
    if len(cache) < _CACHE_MAX_ENTRIES:
        return
    for key in [k for k, (_, at) in cache.items() if now_mono - at >= ttl]:
        cache.pop(key, None)
    if len(cache) >= _CACHE_MAX_ENTRIES:
        cache.clear()


async def _staff_state(staff_id: int) -> Optional[_StaffState]:
    from app.db import database as db_module
    from app.db.models import ResellerStaff, User, UserRole

    now_mono = time.monotonic()
    cached = _staff_cache.get(staff_id)
    if cached is not None and now_mono - cached[1] < STATE_TTL_SECONDS:
        return cached[0]

    async with db_module.async_session() as s:
        row = (await s.execute(
            select(
                ResellerStaff.parent_reseller_id,
                ResellerStaff.name,
                ResellerStaff.is_active,
                ResellerStaff.deleted_at,
                ResellerStaff.token_version,
                ResellerStaff.permissions,
            ).join(User, User.id == ResellerStaff.parent_reseller_id).where(
                ResellerStaff.id == staff_id, User.role == UserRole.RESELLER
            )
        )).first()

    state = None
    if row is not None:
        state = _StaffState(
            owner_id=row.parent_reseller_id,
            name=row.name,
            is_active=bool(row.is_active),
            deleted=row.deleted_at is not None,
            token_version=int(row.token_version or 0),
            permissions=frozenset(perms.clean_permissions(row.permissions or [])),
        )
    _prune(_staff_cache, STATE_TTL_SECONDS, now_mono)
    _staff_cache[staff_id] = (state, now_mono)
    return state


async def _owner_token_version(user_id: int) -> Optional[int]:
    from app.db import database as db_module
    from app.db.models import User

    now_mono = time.monotonic()
    cached = _owner_tv_cache.get(user_id)
    if cached is not None and now_mono - cached[1] < OWNER_TV_TTL_SECONDS:
        return cached[0]

    async with db_module.async_session() as s:
        tv = (await s.execute(
            select(User.token_version).where(User.id == user_id)
        )).scalar_one_or_none()

    value = int(tv) if tv is not None else None
    _prune(_owner_tv_cache, OWNER_TV_TTL_SECONDS, now_mono)
    _owner_tv_cache[user_id] = (value, now_mono)
    return value


# ---------------------------------------------------------------------------
# Activity log and owner alerts (after the handler, own sessions)
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> Optional[str]:
    from app.services.impersonation import client_ip

    return client_ip(request)


async def record_activity(
    *,
    owner_id: int,
    staff_id: Optional[int],
    actor_label: Optional[str],
    action: str,
    permission: Optional[str],
    method: str,
    path: str,
    status_code: Optional[int],
    summary: Optional[str],
    ip_address: Optional[str] = None,
) -> None:
    """Best-effort activity row; never fails the request."""
    from app.core.runtime_mode import shadow_mode_enabled
    from app.db import database as db_module
    from app.db.models import StaffActivityLog

    if shadow_mode_enabled():
        return
    try:
        async with db_module.async_session() as s:
            s.add(StaffActivityLog(
                owner_id=owner_id,
                staff_id=staff_id,
                actor_label=(actor_label or "")[:160] or None,
                action=action[:80],
                permission=permission,
                method=method[:10],
                path=path[:300],
                status_code=status_code,
                summary=(summary or "")[:300] or None,
                ip_address=ip_address,
                created_at=datetime.utcnow(),
            ))
            await s.commit()
    except Exception as exc:
        logger.warning("[staff] could not record activity for owner %s: %s", owner_id, exc)


def _alert_body(actor: str, summary: str) -> str:
    from app.core.local_time import to_local

    when = to_local(datetime.utcnow()).strftime("%d %b %H:%M")
    return (
        f"Bitwave security: {actor} - {summary} ({when}). "
        "If this was not expected, change your password and check Settings > Staff."
    )[:480]


async def alert_owner(owner_id: int, actor: str, summary: str) -> None:
    """Inbox message always; SMS to the owner's phone at most every 10 min."""
    from app.core.runtime_mode import shadow_mode_enabled
    from app.db import database as db_module
    from app.db.models import (
        MessagingSettings, ResellerInboxMessage, SmsMessage, SmsMessageKind,
        SmsMessageStatus, User, UserRole,
    )
    from app.services.messaging import count_segments, resolve_sender_id

    if shadow_mode_enabled():
        return
    body = _alert_body(actor, summary)
    sms_ids: list[int] = []
    sender_id = None
    try:
        async with db_module.async_session() as s:
            owner = await s.get(User, owner_id)
            if owner is None:
                return
            admin_id = (await s.execute(
                select(User.id).where(User.role == UserRole.ADMIN).order_by(User.id).limit(1)
            )).scalar_one_or_none()
            settings_row = await s.get(MessagingSettings, 1)
            messaging_enabled = bool(settings_row.enabled) if settings_row else True
            phone = (owner.support_phone or "").strip()
            now_mono = time.monotonic()
            send_sms = (
                bool(phone)
                and messaging_enabled
                and now_mono - _last_alert_sms.get(owner_id, -1e9) >= ALERT_SMS_COOLDOWN_SECONDS
            )
            if admin_id is not None:
                s.add(ResellerInboxMessage(
                    recipient_user_id=owner_id,
                    sender_user_id=admin_id,
                    subject="Account security alert",
                    body=body,
                    sent_sms=send_sms,
                ))
            if send_sms:
                segments = count_segments(body)
                row = SmsMessage(
                    user_id=owner_id,
                    recipient_phone=phone,
                    body=body,
                    segments=segments,
                    credits_charged=segments,
                    kind=SmsMessageKind.ADMIN_TO_RESELLER,
                    category="account_security",
                    status=SmsMessageStatus.QUEUED,
                )
                s.add(row)
                await s.flush()
                sms_ids.append(row.id)
                _last_alert_sms[owner_id] = now_mono
            sender_id = resolve_sender_id(
                settings_row.sender_id if settings_row and settings_row.sender_id else None
            )
            await s.commit()
    except Exception as exc:
        logger.warning("[staff] could not raise owner alert for %s: %s", owner_id, exc)
        return

    if sms_ids:
        from app.services import sms_dispatch

        task = asyncio.create_task(sms_dispatch.dispatch_admin_sms_messages(sms_ids, sender_id))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

def _deny(status: int, code: str, detail: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail, "code": code, **extra})


async def _after_write(
    request: Request,
    *,
    owner_id: int,
    staff_id: Optional[int],
    actor: str,
    rule: Optional[perms.Rule],
    params: dict,
    method: str,
    path: str,
    status_code: int,
) -> None:
    summary = perms.summarize(rule, params, method, path)
    action = rule.template if rule is not None else "unmapped"
    await record_activity(
        owner_id=owner_id,
        staff_id=staff_id,
        actor_label=actor,
        action=f"{method} {action}",
        permission=rule.permission_label if rule is not None else None,
        method=method,
        path=path,
        status_code=status_code,
        summary=summary,
        ip_address=_client_ip(request),
    )
    if status_code >= 400 or rule is None:
        return
    if rule.template in perms.OWNER_ALERT_TEMPLATES or (
        staff_id is not None and rule.template == "/api/reseller/withdraw"
    ):
        await alert_owner(owner_id, actor, summary)


async def enforce_staff_access(request: Request, call_next):
    """HTTP middleware: staff permissions + session revocation for every token."""
    claims = bearer_claims(request)
    if claims is None or claims.get("imp_sid") is not None:
        # No/invalid token: the endpoint answers. View-as: its own guard owns it.
        return await call_next(request)

    method = request.method.upper()
    path = perms.normalize_path(request.url.path)
    if method == "OPTIONS":
        return await call_next(request)

    if claims.get("staff_id") is not None:
        return await _enforce_staff(request, call_next, claims, method, path)

    # ---- owner / admin token ------------------------------------------------
    user_id = _int(claims.get("user_id"))
    if user_id is not None:
        try:
            current_tv = await _owner_token_version(user_id)
        except Exception as exc:
            logger.warning("[staff] token-version check failed for user %s: %s", user_id, exc)
            return _deny(503, "session_check_failed", "Could not verify your access. Try again.")
        if current_tv is None or (_int(claims.get("tv")) or 0) != current_tv:
            return _deny(401, "session_revoked", OWNER_REVOKED_DETAIL)

    if method not in WRITE_METHODS or claims.get("role") != "reseller" or user_id is None:
        return await call_next(request)
    rule, params = perms.match_rule(method, path)
    if rule is None or rule.template not in perms.OWNER_LOGGED_TEMPLATES:
        return await call_next(request)

    response = await call_next(request)
    await _after_write(
        request,
        owner_id=user_id,
        staff_id=None,
        actor="Account owner",
        rule=rule,
        params=params,
        method=method,
        path=path,
        status_code=response.status_code,
    )
    return response


async def _enforce_staff(request: Request, call_next, claims: dict, method: str, path: str):
    staff_id = _int(claims.get("staff_id"))
    owner_id = _int(claims.get("user_id"))
    if staff_id is None or owner_id is None or claims.get("role") != "reseller":
        return _deny(401, "staff_session_revoked", STAFF_REVOKED_DETAIL)

    try:
        state = await _staff_state(staff_id)
    except Exception as exc:
        logger.error("[staff %s] state check failed: %s", staff_id, exc)
        return _deny(503, "staff_check_failed", "Could not verify your access. Try again.")

    if (
        state is None
        or state.deleted
        or not state.is_active
        or state.owner_id != owner_id
        or state.token_version != (_int(claims.get("stv")) or 0)
    ):
        return _deny(401, "staff_session_revoked", STAFF_REVOKED_DETAIL)

    if perms.is_public(path):
        return await call_next(request)

    actor = f"{state.name} (staff)"
    rule, params = perms.match_rule(method, path)
    if rule is None or not rule.allows(state.permissions):
        needed = rule.permission_label if rule is not None else None
        logger.info("[staff %s owner=%s] denied %s %s (needs %s)",
                    staff_id, owner_id, method, path, needed or "owner")
        if method in WRITE_METHODS:
            await _after_write(
                request, owner_id=owner_id, staff_id=staff_id, actor=actor, rule=rule,
                params=params, method=method, path=path, status_code=403,
            )
        if needed is None and path.startswith("/api/staff"):
            needed = perms.STAFF_MANAGE
        return _deny(403, "staff_permission_denied", DENIED_DETAIL, permission=needed)

    token = _current_staff.set(StaffContext(
        staff_id=staff_id, owner_id=owner_id, name=state.name, permissions=state.permissions,
    ))
    try:
        response = await call_next(request)
    finally:
        _current_staff.reset(token)

    if method in WRITE_METHODS:
        await _after_write(
            request, owner_id=owner_id, staff_id=staff_id, actor=actor, rule=rule,
            params=params, method=method, path=path, status_code=response.status_code,
        )
    return response


def token_expiry() -> timedelta:
    return timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)


async def webfig_staff_session_valid(session) -> bool:
    """Proxy cookies must stop working when the staff JWT stops working."""
    try:
        state = await _staff_state(session.staff_id)
    except Exception:
        return False
    return bool(
        state is not None and not state.deleted and state.is_active
        and state.owner_id == session.created_by_user_id
        and state.token_version == session.staff_token_version
        and "routers.manage" in state.permissions
    )

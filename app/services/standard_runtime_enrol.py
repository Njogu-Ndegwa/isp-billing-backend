"""Automatic install of the standard router runtime.

Every router we manage should end up with the same runtime, without anyone
running a script by hand (Dennis, 2026-09-27):

* the check-in delivery applier (``checkin_applier_script``; race mode on the
  server, ``checkin_delivery``), EXCEPT on hAP lite / smips boards: HTTPS
  check-in cost them ~+40 CPU points (Powernet #3, router 483, 2026-09-26).
  Also not on RADIUS routers (no bypass bindings to deliver), and only when
  the check-in channel is live and enrols the router (``CHECKIN_ROUTER_IDS``
  or ``"all"``), so the installer never puts an applier where the server
  would only answer idle frames;
* the management-tunnel watchdog (``mgmt_watchdog_script``), SSTP or
  WireGuard depending on what the router actually has;
* NOT the command agent: ``router_agent_enabled`` stays false and is never
  touched here.

Same shape as the expiry-reaper enrolment (``expiry_reaper_enrol``): a
background job, off by default (``settings.STANDARD_RUNTIME_AUTO_INSTALL``),
at most ``STANDARD_RUNTIME_BATCH`` routers per run, never-looked-at routers
first. What happened is recorded per router and per component
(``routers.checkin_*`` / ``routers.mgmt_watchdog_*``), so:

* installed components are never looked at again, except a check-in applier
  whose reports carry an older ``v=`` than the server's template: it is
  re-installed (``checkin_delivery.outdated_applier_router_ids``);
* hardware/setup reasons (small board, no watched tunnel, a scheduler someone
  disabled on purpose) are looked at again after a week;
* passing conditions (unreachable, busy, an API error) after 30 minutes, so a
  new router whose tunnel was not up yet, or a router that was offline, is
  picked up again soon.

Guards: nothing runs while the DB pool is busy; routers of suspended owners
and routers currently marked offline are skipped; a busy router (CPU >= 90%)
is left alone and retried; the identity must match before anything is
written.

DB discipline (AGENTS.md): candidates are read in one short session that is
closed before any RouterOS I/O; each router's result is written afterwards in
its own short session.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, update

from app.config import settings
from app.db import database
from app.db.models import Router, RouterAuthMethod, SubscriptionStatus, User
from app.services import checkin_delivery
from app.services.checkin_applier_script import install_checkin_applier
from app.services.expiry_reaper_enrol import routeros_version_ok
from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI
from app.services.mgmt_watchdog_script import detect_kind, install_watchdog

logger = logging.getLogger(__name__)

BUSY_CPU_PERCENT = 90
RECHECK_PERMANENT = timedelta(days=7)
RECHECK_TRANSIENT = timedelta(minutes=30)
# Reasons that describe the hardware or a deliberate setup, not a passing condition.
_PERMANENT_REASON_PREFIXES = (
    "small board", "RouterOS", "no hotspot", "no watched tunnel", "scheduler disabled",
    # RouterOS device-mode "flagged": every scheduler add is refused until someone
    # clears it on site (router 131, 2026-09-27/28). Retrying every 30 min only
    # adds API traffic to a router that is already in trouble.
    "scheduler_failed: failure: configuration flagged",
)
_OK_STATUSES = ("installed", "updated", "unchanged")


def is_small_board(board_name: Optional[str], architecture: Optional[str]) -> bool:
    """hAP lite class: board name contains "lite", or the smips architecture.

    Deliberately broad (it also matches e.g. "hAP ac lite"): Dennis's rule for
    the check-in is "no HTTPS check-in on anything lite or smips".
    """
    return "lite" in str(board_name or "").lower() or str(architecture or "").strip().lower() == "smips"


def recheck_after(reason: Optional[str]) -> timedelta:
    if reason and reason.startswith(_PERMANENT_REASON_PREFIXES):
        return RECHECK_PERMANENT
    return RECHECK_TRANSIENT


def _due(checked_at: Optional[datetime], reason: Optional[str], now: datetime) -> bool:
    return checked_at is None or now - checked_at >= recheck_after(reason)


def _parse_ids(raw) -> frozenset[int]:
    return frozenset(int(p.strip()) for p in str(raw or "").split(",") if p.strip().isdigit())


def in_scope(router_id: int) -> bool:
    """STANDARD_RUNTIME_MIN_ROUTER_ID / _EXTRA_ / _EXCLUDE_ROUTER_IDS."""
    if router_id in _parse_ids(settings.STANDARD_RUNTIME_EXCLUDE_ROUTER_IDS):
        return False
    if router_id in _parse_ids(settings.STANDARD_RUNTIME_EXTRA_ROUTER_IDS):
        return True
    try:
        floor = int(settings.STANDARD_RUNTIME_MIN_ROUTER_ID or 0)
    except (TypeError, ValueError):
        return False
    return router_id >= floor


def checkin_wanted(router_id: int) -> bool:
    """The server side would actually answer this router's check-ins."""
    return (
        bool(settings.STANDARD_RUNTIME_INSTALL_CHECKIN)
        and checkin_delivery.checkin_active()
        and checkin_delivery.checkin_router_enrolled(router_id)
    )


@dataclass
class Candidate:
    id: int
    name: str
    identity: str
    ip_address: str
    username: str
    password: str
    port: int
    want_checkin: bool
    want_watchdog: bool


@dataclass
class Component:
    installed: bool
    reason: str
    kind: Optional[str] = None     # watchdog only: sstp / wg


@dataclass
class Outcome:
    router_id: int
    checkin: Optional[Component] = None
    watchdog: Optional[Component] = None
    board: str = ""


# ---------------------------------------------------------------------------
# DB: candidates and results (short sessions only)
# ---------------------------------------------------------------------------

async def load_candidates(now: datetime, limit: int) -> list[Candidate]:
    """In-scope routers with at least one component still to install and due."""
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.name, Router.identity, Router.ip_address, Router.username,
                   Router.password, Router.port, Router.auth_method, Router.last_status,
                   Router.checkin_installed_at, Router.checkin_install_reason, Router.checkin_checked_at,
                   Router.mgmt_watchdog_installed_at, Router.mgmt_watchdog_reason,
                   Router.mgmt_watchdog_checked_at, User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
            .where(Router.identity.isnot(None), Router.ip_address.isnot(None))
            .order_by(Router.id)
        )).all()
        await db.commit()

    outdated = checkin_delivery.outdated_applier_router_ids()
    picked: list[tuple[tuple, Candidate]] = []
    for r in rows:
        if not in_scope(r.id):
            continue
        owner = getattr(r.subscription_status, "value", r.subscription_status)
        if owner is not None and owner not in (SubscriptionStatus.ACTIVE.value, SubscriptionStatus.TRIAL.value):
            continue
        if r.last_status is False:
            continue
        want_checkin = (
            # Missing, or installed but reporting an older applier version
            # (the installer rewrites the script in place).
            (r.checkin_installed_at is None or r.id in outdated)
            and r.auth_method != RouterAuthMethod.RADIUS
            and checkin_wanted(r.id)
            and _due(r.checkin_checked_at, r.checkin_install_reason, now)
        )
        want_watchdog = (
            bool(settings.STANDARD_RUNTIME_INSTALL_WATCHDOG)
            and r.mgmt_watchdog_installed_at is None
            and _due(r.mgmt_watchdog_checked_at, r.mgmt_watchdog_reason, now)
        )
        if not (want_checkin or want_watchdog):
            continue
        checked = [c for c, want in ((r.checkin_checked_at, want_checkin),
                                     (r.mgmt_watchdog_checked_at, want_watchdog)) if want]
        never = any(c is None for c in checked)
        oldest = min((c for c in checked if c is not None), default=datetime.min)
        picked.append(((not never, oldest, r.id), Candidate(
            r.id, r.name, r.identity, r.ip_address, r.username, r.password,
            int(r.port or 8728), want_checkin, want_watchdog,
        )))
    picked.sort(key=lambda p: p[0])
    return [c for _, c in picked[:max(0, int(limit))]]


async def record_outcome(outcome: Outcome, now: datetime) -> None:
    values: dict = {}
    if outcome.checkin is not None:
        values["checkin_install_reason"] = outcome.checkin.reason[:120]
        values["checkin_checked_at"] = now
        if outcome.checkin.installed:
            values["checkin_installed_at"] = now
    if outcome.watchdog is not None:
        values["mgmt_watchdog_reason"] = outcome.watchdog.reason[:120]
        values["mgmt_watchdog_checked_at"] = now
        if outcome.watchdog.kind:
            values["mgmt_watchdog_kind"] = outcome.watchdog.kind
        if outcome.watchdog.installed:
            values["mgmt_watchdog_installed_at"] = now
    if not values:
        return
    async with database.async_session() as db:
        await db.execute(update(Router).where(Router.id == outcome.router_id).values(**values))
        await db.commit()


# ---------------------------------------------------------------------------
# RouterOS side (sync; run in a worker thread with no DB session open)
# ---------------------------------------------------------------------------

def _first(api, path: str) -> dict:
    data = (api.send_command(path) or {}).get("data") or []
    return data[0] if data else {}


def _both(c: Candidate, reason: str) -> Outcome:
    """The same (not installed) reason for every component this run wanted."""
    return Outcome(
        c.id,
        checkin=Component(False, reason) if c.want_checkin else None,
        watchdog=Component(False, reason) if c.want_watchdog else None,
    )


def _watchdog_sync(api, c: Candidate, version: str) -> Component:
    kind, why = detect_kind(api, version)
    if kind is None:
        return Component(False, f"no watched tunnel: {why}")
    res = install_watchdog(api, kind, c.ip_address)
    if res.ok:
        return Component(True, f"installed ({kind}, {res.status})", kind)
    if res.status == "scheduler_disabled":
        return Component(False, f"scheduler disabled on router ({kind}), left alone", kind)
    return Component(False, f"{res.status}: {res.error}", kind)


def _checkin_sync(api, c: Candidate, identity: str, board: str, arch: str, version: str) -> Component:
    if is_small_board(board, arch):
        return Component(False, f"small board {board or arch} (HTTPS check-in too costly)")
    if not routeros_version_ok(version):
        return Component(False, f"RouterOS {version or '?'} too old for the applier")
    if (api.send_command("/ip/hotspot/ip-binding/print") or {}).get("error"):
        return Component(False, "no hotspot ip-binding table")
    res = install_checkin_applier(api, identity=identity, endpoint_url=settings.CHECKIN_ENDPOINT_URL)
    status = res.get("status")
    if status in _OK_STATUSES:
        return Component(True, f"installed ({status})")
    if status == "scheduler_disabled":
        return Component(False, "scheduler disabled on router, left alone")
    return Component(False, f"{status}: {res.get('error') or ''}")


def probe_and_install_sync(c: Candidate, api_factory=None) -> Outcome:
    """One router: checks, then whatever components it still needs."""
    factory = api_factory or MikroTikAPI
    api = factory(c.ip_address, c.username, c.password, c.port,
                  timeout=60, connect_timeout=6, lane=LANE_BACKGROUND)
    if not api.connect():
        return _both(c, "unreachable")
    try:
        ident = _first(api, "/system/identity/print").get("name")
        if ident != c.identity:
            return _both(c, f"identity mismatch: router says {ident}")
        res = _first(api, "/system/resource/print")
        board = res.get("board-name") or ""
        arch = res.get("architecture-name") or ""
        version = str(res.get("version") or "")
        try:
            busy = int(res.get("cpu-load")) >= BUSY_CPU_PERCENT
        except (TypeError, ValueError):
            busy = False
        if busy:
            return _both(c, f"busy: CPU {res.get('cpu-load')}%")

        out = Outcome(c.id, board=board or arch)
        # Watchdog first: cheap, and it is what keeps the router reachable.
        if c.want_watchdog:
            try:
                out.watchdog = _watchdog_sync(api, c, version)
            except Exception as exc:  # noqa: BLE001 - one component must not block the other
                out.watchdog = Component(False, f"error: {exc}"[:120])
        if c.want_checkin:
            try:
                out.checkin = _checkin_sync(api, c, ident, board, arch, version)
            except Exception as exc:  # noqa: BLE001
                out.checkin = Component(False, f"error: {exc}"[:120])
        return out
    finally:
        try:
            api.disconnect()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------

_running = False


def _describe(o: Outcome) -> str:
    parts = []
    if o.watchdog is not None:
        parts.append(f"watchdog={'ok' if o.watchdog.installed else '-'} ({o.watchdog.reason})")
    if o.checkin is not None:
        parts.append(f"checkin={'ok' if o.checkin.installed else '-'} ({o.checkin.reason})")
    return f"{o.router_id}: " + ", ".join(parts)


async def standard_runtime_enrol_background(*, now: Optional[datetime] = None) -> list[Outcome]:
    global _running
    if not settings.STANDARD_RUNTIME_AUTO_INSTALL or _running:
        return []
    from app.services.mikrotik_background import _background_db_pool_is_busy

    if _background_db_pool_is_busy("STD-RUNTIME"):
        return []
    _running = True
    started = time.monotonic()
    try:
        now = now or datetime.utcnow()
        candidates = await load_candidates(now, settings.STANDARD_RUNTIME_BATCH)
        outcomes: list[Outcome] = []
        for c in candidates:
            try:
                outcome = await asyncio.to_thread(probe_and_install_sync, c)
            except Exception as exc:  # noqa: BLE001
                outcome = _both(c, f"error: {exc}"[:120])
            await record_outcome(outcome, now)
            outcomes.append(outcome)
        if outcomes:
            logger.info("[STD-RUNTIME] %d router(s) in %.0fs: %s", len(outcomes),
                        time.monotonic() - started, "; ".join(_describe(o) for o in outcomes))
        return outcomes
    finally:
        _running = False


# ---------------------------------------------------------------------------
# Right after registration (the provisioning /complete callback)
# ---------------------------------------------------------------------------
#
# A new router should not wait for the next job tick (15 min, reset by every
# app restart) to get the check-in and the watchdog. /complete fires at the
# END of the router's setup script, when its management tunnel may still be
# coming up (and route-sync needs up to ~30 s to route it), so this waits a
# little and retries on a short schedule. Whatever is still missing after
# that is left to the background job, which keeps running as the safety net.

SETUP_FIRST_DELAY_SECONDS = 20
SETUP_RETRY_DELAYS_SECONDS = (40, 120, 300, 600)
# At setup, a tunnel that is not up YET is a passing condition, not a
# permanent one (the background job treats "no watched tunnel" as permanent).
_SETUP_RETRYABLE_PREFIXES = ("unreachable", "busy", "no watched tunnel", "error")

_setup_tasks: set = set()


async def _load_setup_candidate(router_id: int) -> Optional[Candidate]:
    """The router as a candidate for an immediate install, or None if it is
    out of scope, its owner is not active/trial, or it is gone. Short session."""
    async with database.async_session() as db:
        row = (await db.execute(
            select(Router.id, Router.name, Router.identity, Router.ip_address, Router.username,
                   Router.password, Router.port, Router.auth_method,
                   Router.checkin_installed_at, Router.mgmt_watchdog_installed_at,
                   User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
            .where(Router.id == router_id)
        )).first()
        await db.commit()
    if row is None or not row.identity or not row.ip_address or not in_scope(row.id):
        return None
    owner = getattr(row.subscription_status, "value", row.subscription_status)
    if owner is not None and owner not in (SubscriptionStatus.ACTIVE.value, SubscriptionStatus.TRIAL.value):
        return None
    want_checkin = (
        row.checkin_installed_at is None
        and row.auth_method != RouterAuthMethod.RADIUS
        and checkin_wanted(row.id)
    )
    want_watchdog = bool(settings.STANDARD_RUNTIME_INSTALL_WATCHDOG) and row.mgmt_watchdog_installed_at is None
    return Candidate(row.id, row.name, row.identity, row.ip_address, row.username, row.password,
                     int(row.port or 8728), want_checkin, want_watchdog)


def _setup_retryable(o: Outcome) -> bool:
    return any(
        comp is not None and not comp.installed and comp.reason.startswith(_SETUP_RETRYABLE_PREFIXES)
        for comp in (o.watchdog, o.checkin)
    )


async def install_after_registration(router_id: int, *, sleep=asyncio.sleep,
                                     install=probe_and_install_sync) -> Optional[Outcome]:
    """Install the standard runtime on a just-registered router. Never raises."""
    if not settings.STANDARD_RUNTIME_AUTO_INSTALL:
        return None
    outcome: Optional[Outcome] = None
    try:
        await sleep(SETUP_FIRST_DELAY_SECONDS)
        for delay in (0,) + SETUP_RETRY_DELAYS_SECONDS:
            if delay:
                await sleep(delay)
            c = await _load_setup_candidate(router_id)            # short session, released
            if c is None or not (c.want_checkin or c.want_watchdog):
                break
            outcome = await asyncio.to_thread(install, c)          # router I/O, no session held
            await record_outcome(outcome, datetime.utcnow())       # own short session
            if not _setup_retryable(outcome):
                break
        if outcome is not None:
            logger.info("[STD-RUNTIME] at registration: %s", _describe(outcome))
    except Exception:  # noqa: BLE001 - the /complete callback must never be affected
        logger.exception("[STD-RUNTIME] install at registration for router %s failed", router_id)
    return outcome


def schedule_install_after_registration(router_id: int) -> None:
    """Fire-and-forget from the provisioning /complete callback. Never raises."""
    try:
        task = asyncio.get_running_loop().create_task(install_after_registration(router_id))
        _setup_tasks.add(task)
        task.add_done_callback(_setup_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[STD-RUNTIME] could not schedule the install for router %s", router_id)

"""Automatic enrolment of routers onto the router-side expiry reaper.

Decides, per router, who removes its expired hotspot customers:

* ``router`` - the router itself (the reaper script, app/services/expiry_reaper_script.py)
* ``server`` - the server cleanup job only

and records the decision (``routers.expiry_reaper_mode`` / ``_reason`` /
``_checked_at``) so the admin can see why, and so small boards are not probed
again every run.

hAP lite class boards (hAP lite / RB941, hAP mini, RB931: 32 MB, smips) are
``server`` by design: on 2026-09-26 routers 371 and 483 sat at 100% CPU with
5-7 MB free under the stack of Bitwave schedulers, and the reaper was removed
from all of them. Every other board gets the reaper when it is reachable, its
owner is paying (active/trial), it is not a RADIUS router and it is not busy.

Off by default (``settings.EXPIRY_REAPER_AUTO_ENROL``). One run handles at most
``EXPIRY_REAPER_ENROL_BATCH`` routers, so new routers and routers that were
offline are picked up gradually.

DB discipline (AGENTS.md): candidates and their paid customers are read in one
short session that is closed before any RouterOS I/O; each router's result is
written afterwards in its own short session.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, select, update

from app.config import settings
from app.db import database
from app.db.models import (
    Customer, CustomerStatus, Router, RouterAuthMethod, SubscriptionStatus, User,
)
from app.services.expiry_reaper_script import (
    COMMENT, POLICY, SCHEDULER_NAME, SCRIPT_NAME, render_expiry_reaper_script, script_source,
)
from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI
from app.services.router_expiry import expiry_second, normalize_mac, with_exp_tag

logger = logging.getLogger(__name__)

MODE_ROUTER = "router"
MODE_SERVER = "server"

# Board names / RouterBOARD models that stay on server-side removal.
SMALL_BOARD_MARKERS = ("hap lite", "rb941", "hap mini", "rb931")
# Older 64 MB boards: fine with the reaper over the tunnel, but not when every
# call would go over public HTTPS (5-7 s of full CPU on smips/mipsbe).
TUNNEL_REQUIRED_MARKERS = ("rb951", "rb750", "rb9", "hex lite", "map")
BUSY_CPU_PERCENT = 90
NTP_SERVER = "162.159.200.1"
TUNNEL_SERVER_IP = "10.251.0.1"
# How long a "server" decision stands before the router is looked at again.
RECHECK_SMALL_BOARD = timedelta(days=7)
RECHECK_TRANSIENT = timedelta(hours=2)
# The script's first scheduled run happens within a minute of install.
VERIFY_WAIT_SECONDS = 75

# Reasons that describe the hardware or setup, not a passing condition.
_PERMANENT_REASON_PREFIXES = ("small board", "RADIUS")


def classify_board(board_name: str | None, model: str | None) -> str:
    """``server`` for the hAP lite class, else ``router``."""
    text_ = f"{board_name or ''} {model or ''}".lower()
    return MODE_SERVER if any(m in text_ for m in SMALL_BOARD_MARKERS) else MODE_ROUTER


def needs_tunnel(board_name: str | None, model: str | None) -> bool:
    text_ = f"{board_name or ''} {model or ''}".lower()
    return any(m in text_ for m in TUNNEL_REQUIRED_MARKERS)


def routeros_version_ok(version: str) -> bool:
    """6.43+ (``/tool fetch ... output=user as-value``) or any 7.x."""
    try:
        major, minor = (int(x) for x in str(version).split(" ")[0].split(".")[:2])
    except ValueError:
        return False
    return major >= 7 or (major == 6 and minor >= 43)


def recheck_after(reason: str | None) -> timedelta:
    if reason and reason.startswith(_PERMANENT_REASON_PREFIXES):
        return RECHECK_SMALL_BOARD
    return RECHECK_TRANSIENT


@dataclass
class Candidate:
    id: int
    name: str
    identity: str
    ip_address: str
    username: str
    password: str
    port: int
    paid: dict[str, datetime] = field(default_factory=dict)


@dataclass
class Outcome:
    router_id: int
    mode: Optional[str]          # router / server / None (undecided: try again later)
    reason: str
    installed: bool = False
    board: str = ""


# ---------------------------------------------------------------------------
# DB: candidates and results (short sessions only)
# ---------------------------------------------------------------------------

async def load_candidates(now: datetime, limit: int) -> list[Candidate]:
    """Routers not on the reaper, eligible to be looked at now, plus the
    paid-up hotspot customers whose bindings get tagged at install."""
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.name, Router.identity, Router.ip_address, Router.username,
                   Router.password, Router.port, Router.auth_method, Router.last_status,
                   Router.expiry_reaper_reason, Router.expiry_reaper_checked_at,
                   User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
            .where(Router.expiry_reaper_enabled.is_(False),
                   Router.identity.isnot(None), Router.ip_address.isnot(None))
            .order_by(Router.expiry_reaper_checked_at.is_(None).desc(),
                      Router.expiry_reaper_checked_at, Router.id)
        )).all()
        picked = []
        for r in rows:
            if r.auth_method == RouterAuthMethod.RADIUS:
                continue
            owner = getattr(r.subscription_status, "value", r.subscription_status)
            if owner is not None and owner not in (SubscriptionStatus.ACTIVE.value, SubscriptionStatus.TRIAL.value):
                continue
            if r.last_status is False:
                continue
            checked = r.expiry_reaper_checked_at
            if checked is not None and now - checked < recheck_after(r.expiry_reaper_reason):
                continue
            picked.append(r)
            if len(picked) >= limit:
                break
        paid_rows = []
        if picked:
            paid_rows = (await db.execute(
                select(Customer.router_id, Customer.mac_address, func.max(Customer.expiry))
                .where(Customer.router_id.in_([r.id for r in picked]),
                       Customer.status == CustomerStatus.ACTIVE,
                       Customer.expiry > now,
                       Customer.mac_address.isnot(None),
                       Customer.pppoe_username.is_(None))
                .group_by(Customer.router_id, Customer.mac_address)
            )).all()
        await db.commit()
    by_router: dict[int, dict[str, datetime]] = {}
    for router_id, mac_raw, expiry in paid_rows:
        mac = normalize_mac(mac_raw or "")
        if mac:
            current = by_router.setdefault(router_id, {}).get(mac)
            if current is None or expiry > current:
                by_router[router_id][mac] = expiry
    return [
        Candidate(r.id, r.name, r.identity, r.ip_address, r.username, r.password,
                  int(r.port or 8728), by_router.get(r.id, {}))
        for r in picked
    ]


async def record_outcome(outcome: Outcome, now: datetime) -> None:
    values = {
        "expiry_reaper_mode": outcome.mode,
        "expiry_reaper_reason": outcome.reason[:120],
        "expiry_reaper_checked_at": now,
    }
    if outcome.installed:
        values["expiry_reaper_enabled"] = True
        values["expiry_reaper_installed_at"] = now
    async with database.async_session() as db:
        await db.execute(update(Router).where(Router.id == outcome.router_id).values(**values))
        await db.commit()


# ---------------------------------------------------------------------------
# RouterOS side (sync; run in a worker thread with no DB session open)
# ---------------------------------------------------------------------------

def _first(api, path: str) -> dict:
    data = api.send_command(path).get("data") or []
    return data[0] if data else {}


def _ensure_ntp(api, version: str) -> None:
    ntp = _first(api, "/system/ntp/client/print")
    if ntp.get("enabled") == "true":
        return
    args = {"enabled": "yes"}
    if version.startswith("6."):
        if ntp.get("primary-ntp") in (None, "", "0.0.0.0"):
            args["primary-ntp"] = NTP_SERVER
    elif not ntp.get("servers"):
        args["servers"] = NTP_SERVER
    api.send_command("/system/ntp/client/set", args)


def _tag_bindings(api, paid: dict[str, datetime]) -> int:
    changed = 0
    for b in api.send_command("/ip/hotspot/ip-binding/print").get("data") or []:
        mac = normalize_mac(b.get("mac-address", ""))
        if not mac or mac not in paid:
            continue
        comment = b.get("comment", "")
        new = with_exp_tag(comment, expiry_second(paid[mac]))
        if new != comment:
            api.send_command("/ip/hotspot/ip-binding/set", {".id": b[".id"], "comment": new})
            changed += 1
    return changed


def _remove_reaper(api) -> None:
    for path, name in (("/system/scheduler", SCHEDULER_NAME), ("/system/script", SCRIPT_NAME)):
        for item in api.send_command(f"{path}/print").get("data") or []:
            if item.get("name") == name:
                api.send_command(f"{path}/remove", {".id": item[".id"]})
    for env in api.send_command("/system/script/environment/print").get("data") or []:
        if str(env.get("name", "")).startswith("bwExp"):
            api.send_command("/system/script/environment/remove", {".id": env[".id"]})


def _api(c: Candidate, timeout: int = 60):
    return MikroTikAPI(c.ip_address, c.username, c.password, c.port,
                       timeout=timeout, connect_timeout=6, lane=LANE_BACKGROUND)


def probe_and_install_sync(c: Candidate) -> Outcome:
    """Classify the router and, when it qualifies, install the reaper."""
    api = _api(c)
    if not api.connect():
        return Outcome(c.id, None, "unreachable")
    try:
        ident = _first(api, "/system/identity/print").get("name")
        if ident != c.identity:
            return Outcome(c.id, None, f"identity mismatch: router says {ident}")
        res = _first(api, "/system/resource/print")
        board = res.get("board-name") or ""
        version = res.get("version") or ""
        model = _first(api, "/system/routerboard/print").get("model") or ""
        label = board or model
        if classify_board(board, model) == MODE_SERVER:
            return Outcome(c.id, MODE_SERVER, f"small board {label}", board=label)
        if not routeros_version_ok(version):
            return Outcome(c.id, MODE_SERVER, f"RouterOS {version} too old", board=label)
        try:
            busy = int(res.get("cpu-load")) >= BUSY_CPU_PERCENT
        except (TypeError, ValueError):
            busy = False
        if busy:
            return Outcome(c.id, None, f"busy: CPU {res.get('cpu-load')}%", board=label)
        pings = api.send_command("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"}).get("data") or []
        tunnel_ok = any(p.get("time") for p in pings)
        if not tunnel_ok and needs_tunnel(board, model):
            return Outcome(c.id, MODE_SERVER, f"no tunnel route ({label} would use HTTPS)", board=label)
        if api.send_command("/ip/hotspot/ip-binding/print").get("error"):
            return Outcome(c.id, MODE_SERVER, "no hotspot ip-binding table", board=label)

        _ensure_ntp(api, version)
        _tag_bindings(api, c.paid)
        rendered = render_expiry_reaper_script(
            identity=ident,
            tunnel_url=settings.EXPIRY_REAPER_TUNNEL_URL,
            public_url=settings.EXPIRY_REAPER_PUBLIC_URL,
        )
        _remove_reaper(api)
        added = api.send_command("/system/script/add",
                                 {"name": SCRIPT_NAME, "policy": POLICY, "source": script_source(rendered)})
        if added.get("error"):
            return Outcome(c.id, None, f"script add failed: {added['error']}"[:120], board=label)
        added = api.send_command("/system/scheduler/add", {
            "name": SCHEDULER_NAME, "interval": "1m", "start-time": "startup",
            "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY, "comment": COMMENT,
        })
        if added.get("error"):
            # e.g. device-mode "configuration flagged": needs a button press on site.
            _remove_reaper(api)
            return Outcome(c.id, MODE_SERVER, f"scheduler add refused: {added['error']}"[:120], board=label)
        return Outcome(c.id, MODE_ROUTER, "installed, awaiting first run", board=label)
    finally:
        api.disconnect()


def verify_sync(c: Candidate, outcome: Outcome) -> Outcome:
    """After the scheduler's first run: the server must have confirmed the clock."""
    api = _api(c, timeout=30)
    if not api.connect():
        return Outcome(c.id, None, "unreachable at verify (installed, will re-check)", board=outcome.board)
    try:
        env = {e.get("name"): e.get("value")
               for e in api.send_command("/system/script/environment/print").get("data") or []
               if str(e.get("name", "")).startswith("bwExp")}
    finally:
        api.disconnect()
    if env.get("bwExpClockOk") == "true":
        return Outcome(c.id, MODE_ROUTER, "installed", installed=True, board=outcome.board)
    return Outcome(c.id, None, "installed, clock not confirmed yet (will re-check)", board=outcome.board)


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------

_running = False


async def expiry_reaper_enrol_background(*, now: Optional[datetime] = None) -> list[Outcome]:
    global _running
    if not settings.EXPIRY_REAPER_AUTO_ENROL or _running:
        return []
    from app.services.mikrotik_background import _background_db_pool_is_busy

    if _background_db_pool_is_busy("REAPER-ENROL"):
        return []
    _running = True
    started = time.monotonic()
    try:
        now = now or datetime.utcnow()
        candidates = await load_candidates(now, settings.EXPIRY_REAPER_ENROL_BATCH)
        if not candidates:
            return []
        outcomes: dict[int, Outcome] = {}
        for c in candidates:
            try:
                outcomes[c.id] = await asyncio.to_thread(probe_and_install_sync, c)
            except Exception as exc:
                outcomes[c.id] = Outcome(c.id, None, f"error: {exc}"[:120])

        pending = [c for c in candidates if outcomes[c.id].reason == "installed, awaiting first run"]
        if pending:
            await asyncio.sleep(VERIFY_WAIT_SECONDS)
            for c in pending:
                try:
                    outcomes[c.id] = await asyncio.to_thread(verify_sync, c, outcomes[c.id])
                except Exception as exc:
                    outcomes[c.id] = Outcome(c.id, None, f"verify error: {exc}"[:120])

        for o in outcomes.values():
            await record_outcome(o, now)
        logger.info(
            "[REAPER-ENROL] %d router(s) in %.0fs: %s", len(outcomes), time.monotonic() - started,
            "; ".join(f"{o.router_id}={o.mode or '-'} ({o.reason})" for o in outcomes.values()),
        )
        return list(outcomes.values())
    finally:
        _running = False

"""Install / roll back the real-time usage push (v3) on one router.

Used by ``scripts/realtime_push_install.py`` (manual batches and sweeps) and by
provisioning: when a new router finishes setup, ``schedule_install_after_provisioning``
installs the push once its management tunnel answers — no scheduler, no sweep
(Dennis, 2026-09-27).

Rules learnt in the 2026-09-26 fleet rollout (docs/agent-memory/realtime-push-rollout.md):

* Reports go as plain HTTP INSIDE the router's encrypted management tunnel
  (WireGuard, L2TP+IPsec or SSTP) to settings.REALTIME_TUNNEL_PUSH_URL. A router
  with no working encrypted tunnel is skipped: over public HTTPS an RB951 sat at
  80-90% CPU (351) and a hAP lite paid ~5-7 s at 100% CPU per report.
  ``force_https`` overrides.
* hAP lite / hAP mini (smips, 32 MB) are skipped: Dennis's decision, they stay on
  server polling. ``allow_small`` overrides.
* WAN is the interface of the active default route; ether1 is only the fallback.
* The router's previous script is kept as ``bitwave-usage-push-prev`` so
  ``rollback`` restores it.

The functions here do RouterOS I/O only; callers load the router row in a short
DB session and release it first (``install_after_provisioning`` does).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import Router, RouterHealth, User
from app.services.mikrotik_api import MikroTikAPI
from app.services.usage_push_script import SCHEDULER_NAME, SCRIPT_NAME, render_realtime_push_script

logger = logging.getLogger(__name__)

PUBLIC_URL = "https://isp.bitwavetechnologies.net/api/router/usage-push"
TUNNEL_SERVER_IP = "10.251.0.1"
POLICY = "read,write,test,policy"
COMMENT = "Bitwave usage reporting v2 (real-time)"
BACKUP_NAME = f"{SCRIPT_NAME}-prev"
SMALL_ARCHITECTURES = {"smips"}          # hAP lite / hAP mini: 650 MHz single core

# Worth another try later (router still coming up, tunnel not up yet, link blip).
RETRYABLE_STATUSES = {"unreachable", "skipped_no_tunnel", "script_failed",
                      "scheduler_failed", "backup_failed", "error"}


def _data(res) -> list:
    return (res or {}).get("data") or []


def tunnel_interface(api) -> tuple[Optional[str], str]:
    """Name + kind of the interface this router uses to reach TUNNEL_SERVER_IP, if encrypted."""
    routes = _data(api.send_command("/ip/route/print"))
    candidates = [
        r for r in routes
        if r.get("active") == "true" and r.get("dst-address", "") in (f"{TUNNEL_SERVER_IP}/32", "10.251.0.0/16")
    ]
    candidates.sort(key=lambda r: -int(r.get("dst-address", "0/0").split("/")[1]))
    if not candidates:
        return None, "no route"
    iface = (candidates[0].get("gateway") or "").split("%")[-1]
    if any(w.get("name") == iface for w in _data(api.send_command("/interface/wireguard/print"))):
        return iface, "wireguard"
    for l2tp in _data(api.send_command("/interface/l2tp-client/print")):
        if l2tp.get("name") == iface:
            return (iface, "l2tp+ipsec") if l2tp.get("use-ipsec") == "true" else (None, "l2tp WITHOUT ipsec")
    if any(s.get("name") == iface for s in _data(api.send_command("/interface/sstp-client/print"))):
        return iface, "sstp"
    return None, f"unknown interface {iface}"


def wan_interface(api, interface_names: set) -> str:
    """Interface of the active default route; ether1 (or the first ether) if unclear."""
    for route in _data(api.send_command("/ip/route/print")):
        if route.get("dst-address") != "0.0.0.0/0" or route.get("active") != "true":
            continue
        # ROS 7: immediate-gw "192.168.1.1%ether1"; ROS 6: gateway-status
        # "192.168.1.1 reachable via  ether1" or "pppoe-out1 reachable".
        candidates = [(route.get("immediate-gw") or "").split("%")[-1]]
        status = route.get("gateway-status") or ""
        m = re.search(r"via\s+(\S+)", status)
        if m:
            candidates.append(m.group(1))
        candidates.append(status.split(" ")[0])
        candidates.append((route.get("gateway") or "").split("%")[-1])
        for name in candidates:
            if name in interface_names:
                return name
    if "ether1" in interface_names:
        return "ether1"
    ethers = sorted(n for n in interface_names if n.startswith("ether"))
    return ethers[0] if ethers else "ether1"


def cpu_samples(api, n: int = 3) -> list:
    out = []
    for _ in range(n):
        res = _data(api.send_command("/system/resource/print"))
        if res:
            try:
                out.append(int(res[0].get("cpu-load") or 0))
            except ValueError:
                pass
        time.sleep(1)
    return out


def recent_push_log(api) -> list:
    lines = [
        f"{row.get('time', '')} {row.get('message', '')}"
        for row in _data(api.send_command("/log/print"))
        if (row.get("message") or "").startswith("usage-push")
    ]
    return lines[-4:]


def find_one(api, path: str, name: str) -> Optional[dict]:
    rows = [r for r in _data(api.send_command(f"{path}/print")) if r.get("name") == name]
    return rows[0] if rows else None


def _rollback(api, result: dict, current: Optional[dict]) -> dict:
    c = lambda p, a=None: api.send_command(p, a or {})  # noqa: E731
    backup = find_one(api, "/system/script", BACKUP_NAME)
    sched = find_one(api, "/system/scheduler", SCHEDULER_NAME)
    if backup and backup.get("source"):
        if current:
            c("/system/script/set", {".id": current[".id"], "source": backup["source"]})
        else:
            c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": backup["source"]})
        if sched:
            c("/system/scheduler/set", {".id": sched[".id"], "interval": "2m", "comment": "Bitwave usage reporting"})
        return {**result, "status": "rolled_back_to_prev"}
    if sched:
        c("/system/scheduler/remove", {".id": sched[".id"]})
    if current:
        c("/system/script/remove", {".id": current[".id"]})
    return {**result, "status": "removed"}


def install_router(
    router: dict,
    *,
    apply: bool = True,
    rollback: bool = False,
    skip_run: bool = False,
    allow_small: bool = False,
    force_https: bool = False,
    measure_cpu: bool = False,
    api_factory=MikroTikAPI,
) -> dict:
    """Install (or dry-run / roll back) the v3 push on one router. Blocking I/O; never raises.

    ``router``: id, name, identity, ip_address, username, password, port.
    Returns a dict with ``status`` plus what was found on the router.
    """
    result = {"id": router["id"], "name": router.get("name"),
              "action": "rollback" if rollback else ("install" if apply else "dry-run")}
    api = api_factory(router["ip_address"], router["username"], router["password"],
                      router.get("port") or 8728, timeout=60)
    if not api.connect():
        return {**result, "status": "unreachable"}
    try:
        c = lambda p, a=None: api.send_command(p, a or {})  # noqa: E731
        ident = _data(c("/system/identity/print"))[0]["name"]
        if ident != router.get("identity"):
            return {**result, "status": "identity_mismatch", "router_identity": ident}
        res = _data(c("/system/resource/print"))[0]
        arch = res.get("architecture-name", "")
        result.update(board=res.get("board-name"), arch=arch, ros=res.get("version"),
                      free_hdd=int(res.get("free-hdd-space") or 0))
        current = find_one(api, "/system/script", SCRIPT_NAME)
        current_src = (current or {}).get("source") or ""
        result["had_script"] = "v3" if '\\"v\\":3' in current_src else ("v1/v2" if current else "none")

        if rollback:
            return _rollback(api, result, current)

        iface, kind = tunnel_interface(api)
        ping_ok = bool([p for p in _data(c("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"})) if p.get("time")])
        via_tunnel = bool(iface and ping_ok)
        names = {i.get("name") for i in _data(c("/interface/print"))}
        wan = wan_interface(api, names)
        small = arch in SMALL_ARCHITECTURES
        lists_every = 10 if small else 5
        url = settings.REALTIME_TUNNEL_PUSH_URL if via_tunnel else PUBLIC_URL
        result.update(tunnel=iface or None, tunnel_kind=kind, tunnel_ping=ping_ok, via_tunnel=via_tunnel,
                      wan=wan, lists_every=lists_every, url=url)
        if small and not allow_small:
            return {**result, "status": "skipped_small_board"}
        if not via_tunnel and not force_https:
            return {**result, "status": "skipped_no_tunnel"}
        if measure_cpu:
            result["cpu_before"] = cpu_samples(api)
        if not apply:
            return {**result, "status": "would_install"}

        rendered = render_realtime_push_script(identity=ident, endpoint_url=url, interval_seconds=60,
                                               wan_interface=wan, lists_every=lists_every)
        source = rendered[rendered.index("source={\n") + len("source={\n"):
                          rendered.index("\n}\n\n/system scheduler add")]
        if current and result["had_script"] != "v3":
            backup = find_one(api, "/system/script", BACKUP_NAME)
            res_b = (c("/system/script/set", {".id": backup[".id"], "source": current_src}) if backup
                     else c("/system/script/add", {"name": BACKUP_NAME, "policy": POLICY, "source": current_src}))
            if res_b.get("error"):
                return {**result, "status": "backup_failed", "error": str(res_b["error"])[:200]}
        res_s = (c("/system/script/set", {".id": current[".id"], "source": source}) if current
                 else c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": source}))
        if res_s.get("error"):
            return {**result, "status": "script_failed", "error": str(res_s["error"])[:200]}
        # First report before the scheduler exists, so the two can't collide (429).
        run = {}
        if not skip_run:
            sid = find_one(api, "/system/script", SCRIPT_NAME)[".id"]
            t0 = time.time()
            run = c("/system/script/run", {".id": sid})
            result["first_run_seconds"] = round(time.time() - t0, 1)
        sched = find_one(api, "/system/scheduler", SCHEDULER_NAME)
        res_c = (c("/system/scheduler/set", {".id": sched[".id"], "disabled": "no", "interval": "60s",
                                             "comment": COMMENT})
                 if sched else
                 c("/system/scheduler/add", {"name": SCHEDULER_NAME, "interval": "60s", "start-time": "startup",
                                             "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY,
                                             "comment": COMMENT}))
        if res_c.get("error"):
            return {**result, "status": "scheduler_failed", "error": str(res_c["error"])[:200]}
        result["log"] = recent_push_log(api)
        if run.get("error"):
            result["run_error"] = str(run["error"])[:200]
        bad = [line for line in result["log"][-1:] if "deferred" in line or "skipped" in line]
        return {**result, "status": "installed_check_log" if bad else "installed"}
    except Exception as exc:  # noqa: BLE001 - one router must never break a batch
        return {**result, "status": "error", "error": str(exc)[:200]}
    finally:
        try:
            api.disconnect()
        except Exception:  # noqa: BLE001
            pass


# --- at setup -------------------------------------------------------------------

# The router calls /complete at the END of its setup script; its tunnel may take
# a little longer to come up. Wait, then keep trying with growing gaps for
# ~8 h (a router set up before its uplink is ready, or on a flaky tunnel).
SETUP_FIRST_DELAY_SECONDS = 60
SETUP_RETRY_DELAYS_SECONDS = (60, 120, 300, 600, 1800, 3600, 7200, 14400)

# The pending install lives in process memory, so a deploy in the retry window
# loses it. At startup (once, no scheduler) routers added in the last day that
# are not pushing get it again. The delay lets pushing routers report first.
CATCH_UP_WINDOW_HOURS = 24
CATCH_UP_STARTUP_DELAY_SECONDS = 180
PUSH_FRESH_MINUTES = 10
_SMALL_BOARD_RE = re.compile(r"hap\s*(lite|mini)|rb9[34]1", re.IGNORECASE)

_setup_tasks: set = set()


async def _load_router(router_id: int) -> Optional[dict]:
    async with database.async_session() as db:
        r = await db.get(Router, router_id)
        info = None if r is None else {
            "id": r.id, "name": r.name, "identity": r.identity, "ip_address": r.ip_address,
            "username": r.username, "password": r.password, "port": r.port,
        }
        await db.commit()
    return info


async def install_after_provisioning(router_id: int, *, first_delay: float = SETUP_FIRST_DELAY_SECONDS,
                                     sleep=asyncio.sleep, install=install_router) -> dict:
    """Put the real-time push on a freshly provisioned router. Never raises."""
    result: dict = {"id": router_id, "status": "disabled"}
    if not settings.REALTIME_PUSH_INSTALL_AT_SETUP:
        return result
    try:
        if first_delay:
            await sleep(first_delay)
        for delay in (0,) + SETUP_RETRY_DELAYS_SECONDS:
            if delay:
                await sleep(delay)
            info = await _load_router(router_id)          # short session, released
            if info is None:
                return {"id": router_id, "status": "no_router"}
            # First report left to the scheduler's first tick: the router may
            # still be finishing its own setup.
            result = await asyncio.to_thread(install, info, apply=True, skip_run=True)
            if result.get("status") not in RETRYABLE_STATUSES:
                break
        logger.info("[REALTIME-PUSH] setup install for router %s: %s", router_id,
                    {k: result.get(k) for k in ("status", "board", "tunnel_kind", "wan", "error")})
    except Exception:  # noqa: BLE001
        logger.exception("[REALTIME-PUSH] setup install for router %s failed", router_id)
    return result


def schedule_install_after_provisioning(router_id: int, *, first_delay: float = SETUP_FIRST_DELAY_SECONDS) -> None:
    """Fire-and-forget (setup callback, manual router creation, startup catch-up). Never raises."""
    try:
        task = asyncio.get_running_loop().create_task(
            install_after_provisioning(router_id, first_delay=first_delay))
        _setup_tasks.add(task)
        task.add_done_callback(_setup_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[REALTIME-PUSH] could not schedule setup install for router %s", router_id)


async def recent_routers_without_push(now: Optional[datetime] = None) -> list[int]:
    """Routers added in the catch-up window, owner not cut off, not pushing, not a known hAP lite."""
    from app.services.ops_health import is_owner_cut_off

    now = now or datetime.utcnow()
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, User.subscription_status, RouterHealth.source,
                   RouterHealth.sampled_at, RouterHealth.board_name)
            .outerjoin(User, User.id == Router.user_id)
            .outerjoin(RouterHealth, RouterHealth.router_id == Router.id)
            .where(Router.created_at >= now - timedelta(hours=CATCH_UP_WINDOW_HOURS))
        )).all()
        await db.commit()
    ids = []
    for router_id, owner_status, source, sampled_at, board in rows:
        if is_owner_cut_off(owner_status):
            continue
        if source == "push" and sampled_at and now - sampled_at <= timedelta(minutes=PUSH_FRESH_MINUTES):
            continue
        if board and _SMALL_BOARD_RE.search(board):
            continue
        ids.append(router_id)
    return ids


async def catch_up_after_restart(*, sleep=asyncio.sleep, schedule=schedule_install_after_provisioning) -> list[int]:
    """Once per app start: re-queue setup installs a deploy may have cut short. Never raises."""
    if not settings.REALTIME_PUSH_INSTALL_AT_SETUP:
        return []
    try:
        await sleep(CATCH_UP_STARTUP_DELAY_SECONDS)
        ids = await recent_routers_without_push()
        for router_id in ids:
            schedule(router_id, first_delay=0)
        if ids:
            logger.info("[REALTIME-PUSH] startup catch-up: setup install queued for routers %s", ids)
        return ids
    except Exception:  # noqa: BLE001
        logger.exception("[REALTIME-PUSH] startup catch-up failed")
        return []


def schedule_catch_up_after_restart() -> None:
    try:
        task = asyncio.get_running_loop().create_task(catch_up_after_restart())
        _setup_tasks.add(task)
        task.add_done_callback(_setup_tasks.discard)
    except Exception:  # noqa: BLE001
        logger.exception("[REALTIME-PUSH] could not schedule the startup catch-up")

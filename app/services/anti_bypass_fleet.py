"""Find and close the hotspot proxy bypass (HTTP Injector) across the fleet.

The check is the router check-up's own (`router_checkup.proxy_bypass_finding`) and
the fix is the one-router endpoint's own (`router_checkup.apply_anti_bypass`), run a
few routers at a time with short timeouts. Callers load what they need from the DB
in one short session and release it before calling anything here: nothing in this
module touches the database.

Nothing here runs on a schedule or on deploy. The admin endpoints
(`/api/admin/anti-bypass/scan`, `/api/admin/anti-bypass/apply`) and the read-only
detector `scripts/detect_anti_bypass_missing.py` are the only callers.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Iterable

from app.services import router_checkup
from app.services.mikrotik_api import MikroTikAPI

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5
COMMAND_TIMEOUT = 12
DEFAULT_CONCURRENCY = 3
MAX_CONCURRENCY = 6

# Scan statuses: "open" (hotspot, relay block missing), "protected" (block there),
# "no_hotspot" (no hotspot server, so no proxy to abuse), "unreachable", "error".
# Unreachable is never reported as protected.


def router_info(router: Any) -> dict:
    """The connection details for one Router row, read while the session is open."""
    return {"id": router.id, "account_id": router.user_id, "ip": router.ip_address,
            "username": router.username, "password": router.password, "port": router.port}


def _ok(result: Any) -> bool:
    return isinstance(result, dict) and bool(result.get("success")) and isinstance(result.get("data"), list)


def scan_connected(api, router_id: int) -> dict:
    """Read-only: is the hotspot proxy open with the relay block missing?"""
    hotspot = api.send_command("/ip/hotspot/print")
    if not _ok(hotspot):
        return {"status": "error", "detail": "could not read the hotspot servers"}
    if not router_checkup._rows(hotspot):
        return {"status": "no_hotspot"}
    rules = api.send_command("/ip/firewall/filter/print")
    if not _ok(rules):
        # An unreadable filter table is not "rule missing": never guess either way.
        return {"status": "error", "detail": "could not read the firewall filter"}
    found = router_checkup.proxy_bypass_finding(router_checkup._rows(rules), router_id)
    return {"status": "open", "finding": found["code"]} if found else {"status": "protected"}


def _connect(info: dict) -> MikroTikAPI:
    return MikroTikAPI(info["ip"], info["username"], info["password"], info["port"] or 8728,
                       timeout=COMMAND_TIMEOUT, connect_timeout=CONNECT_TIMEOUT)


def _short(text: Any) -> str:
    return str(text or "")[:200]


def scan_router(info: dict) -> dict:
    out = {"router_id": info["id"], "account_id": info["account_id"]}
    api = _connect(info)
    if not api.connect():
        return {**out, "status": "unreachable", "detail": _short(api.last_connect_error or "connection failed")}
    try:
        return {**out, **scan_connected(api, info["id"])}
    except Exception as exc:  # one bad router never stops the scan
        return {**out, "status": "error", "detail": _short(exc)}
    finally:
        api.disconnect()


def fix_router(info: dict, allow_entries: list[str]) -> dict:
    """The one-router fix, then the same check again on the same connection."""
    out = {"router_id": info["id"], "account_id": info["account_id"]}
    api = _connect(info)
    if not api.connect():
        return {**out, "status": "unreachable", "detail": _short(api.last_connect_error or "connection failed")}
    try:
        applied = router_checkup.apply_anti_bypass(api, allow_entries)
        after = scan_connected(api, info["id"])
        fixed = bool(applied.get("success")) and after["status"] == "protected"
        return {**out, "status": "fixed" if fixed else "failed", "after": after["status"],
                "steps": applied.get("steps", [])}
    except Exception as exc:
        return {**out, "status": "error", "detail": _short(exc)}
    finally:
        api.disconnect()


def clamp_concurrency(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = DEFAULT_CONCURRENCY
    return max(1, min(MAX_CONCURRENCY, n))


async def run_bounded(items: Iterable[Any], work: Callable[[Any], dict], concurrency: int,
                      on_error: Callable[[Any, Exception], dict]) -> list[dict]:
    """Run blocking `work(item)` in threads, at most `concurrency` at a time, in order."""
    gate = asyncio.Semaphore(clamp_concurrency(concurrency))

    async def one(item: Any) -> dict:
        async with gate:
            try:
                return await asyncio.to_thread(work, item)
            except Exception as exc:
                logger.warning("anti-bypass fleet: item failed: %s", exc)
                return on_error(item, exc)

    tasks: list[Awaitable[dict]] = [one(i) for i in items]
    return list(await asyncio.gather(*tasks))


def summarize(results: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


DETECTOR_ID = "hotspot_proxy_bypass_open"
_DETECTOR_STATUS = {"open": "hit", "protected": "clean", "no_hotspot": "clean",
                    "unreachable": "unreachable", "error": "error"}


def detector_line(result: dict) -> dict:
    """One scan result in the incident-to-detector contract's JSON-line shape."""
    status = _DETECTOR_STATUS.get(result["status"], "error")
    line = {"router_id": result["router_id"], "detector": DETECTOR_ID, "status": status,
            "severity": "blocker", "code": "HTTP_INJECTOR_BYPASS" if status == "hit" else None,
            "evidence": {k: v for k, v in result.items() if k not in ("router_id",)},
            "fix_ref": "skill:hotspot-bypass-fix; POST /api/admin/anti-bypass/apply"}
    if status == "hit":
        line["reseller_message"] = (
            "Your hotspot can be used to browse without paying (apps like HTTP Injector). "
            "Bitwave can close this from here; nothing needs doing at the site.")
    return line


async def scan(infos: list[dict], concurrency: int = DEFAULT_CONCURRENCY) -> list[dict]:
    return await run_bounded(
        infos, scan_router, concurrency,
        lambda i, e: {"router_id": i["id"], "account_id": i["account_id"], "status": "error", "detail": _short(e)})


async def apply(jobs: list[tuple[dict, list[str]]], concurrency: int = DEFAULT_CONCURRENCY) -> list[dict]:
    return await run_bounded(
        jobs, lambda job: fix_router(*job), concurrency,
        lambda j, e: {"router_id": j[0]["id"], "account_id": j[0]["account_id"], "status": "error",
                      "detail": _short(e)})

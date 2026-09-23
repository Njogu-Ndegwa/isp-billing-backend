"""Staged, reversible enrolment of routers into SNMP CPU monitoring.

Operator-run only (scripts/router_snmp_rollout.py); nothing calls this from the
app. Dry-run by default. Per router, with --apply:

1. Read the API service's allowed ``address`` list (our management sources) and
   the current SNMP settings; save them to the state file for rollback.
2. If the built-in default community is open to everyone (0.0.0.0/0 or ::/0),
   restrict it to 127.0.0.1/32 so enabling SNMP never exposes the router to its
   LAN/WAN.
3. Add our read-only community restricted to the same sources as the API.
4. ``/snmp set enabled=yes``.
5. Verify with one real SNMP CPU read from this host. Success marks
   ``routers.snmp_enabled`` (the poller only reads enrolled routers); failure
   rolls that router back to exactly what was saved.

Database Session Discipline: router rows are read in a short session that is
committed before any router I/O, and the enrolment flag is written afterwards
in a fresh short session.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select, update

from app.db import database
from app.db.models import Router
from app.services import snmp_cpu
from app.services.mikrotik_api import LANE_DEFAULT, MikroTikAPI

logger = logging.getLogger(__name__)

OPEN_ADDRESSES = {"0.0.0.0/0", "::/0", ""}
FALLBACK_SOURCES = "10.0.0.1/32,10.251.0.1/32"
MAX_BATCH = 10


@dataclass
class RouterPlan:
    router_id: int
    name: str
    ip: str
    sources: str = ""
    snmp_was_enabled: Optional[str] = None
    default_community_id: Optional[str] = None
    default_community_prev_addresses: Optional[str] = None
    ours_exists: bool = False
    actions: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _rows(result: dict) -> list[dict]:
    if not isinstance(result, dict) or result.get("error"):
        raise RuntimeError(str((result or {}).get("error") or "no response"))
    return [r for r in (result.get("data") or []) if isinstance(r, dict)]


def build_plan(api, router_id: int, name: str, ip: str, community: str) -> RouterPlan:
    """Read-only: work out what enrolment would change on this router."""
    plan = RouterPlan(router_id=router_id, name=name, ip=ip)
    services = _rows(api.send_command("/ip/service/print", {}))
    api_row = next((s for s in services if s.get("name") == "api"), {})
    plan.sources = (api_row.get("address") or "").strip() or FALLBACK_SOURCES

    snmp = _rows(api.send_command("/snmp/print", {}))
    plan.snmp_was_enabled = (snmp[0].get("enabled") if snmp else None) or "false"

    for row in _rows(api.send_command("/snmp/community/print", {})):
        if row.get("name") == community:
            plan.ours_exists = True
        is_default = row.get("default") == "true" or row.get("name") == "public"
        if is_default and plan.default_community_id is None:
            plan.default_community_id = row.get(".id")
            plan.default_community_prev_addresses = row.get("addresses") or ""

    if (plan.default_community_id
            and set((plan.default_community_prev_addresses or "").split(",")) & OPEN_ADDRESSES):
        plan.actions.append("restrict default community to 127.0.0.1/32")
    if not plan.ours_exists:
        plan.actions.append(f"add read-only community limited to {plan.sources}")
    if plan.snmp_was_enabled != "true":
        plan.actions.append("enable SNMP")
    return plan


def apply_plan(api, plan: RouterPlan, community: str) -> None:
    for action in plan.actions:
        if action.startswith("restrict default"):
            _rows(api.send_command("/snmp/community/set", {
                "numbers": plan.default_community_id, "addresses": "127.0.0.1/32"}))
        elif action.startswith("add read-only"):
            _rows(api.send_command("/snmp/community/add", {
                "name": community, "addresses": plan.sources,
                "read-access": "yes", "write-access": "no"}))
        elif action == "enable SNMP":
            _rows(api.send_command("/snmp/set", {"enabled": "yes"}))


def rollback_plan(api, saved: dict, community: str) -> None:
    """Restore exactly what build_plan saved. Tolerates partial application."""
    if saved.get("snmp_was_enabled") != "true":
        api.send_command("/snmp/set", {"enabled": "no"})
    if not saved.get("ours_exists"):
        for row in _rows(api.send_command("/snmp/community/print", {})):
            if row.get("name") == community and row.get(".id"):
                api.send_command("/snmp/community/remove", {"numbers": row[".id"]})
    if saved.get("default_community_id") is not None:
        api.send_command("/snmp/community/set", {
            "numbers": saved["default_community_id"],
            "addresses": saved.get("default_community_prev_addresses") or "0.0.0.0/0"})


async def _load_routers(router_ids: list[int]) -> list[tuple[int, str, str, str, str, int]]:
    async with database.async_session() as db:
        rows = (await db.execute(
            select(Router.id, Router.name, Router.ip_address, Router.username,
                   Router.password, Router.port).where(Router.id.in_(router_ids))
        )).all()
        await db.commit()
    return [tuple(r) for r in rows]


async def _set_enrolled(router_id: int, enrolled: bool, cpu: Optional[int] = None) -> None:
    values: dict[str, Any] = {"snmp_enabled": enrolled}
    if cpu is not None:
        from datetime import datetime
        values.update(cpu_load=cpu, cpu_checked_at=datetime.utcnow())
    async with database.async_session() as db:
        await db.execute(update(Router).where(Router.id == router_id).values(**values))
        await db.commit()


def _connect(ip, user, password, port) -> MikroTikAPI:
    api = MikroTikAPI(ip, user, password, port or 8728, timeout=30, connect_timeout=8,
                      lane=LANE_DEFAULT)
    if not api.connect():
        raise RuntimeError(api.last_connect_error or "connect failed")
    return api


async def run(router_ids: list[int], community: str, *, apply: bool,
              rollback: bool = False, state_path: Path) -> list[dict]:
    """Plan / apply / roll back one batch. Returns a per-router report."""
    if not community:
        raise ValueError("ROUTER_SNMP_COMMUNITY must be set")
    if len(router_ids) > MAX_BATCH:
        raise ValueError(f"batch too large: {len(router_ids)} > {MAX_BATCH}")
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    report: list[dict] = []
    for rid, name, ip, user, password, port in await _load_routers(router_ids):
        entry: dict[str, Any] = {"router_id": rid, "name": name}
        try:
            api = await asyncio.to_thread(_connect, ip, user, password, port)
            try:
                if rollback:
                    saved = state.get(str(rid))
                    if not saved:
                        entry["result"] = "no saved state; nothing rolled back"
                    elif apply:
                        await asyncio.to_thread(rollback_plan, api, saved, community)
                        entry["result"] = "rolled back"
                    else:
                        entry["result"] = "would roll back"
                else:
                    plan = await asyncio.to_thread(build_plan, api, rid, name, ip, community)
                    entry["actions"] = plan.actions
                    if apply:
                        state[str(rid)] = plan.__dict__
                        state_path.write_text(json.dumps(state, indent=2))
                        await asyncio.to_thread(apply_plan, api, plan, community)
            finally:
                api.disconnect()
            if rollback and apply and entry.get("result") == "rolled back":
                await _set_enrolled(rid, False)
            if not rollback and apply:
                cpu = await snmp_cpu.read_cpu_load(ip, community, timeout=3.0, retries=2)
                if cpu is None:
                    api = await asyncio.to_thread(_connect, ip, user, password, port)
                    try:
                        await asyncio.to_thread(rollback_plan, api, state[str(rid)], community)
                    finally:
                        api.disconnect()
                    entry["result"] = "SNMP not reachable after enabling; rolled back"
                else:
                    await _set_enrolled(rid, True, cpu)
                    entry["result"] = f"enrolled (cpu {cpu}%)"
            elif not rollback:
                entry["result"] = "dry-run"
        except Exception as exc:  # noqa: BLE001 - report per router, continue batch
            entry["result"] = f"error: {exc}"[:200]
        report.append(entry)
    return report

"""Sequential, reversible installer for the outbound RouterOS command agent.

Database sessions are used only to load one batch or persist one result. Router
I/O always happens after the session is closed, which keeps a slow/offline
router from consuming a PostgreSQL connection.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import random
from typing import Iterable

from sqlalchemy import select

from app.config import settings
from app.db.database import async_session
from app.db.models import AppSetting, ProvisioningToken, Router
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_agent_commands import AGENT_ENABLED_SETTING
from app.services.router_agent_script import (
    SCRIPT_NAME,
    SCHEDULER_NAME,
    render_router_agent_source,
)


# RouterOS requires the ftp policy for scripts/schedulers that create, remove,
# or import files. The agent fetches its response to a temporary .rsc file.
AGENT_ROUTEROS_POLICY = "ftp,read,write,test,policy,sensitive"


@dataclass(frozen=True)
class RouterAgentCandidate:
    router_id: int
    identity: str
    ip_address: str
    username: str
    password: str
    port: int
    tunnel_type: str | None
    already_enabled: bool


def _rows(result: dict) -> list[dict]:
    if not isinstance(result, dict) or not result.get("success"):
        return []
    data = result.get("data")
    return data if isinstance(data, list) else []


def _command_ok(result: dict) -> bool:
    return isinstance(result, dict) and bool(result.get("success"))


async def load_router_agent_candidates(
    *,
    router_ids: Iterable[int] | None = None,
    limit: int | None = None,
    enabled: bool | None = None,
) -> list[RouterAgentCandidate]:
    selected_ids = sorted({int(value) for value in (router_ids or [])})
    async with async_session() as db:
        query = select(Router).where(Router.identity.isnot(None)).order_by(Router.id)
        if selected_ids:
            query = query.where(Router.id.in_(selected_ids))
        if enabled is not None:
            query = query.where(Router.router_agent_enabled == enabled)  # noqa: E712
        if limit is not None:
            query = query.limit(max(1, int(limit)))
        routers = (await db.execute(query)).scalars().all()

        ids = [router.id for router in routers]
        token_rows = []
        if ids:
            token_rows = (
                await db.execute(
                    select(
                        ProvisioningToken.router_id,
                        ProvisioningToken.vpn_type,
                        ProvisioningToken.created_at,
                    )
                    .where(ProvisioningToken.router_id.in_(ids))
                    .order_by(
                        ProvisioningToken.router_id,
                        ProvisioningToken.created_at.desc(),
                    )
                )
            ).all()

        tunnel_by_router: dict[int, str] = {}
        for router_id, vpn_type, _created_at in token_rows:
            if router_id not in tunnel_by_router and vpn_type in {"wireguard", "l2tp"}:
                tunnel_by_router[router_id] = vpn_type

        return [
            RouterAgentCandidate(
                router_id=router.id,
                identity=router.identity,
                ip_address=router.ip_address,
                username=router.username,
                password=router.password,
                port=router.port,
                tunnel_type=tunnel_by_router.get(router.id),
                already_enabled=bool(router.router_agent_enabled),
            )
            for router in routers
            if router.identity
        ]


def _detect_tunnel_type(api: MikroTikAPI, preferred: str | None) -> str:
    if preferred in {"wireguard", "l2tp"}:
        return preferred
    l2tp_rows = _rows(
        api.send_command_optimized(
            "/interface/l2tp-client/print",
            proplist=["name"],
        )
    )
    if any(row.get("name") == "l2tp-aws" for row in l2tp_rows):
        return "l2tp"
    return "wireguard"


def install_router_agent_sync(
    candidate: RouterAgentCandidate,
    *,
    endpoint_base_url: str,
    management_probe_ip: str = "10.0.0.1",
) -> dict:
    """Install and verify one router. No database connection is held here."""

    api = MikroTikAPI(
        candidate.ip_address,
        candidate.username,
        candidate.password,
        candidate.port,
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"ok": False, "router_id": candidate.router_id, "error": "connect_failed"}
    try:
        tunnel_type = _detect_tunnel_type(api, candidate.tunnel_type)
        source = render_router_agent_source(
            identity=candidate.identity,
            endpoint_base_url=endpoint_base_url,
            tunnel_type=tunnel_type,
            management_probe_ip=management_probe_ip,
            check_certificate=tunnel_type != "l2tp",
        )

        scripts = _rows(
            api.send_command_optimized(
                "/system/script/print",
                proplist=[".id", "name"],
                query=f"?name={SCRIPT_NAME}",
            )
        )
        script_params = {
            "name": SCRIPT_NAME,
            "source": source,
            "policy": AGENT_ROUTEROS_POLICY,
            "comment": "Bitwave outbound command fallback v1",
        }
        if scripts:
            result = api.send_command(
                "/system/script/set",
                {"numbers": scripts[0][".id"], **script_params},
            )
        else:
            result = api.send_command("/system/script/add", script_params)
        if not _command_ok(result):
            return {
                "ok": False,
                "router_id": candidate.router_id,
                "error": f"script_write_failed:{result.get('error', 'unknown')}",
            }

        schedulers = _rows(
            api.send_command_optimized(
                "/system/scheduler/print",
                proplist=[".id", "name"],
                query=f"?name={SCHEDULER_NAME}",
            )
        )
        scheduler_params = {
            "name": SCHEDULER_NAME,
            "interval": f"{random.randint(90, 150)}s",
            "start-time": "startup",
            "on-event": f"/system script run {SCRIPT_NAME}",
            "policy": AGENT_ROUTEROS_POLICY,
            "comment": "Bitwave adaptive command polling",
            "disabled": "no",
        }
        if schedulers:
            result = api.send_command(
                "/system/scheduler/set",
                {"numbers": schedulers[0][".id"], **scheduler_params},
            )
        else:
            result = api.send_command("/system/scheduler/add", scheduler_params)
        if not _command_ok(result):
            return {
                "ok": False,
                "router_id": candidate.router_id,
                "error": f"scheduler_write_failed:{result.get('error', 'unknown')}",
            }

        verified_scripts = _rows(
            api.send_command_optimized(
                "/system/script/print",
                proplist=[".id", "name", "source", "policy"],
                query=f"?name={SCRIPT_NAME}",
            )
        )
        verified_schedulers = _rows(
            api.send_command_optimized(
                "/system/scheduler/print",
                proplist=[".id", "name", "disabled", "interval", "on-event", "policy"],
                query=f"?name={SCHEDULER_NAME}",
            )
        )
        source_ok = bool(
            verified_scripts
            and candidate.identity in (verified_scripts[0].get("source") or "")
            and "/api/router/agent/poll" in (verified_scripts[0].get("source") or "")
        )
        scheduler_ok = bool(
            verified_schedulers
            and verified_schedulers[0].get("disabled") != "true"
            and SCRIPT_NAME in (verified_schedulers[0].get("on-event") or "")
        )
        required_policies = set(AGENT_ROUTEROS_POLICY.split(","))
        script_policy_ok = bool(
            verified_scripts
            and required_policies.issubset(
                set((verified_scripts[0].get("policy") or "").split(","))
            )
        )
        scheduler_policy_ok = bool(
            verified_schedulers
            and required_policies.issubset(
                set((verified_schedulers[0].get("policy") or "").split(","))
            )
        )
        if not source_ok or not scheduler_ok or not script_policy_ok or not scheduler_policy_ok:
            return {
                "ok": False,
                "router_id": candidate.router_id,
                "error": "verification_failed",
                "source_ok": source_ok,
                "scheduler_ok": scheduler_ok,
                "script_policy_ok": script_policy_ok,
                "scheduler_policy_ok": scheduler_policy_ok,
            }
        return {
            "ok": True,
            "router_id": candidate.router_id,
            "identity": candidate.identity,
            "tunnel_type": tunnel_type,
            "script_bytes": len(source.encode("utf-8")),
        }
    except Exception as exc:
        return {"ok": False, "router_id": candidate.router_id, "error": str(exc)}
    finally:
        api.disconnect()


def uninstall_router_agent_sync(candidate: RouterAgentCandidate) -> dict:
    """Remove the scheduler first, then the script, from one reachable router."""

    api = MikroTikAPI(
        candidate.ip_address,
        candidate.username,
        candidate.password,
        candidate.port,
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"ok": False, "router_id": candidate.router_id, "error": "connect_failed"}
    try:
        for path, name in (
            ("/system/scheduler", SCHEDULER_NAME),
            ("/system/script", SCRIPT_NAME),
        ):
            rows = _rows(
                api.send_command_optimized(
                    f"{path}/print",
                    proplist=[".id", "name"],
                    query=f"?name={name}",
                )
            )
            for row in rows:
                result = api.send_command(f"{path}/remove", {"numbers": row[".id"]})
                if not _command_ok(result):
                    return {
                        "ok": False,
                        "router_id": candidate.router_id,
                        "error": f"remove_failed:{path}",
                    }
        return {"ok": True, "router_id": candidate.router_id}
    except Exception as exc:
        return {"ok": False, "router_id": candidate.router_id, "error": str(exc)}
    finally:
        api.disconnect()


async def _set_router_enabled(router_id: int, enabled: bool) -> None:
    async with async_session() as db:
        router = await db.get(Router, router_id)
        if router is not None:
            router.router_agent_enabled = enabled
            await db.commit()


async def set_router_agent_global_enabled(enabled: bool) -> None:
    async with async_session() as db:
        setting = await db.get(AppSetting, AGENT_ENABLED_SETTING)
        value = "true" if enabled else "false"
        if setting is None:
            db.add(AppSetting(key=AGENT_ENABLED_SETTING, value=value))
        else:
            setting.value = value
        await db.commit()


async def run_router_agent_fleet_change(
    *,
    mode: str,
    router_ids: Iterable[int] | None = None,
    limit: int | None = None,
    endpoint_base_url: str | None = None,
    management_probe_ip: str = "10.0.0.1",
) -> list[dict]:
    """Apply one bounded sequential batch and return a result per router."""

    if mode not in {"install", "uninstall"}:
        raise ValueError("mode must be install or uninstall")
    candidates = await load_router_agent_candidates(
        router_ids=router_ids,
        limit=limit,
        enabled=False if mode == "install" else True,
    )
    results: list[dict] = []
    for candidate in candidates:
        if mode == "install":
            result = await asyncio.to_thread(
                install_router_agent_sync,
                candidate,
                endpoint_base_url=(endpoint_base_url or settings.PROVISION_BASE_URL),
                management_probe_ip=management_probe_ip,
            )
            if result.get("ok"):
                await _set_router_enabled(candidate.router_id, True)
        else:
            # DB first: even if the router is unreachable, command delivery is
            # disabled immediately and the installed agent receives only 401.
            await _set_router_enabled(candidate.router_id, False)
            result = await asyncio.to_thread(uninstall_router_agent_sync, candidate)
        results.append({**asdict(candidate), **result})
    return results

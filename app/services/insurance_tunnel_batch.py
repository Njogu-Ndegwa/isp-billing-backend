from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select

from app.db.database import async_session, db_pool_snapshot
from app.db.models import ProvisioningToken, Router
from app.services.insurance_l2tp import (
    configure_router_backup_l2tp,
    register_insurance_l2tp_peer,
    validate_insurance_l2tp_settings,
)
from app.services.insurance_wireguard import (
    InsuranceWireGuardError,
    configure_router_backup_wireguard,
    derive_insurance_ip,
    parse_routeros_major_version,
    read_routeros_version,
    register_insurance_peer,
    validate_insurance_settings,
    verify_insurance_router,
)
from app.services.router_availability import router_recently_offline
from app.services.router_helpers import connect_to_router

logger = logging.getLogger(__name__)


TERMINAL_JOB_STATUSES = {"completed", "failed"}
ACTIVE_JOB_STATUSES = {"queued", "running"}
MAX_JOB_HISTORY = 20


class Priority(Enum):
    BACKGROUND = "background"


class RouterOpStatus(Enum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED_OFFLINE = "skipped_offline"
    SKIPPED_CIRCUIT_OPEN = "skipped_circuit_open"
    SKIPPED_DB_PRESSURE = "skipped_db_pressure"


@dataclass(frozen=True)
class RouterSnapshot:
    id: int
    name: str
    ip_address: str
    username: str
    password: str
    port: int
    recently_offline: bool

    @classmethod
    def from_router(cls, router: Router, now: datetime) -> "RouterSnapshot":
        return cls(
            id=router.id,
            name=router.name,
            ip_address=router.ip_address,
            username=router.username,
            password=router.password,
            port=router.port or 8728,
            recently_offline=router_recently_offline(router, now=now),
        )


@dataclass(frozen=True)
class RouterOpResult:
    status: RouterOpStatus
    value: Any = None
    error: Optional[str] = None

    @property
    def is_ok(self) -> bool:
        return self.status is RouterOpStatus.OK


@dataclass(frozen=True)
class InsuranceTunnelCandidate:
    router: RouterSnapshot
    backup_ip: Optional[str]
    backup_ip_error: Optional[str]
    token_vpn_type: Optional[str]
    l2tp_username: Optional[str]
    l2tp_password: Optional[str]


_jobs: Dict[str, Dict[str, Any]] = {}
_active_job_id: Optional[str] = None
_jobs_lock = asyncio.Lock()


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _db_pool_too_busy_for_background_work() -> bool:
    try:
        pressure = (db_pool_snapshot().get("pressure") or {}).get("level")
    except Exception as exc:  # noqa: BLE001 - never fail the batch on telemetry
        logger.warning("Could not read DB pool pressure for insurance batch: %s", exc)
        return False
    return pressure in {"warning", "critical"}


async def run_router_op(
    router: RouterSnapshot,
    operation,
    *,
    priority: Priority = Priority.BACKGROUND,
    purpose: str = "insurance_tunnel",
) -> RouterOpResult:
    if router.recently_offline:
        return RouterOpResult(
            status=RouterOpStatus.SKIPPED_OFFLINE,
            error="Router was recently offline; skipped to protect the batch",
        )
    if priority is Priority.BACKGROUND and _db_pool_too_busy_for_background_work():
        return RouterOpResult(
            status=RouterOpStatus.SKIPPED_DB_PRESSURE,
            error="DB pool is busy; skipped background router work",
        )

    def _run():
        api = connect_to_router(router, connect_timeout=5, timeout=20)
        if not api.connect():
            error = api.last_connect_error or "Failed to connect to router"
            status = (
                RouterOpStatus.SKIPPED_CIRCUIT_OPEN
                if "Circuit breaker open" in error
                else RouterOpStatus.FAILED
            )
            return RouterOpResult(status=status, error=error)
        try:
            logger.debug("Running router op %s for router %s", purpose, router.id)
            return RouterOpResult(status=RouterOpStatus.OK, value=operation(api))
        finally:
            api.disconnect()

    return await asyncio.to_thread(_run)


def _token_vpn_type(token: Optional[ProvisioningToken]) -> Optional[str]:
    vpn_type = (getattr(token, "vpn_type", None) or "").lower()
    return vpn_type if vpn_type in {"wireguard", "l2tp"} else None


def _blank_counts() -> Dict[str, int]:
    return {
        "queued": 0,
        "running": 0,
        "verified": 0,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
    }


def _summarize_items(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = _blank_counts()
    for item in items:
        status = item.get("status") or "queued"
        counts[status] = counts.get(status, 0) + 1
    return counts


def _public_job(job: Dict[str, Any]) -> Dict[str, Any]:
    public = dict(job)
    public["items"] = [dict(item) for item in job["items"]]
    public["summary"] = _summarize_items(public["items"])
    return public


def _prune_jobs() -> None:
    finished = [
        (job.get("finished_at") or job.get("created_at") or "", job_id)
        for job_id, job in _jobs.items()
        if job.get("status") in TERMINAL_JOB_STATUSES
    ]
    finished.sort(reverse=True)
    for _, job_id in finished[MAX_JOB_HISTORY:]:
        _jobs.pop(job_id, None)


def _item_from_candidate(candidate: InsuranceTunnelCandidate) -> Dict[str, Any]:
    return {
        "router_id": candidate.router.id,
        "router_name": candidate.router.name,
        "current_ip": candidate.router.ip_address,
        "backup_ip": candidate.backup_ip,
        "token_vpn_type": candidate.token_vpn_type,
        "planned_tunnel_type": candidate.token_vpn_type or "auto",
        "recently_offline": candidate.router.recently_offline,
        "eligible": bool(candidate.backup_ip and not candidate.backup_ip_error and not candidate.router.recently_offline),
        "status": "queued",
        "error": candidate.backup_ip_error,
    }


async def load_insurance_tunnel_candidates(
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
) -> List[InsuranceTunnelCandidate]:
    async with async_session() as db:
        stmt = select(Router).order_by(Router.id)
        if router_ids:
            stmt = stmt.where(Router.id.in_(router_ids))
        if limit:
            stmt = stmt.limit(limit)
        routers = list((await db.execute(stmt)).scalars().all())

        token_by_router: Dict[int, ProvisioningToken] = {}
        if routers:
            token_stmt = (
                select(ProvisioningToken)
                .where(ProvisioningToken.router_id.in_([router.id for router in routers]))
                .order_by(ProvisioningToken.router_id, ProvisioningToken.created_at.desc())
            )
            for token in (await db.execute(token_stmt)).scalars().all():
                token_by_router.setdefault(token.router_id, token)

        now = datetime.utcnow()
        candidates = []
        for router in routers:
            token = token_by_router.get(router.id)
            try:
                backup_ip = derive_insurance_ip(router.ip_address)
                backup_ip_error = None
            except InsuranceWireGuardError as exc:
                backup_ip = None
                backup_ip_error = str(exc)

            candidates.append(
                InsuranceTunnelCandidate(
                    router=RouterSnapshot.from_router(router, now),
                    backup_ip=backup_ip,
                    backup_ip_error=backup_ip_error,
                    token_vpn_type=_token_vpn_type(token),
                    l2tp_username=getattr(token, "l2tp_username", None),
                    l2tp_password=getattr(token, "l2tp_password", None),
                )
            )
        return candidates


async def preview_insurance_tunnel_batch(
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    candidates = await load_insurance_tunnel_candidates(router_ids=router_ids, limit=limit)
    items = [_item_from_candidate(candidate) for candidate in candidates]
    return {
        "success": True,
        "applied": False,
        "total": len(items),
        "eligible": sum(1 for item in items if item["eligible"]),
        "skipped": sum(1 for item in items if not item["eligible"]),
        "missing_wireguard_settings": validate_insurance_settings("wireguard"),
        "missing_l2tp_settings": validate_insurance_l2tp_settings(),
        "items": items,
    }


async def get_insurance_tunnel_batch(job_id: str) -> Optional[Dict[str, Any]]:
    async with _jobs_lock:
        job = _jobs.get(job_id)
        return _public_job(job) if job else None


async def get_current_insurance_tunnel_batch() -> Optional[Dict[str, Any]]:
    async with _jobs_lock:
        if _active_job_id and _active_job_id in _jobs:
            return _public_job(_jobs[_active_job_id])
        if not _jobs:
            return None
        latest = max(_jobs.values(), key=lambda job: job.get("created_at") or "")
        return _public_job(latest)


async def start_insurance_tunnel_batch(
    *,
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
    max_concurrency: int = 2,
    force_rotate: bool = False,
) -> Dict[str, Any]:
    global _active_job_id

    candidates = await load_insurance_tunnel_candidates(router_ids=router_ids, limit=limit)
    max_concurrency = max(1, min(int(max_concurrency or 2), 5))
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "status": "queued",
        "created_at": _now_iso(),
        "started_at": None,
        "finished_at": None,
        "updated_at": _now_iso(),
        "total": len(candidates),
        "options": {
            "router_ids": router_ids,
            "limit": limit,
            "max_concurrency": max_concurrency,
            "force_rotate": force_rotate,
            "skips_recently_offline": True,
        },
        "items": [_item_from_candidate(candidate) for candidate in candidates],
    }

    async with _jobs_lock:
        if _active_job_id and _jobs.get(_active_job_id, {}).get("status") in ACTIVE_JOB_STATUSES:
            raise InsuranceWireGuardError(f"Insurance tunnel batch already running: {_active_job_id}")
        _jobs[job_id] = job
        _active_job_id = job_id
        _prune_jobs()

    asyncio.create_task(_run_insurance_tunnel_batch(job_id, candidates, max_concurrency, force_rotate))
    return _public_job(job)


async def _update_item(job_id: str, router_id: int, **updates) -> None:
    async with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        for item in job["items"]:
            if item["router_id"] == router_id:
                item.update(updates)
                break
        job["updated_at"] = _now_iso()


async def _set_job_status(job_id: str, status: str, **updates) -> None:
    global _active_job_id
    async with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.update(updates)
        job["status"] = status
        job["updated_at"] = _now_iso()
        if status in TERMINAL_JOB_STATUSES and _active_job_id == job_id:
            _active_job_id = None


async def _run_insurance_tunnel_batch(
    job_id: str,
    candidates: List[InsuranceTunnelCandidate],
    max_concurrency: int,
    force_rotate: bool,
) -> None:
    await _set_job_status(job_id, "running", started_at=_now_iso())
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _worker(candidate: InsuranceTunnelCandidate) -> None:
        async with semaphore:
            await _process_candidate(job_id, candidate, force_rotate)

    try:
        await asyncio.gather(*[_worker(candidate) for candidate in candidates])
        await _set_job_status(job_id, "completed", finished_at=_now_iso())
    except Exception as exc:  # noqa: BLE001 - keep batch failure visible
        logger.exception("Insurance tunnel batch %s failed: %s", job_id, exc)
        await _set_job_status(job_id, "failed", finished_at=_now_iso(), error=repr(exc))


def _gateway_error(result) -> str:
    if result.status is RouterOpStatus.SKIPPED_OFFLINE:
        return "Router was recently offline; skipped to protect the batch"
    if result.status is RouterOpStatus.SKIPPED_CIRCUIT_OPEN:
        return "Router circuit breaker is open; skipped"
    if result.status is RouterOpStatus.SKIPPED_DB_PRESSURE:
        return "DB pool is busy; skipped background router work"
    return result.error or result.status.value


async def _process_candidate(
    job_id: str,
    candidate: InsuranceTunnelCandidate,
    force_rotate: bool,
) -> None:
    router_id = candidate.router.id
    if candidate.backup_ip_error:
        await _update_item(job_id, router_id, status="skipped", error=candidate.backup_ip_error, finished_at=_now_iso())
        return
    if candidate.router.recently_offline:
        await _update_item(
            job_id,
            router_id,
            status="skipped",
            error="Router was recently offline; skipped for batch safety",
            finished_at=_now_iso(),
        )
        return

    await _update_item(job_id, router_id, status="running", started_at=_now_iso())

    version_result = await run_router_op(
        candidate.router,
        read_routeros_version,
        priority=Priority.BACKGROUND,
        purpose="insurance_tunnel_version",
    )
    if not version_result.is_ok:
        await _update_item(
            job_id,
            router_id,
            status="skipped" if version_result.status.name.startswith("SKIPPED") else "failed",
            error=_gateway_error(version_result),
            finished_at=_now_iso(),
        )
        return

    version = version_result.value
    major_version = parse_routeros_major_version(version)
    if major_version is None:
        await _update_item(
            job_id,
            router_id,
            status="failed",
            routeros_version=version,
            error=f"Could not determine RouterOS major version from '{version}'",
            finished_at=_now_iso(),
        )
        return

    tunnel_type = "wireguard" if major_version >= 7 else "l2tp"
    await _update_item(
        job_id,
        router_id,
        tunnel_type=tunnel_type,
        routeros_version=version,
        backup_ip=candidate.backup_ip,
    )

    missing_settings = (
        validate_insurance_l2tp_settings()
        if tunnel_type == "l2tp"
        else validate_insurance_settings("wireguard")
    )
    if missing_settings:
        await _update_item(
            job_id,
            router_id,
            status="failed",
            error=f"Missing insurance {tunnel_type} setting(s): {', '.join(missing_settings)}",
            finished_at=_now_iso(),
        )
        return

    try:
        if tunnel_type == "l2tp":
            await _process_l2tp_candidate(job_id, candidate)
        else:
            await _process_wireguard_candidate(job_id, candidate, force_rotate)
    except InsuranceWireGuardError as exc:
        await _update_item(job_id, router_id, status="failed", error=str(exc), finished_at=_now_iso())
    except Exception as exc:  # noqa: BLE001 - per-router failure should not stop batch
        logger.exception("Insurance tunnel batch router %s failed: %s", router_id, exc)
        await _update_item(job_id, router_id, status="failed", error=repr(exc), finished_at=_now_iso())


async def _process_l2tp_candidate(job_id: str, candidate: InsuranceTunnelCandidate) -> None:
    if not candidate.l2tp_username or not candidate.l2tp_password:
        raise InsuranceWireGuardError(
            "RouterOS v6 insurance tunnel requires linked L2TP provisioning token credentials"
        )

    manager_result = await register_insurance_l2tp_peer(
        candidate.l2tp_username,
        candidate.l2tp_password,
        candidate.backup_ip,
    )
    config_result = await run_router_op(
        candidate.router,
        lambda api: configure_router_backup_l2tp(
            api,
            backup_ip=candidate.backup_ip,
            username=candidate.l2tp_username,
            password=candidate.l2tp_password,
        ),
        priority=Priority.BACKGROUND,
        purpose="insurance_tunnel_l2tp_apply",
    )
    if not config_result.is_ok:
        raise InsuranceWireGuardError(_gateway_error(config_result))
    await _verify_candidate(job_id, candidate, manager_result, config_result.value)


async def _process_wireguard_candidate(
    job_id: str,
    candidate: InsuranceTunnelCandidate,
    force_rotate: bool,
) -> None:
    config_result = await run_router_op(
        candidate.router,
        lambda api: configure_router_backup_wireguard(
            api,
            backup_ip=candidate.backup_ip,
            force_rotate=force_rotate,
        ),
        priority=Priority.BACKGROUND,
        purpose="insurance_tunnel_wireguard_apply",
    )
    if not config_result.is_ok:
        raise InsuranceWireGuardError(_gateway_error(config_result))

    manager_result = await register_insurance_peer(
        config_result.value["router_public_key"],
        candidate.backup_ip,
    )
    await _verify_candidate(job_id, candidate, manager_result, config_result.value)


async def _verify_candidate(
    job_id: str,
    candidate: InsuranceTunnelCandidate,
    manager_result: Dict[str, Any],
    router_config: Dict[str, Any],
) -> None:
    verification = await verify_insurance_router(candidate.backup_ip, port=candidate.router.port)
    verified = bool(verification.get("ping_success") and verification.get("tcp_success"))
    await _update_item(
        job_id,
        candidate.router.id,
        status="verified" if verified else "partial",
        manager=manager_result,
        router_actions=router_config.get("actions", []),
        verification=verification,
        finished_at=_now_iso(),
        error=None if verified else "Insurance tunnel applied but verification did not fully pass",
    )

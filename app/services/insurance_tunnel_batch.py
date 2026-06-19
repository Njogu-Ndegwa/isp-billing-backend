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
from app.db.models import ProvisioningToken, Router, User
from app.services.insurance_l2tp import (
    configure_router_backup_l2tp,
    register_insurance_l2tp_peer,
    validate_insurance_l2tp_settings,
)
from app.services.insurance_wireguard import (
    InsuranceWireGuardError,
    backup_ips_from_manager_peers,
    configure_router_backup_wireguard,
    derive_insurance_ip,
    list_insurance_peers,
    parse_routeros_major_version,
    read_routeros_version,
    register_insurance_peer,
    validate_insurance_settings,
    verify_insurance_router,
)
from app.services.router_availability import derive_router_status, router_recently_offline
from app.services.router_helpers import connect_to_router

logger = logging.getLogger(__name__)


TERMINAL_JOB_STATUSES = {"completed", "failed"}
ACTIVE_JOB_STATUSES = {"queued", "running"}
MAX_JOB_HISTORY = 20
DEFAULT_START_LIMIT = 10
MAX_BATCH_LIMIT = 50
MAX_BATCH_CONCURRENCY = 3
ACTIVE_OWNER_STATUSES = {"active", "trial"}
PAID_OWNER_STATUSES = {"active"}
VERIFICATION_ATTEMPTS = 3
VERIFICATION_RETRY_DELAY_SECONDS = 15
SELECTION_MODES = {
    "all",
    "online",
    "online_missing_backup",
    "paid_reseller_online_missing_backup",
}
TUNNEL_TYPE_FILTERS = {"wireguard", "l2tp", "auto"}


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
    status: str

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
            status=derive_router_status(router, now=now),
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
    owner_user_id: Optional[int]
    owner_role: Optional[str]
    owner_subscription_status: Optional[str]
    has_known_backup: bool = False
    skip_reason: Optional[str] = None


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


def _enum_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    raw = value.value if hasattr(value, "value") else value
    return str(raw).lower()


def _owner_skip_reason(owner_role: Optional[str], subscription_status: Optional[str]) -> Optional[str]:
    if owner_role == "admin":
        return None
    if owner_role == "reseller" and subscription_status in ACTIVE_OWNER_STATUSES:
        return None
    if owner_role == "reseller":
        return f"Owner subscription is {subscription_status or 'unknown'}"
    return "Router owner is missing or unsupported"


def _candidate_skip_reason(
    *,
    backup_ip_error: Optional[str],
    recently_offline: bool,
    owner_role: Optional[str],
    subscription_status: Optional[str],
) -> Optional[str]:
    if backup_ip_error:
        return backup_ip_error
    if recently_offline:
        return "Router was recently offline; skipped for batch safety"
    return _owner_skip_reason(owner_role, subscription_status)


def _normalize_selection_mode(selection_mode: Optional[str]) -> str:
    value = (selection_mode or "all").strip().lower()
    if value not in SELECTION_MODES:
        raise InsuranceWireGuardError(
            f"Invalid insurance tunnel batch selection_mode '{selection_mode}'. "
            f"Allowed values: {', '.join(sorted(SELECTION_MODES))}"
        )
    return value


def _normalize_tunnel_type(tunnel_type: Optional[str]) -> Optional[str]:
    value = (tunnel_type or "").strip().lower()
    if not value or value == "all":
        return None
    if value not in TUNNEL_TYPE_FILTERS:
        raise InsuranceWireGuardError(
            f"Invalid insurance tunnel batch tunnel_type '{tunnel_type}'. "
            f"Allowed values: all, {', '.join(sorted(TUNNEL_TYPE_FILTERS))}"
        )
    return value


def _normalize_limit(limit: Optional[int], *, for_start: bool) -> Optional[int]:
    if limit is None:
        return DEFAULT_START_LIMIT if for_start else None
    return min(max(int(limit), 1), MAX_BATCH_LIMIT)


def _matches_tunnel_filter(candidate: InsuranceTunnelCandidate, tunnel_type: Optional[str]) -> bool:
    if tunnel_type is None:
        return True
    return (candidate.token_vpn_type or "auto") == tunnel_type


def _matches_selection(candidate: InsuranceTunnelCandidate, selection_mode: str) -> bool:
    if selection_mode == "all":
        return True
    if selection_mode == "online":
        return candidate.router.status == "online"
    if selection_mode == "online_missing_backup":
        return candidate.router.status == "online" and not candidate.has_known_backup
    if selection_mode == "paid_reseller_online_missing_backup":
        return (
            candidate.router.status == "online"
            and candidate.owner_role == "reseller"
            and candidate.owner_subscription_status in PAID_OWNER_STATUSES
            and not candidate.has_known_backup
        )
    return True


def _select_candidates(
    candidates: List[InsuranceTunnelCandidate],
    *,
    selection_mode: str,
    tunnel_type: Optional[str],
    limit: Optional[int],
) -> List[InsuranceTunnelCandidate]:
    selected = [
        candidate for candidate in candidates
        if _matches_selection(candidate, selection_mode)
        and _matches_tunnel_filter(candidate, tunnel_type)
    ]
    return selected[:limit] if limit else selected


def _selection_requires_backup_lookup(selection_mode: str) -> bool:
    return selection_mode in {"online_missing_backup", "paid_reseller_online_missing_backup"}


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
    eligible = candidate.skip_reason is None
    return {
        "router_id": candidate.router.id,
        "router_name": candidate.router.name,
        "current_ip": candidate.router.ip_address,
        "backup_ip": candidate.backup_ip,
        "owner_user_id": candidate.owner_user_id,
        "owner_role": candidate.owner_role,
        "owner_subscription_status": candidate.owner_subscription_status,
        "token_vpn_type": candidate.token_vpn_type,
        "planned_tunnel_type": candidate.token_vpn_type or "auto",
        "router_status": candidate.router.status,
        "recently_offline": candidate.router.recently_offline,
        "has_known_backup": candidate.has_known_backup,
        "eligible": eligible,
        "status": "queued",
        "error": candidate.skip_reason,
    }


async def load_insurance_tunnel_candidates(
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
    selection_mode: str = "all",
    tunnel_type: Optional[str] = None,
    for_start: bool = False,
) -> List[InsuranceTunnelCandidate]:
    selection_mode = _normalize_selection_mode(selection_mode)
    tunnel_type = _normalize_tunnel_type(tunnel_type)
    effective_limit = _normalize_limit(limit, for_start=for_start)

    async with async_session() as db:
        stmt = select(Router).order_by(Router.id)
        if router_ids:
            stmt = stmt.where(Router.id.in_(router_ids))
        routers = list((await db.execute(stmt)).scalars().all())

        token_by_router: Dict[int, ProvisioningToken] = {}
        owner_by_id: Dict[int, User] = {}
        if routers:
            token_stmt = (
                select(ProvisioningToken)
                .where(ProvisioningToken.router_id.in_([router.id for router in routers]))
                .order_by(ProvisioningToken.router_id, ProvisioningToken.created_at.desc())
            )
            for token in (await db.execute(token_stmt)).scalars().all():
                token_by_router.setdefault(token.router_id, token)

            owner_ids = sorted({router.user_id for router in routers if router.user_id})
            if owner_ids:
                owner_result = await db.execute(select(User).where(User.id.in_(owner_ids)))
                owner_by_id = {owner.id: owner for owner in owner_result.scalars().all()}

        now = datetime.utcnow()
        candidates = []
        for router in routers:
            token = token_by_router.get(router.id)
            owner = owner_by_id.get(router.user_id)
            owner_role = _enum_value(getattr(owner, "role", None))
            owner_subscription_status = _enum_value(getattr(owner, "subscription_status", None))
            try:
                backup_ip = derive_insurance_ip(router.ip_address)
                backup_ip_error = None
            except InsuranceWireGuardError as exc:
                backup_ip = None
                backup_ip_error = str(exc)
            router_snapshot = RouterSnapshot.from_router(router, now)
            skip_reason = _candidate_skip_reason(
                backup_ip_error=backup_ip_error,
                recently_offline=router_snapshot.recently_offline,
                owner_role=owner_role,
                subscription_status=owner_subscription_status,
            )

            candidates.append(
                InsuranceTunnelCandidate(
                    router=router_snapshot,
                    backup_ip=backup_ip,
                    backup_ip_error=backup_ip_error,
                    token_vpn_type=_token_vpn_type(token),
                    l2tp_username=getattr(token, "l2tp_username", None),
                    l2tp_password=getattr(token, "l2tp_password", None),
                    owner_user_id=router.user_id,
                    owner_role=owner_role,
                    owner_subscription_status=owner_subscription_status,
                    skip_reason=skip_reason,
                )
            )

    if not candidates:
        return []

    latest_backup_by_router = await get_latest_insurance_tunnel_items_by_router(
        [candidate.router.id for candidate in candidates]
    )
    manager_backup_ips = set()
    if _selection_requires_backup_lookup(selection_mode):
        try:
            manager_backup_ips = backup_ips_from_manager_peers(await list_insurance_peers())
        except InsuranceWireGuardError as exc:
            raise InsuranceWireGuardError(
                f"Cannot select routers without backup because the insurance manager peer list is unavailable: {exc}"
            ) from exc

    candidates = [
        InsuranceTunnelCandidate(
            router=candidate.router,
            backup_ip=candidate.backup_ip,
            backup_ip_error=candidate.backup_ip_error,
            token_vpn_type=candidate.token_vpn_type,
            l2tp_username=candidate.l2tp_username,
            l2tp_password=candidate.l2tp_password,
            owner_user_id=candidate.owner_user_id,
            owner_role=candidate.owner_role,
            owner_subscription_status=candidate.owner_subscription_status,
            has_known_backup=(
                (latest_backup_by_router.get(candidate.router.id) or {}).get("status") == "verified"
                or bool(candidate.backup_ip and candidate.backup_ip in manager_backup_ips)
            ),
            skip_reason=candidate.skip_reason,
        )
        for candidate in candidates
    ]
    return _select_candidates(
        candidates,
        selection_mode=selection_mode,
        tunnel_type=tunnel_type,
        limit=effective_limit,
    )


async def preview_insurance_tunnel_batch(
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
    selection_mode: str = "all",
    tunnel_type: Optional[str] = None,
) -> Dict[str, Any]:
    selection_mode = _normalize_selection_mode(selection_mode)
    tunnel_type = _normalize_tunnel_type(tunnel_type)
    effective_limit = _normalize_limit(limit, for_start=False)
    candidates = await load_insurance_tunnel_candidates(
        router_ids=router_ids,
        limit=effective_limit,
        selection_mode=selection_mode,
        tunnel_type=tunnel_type,
    )
    items = [_item_from_candidate(candidate) for candidate in candidates]
    return {
        "success": True,
        "applied": False,
        "options": {
            "router_ids": router_ids,
            "limit": effective_limit,
            "selection_mode": selection_mode,
            "tunnel_type": tunnel_type,
            "default_start_limit": DEFAULT_START_LIMIT,
            "max_limit": MAX_BATCH_LIMIT,
            "max_concurrency": MAX_BATCH_CONCURRENCY,
            "skips_recently_offline": True,
            "eligible_owner_subscription_statuses": sorted(ACTIVE_OWNER_STATUSES),
            "paid_owner_subscription_statuses": sorted(PAID_OWNER_STATUSES),
        },
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


async def get_latest_insurance_tunnel_items_by_router(
    router_ids: Optional[Iterable[int]] = None,
) -> Dict[int, Dict[str, Any]]:
    """Return the latest stored batch item per router without doing network I/O."""
    wanted = {int(router_id) for router_id in router_ids} if router_ids else None
    latest: Dict[int, Dict[str, Any]] = {}

    async with _jobs_lock:
        jobs = sorted(
            _jobs.values(),
            key=lambda job: job.get("updated_at") or job.get("created_at") or "",
            reverse=True,
        )
        for job in jobs:
            for item in job.get("items", []):
                router_id = item.get("router_id")
                if router_id is None:
                    continue
                router_id = int(router_id)
                if wanted is not None and router_id not in wanted:
                    continue
                if router_id in latest:
                    continue
                item_copy = dict(item)
                item_copy["job_id"] = job.get("job_id")
                item_copy["job_status"] = job.get("status")
                item_copy["job_updated_at"] = job.get("updated_at")
                latest[router_id] = item_copy
    return latest


async def start_insurance_tunnel_batch(
    *,
    router_ids: Optional[List[int]] = None,
    limit: Optional[int] = None,
    selection_mode: str = "all",
    tunnel_type: Optional[str] = None,
    max_concurrency: int = 2,
    force_rotate: bool = False,
) -> Dict[str, Any]:
    global _active_job_id

    selection_mode = _normalize_selection_mode(selection_mode)
    tunnel_type = _normalize_tunnel_type(tunnel_type)
    effective_limit = _normalize_limit(limit, for_start=True)
    candidates = await load_insurance_tunnel_candidates(
        router_ids=router_ids,
        limit=effective_limit,
        selection_mode=selection_mode,
        tunnel_type=tunnel_type,
        for_start=True,
    )
    max_concurrency = max(1, min(int(max_concurrency or 2), MAX_BATCH_CONCURRENCY))
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
            "limit": effective_limit,
            "selection_mode": selection_mode,
            "tunnel_type": tunnel_type,
            "max_concurrency": max_concurrency,
            "force_rotate": force_rotate,
            "skips_recently_offline": True,
            "eligible_owner_subscription_statuses": sorted(ACTIVE_OWNER_STATUSES),
            "paid_owner_subscription_statuses": sorted(PAID_OWNER_STATUSES),
            "default_start_limit": DEFAULT_START_LIMIT,
            "max_limit": MAX_BATCH_LIMIT,
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


def _short_text(value: Any, max_length: int = 160) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _verification_error(verification: Dict[str, Any]) -> str:
    ping_success = bool(verification.get("ping_success"))
    tcp_success = bool(verification.get("tcp_success"))
    parts = [
        f"ping={'ok' if ping_success else 'failed'}",
        f"tcp={'ok' if tcp_success else 'failed'}",
    ]
    tcp_error = _short_text(verification.get("tcp_error"))
    if tcp_error:
        parts.append(f"tcp_error={tcp_error}")
    if not ping_success:
        ping_error = _short_text(verification.get("ping_stderr") or verification.get("ping_stdout"))
        if ping_error:
            parts.append(f"ping_output={ping_error}")
    return f"Insurance tunnel applied but verification did not fully pass ({'; '.join(parts)})"


async def _process_candidate(
    job_id: str,
    candidate: InsuranceTunnelCandidate,
    force_rotate: bool,
) -> None:
    router_id = candidate.router.id
    if candidate.skip_reason:
        await _update_item(job_id, router_id, status="skipped", error=candidate.skip_reason, finished_at=_now_iso())
        return
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
    verification: Dict[str, Any] = {}
    verification_attempts = []
    verified = False
    for attempt in range(1, VERIFICATION_ATTEMPTS + 1):
        verification = await verify_insurance_router(candidate.backup_ip, port=candidate.router.port)
        verified = bool(verification.get("ping_success") and verification.get("tcp_success"))
        verification_attempts.append({
            "attempt": attempt,
            "verified": verified,
            "verification": verification,
        })
        if verified:
            break
        if attempt < VERIFICATION_ATTEMPTS:
            await _update_item(
                job_id,
                candidate.router.id,
                status="running",
                error=_verification_error(verification),
                verification=verification,
                verification_attempts=verification_attempts,
            )
            await asyncio.sleep(VERIFICATION_RETRY_DELAY_SECONDS)

    error = None if verified else _verification_error(verification)
    if verified:
        logger.info(
            "Insurance tunnel verified for router %s (%s -> %s) after %s attempt(s)",
            candidate.router.id,
            candidate.router.ip_address,
            candidate.backup_ip,
            len(verification_attempts),
        )
    else:
        logger.warning(
            "Insurance tunnel partial for router %s (%s -> %s) after %s attempt(s): %s; verification=%s",
            candidate.router.id,
            candidate.router.ip_address,
            candidate.backup_ip,
            len(verification_attempts),
            error,
            verification,
        )
    await _update_item(
        job_id,
        candidate.router.id,
        status="verified" if verified else "partial",
        manager=manager_result,
        router_actions=router_config.get("actions", []),
        verification=verification,
        verification_attempts=verification_attempts,
        finished_at=_now_iso(),
        error=error,
    )

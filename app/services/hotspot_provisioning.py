import asyncio
import functools
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable

from sqlalchemy import and_, or_, select, text

from app.config import settings
from app.db.database import async_session
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    Plan,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterAuthMethod,
)
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

HOTSPOT_PROVISIONING_TIMEOUT_SECONDS = 75
HOTSPOT_RETRY_STALE_IN_PROGRESS_SECONDS = 90
HOTSPOT_RETRY_BATCH_SIZE = 25
HOTSPOT_RETRY_MAX_ATTEMPTS = 5
HOTSPOT_RETRY_MAX_AGE = timedelta(hours=4)
HOTSPOT_VERIFY_REFRESH_WINDOW = timedelta(minutes=15)
HOTSPOT_RECENT_DELIVERY_WINDOW = timedelta(minutes=30)
HOTSPOT_ONLINE_POLL_INTERVAL_SECONDS = 3
HOTSPOT_ONLINE_POLL_TIMEOUT_SECONDS = 30

_hotspot_provision_pool = ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix="mikrotik-provision",
)


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def build_hotspot_payload(customer: Customer, plan: Plan, router: Router, comment: str) -> Dict[str, Any]:
    """Build the direct API payload used for hotspot bypass provisioning."""
    duration_unit = plan.duration_unit.value.upper()
    duration_value = plan.duration_value

    if duration_unit == "MINUTES":
        time_limit = f"{int(duration_value)}m"
    elif duration_unit == "HOURS":
        time_limit = f"{int(duration_value)}h"
    elif duration_unit == "DAYS":
        time_limit = f"{int(duration_value)}d"
    else:
        time_limit = f"{int(duration_value)}h"

    return {
        "mac_address": customer.mac_address,
        "username": customer.mac_address.replace(":", ""),
        "password": customer.mac_address.replace(":", ""),
        "time_limit": time_limit,
        "bandwidth_limit": f"{plan.speed}",
        "comment": comment,
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
    }


def _truncate(value: Any, limit: int = 255) -> str | None:
    if value is None:
        return None
    text_value = str(value)
    return text_value[:limit]


_IDEMPOTENT_MIKROTIK_ERRORS = (
    "already have user with this name",
    "such client already exists",
)


def _is_idempotent_success(error_msg: str | None) -> bool:
    """Return True if MikroTik error means the resource already exists."""
    if not error_msg:
        return False
    msg = error_msg.lower()
    return any(phrase in msg for phrase in _IDEMPOTENT_MIKROTIK_ERRORS)


def _extract_provisioning_error(result: Dict[str, Any]) -> str | None:
    """Promote MikroTik partial failures to a top-level error."""
    if not result:
        return "Empty provisioning result"

    if result.get("error"):
        return str(result["error"])

    profile_error = (result.get("profile_result") or {}).get("error")
    if profile_error:
        return f"profile_error: {profile_error}"

    user_error = (result.get("hotspot_user_result") or {}).get("error")
    if user_error and not _is_idempotent_success(user_error):
        return f"user_error: {user_error}"

    binding_error = (result.get("ip_binding_result") or {}).get("error")
    if binding_error and not _is_idempotent_success(binding_error):
        return f"binding_error: {binding_error}"

    return None


def derive_delivery_status(
    provisioning_state: ProvisioningState | str | None,
    online_state: ProvisioningOnlineState | str | None,
) -> str | None:
    provisioning_state_value = _enum_value(provisioning_state)
    online_state_value = _enum_value(online_state)

    if provisioning_state_value in {
        ProvisioningState.SCHEDULED.value,
        ProvisioningState.IN_PROGRESS.value,
        ProvisioningState.RETRY_PENDING.value,
    }:
        return "activating"

    if provisioning_state_value == ProvisioningState.ROUTER_UPDATED.value:
        if online_state_value == ProvisioningOnlineState.ONLINE.value:
            return "online"
        return "access_ready"

    if provisioning_state_value == ProvisioningState.FAILED.value:
        return "needs_attention"

    return None


def serialize_delivery_attempt(attempt: ProvisioningAttempt | None) -> Dict[str, Any] | None:
    if not attempt:
        return None

    return {
        "attempt_id": attempt.id,
        "delivery_status": derive_delivery_status(attempt.provisioning_state, attempt.online_state),
        "provisioning_state": _enum_value(attempt.provisioning_state),
        "online_state": _enum_value(attempt.online_state),
        "attempt_count": attempt.attempt_count,
        "last_error": attempt.last_error,
        "last_attempt_at": attempt.last_attempt_at.isoformat() if attempt.last_attempt_at else None,
        "last_online_at": attempt.last_online_at.isoformat() if attempt.last_online_at else None,
        "external_reference": attempt.external_reference,
    }


async def log_provisioning_event(
    customer_id: int,
    router_id: int | None,
    mac_address: str | None,
    action: str,
    status: str,
    details: str | None = None,
    error: str | None = None,
    attempt_id: int | None = None,
):
    """Persist direct API provisioning activity for later diagnosis and retries."""
    try:
        async with async_session() as db:
            await db.execute(
                text(
                    """
                    INSERT INTO provisioning_logs
                    (customer_id, router_id, attempt_id, mac_address, action, status, details, error, log_date)
                    VALUES (:customer_id, :router_id, :attempt_id, :mac_address, :action, :status, :details, :error, :log_date)
                    """
                ),
                {
                    "customer_id": customer_id,
                    "router_id": router_id,
                    "attempt_id": attempt_id,
                    "mac_address": mac_address,
                    "action": action,
                    "status": status,
                    "details": _truncate(details),
                    "error": _truncate(error),
                    "log_date": datetime.utcnow(),
                },
            )
            await db.commit()
    except Exception as exc:
        logger.warning("Failed to persist provisioning log for customer %s: %s", customer_id, exc)


async def get_or_create_provisioning_attempt(
    db,
    *,
    customer_id: int,
    router_id: int | None,
    mac_address: str | None,
    source_table: ProvisioningAttemptSource,
    source_pk: int,
    external_reference: str | None,
    entrypoint: ProvisioningAttemptEntrypoint,
) -> ProvisioningAttempt:
    attempt = (
        await db.execute(
            select(ProvisioningAttempt).where(
                ProvisioningAttempt.source_table == source_table,
                ProvisioningAttempt.source_pk == source_pk,
            )
        )
    ).scalar_one_or_none()

    normalized_mac = normalize_mac_address(mac_address) if mac_address else None
    now = datetime.utcnow()

    if attempt:
        attempt.customer_id = customer_id
        attempt.router_id = router_id
        attempt.mac_address = normalized_mac
        attempt.external_reference = external_reference
        attempt.entrypoint = entrypoint
        attempt.updated_at = now
        await db.flush()
        return attempt

    attempt = ProvisioningAttempt(
        customer_id=customer_id,
        router_id=router_id,
        mac_address=normalized_mac,
        source_table=source_table,
        source_pk=source_pk,
        external_reference=external_reference,
        entrypoint=entrypoint,
        provisioning_state=ProvisioningState.SCHEDULED,
        online_state=ProvisioningOnlineState.UNKNOWN,
        created_at=now,
        updated_at=now,
    )
    db.add(attempt)
    await db.flush()
    return attempt


async def schedule_provisioning_attempt(db, attempt: ProvisioningAttempt) -> ProvisioningAttempt:
    attempt.provisioning_state = ProvisioningState.SCHEDULED
    attempt.online_state = ProvisioningOnlineState.UNKNOWN
    attempt.last_error = None
    attempt.updated_at = datetime.utcnow()
    await db.flush()
    return attempt


async def get_recent_delivery_attempt_for_customer(
    db,
    customer_id: int,
    *,
    now: datetime | None = None,
) -> ProvisioningAttempt | None:
    now = now or datetime.utcnow()
    cutoff = now - HOTSPOT_RECENT_DELIVERY_WINDOW

    return (
        await db.execute(
            select(ProvisioningAttempt)
            .where(
                ProvisioningAttempt.customer_id == customer_id,
                ProvisioningAttempt.updated_at >= cutoff,
            )
            .order_by(ProvisioningAttempt.updated_at.desc(), ProvisioningAttempt.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def load_delivery_attempts_by_source(
    db,
    *,
    mpesa_ids: Iterable[int] | None = None,
    customer_payment_ids: Iterable[int] | None = None,
) -> Dict[tuple[str, int], ProvisioningAttempt]:
    mpesa_ids = [source_id for source_id in (mpesa_ids or []) if source_id is not None]
    customer_payment_ids = [source_id for source_id in (customer_payment_ids or []) if source_id is not None]

    predicates = []
    if mpesa_ids:
        predicates.append(
            and_(
                ProvisioningAttempt.source_table == ProvisioningAttemptSource.MPESA_TRANSACTION,
                ProvisioningAttempt.source_pk.in_(mpesa_ids),
            )
        )
    if customer_payment_ids:
        predicates.append(
            and_(
                ProvisioningAttempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                ProvisioningAttempt.source_pk.in_(customer_payment_ids),
            )
        )

    if not predicates:
        return {}

    attempts = (
        await db.execute(
            select(ProvisioningAttempt).where(or_(*predicates))
        )
    ).scalars().all()

    return {
        (_enum_value(attempt.source_table), attempt.source_pk): attempt
        for attempt in attempts
    }


async def get_provisioning_attempt_for_source(
    db,
    *,
    source_table: ProvisioningAttemptSource,
    source_pk: int,
) -> ProvisioningAttempt | None:
    return (
        await db.execute(
            select(ProvisioningAttempt).where(
                ProvisioningAttempt.source_table == source_table,
                ProvisioningAttempt.source_pk == source_pk,
            )
        )
    ).scalar_one_or_none()


def _verify_hotspot_configuration(api: MikroTikAPI, hotspot_payload: Dict[str, Any]) -> Dict[str, Any]:
    username = hotspot_payload["username"]
    mac_address = hotspot_payload["mac_address"]

    hotspot_user = api.get_hotspot_user_by_name(username)
    if hotspot_user.get("error"):
        return {"error": f"Hotspot user lookup failed: {hotspot_user['error']}"}
    if not hotspot_user.get("found"):
        return {"error": f"Hotspot user {username} not found after provisioning"}

    ip_binding = api.get_ip_binding_by_mac(mac_address)
    if ip_binding.get("error"):
        return {"error": f"IP binding lookup failed: {ip_binding['error']}"}
    if not ip_binding.get("found"):
        return {"error": f"IP binding for {mac_address} not found after provisioning"}

    binding_type = str((ip_binding.get("data") or {}).get("type", "")).lower()
    if binding_type != "bypassed":
        return {"error": f"IP binding for {mac_address} is {binding_type or 'unknown'} instead of bypassed"}

    return {
        "success": True,
        "hotspot_user": hotspot_user.get("data"),
        "ip_binding": ip_binding.get("data"),
    }


def _poll_online_state(api: MikroTikAPI, mac_address: str) -> Dict[str, Any]:
    deadline = time.monotonic() + HOTSPOT_ONLINE_POLL_TIMEOUT_SECONDS
    last_result: Dict[str, Any] = {
        "success": True,
        "online": False,
        "source": None,
        "details": None,
    }

    while True:
        state_result = api.get_online_state_by_mac(mac_address)
        if state_result.get("success"):
            last_result = state_result
            if state_result.get("online"):
                return state_result
        else:
            last_result = state_result

        if time.monotonic() >= deadline:
            break

        time.sleep(HOTSPOT_ONLINE_POLL_INTERVAL_SECONDS)

    return last_result


def _call_mikrotik_bypass_sync(hotspot_payload: dict, verify_only: bool = False) -> dict:
    """
    Run MikroTik direct API work in a dedicated thread pool.

    Full provisioning:
    - writes hotspot user / bypass binding / queue
    - verifies hotspot user and bypass binding exist
    - polls router-side online state

    Verify-only refresh:
    - skips writes
    - refreshes router-side online state only
    """
    router_ip = hotspot_payload.get("router_ip", settings.MIKROTIK_HOST)
    router_username = hotspot_payload.get("router_username", settings.MIKROTIK_USERNAME)
    router_password = hotspot_payload.get("router_password", settings.MIKROTIK_PASSWORD)
    router_port = hotspot_payload.get("router_port", settings.MIKROTIK_PORT)

    logger.info("[PROVISION] Connecting to MikroTik router at %s:%s", router_ip, router_port)

    api = MikroTikAPI(
        router_ip,
        router_username,
        router_password,
        router_port,
        timeout=15,
        connect_timeout=5,
    )

    if not api.connect():
        logger.error("[PROVISION] Failed to connect to MikroTik router at %s", router_ip)
        return {"error": "Failed to connect"}

    try:
        if verify_only:
            online_result = _poll_online_state(api, hotspot_payload["mac_address"])
            return {
                "success": True,
                "verify_only": True,
                "online_result": online_result,
                "online_state": (
                    ProvisioningOnlineState.ONLINE.value
                    if online_result.get("online")
                    else ProvisioningOnlineState.OFFLINE.value
                ),
            }

        provision_result = api.add_customer_bypass_mode(
            hotspot_payload["mac_address"],
            hotspot_payload["username"],
            hotspot_payload["password"],
            hotspot_payload["time_limit"],
            hotspot_payload["bandwidth_limit"],
            hotspot_payload["comment"],
            router_ip,
            router_username,
            router_password,
        )

        logger.info("[PROVISION] MikroTik API response: %s", provision_result)

        provisioning_error = _extract_provisioning_error(provision_result)
        if provisioning_error:
            return {
                "success": False,
                "error": provisioning_error,
                "provision_result": provision_result,
            }

        verification_result = _verify_hotspot_configuration(api, hotspot_payload)
        if verification_result.get("error"):
            return {
                "success": False,
                "verification_error": verification_result["error"],
                "provision_result": provision_result,
            }

        online_result = _poll_online_state(api, hotspot_payload["mac_address"])
        return {
            "success": True,
            "provision_result": provision_result,
            "verification_result": verification_result,
            "online_result": online_result,
            "online_state": (
                ProvisioningOnlineState.ONLINE.value
                if online_result.get("online")
                else ProvisioningOnlineState.OFFLINE.value
            ),
        }
    finally:
        api.disconnect()


async def _run_mikrotik_operation(hotspot_payload: Dict[str, Any], verify_only: bool = False) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(
            _hotspot_provision_pool,
            functools.partial(_call_mikrotik_bypass_sync, hotspot_payload, verify_only),
        ),
        timeout=HOTSPOT_PROVISIONING_TIMEOUT_SECONDS,
    )


def _attempt_should_be_terminal(attempt: ProvisioningAttempt, now: datetime) -> bool:
    return (
        attempt.attempt_count >= HOTSPOT_RETRY_MAX_ATTEMPTS
        or attempt.created_at <= (now - HOTSPOT_RETRY_MAX_AGE)
    )


async def provision_hotspot_customer(
    customer_id: int,
    router_id: int | None,
    hotspot_payload: Dict[str, Any],
    action: str = "hotspot_payment",
    attempt_id: int | None = None,
    verify_only: bool = False,
) -> Dict[str, Any]:
    """Provision a hotspot customer and persist the result for later reconciliation."""
    router_ip = hotspot_payload.get("router_ip")
    mac_address = hotspot_payload.get("mac_address")
    now = datetime.utcnow()

    attempt: ProvisioningAttempt | None = None

    if attempt_id is not None:
        async with async_session() as db:
            attempt = await db.get(ProvisioningAttempt, attempt_id)
            if attempt:
                attempt.customer_id = customer_id
                attempt.router_id = router_id
                attempt.mac_address = normalize_mac_address(mac_address) if mac_address else None
                if verify_only:
                    attempt.updated_at = now
                else:
                    attempt.provisioning_state = ProvisioningState.IN_PROGRESS
                    attempt.last_attempt_at = now
                    attempt.attempt_count += 1
                    attempt.last_error = None
                    attempt.updated_at = now
                await db.commit()

    try:
        result = await _run_mikrotik_operation(hotspot_payload, verify_only=verify_only)
    except asyncio.TimeoutError:
        result = {
            "success": False,
            "error": f"Provisioning timed out after {HOTSPOT_PROVISIONING_TIMEOUT_SECONDS}s",
        }
    except Exception as exc:
        result = {"success": False, "error": str(exc)}

    if verify_only:
        verify_succeeded = not bool(result.get("error"))
        online_state_value = (
            ProvisioningOnlineState.ONLINE.value
            if (result.get("online_result") or {}).get("online")
            else ProvisioningOnlineState.OFFLINE.value
        )

        if attempt_id is not None:
            async with async_session() as db:
                attempt = await db.get(ProvisioningAttempt, attempt_id)
                if attempt:
                    attempt.updated_at = datetime.utcnow()
                    if verify_succeeded:
                        attempt.online_state = ProvisioningOnlineState(online_state_value)
                    if verify_succeeded and online_state_value == ProvisioningOnlineState.ONLINE.value:
                        attempt.last_online_at = datetime.utcnow()
                    await db.commit()
                    await db.refresh(attempt)

        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac_address,
            action=action,
            status="verify_success" if result.get("success") else "verify_failed",
            details=f"router={router_ip}; online_state={online_state_value if verify_succeeded else 'unknown'}",
            error=None if verify_succeeded else result.get("error"),
            attempt_id=attempt_id,
        )

        result["success"] = verify_succeeded
        result["provisioning_error"] = None
        result["delivery"] = serialize_delivery_attempt(attempt)
        return result

    provisioning_error = result.get("error") or result.get("verification_error")

    if provisioning_error:
        final_state = ProvisioningState.RETRY_PENDING
        refreshed_attempt = None

        if attempt_id is not None:
            async with async_session() as db:
                refreshed_attempt = await db.get(ProvisioningAttempt, attempt_id)
                if refreshed_attempt:
                    if _attempt_should_be_terminal(refreshed_attempt, datetime.utcnow()):
                        final_state = ProvisioningState.FAILED
                    refreshed_attempt.provisioning_state = final_state
                    refreshed_attempt.online_state = ProvisioningOnlineState.UNKNOWN
                    refreshed_attempt.last_error = _truncate(provisioning_error)
                    refreshed_attempt.updated_at = datetime.utcnow()
                    await db.commit()
                    await db.refresh(refreshed_attempt)

        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac_address,
            action=action,
            status="failed" if final_state == ProvisioningState.FAILED else "retry_pending",
            details=f"router={router_ip}",
            error=provisioning_error,
            attempt_id=attempt_id,
        )
        logger.error(
            "[PROVISION] Hotspot provisioning failed for customer %s on router %s: %s",
            customer_id,
            router_ip,
            provisioning_error,
        )

        result["success"] = False
        result["provisioning_error"] = provisioning_error
        result["delivery"] = serialize_delivery_attempt(refreshed_attempt)
        return result

    provision_result = result.get("provision_result") or {}
    queue_result = provision_result.get("queue_result", {})
    queue_state = "pending" if queue_result.get("pending") else "ready"
    kick_result = provision_result.get("kick_result", {})
    hosts_kicked = kick_result.get("hosts_removed", 0)
    sessions_kicked = kick_result.get("sessions_removed", 0)
    online_state_value = result.get("online_state") or ProvisioningOnlineState.OFFLINE.value

    refreshed_attempt = None
    if attempt_id is not None:
        async with async_session() as db:
            refreshed_attempt = await db.get(ProvisioningAttempt, attempt_id)
            if refreshed_attempt:
                refreshed_attempt.provisioning_state = ProvisioningState.ROUTER_UPDATED
                refreshed_attempt.online_state = ProvisioningOnlineState(online_state_value)
                refreshed_attempt.router_updated_at = datetime.utcnow()
                refreshed_attempt.last_error = None
                refreshed_attempt.updated_at = datetime.utcnow()
                if online_state_value == ProvisioningOnlineState.ONLINE.value:
                    refreshed_attempt.last_online_at = datetime.utcnow()
                await db.commit()
                await db.refresh(refreshed_attempt)

    await log_provisioning_event(
        customer_id=customer_id,
        router_id=router_id,
        mac_address=mac_address,
        action=action,
        status="success",
        details=(
            f"router={router_ip}; queue={queue_state}; "
            f"kicked_hosts={hosts_kicked}; kicked_sessions={sessions_kicked}; "
            f"online_state={online_state_value}"
        ),
        attempt_id=attempt_id,
    )
    logger.info(
        "[PROVISION] Hotspot provisioning succeeded for customer %s on router %s (kicked %d host(s), %d session(s), online=%s)",
        customer_id,
        router_ip,
        hosts_kicked,
        sessions_kicked,
        online_state_value,
    )

    result["success"] = True
    result["provisioning_error"] = None
    result["delivery"] = serialize_delivery_attempt(refreshed_attempt)
    return result


async def retry_pending_hotspot_provisioning_background():
    """
    Retry or verify direct API hotspot delivery using provisioning attempts.

    Rules:
    - scheduled or stale in_progress older than 90s: full provisioning
    - retry_pending while attempts < 5 and age < 4h: full provisioning
    - router_updated with online_state != online within 15m: verify-only refresh
    - after 5 attempts or 4h age: mark failed

    Safety net:
    - recent completed DIRECT_API hotspot M-Pesa transactions with no attempt
      get an attempt created so payment success never remains invisible.
    """
    try:
        now = datetime.utcnow()
        stale_cutoff = now - timedelta(seconds=HOTSPOT_RETRY_STALE_IN_PROGRESS_SECONDS)
        verify_cutoff = now - HOTSPOT_VERIFY_REFRESH_WINDOW
        expiry_cutoff = now - HOTSPOT_RETRY_MAX_AGE

        work_items: list[tuple[ProvisioningAttempt, Customer, Plan, Router, bool]] = []
        queued_attempt_ids: set[int] = set()

        async with async_session() as db:
            terminal_candidates = (
                await db.execute(
                    select(ProvisioningAttempt).where(
                        ProvisioningAttempt.provisioning_state.in_(
                            [
                                ProvisioningState.SCHEDULED,
                                ProvisioningState.IN_PROGRESS,
                                ProvisioningState.RETRY_PENDING,
                            ]
                        ),
                        or_(
                            ProvisioningAttempt.attempt_count >= HOTSPOT_RETRY_MAX_ATTEMPTS,
                            ProvisioningAttempt.created_at <= expiry_cutoff,
                        ),
                    )
                )
            ).scalars().all()

            for attempt in terminal_candidates:
                attempt.provisioning_state = ProvisioningState.FAILED
                attempt.last_error = attempt.last_error or "Provisioning retry window exhausted"
                attempt.updated_at = now

            if terminal_candidates:
                await db.commit()

            attempt_rows = (
                await db.execute(
                    select(ProvisioningAttempt, Customer, Plan, Router)
                    .join(Customer, ProvisioningAttempt.customer_id == Customer.id)
                    .join(Plan, Customer.plan_id == Plan.id)
                    .join(Router, Customer.router_id == Router.id)
                    .where(
                        Customer.status == CustomerStatus.ACTIVE,
                        Customer.mac_address.isnot(None),
                        Customer.expiry.isnot(None),
                        Customer.expiry > now,
                        Plan.connection_type == ConnectionType.HOTSPOT,
                        Router.auth_method == RouterAuthMethod.DIRECT_API,
                        or_(
                            ProvisioningAttempt.provisioning_state == ProvisioningState.SCHEDULED,
                            and_(
                                ProvisioningAttempt.provisioning_state == ProvisioningState.IN_PROGRESS,
                                or_(
                                    ProvisioningAttempt.last_attempt_at.is_(None),
                                    ProvisioningAttempt.last_attempt_at <= stale_cutoff,
                                ),
                            ),
                            and_(
                                ProvisioningAttempt.provisioning_state == ProvisioningState.RETRY_PENDING,
                                ProvisioningAttempt.attempt_count < HOTSPOT_RETRY_MAX_ATTEMPTS,
                                ProvisioningAttempt.created_at > expiry_cutoff,
                            ),
                            and_(
                                ProvisioningAttempt.provisioning_state == ProvisioningState.ROUTER_UPDATED,
                                ProvisioningAttempt.online_state != ProvisioningOnlineState.ONLINE,
                                ProvisioningAttempt.created_at > verify_cutoff,
                            ),
                        ),
                    )
                    .order_by(ProvisioningAttempt.updated_at.asc(), ProvisioningAttempt.id.asc())
                    .limit(HOTSPOT_RETRY_BATCH_SIZE)
                )
            ).all()

            for attempt, customer, plan, router in attempt_rows:
                verify_only = (
                    attempt.provisioning_state == ProvisioningState.ROUTER_UPDATED
                    and attempt.online_state != ProvisioningOnlineState.ONLINE
                    and attempt.created_at > verify_cutoff
                )
                work_items.append((attempt, customer, plan, router, verify_only))
                queued_attempt_ids.add(attempt.id)

            remaining_capacity = max(HOTSPOT_RETRY_BATCH_SIZE - len(work_items), 0)
            if remaining_capacity:
                safety_rows = (
                    await db.execute(
                        select(MpesaTransaction, Customer, Plan, Router)
                        .join(Customer, MpesaTransaction.customer_id == Customer.id)
                        .join(Plan, Customer.plan_id == Plan.id)
                        .join(Router, Customer.router_id == Router.id)
                        .outerjoin(
                            ProvisioningAttempt,
                            and_(
                                ProvisioningAttempt.source_table == ProvisioningAttemptSource.MPESA_TRANSACTION,
                                ProvisioningAttempt.source_pk == MpesaTransaction.id,
                            ),
                        )
                        .where(
                            MpesaTransaction.status == MpesaTransactionStatus.completed,
                            MpesaTransaction.created_at >= expiry_cutoff,
                            ProvisioningAttempt.id.is_(None),
                            Customer.status == CustomerStatus.ACTIVE,
                            Customer.mac_address.isnot(None),
                            Customer.expiry.isnot(None),
                            Customer.expiry > now,
                            Plan.connection_type == ConnectionType.HOTSPOT,
                            Router.auth_method == RouterAuthMethod.DIRECT_API,
                        )
                        .order_by(MpesaTransaction.created_at.asc(), MpesaTransaction.id.asc())
                        .limit(remaining_capacity)
                    )
                ).all()

                for txn, customer, plan, router in safety_rows:
                    attempt = await get_or_create_provisioning_attempt(
                        db,
                        customer_id=customer.id,
                        router_id=router.id,
                        mac_address=customer.mac_address,
                        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION,
                        source_pk=txn.id,
                        external_reference=txn.checkout_request_id,
                        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
                    )
                    await schedule_provisioning_attempt(db, attempt)
                    work_items.append((attempt, customer, plan, router, False))
                    queued_attempt_ids.add(attempt.id)

                if safety_rows:
                    await db.commit()

        if not work_items:
            logger.debug("[PROVISION-RETRY] No direct hotspot delivery attempts need work")
            return

        logger.warning("[PROVISION-RETRY] Processing %d direct hotspot delivery attempt(s)", len(work_items))

        for attempt, customer, plan, router, verify_only in work_items:
            if attempt.id in queued_attempt_ids:
                hotspot_payload = build_hotspot_payload(
                    customer,
                    plan,
                    router,
                    comment=(
                        f"Verify direct hotspot delivery for {customer.name}"
                        if verify_only
                        else f"Retry provisioning for {customer.name}"
                    ),
                )
                await provision_hotspot_customer(
                    customer_id=customer.id,
                    router_id=router.id,
                    hotspot_payload=hotspot_payload,
                    action="hotspot_retry_verify" if verify_only else "hotspot_retry",
                    attempt_id=attempt.id,
                    verify_only=verify_only,
                )

    except Exception as exc:
        logger.error("[PROVISION-RETRY] Background retry job failed: %s", exc)

import asyncio
import functools
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable

from sqlalchemy import and_, not_, or_, select, text

from app.config import settings
from app.db.database import async_session, db_pool_snapshot
from app.services.router_availability import record_router_availability
from app.db.models import (
    DELIVERED_VIA_CHECKIN,
    DELIVERED_VIA_OBSERVED,
    DELIVERED_VIA_PUSH,
    ConnectionType,
    Customer,
    CustomerStatus,
    MpesaTransaction,
    MpesaTransactionStatus,
    Plan,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterAuthMethod,
)
from app.services.mikrotik_api import LANE_PAYMENT, MikroTikAPI, normalize_mac_address
from app.services.provisioning_retry_policy import (
    PAID_PROVISIONING_RETRY_MAX_ATTEMPTS,
    retry_due_clause,
    retryable_connectivity_error_clause,
)

logger = logging.getLogger(__name__)

HOTSPOT_PROVISIONING_TIMEOUT_SECONDS = 75
HOTSPOT_RETRY_STALE_IN_PROGRESS_SECONDS = 90
HOTSPOT_RETRY_BATCH_SIZE = 25
HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS = 4
HOTSPOT_RETRY_MAX_ATTEMPTS = PAID_PROVISIONING_RETRY_MAX_ATTEMPTS
HOTSPOT_RETRY_MAX_AGE = timedelta(hours=4)
HOTSPOT_VERIFY_REFRESH_WINDOW = timedelta(minutes=15)
HOTSPOT_RECENT_DELIVERY_WINDOW = timedelta(minutes=30)
HOTSPOT_ONLINE_POLL_INTERVAL_SECONDS = 2
HOTSPOT_ONLINE_POLL_TIMEOUT_SECONDS = 8
HOTSPOT_RETRY_DB_BUSY_THRESHOLD_PERCENT = 60

_hotspot_provision_pool = ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix="mikrotik-provision",
)


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _retry_db_pool_is_busy() -> bool:
    snapshot = db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    if isinstance(checked_out_percent, (int, float)) and checked_out_percent >= HOTSPOT_RETRY_DB_BUSY_THRESHOLD_PERCENT:
        logger.warning(
            "[PROVISION-RETRY] Skipping background retry because DB pool is busy: "
            "checked_out=%s/%s (%.2f%%), status=%s",
            snapshot.get("checked_out"),
            snapshot.get("configured_max_app_connections"),
            checked_out_percent,
            snapshot.get("status"),
        )
        return True
    return False


def _hotspot_time_limit_for_customer(customer: Customer, plan: Plan) -> str:
    if customer.subscription_owner_id and customer.expiry:
        remaining_seconds = int((customer.expiry - datetime.utcnow()).total_seconds())
        remaining_minutes = max(1, (remaining_seconds + 59) // 60)
        return f"{remaining_minutes}m"

    duration_unit = plan.duration_unit.value.upper()
    duration_value = plan.duration_value

    if duration_unit == "MINUTES":
        return f"{int(duration_value)}m"
    if duration_unit == "HOURS":
        return f"{int(duration_value)}h"
    if duration_unit == "DAYS":
        return f"{int(duration_value)}d"
    return f"{int(duration_value)}h"


def build_hotspot_payload(customer: Customer, plan: Plan, router: Router, comment: str) -> Dict[str, Any]:
    """Build the direct API payload used for hotspot bypass provisioning."""
    time_limit = _hotspot_time_limit_for_customer(customer, plan)

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
        # Multi-WAN load balancing: bypassed customers only balance while
        # listed in LB_PAID, so provisioning adds the entry when LB is on.
        "lb_enabled": bool(getattr(router, "lb_enabled", False)),
        "customer_expiry": customer.expiry,
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

    queue_result = result.get("queue_result") or {}
    queue_error = queue_result.get("error")
    if queue_error:
        return f"queue_error: {queue_error}"

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


def _is_queue_pending_error(error: str | None) -> bool:
    return bool(error and str(error).lower().startswith("queue_pending:"))


def serialize_delivery_attempt(attempt: ProvisioningAttempt | None) -> Dict[str, Any] | None:
    if not attempt:
        return None

    provisioning_state = _enum_value(attempt.provisioning_state)
    online_state = _enum_value(attempt.online_state)
    last_error = attempt.last_error

    if _is_queue_pending_error(last_error):
        provisioning_state = ProvisioningState.ROUTER_UPDATED.value
        if online_state == ProvisioningOnlineState.UNKNOWN.value:
            online_state = ProvisioningOnlineState.OFFLINE.value
        last_error = None
    delivery_status = derive_delivery_status(provisioning_state, online_state)

    return {
        "attempt_id": attempt.id,
        "delivery_status": delivery_status,
        "provisioning_state": provisioning_state,
        "online_state": online_state,
        "attempt_count": attempt.attempt_count,
        "last_error": last_error,
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
    _note_attempt_for_checkin(router_id, entrypoint)

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


def _note_attempt_for_checkin(router_id: int | None, entrypoint) -> None:
    """A customer-waiting attempt exists: tell the router check-in (in memory).

    Every hotspot payment path (STK callback, reconciliation, vouchers,
    device pairing, the retry job's safety net) creates its attempt here, so
    none of them can forget it. Never raises: it must not touch the payment.
    """
    try:
        from app.services.checkin_delivery import note_attempt_created

        note_attempt_created(router_id, entrypoint)
    except Exception:  # pragma: no cover - defensive
        pass


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
        lane=LANE_PAYMENT,
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
            expiry=hotspot_payload.get("customer_expiry"),
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

        # Load-balancing hook: the bypass binding is in place, so list the
        # client in LB_PAID (with a timeout capped to expiry) while the API
        # connection is still usable. MUST NOT fail provisioning — a paid
        # customer missing from LB_PAID just doesn't balance, which is benign.
        lb_paid_result = None
        if hotspot_payload.get("lb_enabled"):
            try:
                from app.services.mikrotik_lb import lb_add_paid_entry

                lb_paid_result = lb_add_paid_entry(
                    api,
                    hotspot_payload["mac_address"],
                    hotspot_payload.get("customer_expiry"),
                )
                if not lb_paid_result.get("ok"):
                    logger.warning(
                        "[PROVISION] LB_PAID add skipped/failed for %s: %s",
                        hotspot_payload["mac_address"],
                        lb_paid_result.get("reason"),
                    )
            except Exception as lb_exc:
                logger.warning(
                    "[PROVISION] LB_PAID add crashed for %s (ignored): %s",
                    hotspot_payload["mac_address"],
                    lb_exc,
                )

        online_result = _poll_online_state(api, hotspot_payload["mac_address"])
        return {
            "success": True,
            "provision_result": provision_result,
            "verification_result": verification_result,
            "lb_paid_result": lb_paid_result,
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


def _delivered_by_checkin(attempt: ProvisioningAttempt) -> bool:
    """The router's check-in already confirmed this customer on the router,
    whether it added the binding itself ('checkin') or only saw it ('observed')."""
    return (
        _enum_value(attempt.provisioning_state) == ProvisioningState.ROUTER_UPDATED.value
        and attempt.delivered_via in (DELIVERED_VIA_CHECKIN, DELIVERED_VIA_OBSERVED)
    )


async def _persist_provisioning_result(
    *,
    result: Dict[str, Any],
    verify_only: bool,
    customer_id: int,
    router_id: int | None,
    router_ip: str | None,
    mac_address: str | None,
    action: str,
    attempt_id: int | None,
    hotspot_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist the MikroTik operation result to the provisioning attempt.

    Extracted so provision_hotspot_customer can wrap this in a safety
    try/except and recover stuck IN_PROGRESS attempts on any crash.
    """
    if verify_only:
        verify_succeeded = not bool(result.get("error"))
        online_state_value = (
            ProvisioningOnlineState.ONLINE.value
            if (result.get("online_result") or {}).get("online")
            else ProvisioningOnlineState.OFFLINE.value
        )

        attempt = None
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
                if refreshed_attempt and _delivered_by_checkin(refreshed_attempt):
                    # The router's check-in showed this customer present while
                    # this push was in flight. A late push failure must not
                    # drag a delivered payment back into retry (nor into the
                    # overload alert's failure count): leave the row as is.
                    final_state = ProvisioningState.ROUTER_UPDATED
                    await db.commit()
                elif refreshed_attempt:
                    if _attempt_should_be_terminal(refreshed_attempt, datetime.utcnow()):
                        final_state = ProvisioningState.FAILED
                    refreshed_attempt.provisioning_state = final_state
                    refreshed_attempt.online_state = ProvisioningOnlineState.UNKNOWN
                    refreshed_attempt.last_error = _truncate(provisioning_error)
                    refreshed_attempt.updated_at = datetime.utcnow()
                    await db.commit()
                    await db.refresh(refreshed_attempt)

        if final_state == ProvisioningState.FAILED:
            failure_status = "failed"
        elif final_state == ProvisioningState.ROUTER_UPDATED:
            failure_status = "push_failed_after_checkin_delivery"
        else:
            failure_status = "retry_pending"
        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac_address,
            action=action,
            status=failure_status,
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

        if router_id:
            try:
                async with async_session() as avail_db:
                    is_online = "connect" not in provisioning_error.lower()
                    await record_router_availability(avail_db, router_id, is_online, "provisioning")
                    await avail_db.commit()
            except Exception:
                pass

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
                # First path to land wins: a check-in may have confirmed the
                # customer while this (slow) push was still in flight.
                if refreshed_attempt.delivered_via is None:
                    refreshed_attempt.delivered_via = DELIVERED_VIA_PUSH
                if refreshed_attempt.access_seen_at is None:
                    refreshed_attempt.access_seen_at = refreshed_attempt.router_updated_at
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
        "[PROVISION] Hotspot provisioning succeeded for customer %s on router %s "
        "(kicked %d host(s), %d session(s), online=%s)",
        customer_id,
        router_ip,
        hosts_kicked,
        sessions_kicked,
        online_state_value,
    )

    if router_id:
        try:
            async with async_session() as avail_db:
                await record_router_availability(avail_db, router_id, True, "provisioning")
                await avail_db.commit()
        except Exception:
            pass

    result["success"] = True
    result["provisioning_error"] = None
    result["delivery"] = serialize_delivery_attempt(refreshed_attempt)
    return result


# ---------------------------------------------------------------------------
# checkin_only routers (push-vs-check-in A/B): the payment-time push is left
# to the router's check-in, with a timed push fallback as the safety net.
# ---------------------------------------------------------------------------

# Push paths that must never be deferred: they ARE the fallback/backstop.
CHECKIN_FALLBACK_ACTION = "checkin_only_fallback"
# checkin_only payment whose MAC is already bound on the router (renewal while
# still bound): the applier never edits a binding it did not add, so the push
# (which updates the EXP tag and queue rate) runs at once instead of waiting
# for the fallback. Same string as checkin_delivery.ACTION_RENEWAL_HANDOFF,
# which the A/B metrics count.
CHECKIN_HANDOFF_ACTION = "checkin_only_renewal_handoff"
# The channel stopped being able to deliver while an attempt was waiting
# (kill switch, shadow mode, router dropped from a list): push at once.
CHECKIN_HANDBACK_ACTION = "checkin_only_handback"
_NEVER_DEFER_ACTIONS = frozenset({
    "hotspot_retry", "hotspot_retry_verify",
    CHECKIN_FALLBACK_ACTION, CHECKIN_HANDOFF_ACTION, CHECKIN_HANDBACK_ACTION,
})
# The retry job leaves a deferred attempt alone a little past the fallback
# deadline so the in-process fallback timer gets first go; after a restart
# (timer lost) the retry job re-arms the timer, then is the fallback itself.
CHECKIN_FALLBACK_RETRY_SLACK_SECONDS = 30
# How often a waiting timer checks that the check-in can still deliver.
CHECKIN_HANDBACK_POLL_SECONDS = 5

_fallback_tasks: set = set()
# attempt id -> Event that wakes its fallback timer early (a hand-off).
_fallback_waiters: dict[int, asyncio.Event] = {}
_fallback_wake_reason: dict[int, str] = {}
# attempt ids a fallback/hand-off push is running for right now.
_push_inflight: set[int] = set()
# Returned by _maybe_defer_to_checkin: push now, as a renewal hand-off.
_HANDOFF = object()

_WAITING_PUSH_DETAILS = {
    CHECKIN_FALLBACK_ACTION: "checkin_only: check-in did not deliver within the fallback window; pushing",
    CHECKIN_HANDOFF_ACTION: (
        "checkin_only: MAC already bound on the router (renewal while bound); "
        "the check-in cannot update it, pushing now"
    ),
    CHECKIN_HANDBACK_ACTION: (
        "checkin_only: check-in channel can no longer deliver (kill switch, mode or "
        "router list changed); pushing now"
    ),
}


def _bound_marker_log(
    *,
    customer_id: int,
    router_id: int | None,
    attempt_id: int,
    mac_address: str | None,
    now: datetime,
) -> ProvisioningLog | None:
    """The A/B's "new device vs already bound" marker, from the router's
    latest check-in report (memory, no I/O). None when not a pilot router or
    no fresh report: the metrics then count the attempt as ``unknown``."""
    from app.services import checkin_delivery

    try:
        if router_id is None or int(router_id) not in checkin_delivery.checkin_router_ids():
            return None
        bound = checkin_delivery.mac_bound_on_router(router_id, mac_address)
    except Exception:  # pragma: no cover - defensive
        return None
    if bound is None:
        return None
    return ProvisioningLog(
        customer_id=customer_id,
        router_id=router_id,
        attempt_id=attempt_id,
        mac_address=mac_address,
        action=checkin_delivery.ACTION_BOUND_AT_PAYMENT,
        status=checkin_delivery.BOUND_STATUS_BOUND if bound else checkin_delivery.BOUND_STATUS_NOT_BOUND,
        details="MAC in the router's latest check-in report" if bound else "MAC not in the router's latest check-in report",
        log_date=now,
    )


def _checkin_only_decision(
    attempt: ProvisioningAttempt,
    router_id: int | None,
    router_auth_method: Any,
    action: str,
    now: datetime,
) -> tuple[str, float] | None:
    """Should this push be left to the check-in? Pure; no I/O.

    Returns ``("defer", seconds_until_fallback)``, ``("delivered", 0)`` when
    the check-in already delivered this attempt inside the window, or None to
    push as usual.
    """
    from app.services import checkin_delivery

    if router_id is None or action in _NEVER_DEFER_ACTIONS:
        return None
    if not checkin_delivery.checkin_only_active(router_id):
        return None
    if _enum_value(router_auth_method) != RouterAuthMethod.DIRECT_API.value:
        return None  # RADIUS routers get no A lines; the check-in cannot deliver
    if attempt.router_id != router_id:
        return None
    if _enum_value(attempt.entrypoint) not in checkin_delivery.CHECKIN_DEFERRABLE_ENTRYPOINTS:
        return None
    if attempt.created_at is None:
        return None
    remaining = checkin_delivery.checkin_only_fallback_seconds() - (now - attempt.created_at).total_seconds()
    if remaining <= 0:
        return None  # the check-in had its window: push now
    state = _enum_value(attempt.provisioning_state)
    if state == ProvisioningState.ROUTER_UPDATED.value and attempt.delivered_via is not None:
        return ("delivered", 0.0)
    if state == ProvisioningState.SCHEDULED.value:
        return ("defer", remaining)
    return None


def _spawn_checkin_fallback(
    delay: float,
    customer_id: int,
    router_id: int,
    hotspot_payload: Dict[str, Any] | None,
    attempt_id: int,
) -> None:
    if attempt_id in _fallback_waiters:
        return  # already armed (a duplicate payment-time call, or a re-arm)
    _fallback_waiters[attempt_id] = asyncio.Event()
    task = asyncio.create_task(
        _checkin_only_fallback_after(delay, customer_id, router_id, hotspot_payload, attempt_id)
    )
    _fallback_tasks.add(task)
    task.add_done_callback(_fallback_tasks.discard)


async def _wait_for_fallback(delay: float, router_id: int, attempt_id: int) -> str:
    """Sleep until the fallback deadline, a hand-off request, or hand-back.

    Returns the push action to run. No DB session is held while waiting. The
    hand-back check is pure memory (settings), every few seconds.
    """
    from app.services import checkin_delivery

    event = _fallback_waiters.setdefault(attempt_id, asyncio.Event())
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, delay)
    while True:
        if event.is_set():
            return _fallback_wake_reason.pop(attempt_id, CHECKIN_HANDOFF_ACTION)
        remaining = deadline - loop.time()
        if remaining <= 0:
            return CHECKIN_FALLBACK_ACTION
        try:
            await asyncio.wait_for(event.wait(), timeout=min(remaining, CHECKIN_HANDBACK_POLL_SECONDS))
        except asyncio.TimeoutError:
            if not checkin_delivery.checkin_only_active(router_id):
                return CHECKIN_HANDBACK_ACTION


async def _checkin_only_fallback_after(
    delay: float,
    customer_id: int,
    router_id: int,
    hotspot_payload: Dict[str, Any] | None,
    attempt_id: int,
) -> Dict[str, Any] | None:
    """The safety net: push if the check-in has not delivered by the deadline.

    Also woken early by a renewal hand-off (``request_renewal_handoffs``) or
    when the channel can no longer deliver (hand-back). The push itself is
    ``_push_waiting_attempt``: only a still-``scheduled`` attempt is pushed.
    """
    try:
        try:
            reason = await _wait_for_fallback(delay, router_id, attempt_id)
        finally:
            _fallback_waiters.pop(attempt_id, None)
            _fallback_wake_reason.pop(attempt_id, None)
        return await _push_waiting_attempt(
            attempt_id, reason, comment=(hotspot_payload or {}).get("comment"),
        )
    except Exception as exc:  # the retry job is the backstop
        logger.error("[PROVISION] checkin_only fallback for attempt %s failed: %s", attempt_id, exc)
        return None


async def _load_waiting_push_context(
    attempt_id: int, comment: str | None, now: datetime,
) -> tuple[int, int, Dict[str, Any]] | None:
    """One short read: (customer_id, router_id, payload) for a waiting attempt.

    The payload is built from the customer row NOW, as the retry job does,
    not the one captured at payment time: a Reconnect during the wait moves
    the customer to a new MAC, and pushing the old one would re-add it as an
    orphan binding. Only a ``scheduled`` attempt of an ACTIVE, unexpired
    hotspot customer on a direct-API router qualifies (the retry job's filter).
    """
    async with async_session() as db:
        row = (
            await db.execute(
                select(ProvisioningAttempt, Customer, Plan, Router)
                .join(Customer, ProvisioningAttempt.customer_id == Customer.id)
                .join(Plan, Customer.plan_id == Plan.id)
                .join(Router, Customer.router_id == Router.id)
                .where(ProvisioningAttempt.id == attempt_id)
            )
        ).first()
        ctx = None
        if row is not None:
            attempt, customer, plan, router = row
            if (
                _enum_value(attempt.provisioning_state) == ProvisioningState.SCHEDULED.value
                and attempt.router_id == router.id
                and _enum_value(customer.status) == CustomerStatus.ACTIVE.value
                and customer.mac_address
                and customer.expiry is not None
                and customer.expiry > now
                and _enum_value(plan.connection_type) == ConnectionType.HOTSPOT.value
                and _enum_value(router.auth_method) == RouterAuthMethod.DIRECT_API.value
            ):
                ctx = (
                    customer.id,
                    router.id,
                    build_hotspot_payload(
                        customer, plan, router,
                        comment=comment or f"Payment successful for {customer.name}",
                    ),
                )
        await db.commit()
    return ctx


async def _push_waiting_attempt(
    attempt_id: int, reason: str, comment: str | None = None,
) -> Dict[str, Any] | None:
    """Push a checkin_only attempt that is still waiting (fallback, renewal
    hand-off or hand-back). A no-op if it was delivered or another push has
    it meanwhile. At most one such push per attempt at a time."""
    if attempt_id in _push_inflight:
        return None
    _push_inflight.add(attempt_id)
    try:
        ctx = await _load_waiting_push_context(attempt_id, comment, datetime.utcnow())
        if ctx is None:
            return None
        customer_id, router_id, payload = ctx
        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=payload.get("mac_address"),
            action=reason,
            status="started",
            details=_WAITING_PUSH_DETAILS.get(reason, reason),
            attempt_id=attempt_id,
        )
        log = logger.info if reason == CHECKIN_HANDOFF_ACTION else logger.warning
        log("[PROVISION] checkin_only router %s: attempt %s -> push (%s)", router_id, attempt_id, reason)
        return await provision_hotspot_customer(customer_id, router_id, payload, reason, attempt_id)
    finally:
        _push_inflight.discard(attempt_id)


def request_renewal_handoffs(attempt_ids: Iterable[int]) -> int:
    """Hand waiting checkin_only attempts to the push now (called by the
    check-in endpoint when its report shows their MAC already bound).

    Wakes the attempt's fallback timer early; with no timer in this process
    (restart) it starts the same push directly. Pure scheduling, returns at
    once; must be called from the event loop.
    """
    started = 0
    for attempt_id in attempt_ids:
        attempt_id = int(attempt_id)
        event = _fallback_waiters.get(attempt_id)
        if event is not None:
            if not event.is_set():
                _fallback_wake_reason[attempt_id] = CHECKIN_HANDOFF_ACTION
                event.set()
                started += 1
        elif attempt_id not in _push_inflight:
            task = asyncio.create_task(_push_waiting_attempt(attempt_id, CHECKIN_HANDOFF_ACTION))
            _fallback_tasks.add(task)
            task.add_done_callback(_fallback_tasks.discard)
            started += 1
    return started


async def rearm_checkin_only_fallbacks(now: datetime | None = None) -> int:
    """Re-arm fallback timers lost to a restart (called by the retry job).

    Waiting attempts on checkin_only routers with no timer in this process
    get one for the rest of their window (0 if it already passed), so the
    fallback still lands about CHECKIN_ONLY_FALLBACK_SECONDS after payment
    instead of at the retry job's hold cutoff plus a tick. One short read.
    """
    from app.services import checkin_delivery

    router_ids = checkin_delivery.effective_checkin_only_router_ids()
    if not router_ids:
        return 0
    now = now or datetime.utcnow()
    window = checkin_delivery.checkin_only_fallback_seconds()
    entrypoints = [
        ProvisioningAttemptEntrypoint(value) for value in sorted(checkin_delivery.CHECKIN_DEFERRABLE_ENTRYPOINTS)
    ]
    async with async_session() as db:
        rows = (
            await db.execute(
                select(
                    ProvisioningAttempt.id,
                    ProvisioningAttempt.customer_id,
                    ProvisioningAttempt.router_id,
                    ProvisioningAttempt.created_at,
                )
                .where(
                    ProvisioningAttempt.provisioning_state == ProvisioningState.SCHEDULED,
                    ProvisioningAttempt.router_id.in_(sorted(router_ids)),
                    ProvisioningAttempt.entrypoint.in_(entrypoints),
                    ProvisioningAttempt.created_at > now - timedelta(
                        seconds=window + CHECKIN_FALLBACK_RETRY_SLACK_SECONDS
                    ),
                )
                .order_by(ProvisioningAttempt.created_at.asc())
                .limit(HOTSPOT_RETRY_BATCH_SIZE * 4)
            )
        ).all()
        await db.commit()
    armed = 0
    for attempt_id, customer_id, router_id, created_at in rows:
        if attempt_id in _fallback_waiters or attempt_id in _push_inflight or created_at is None:
            continue
        remaining = window - (now - created_at).total_seconds()
        _spawn_checkin_fallback(max(0.0, remaining), customer_id, router_id, None, attempt_id)
        armed += 1
    if armed:
        logger.warning("[PROVISION] re-armed %d checkin_only fallback timer(s) (restart?)", armed)
    return armed


async def _maybe_defer_to_checkin(
    *,
    customer_id: int,
    router_id: int,
    hotspot_payload: Dict[str, Any],
    action: str,
    attempt_id: int,
    now: datetime,
):
    """Leave this push to the check-in?

    Returns the caller's result (deferred, or already delivered), ``_HANDOFF``
    to push now as a renewal hand-off, or None to push as usual.

    One short session: read the attempt + router auth method and, for a
    fresh deferrable attempt, write the bound-at-payment marker. Released
    before the log write and before the fallback timer is armed.
    """
    from app.services import checkin_delivery

    mac = hotspot_payload.get("mac_address")
    bound = None
    async with async_session() as db:
        attempt = await db.get(ProvisioningAttempt, attempt_id)
        auth_method = None
        if attempt is not None:
            auth_method = (
                await db.execute(select(Router.auth_method).where(Router.id == router_id))
            ).scalar_one_or_none()
        decision = (
            _checkin_only_decision(attempt, router_id, auth_method, action, now)
            if attempt is not None else None
        )
        delivery = serialize_delivery_attempt(attempt) if decision is not None else None
        if decision is not None and decision[0] == "defer":
            mac = mac or attempt.mac_address
            bound = checkin_delivery.mac_bound_on_router(router_id, mac)
            marker = _bound_marker_log(
                customer_id=customer_id, router_id=router_id, attempt_id=attempt_id,
                mac_address=mac, now=now,
            )
            if marker is not None:
                db.add(marker)
        await db.commit()

    if decision is None:
        return None
    kind, remaining = decision
    if kind == "delivered":
        logger.info(
            "[PROVISION] checkin_only router %s: attempt %s already delivered by check-in; no push",
            router_id, attempt_id,
        )
        return {"success": True, "skipped_push": "delivered_by_checkin",
                "provisioning_error": None, "delivery": delivery}

    if bound:
        # Renewal while still bound: the applier leaves an existing binding
        # alone, so waiting would only delay the new expiry/rate to the
        # fallback. The push is the path that updates it.
        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac,
            action=CHECKIN_HANDOFF_ACTION,
            status="started",
            details=f"{action}: {_WAITING_PUSH_DETAILS[CHECKIN_HANDOFF_ACTION]} (at payment)",
            attempt_id=attempt_id,
        )
        logger.info(
            "[PROVISION] checkin_only router %s: attempt %s MAC already bound; push now (renewal hand-off)",
            router_id, attempt_id,
        )
        return _HANDOFF

    await log_provisioning_event(
        customer_id=customer_id,
        router_id=router_id,
        mac_address=mac,
        action="checkin_only_deferred",
        status="deferred",
        details=(
            f"{action}: push left to router check-in (checkin_only); "
            f"fallback push in {int(remaining)}s if not delivered"
        ),
        attempt_id=attempt_id,
    )
    logger.info(
        "[PROVISION] checkin_only router %s: attempt %s left to check-in; fallback push in %ds",
        router_id, attempt_id, int(remaining),
    )
    _spawn_checkin_fallback(remaining, customer_id, router_id, hotspot_payload, attempt_id)
    return {
        "success": False,
        "deferred_to_checkin": True,
        "provisioning_error": None,
        "delivery": delivery,
    }


async def provision_hotspot_customer(
    customer_id: int,
    router_id: int | None,
    hotspot_payload: Dict[str, Any],
    action: str = "hotspot_payment",
    attempt_id: int | None = None,
    verify_only: bool = False,
) -> Dict[str, Any]:
    """Provision a hotspot customer and persist the result for later reconciliation.

    On a checkin_only router (``CHECKIN_ONLY_ROUTER_IDS``, channel live) a
    fresh payment/voucher attempt is NOT pushed: it stays ``scheduled`` for the
    router's check-in, and a timer pushes it after
    ``CHECKIN_ONLY_FALLBACK_SECONDS`` if the check-in has not delivered.
    """
    router_ip = hotspot_payload.get("router_ip")
    mac_address = hotspot_payload.get("mac_address")
    now = datetime.utcnow()

    attempt: ProvisioningAttempt | None = None

    if attempt_id is not None and not verify_only and router_id is not None:
        from app.services.checkin_delivery import checkin_only_active

        if checkin_only_active(router_id) and action not in _NEVER_DEFER_ACTIONS:
            deferred = await _maybe_defer_to_checkin(
                customer_id=customer_id,
                router_id=router_id,
                hotspot_payload=hotspot_payload,
                action=action,
                attempt_id=attempt_id,
                now=now,
            )
            if deferred is _HANDOFF:
                action = CHECKIN_HANDOFF_ACTION
            elif deferred is not None:
                return deferred

    if attempt_id is not None:
        async with async_session() as db:
            attempt = await db.get(ProvisioningAttempt, attempt_id)
            if (
                attempt
                and not verify_only
                and action not in _NEVER_DEFER_ACTIONS
                and not attempt.attempt_count
            ):
                # The A/B's bound-at-payment marker, once, at the first push of
                # a customer-waiting attempt (the deferral path writes its own).
                from app.services.checkin_delivery import CHECKIN_DEFERRABLE_ENTRYPOINTS

                if _enum_value(attempt.entrypoint) in CHECKIN_DEFERRABLE_ENTRYPOINTS:
                    marker = _bound_marker_log(
                        customer_id=customer_id, router_id=router_id, attempt_id=attempt_id,
                        mac_address=normalize_mac_address(mac_address) if mac_address else None,
                        now=now,
                    )
                    if marker is not None:
                        db.add(marker)
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

    # Create the durable command BEFORE network I/O. Direct tunnel push remains
    # the immediate fast path; if it fails or this process dies mid-call, the
    # outbound agent can still fetch the same idempotent entitlement.
    agent_command_id = None
    if router_id and not verify_only:
        try:
            from app.services.router_agent_commands import queue_hotspot_provision_command

            agent_command_id = await queue_hotspot_provision_command(
                router_id=router_id,
                customer_id=customer_id,
                attempt_id=attempt_id,
                hotspot_payload=hotspot_payload,
            )
        except Exception as command_exc:
            # Agent fallback is defence-in-depth; never suppress the immediate
            # paid delivery path because command rendering/queueing failed.
            logger.warning(
                "[PROVISION] Router-agent command skipped for customer %s: %s",
                customer_id,
                command_exc,
            )

    try:
        result = await _run_mikrotik_operation(hotspot_payload, verify_only=verify_only)
    except asyncio.TimeoutError:
        result = {
            "success": False,
            "error": f"Provisioning timed out after {HOTSPOT_PROVISIONING_TIMEOUT_SECONDS}s",
        }
    except Exception as exc:
        result = {"success": False, "error": str(exc)}

    # Whichever delivery path wins closes the same command. If the agent already
    # acknowledged it, this is an idempotent no-op.
    if agent_command_id is not None and result.get("success"):
        try:
            from app.services.router_agent_commands import complete_command_from_push

            await complete_command_from_push(agent_command_id)
        except Exception as command_exc:
            logger.warning(
                "[PROVISION] Could not close router-agent command %s after direct push: %s",
                agent_command_id,
                command_exc,
            )

    try:
        return await _persist_provisioning_result(
            result=result,
            verify_only=verify_only,
            customer_id=customer_id,
            router_id=router_id,
            router_ip=router_ip,
            mac_address=mac_address,
            action=action,
            attempt_id=attempt_id,
            hotspot_payload=hotspot_payload,
        )
    except Exception as exc:
        logger.error(
            "[PROVISION] Unhandled error persisting provisioning result for customer %s "
            "(attempt %s): %s",
            customer_id, attempt_id, exc,
        )
        if attempt_id is not None:
            try:
                async with async_session() as db:
                    stuck = await db.get(ProvisioningAttempt, attempt_id)
                    if stuck and stuck.provisioning_state == ProvisioningState.IN_PROGRESS:
                        stuck.provisioning_state = ProvisioningState.RETRY_PENDING
                        stuck.last_error = _truncate(f"Post-MikroTik error: {exc}")
                        stuck.updated_at = datetime.utcnow()
                        await db.commit()
                        logger.warning(
                            "[PROVISION] Recovered stuck attempt %s → RETRY_PENDING",
                            attempt_id,
                        )
            except Exception as recovery_exc:
                logger.error(
                    "[PROVISION] Failed to recover stuck attempt %s: %s",
                    attempt_id, recovery_exc,
                )
        return {"success": False, "error": str(exc), "delivery": None}


async def _process_hotspot_retry_router_groups(router_groups: dict[str, list]) -> None:
    retry_group_sem = asyncio.Semaphore(HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS)

    async def _process_router_group(items):
        async with retry_group_sem:
            for attempt, customer, plan, router, verify_only in items:
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

    await asyncio.gather(
        *[_process_router_group(items) for items in router_groups.values()],
        return_exceptions=True,
    )


def _retry_scheduled_clause(now: datetime):
    """``scheduled`` attempts the retry job may push.

    A payment attempt on a checkin_only router is ``scheduled`` on purpose
    while it waits for the check-in: the retry job leaves it alone until the
    fallback deadline (+ slack for the in-process timer). After that, or if
    the channel is switched off (kill switch, shadow, list emptied), it is an
    ordinary stranded attempt again and gets pushed.
    """
    from app.services import checkin_delivery

    clause = ProvisioningAttempt.provisioning_state == ProvisioningState.SCHEDULED
    waiting_ids = checkin_delivery.effective_checkin_only_router_ids()
    if not waiting_ids:
        return clause
    hold_cutoff = now - timedelta(
        seconds=checkin_delivery.checkin_only_fallback_seconds() + CHECKIN_FALLBACK_RETRY_SLACK_SECONDS
    )
    entrypoints = [
        ProvisioningAttemptEntrypoint(value) for value in sorted(checkin_delivery.CHECKIN_DEFERRABLE_ENTRYPOINTS)
    ]
    waiting_for_checkin = and_(
        ProvisioningAttempt.router_id.in_(sorted(waiting_ids)),
        ProvisioningAttempt.entrypoint.in_(entrypoints),
        ProvisioningAttempt.created_at > hold_cutoff,
    )
    return and_(clause, not_(waiting_for_checkin))


async def retry_pending_hotspot_provisioning_background():
    """
    Retry or verify direct API hotspot delivery using provisioning attempts.

    Rules:
    - scheduled or stale in_progress older than 90s: full provisioning
    - retry_pending while attempts < 14 and age < 4h: backoff-spaced provisioning
    - legacy failed connectivity attempts below the new limit: resume with backoff
    - router_updated with online_state != online within 15m: verify-only refresh
    - after 14 attempts or 4h age: mark failed

    Safety net:
    - recent completed DIRECT_API hotspot M-Pesa transactions with no attempt
      get an attempt created so payment success never remains invisible.
    """
    try:
        if _retry_db_pool_is_busy():
            return

        now = datetime.utcnow()
        stale_cutoff = now - timedelta(seconds=HOTSPOT_RETRY_STALE_IN_PROGRESS_SECONDS)
        verify_cutoff = now - HOTSPOT_VERIFY_REFRESH_WINDOW
        expiry_cutoff = now - HOTSPOT_RETRY_MAX_AGE

        work_items: list[tuple[ProvisioningAttempt, Customer, Plan, Router, bool]] = []
        queued_attempt_ids: set[int] = set()
        scheduled_clause = _retry_scheduled_clause(now)

        try:
            await rearm_checkin_only_fallbacks(now)
        except Exception as rearm_exc:  # the hold cutoff below is the backstop
            logger.warning("[PROVISION-RETRY] checkin_only re-arm failed: %s", rearm_exc)

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
                            scheduled_clause,
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
                                retry_due_clause(
                                    ProvisioningAttempt,
                                    now,
                                    max_attempts=HOTSPOT_RETRY_MAX_ATTEMPTS,
                                ),
                            ),
                            and_(
                                ProvisioningAttempt.provisioning_state == ProvisioningState.FAILED,
                                ProvisioningAttempt.attempt_count < HOTSPOT_RETRY_MAX_ATTEMPTS,
                                ProvisioningAttempt.created_at > expiry_cutoff,
                                retryable_connectivity_error_clause(ProvisioningAttempt),
                                retry_due_clause(
                                    ProvisioningAttempt,
                                    now,
                                    max_attempts=HOTSPOT_RETRY_MAX_ATTEMPTS,
                                ),
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

        if _retry_db_pool_is_busy():
            return

        logger.warning("[PROVISION-RETRY] Processing %d direct hotspot delivery attempt(s)", len(work_items))

        from collections import defaultdict
        router_groups: dict[str, list] = defaultdict(list)
        for item in work_items:
            _attempt, _customer, _plan, _router, _verify = item
            if _attempt.id in queued_attempt_ids:
                rk = f"{_router.ip_address}:{_router.port}"
                router_groups[rk].append(item)

        await _process_hotspot_retry_router_groups(router_groups)

    except Exception as exc:
        logger.error("[PROVISION-RETRY] Background retry job failed: %s", exc)

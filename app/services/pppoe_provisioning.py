import asyncio
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from sqlalchemy import and_, or_, select

from app.db import database as db_module
from app.db.database import db_pool_snapshot
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    Plan,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterAuthMethod,
)
from app.services.mikrotik_api import MikroTikAPI
from app.config import settings
from app.services.router_availability import derive_router_status, record_router_availability

logger = logging.getLogger("pppoe_provisioning")

PPPOE_RETRY_STALE_IN_PROGRESS_SECONDS = 90
PPPOE_RETRY_BATCH_SIZE = 20
PPPOE_RETRY_MAX_ATTEMPTS = 5
PPPOE_RETRY_MAX_AGE = timedelta(hours=4)
PPPOE_RETRY_DB_BUSY_THRESHOLD_PERCENT = 60
PPPOE_DEFAULT_LOCAL_ADDRESS = "192.168.89.1"
PPPOE_DEFAULT_POOL_NAME = "pppoe-pool"
PPPOE_DEFAULT_POOL_RANGE = "192.168.89.2-192.168.89.254"

_RATE_SUFFIX_MULTIPLIERS = {
    "": 1,
    "K": 1_000,
    "M": 1_000_000,
    "G": 1_000_000_000,
}


def _truncate(value: Any, limit: int = 255) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _retry_db_pool_is_busy() -> bool:
    snapshot = db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    if (
        isinstance(checked_out_percent, (int, float))
        and checked_out_percent >= PPPOE_RETRY_DB_BUSY_THRESHOLD_PERCENT
    ):
        logger.warning(
            "[PPPoE-RETRY] Skipping background retry because DB pool is busy: "
            "checked_out=%s/%s (%.2f%%), status=%s",
            snapshot.get("checked_out"),
            snapshot.get("configured_max_app_connections"),
            checked_out_percent,
            snapshot.get("status"),
        )
        return True
    return False


def _attempt_should_be_terminal(attempt: ProvisioningAttempt, now: datetime) -> bool:
    return (
        attempt.attempt_count >= PPPOE_RETRY_MAX_ATTEMPTS
        or attempt.created_at <= (now - PPPOE_RETRY_MAX_AGE)
    )


def _apply_pppoe_headroom(rate_limit: str, factor: float) -> str:
    """Scale a MikroTik rate-limit string by a compensation factor."""
    if not rate_limit or factor <= 0:
        return rate_limit
    if abs(factor - 1.0) < 0.0001:
        return rate_limit

    def _scale_part(part: str) -> Optional[str]:
        match = re.match(r"^(\d+(?:\.\d+)?)([KMG]?)$", part.strip().upper())
        if not match:
            return None

        value = float(match.group(1))
        suffix = match.group(2)
        bps = int(round(value * _RATE_SUFFIX_MULTIPLIERS[suffix] * factor))
        return str(bps)

    if "/" not in rate_limit:
        scaled = _scale_part(rate_limit)
        return scaled or rate_limit

    upload, download = [p.strip() for p in rate_limit.split("/", 1)]
    scaled_upload = _scale_part(upload)
    scaled_download = _scale_part(download)
    if not scaled_upload or not scaled_download:
        return rate_limit

    return f"{scaled_upload}/{scaled_download}"


def _provision_pppoe_sync(payload: dict) -> dict:
    """
    Synchronous PPPoE provisioning -- runs in thread pool.
    Mirrors _call_mikrotik_bypass_sync for hotspot.
    """
    router_ip = payload.get("router_ip", settings.MIKROTIK_HOST)
    router_username = payload.get("router_username", settings.MIKROTIK_USERNAME)
    router_password = payload.get("router_password", settings.MIKROTIK_PASSWORD)
    router_port = payload.get("router_port", settings.MIKROTIK_PORT)

    logger.info(f"[PPPoE] Connecting to MikroTik at {router_ip}:{router_port}")

    api = MikroTikAPI(
        router_ip, router_username, router_password, router_port,
        timeout=15, connect_timeout=5,
    )

    if not api.connect():
        logger.error(f"[PPPoE] Failed to connect to MikroTik at {router_ip}")
        return {"error": "Failed to connect to router"}

    try:
        base_rate_limit = api._parse_speed_to_mikrotik(payload["bandwidth_limit"])
        headroom_factor = float(getattr(settings, "PPPOE_RATE_LIMIT_HEADROOM", 1.0) or 1.0)
        rate_limit = _apply_pppoe_headroom(base_rate_limit, headroom_factor)
        profile_name = f"pppoe_{base_rate_limit.replace('/', '_')}"

        base_profile = api.get_active_pppoe_profile()
        base_profile_data = base_profile.get("data") if base_profile.get("found") else {}

        # Fall back to the standard infrastructure defaults when the server lookup
        # doesn't resolve them. This covers: (a) customer provisioned before PPPoE
        # ports are configured on the router, and (b) any race/timing window where
        # the server is not yet visible. Without these fallbacks the created profile
        # would have no remote-address, so RouterOS accepts the PPPoE auth but then
        # fails to assign an IP -- the session silently drops at IPCP.
        local_address = base_profile_data.get("local_address") or PPPOE_DEFAULT_LOCAL_ADDRESS
        pool_name = base_profile_data.get("remote_address") or PPPOE_DEFAULT_POOL_NAME

        if pool_name == PPPOE_DEFAULT_POOL_NAME:
            pool_result = api.ensure_ip_pool(PPPOE_DEFAULT_POOL_NAME, PPPOE_DEFAULT_POOL_RANGE)
            if pool_result.get("error"):
                logger.error(f"[PPPoE] IP pool ensure failed: {pool_result['error']}")
                return {"error": f"IP pool ensure failed: {pool_result['error']}"}

        profile_result = api.ensure_pppoe_profile(
            profile_name,
            rate_limit,
            local_address=local_address,
            pool_name=pool_name,
            dns_server=base_profile_data.get("dns_server", ""),
            change_tcp_mss=base_profile_data.get("change_tcp_mss", ""),
        )
        if profile_result.get("error"):
            logger.error(f"[PPPoE] Profile creation failed: {profile_result['error']}")
            return {"error": f"Profile creation failed: {profile_result['error']}"}

        comment = payload.get("comment", "")
        secret_result = api.add_pppoe_secret(
            username=payload["pppoe_username"],
            password=payload["pppoe_password"],
            profile=profile_name,
            comment=comment,
        )
        if secret_result.get("error"):
            logger.error(f"[PPPoE] Secret creation failed: {secret_result['error']}")
            return {"error": f"Secret creation failed: {secret_result['error']}"}

        # Pass pool_name directly so the bypass logic doesn't have to re-query the
        # server profile. Without this, on direct-interface routers the pool lookup
        # can fail silently, leaving FastTrack in place without bypass rules and
        # allowing it to skip the per-user simple queues (rate limits unenforced).
        bypass_result = api.ensure_pppoe_fasttrack_bypass(pool_name=pool_name)
        if bypass_result.get("error"):
            logger.warning(f"[PPPoE] FastTrack bypass ensure failed: {bypass_result['error']}")

        # Force the client to reconnect so any profile/rate-limit change applies immediately.
        disconnect_result = api.disconnect_pppoe_session(payload["pppoe_username"])

        logger.info(
            f"[PPPoE] Provisioned {payload['pppoe_username']} "
            f"with profile {profile_name} on {router_ip} "
            f"(plan={base_rate_limit}, applied={rate_limit}, headroom={headroom_factor})"
        )

        return {
            "success": True,
            "pppoe_username": payload["pppoe_username"],
            "profile": profile_name,
            "base_rate_limit": base_rate_limit,
            "rate_limit": rate_limit,
            "headroom_factor": headroom_factor,
            "profile_result": profile_result,
            "secret_result": secret_result,
            "fasttrack_bypass_result": bypass_result,
            "disconnect_result": disconnect_result,
        }
    except Exception as e:
        logger.error(f"[PPPoE] Provisioning error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _remove_pppoe_sync(payload: dict) -> dict:
    """
    Synchronous PPPoE removal -- runs in thread pool.
    Disconnects active session and removes secret from router.
    """
    router_ip = payload.get("router_ip", settings.MIKROTIK_HOST)
    router_username = payload.get("router_username", settings.MIKROTIK_USERNAME)
    router_password = payload.get("router_password", settings.MIKROTIK_PASSWORD)
    router_port = payload.get("router_port", settings.MIKROTIK_PORT)
    pppoe_username = payload["pppoe_username"]

    logger.info(f"[PPPoE] Removing {pppoe_username} from {router_ip}:{router_port}")

    api = MikroTikAPI(
        router_ip, router_username, router_password, router_port,
        timeout=15, connect_timeout=5,
    )

    if not api.connect():
        logger.error(f"[PPPoE] Failed to connect to MikroTik at {router_ip}")
        return {"error": "Failed to connect to router"}

    try:
        disconnect_result = api.disconnect_pppoe_session(pppoe_username)
        if disconnect_result.get("error"):
            return {
                "error": f"Session disconnect failed: {disconnect_result['error']}",
                "disconnect_result": disconnect_result,
            }

        remove_result = api.remove_pppoe_secret(pppoe_username)
        if remove_result.get("error"):
            return {
                "error": f"Secret removal failed: {remove_result['error']}",
                "disconnect_result": disconnect_result,
                "remove_result": remove_result,
            }

        logger.info(
            f"[PPPoE] Removed {pppoe_username}: "
            f"disconnected={disconnect_result.get('disconnected', 0)}, "
            f"secret={remove_result.get('action', 'unknown')}"
        )

        return {
            "success": True,
            "disconnect_result": disconnect_result,
            "remove_result": remove_result,
        }
    except Exception as e:
        logger.error(f"[PPPoE] Removal error for {pppoe_username}: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


async def call_pppoe_provision(payload: dict):
    """
    Async wrapper that runs PPPoE provisioning in a thread pool.
    Same pattern as call_mikrotik_bypass -- never blocks the event loop.
    """
    try:
        result = await asyncio.to_thread(_provision_pppoe_sync, payload)
        if result and result.get("error"):
            logger.error(f"[PPPoE] Provision failed: {result['error']}")
        return result
    except Exception as e:
        logger.error(f"[PPPoE] Error in provision task: {e}")
        return {"error": str(e)}


async def call_pppoe_remove(payload: dict):
    """
    Async wrapper that runs PPPoE removal in a thread pool.
    """
    try:
        result = await asyncio.to_thread(_remove_pppoe_sync, payload)
        if result and result.get("error"):
            logger.error(f"[PPPoE] Remove failed: {result['error']}")
        return result
    except Exception as e:
        logger.error(f"[PPPoE] Error in remove task: {e}")
        return {"error": str(e)}


async def _persist_pppoe_provisioning_result(
    *,
    result: Dict[str, Any],
    customer_id: int,
    router_id: int | None,
    router_ip: str | None,
    pppoe_username: str | None,
    action: str,
    attempt_id: int | None,
) -> Dict[str, Any]:
    from app.services.hotspot_provisioning import log_provisioning_event, serialize_delivery_attempt

    provisioning_error = result.get("error")
    refreshed_attempt = None

    if provisioning_error:
        final_state = ProvisioningState.RETRY_PENDING
        if attempt_id is not None:
            async with db_module.async_session() as db:
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
            mac_address=None,
            action=action,
            status="failed" if final_state == ProvisioningState.FAILED else "retry_pending",
            details=f"router={router_ip}; username={pppoe_username}",
            error=provisioning_error,
            attempt_id=attempt_id,
        )

        if router_id:
            try:
                async with db_module.async_session() as avail_db:
                    is_online = "connect" not in provisioning_error.lower()
                    await record_router_availability(avail_db, router_id, is_online, "pppoe_provisioning")
                    await avail_db.commit()
            except Exception:
                pass

        result["success"] = False
        result["provisioning_error"] = provisioning_error
        result["delivery"] = serialize_delivery_attempt(refreshed_attempt)
        return result

    if attempt_id is not None:
        async with db_module.async_session() as db:
            refreshed_attempt = await db.get(ProvisioningAttempt, attempt_id)
            if refreshed_attempt:
                refreshed_attempt.provisioning_state = ProvisioningState.ROUTER_UPDATED
                # For PPPoE, ROUTER_UPDATED means the secret/profile exist.
                # Online status depends on the customer CPE dialing in later.
                refreshed_attempt.online_state = ProvisioningOnlineState.UNKNOWN
                refreshed_attempt.router_updated_at = datetime.utcnow()
                refreshed_attempt.last_error = None
                refreshed_attempt.updated_at = datetime.utcnow()
                await db.commit()
                await db.refresh(refreshed_attempt)

    await log_provisioning_event(
        customer_id=customer_id,
        router_id=router_id,
        mac_address=None,
        action=action,
        status="success",
        details=(
            f"router={router_ip}; username={pppoe_username}; "
            f"profile={result.get('profile', '')}; rate_limit={result.get('rate_limit', '')}"
        ),
        attempt_id=attempt_id,
    )

    if router_id:
        try:
            async with db_module.async_session() as avail_db:
                await record_router_availability(avail_db, router_id, True, "pppoe_provisioning")
                await avail_db.commit()
        except Exception:
            pass

    result["success"] = True
    result["provisioning_error"] = None
    result["delivery"] = serialize_delivery_attempt(refreshed_attempt)
    return result


async def provision_pppoe_customer(
    *,
    customer_id: int,
    router_id: int | None,
    pppoe_payload: Dict[str, Any],
    action: str = "pppoe_activation",
    attempt_id: int | None = None,
) -> Dict[str, Any]:
    """
    Provision a PPPoE customer and persist delivery state for retry/reconciliation.

    The DB attempt update, RouterOS write, and result persistence are deliberately
    separate sections so no DB transaction is held while waiting on MikroTik I/O.
    """
    router_ip = pppoe_payload.get("router_ip")
    pppoe_username = pppoe_payload.get("pppoe_username")
    now = datetime.utcnow()

    if attempt_id is not None:
        async with db_module.async_session() as db:
            attempt = await db.get(ProvisioningAttempt, attempt_id)
            if attempt:
                attempt.customer_id = customer_id
                attempt.router_id = router_id
                attempt.provisioning_state = ProvisioningState.IN_PROGRESS
                attempt.last_attempt_at = now
                attempt.attempt_count += 1
                attempt.last_error = None
                attempt.updated_at = now
                await db.commit()

    if router_id:
        try:
            async with db_module.async_session() as db:
                router_obj = await db.get(Router, router_id)
                if router_obj and derive_router_status(router_obj) == "offline":
                    result = {
                        "success": False,
                        "error": f"Router {router_ip} is known offline, will retry",
                    }
                    return await _persist_pppoe_provisioning_result(
                        result=result,
                        customer_id=customer_id,
                        router_id=router_id,
                        router_ip=router_ip,
                        pppoe_username=pppoe_username,
                        action=action,
                        attempt_id=attempt_id,
                    )
        except Exception:
            pass

    result = await call_pppoe_provision(pppoe_payload)
    return await _persist_pppoe_provisioning_result(
        result=result or {"success": False, "error": "PPPoE provisioning returned no result"},
        customer_id=customer_id,
        router_id=router_id,
        router_ip=router_ip,
        pppoe_username=pppoe_username,
        action=action,
        attempt_id=attempt_id,
    )


async def retry_pending_pppoe_provisioning_background():
    """
    Retry active PPPoE customer delivery attempts in small batches.

    This repairs the exact drift where a customer is ACTIVE in the DB but the
    MikroTik profile/secret creation failed during activation. It is bounded by
    batch size, retry count, retry age, DB-pool pressure, and per-router grouping.
    """
    try:
        if _retry_db_pool_is_busy():
            return

        from app.services.hotspot_provisioning import (
            get_or_create_provisioning_attempt,
            schedule_provisioning_attempt,
        )

        now = datetime.utcnow()
        stale_cutoff = now - timedelta(seconds=PPPOE_RETRY_STALE_IN_PROGRESS_SECONDS)
        expiry_cutoff = now - PPPOE_RETRY_MAX_AGE
        work_items: list[tuple[ProvisioningAttempt, Customer, Plan, Router]] = []

        async with db_module.async_session() as db:
            terminal_candidates = (
                await db.execute(
                    select(ProvisioningAttempt)
                    .join(Customer, ProvisioningAttempt.customer_id == Customer.id)
                    .join(Plan, Customer.plan_id == Plan.id)
                    .where(
                        Customer.pppoe_username.isnot(None),
                        Plan.connection_type == ConnectionType.PPPOE,
                        ProvisioningAttempt.provisioning_state.in_(
                            [
                                ProvisioningState.SCHEDULED,
                                ProvisioningState.IN_PROGRESS,
                                ProvisioningState.RETRY_PENDING,
                            ]
                        ),
                        or_(
                            ProvisioningAttempt.attempt_count >= PPPOE_RETRY_MAX_ATTEMPTS,
                            ProvisioningAttempt.created_at <= expiry_cutoff,
                        ),
                    )
                )
            ).scalars().all()

            for attempt in terminal_candidates:
                attempt.provisioning_state = ProvisioningState.FAILED
                attempt.last_error = attempt.last_error or "PPPoE provisioning retry window exhausted"
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
                        Customer.pppoe_username.isnot(None),
                        Customer.expiry.isnot(None),
                        Customer.expiry > now,
                        Plan.connection_type == ConnectionType.PPPOE,
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
                                ProvisioningAttempt.attempt_count < PPPOE_RETRY_MAX_ATTEMPTS,
                                ProvisioningAttempt.created_at > expiry_cutoff,
                            ),
                        ),
                    )
                    .order_by(ProvisioningAttempt.updated_at.asc(), ProvisioningAttempt.id.asc())
                    .limit(PPPOE_RETRY_BATCH_SIZE)
                )
            ).all()

            for attempt, customer, plan, router in attempt_rows:
                work_items.append((attempt, customer, plan, router))

            remaining_capacity = max(PPPOE_RETRY_BATCH_SIZE - len(work_items), 0)
            if remaining_capacity:
                # Safety net: recent paid active PPPoE customers with no attempt
                # get one. This keeps one missed scheduling bug from becoming
                # permanent drift, without scanning the full customer table.
                safety_rows = (
                    await db.execute(
                        select(CustomerPayment, Customer, Plan, Router)
                        .join(Customer, CustomerPayment.customer_id == Customer.id)
                        .join(Plan, Customer.plan_id == Plan.id)
                        .join(Router, Customer.router_id == Router.id)
                        .outerjoin(
                            ProvisioningAttempt,
                            and_(
                                ProvisioningAttempt.source_table == ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                                ProvisioningAttempt.source_pk == CustomerPayment.id,
                            ),
                        )
                        .where(
                            CustomerPayment.created_at >= expiry_cutoff,
                            ProvisioningAttempt.id.is_(None),
                            Customer.status == CustomerStatus.ACTIVE,
                            Customer.pppoe_username.isnot(None),
                            Customer.expiry.isnot(None),
                            Customer.expiry > now,
                            Plan.connection_type == ConnectionType.PPPOE,
                            Router.auth_method == RouterAuthMethod.DIRECT_API,
                        )
                        .order_by(CustomerPayment.created_at.asc(), CustomerPayment.id.asc())
                        .limit(remaining_capacity)
                    )
                ).all()

                for payment, customer, _plan, router in safety_rows:
                    attempt = await get_or_create_provisioning_attempt(
                        db,
                        customer_id=customer.id,
                        router_id=router.id,
                        mac_address=None,
                        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT,
                        source_pk=payment.id,
                        external_reference=payment.payment_reference,
                        entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION,
                    )
                    await schedule_provisioning_attempt(db, attempt)
                    work_items.append((attempt, customer, _plan, router))

                if safety_rows:
                    await db.commit()

        if not work_items:
            logger.debug("[PPPoE-RETRY] No PPPoE delivery attempts need work")
            return

        if _retry_db_pool_is_busy():
            return

        logger.warning("[PPPoE-RETRY] Processing %d PPPoE delivery attempt(s)", len(work_items))

        from collections import defaultdict

        router_groups: dict[str, list[tuple[ProvisioningAttempt, Customer, Plan, Router]]] = defaultdict(list)
        for item in work_items:
            attempt, customer, _plan, router = item
            if customer.pppoe_username and customer.pppoe_password:
                router_key = f"{router.ip_address}:{router.port}"
                router_groups[router_key].append(item)

        for items in router_groups.values():
            for attempt, customer, _plan, router in items:
                payload = {
                    "pppoe_username": customer.pppoe_username,
                    "pppoe_password": customer.pppoe_password,
                    "bandwidth_limit": _plan.speed if _plan else "10Mbps",
                    "comment": (
                        f"CID:{customer.id}|{customer.name or customer.phone}|"
                        f"{datetime.utcnow().strftime('%Y-%m-%d')}"
                    ),
                    "router_ip": router.ip_address,
                    "router_username": router.username,
                    "router_password": router.password,
                    "router_port": router.port,
                }
                await provision_pppoe_customer(
                    customer_id=customer.id,
                    router_id=router.id,
                    pppoe_payload=payload,
                    action="pppoe_retry",
                    attempt_id=attempt.id,
                )

    except Exception as exc:
        logger.error("[PPPoE-RETRY] Background retry job failed: %s", exc)


def build_pppoe_payload(customer, router) -> dict:
    """Build the payload dict for PPPoE provisioning from ORM objects."""
    return {
        "pppoe_username": customer.pppoe_username,
        "pppoe_password": customer.pppoe_password,
        "bandwidth_limit": customer.plan.speed if customer.plan else "10Mbps",
        "comment": f"CID:{customer.id}|{customer.name or customer.phone}|{datetime.utcnow().strftime('%Y-%m-%d')}",
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
    }


def build_pppoe_remove_payload(customer, router) -> dict:
    """Build the payload dict for PPPoE removal from ORM objects."""
    return {
        "pppoe_username": customer.pppoe_username,
        "router_ip": router.ip_address,
        "router_username": router.username,
        "router_password": router.password,
        "router_port": router.port,
    }

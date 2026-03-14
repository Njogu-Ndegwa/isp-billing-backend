import asyncio
import functools
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any, Dict

from sqlalchemy import func, select, text
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.database import async_session
from app.db.models import ConnectionType, Customer, CustomerStatus, Plan, ProvisioningLog, Router
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

HOTSPOT_PROVISIONING_TIMEOUT_SECONDS = 75
HOTSPOT_RETRY_COOLDOWN_SECONDS = 90
HOTSPOT_RETRY_BATCH_SIZE = 25
HOTSPOT_PROVISIONING_ACTIONS = (
    "hotspot_payment",
    "hotspot_retry",
    "voucher_direct_api",
)

_hotspot_provision_pool = ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix="mikrotik-provision",
)


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


def _extract_provisioning_error(result: Dict[str, Any]) -> str | None:
    """Promote partial MikroTik failures to a retryable top-level error."""
    if not result:
        return "Empty provisioning result"

    if result.get("error"):
        return str(result["error"])

    profile_error = (result.get("profile_result") or {}).get("error")
    if profile_error:
        return f"profile_error: {profile_error}"

    user_error = (result.get("hotspot_user_result") or {}).get("error")
    if user_error:
        return f"user_error: {user_error}"

    binding_error = (result.get("ip_binding_result") or {}).get("error")
    if binding_error:
        return f"binding_error: {binding_error}"

    return None


async def log_provisioning_event(
    customer_id: int,
    router_id: int | None,
    mac_address: str | None,
    action: str,
    status: str,
    details: str | None = None,
    error: str | None = None,
):
    """Persist direct API provisioning activity for later diagnosis and retries."""
    try:
        async with async_session() as db:
            await db.execute(
                text(
                    """
                    INSERT INTO provisioning_logs
                    (customer_id, router_id, mac_address, action, status, details, error, log_date)
                    VALUES (:customer_id, :router_id, :mac_address, :action, :status, :details, :error, :log_date)
                    """
                ),
                {
                    "customer_id": customer_id,
                    "router_id": router_id,
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


def _call_mikrotik_bypass_sync(hotspot_payload: dict) -> dict:
    """
    Synchronous function to provision customer on MikroTik.
    Runs in a dedicated thread pool so payment provisioning is isolated from
    the generic asyncio default executor used elsewhere in the app.
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
        result = api.add_customer_bypass_mode(
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

        logger.info("[PROVISION] MikroTik API response: %s", result)

        queue_result = result.get("queue_result", {})
        if queue_result and queue_result.get("pending"):
            logger.info(
                "[PROVISION] Queue pending for %s, will retry in 5 seconds...",
                hotspot_payload["mac_address"],
            )
            time.sleep(5)

            if not api.connected:
                api.connect()

            if api.connected:
                normalized_mac = normalize_mac_address(hotspot_payload["mac_address"])
                username = normalized_mac.replace(":", "")
                rate_limit = api._parse_speed_to_mikrotik(hotspot_payload["bandwidth_limit"])

                client_ip = api.get_client_ip_by_mac(normalized_mac)

                if client_ip:
                    retry_result = api.send_command(
                        "/queue/simple/add",
                        {
                            "name": f"plan_{username}",
                            "target": f"{client_ip}/32",
                            "max-limit": rate_limit,
                            "comment": f"MAC:{hotspot_payload['mac_address']}|Plan rate limit",
                        },
                    )
                    if retry_result.get("error") and "already have" in retry_result.get("error", "").lower():
                        queues_result = api.get_simple_queues_minimal()
                        if queues_result.get("success") and queues_result.get("data"):
                            for queue_item in queues_result["data"]:
                                if (
                                    str(queue_item.get("name", "")).lower() == f"plan_{username}".lower()
                                    and queue_item.get(".id")
                                ):
                                    retry_result = api.send_command(
                                        "/queue/simple/set",
                                        {
                                            "numbers": queue_item[".id"],
                                            "target": f"{client_ip}/32",
                                            "max-limit": rate_limit,
                                            "disabled": "no",
                                        },
                                    )
                                    break
                    bypass_result = api.ensure_queue_fasttrack_bypass([client_ip])
                    if bypass_result.get("error"):
                        logger.warning(
                            "[PROVISION] Queue exists but FastTrack bypass setup failed for %s: %s",
                            client_ip,
                            bypass_result.get("error"),
                        )
                    logger.info("[PROVISION] Queue created for %s -> %s: %s", username, client_ip, retry_result)
                else:
                    logger.warning(
                        "[PROVISION] Still no IP for %s - queue will be synced later",
                        hotspot_payload["mac_address"],
                    )

        return result
    finally:
        api.disconnect()


async def provision_hotspot_customer(
    customer_id: int,
    router_id: int | None,
    hotspot_payload: Dict[str, Any],
    action: str = "hotspot_payment",
) -> Dict[str, Any]:
    """Provision a hotspot customer and persist the result for later reconciliation."""
    loop = asyncio.get_running_loop()

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(
                _hotspot_provision_pool,
                functools.partial(_call_mikrotik_bypass_sync, hotspot_payload),
            ),
            timeout=HOTSPOT_PROVISIONING_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        result = {
            "error": f"Provisioning timed out after {HOTSPOT_PROVISIONING_TIMEOUT_SECONDS}s"
        }
    except Exception as exc:
        result = {"error": str(exc)}

    router_ip = hotspot_payload.get("router_ip")
    mac_address = hotspot_payload.get("mac_address")
    provisioning_error = _extract_provisioning_error(result)

    if provisioning_error:
        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac_address,
            action=action,
            status="failed",
            details=f"router={router_ip}",
            error=provisioning_error,
        )
        logger.error(
            "[PROVISION] Hotspot provisioning failed for customer %s on router %s: %s",
            customer_id,
            router_ip,
            provisioning_error,
        )
    else:
        queue_result = result.get("queue_result", {})
        queue_state = "pending" if queue_result.get("pending") else "ready"
        await log_provisioning_event(
            customer_id=customer_id,
            router_id=router_id,
            mac_address=mac_address,
            action=action,
            status="success",
            details=f"router={router_ip}; queue={queue_state}",
        )
        logger.info(
            "[PROVISION] Hotspot provisioning succeeded for customer %s on router %s",
            customer_id,
            router_ip,
        )

    return result


async def retry_pending_hotspot_provisioning_background():
    """
    Retry direct API hotspot provisioning that was scheduled or failed previously.
    This repairs payments that succeeded while the router was briefly unreachable
    or while the web worker was restarted before the background task finished.
    """
    try:
        now = datetime.utcnow()
        stale_cutoff = now - timedelta(seconds=HOTSPOT_RETRY_COOLDOWN_SECONDS)

        async with async_session() as db:
            latest_logs = (
                select(
                    ProvisioningLog.customer_id.label("customer_id"),
                    ProvisioningLog.status.label("status"),
                    ProvisioningLog.log_date.label("log_date"),
                    func.row_number().over(
                        partition_by=ProvisioningLog.customer_id,
                        order_by=[ProvisioningLog.log_date.desc(), ProvisioningLog.id.desc()],
                    ).label("rn"),
                )
                .where(ProvisioningLog.action.in_(HOTSPOT_PROVISIONING_ACTIONS))
                .subquery()
            )

            stmt = (
                select(Customer)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .join(Plan, Customer.plan_id == Plan.id)
                .join(latest_logs, latest_logs.c.customer_id == Customer.id)
                .where(
                    latest_logs.c.rn == 1,
                    latest_logs.c.status.in_(("scheduled", "failed")),
                    latest_logs.c.log_date <= stale_cutoff,
                    Customer.status == CustomerStatus.ACTIVE,
                    Customer.mac_address.isnot(None),
                    Customer.router_id.isnot(None),
                    Customer.expiry.isnot(None),
                    Customer.expiry > now,
                    Plan.connection_type == ConnectionType.HOTSPOT,
                )
                .order_by(latest_logs.c.log_date.asc())
                .limit(HOTSPOT_RETRY_BATCH_SIZE)
            )

            customers = (await db.execute(stmt)).scalars().unique().all()

        if not customers:
            logger.debug("[PROVISION-RETRY] No stranded hotspot provisions found")
            return

        logger.warning("[PROVISION-RETRY] Retrying %s stranded hotspot provision(s)", len(customers))

        for customer in customers:
            if not customer.router or not customer.plan or not customer.mac_address:
                continue

            hotspot_payload = build_hotspot_payload(
                customer,
                customer.plan,
                customer.router,
                comment=f"Retry provisioning for {customer.name}",
            )
            await log_provisioning_event(
                customer_id=customer.id,
                router_id=customer.router.id,
                mac_address=customer.mac_address,
                action="hotspot_retry",
                status="scheduled",
                details=f"Retry queued for router {customer.router.ip_address}",
            )
            await provision_hotspot_customer(
                customer_id=customer.id,
                router_id=customer.router.id,
                hotspot_payload=hotspot_payload,
                action="hotspot_retry",
            )

    except Exception as exc:
        logger.error("[PROVISION-RETRY] Background retry job failed: %s", exc)

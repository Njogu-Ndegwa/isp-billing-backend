"""Fair Usage Policy (FUP) enforcement for customer access.

Called once per snapshot cycle from the bandwidth collection job, and from
renewal hooks (payment / mpesa / momo / zenopay reconciliation) to revert.

Idempotency rules
-----------------
* :func:`evaluate_and_enforce` only takes router action when
  ``period.fup_triggered_at`` is ``None`` (transition into FUP) or when the
  user falls back below the cap and a previous trigger has not been reverted
  (transition out of FUP).
* :func:`revert` is safe to call any number of times; if there is no trigger
  to undo, it is a no-op.

All router I/O runs in a thread pool via :func:`asyncio.to_thread` so the
snapshot job's event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerUsagePeriod,
    FupAction,
    Plan,
    Router,
)
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address, parse_speed_to_mikrotik

logger = logging.getLogger("fup")

DEFAULT_FUP_THROTTLE_RATE = "1M/1M"
DEFAULT_HOTSPOT_FUP_THROTTLE_RATE = DEFAULT_FUP_THROTTLE_RATE


# --------------------------- Helpers ---------------------------


def _cap_bytes(period: CustomerUsagePeriod, plan: Optional[Plan]) -> Optional[int]:
    """Return the byte cap for this period, or ``None`` if uncapped."""
    cap_mb = period.cap_mb_snapshot if period.cap_mb_snapshot is not None else (
        plan.data_cap_mb if plan else None
    )
    if not cap_mb or cap_mb <= 0:
        return None
    return int(cap_mb) * 1024 * 1024


def _effective_action(period: CustomerUsagePeriod, plan: Optional[Plan]) -> FupAction:
    """Action to apply when the cap is hit.  Snapshot wins, plan is fallback."""
    return (
        period.fup_action_snapshot
        or (plan.fup_action if plan else None)
        or FupAction.THROTTLE
    )


async def _load_router(db: AsyncSession, router_id: int) -> Optional[Router]:
    if not router_id:
        return None
    r = await db.execute(select(Router).where(Router.id == router_id))
    return r.scalar_one_or_none()


def _router_info(router: Router) -> dict:
    return {
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
    }


def hotspot_throttle_rate_for_plan(plan: Optional[Plan]) -> str:
    """Return the RouterOS rate string used when a hotspot plan is throttled."""
    return parse_speed_to_mikrotik(
        (plan.fup_throttle_profile if plan else None)
        or DEFAULT_HOTSPOT_FUP_THROTTLE_RATE
    )


def pppoe_throttle_rate_for_plan(plan: Optional[Plan]) -> str:
    """Return the RouterOS rate string used when a PPPoE plan is throttled.

    ``fup_throttle_profile`` carries a *speed* (e.g. ``"5M/2M"``), matching the
    hotspot field, rather than a hand-named PPP profile.
    """
    return parse_speed_to_mikrotik(
        (plan.fup_throttle_profile if plan else None)
        or DEFAULT_FUP_THROTTLE_RATE
    )


def _fup_profile_name_for_rate(rate_limit: str) -> str:
    """Deterministic ``/ppp/profile`` name carrying a throttle rate.

    ``"3M/1M"`` -> ``"fup-3M-1M"`` so plans that share a throttle speed reuse a
    single profile instead of proliferating per-customer profiles on the router.
    """
    safe = re.sub(r"[^0-9A-Za-z]+", "-", rate_limit).strip("-") or "default"
    return f"fup-{safe}"


def _hotspot_identity(customer: Customer) -> tuple[Optional[str], Optional[str]]:
    if not customer.mac_address:
        return None, None
    normalized_mac = normalize_mac_address(customer.mac_address)
    return normalized_mac, normalized_mac.replace(":", "")


# --------------------------- Sync MikroTik helpers ---------------------------


def _set_secret_profile_sync(router_info: dict, username: str, profile: str) -> dict:
    """Set the PPP secret's ``profile`` and re-enable it; disconnect active session."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        result = api.send_command("/ppp/secret/set", {
            "numbers": username,
            "profile": profile,
            "disabled": "no",
        })
        api.disconnect_pppoe_session(username)
        return result
    finally:
        api.disconnect()


def _set_secret_throttle_profile_sync(
    router_info: dict, username: str, profile_name: str, rate_limit: str
) -> dict:
    """Throttle a PPPoE user to ``rate_limit``.

    Ensures a ``/ppp/profile`` named ``profile_name`` carries ``rate_limit``,
    points the PPP secret at it, and drops the live session so the new rate
    takes effect immediately.
    """
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        ensured = api.ensure_pppoe_profile(profile_name, rate_limit)
        if ensured.get("error"):
            return {"error": ensured["error"]}
        result = api.send_command("/ppp/secret/set", {
            "numbers": username,
            "profile": profile_name,
            "disabled": "no",
        })
        api.disconnect_pppoe_session(username)
        return result
    finally:
        api.disconnect()


def _disable_secret_sync(router_info: dict, username: str) -> dict:
    """Set ``disabled=yes`` on the PPP secret and disconnect any active session."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        result = api.send_command("/ppp/secret/set", {
            "numbers": username,
            "disabled": "yes",
        })
        api.disconnect_pppoe_session(username)
        return result
    finally:
        api.disconnect()


def _find_hotspot_queue(queues: list[dict], username: str, mac_address: str) -> Optional[dict]:
    wanted_names = {f"plan_{username}".lower(), f"queue_{username}".lower()}
    normalized = normalize_mac_address(mac_address)
    compact = normalized.replace(":", "")
    for queue in queues or []:
        name = str(queue.get("name") or "").strip().lower()
        comment = str(queue.get("comment") or "").upper()
        if name in wanted_names:
            return queue
        if (
            f"MAC:{normalized}".upper() in comment
            or f"MAC:{compact}".upper() in comment
            or normalized.upper() in comment
            or compact.upper() in comment
        ):
            return queue
    return None


def _find_hotspot_binding(bindings: list[dict], mac_address: str) -> Optional[dict]:
    normalized = normalize_mac_address(mac_address)
    for binding in bindings or []:
        binding_mac = binding.get("mac-address")
        if binding_mac and normalize_mac_address(binding_mac) == normalized:
            return binding
    return None


def _kick_hotspot_client(api: MikroTikAPI, normalized_mac: str, username: str) -> dict:
    result = {"sessions_removed": 0, "hosts_removed": 0, "errors": []}

    active = api.send_command("/ip/hotspot/active/print")
    if active.get("success"):
        for session in active.get("data", []) or []:
            session_mac = session.get("mac-address")
            session_user = str(session.get("user") or "")
            if (
                (session_mac and normalize_mac_address(session_mac) == normalized_mac)
                or session_user.lower() == username.lower()
            ):
                sid = session.get(".id")
                if not sid:
                    continue
                remove = api.send_command("/ip/hotspot/active/remove", {"numbers": sid})
                if remove.get("error"):
                    result["errors"].append(f"active:{remove['error']}")
                else:
                    result["sessions_removed"] += 1
    elif active.get("error"):
        result["errors"].append(f"active_print:{active['error']}")

    hosts = api.send_command("/ip/hotspot/host/print")
    if hosts.get("success"):
        for host in hosts.get("data", []) or []:
            host_mac = host.get("mac-address")
            if host_mac and normalize_mac_address(host_mac) == normalized_mac:
                hid = host.get(".id")
                if not hid:
                    continue
                remove = api.send_command("/ip/hotspot/host/remove", {"numbers": hid})
                if remove.get("error"):
                    result["errors"].append(f"host:{remove['error']}")
                else:
                    result["hosts_removed"] += 1
    elif hosts.get("error"):
        result["errors"].append(f"host_print:{hosts['error']}")

    return result


def _set_hotspot_queue_limit_sync(
    router_info: dict,
    mac_address: str,
    rate_limit: str,
    *,
    disabled: str = "no",
) -> dict:
    """Set or create the direct-API hotspot simple queue for this customer."""
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        queues = api.get_simple_queues_minimal()
        if not queues.get("success"):
            return {"error": queues.get("error", "queue_print_failed")}

        queue = _find_hotspot_queue(queues.get("data", []), username, normalized_mac)
        if queue and queue.get(".id"):
            payload = {
                "numbers": queue[".id"],
                "max-limit": rate_limit,
                "disabled": disabled,
            }
            result = api.send_command("/queue/simple/set", payload)
            if result.get("error"):
                return {"error": result["error"]}
            return {"success": True, "queue": queue.get("name"), "max_limit": rate_limit}

        client_ip = api.get_client_ip_by_mac(normalized_mac)
        if not client_ip:
            return {"error": "queue_not_found_and_client_ip_unknown"}

        result = api.send_command("/queue/simple/add", {
            "name": f"plan_{username}",
            "target": f"{client_ip}/32",
            "max-limit": rate_limit,
            "disabled": disabled,
            "comment": f"MAC:{normalized_mac}|Plan rate limit",
        })
        if result.get("error"):
            return {"error": result["error"]}
        bypass = api.ensure_queue_fasttrack_bypass([client_ip])
        return {
            "success": True,
            "queue": f"plan_{username}",
            "max_limit": rate_limit,
            "created": True,
            "fasttrack_bypass": bypass,
        }
    finally:
        api.disconnect()


def _block_hotspot_sync(router_info: dict, mac_address: str) -> dict:
    """Block a direct-API hotspot customer via IP binding and kick live state."""
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if not bindings.get("success"):
            return {"error": bindings.get("error", "ip_binding_print_failed")}

        binding = _find_hotspot_binding(bindings.get("data", []), normalized_mac)
        comment = f"FUP_BLOCKED|USER:{username}|{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
        if binding and binding.get(".id"):
            binding_result = api.send_command("/ip/hotspot/ip-binding/set", {
                "numbers": binding[".id"],
                "type": "blocked",
                "comment": comment,
            })
        else:
            binding_result = api.send_command("/ip/hotspot/ip-binding/add", {
                "mac-address": normalized_mac,
                "type": "blocked",
                "comment": comment,
            })
        if binding_result.get("error"):
            return {"error": binding_result["error"]}

        queue_result = _set_hotspot_queue_disabled_connected(api, normalized_mac, username)
        kick_result = _kick_hotspot_client(api, normalized_mac, username)
        return {
            "success": True,
            "binding_result": binding_result,
            "queue_result": queue_result,
            "kick_result": kick_result,
        }
    finally:
        api.disconnect()


def _set_hotspot_queue_disabled_connected(
    api: MikroTikAPI, normalized_mac: str, username: str
) -> dict:
    queues = api.get_simple_queues_minimal()
    if not queues.get("success"):
        return {"error": queues.get("error", "queue_print_failed")}
    queue = _find_hotspot_queue(queues.get("data", []), username, normalized_mac)
    if not queue or not queue.get(".id"):
        return {"skipped": True, "reason": "queue_not_found"}
    result = api.send_command("/queue/simple/set", {
        "numbers": queue[".id"],
        "disabled": "yes",
    })
    if result.get("error"):
        return {"error": result["error"]}
    return {"success": True, "queue": queue.get("name"), "disabled": "yes"}


def _restore_hotspot_sync(router_info: dict, mac_address: str, normal_rate_limit: str) -> dict:
    """Restore bypass binding and normal simple queue speed for a hotspot customer."""
    normalized_mac = normalize_mac_address(mac_address)
    username = normalized_mac.replace(":", "")
    api = MikroTikAPI(
        router_info["ip"], router_info["username"], router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if not bindings.get("success"):
            return {"error": bindings.get("error", "ip_binding_print_failed")}

        binding = _find_hotspot_binding(bindings.get("data", []), normalized_mac)
        comment = f"USER:{username}|EXPIRES:DB_MANAGED|FUP_RESTORED:{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
        if binding and binding.get(".id"):
            binding_result = api.send_command("/ip/hotspot/ip-binding/set", {
                "numbers": binding[".id"],
                "type": "bypassed",
                "comment": comment,
            })
        else:
            binding_result = api.send_command("/ip/hotspot/ip-binding/add", {
                "mac-address": normalized_mac,
                "type": "bypassed",
                "comment": comment,
            })
        if binding_result.get("error"):
            return {"error": binding_result["error"]}

        queues = api.get_simple_queues_minimal()
        if not queues.get("success"):
            return {"error": queues.get("error", "queue_print_failed")}

        queue = _find_hotspot_queue(queues.get("data", []), username, normalized_mac)
        if queue and queue.get(".id"):
            queue_result = api.send_command("/queue/simple/set", {
                "numbers": queue[".id"],
                "max-limit": normal_rate_limit,
                "disabled": "no",
            })
        else:
            client_ip = api.get_client_ip_by_mac(normalized_mac)
            if client_ip:
                queue_result = api.send_command("/queue/simple/add", {
                    "name": f"plan_{username}",
                    "target": f"{client_ip}/32",
                    "max-limit": normal_rate_limit,
                    "disabled": "no",
                    "comment": f"MAC:{normalized_mac}|Plan rate limit",
                })
                if not queue_result.get("error"):
                    api.ensure_queue_fasttrack_bypass([client_ip])
            else:
                queue_result = {"skipped": True, "reason": "queue_not_found_and_client_ip_unknown"}

        if queue_result.get("error"):
            return {"error": queue_result["error"]}

        kick_result = _kick_hotspot_client(api, normalized_mac, username)
        return {
            "success": True,
            "binding_result": binding_result,
            "queue_result": queue_result,
            "kick_result": kick_result,
        }
    finally:
        api.disconnect()


# --------------------------- Public API ---------------------------


async def apply_throttle(
    db: AsyncSession, customer: Customer, plan: Optional[Plan]
) -> dict:
    """Apply the plan's throttled access state."""
    plan = plan if plan is not None else customer.plan
    if plan and plan.connection_type == ConnectionType.HOTSPOT:
        normalized_mac, _username = _hotspot_identity(customer)
        if not normalized_mac:
            return {"error": "no_mac_address"}
        router = await _load_router(db, customer.router_id)
        if not router:
            return {"error": "no_router"}
        info = _router_info(router)
        rate_limit = hotspot_throttle_rate_for_plan(plan)
        await db.commit()
        return await asyncio.to_thread(
            _set_hotspot_queue_limit_sync, info, normalized_mac, rate_limit
        )

    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    rate_limit = pppoe_throttle_rate_for_plan(plan)
    profile_name = _fup_profile_name_for_rate(rate_limit)
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    await db.commit()
    return await asyncio.to_thread(
        _set_secret_throttle_profile_sync,
        info,
        customer.pppoe_username,
        profile_name,
        rate_limit,
    )


async def apply_block(
    db: AsyncSession, customer: Customer, plan: Optional[Plan] = None
) -> dict:
    """Block customer access at the router."""
    plan = plan if plan is not None else customer.plan
    if plan and plan.connection_type == ConnectionType.HOTSPOT:
        normalized_mac, _username = _hotspot_identity(customer)
        if not normalized_mac:
            return {"error": "no_mac_address"}
        router = await _load_router(db, customer.router_id)
        if not router:
            return {"error": "no_router"}
        info = _router_info(router)
        await db.commit()
        return await asyncio.to_thread(_block_hotspot_sync, info, normalized_mac)

    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    await db.commit()
    return await asyncio.to_thread(
        _disable_secret_sync, info, customer.pppoe_username
    )


async def restore_normal_profile(
    db: AsyncSession, customer: Customer, plan: Optional[Plan]
) -> dict:
    """Restore the customer's normal router-side access state."""
    plan = plan if plan is not None else customer.plan
    if plan and plan.connection_type == ConnectionType.HOTSPOT:
        normalized_mac, _username = _hotspot_identity(customer)
        if not normalized_mac:
            return {"error": "no_mac_address"}
        router = await _load_router(db, customer.router_id)
        if not router:
            return {"error": "no_router"}
        info = _router_info(router)
        rate_limit = parse_speed_to_mikrotik(plan.speed if plan else "")
        await db.commit()
        return await asyncio.to_thread(
            _restore_hotspot_sync, info, normalized_mac, rate_limit
        )

    if not customer.pppoe_username:
        return {"error": "no_pppoe_username"}
    profile = (plan.router_profile if plan else None) or "default"
    router = await _load_router(db, customer.router_id)
    if not router:
        return {"error": "no_router"}
    info = _router_info(router)
    await db.commit()
    return await asyncio.to_thread(
        _set_secret_profile_sync, info, customer.pppoe_username, profile
    )


async def evaluate_and_enforce(
    db: AsyncSession,
    customer: Customer,
    period: CustomerUsagePeriod,
    plan: Optional[Plan] = None,
    now: Optional[datetime] = None,
) -> Optional[FupAction]:
    """Decide whether to trigger or release FUP, taking router action as needed.

    Returns the action that was applied (if any), or ``None`` if no change.
    """
    plan = plan if plan is not None else customer.plan
    if not plan or plan.connection_type not in (ConnectionType.PPPOE, ConnectionType.HOTSPOT):
        return None

    cap_bytes = _cap_bytes(period, plan)
    if cap_bytes is None:
        # Uncapped plan: if a stale trigger exists, clear it.
        if period.fup_triggered_at and not period.fup_reverted_at:
            await restore_normal_profile(db, customer, plan)
            period.fup_reverted_at = now or datetime.utcnow()
        return None

    now = now or datetime.utcnow()
    over_cap = (period.total_bytes or 0) >= cap_bytes

    if over_cap and period.fup_triggered_at is None:
        action = _effective_action(period, plan)
        identifier = customer.pppoe_username or customer.mac_address or f"customer:{customer.id}"
        logger.info(
            f"[FUP] Trigger {action.value} for customer={customer.id} "
            f"({identifier}) used={period.total_bytes} cap={cap_bytes}"
        )
        if action == FupAction.THROTTLE:
            res = await apply_throttle(db, customer, plan)
            if res.get("error"):
                logger.error(f"[FUP] Throttle failed for {identifier}: {res}")
                return None
        elif action == FupAction.BLOCK:
            res = await apply_block(db, customer, plan)
            if res.get("error"):
                logger.error(f"[FUP] Block failed for {identifier}: {res}")
                return None
        elif action == FupAction.NOTIFY_ONLY:
            pass

        period.fup_triggered_at = now
        period.fup_action_taken = action
        period.fup_reverted_at = None
        return action

    if not over_cap and period.fup_triggered_at and not period.fup_reverted_at:
        # User dropped below the cap (rare mid-period; mostly via renewal).
        identifier = customer.pppoe_username or customer.mac_address or f"customer:{customer.id}"
        logger.info(
            f"[FUP] Auto-revert for customer={customer.id} ({identifier}) "
            f"used={period.total_bytes} < cap={cap_bytes}"
        )
        if period.fup_action_taken in (FupAction.THROTTLE, FupAction.BLOCK):
            await restore_normal_profile(db, customer, plan)
        period.fup_reverted_at = now
        return None

    return None


async def revert(
    db: AsyncSession,
    customer: Customer,
    plan: Optional[Plan] = None,
    period: Optional[CustomerUsagePeriod] = None,
    now: Optional[datetime] = None,
) -> bool:
    """Unconditionally restore the user's normal profile / re-enable secret.

    Called from renewal hooks after payment.  If ``period`` is supplied (the
    just-closed previous period), its ``fup_reverted_at`` is set so the
    history reflects the revert.  Returns True if router action was taken.
    """
    plan = plan if plan is not None else customer.plan
    if not plan or plan.connection_type not in (ConnectionType.PPPOE, ConnectionType.HOTSPOT):
        return False
    if plan.connection_type == ConnectionType.PPPOE and not customer.pppoe_username:
        return False
    if plan.connection_type == ConnectionType.HOTSPOT and not customer.mac_address:
        return False

    needs_action = True
    if period is not None and period.fup_triggered_at is None:
        needs_action = False
    if plan.connection_type == ConnectionType.HOTSPOT and (
        period is None or period.fup_triggered_at is None
    ):
        needs_action = False

    if needs_action:
        identifier = customer.pppoe_username or customer.mac_address or f"customer:{customer.id}"
        try:
            res = await restore_normal_profile(db, customer, plan)
            if res.get("error"):
                logger.warning(
                    f"[FUP] Revert failed for {identifier}: {res}"
                )
        except Exception as e:
            logger.error(f"[FUP] Revert error for {identifier}: {e}")

    if period is not None and period.fup_triggered_at and not period.fup_reverted_at:
        period.fup_reverted_at = now or datetime.utcnow()

    return needs_action

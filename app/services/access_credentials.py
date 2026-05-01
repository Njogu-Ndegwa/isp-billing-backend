"""
Access Credentials Service
==========================

Reseller-managed comp hotspot credentials. Provision/deprovision flows handle
both ``DIRECT_API`` routers (writing to ``/ip/hotspot/user`` + a per-rate
profile with ``shared-users=1``) and ``RADIUS`` routers (writing rows to
``radius_check`` / ``radius_reply`` with ``Simultaneous-Use := 1``).

The MAC binding that actually grants internet access is installed by the
public ``/api/public/access-login`` endpoint, mirroring how vouchers grant
access. This module owns lifecycle of the user record + the per-MAC
``simple-queue`` that carries the credential's rate-limit.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import string
import time
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AccessCredential, Router, RouterAuthMethod
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

CMD_DELAY = 0.05
USER_COMMENT_PREFIX = "ACCESS_CRED"


# ---------------------------------------------------------------------------
# Username / password generation
# ---------------------------------------------------------------------------

_USERNAME_ALPHABET = string.ascii_lowercase + string.digits
_PASSWORD_ALPHABET = string.ascii_letters + string.digits


def generate_username(length: int = 8) -> str:
    return "".join(secrets.choice(_USERNAME_ALPHABET) for _ in range(length))


def generate_password(length: int = 10) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def profile_name_for_rate(rate_limit: Optional[str]) -> str:
    """Return the hotspot profile name used to carry a given rate-limit.

    Profiles are reused across credentials with the same rate-limit, so we
    don't churn MikroTik state. ``shared-users=1`` is applied to every
    ``cred-*`` profile to enforce single concurrent login at the router level.
    """
    if not rate_limit:
        return "cred-unlimited"
    safe = rate_limit.replace("/", "_").replace(" ", "")
    return f"cred-{safe}"


def queue_name_for_credential(cred_id: int) -> str:
    return f"cred_{cred_id}"


def comment_for_credential(cred: AccessCredential) -> str:
    return f"{USER_COMMENT_PREFIX}|cred:{cred.id}|user:{cred.user_id}"


# ---------------------------------------------------------------------------
# Direct API path
# ---------------------------------------------------------------------------

def _ensure_cred_profile(api: MikroTikAPI, profile_name: str, rate_limit: Optional[str]) -> Dict[str, Any]:
    """Ensure a hotspot profile exists with shared-users=1 + the given rate.

    A null/empty rate_limit removes any rate cap on the profile but keeps the
    single-user enforcement.
    """
    profiles = api.send_command("/ip/hotspot/user/profile/print")
    profile_id = None
    if profiles.get("success") and profiles.get("data"):
        for p in profiles["data"]:
            if p.get("name") == profile_name:
                profile_id = p.get(".id")
                break

    args: Dict[str, Any] = {
        "name": profile_name,
        "shared-users": "1",
    }
    if rate_limit:
        args["rate-limit"] = rate_limit
    else:
        args["rate-limit"] = ""  # clear any prior cap

    if profile_id:
        args["numbers"] = profile_id
        return api.send_command("/ip/hotspot/user/profile/set", args)
    return api.send_command("/ip/hotspot/user/profile/add", args)


def _provision_direct_api_sync(router_info: dict, payload: dict) -> dict:
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connection_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        username = payload["username"]
        password = payload["password"]
        rate_limit = payload.get("rate_limit") or None
        comment = payload["comment"]

        profile_name = profile_name_for_rate(rate_limit)
        profile_result = _ensure_cred_profile(api, profile_name, rate_limit)
        if profile_result.get("error"):
            return {"error": "profile_failed", "message": profile_result["error"]}
        time.sleep(CMD_DELAY)

        users = api.send_command("/ip/hotspot/user/print")
        existing_id = None
        if users.get("success") and users.get("data"):
            for u in users["data"]:
                if u.get("name", "").lower() == username.lower():
                    existing_id = u.get(".id")
                    break

        if existing_id:
            update_args = {
                "numbers": existing_id,
                "name": username,
                "password": password,
                "profile": profile_name,
                "disabled": "no",
                "comment": comment,
            }
            result = api.send_command("/ip/hotspot/user/set", update_args)
        else:
            add_args = {
                "name": username,
                "password": password,
                "profile": profile_name,
                "disabled": "no",
                "comment": comment,
            }
            result = api.send_command("/ip/hotspot/user/add", add_args)

        if result.get("error"):
            return {"error": "user_failed", "message": result["error"]}

        return {"success": True, "profile": profile_name}
    finally:
        api.disconnect()


def _deprovision_direct_api_sync(router_info: dict, payload: dict) -> dict:
    """Remove the hotspot user record and any per-MAC simple-queue/binding for the credential."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connection_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        username = payload["username"]
        bound_mac = payload.get("bound_mac_address")
        cred_id = payload["cred_id"]
        removed = {"user": False, "bindings": 0, "queues": 0, "sessions": 0}

        users = api.send_command("/ip/hotspot/user/print")
        if users.get("success") and users.get("data"):
            for u in users["data"]:
                if u.get("name", "").lower() == username.lower():
                    user_id = u.get(".id")
                    if user_id:
                        time.sleep(CMD_DELAY)
                        api.send_command("/ip/hotspot/user/remove", {"numbers": user_id})
                        removed["user"] = True
                    break

        active = api.send_command("/ip/hotspot/active/print")
        if active.get("success") and active.get("data"):
            for s in active["data"]:
                if s.get("user", "").lower() == username.lower():
                    sid = s.get(".id")
                    if sid:
                        time.sleep(CMD_DELAY)
                        api.send_command("/ip/hotspot/active/remove", {"numbers": sid})
                        removed["sessions"] += 1

        queue_name = queue_name_for_credential(cred_id)
        queues = api.send_command("/queue/simple/print")
        if queues.get("success") and queues.get("data"):
            for q in queues["data"]:
                if q.get("name", "") == queue_name:
                    qid = q.get(".id")
                    if qid:
                        time.sleep(CMD_DELAY)
                        api.send_command("/queue/simple/remove", {"numbers": qid})
                        removed["queues"] += 1

        if bound_mac:
            wanted = normalize_mac_address(bound_mac)
            bindings = api.send_command("/ip/hotspot/ip-binding/print")
            if bindings.get("success") and bindings.get("data"):
                for b in bindings["data"]:
                    bm = b.get("mac-address", "")
                    if bm and normalize_mac_address(bm) == wanted:
                        bid = b.get(".id")
                        if bid:
                            time.sleep(CMD_DELAY)
                            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": bid})
                            removed["bindings"] += 1

        return {"success": True, "removed": removed}
    finally:
        api.disconnect()


def _bind_mac_direct_api_sync(router_info: dict, payload: dict) -> dict:
    """Add an IP-binding ``bypassed`` entry for the user's MAC + per-MAC simple-queue.

    Mirrors the voucher / payment flow's bypass logic but does not write a hotspot
    user record (the reseller side already provisioned it).
    """
    logger.info(
        "[ACCESS-CRED BIND] start router=%s mac=%s cred=%s rate=%s",
        router_info.get("ip"),
        payload.get("mac_address"),
        payload.get("cred_id"),
        payload.get("rate_limit") or "(none)",
    )
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        logger.warning(
            "[ACCESS-CRED BIND] connect failed router=%s err=%s",
            router_info.get("ip"), api.last_connect_error,
        )
        return {
            "error": "connection_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        bind_started = time.monotonic()
        mac_address = normalize_mac_address(payload["mac_address"])
        username = payload["username"]
        cred_id = payload["cred_id"]
        rate_limit = payload.get("rate_limit") or None
        comment = f"{USER_COMMENT_PREFIX}|cred:{cred_id}|user:{username}"
        old_mac_raw = payload.get("previous_mac_address")
        wanted_old = normalize_mac_address(old_mac_raw) if (old_mac_raw and normalize_mac_address(old_mac_raw) != mac_address) else None

        # 1. Single /ip/hotspot/ip-binding/print covers BOTH:
        #      - old-MAC removal (if the credential moved devices)
        #      - existing-binding lookup for the current MAC
        #    The previous code did this as two separate /print calls back to
        #    back -- on busy routers each /print walks the binding table, so
        #    the round-trip cost shows up directly in user-perceived login
        #    latency. One scan is enough.
        bindings_resp = api.send_command("/ip/hotspot/ip-binding/print")
        existing_id = None
        old_binding_id = None
        if bindings_resp.get("success") and bindings_resp.get("data"):
            for b in bindings_resp["data"]:
                bm_raw = b.get("mac-address", "")
                if not bm_raw:
                    continue
                bm = normalize_mac_address(bm_raw)
                if bm == mac_address and existing_id is None:
                    existing_id = b.get(".id")
                elif wanted_old and bm == wanted_old and old_binding_id is None:
                    old_binding_id = b.get(".id")

        # 2. Capture the client IP BEFORE writing the bypass binding.
        #    When RouterOS processes a new bypass entry it immediately
        #    transitions the device out of hotspot tracking, which removes
        #    (or clears the address on) its /ip/hotspot/host row.  Reading
        #    the host table after the bypass is written therefore returns
        #    nothing, client_ip stays None, and the rate-limit queue is
        #    never created — leaving the user with unrestricted speed.
        #    Reading here, before the binding write, guarantees we capture
        #    the IP while the device is still a tracked hotspot guest.
        #    The ARP table is checked as a fallback for devices that
        #    connected without triggering a hotspot redirect.
        client_ip = None
        hosts_resp = api.send_command("/ip/hotspot/host/print")
        if hosts_resp.get("success") and hosts_resp.get("data"):
            for h in hosts_resp["data"]:
                hm = h.get("mac-address", "")
                if hm and normalize_mac_address(hm) == mac_address:
                    client_ip = h.get("address") or h.get("to-address")
                    if client_ip:
                        break

        if not client_ip:
            arp_resp = api.send_command("/ip/arp/print")
            if arp_resp.get("success") and arp_resp.get("data"):
                for entry in arp_resp["data"]:
                    am = entry.get("mac-address", "")
                    if am and normalize_mac_address(am) == mac_address:
                        client_ip = entry.get("address")
                        if client_ip:
                            break

        if old_binding_id:
            time.sleep(CMD_DELAY)
            api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": old_binding_id})

        # 3. Add or update the bypass IP-binding for the current MAC
        if existing_id:
            time.sleep(CMD_DELAY)
            br = api.send_command("/ip/hotspot/ip-binding/set", {
                "numbers": existing_id,
                "type": "bypassed",
                "comment": comment,
            })
        else:
            time.sleep(CMD_DELAY)
            br = api.send_command("/ip/hotspot/ip-binding/add", {
                "mac-address": mac_address,
                "type": "bypassed",
                "comment": comment,
            })
        if br.get("error"):
            logger.warning(
                "[ACCESS-CRED BIND] binding write FAILED router=%s mac=%s err=%s",
                router_info.get("ip"), mac_address, br.get("error"),
            )
            return {"error": "binding_failed", "message": br["error"]}

        # 4. Per-credential simple queue (only if a rate-limit is set AND we
        #    found a client IP; without an IP there's nothing to attach the
        #    queue to, and MikroTik would reject the call).
        if rate_limit and client_ip:
            queue_name = queue_name_for_credential(cred_id)
            queues_resp = api.send_command("/queue/simple/print")
            existing_qid = None
            if queues_resp.get("success") and queues_resp.get("data"):
                for q in queues_resp["data"]:
                    if q.get("name", "") == queue_name:
                        existing_qid = q.get(".id")
                        break

            target = f"{client_ip}/32"
            if existing_qid:
                time.sleep(CMD_DELAY)
                api.send_command("/queue/simple/set", {
                    "numbers": existing_qid,
                    "target": target,
                    "max-limit": rate_limit,
                    "comment": comment,
                })
            else:
                time.sleep(CMD_DELAY)
                api.send_command("/queue/simple/add", {
                    "name": queue_name,
                    "target": target,
                    "max-limit": rate_limit,
                    "comment": comment,
                })

        # NOTE: the "kick" step (removing /ip/hotspot/active + /ip/hotspot/host
        # entries to force MikroTik to re-evaluate against the bypass binding)
        # used to live here, but it MUST NOT run during the access-login HTTP
        # request: removing the host row drops the conntrack entry that's
        # anchoring the response packet back to the phone, and the phone then
        # sees a "network error" even though the API returned 200. The kick is
        # now exposed as a separate helper (`kick_mac_async`) and is scheduled
        # by the access-login route as a FastAPI BackgroundTask, so it runs
        # *after* the response has been delivered.
        elapsed_ms = int((time.monotonic() - bind_started) * 1000)
        logger.info(
            "[ACCESS-CRED BIND] ok router=%s mac=%s client_ip=%s elapsed_ms=%d",
            router_info.get("ip"), mac_address, client_ip, elapsed_ms,
        )
        return {"success": True, "client_ip": client_ip}
    finally:
        api.disconnect()


def _kick_mac_direct_api_sync(router_info: dict, mac_address: str) -> dict:
    """Remove the device's stale ``/ip/hotspot/active`` + ``/ip/hotspot/host``
    rows so MikroTik re-evaluates the MAC against the freshly-installed
    bypass IP-binding.

    Run this AFTER the access-login HTTP response has been sent to the phone
    (via FastAPI ``BackgroundTasks``). Doing it during the request itself
    drops the conntrack entry carrying the response and the phone sees a
    spurious network error.
    """
    logger.info(
        "[ACCESS-CRED KICK] start router=%s mac=%s",
        router_info.get("ip"), mac_address,
    )
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        logger.warning(
            "[ACCESS-CRED KICK] connect failed router=%s err=%s",
            router_info.get("ip"), api.last_connect_error,
        )
        return {
            "error": "connection_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        wanted = normalize_mac_address(mac_address)
        kicked = {"hosts_removed": 0, "sessions_removed": 0}

        try:
            active = api.send_command("/ip/hotspot/active/print")
            if active.get("success") and active.get("data"):
                for s in active["data"]:
                    sm = s.get("mac-address", "")
                    if sm and normalize_mac_address(sm) == wanted:
                        sid = s.get(".id")
                        if sid:
                            time.sleep(CMD_DELAY)
                            api.send_command("/ip/hotspot/active/remove", {"numbers": sid})
                            kicked["sessions_removed"] += 1
        except Exception as e:
            logger.warning("[ACCESS-CRED KICK] active-session removal failed mac=%s err=%s", wanted, e)

        try:
            hosts = api.send_command("/ip/hotspot/host/print")
            if hosts.get("success") and hosts.get("data"):
                for h in hosts["data"]:
                    hm = h.get("mac-address", "")
                    if hm and normalize_mac_address(hm) == wanted:
                        hid = h.get(".id")
                        if hid:
                            time.sleep(CMD_DELAY)
                            api.send_command("/ip/hotspot/host/remove", {"numbers": hid})
                            kicked["hosts_removed"] += 1
        except Exception as e:
            logger.warning("[ACCESS-CRED KICK] host-table removal failed mac=%s err=%s", wanted, e)

        logger.info(
            "[ACCESS-CRED KICK] done router=%s mac=%s hosts_removed=%s sessions_removed=%s",
            router_info.get("ip"), wanted,
            kicked["hosts_removed"], kicked["sessions_removed"],
        )
        return {"success": True, "kicked": kicked}
    finally:
        api.disconnect()


def _release_mac_direct_api_sync(router_info: dict, payload: dict) -> dict:
    """Remove the IP-binding + per-cred queue for a MAC. Used by the idle reaper
    and by reseller force-logout / revoke flows.
    """
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {
            "error": "connection_failed",
            "message": api.last_connect_error or "Failed to connect to router",
        }
    try:
        mac_address = normalize_mac_address(payload["mac_address"])
        cred_id = payload["cred_id"]
        removed = {"bindings": 0, "queues": 0}

        bindings = api.send_command("/ip/hotspot/ip-binding/print")
        if bindings.get("success") and bindings.get("data"):
            for b in bindings["data"]:
                bm = b.get("mac-address", "")
                if bm and normalize_mac_address(bm) == mac_address:
                    bid = b.get(".id")
                    if bid:
                        time.sleep(CMD_DELAY)
                        api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": bid})
                        removed["bindings"] += 1

        queue_name = queue_name_for_credential(cred_id)
        queues = api.send_command("/queue/simple/print")
        if queues.get("success") and queues.get("data"):
            for q in queues["data"]:
                if q.get("name", "") == queue_name:
                    qid = q.get(".id")
                    if qid:
                        time.sleep(CMD_DELAY)
                        api.send_command("/queue/simple/remove", {"numbers": qid})
                        removed["queues"] += 1

        return {"success": True, "removed": removed}
    finally:
        api.disconnect()


def _live_usage_direct_api_sync(router_info: dict, mac_address: str, queue_name: str) -> dict:
    """One-shot live-usage read: host entry for the bound MAC + matching simple-queue."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=10, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "message": api.last_connect_error}
    try:
        wanted = normalize_mac_address(mac_address)
        info: Dict[str, Any] = {"online": False}

        hosts = api.send_command("/ip/hotspot/host/print")
        if hosts.get("success") and hosts.get("data"):
            for h in hosts["data"]:
                hm = h.get("mac-address", "")
                if hm and normalize_mac_address(hm) == wanted:
                    info["online"] = True
                    info["bound_ip_address"] = h.get("address") or h.get("to-address")
                    info["uptime"] = h.get("uptime")
                    info["idle_time"] = h.get("idle-time")
                    info["bytes_in"] = _safe_int(h.get("bytes-in"))
                    info["bytes_out"] = _safe_int(h.get("bytes-out"))
                    break

        queues = api.send_command("/queue/simple/print")
        if queues.get("success") and queues.get("data"):
            for q in queues["data"]:
                if q.get("name", "") == queue_name:
                    rate = q.get("rate", "0/0")
                    rx_str, _, tx_str = rate.partition("/")
                    info["current_rx_rate_bps"] = _safe_int(rx_str)
                    info["current_tx_rate_bps"] = _safe_int(tx_str)
                    break

        return info
    finally:
        api.disconnect()


def _safe_int(v: Any) -> int:
    try:
        return int(v) if v not in (None, "") else 0
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# RADIUS path
# ---------------------------------------------------------------------------

async def _provision_radius(db: AsyncSession, cred: AccessCredential) -> dict:
    """Insert/replace radius_check + radius_reply rows for this credential.

    Uses ``customer_id = NULL`` (the FK is nullable for accounting tables in this
    codebase) and is keyed solely on ``username``.
    """
    username = cred.username

    await db.execute(text(
        "DELETE FROM radius_check WHERE username = :u AND customer_id IS NULL"
    ), {"u": username})
    await db.execute(text(
        "DELETE FROM radius_reply WHERE username = :u AND customer_id IS NULL"
    ), {"u": username})

    insert_check = text(
        "INSERT INTO radius_check (username, attribute, op, value, expiry, customer_id) "
        "VALUES (:u, :attr, :op, :val, NULL, NULL)"
    )
    await db.execute(insert_check, {
        "u": username, "attr": "Cleartext-Password", "op": ":=", "val": cred.password,
    })
    await db.execute(insert_check, {
        "u": username, "attr": "Simultaneous-Use", "op": ":=", "val": "1",
    })

    if cred.rate_limit:
        await db.execute(text(
            "INSERT INTO radius_reply (username, attribute, op, value, expiry, customer_id) "
            "VALUES (:u, :attr, :op, :val, NULL, NULL)"
        ), {
            "u": username, "attr": "Mikrotik-Rate-Limit", "op": ":=", "val": cred.rate_limit,
        })

    await db.commit()
    return {"success": True, "method": "radius"}


async def _deprovision_radius(db: AsyncSession, cred: AccessCredential) -> dict:
    await db.execute(text(
        "DELETE FROM radius_check WHERE username = :u AND customer_id IS NULL"
    ), {"u": cred.username})
    await db.execute(text(
        "DELETE FROM radius_reply WHERE username = :u AND customer_id IS NULL"
    ), {"u": cred.username})
    await db.commit()
    return {"success": True, "method": "radius"}


# ---------------------------------------------------------------------------
# Public service API (used by routes)
# ---------------------------------------------------------------------------

def _router_info(router: Router) -> dict:
    return {
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
        "name": router.name,
    }


async def provision_credential(db: AsyncSession, cred: AccessCredential, router: Router) -> dict:
    """Push a credential to the router. Idempotent."""
    if router.auth_method == RouterAuthMethod.RADIUS:
        return await _provision_radius(db, cred)

    payload = {
        "username": cred.username,
        "password": cred.password,
        "rate_limit": cred.rate_limit or "",
        "comment": comment_for_credential(cred),
    }
    return await asyncio.to_thread(_provision_direct_api_sync, _router_info(router), payload)


async def deprovision_credential(db: AsyncSession, cred: AccessCredential, router: Router) -> dict:
    """Remove a credential from the router (also clears any active session/binding/queue)."""
    if router.auth_method == RouterAuthMethod.RADIUS:
        return await _deprovision_radius(db, cred)

    payload = {
        "cred_id": cred.id,
        "username": cred.username,
        "bound_mac_address": cred.bound_mac_address,
    }
    return await asyncio.to_thread(_deprovision_direct_api_sync, _router_info(router), payload)


async def bind_mac_for_login(
    cred: AccessCredential, router: Router, mac_address: str,
) -> dict:
    """Install the bypass binding + queue for the user's MAC.

    Used by the public access-login endpoint after the credential validates.
    For RADIUS routers the binding is implicit (RADIUS authorizes the user when
    they hit the MikroTik captive portal), so we only run the IP-binding flow
    on DIRECT_API routers.

    This intentionally does NOT kick the device's stale hotspot host/active
    entries -- that step has to happen *after* the HTTP response has been
    delivered to the phone (see ``kick_mac_async``).
    """
    if router.auth_method == RouterAuthMethod.RADIUS:
        return {"success": True, "method": "radius", "client_ip": None}

    payload = {
        "cred_id": cred.id,
        "username": cred.username,
        "mac_address": mac_address,
        "rate_limit": cred.rate_limit or "",
        "previous_mac_address": cred.bound_mac_address,
    }
    return await asyncio.to_thread(_bind_mac_direct_api_sync, _router_info(router), payload)


# Delay (seconds) between the access-login response being sent to the phone
# and the kick that forces MikroTik to re-evaluate the bypass binding.
#
# FastAPI BackgroundTasks run AFTER the response bytes have been handed to
# the OS network stack, so even at 0 s the kick never races with the response
# itself. The conntrack entry for the phone→server TCP session is a Layer-4
# kernel structure that persists independently of the hotspot host table; it
# is not torn down when the host entry is removed.
#
# Keeping this at 0 is important for two reasons:
#  1. Android/iOS captive-portal detection sends a probe request (to
#     connectivitycheck.gstatic.com / captive.apple.com) within ~200 ms of
#     the device seeing the 200 OK. If the stale "unauthorized" host entry is
#     still in place at that point, MikroTik redirects the probe to the
#     captive portal, the OS marks the network as captive, and the user sees
#     a "Sign in to network" notification even though they just logged in.
#  2. The background REAPER job treats any MAC absent from /ip/hotspot/host
#     as idle and removes its bypass binding. A non-zero kick delay creates a
#     window where the host entry is gone but the REAPER can fire and
#     mistakenly release the credential.
KICK_DELAY_SECONDS = 0


async def kick_mac_async(router_info: dict, mac_address: str, *, is_radius: bool = False) -> None:
    """Background-task helper.

    Schedule this with FastAPI's ``BackgroundTasks`` from the access-login
    route. It removes the device's stale ``/ip/hotspot/host`` + ``/ip/hotspot/
    active`` entries so MikroTik re-evaluates against the bypass binding
    that the request just installed.

    The task is intentionally delayed by ``KICK_DELAY_SECONDS`` so that the
    phone has time to establish a real browsing session through the new
    bypass binding *before* the kick disturbs MikroTik's connection-tracking
    state. See the comment on ``KICK_DELAY_SECONDS`` for why.

    Takes a plain dict (built via ``router_info_for_kick``) rather than an
    ORM ``Router`` because the request-scoped DB session is already closed
    by the time a BackgroundTask runs, so the ORM object would be detached.

    Failures are swallowed: by the time we get here the user already has
    their 200 OK and the bypass binding is in place, so they'll come online
    on the next packet anyway.
    """
    if is_radius:
        return
    try:
        await asyncio.sleep(KICK_DELAY_SECONDS)
        await asyncio.to_thread(
            _kick_mac_direct_api_sync,
            router_info,
            mac_address,
        )
    except Exception as e:
        logger.warning("[ACCESS-CRED KICK] background task failed mac=%s err=%s", mac_address, e)


def router_info_for_kick(router: Router) -> dict:
    """Snapshot the router's connection details into a plain dict that's safe
    to hand to a FastAPI BackgroundTask (which runs after the DB session has
    closed)."""
    return _router_info(router)


async def release_mac(cred: AccessCredential, router: Router, mac_address: str) -> dict:
    """Remove the per-MAC bypass binding + queue without removing the credential."""
    if router.auth_method == RouterAuthMethod.RADIUS:
        return {"success": True, "method": "radius"}

    payload = {
        "cred_id": cred.id,
        "mac_address": mac_address,
    }
    return await asyncio.to_thread(_release_mac_direct_api_sync, _router_info(router), payload)


async def fetch_live_usage(cred: AccessCredential, router: Router) -> dict:
    """Best-effort live read of host/queue stats for the bound MAC. Failures are
    swallowed so reseller GET endpoints stay responsive when a router is offline.
    """
    if not cred.bound_mac_address or router.auth_method == RouterAuthMethod.RADIUS:
        return {"online": False}
    try:
        return await asyncio.to_thread(
            _live_usage_direct_api_sync,
            _router_info(router),
            cred.bound_mac_address,
            queue_name_for_credential(cred.id),
        )
    except Exception as e:
        logger.debug(f"Live-usage read failed for cred {cred.id}: {e}")
        return {"online": False}


def serialize_credential(
    cred: AccessCredential,
    *,
    include_password: bool = False,
    live: Optional[dict] = None,
) -> dict:
    """Render a credential for API responses, with an optional live-usage block."""
    data = {
        "id": cred.id,
        "router_id": cred.router_id,
        "username": cred.username,
        "rate_limit": cred.rate_limit,
        "data_cap_mb": cred.data_cap_mb,
        "label": cred.label,
        "status": cred.status.value,
        "bound_mac_address": cred.bound_mac_address,
        "bound_at": cred.bound_at.isoformat() if cred.bound_at else None,
        "last_login_at": cred.last_login_at.isoformat() if cred.last_login_at else None,
        "last_seen_at": cred.last_seen_at.isoformat() if cred.last_seen_at else None,
        "last_seen_ip": cred.last_seen_ip,
        "total_bytes_in": int(cred.total_bytes_in or 0),
        "total_bytes_out": int(cred.total_bytes_out or 0),
        "created_at": cred.created_at.isoformat() if cred.created_at else None,
        "updated_at": cred.updated_at.isoformat() if cred.updated_at else None,
        "revoked_at": cred.revoked_at.isoformat() if cred.revoked_at else None,
    }
    if include_password:
        data["password"] = cred.password

    if live is None:
        live = {"online": False}
    data["live"] = {
        "is_online": bool(live.get("online")),
        "bound_mac_address": cred.bound_mac_address,
        "bound_ip_address": live.get("bound_ip_address"),
        "uptime_this_session": live.get("uptime"),
        "idle_time": live.get("idle_time"),
        "current_rx_rate_bps": live.get("current_rx_rate_bps"),
        "current_tx_rate_bps": live.get("current_tx_rate_bps"),
    }
    return data

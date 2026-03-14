import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.mikrotik_api import MikroTikAPI
from app.config import settings

logger = logging.getLogger("pppoe_provisioning")


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
        rate_limit = api._parse_speed_to_mikrotik(payload["bandwidth_limit"])
        profile_name = f"pppoe_{rate_limit.replace('/', '_')}"

        base_profile = api.get_active_pppoe_profile()
        base_profile_data = base_profile.get("data") if base_profile.get("found") else {}

        profile_result = api.ensure_pppoe_profile(
            profile_name,
            rate_limit,
            local_address=base_profile_data.get("local_address", ""),
            pool_name=base_profile_data.get("remote_address", ""),
            dns_server=base_profile_data.get("dns_server", ""),
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

        bypass_result = api.ensure_pppoe_fasttrack_bypass()
        if bypass_result.get("error"):
            logger.warning(f"[PPPoE] FastTrack bypass ensure failed: {bypass_result['error']}")

        # Force the client to reconnect so any profile/rate-limit change applies immediately.
        disconnect_result = api.disconnect_pppoe_session(payload["pppoe_username"])

        logger.info(
            f"[PPPoE] Provisioned {payload['pppoe_username']} "
            f"with profile {profile_name} on {router_ip}"
        )

        return {
            "success": True,
            "pppoe_username": payload["pppoe_username"],
            "profile": profile_name,
            "rate_limit": rate_limit,
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
        remove_result = api.remove_pppoe_secret(pppoe_username)

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

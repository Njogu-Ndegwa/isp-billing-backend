"""Shared management-tunnel health helpers.

The wg-manager call is deliberately separate from database work. Callers must
finish and commit their short DB section before awaiting ``fetch_manager_health``.
"""

from datetime import datetime, timezone
import ipaddress

import httpx

from app.config import settings
from app.services.provisioning import _wg_client


def classify_primary_tunnel(ip_address: str | None) -> str | None:
    try:
        address = ipaddress.ip_address(ip_address or "")
    except ValueError:
        return None
    octets = str(address).split(".")
    if len(octets) != 4 or octets[:2] != ["10", "0"]:
        return None
    third = int(octets[2])
    if 0 <= third <= 99:
        return "wireguard"
    if 100 <= third <= 199:
        return "l2tp"
    return None


def fleet_counts(rows) -> dict:
    counts = {
        "wireguard": {"registered_routers": 0, "online_routers": 0},
        "l2tp": {"registered_routers": 0, "online_routers": 0},
    }
    for ip_address, last_status in rows:
        tunnel = classify_primary_tunnel(ip_address)
        if not tunnel:
            continue
        counts[tunnel]["registered_routers"] += 1
        if last_status:
            counts[tunnel]["online_routers"] += 1
    return counts


async def fetch_manager_health(timeout: float = 6.0) -> dict:
    async with _wg_client(timeout=timeout) as client:
        response = await client.get(
            "/health",
            headers={"X-API-Key": settings.WG_MANAGER_SECRET},
        )
        response.raise_for_status()
        return response.json()


def build_management_tunnel_health(manager: dict | None, fleet: dict, error: str | None = None) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    if manager is None:
        issue = "Tunnel manager is unreachable; WireGuard and L2TP state cannot be verified."
        return {
            "generated_at": generated_at,
            "overall_status": "critical",
            "manager_reachable": False,
            "summary": issue,
            "issues": [issue],
            "services": {
                name: {**counts, "available": None}
                for name, counts in fleet.items()
            },
            "error": error or "manager_unavailable",
        }

    wireguard = dict(manager.get("wireguard") or {})
    l2tp = dict(manager.get("l2tp") or {})
    wireguard.update(fleet["wireguard"])
    l2tp.update(fleet["l2tp"])

    issues = []
    if not wireguard.get("available"):
        issues.append(
            f"WireGuard is unavailable; {wireguard['registered_routers']} registered routers may be unreachable."
        )
    if l2tp.get("required") and not l2tp.get("available"):
        issues.append(
            f"L2TP/IPsec is unavailable; {l2tp['registered_routers']} registered routers may be unreachable."
        )

    overall = "critical" if issues else "healthy"
    summary = "All primary management tunnel services are operational." if not issues else " ".join(issues)
    return {
        "generated_at": generated_at,
        "overall_status": overall,
        "manager_reachable": True,
        "summary": summary,
        "issues": issues,
        "services": {"wireguard": wireguard, "l2tp": l2tp},
    }


def manager_error_code(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "manager_timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"manager_http_{exc.response.status_code}"
    return "manager_unavailable"

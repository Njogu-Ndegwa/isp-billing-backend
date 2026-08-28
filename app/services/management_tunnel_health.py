"""Primary and Hetzner emergency management-tunnel health helpers.

Manager calls are deliberately separate from database work. Callers must finish
and commit their short DB section before awaiting either network request.
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


async def fetch_insurance_manager_health(timeout: float | None = None) -> dict:
    base_url = (settings.INSURANCE_WG_MANAGER_URL or "").rstrip("/")
    if not base_url:
        raise RuntimeError("INSURANCE_WG_MANAGER_URL is not configured")
    request_timeout = timeout or settings.INSURANCE_MANAGER_TIMEOUT
    async with httpx.AsyncClient(base_url=base_url, timeout=request_timeout) as client:
        response = await client.get(
            "/health",
            headers={"X-API-Key": settings.INSURANCE_WG_MANAGER_SECRET},
        )
        response.raise_for_status()
        return response.json()


def _unknown_services(counts: dict) -> dict:
    return {
        name: {**service_counts, "available": None}
        for name, service_counts in counts.items()
    }


def _primary_plane(
    manager: dict | None,
    fleet: dict,
    error: str | None,
) -> tuple[dict, list[str]]:
    if manager is None:
        issue = "Primary tunnel manager is unreachable; AWS WireGuard and L2TP cannot be verified."
        return {
            "manager_reachable": False,
            "overall_status": "critical",
            "summary": issue,
            "services": _unknown_services(fleet),
            "error": error or "manager_unavailable",
        }, [issue]

    wireguard = dict(manager.get("wireguard") or {})
    l2tp = dict(manager.get("l2tp") or {})
    wireguard.update(fleet["wireguard"])
    l2tp.update(fleet["l2tp"])

    issues = []
    if not wireguard.get("available"):
        issues.append(
            f"Primary WireGuard is unavailable; {wireguard['registered_routers']} registered routers may be unreachable."
        )
    if l2tp.get("required") and not l2tp.get("available"):
        issues.append(
            f"Primary L2TP/IPsec is unavailable; {l2tp['registered_routers']} registered routers may be unreachable."
        )
    summary = "Primary AWS management tunnels are operational." if not issues else " ".join(issues)
    return {
        "manager_reachable": True,
        "overall_status": "critical" if issues else "healthy",
        "summary": summary,
        "services": {"wireguard": wireguard, "l2tp": l2tp},
    }, issues


def _insurance_plane(
    manager: dict | None,
    error: str | None,
) -> tuple[dict, list[str]]:
    base = {
        "server_public_ip": settings.INSURANCE_SERVER_PUBLIC_IP or None,
        "vpn_ip": settings.INSURANCE_SERVER_VPN_IP or None,
        "subnet": settings.INSURANCE_WG_SUBNET or None,
        "mode": "manual_rescue",
        "automatic_failover_enabled": False,
    }
    if manager is None:
        issue = "Hetzner emergency tunnel manager is unreachable; backup control cannot be verified."
        services = {
            "wireguard": {"available": None, "registered_routers": 0, "online_routers": 0},
            "l2tp": {"available": None, "registered_routers": 0, "online_routers": 0},
        }
        return {
            **base,
            "manager_reachable": False,
            "overall_status": "critical",
            "summary": issue,
            "services": services,
            "error": error or "manager_unavailable",
        }, [issue]

    wireguard = dict(manager.get("wireguard") or {})
    if not wireguard and "wg_available" in manager:
        wireguard = {
            "available": bool(manager.get("wg_available")),
            "interface": manager.get("interface"),
        }
    l2tp = dict(manager.get("l2tp") or {})
    wireguard.update({
        "registered_routers": wireguard.get("configured_peers", 0),
        "online_routers": wireguard.get("recent_handshakes", 0),
    })
    l2tp.update({
        "registered_routers": l2tp.get("configured_peers", 0),
        "online_routers": l2tp.get("active_sessions", 0),
    })

    issues = []
    if wireguard.get("available") is not True:
        issues.append("Hetzner emergency WireGuard is unavailable or cannot be verified.")
    if l2tp.get("available") is not True:
        issues.append("Hetzner emergency L2TP/IPsec is unavailable or cannot be verified.")
    summary = "Hetzner emergency tunnels are operational." if not issues else " ".join(issues)
    return {
        **base,
        "manager_reachable": True,
        "overall_status": "critical" if issues else "healthy",
        "summary": summary,
        "services": {"wireguard": wireguard, "l2tp": l2tp},
    }, issues


def build_management_tunnel_health(
    manager: dict | None,
    fleet: dict,
    error: str | None = None,
    *,
    insurance_manager: dict | None = None,
    insurance_error: str | None = None,
) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    primary, primary_issues = _primary_plane(manager, fleet, error)
    insurance, insurance_issues = _insurance_plane(insurance_manager, insurance_error)
    issues = primary_issues + insurance_issues
    if primary_issues and not insurance_issues:
        summary = (
            f"{' '.join(primary_issues)} Hetzner emergency tunnels are operational, "
            "but application failover is manual."
        )
    elif issues:
        summary = " ".join(issues)
    else:
        summary = (
            "Primary AWS and Hetzner emergency tunnels are operational. "
            "Application failover to Hetzner is currently manual."
        )
    return {
        "generated_at": generated_at,
        "overall_status": "critical" if issues else "healthy",
        "manager_reachable": primary["manager_reachable"],
        "summary": summary,
        "issues": issues,
        "services": primary["services"],
        "primary": primary,
        "insurance": insurance,
        "automatic_failover_enabled": False,
    }


def manager_error_code(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "manager_timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"manager_http_{exc.response.status_code}"
    return "manager_unavailable"

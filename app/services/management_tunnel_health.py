"""Primary and Hetzner emergency management-tunnel health helpers.

Manager calls are deliberately separate from database work. Callers must finish
and commit their short DB section before awaiting either network request.
"""

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress

import httpx

from app.config import settings
from app.services.provisioning import _wg_client
from app.services.router_availability import (
    ROUTER_STATUS_STALE_AFTER_SECONDS,
    summarize_router_flaps,
)


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


def build_fleet_flap_history(
    routers: list[dict],
    checks,
    *,
    hours: int = 24,
    now: datetime | None = None,
) -> dict:
    """Summarize management-path transitions for the admin tunnel dashboard."""
    now = now or datetime.utcnow()
    checks_by_router = defaultdict(list)
    for check in checks:
        router_id = check.get("router_id") if isinstance(check, dict) else check.router_id
        checks_by_router[router_id].append(check)

    rows = []
    for router in routers:
        summary = summarize_router_flaps(checks_by_router.get(router["id"], []), now=now)
        tunnel_type = classify_primary_tunnel(router.get("ip_address"))
        if not tunnel_type:
            continue
        rows.append({
            "router_id": router["id"],
            "router_name": router.get("name"),
            "identity": router.get("identity"),
            "ip_address": router.get("ip_address"),
            "tunnel_type": tunnel_type,
            "current_status": summary["status"],
            "sample_count": summary["sample_count"],
            "transition_count": summary["transition_count"],
            "outage_count": summary["outage_count"],
            "is_flapping": summary["is_flapping"],
            "last_transition_at": summary["last_transition_at"],
        })

    affected = sorted(
        (row for row in rows if row["is_flapping"]),
        key=lambda row: (
            -row["transition_count"],
            -row["outage_count"],
            row["router_name"] or row["identity"] or "",
        ),
    )
    return {
        "window_hours": hours,
        "monitored_routers": sum(1 for row in rows if row["sample_count"]),
        "affected_count": len(affected),
        "total_transitions": sum(row["transition_count"] for row in rows),
        "routers": affected[:25],
    }


def build_fleet_tunnel_status(
    routers: list[dict],
    checks,
    *,
    now: datetime | None = None,
) -> dict:
    """Build a current, cached per-router tunnel state and early-warning queue."""
    now = now or datetime.utcnow()
    checks_by_router = defaultdict(list)
    for check in checks:
        router_id = check.get("router_id") if isinstance(check, dict) else check.router_id
        checks_by_router[router_id].append(check)

    counts = {"online": 0, "watch": 0, "offline": 0, "unknown": 0}
    rows = []
    for router in routers:
        tunnel_type = classify_primary_tunnel(router.get("ip_address"))
        if not tunnel_type:
            continue

        summary = summarize_router_flaps(checks_by_router.get(router["id"], []), now=now)
        last_checked_at = router.get("last_checked_at")
        age_seconds = (
            max(0, round((now - last_checked_at).total_seconds()))
            if last_checked_at
            else None
        )
        status_is_fresh = (
            age_seconds is not None and age_seconds <= ROUTER_STATUS_STALE_AFTER_SECONDS
        )
        last_status = router.get("last_status")

        if status_is_fresh and last_status is False:
            state = "offline"
            reason = "Two recent probes confirmed the management tunnel is down."
        elif status_is_fresh and last_status is True and summary["pending_outage"]:
            state = "watch"
            reason = "The latest probe failed; waiting for a second failure before declaring an outage."
        elif status_is_fresh and last_status is True and summary["is_flapping"]:
            state = "watch"
            reason = "Repeated outage and recovery cycles were detected in the last 24 hours."
        elif status_is_fresh and last_status is True:
            state = "online"
            reason = "The latest confirmed management-tunnel probe succeeded."
        else:
            state = "unknown"
            reason = "There is no reachability sample newer than 10 minutes."

        counts[state] += 1
        rows.append({
            "router_id": router["id"],
            "router_name": router.get("name"),
            "identity": router.get("identity"),
            "ip_address": router.get("ip_address"),
            "tunnel_type": tunnel_type,
            "state": state,
            "reason": reason,
            "last_checked_at": last_checked_at.isoformat() if last_checked_at else None,
            "status_age_seconds": age_seconds,
            "status_source": router.get("last_status_source"),
            "pending_outage": summary["pending_outage"],
            "is_flapping": summary["is_flapping"],
            "transition_count": summary["transition_count"],
            "outage_count": summary["outage_count"],
            "last_transition_at": summary["last_transition_at"],
        })

    priority = {"offline": 0, "watch": 1, "unknown": 2, "online": 3}
    attention = sorted(
        (row for row in rows if row["state"] != "online"),
        key=lambda row: (
            priority[row["state"]],
            -row["transition_count"],
            row["router_name"] or row["identity"] or "",
        ),
    )
    return {
        "stale_after_seconds": ROUTER_STATUS_STALE_AFTER_SECONDS,
        "total_routers": len(rows),
        "online_count": counts["online"],
        "watch_count": counts["watch"],
        "offline_count": counts["offline"],
        "unknown_count": counts["unknown"],
        "attention_count": len(attention),
        "routers": attention[:50],
    }


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
    ipsec_connmark = dict(manager.get("ipsec_connmark") or {})
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
    if ipsec_connmark.get("healthy") is False:
        issues.append(
            f"IPsec early warning: {ipsec_connmark.get('duplicate_tuple_count', 0)} duplicate NAT-T tuple(s) "
            f"contain {ipsec_connmark.get('superseded_rule_count', 0)} superseded connmark rule(s)."
        )
    summary = "Primary AWS management tunnels are operational." if not issues else " ".join(issues)
    return {
        "manager_reachable": True,
        "overall_status": "critical" if issues else "healthy",
        "summary": summary,
        "services": {"wireguard": wireguard, "l2tp": l2tp},
        "ipsec_connmark": ipsec_connmark,
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
    flap_history: dict | None = None,
    fleet_status: dict | None = None,
) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    primary, primary_issues = _primary_plane(manager, fleet, error)
    insurance, insurance_issues = _insurance_plane(insurance_manager, insurance_error)
    flap_history = flap_history or {
        "window_hours": 24,
        "monitored_routers": 0,
        "affected_count": 0,
        "total_transitions": 0,
        "routers": [],
    }
    fleet_status = fleet_status or {
        "stale_after_seconds": ROUTER_STATUS_STALE_AFTER_SECONDS,
        "total_routers": 0,
        "online_count": 0,
        "watch_count": 0,
        "offline_count": 0,
        "unknown_count": 0,
        "attention_count": 0,
        "routers": [],
    }
    flap_issues = []
    if flap_history.get("affected_count"):
        flap_issues.append(
            f"{flap_history['affected_count']} router(s) are repeatedly losing and recovering their management tunnel."
        )
    issues = primary_issues + insurance_issues + flap_issues
    if primary_issues and not insurance_issues:
        summary = (
            f"{' '.join(primary_issues)} Hetzner emergency tunnels are operational, "
            "but application failover is manual."
        )
        if flap_issues:
            summary = f"{summary} {' '.join(flap_issues)}"
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
        "fleet_status": fleet_status,
        "flapping": flap_history,
        "automatic_failover_enabled": False,
    }


def manager_error_code(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "manager_timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"manager_http_{exc.response.status_code}"
    return "manager_unavailable"

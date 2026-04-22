from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional
from datetime import datetime

from app.db.database import get_db
from app.db.models import Customer
from app.services.auth import verify_token, get_current_user
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_helpers import get_router_by_id
from app.services.log_persistence import persist_notable_logs
from app.services.router_concurrency import run_with_guard
from app.services.router_availability import record_router_availability

import asyncio
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pppoe-monitor"])

_pppoe_overview_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_OVERVIEW_CACHE_TTL = 60  # 60 seconds -- overview changes slowly, no need to hit router every refresh


# ---------------------------------------------------------------------------
# Sync helpers (run in thread pool)
# ---------------------------------------------------------------------------

def _pppoe_overview_sync(router_info: dict, db_pppoe_ports: list, db_dual_ports: list = None) -> dict:
    """Gather all PPPoE infrastructure data in one connection."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        checks = []

        pppoe_servers = api.get_pppoe_server_status()
        servers = pppoe_servers.get("data", []) if pppoe_servers.get("success") else []
        enabled_servers = [s for s in servers if not s["disabled"]]
        access_state = api.get_pppoe_access_state()
        attachment_map = access_state.get("attachment_map", {}) if access_state.get("success") else {}
        checks.append({
            "check": "pppoe_server",
            "description": "PPPoE server service running",
            "passed": len(enabled_servers) > 0,
            "detail": enabled_servers if enabled_servers else "No PPPoE server found or all disabled",
        })

        bridge_data = api.get_bridge_ports_status()
        bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
        bridge_ports = bridge_data.get("ports", []) if bridge_data.get("success") else []

        pppoe_bridge = bridges.get("bridge-pppoe")
        checks.append({
            "check": "pppoe_bridge",
            "description": "PPPoE shared infrastructure is available",
            "passed": (
                (pppoe_bridge is not None and pppoe_bridge.get("running", False))
                or bool(enabled_servers)
            ),
            "detail": pppoe_bridge if pppoe_bridge else {
                "mode": access_state.get("mode", "unknown"),
                "message": "Direct-interface PPPoE mode in use",
            },
        })

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports}
        port_checks = []
        any_port_up = False
        for port_name in (db_pppoe_ports or []):
            attachment = attachment_map.get(port_name, {})
            actual_mode = attachment.get("mode", "none")
            actual_bridge = port_bridge_map.get(port_name)
            iface = ifaces.get(port_name, {})
            link_up = iface.get("running", False)
            if link_up:
                any_port_up = True
            port_checks.append({
                "port": port_name,
                "expected_mode": "direct",
                "actual_mode": actual_mode,
                "actual_bridge": actual_bridge or "(none)",
                "server_interface": attachment.get("server_interface", ""),
                "attached": port_name in access_state.get("ports", []),
                "needs_migration": actual_mode == "legacy_bridge",
                "link_up": link_up,
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
            })
        checks.append({
            "check": "pppoe_ports",
            "description": "PPPoE ports attached correctly with link up",
            "passed": all(p["attached"] and p["link_up"] for p in port_checks) if port_checks else bool(db_dual_ports),
            "any_port_up": any_port_up,
            "detail": port_checks if port_checks else "No PPPoE ports configured in DB",
        })

        # Dual-mode ports (PPPoE + Hotspot on same bridge)
        dual_port_checks = []
        has_dual = access_state.get("has_dual", False)
        for port_name in (db_dual_ports or []):
            iface = ifaces.get(port_name, {})
            link_up = iface.get("running", False)
            actual_bridge = port_bridge_map.get(port_name)
            attachment = attachment_map.get(port_name, {})
            dual_port_checks.append({
                "port": port_name,
                "mode": "dual",
                "actual_bridge": actual_bridge or "(none)",
                "pppoe_attachment_mode": attachment.get("mode", "none"),
                "pppoe_server_on_bridge": has_dual and attachment.get("mode") == "dual",
                "link_up": link_up,
            })
        if dual_port_checks:
            checks.append({
                "check": "dual_ports",
                "description": "Dual-mode ports (PPPoE + Hotspot) on the dual bridge",
                "passed": has_dual and all(
                    p["pppoe_attachment_mode"] == "dual" and p["link_up"] for p in dual_port_checks
                ),
                "detail": dual_port_checks,
            })

        ppp_profiles = api.get_ppp_profiles()
        profile_list = ppp_profiles.get("data", []) if ppp_profiles.get("success") else []
        checks.append({
            "check": "ppp_profiles",
            "description": "PPP profiles exist",
            "passed": len(profile_list) > 0,
            "detail": profile_list,
        })

        pool_name = "pppoe-pool"
        if enabled_servers:
            server_profile_name = enabled_servers[0].get("default_profile", "")
            for prof in profile_list:
                if prof["name"] == server_profile_name and prof.get("remote_address"):
                    pool_name = prof["remote_address"]
                    break

        pool_data = api.get_ip_pool_status(pool_name)
        pools = pool_data.get("pools", []) if pool_data.get("success") else []
        pool_ok = len(pools) > 0 and not any(p.get("exhausted") for p in pools)
        checks.append({
            "check": "ip_pool",
            "description": f"IP pool '{pool_name}' configured and not exhausted",
            "passed": pool_ok,
            "detail": pools if pools else f"Pool '{pool_name}' not found",
        })

        nat_data = api.get_nat_rules()
        nat_rules = nat_data.get("data", []) if nat_data.get("success") else []
        masquerade_exists = any(
            r["action"] == "masquerade" and not r["disabled"]
            for r in nat_rules
        )
        pppoe_masquerade = any(
            r["action"] == "masquerade" and not r["disabled"]
            and ("pppoe" in r.get("comment", "").lower() or "192.168.89" in r.get("src_address", ""))
            for r in nat_rules
        )
        checks.append({
            "check": "nat_masquerade",
            "description": "NAT masquerade rule for PPPoE subnet",
            "passed": pppoe_masquerade or masquerade_exists,
            "specific_pppoe_rule": pppoe_masquerade,
            "any_masquerade": masquerade_exists,
            "detail": [r for r in nat_rules if r["action"] == "masquerade"],
        })

        active_data = api.get_active_pppoe_sessions()
        session_count = active_data.get("count", 0) if active_data.get("success") else 0

        all_passed = all(c["passed"] for c in checks)
        return {
            "success": True,
            "healthy": all_passed,
            "active_sessions": session_count,
            "checks": checks,
        }
    except Exception as e:
        logger.error(f"PPPoE overview error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _pppoe_diagnose_sync(router_info: dict, username: str, db_pppoe_ports: list) -> dict:
    """Run layered PPPoE diagnostics for a single username."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        issues = []
        info = {}

        # --- Layer 1: Physical ---
        bridge_data = api.get_bridge_ports_status()
        bridges = bridge_data.get("bridges", {}) if bridge_data.get("success") else {}
        bridge_ports_list = bridge_data.get("ports", []) if bridge_data.get("success") else []
        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports_list}
        access_state = api.get_pppoe_access_state()
        attachment_map = access_state.get("attachment_map", {}) if access_state.get("success") else {}

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        any_link_up = False
        port_details = []
        for port_name in (db_pppoe_ports or []):
            attachment = attachment_map.get(port_name, {})
            actual_mode = attachment.get("mode", "none")
            actual_bridge = port_bridge_map.get(port_name)
            iface = ifaces.get(port_name, {})
            link_up = iface.get("running", False)
            if link_up:
                any_link_up = True
            port_details.append({
                "port": port_name,
                "attachment_mode": actual_mode,
                "server_interface": attachment.get("server_interface", ""),
                "bridge": actual_bridge or "(none)",
                "link_up": link_up,
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
            })
            if port_name not in access_state.get("ports", []):
                issues.append({
                    "severity": "critical",
                    "layer": "access",
                    "message": f"Port {port_name} is not attached to PPPoE access",
                    "recommendation": "Reconfigure PPPoE ports via PUT /api/routers/{id}/pppoe-ports",
                })
            elif actual_mode == "legacy_bridge":
                issues.append({
                    "severity": "info",
                    "layer": "access",
                    "message": f"Port {port_name} is still using legacy bridge-based PPPoE mode",
                    "recommendation": "Re-save the PPPoE port configuration to migrate this router to direct-interface mode",
                })
            elif actual_bridge:
                issues.append({
                    "severity": "critical",
                    "layer": "access",
                    "message": f"Port {port_name} is directly attached to PPPoE but still belongs to bridge '{actual_bridge}'",
                    "recommendation": "Reconfigure PPPoE ports so the port is unbridged in direct PPPoE mode",
                })
            if iface.get("rx_error", 0) > 0 or iface.get("tx_error", 0) > 0:
                issues.append({
                    "severity": "warning",
                    "layer": "physical",
                    "message": f"Port {port_name} has RX/TX errors (rx={iface.get('rx_error')}, tx={iface.get('tx_error')})",
                    "recommendation": "Check cable or replace it",
                })

        info["ports"] = port_details

        if db_pppoe_ports and not any_link_up:
            issues.append({
                "severity": "critical",
                "layer": "physical",
                "message": "No PPPoE port has link up -- no cable connected",
                "recommendation": "Check physical cable connections to PPPoE ports",
            })

        # --- Layer 2: PPPoE service ---
        pppoe_servers = api.get_pppoe_server_status()
        servers = pppoe_servers.get("data", []) if pppoe_servers.get("success") else []
        enabled_servers = [s for s in servers if not s["disabled"]]
        if not enabled_servers:
            issues.append({
                "severity": "critical",
                "layer": "service",
                "message": "PPPoE server is not running or disabled",
                "recommendation": "Enable PPPoE server on the selected PPPoE interface(s)",
            })
        info["pppoe_servers"] = servers
        info["pppoe_access"] = access_state if access_state.get("success") else {"error": access_state.get("error")}

        # --- Layer 3: Shared bridge infrastructure ---
        pppoe_bridge = bridges.get("bridge-pppoe")
        if not pppoe_bridge and not enabled_servers:
            issues.append({
                "severity": "critical",
                "layer": "bridge",
                "message": "bridge-pppoe does not exist and no PPPoE server is enabled",
                "recommendation": "Set up PPPoE infrastructure via PUT /api/routers/{id}/pppoe-ports",
            })
        elif pppoe_bridge and not pppoe_bridge.get("running", False):
            issues.append({
                "severity": "warning",
                "layer": "bridge",
                "message": "bridge-pppoe exists but is not running",
                "recommendation": "Check shared PPPoE infrastructure on the router",
            })
        info["bridge_pppoe"] = pppoe_bridge

        pool_name = "pppoe-pool"
        profiles = api.get_ppp_profiles()
        profile_list = profiles.get("data", []) if profiles.get("success") else []
        if enabled_servers:
            server_profile_name = enabled_servers[0].get("default_profile", "")
            for prof in profile_list:
                if prof["name"] == server_profile_name and prof.get("remote_address"):
                    pool_name = prof["remote_address"]
                    break

        pool_data = api.get_ip_pool_status(pool_name)
        pools = pool_data.get("pools", []) if pool_data.get("success") else []
        if not pools:
            issues.append({
                "severity": "critical",
                "layer": "service",
                "message": f"IP pool '{pool_name}' not found",
                "recommendation": "Create the IP pool for PPPoE clients",
            })
        elif any(p.get("exhausted") for p in pools):
            issues.append({
                "severity": "critical",
                "layer": "service",
                "message": f"IP pool '{pool_name}' is exhausted -- no addresses available",
                "recommendation": "Expand pool range or disconnect stale sessions",
            })
        info["pool"] = pools

        nat_data = api.get_nat_rules()
        nat_rules = nat_data.get("data", []) if nat_data.get("success") else []
        has_masquerade = any(r["action"] == "masquerade" and not r["disabled"] for r in nat_rules)
        if not has_masquerade:
            issues.append({
                "severity": "warning",
                "layer": "service",
                "message": "No active NAT masquerade rule found -- PPPoE clients may connect but have no internet",
                "recommendation": "Add srcnat masquerade rule for PPPoE subnet",
            })

        # --- Layer 4: User/Auth ---
        secret_data = api.get_pppoe_secret_detail(username)
        secret = secret_data.get("data") if secret_data.get("found") else None
        info["secret"] = secret

        if not secret:
            issues.append({
                "severity": "critical",
                "layer": "auth",
                "message": f"PPPoE secret '{username}' not found on router",
                "recommendation": "Re-provision this customer or check username spelling",
            })
        else:
            if secret.get("disabled"):
                issues.append({
                    "severity": "critical",
                    "layer": "auth",
                    "message": f"PPPoE secret '{username}' is disabled on the router",
                    "recommendation": "Enable the secret or re-provision the customer",
                })

            secret_profile = secret.get("profile", "")
            profile_exists = any(p["name"] == secret_profile for p in profile_list)
            if secret_profile and not profile_exists:
                issues.append({
                    "severity": "critical",
                    "layer": "auth",
                    "message": f"Secret references profile '{secret_profile}' which does not exist",
                    "recommendation": "Re-provision to recreate the profile",
                })
            info["secret_profile_exists"] = profile_exists

        active_data = api.get_active_pppoe_sessions()
        sessions = active_data.get("data", []) if active_data.get("success") else []
        user_session = next((s for s in sessions if s.get("user") == username), None)
        info["active_session"] = user_session

        if user_session:
            info["status"] = "online"
        else:
            info["status"] = "offline"
            if secret and secret.get("last_disconnect_reason"):
                info["last_disconnect_reason"] = secret["last_disconnect_reason"]
                issues.append({
                    "severity": "info",
                    "layer": "auth",
                    "message": f"Last disconnect reason: {secret['last_disconnect_reason']}",
                    "recommendation": "Review disconnect reason for clues",
                })

        # --- Logs ---
        logs = api.get_router_logs(topics="pppoe,ppp", limit=50)
        log_entries = logs.get("data", []) if logs.get("success") else []
        user_logs = [e for e in log_entries if username.lower() in e.get("message", "").lower()]
        info["recent_logs"] = user_logs[-10:]

        severity_order = {"critical": 0, "warning": 1, "info": 2}
        issues.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 99))

        return {
            "success": True,
            "username": username,
            "status": info.get("status", "unknown"),
            "issues_count": len(issues),
            "has_critical": any(i["severity"] == "critical" for i in issues),
            "issues": issues,
            "info": info,
        }
    except Exception as e:
        logger.error(f"PPPoE diagnose error for {username}: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _pppoe_logs_sync(router_info: dict, username: str = "", limit: int = 50) -> dict:
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        logs = api.get_router_logs(topics="pppoe,ppp", limit=200)
        entries = logs.get("data", []) if logs.get("success") else []
        if username:
            entries = [e for e in entries if username.lower() in e.get("message", "").lower()]
        return {"success": True, "data": entries[-limit:], "count": len(entries[-limit:])}
    except Exception as e:
        logger.error(f"PPPoE logs error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _pppoe_secrets_sync(router_info: dict) -> dict:
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        secrets_data = api.get_ppp_secrets_full()
        secrets = secrets_data.get("data", []) if secrets_data.get("success") else []

        active_data = api.get_active_pppoe_sessions()
        active = {s["user"]: s for s in active_data.get("data", [])} if active_data.get("success") else {}

        profiles_data = api.get_ppp_profiles()
        profiles = {p["name"]: p for p in profiles_data.get("data", [])} if profiles_data.get("success") else {}

        enriched = []
        for s in secrets:
            session = active.get(s["name"])
            profile = profiles.get(s.get("profile", ""))
            enriched.append({
                **s,
                "online": session is not None,
                "session": session,
                "profile_detail": profile,
            })
        return {"success": True, "data": enriched, "count": len(enriched)}
    except Exception as e:
        logger.error(f"PPPoE secrets error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _pppoe_users_sync(router_info: dict) -> dict:
    """Gather all PPPoE users with online/offline status and live bandwidth."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=15, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    try:
        secrets_data = api.get_ppp_secrets_full()
        secrets = secrets_data.get("data", []) if secrets_data.get("success") else []

        sessions_data = api.get_pppoe_sessions_with_bandwidth()
        active_map = {
            s["user"]: s
            for s in sessions_data.get("data", [])
        } if sessions_data.get("success") else {}

        profiles_data = api.get_ppp_profiles()
        profiles = {
            p["name"]: p
            for p in profiles_data.get("data", [])
        } if profiles_data.get("success") else {}

        users = []
        total_upload_rate = 0
        total_download_rate = 0
        online_count = 0
        offline_count = 0

        for secret in secrets:
            username = secret["name"]
            session = active_map.get(username)
            profile = profiles.get(secret.get("profile", ""))
            is_online = session is not None

            if is_online:
                online_count += 1
                upload_rate_raw = _parse_rate_to_bps(session.get("upload_rate", "0"))
                download_rate_raw = _parse_rate_to_bps(session.get("download_rate", "0"))
                total_upload_rate += upload_rate_raw
                total_download_rate += download_rate_raw
            else:
                offline_count += 1

            users.append({
                "username": username,
                "service": secret.get("service", ""),
                "profile": secret.get("profile", ""),
                "disabled": secret.get("disabled", False),
                "comment": secret.get("comment", ""),
                "online": is_online,
                "address": session.get("address", "") if session else None,
                "uptime": session.get("uptime", "") if session else None,
                "caller_id": session.get("caller_id", "") if session else None,
                "upload_bytes": session.get("upload_bytes", 0) if session else 0,
                "download_bytes": session.get("download_bytes", 0) if session else 0,
                "upload_rate": session.get("upload_rate", "0") if session else "0",
                "download_rate": session.get("download_rate", "0") if session else "0",
                "max_limit": session.get("max_limit", "") if session else (
                    profile.get("rate_limit", "") if profile else ""
                ),
                "last_logged_out": secret.get("last_logged_out", ""),
                "last_disconnect_reason": secret.get("last_disconnect_reason", ""),
                "last_caller_id": secret.get("last_caller_id", ""),
            })

        return {
            "success": True,
            "users": users,
            "summary": {
                "total": len(users),
                "online": online_count,
                "offline": offline_count,
                "disabled": sum(1 for u in users if u["disabled"]),
                "total_upload_rate_bps": total_upload_rate,
                "total_download_rate_bps": total_download_rate,
            },
        }
    except Exception as e:
        logger.error(f"PPPoE users error: {e}")
        return {"error": str(e)}
    finally:
        api.disconnect()


def _parse_rate_to_bps(rate_str: str) -> int:
    """Convert a MikroTik rate string like '1500000' or '1.5M' to bits per second."""
    if not rate_str:
        return 0
    rate_str = rate_str.strip()
    try:
        return int(rate_str)
    except ValueError:
        pass
    try:
        upper = rate_str.upper()
        if upper.endswith("G"):
            return int(float(upper[:-1]) * 1_000_000_000)
        if upper.endswith("M"):
            return int(float(upper[:-1]) * 1_000_000)
        if upper.endswith("K"):
            return int(float(upper[:-1]) * 1_000)
        return int(float(rate_str))
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/pppoe/{router_id}/overview")
async def pppoe_overview(
    router_id: int,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """PPPoE infrastructure health check for a router. Cached for 60s unless ?refresh=true."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    # Check cache first (skip if explicit refresh requested)
    if not refresh and router_id in _pppoe_overview_cache:
        cached = _pppoe_overview_cache[router_id]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _OVERVIEW_CACHE_TTL:
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(
        router_id, _pppoe_overview_sync, router_info,
        router_obj.pppoe_ports or [],
        getattr(router_obj, "dual_ports", None) or [],
    )

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_overview")
        if router_id in _pppoe_overview_cache:
            stale = _pppoe_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            stale["cache_age_seconds"] = (datetime.utcnow() - _pppoe_overview_cache[router_id]["timestamp"]).total_seconds()
            return stale
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_overview")
        if router_id in _pppoe_overview_cache:
            stale = _pppoe_overview_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "pppoe_overview")

    response = {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        "cached": False,
        **result,
    }

    _pppoe_overview_cache[router_id] = {
        "data": response,
        "timestamp": datetime.utcnow(),
    }

    return response


@router.get("/api/pppoe/{router_id}/diagnose/{username}")
async def pppoe_diagnose(
    router_id: int,
    username: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Full layered PPPoE diagnosis for a specific customer username."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    # Cross-reference with DB
    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.pppoe_username == username,
            Customer.router_id == router_id,
        )
    )
    result = await db.execute(stmt)
    customer = result.scalar_one_or_none()

    db_info = None
    if customer:
        db_info = {
            "customer_id": customer.id,
            "name": customer.name,
            "phone": customer.phone,
            "status": customer.status.value if customer.status else "unknown",
            "expiry": customer.expiry.isoformat() if customer.expiry else None,
            "is_expired": customer.expiry < datetime.utcnow() if customer.expiry else False,
            "plan": customer.plan.name if customer.plan else None,
            "plan_speed": customer.plan.speed if customer.plan else None,
        }

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    diag = await run_with_guard(
        router_id, _pppoe_diagnose_sync, router_info, username, router_obj.pppoe_ports or [],
    )

    if diag.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_diagnose")
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if diag.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_diagnose")
        raise HTTPException(status_code=504, detail=diag.get("detail", "Diagnostic timed out"))
    if diag.get("error"):
        raise HTTPException(status_code=500, detail=diag["error"])

    await record_router_availability(db, router_id, True, "pppoe_diagnose")

    # Add DB cross-reference issues
    if db_info:
        if db_info["status"] != "active":
            diag["issues"].insert(0, {
                "severity": "warning",
                "layer": "billing",
                "message": f"Customer status is '{db_info['status']}' in the database",
                "recommendation": "Customer may need to renew their subscription",
            })
        if db_info.get("is_expired"):
            diag["issues"].insert(0, {
                "severity": "warning",
                "layer": "billing",
                "message": f"Customer subscription expired at {db_info['expiry']}",
                "recommendation": "Customer needs to pay to reactivate",
            })
    else:
        diag["issues"].append({
            "severity": "info",
            "layer": "billing",
            "message": f"No customer with pppoe_username='{username}' found on router {router_id} in DB",
            "recommendation": "Verify the username or register the customer",
        })

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        "customer": db_info,
        **diag,
    }


@router.get("/api/pppoe/{router_id}/logs")
async def pppoe_logs(
    router_id: int,
    username: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get PPPoE-related log entries from the router."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(router_id, _pppoe_logs_sync, router_info, username or "", limit)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_logs")
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_logs")
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "pppoe_logs")

    # Persist notable entries in the background
    entries = result.get("data", [])
    persisted = await persist_notable_logs(db, router_id, entries, topic_filter="pppoe,ppp")

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "filter_username": username,
        "generated_at": datetime.utcnow().isoformat(),
        "notable_entries_persisted": persisted,
        **result,
    }


@router.get("/api/pppoe/{router_id}/secrets")
async def pppoe_secrets(
    router_id: int,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """List all PPPoE secrets on a router with session status and DB cross-reference."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(router_id, _pppoe_secrets_sync, router_info)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_secrets")
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_secrets")
        raise HTTPException(status_code=504, detail=result.get("detail", "Diagnostic timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "pppoe_secrets")

    # Cross-reference with DB customers
    stmt = select(Customer).where(
        Customer.router_id == router_id,
        Customer.pppoe_username.isnot(None),
    )
    db_result = await db.execute(stmt)
    customers = db_result.scalars().all()
    customer_map = {c.pppoe_username: c for c in customers}

    for secret in result.get("data", []):
        cust = customer_map.get(secret["name"])
        if cust:
            secret["db_customer"] = {
                "id": cust.id,
                "name": cust.name,
                "status": cust.status.value if cust.status else "unknown",
                "expiry": cust.expiry.isoformat() if cust.expiry else None,
            }
        else:
            secret["db_customer"] = None

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        **result,
    }


_pppoe_users_cache: dict = {}  # router_id -> {"data": ..., "timestamp": datetime}
_USERS_CACHE_TTL = 30  # 30 seconds -- live bandwidth changes fast, keep cache short


def _infer_disconnect_cause(reason: str) -> dict:
    """Map MikroTik disconnect reasons to technician-friendly guidance."""
    normalized = (reason or "").strip().lower()
    if not normalized:
        return {
            "category": "unknown",
            "probable_cause": "No router-reported disconnect reason",
            "technician_action": "Check live logs and run full diagnose for this user",
        }

    reason_map = {
        "peer-not-responding": {
            "category": "physical_or_cpe",
            "probable_cause": "Client CPE is unreachable or link is unstable",
            "technician_action": "Check cable, switch port, CPE power, and link flaps",
        },
        "admin-disconnect": {
            "category": "operator_action",
            "probable_cause": "Session terminated manually by admin/script",
            "technician_action": "Check operator actions, automation jobs, or reconnect endpoint calls",
        },
        "authentication-failed": {
            "category": "authentication",
            "probable_cause": "Wrong PPPoE credentials or secret mismatch",
            "technician_action": "Confirm username/password on CPE and router secret state",
        },
        "tcp-connection-reset": {
            "category": "network_instability",
            "probable_cause": "Session dropped due to unstable network path",
            "technician_action": "Inspect upstream stability and port errors",
        },
        "lost-service": {
            "category": "service_state",
            "probable_cause": "PPPoE service became unavailable on router",
            "technician_action": "Check PPPoE server status and attached interfaces",
        },
        "disconnected": {
            "category": "client_disconnect",
            "probable_cause": "Client device disconnected normally",
            "technician_action": "Verify customer CPE uptime and power",
        },
    }
    return reason_map.get(normalized, {
        "category": "other",
        "probable_cause": f"Router reported: {reason}",
        "technician_action": "Inspect per-user router logs and run diagnosis",
    })


def _build_technician_checklist(diag: dict) -> list:
    """Create a compact action checklist from diagnostic issues."""
    checklist = []
    for issue in (diag or {}).get("issues", []):
        checklist.append({
            "severity": issue.get("severity", "info"),
            "layer": issue.get("layer", "unknown"),
            "action": issue.get("recommendation", "Review router state"),
        })
    return checklist[:8]


@router.get("/api/pppoe/{router_id}/users")
async def pppoe_users(
    router_id: int,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """All PPPoE users for a router with online/offline status and live bandwidth.

    Returns every PPPoE secret on the router, enriched with:
    - ``online`` flag (whether the user has an active session right now)
    - Live ``upload_rate`` / ``download_rate`` (current throughput from dynamic queues)
    - Session ``upload_bytes`` / ``download_bytes`` (cumulative for current session)
    - ``uptime``, ``address``, ``caller_id`` for online users
    - ``last_disconnect_reason``, ``last_logged_out`` for offline users
    - DB customer cross-reference (name, phone, status, plan, expiry)

    Cached for 30s per router unless ``?refresh=true``.
    """
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    if not refresh and router_id in _pppoe_users_cache:
        cached = _pppoe_users_cache[router_id]
        age = (datetime.utcnow() - cached["timestamp"]).total_seconds()
        if age < _USERS_CACHE_TTL:
            result = cached["data"].copy()
            result["cached"] = True
            result["cache_age_seconds"] = round(age, 1)
            return result

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }
    result = await run_with_guard(router_id, _pppoe_users_sync, router_info)

    if result.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_users")
        if router_id in _pppoe_users_cache:
            stale = _pppoe_users_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            stale["cache_age_seconds"] = (
                datetime.utcnow() - _pppoe_users_cache[router_id]["timestamp"]
            ).total_seconds()
            return stale
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if result.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_users")
        if router_id in _pppoe_users_cache:
            stale = _pppoe_users_cache[router_id]["data"].copy()
            stale["cached"] = True
            stale["stale"] = True
            return stale
        raise HTTPException(status_code=504, detail=result.get("detail", "Operation timed out"))
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    await record_router_availability(db, router_id, True, "pppoe_users")

    stmt = (
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.router_id == router_id,
            Customer.pppoe_username.isnot(None),
        )
    )
    db_result = await db.execute(stmt)
    customers = db_result.scalars().all()
    customer_map = {c.pppoe_username: c for c in customers}

    for u in result.get("users", []):
        cust = customer_map.get(u["username"])
        if cust:
            u["customer"] = {
                "id": cust.id,
                "name": cust.name,
                "phone": cust.phone,
                "status": cust.status.value if cust.status else "unknown",
                "plan": cust.plan.name if cust.plan else None,
                "plan_speed": cust.plan.speed if cust.plan else None,
                "expiry": cust.expiry.isoformat() if cust.expiry else None,
            }
        else:
            u["customer"] = None

    response = {
        "router_id": router_id,
        "router_name": router_obj.name,
        "generated_at": datetime.utcnow().isoformat(),
        "cached": False,
        **result,
    }

    _pppoe_users_cache[router_id] = {
        "data": response,
        "timestamp": datetime.utcnow(),
    }

    return response


@router.get("/api/pppoe/{router_id}/client-details/{username}")
async def pppoe_client_details(
    router_id: int,
    username: str,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Detailed troubleshooting payload for one PPPoE client."""
    user = await get_current_user(token, db)
    router_obj = await get_router_by_id(db, router_id, user.id, user.role.value)
    if not router_obj:
        raise HTTPException(status_code=404, detail="Router not found or not accessible")

    router_info = {
        "ip": router_obj.ip_address, "username": router_obj.username,
        "password": router_obj.password, "port": router_obj.port,
    }

    diag = await run_with_guard(
        router_id, _pppoe_diagnose_sync, router_info, username, router_obj.pppoe_ports or [],
    )
    if diag.get("error") == "connect_failed":
        await record_router_availability(db, router_id, False, "pppoe_client_details")
        raise HTTPException(status_code=503, detail="Failed to connect to router")
    if diag.get("error") == "timeout":
        await record_router_availability(db, router_id, False, "pppoe_client_details")
        raise HTTPException(status_code=504, detail=diag.get("detail", "Diagnostic timed out"))
    if diag.get("error"):
        raise HTTPException(status_code=500, detail=diag["error"])

    logs = await run_with_guard(router_id, _pppoe_logs_sync, router_info, username, 30)
    if logs.get("error") in {"connect_failed", "timeout"}:
        await record_router_availability(db, router_id, False, "pppoe_client_details_logs")
        logs = {"success": False, "data": [], "count": 0}
    elif logs.get("error"):
        logs = {"success": False, "data": [], "count": 0}

    await record_router_availability(db, router_id, True, "pppoe_client_details")

    disconnect_reason = (
        diag.get("info", {}).get("last_disconnect_reason")
        or diag.get("info", {}).get("secret", {}).get("last_disconnect_reason", "")
    )
    cause = _infer_disconnect_cause(disconnect_reason)

    return {
        "router_id": router_id,
        "router_name": router_obj.name,
        "username": username,
        "generated_at": datetime.utcnow().isoformat(),
        "connection_state": diag.get("status", "unknown"),
        "disconnect_reason": disconnect_reason,
        "cause_hints": cause,
        "summary": {
            "issues_count": diag.get("issues_count", 0),
            "has_critical": diag.get("has_critical", False),
            "log_entries": logs.get("count", 0),
        },
        "technician_checklist": _build_technician_checklist(diag),
        "diagnostic": diag,
        "recent_logs": logs.get("data", []),
    }

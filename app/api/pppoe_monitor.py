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

def _pppoe_overview_sync(router_info: dict, db_pppoe_ports: list) -> dict:
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
            "description": "bridge-pppoe interface exists and running",
            "passed": pppoe_bridge is not None and pppoe_bridge.get("running", False),
            "detail": pppoe_bridge if pppoe_bridge else "bridge-pppoe not found",
        })

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        port_bridge_map = {p["interface"]: p["bridge"] for p in bridge_ports}
        port_checks = []
        any_port_up = False
        for port_name in (db_pppoe_ports or []):
            actual_bridge = port_bridge_map.get(port_name)
            iface = ifaces.get(port_name, {})
            link_up = iface.get("running", False)
            if link_up:
                any_port_up = True
            port_checks.append({
                "port": port_name,
                "expected_bridge": "bridge-pppoe",
                "actual_bridge": actual_bridge or "(none)",
                "in_correct_bridge": actual_bridge == "bridge-pppoe",
                "link_up": link_up,
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
            })
        checks.append({
            "check": "pppoe_ports",
            "description": "PPPoE ports in correct bridge with link up",
            "passed": all(p["in_correct_bridge"] and p["link_up"] for p in port_checks) if port_checks else False,
            "any_port_up": any_port_up,
            "detail": port_checks if port_checks else "No PPPoE ports configured in DB",
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

        ifaces_data = api.get_all_interfaces_detail()
        ifaces = {i["name"]: i for i in ifaces_data.get("data", [])} if ifaces_data.get("success") else {}

        any_link_up = False
        port_details = []
        for port_name in (db_pppoe_ports or []):
            actual_bridge = port_bridge_map.get(port_name)
            iface = ifaces.get(port_name, {})
            link_up = iface.get("running", False)
            if link_up:
                any_link_up = True
            port_details.append({
                "port": port_name,
                "bridge": actual_bridge or "(none)",
                "link_up": link_up,
                "rx_error": iface.get("rx_error", 0),
                "tx_error": iface.get("tx_error", 0),
            })
            if actual_bridge != "bridge-pppoe":
                issues.append({
                    "severity": "critical",
                    "layer": "bridge",
                    "message": f"Port {port_name} is in '{actual_bridge or 'no bridge'}' instead of 'bridge-pppoe'",
                    "recommendation": "Reconfigure PPPoE ports via PUT /api/routers/{id}/pppoe-ports",
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

        # --- Layer 2: Bridge ---
        pppoe_bridge = bridges.get("bridge-pppoe")
        if not pppoe_bridge:
            issues.append({
                "severity": "critical",
                "layer": "bridge",
                "message": "bridge-pppoe does not exist",
                "recommendation": "Set up PPPoE infrastructure via PUT /api/routers/{id}/pppoe-ports",
            })
        elif not pppoe_bridge.get("running", False):
            issues.append({
                "severity": "critical",
                "layer": "bridge",
                "message": "bridge-pppoe exists but is not running",
                "recommendation": "Enable bridge-pppoe on the router",
            })
        info["bridge_pppoe"] = pppoe_bridge

        # --- Layer 3: PPPoE service ---
        pppoe_servers = api.get_pppoe_server_status()
        servers = pppoe_servers.get("data", []) if pppoe_servers.get("success") else []
        enabled_servers = [s for s in servers if not s["disabled"]]
        if not enabled_servers:
            issues.append({
                "severity": "critical",
                "layer": "service",
                "message": "PPPoE server is not running or disabled",
                "recommendation": "Enable PPPoE server on bridge-pppoe",
            })
        info["pppoe_servers"] = servers

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
        router_id, _pppoe_overview_sync, router_info, router_obj.pppoe_ports or [],
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

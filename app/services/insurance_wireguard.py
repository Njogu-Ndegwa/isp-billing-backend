import ipaddress
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.services.mikrotik_api import MikroTikAPI
from app.services.provisioning import generate_wireguard_keypair

logger = logging.getLogger(__name__)


SOURCE_MGMT_SUBNET = ipaddress.IPv4Network("10.0.0.0/16")
DEFAULT_INSURANCE_SUBNET = ipaddress.IPv4Network("10.250.0.0/16")


class InsuranceWireGuardError(Exception):
    pass


def derive_insurance_ip(router_ip: str, target_subnet: str | None = None) -> str:
    """Map 10.0.X.Y to 10.250.X.Y while preserving the host offset."""
    source_ip = ipaddress.IPv4Address(router_ip)
    if source_ip not in SOURCE_MGMT_SUBNET:
        raise InsuranceWireGuardError(
            f"Router IP {router_ip} is outside {SOURCE_MGMT_SUBNET}; cannot derive insurance IP"
        )

    target = ipaddress.IPv4Network(target_subnet or str(DEFAULT_INSURANCE_SUBNET))
    if target.prefixlen != SOURCE_MGMT_SUBNET.prefixlen:
        raise InsuranceWireGuardError(
            f"Insurance subnet {target} must use /16 to preserve router host offsets"
        )

    offset = int(source_ip) - int(SOURCE_MGMT_SUBNET.network_address)
    mapped = ipaddress.IPv4Address(int(target.network_address) + offset)
    if mapped not in target:
        raise InsuranceWireGuardError(f"Derived IP {mapped} is outside {target}")
    return str(mapped)


def validate_insurance_settings() -> List[str]:
    missing = []
    for name in (
        "INSURANCE_WG_MANAGER_URL",
        "INSURANCE_WG_MANAGER_SECRET",
        "INSURANCE_SERVER_PUBLIC_IP",
        "INSURANCE_SERVER_WG_PUBLIC_KEY",
    ):
        if not (getattr(settings, name, "") or "").strip():
            missing.append(name)
    return missing


def build_plan(router_ip: str, backup_ip: str) -> List[str]:
    return [
        f"Connect to router over current management IP {router_ip}",
        f"Ensure {settings.INSURANCE_ROUTER_INTERFACE} exists on RouterOS",
        f"Ensure backup address {backup_ip}/16 is assigned",
        f"Ensure peer to {settings.INSURANCE_SERVER_PUBLIC_IP}:{settings.INSURANCE_WG_PORT} exists",
        f"Register router backup public key on new server wg1 as {backup_ip}/32",
        f"Ensure MikroTik API accepts {settings.INSURANCE_SERVER_VPN_IP}/32",
        "Ensure firewall allows backup WireGuard and backup API source",
        f"Ensure hotspot walled garden includes {settings.INSURANCE_SERVER_PUBLIC_IP}/32",
        "Ask new server to verify ping and TCP 8728 over the backup tunnel",
    ]


def _require_success(result: Dict[str, Any], action: str) -> Dict[str, Any]:
    if not result:
        raise InsuranceWireGuardError(f"{action} returned no response")
    if result.get("error"):
        raise InsuranceWireGuardError(f"{action} failed: {result['error']}")
    if not result.get("success"):
        raise InsuranceWireGuardError(f"{action} failed")
    return result


def _rows(result: Dict[str, Any], action: str) -> List[Dict[str, str]]:
    return _require_success(result, action).get("data", []) or []


def _find_by(rows: List[Dict[str, str]], **matches: str) -> Optional[Dict[str, str]]:
    for row in rows:
        if all(row.get(k) == v for k, v in matches.items()):
            return row
    return None


def _ensure_wireguard_interface(
    api: MikroTikAPI,
    interface_name: str,
    listen_port: int,
    force_rotate: bool,
    actions: List[str],
) -> str:
    rows = _rows(api.send_command("/interface/wireguard/print"), "List WireGuard interfaces")
    existing = _find_by(rows, name=interface_name)

    private_key = None
    if not existing or force_rotate:
        private_key, _ = generate_wireguard_keypair()

    if existing:
        params = {
            "numbers": existing[".id"],
            "listen-port": str(listen_port),
            "disabled": "no",
        }
        if private_key:
            params["private-key"] = private_key
            actions.append(f"Rotated {interface_name} private key")
        else:
            actions.append(f"Reused existing {interface_name} key")
        _require_success(api.send_command("/interface/wireguard/set", params), f"Update {interface_name}")
    else:
        _require_success(
            api.send_command(
                "/interface/wireguard/add",
                {
                    "name": interface_name,
                    "listen-port": str(listen_port),
                    "private-key": private_key,
                },
            ),
            f"Create {interface_name}",
        )
        actions.append(f"Created {interface_name}")

    rows = _rows(api.send_command("/interface/wireguard/print"), f"Read {interface_name}")
    refreshed = _find_by(rows, name=interface_name)
    if not refreshed or not refreshed.get("public-key"):
        raise InsuranceWireGuardError(f"Could not read public key for {interface_name}")
    return refreshed["public-key"]


def _ensure_ip_address(api: MikroTikAPI, interface_name: str, backup_ip: str, actions: List[str]) -> None:
    address = f"{backup_ip}/16"
    rows = _rows(api.send_command("/ip/address/print"), "List IP addresses")
    if _find_by(rows, address=address, interface=interface_name):
        actions.append(f"Backup IP {address} already exists")
        return
    _require_success(
        api.send_command("/ip/address/add", {"address": address, "interface": interface_name}),
        f"Add backup IP {address}",
    )
    actions.append(f"Added backup IP {address}")


def _ensure_server_peer(api: MikroTikAPI, interface_name: str, actions: List[str]) -> None:
    rows = _rows(api.send_command("/interface/wireguard/peers/print"), "List WireGuard peers")
    existing = _find_by(
        rows,
        interface=interface_name,
        **{"public-key": settings.INSURANCE_SERVER_WG_PUBLIC_KEY},
    )
    params = {
        "interface": interface_name,
        "public-key": settings.INSURANCE_SERVER_WG_PUBLIC_KEY,
        "endpoint-address": settings.INSURANCE_SERVER_PUBLIC_IP,
        "endpoint-port": str(settings.INSURANCE_WG_PORT),
        "allowed-address": settings.INSURANCE_WG_SUBNET,
        "persistent-keepalive": "25",
    }
    if existing:
        set_params = {"numbers": existing[".id"], **{k: v for k, v in params.items() if k != "interface"}}
        _require_success(api.send_command("/interface/wireguard/peers/set", set_params), "Update backup peer")
        actions.append("Updated backup peer to new server")
    else:
        _require_success(api.send_command("/interface/wireguard/peers/add", params), "Add backup peer")
        actions.append("Added backup peer to new server")


def _ensure_api_access(api: MikroTikAPI, actions: List[str]) -> str:
    rows = _rows(api.send_command("/ip/service/print"), "List IP services")
    api_row = _find_by(rows, name="api")
    if not api_row:
        raise InsuranceWireGuardError("MikroTik API service was not found")

    api_port = api_row.get("port") or "8728"
    backup_source = f"{settings.INSURANCE_SERVER_VPN_IP}/32"
    current = (api_row.get("address", "") or "").strip()
    if not current or current in {"0.0.0.0/0", "::/0"}:
        _require_success(
            api.send_command(
                "/ip/service/set",
                {
                    "numbers": api_row[".id"],
                    "disabled": "no",
                },
            ),
            "Ensure API service enabled",
        )
        actions.append("API address list already allows backup source")
        return api_port

    parts = [p.strip() for p in current.split(",") if p.strip()]
    if backup_source not in parts:
        parts.append(backup_source)
    new_address = ",".join(parts)
    _require_success(
        api.send_command(
            "/ip/service/set",
            {
                "numbers": api_row[".id"],
                "address": new_address,
                "disabled": "no",
            },
        ),
        "Update API allowed addresses",
    )
    actions.append(f"Ensured API allows {backup_source}")
    return api_port


def _ensure_firewall_rule(
    api: MikroTikAPI,
    comment: str,
    protocol: str,
    dst_port: str,
    actions: List[str],
    src_address: str | None = None,
) -> None:
    rows = _rows(api.send_command("/ip/firewall/filter/print"), "List firewall filters")
    existing = _find_by(rows, comment=comment)
    params = {
        "chain": "input",
        "action": "accept",
        "protocol": protocol,
        "dst-port": dst_port,
        "comment": comment,
        "disabled": "no",
    }
    if src_address:
        params["src-address"] = src_address

    if existing:
        _require_success(
            api.send_command("/ip/firewall/filter/set", {"numbers": existing[".id"], **params}),
            f"Update firewall rule {comment}",
        )
        actions.append(f"Updated firewall rule: {comment}")
    else:
        _require_success(api.send_command("/ip/firewall/filter/add", params), f"Add firewall rule {comment}")
        actions.append(f"Added firewall rule: {comment}")

    _move_firewall_rule_before_input_drop(api, comment, actions)


def _move_firewall_rule_before_input_drop(api: MikroTikAPI, comment: str, actions: List[str]) -> None:
    rows = _rows(api.send_command("/ip/firewall/filter/print"), "List firewall filters")
    target_index = next((index for index, row in enumerate(rows) if row.get("comment") == comment), None)
    if target_index is None:
        raise InsuranceWireGuardError(f"Firewall rule {comment} was not found after update")

    drop_index = next(
        (
            index
            for index, row in enumerate(rows)
            if row.get("chain") == "input"
            and row.get("disabled") != "true"
            and row.get("action") in {"drop", "reject"}
        ),
        None,
    )
    if drop_index is None or target_index < drop_index:
        return

    target = rows[target_index]
    destination = rows[drop_index]
    _require_success(
        api.send_command(
            "/ip/firewall/filter/move",
            {
                "numbers": target[".id"],
                "destination": destination[".id"],
            },
        ),
        f"Move firewall rule {comment} before input drop",
    )
    actions.append(f"Moved firewall rule before input drop: {comment}")


def _ensure_walled_garden(api: MikroTikAPI, actions: List[str]) -> None:
    result = api.add_walled_garden_ip(
        settings.INSURANCE_SERVER_PUBLIC_IP,
        action="accept",
        comment="New AWS backend API",
    )
    _require_success(result, "Ensure walled garden")
    actions.append(f"Ensured walled garden allows {settings.INSURANCE_SERVER_PUBLIC_IP}/32")


def configure_router_backup_wireguard(
    api: MikroTikAPI,
    backup_ip: str,
    force_rotate: bool = False,
) -> Dict[str, Any]:
    actions: List[str] = []
    interface_name = settings.INSURANCE_ROUTER_INTERFACE

    router_public_key = _ensure_wireguard_interface(
        api,
        interface_name=interface_name,
        listen_port=settings.INSURANCE_WG_PORT,
        force_rotate=force_rotate,
        actions=actions,
    )
    _ensure_ip_address(api, interface_name, backup_ip, actions)
    _ensure_server_peer(api, interface_name, actions)
    api_port = _ensure_api_access(api, actions)
    _ensure_firewall_rule(
        api,
        comment="Allow backup WireGuard",
        protocol="udp",
        dst_port=str(settings.INSURANCE_WG_PORT),
        actions=actions,
    )
    _ensure_firewall_rule(
        api,
        comment="Allow API from new AWS insurance VPN",
        protocol="tcp",
        dst_port=api_port,
        src_address=settings.INSURANCE_SERVER_VPN_IP,
        actions=actions,
    )
    _ensure_walled_garden(api, actions)

    return {
        "router_public_key": router_public_key,
        "actions": actions,
    }


async def insurance_manager_request(
    method: str,
    path: str,
    json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = settings.INSURANCE_WG_MANAGER_URL.rstrip("/")
    if not url:
        raise InsuranceWireGuardError("INSURANCE_WG_MANAGER_URL is not configured")

    async with httpx.AsyncClient(base_url=url, timeout=settings.INSURANCE_MANAGER_TIMEOUT) as client:
        response = await client.request(
            method,
            path,
            json=json,
            headers={"X-API-Key": settings.INSURANCE_WG_MANAGER_SECRET},
        )
    if response.status_code >= 400:
        raise InsuranceWireGuardError(
            f"Insurance wg-manager {path} returned {response.status_code}: {response.text}"
        )
    return response.json()


async def register_insurance_peer(router_public_key: str, backup_ip: str) -> Dict[str, Any]:
    return await insurance_manager_request(
        "POST",
        "/add-peer",
        json={"public_key": router_public_key, "allowed_ips": f"{backup_ip}/32"},
    )


async def verify_insurance_router(backup_ip: str, port: int = 8728) -> Dict[str, Any]:
    return await insurance_manager_request(
        "POST",
        "/test-router",
        json={"ip": backup_ip, "port": port, "timeout": 5, "ping_count": 3},
    )

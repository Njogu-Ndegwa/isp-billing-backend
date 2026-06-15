from typing import Any, Dict, List

from app.config import settings
from app.services.mikrotik_api import MikroTikAPI
from app.services.insurance_wireguard import (
    InsuranceWireGuardError,
    _ensure_api_access,
    _ensure_firewall_rule,
    _ensure_walled_garden,
    _find_by,
    _require_success,
    _rows,
    insurance_manager_request,
    parse_routeros_major_version,
    read_routeros_version,
)


def insurance_l2tp_psk() -> str:
    return (settings.INSURANCE_L2TP_IPSEC_PSK or settings.L2TP_IPSEC_PSK or "").strip()


def build_l2tp_plan(router_ip: str, backup_ip: str) -> List[str]:
    return [
        f"Connect to router over current management IP {router_ip}",
        "Confirm RouterOS version needs the L2TP/IPsec insurance tunnel",
        f"Register L2TP credentials on new server as {backup_ip}",
        f"Ensure {settings.INSURANCE_L2TP_INTERFACE} exists on RouterOS",
        f"Ensure {settings.INSURANCE_L2TP_INTERFACE} connects to {settings.INSURANCE_SERVER_PUBLIC_IP}",
        f"Ensure MikroTik API accepts {settings.INSURANCE_SERVER_VPN_IP}/32",
        "Ensure firewall allows backup API source before input drops",
        f"Ensure hotspot walled garden includes {settings.INSURANCE_SERVER_PUBLIC_IP}/32",
        "Ask new server to verify ping and TCP 8728 over the backup tunnel",
    ]


def validate_insurance_l2tp_settings() -> List[str]:
    missing = []
    for name in (
        "INSURANCE_WG_MANAGER_URL",
        "INSURANCE_WG_MANAGER_SECRET",
        "INSURANCE_SERVER_PUBLIC_IP",
    ):
        if not (getattr(settings, name, "") or "").strip():
            missing.append(name)
    if not insurance_l2tp_psk():
        missing.append("INSURANCE_L2TP_IPSEC_PSK or L2TP_IPSEC_PSK")
    return missing


def _ensure_routeros_supports_l2tp_insurance(api: MikroTikAPI, actions: List[str]) -> str:
    version = read_routeros_version(api)
    major_version = parse_routeros_major_version(version)
    if major_version is None:
        raise InsuranceWireGuardError(f"Could not determine RouterOS major version from '{version}'")
    if major_version >= 7:
        raise InsuranceWireGuardError(
            f"RouterOS {version} supports WireGuard. Use the WireGuard insurance tunnel flow."
        )
    actions.append(f"Confirmed RouterOS {version} needs L2TP/IPsec insurance tunnel")
    return version


def _ensure_l2tp_client(
    api: MikroTikAPI,
    interface_name: str,
    username: str,
    password: str,
    actions: List[str],
) -> None:
    rows = _rows(api.send_command("/interface/l2tp-client/print"), "List L2TP clients")
    existing = _find_by(rows, name=interface_name)
    params = {
        "connect-to": settings.INSURANCE_SERVER_PUBLIC_IP,
        "user": username,
        "password": password,
        "disabled": "no",
        "allow": "mschap2,mschap1",
        "add-default-route": "no",
        "use-peer-dns": "no",
        "comment": "Insurance tunnel to new AWS",
    }

    if existing:
        client_id = existing[".id"]
        _require_success(
            api.send_command("/interface/l2tp-client/set", {"numbers": client_id, **params}),
            f"Update {interface_name}",
        )
        actions.append(f"Updated {interface_name}")
    else:
        _require_success(
            api.send_command("/interface/l2tp-client/add", {"name": interface_name, **params}),
            f"Create {interface_name}",
        )
        actions.append(f"Created {interface_name}")
        rows = _rows(api.send_command("/interface/l2tp-client/print"), f"Read {interface_name}")
        refreshed = _find_by(rows, name=interface_name)
        if not refreshed:
            raise InsuranceWireGuardError(f"Could not read {interface_name} after creation")
        client_id = refreshed[".id"]

    _require_success(
        api.send_command(
            "/interface/l2tp-client/set",
            {
                "numbers": client_id,
                "use-ipsec": "yes",
                "ipsec-secret": insurance_l2tp_psk(),
            },
        ),
        f"Apply IPsec settings to {interface_name}",
    )
    actions.append(f"Ensured IPsec settings on {interface_name}")


def configure_router_backup_l2tp(
    api: MikroTikAPI,
    backup_ip: str,
    username: str,
    password: str,
) -> Dict[str, Any]:
    actions: List[str] = []
    routeros_version = _ensure_routeros_supports_l2tp_insurance(api, actions)
    interface_name = settings.INSURANCE_L2TP_INTERFACE

    _ensure_l2tp_client(api, interface_name, username, password, actions)
    api_port = _ensure_api_access(api, actions)
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
        "routeros_version": routeros_version,
        "l2tp_username": username,
        "actions": actions,
        "backup_ip": backup_ip,
    }


async def register_insurance_l2tp_peer(username: str, password: str, backup_ip: str) -> Dict[str, Any]:
    return await insurance_manager_request(
        "POST",
        "/add-l2tp-peer",
        json={"username": username, "password": password, "ip": backup_ip},
    )


async def remove_insurance_l2tp_peer(username: str) -> Dict[str, Any]:
    return await insurance_manager_request(
        "DELETE",
        "/remove-l2tp-peer",
        json={"username": username},
    )

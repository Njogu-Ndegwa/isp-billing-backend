from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_network
import secrets
from typing import Any, Iterable

from app.config import settings
from app.services.mikrotik_api import MikroTikAPI


class RouterRemoteAccessError(ValueError):
    """Raised when a router remote-access request cannot be applied safely."""


REMOTE_ACCESS_FIREWALL_COMMENT_PREFIX = "API-managed: remote-access"

REMOTE_ACCESS_SERVICES: dict[str, dict[str, Any]] = {
    "winbox": {
        "label": "WinBox",
        "routeros_service": "winbox",
        "port": 8291,
        "protocol": "tcp",
        "client": "winbox",
    },
    "ssh": {
        "label": "SSH",
        "routeros_service": "ssh",
        "port": 22,
        "protocol": "tcp",
        "client": "ssh",
    },
    "webfig": {
        "label": "WebFig",
        "routeros_service": "www",
        "routeros_services": ["www", "www-ssl"],
        "port": 80,
        "default_port_by_routeros_service": {"www": 80, "www-ssl": 443},
        "scheme": "http",
        "scheme_by_routeros_service": {"www": "http", "www-ssl": "https"},
        "protocol": "tcp",
        "client": "browser",
    },
}

SERVICE_ALIASES = {
    "www": "webfig",
    "www-ssl": "webfig",
    "web": "webfig",
    "webfig-http": "webfig",
    "webfig-https": "webfig",
}


@dataclass
class WebFigProxySession:
    token: str
    router_id: int
    router_name: str
    router_ip: str
    created_by_user_id: int
    expires_at: datetime
    webfig_scheme: str = "http"
    webfig_port: int = 80

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "router_name": self.router_name,
            "expires_at": self.expires_at.isoformat(),
            "webfig_scheme": self.webfig_scheme,
            "webfig_port": self.webfig_port,
        }


_WEBFIG_PROXY_SESSIONS: dict[str, WebFigProxySession] = {}


def webfig_access_cookie_name(router_id: int) -> str:
    return f"webfig_access_{router_id}"


def build_webfig_proxy_path(router_id: int, token: str, proxy_path: str = "") -> str:
    suffix = proxy_path.lstrip("/")
    if suffix:
        return f"/api/admin/routers/{router_id}/webfig/{suffix}?remote_access_token={token}"
    return f"/api/admin/routers/{router_id}/webfig/?remote_access_token={token}"


def create_webfig_proxy_session(
    router_id: int,
    router_name: str,
    router_ip: str,
    created_by_user_id: int,
    ttl_minutes: int | None = None,
    webfig_scheme: str = "http",
    webfig_port: int | str | None = None,
) -> WebFigProxySession:
    _prune_expired_webfig_sessions()
    ttl = max(1, int(ttl_minutes or settings.ROUTER_WEBFIG_SESSION_MINUTES))
    scheme = _normalize_webfig_scheme(webfig_scheme)
    session = WebFigProxySession(
        token=secrets.token_urlsafe(32),
        router_id=router_id,
        router_name=router_name,
        router_ip=router_ip,
        created_by_user_id=created_by_user_id,
        expires_at=datetime.utcnow() + timedelta(minutes=ttl),
        webfig_scheme=scheme,
        webfig_port=_coerce_service_port(
            webfig_port,
            443 if scheme == "https" else 80,
        ),
    )
    _WEBFIG_PROXY_SESSIONS[session.token] = session
    return session


def get_webfig_proxy_session(router_id: int, token: str | None) -> WebFigProxySession | None:
    if not token:
        return None
    session = _WEBFIG_PROXY_SESSIONS.get(token)
    if not session:
        return None
    if session.router_id != router_id or session.expires_at <= datetime.utcnow():
        _WEBFIG_PROXY_SESSIONS.pop(token, None)
        return None
    return session


def revoke_webfig_proxy_sessions(router_id: int) -> int:
    tokens = [
        token
        for token, session in _WEBFIG_PROXY_SESSIONS.items()
        if session.router_id == router_id
    ]
    for token in tokens:
        _WEBFIG_PROXY_SESSIONS.pop(token, None)
    return len(tokens)


def _prune_expired_webfig_sessions() -> None:
    now = datetime.utcnow()
    expired = [
        token
        for token, session in _WEBFIG_PROXY_SESSIONS.items()
        if session.expires_at <= now
    ]
    for token in expired:
        _WEBFIG_PROXY_SESSIONS.pop(token, None)


def normalize_remote_access_services(services: Iterable[str] | None = None) -> list[str]:
    raw_services = list(services or ["winbox"])
    if not raw_services:
        raise RouterRemoteAccessError("At least one remote-access service is required")

    normalized: list[str] = []
    for service in raw_services:
        key = str(service or "").strip().lower().replace("_", "-")
        key = SERVICE_ALIASES.get(key, key)
        if key not in REMOTE_ACCESS_SERVICES:
            allowed = ", ".join(sorted(REMOTE_ACCESS_SERVICES))
            raise RouterRemoteAccessError(
                f"Unsupported remote-access service '{service}'. Allowed: {allowed}"
            )
        if key not in normalized:
            normalized.append(key)
    return normalized


def default_remote_access_source_cidrs() -> list[str]:
    return normalize_source_cidrs([settings.ROUTER_REMOTE_ACCESS_SOURCE_CIDRS])


def normalize_source_cidrs(source_cidrs: Iterable[str] | None = None) -> list[str]:
    raw_sources = list(source_cidrs) if source_cidrs is not None else default_remote_access_source_cidrs()
    if not raw_sources:
        raise RouterRemoteAccessError("At least one trusted source CIDR is required")

    normalized: list[str] = []
    for item in raw_sources:
        for part in str(item or "").split(","):
            source = part.strip()
            if not source:
                continue
            try:
                network = ip_network(source, strict=False)
            except ValueError as exc:
                raise RouterRemoteAccessError(f"Invalid source CIDR '{source}'") from exc
            if network.prefixlen == 0:
                raise RouterRemoteAccessError(
                    f"Refusing to open router access to unrestricted source '{source}'"
                )
            rendered = str(network)
            if rendered not in normalized:
                normalized.append(rendered)

    if not normalized:
        raise RouterRemoteAccessError("At least one trusted source CIDR is required")
    return normalized


def build_remote_access_targets(
    router_ip: str,
    username: str,
    source_cidrs: Iterable[str] | None = None,
    services: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    source_list = normalize_source_cidrs(source_cidrs)
    service_keys = normalize_remote_access_services(services)
    targets: list[dict[str, Any]] = []

    for key in service_keys:
        service = REMOTE_ACCESS_SERVICES[key]
        targets.append(_build_remote_access_target(router_ip, username, source_list, key, service))

    return targets


def configure_router_remote_access_sync(
    router_info: dict[str, Any],
    services: Iterable[str] | None = None,
    enable: bool = True,
    source_cidrs: Iterable[str] | None = None,
) -> dict[str, Any]:
    service_keys = normalize_remote_access_services(services)
    source_list = normalize_source_cidrs(source_cidrs)

    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=15,
        connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connection_failed", "reason": api.last_connect_error}

    try:
        service_results = [
            _apply_remote_access_service(api, service_key, enable, source_list)
            for service_key in service_keys
        ]
        labels = ", ".join(REMOTE_ACCESS_SERVICES[key]["label"] for key in service_keys)
        state = "enabled" if enable else "disabled"
        response = {
            "success": True,
            "enabled": enable,
            "services": service_results,
            "source_cidrs": source_list,
            "targets": [
                _build_remote_access_target(
                    router_info["ip"],
                    router_info["username"],
                    source_list,
                    result["service"],
                    result,
                )
                for result in service_results
            ],
            "message": f"Remote {labels} access {state} over the management VPN.",
        }
        if service_keys == ["winbox"] and service_results:
            response.update({
                "steps": service_results[0]["steps"],
                "winbox_service_after": service_results[0]["service_after"],
                "firewall_rules_after": service_results[0]["firewall_rules_after"],
            })
        return response
    finally:
        api.disconnect()


def _apply_remote_access_service(
    api: MikroTikAPI,
    service_key: str,
    enable: bool,
    source_cidrs: list[str],
) -> dict[str, Any]:
    service = _resolve_remote_access_service(api, service_key)
    steps: list[dict[str, Any]] = []

    if enable:
        steps.extend(_sync_firewall_rules(api, service_key, service, source_cidrs))
        service_after = _set_routeros_service(api, service, True, source_cidrs)
    else:
        steps.extend(_remove_managed_firewall_rules(api, service_key))
        service_after = _set_routeros_service(api, service, False, source_cidrs)

    return {
        "service": service_key,
        "label": service["label"],
        "routeros_service": service["routeros_service"],
        "port": service["port"],
        "protocol": service["protocol"],
        "scheme": service.get("scheme"),
        "enabled": enable,
        "steps": steps,
        "service_after": service_after,
        "firewall_rules_after": _read_managed_firewall_rules(api, service_key),
    }


def _build_remote_access_target(
    router_ip: str,
    username: str,
    source_cidrs: list[str],
    service_key: str,
    service: dict[str, Any],
) -> dict[str, Any]:
    port = _coerce_service_port(service.get("port"), REMOTE_ACCESS_SERVICES[service_key]["port"])
    target: dict[str, Any] = {
        "service": service_key,
        "label": service["label"],
        "routeros_service": service["routeros_service"],
        "host": router_ip,
        "port": port,
        "protocol": service["protocol"],
        "access_path": "management_vpn",
        "source_cidrs": source_cidrs,
        "credentials_note": "Use the router's stored admin credentials; the password is not returned by this API.",
    }
    if service_key == "winbox":
        target["winbox_address"] = f"{router_ip}:{port}"
        target["operator_hint"] = f"Open WinBox and connect to {router_ip}:{port} from the trusted management source."
    elif service_key == "ssh":
        target["ssh_command"] = f"ssh {username}@{router_ip} -p {port}"
    elif service_key == "webfig":
        scheme = _normalize_webfig_scheme(str(service.get("scheme") or "http"))
        target["scheme"] = scheme
        target["url"] = f"{scheme}://{router_ip}:{port}/"
    return target


def _resolve_remote_access_service(api: MikroTikAPI, service_key: str) -> dict[str, Any]:
    base_service = REMOTE_ACCESS_SERVICES[service_key]
    candidates = base_service.get("routeros_services") or [base_service["routeros_service"]]
    failures: list[str] = []

    for service_name in candidates:
        try:
            service_row = _read_routeros_service(api, service_name)
        except RouterRemoteAccessError as exc:
            failures.append(str(exc))
            continue

        resolved = dict(base_service)
        resolved["routeros_service"] = service_name
        resolved["port"] = _coerce_service_port(
            service_row.get("port"),
            _default_port_for_routeros_service(base_service, service_name),
        )
        scheme_by_name = base_service.get("scheme_by_routeros_service") or {}
        if service_name in scheme_by_name:
            resolved["scheme"] = scheme_by_name[service_name]
        return resolved

    tried = ", ".join(str(candidate) for candidate in candidates)
    detail = f": {'; '.join(failures)}" if failures else ""
    raise RouterRemoteAccessError(
        f"RouterOS service for {base_service['label']} not found; tried {tried}{detail}"
    )


def _default_port_for_routeros_service(service: dict[str, Any], service_name: str) -> int:
    by_name = service.get("default_port_by_routeros_service") or {}
    return _coerce_service_port(by_name.get(service_name), service["port"])


def _coerce_service_port(value: Any, fallback: int) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return int(fallback)
    if port < 1 or port > 65535:
        return int(fallback)
    return port


def _normalize_webfig_scheme(value: str) -> str:
    scheme = (value or "http").strip().lower()
    if scheme not in {"http", "https"}:
        return "http"
    return scheme


def _rows(response: dict[str, Any], context: str) -> list[dict[str, Any]]:
    if response.get("error"):
        raise RouterRemoteAccessError(f"{context}: {response['error']}")
    return response.get("data") or []


def _ensure_success(response: dict[str, Any], context: str) -> None:
    if response.get("error"):
        raise RouterRemoteAccessError(f"{context}: {response['error']}")


def _managed_comment_prefix(service_key: str) -> str:
    return f"{REMOTE_ACCESS_FIREWALL_COMMENT_PREFIX}: {service_key}: "


def _managed_comment(service_key: str, source_cidr: str) -> str:
    return f"{_managed_comment_prefix(service_key)}{source_cidr}"


def _read_managed_firewall_rules(api: MikroTikAPI, service_key: str) -> list[dict[str, Any]]:
    prefix = _managed_comment_prefix(service_key)
    rows = _rows(
        api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[
                ".id",
                "chain",
                "action",
                "protocol",
                "dst-port",
                "src-address",
                "comment",
                "disabled",
            ],
            query="?chain=input",
        ),
        "Read remote-access firewall rules",
    )
    return [row for row in rows if (row.get("comment") or "").startswith(prefix)]


def _sync_firewall_rules(
    api: MikroTikAPI,
    service_key: str,
    service: dict[str, Any],
    source_cidrs: list[str],
) -> list[dict[str, Any]]:
    wanted = set(source_cidrs)
    current = _read_managed_firewall_rules(api, service_key)
    steps: list[dict[str, Any]] = []

    matching_sources: set[str] = set()
    for rule in current:
        source = rule.get("src-address")
        if source in wanted and _firewall_rule_matches(rule, service, source):
            matching_sources.add(source)
            continue
        rule_id = rule.get(".id")
        if rule_id:
            _ensure_success(
                api.send_command("/ip/firewall/filter/remove", {"numbers": rule_id}),
                "Remove stale remote-access firewall rule",
            )
            steps.append({"step": "remove_stale_firewall_rule", "rule_id": rule_id})

    place_before = _find_defconf_input_drop_rule(api)
    for source in source_cidrs:
        if source in matching_sources:
            steps.append({"step": "firewall_rule_exists", "src_address": source})
            continue
        add_args = {
            "chain": "input",
            "protocol": service["protocol"],
            "dst-port": str(service["port"]),
            "src-address": source,
            "action": "accept",
            "comment": _managed_comment(service_key, source),
        }
        if place_before:
            add_args["place-before"] = place_before
        _ensure_success(
            api.send_command("/ip/firewall/filter/add", add_args),
            "Add remote-access firewall rule",
        )
        steps.append({"step": "add_firewall_rule", "src_address": source})

    return steps


def _remove_managed_firewall_rules(api: MikroTikAPI, service_key: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for rule in _read_managed_firewall_rules(api, service_key):
        rule_id = rule.get(".id")
        if not rule_id:
            continue
        _ensure_success(
            api.send_command("/ip/firewall/filter/remove", {"numbers": rule_id}),
            "Remove remote-access firewall rule",
        )
        steps.append({"step": "remove_firewall_rule", "rule_id": rule_id})
    return steps


def _firewall_rule_matches(
    rule: dict[str, Any],
    service: dict[str, Any],
    source_cidr: str,
) -> bool:
    disabled = str(rule.get("disabled") or "").lower() in {"true", "yes"}
    return (
        not disabled
        and rule.get("chain") == "input"
        and rule.get("action") == "accept"
        and rule.get("protocol") == service["protocol"]
        and str(rule.get("dst-port")) == str(service["port"])
        and rule.get("src-address") == source_cidr
    )


def _find_defconf_input_drop_rule(api: MikroTikAPI) -> str | None:
    rows = _rows(
        api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[".id", "chain", "action", "comment"],
            query="?comment=defconf: drop all not coming from LAN",
        ),
        "Read default input drop rule",
    )
    for row in rows:
        if row.get("chain") == "input" and row.get("action") == "drop":
            return row.get(".id")
    return None


def _set_routeros_service(
    api: MikroTikAPI,
    service: dict[str, Any],
    enable: bool,
    source_cidrs: list[str],
) -> dict[str, Any]:
    service_name = service["routeros_service"]
    service_row = _read_routeros_service(api, service_name)
    service_id = service_row.get(".id")
    if not service_id:
        raise RouterRemoteAccessError(f"RouterOS service '{service_name}' not found")

    args = {"numbers": service_id, "disabled": "no" if enable else "yes"}
    if enable:
        args["address"] = ",".join(source_cidrs)
    _ensure_success(
        api.send_command("/ip/service/set", args),
        f"Set RouterOS service '{service_name}'",
    )
    return _read_routeros_service(api, service_name)


def _read_routeros_service(api: MikroTikAPI, service_name: str) -> dict[str, Any]:
    rows = _rows(
        api.send_command("/ip/service/print", {"?name": service_name}),
        f"Read RouterOS service '{service_name}'",
    )
    for row in rows:
        if row.get("name") in (None, service_name):
            return row
    raise RouterRemoteAccessError(f"RouterOS service '{service_name}' not found")

"""Render the adaptive RouterOS command-agent script and installer data."""

from __future__ import annotations

import re

from app.services.router_agent_auth import derive_router_agent_token


SCRIPT_NAME = "bitwave-command-agent"
SCHEDULER_NAME = "bitwave-command-agent"
COMMAND_FILE = "bitwave-agent-command.rsc"
AGENT_VERSION = "1"

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._:/-]{3,200}$")
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_TUNNEL_TYPES = {"wireguard", "l2tp"}


def _require(value: str, rx: re.Pattern, name: str) -> str:
    clean = str(value or "").strip()
    if not rx.fullmatch(clean):
        raise ValueError(f"router-agent script: unsafe {name}={value!r}")
    return clean


def render_router_agent_source(
    *,
    identity: str,
    endpoint_base_url: str,
    tunnel_type: str,
    management_probe_ip: str = "10.0.0.1",
    check_certificate: bool = True,
) -> str:
    """Return the source installed in ``/system script`` on one router.

    The server controls the successful next-poll interval in the idle response.
    Transport/server failures back off locally to five minutes, protecting both
    the router and the small production server.
    """

    identity = _require(identity, _IDENTITY_RE, "identity")
    endpoint = _require(endpoint_base_url.rstrip("/"), _URL_RE, "endpoint_base_url")
    if not endpoint.lower().startswith("https://"):
        raise ValueError("router-agent script: endpoint_base_url must use HTTPS")
    probe_ip = _require(management_probe_ip, _IP_RE, "management_probe_ip")
    tunnel_type = str(tunnel_type or "").strip().lower()
    if tunnel_type not in _TUNNEL_TYPES:
        raise ValueError(f"router-agent script: unsafe tunnel_type={tunnel_type!r}")
    token = derive_router_agent_token(identity)
    certificate_flag = "" if check_certificate else " check-certificate=no"
    tunnel_probe = (
        ':if ([:len [/interface l2tp-client find where name="l2tp-aws" running=yes]] > 0) '
        'do={ :set tunnel "up" }'
        if tunnel_type == "l2tp"
        else f':if ([/ping {probe_ip} count=1 interval=500ms] > 0) do={{ :set tunnel "up" }}'
    )

    return f""":global bitwaveAgentRunning
:if ([:typeof $bitwaveAgentRunning] = "bool" and $bitwaveAgentRunning) do={{
    :log info "bitwave-agent: previous poll still running"
    :return
}}
:set bitwaveAgentRunning true
:global bitwaveAgentFailures
:if ([:typeof $bitwaveAgentFailures] = "nil") do={{ :set bitwaveAgentFailures 0 }}
:local tunnel "down"
:do {{
    {tunnel_probe}
}} on-error={{}}
:local url ("{endpoint}/api/router/agent/poll?identity={identity}&tunnel=" . $tunnel . "&version={AGENT_VERSION}")
:local fileName "{COMMAND_FILE}"
:do {{ /file remove [find name=$fileName] }} on-error={{}}
:do {{
    /tool fetch url=$url http-method=get http-header-field="Authorization: Bearer {token}" dst-path=$fileName output=file{certificate_flag}
    :local bitwaveImportOk true
    # Every authenticated response is an importable RouterOS script. Idle
    # responses only retune this scheduler; command responses retune, apply and
    # acknowledge. Importing directly keeps this compatible with the smaller
    # file-content read limits on older RouterOS builds.
    :do {{ /import file-name=$fileName }} on-error={{
        :set bitwaveImportOk false
        :log warning "bitwave-agent: response import failed; server will retry"
    }}
    :if ($bitwaveImportOk) do={{
        :set bitwaveAgentFailures 0
    }} else={{
        :set bitwaveAgentFailures ($bitwaveAgentFailures + 1)
        /system scheduler set [find name="{SCHEDULER_NAME}"] interval=90s
    }}
}} on-error={{
    :set bitwaveAgentFailures ($bitwaveAgentFailures + 1)
    :local backoff 60
    :if ($bitwaveAgentFailures = 1) do={{ :set backoff 45 }}
    :if ($bitwaveAgentFailures = 2) do={{ :set backoff 90 }}
    :if ($bitwaveAgentFailures = 3) do={{ :set backoff 180 }}
    :if ($bitwaveAgentFailures > 3) do={{ :set backoff 300 }}
    :set backoff ($backoff + [:rndnum from=0 to=30])
    /system scheduler set [find name="{SCHEDULER_NAME}"] interval=($backoff . "s")
    :log info "bitwave-agent: poll deferred"
}}
:do {{ /file remove [find name=$fileName] }} on-error={{}}
:set bitwaveAgentRunning false
"""


def rollback_router_agent_rsc() -> str:
    return (
        f'/system scheduler remove [find name="{SCHEDULER_NAME}"]\n'
        f'/system script remove [find name="{SCRIPT_NAME}"]\n'
        f'/file remove [find name="{COMMAND_FILE}"]\n'
    )

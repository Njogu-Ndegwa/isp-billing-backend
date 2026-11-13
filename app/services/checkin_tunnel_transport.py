"""Opt-in tunnel transport around an existing check-in fetch."""

import ipaddress
import re
from urllib.parse import urlsplit

BEGIN = "# bw-checkin-tunnel v1"
END = "# bw-checkin-tunnel end"
FETCH = re.compile(
    r"(?m)^(?P<indent>[ \t]*):local res (?P<fetch>\[/tool fetch url=\$url [^\r\n]*\])$"
)


def prefer_tunnel_transport(source: str, endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
        address = ipaddress.ip_address(parsed.hostname or "")
        valid = (
            parsed.scheme == "http"
            and address in ipaddress.ip_network("10.0.0.0/8")
            and parsed.port == 8088
            and parsed.path == "/api/router/checkin"
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
            and parsed.password is None
            and not re.search(r"[^A-Za-z0-9./:-]", endpoint)
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError(
            "Check-in tunnel endpoint must use a literal 10/8 address, port 8088, and the check-in path"
        )
    if BEGIN in source:
        marker = BEGIN + " " + endpoint
        if source.count(marker) == 1 and source.count(END) == 1:
            return source
        raise ValueError(
            "Existing check-in transport does not match the requested tunnel"
        )
    matches = list(FETCH.finditer(source))
    if len(matches) != 1:
        raise ValueError("Expected one existing check-in fetch")
    match = matches[0]
    public = match["fetch"]
    tunnel = public.replace("url=$url", 'url="' + endpoint + '"', 1)
    tunnel, count = re.subn(
        r" check-certificate=(?:yes-without-crl|yes|no)(?= )", "", tunnel
    )
    if count != 1 or tunnel.count(" output=user as-value]") != 1:
        raise ValueError("Unexpected existing check-in fetch shape")
    tunnel = tunnel.replace(
        " output=user as-value]", " idle-timeout=3s duration=5s output=user as-value]"
    )
    lines = [
        BEGIN + " " + endpoint,
        ":local res",
        ":local bwcTunnelOk false",
        ":do {",
        "    :set res " + tunnel,
        '    :if (($res->"status") = "finished") do={ :set bwcTunnelOk true }',
        "} on-error={}",
        ":if (!$bwcTunnelOk) do={",
        "    :set res " + public,
        "}",
        END,
    ]
    replacement = "\n".join(match["indent"] + line for line in lines)
    return source[: match.start()] + replacement + source[match.end() :]

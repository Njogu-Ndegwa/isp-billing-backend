"""Project native API rows onto the existing v3 counter contract.

The router sends data only. A partial upload never becomes a usage report.
This module has no database or network I/O.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

BASE_PARTS = frozenset({"queues", "queue_stats", "hosts", "summary"})
MAX_ROWS = 2_000


def rows(value: Any) -> list[dict]:
    # RouterOS serializes an empty untyped array as an empty object.
    if value == {}:
        return []
    if (
        not isinstance(value, list)
        or len(value) > MAX_ROWS
        or any(not isinstance(x, dict) for x in value)
    ):
        raise ValueError("invalid native table")
    return value


def ids(value: Any) -> set[str]:
    if value == {}:
        return set()
    if (
        not isinstance(value, list)
        or len(value) > MAX_ROWS
        or any(not isinstance(x, str) for x in value)
    ):
        raise ValueError("invalid native ID list")
    return {x.upper() for x in value}


def _id(row: dict) -> str:
    return str(row.get(".id", "")).upper()


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(_text(x) for x in value)
    if not isinstance(value, (str, int, float, bool)):
        raise ValueError("invalid native scalar")
    return str(value)


def _number(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid native counter")
    try:
        integer = int(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("invalid native counter") from exc
    if (
        integer < 0
        or integer > 9_223_372_036_854_775_807
        or isinstance(value, float)
        and value != integer
    ):
        raise ValueError("native counter out of range")
    return integer


def _duration(value: Any) -> str:
    text = _text(value)
    # RouterOS JSON serializes typed durations as dates relative to Unix epoch.
    # Absolute link timestamps use _text instead and must remain absolute.
    if re.fullmatch(r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?", text):
        try:
            seconds = (
                datetime.fromisoformat(text) - datetime(1970, 1, 1)
            ).total_seconds()
        except ValueError as exc:
            raise ValueError("invalid native duration") from exc
        if not 0 <= seconds <= 10_000_000_000:
            raise ValueError("native duration out of range")
        return f"{int(seconds)}s"
    return text


def decode_snapshot(identity: str, parts: dict[str, Any]) -> dict:
    """Return the existing v3-shaped ingestion contract, preserving queue order."""
    if not BASE_PARTS <= parts.keys():
        raise ValueError("incomplete native snapshot")
    summary = parts["summary"]
    host_part = parts["hosts"]
    if not isinstance(summary, dict) or not isinstance(host_part, dict):
        raise ValueError("invalid native summary")
    resource = summary.get("resource")
    if isinstance(resource, list) and len(resource) == 1:
        resource = resource[0]
    if not isinstance(resource, dict):
        raise ValueError("missing native health")
    disabled_queues = ids(summary.get("queue_disabled"))
    queue_stats = {_id(x): x for x in rows(parts["queue_stats"])}
    reports = []
    for queue in rows(parts["queues"]):
        name = _text(queue.get("name"))
        key = (
            name[5:]
            if name.startswith("plan_")
            else (
                "pppoe:" + name[7:-1]
                if name.startswith("<pppoe-") and name.endswith(">")
                else ""
            )
        )
        stat = queue_stats.get(_id(queue))
        if not key or stat is None:
            continue  # a dynamic queue may disappear between the two reads
        counters = _text(stat.get("bytes")).split("/")
        if len(counters) != 2:
            raise ValueError("missing native queue counters")
        reports.append(
            {
                "queue_key": key,
                "upload_bytes": _number(counters[0]),
                "download_bytes": _number(counters[1]),
                "target_ip": _text(queue.get("target")),
                "max_limit": _text(queue.get("max-limit")),
                "disabled": _id(queue) in disabled_queues,
            }
        )
    authorized = ids(host_part.get("authorized"))
    bypassed = ids(host_part.get("bypassed"))
    host_rows = rows(host_part.get("rows"))
    if not (authorized | bypassed) <= {_id(x) for x in host_rows}:
        raise ValueError("host table changed during snapshot")
    hosts = []
    for host in host_rows:
        if _id(host) not in authorized | bypassed:
            continue
        hosts.append(
            {
                "mac": _text(host.get("mac-address")),
                "ip": _text(host.get("address")),
                "bytes_in": _number(host.get("bytes-in")),
                "bytes_out": _number(host.get("bytes-out")),
                "authorized": _id(host) in authorized,
                "bypassed": _id(host) in bypassed,
                "idle_time": _duration(host.get("idle-time")),
                "uptime": _duration(host.get("uptime")),
            }
        )
    ppp = [
        {
            "name": _text(x.get("name")),
            "address": _text(x.get("address")),
            "uptime": _duration(x.get("uptime")),
            "caller_id": _text(x.get("caller-id")),
        }
        for x in rows(summary.get("ppp"))
    ]
    interface_stats = {_id(x): x for x in rows(summary.get("interface_stats"))}
    running = ids(summary.get("interface_running"))
    disabled_interfaces = ids(summary.get("interface_disabled"))
    ports = []
    wan_stats = None
    for interface in rows(summary.get("interfaces")):
        stat = interface_stats.get(_id(interface), {})
        if interface.get("name") == summary.get("wan"):
            wan_stats = stat
        if interface.get("type") not in ("ether", "wlan", "wifi"):
            continue
        port = {
            "name": _text(interface.get("name")),
            "running": _id(interface) in running,
            "disabled": _id(interface) in disabled_interfaces,
            "last_link_up": _text(interface.get("last-link-up-time")),
        }
        for native, canonical in (
            ("rx-byte", "rx_bytes"),
            ("tx-byte", "tx_bytes"),
            ("rx-packet", "rx_packets"),
            ("tx-packet", "tx_packets"),
            ("rx-error", "rx_errors"),
            ("tx-error", "tx_errors"),
            ("link-downs", "link_downs"),
        ):
            port[canonical] = _number(stat.get(native) or interface.get(native) or 0)
        ports.append(port)
    if wan_stats is None:
        raise ValueError("missing native WAN counters")
    metrics = {
        "iface_rx_bytes": _number(wan_stats.get("rx-byte")),
        "iface_tx_bytes": _number(wan_stats.get("tx-byte")),
        "hotspot_active": len(authorized) + len(bypassed),
        "pppoe_active": len(ppp),
        "queue_count": len(reports),
    }
    if wan_stats.get("link-downs") is not None:
        metrics["wan_link_downs"] = _number(wan_stats["link-downs"])
    for native, canonical in (
        ("cpu-load", "cpu_load"),
        ("free-memory", "free_memory"),
        ("total-memory", "total_memory"),
        ("free-hdd-space", "free_hdd"),
        ("total-hdd-space", "total_hdd"),
    ):
        metrics[canonical] = _number(resource.get(native))
    for native, canonical in (
        ("uptime", "uptime"),
        ("version", "version"),
        ("board-name", "board"),
    ):
        metrics[canonical] = (
            _duration(resource.get(native))
            if native == "uptime"
            else _text(resource.get(native))
        )
    result = {
        "identity": identity,
        "v": 3,
        "reports": reports,
        "hosts": hosts,
        "ppp": ppp,
        "ports": ports,
        "router": metrics,
    }
    mappings = {
        "bridge_hosts": {"mac-address": "mac", "on-interface": "port"},
        "leases": {
            "mac-address": "mac",
            "address": "ip",
            "host-name": "host",
            "status": "status",
            "comment": "comment",
        },
        "neighbors": {
            "mac-address": "mac",
            "identity": "identity",
            "board": "board",
            "platform": "platform",
            "version": "version",
            "interface": "interface",
            "address": "address",
        },
        "bridge_ports": {"interface": "interface", "bridge": "bridge"},
    }
    for name, mapping in mappings.items():
        if name in parts:
            result[name] = [
                {
                    canonical: _text(row.get(native))
                    for native, canonical in mapping.items()
                }
                for row in rows(parts[name])
            ]
    if "bindings" in parts:
        binding_part = parts["bindings"]
        if not isinstance(binding_part, dict):
            raise ValueError("invalid native bindings")
        disabled = ids(binding_part.get("disabled"))
        result["bindings"] = [
            {
                "mac": _text(x.get("mac-address")),
                "type": _text(x.get("type")),
                "disabled": _id(x) in disabled,
            }
            for x in rows(binding_part.get("rows"))
        ]
    return result


def api_bool(value):
    if value is None or value == "":
        return False
    if value is True or value in ("true", "yes", "1"):
        return True
    if value is False or value in ("false", "no", "0"):
        return False
    raise ValueError("invalid native API flag")


def native_api_to_v3(identity, tables, wan, *, queue_order=None, observed=None):
    """Project native API data onto the unchanged host-counter ingest contract."""
    hosts = []
    keys = set()
    for host in rows(tables.get("hosts", [])):
        if not (api_bool(host.get("authorized")) or api_bool(host.get("bypassed"))):
            continue
        if (
            not host.get(".id")
            or not host.get("mac-address")
            or host.get("bytes-in") is None
            or host.get("bytes-out") is None
        ):
            continue
        key = (host["mac-address"].upper(), host.get("address", ""))
        if key in keys:
            raise ValueError("duplicate native host counter key")
        keys.add(key)
        hosts.append(host)
    queues = rows(tables.get("queues", []))
    if queue_order is not None:
        order = {identifier: index for index, identifier in enumerate(queue_order)}
        queues = sorted(queues, key=lambda row: order.get(row.get(".id"), len(order)))
    interfaces = rows(tables.get("interfaces", []))
    bindings = rows(tables.get("bindings", []))
    parts = {
        "queues": queues,
        "queue_stats": [
            q for q in queues if q.get(".id") and q.get("bytes") is not None
        ],
        "hosts": {
            "rows": hosts,
            "authorized": [h[".id"] for h in hosts if api_bool(h.get("authorized"))],
            "bypassed": [h[".id"] for h in hosts if api_bool(h.get("bypassed"))],
        },
        "summary": {
            "resource": tables.get("resource"),
            "wan": wan,
            "queue_disabled": [
                q[".id"] for q in queues if q.get(".id") and api_bool(q.get("disabled"))
            ],
            "ppp": tables.get("ppp", []),
            "interfaces": interfaces,
            "interface_stats": interfaces,
            "interface_running": [
                i[".id"] for i in interfaces if api_bool(i.get("running"))
            ],
            "interface_disabled": [
                i[".id"] for i in interfaces if api_bool(i.get("disabled"))
            ],
        },
        "bindings": {
            "rows": bindings,
            "disabled": [b[".id"] for b in bindings if api_bool(b.get("disabled"))],
        },
        "bridge_hosts": [
            b
            for b in rows(tables.get("bridge_hosts", []))
            if not api_bool(b.get("local"))
        ],
    }
    for name in ["leases", "neighbors", "bridge_ports"]:
        if name in tables:
            parts[name] = tables[name]
    result = decode_snapshot(identity, parts)
    result["v"] = 3
    if observed is not None:
        host_times = {
            (h["mac-address"].upper(), h.get("address", "")): observed["hosts"][
                h[".id"]
            ].isoformat()
            for h in hosts
        }
        queue_times = {}
        for q in queues:
            name = q.get("name", "")
            key = (
                name[5:]
                if name.startswith("plan_")
                else (
                    "pppoe:" + name[7:-1]
                    if name.startswith("<pppoe-") and name.endswith(">")
                    else ""
                )
            )
            if key and q.get("bytes") is not None:
                queue_times[key] = observed["queues"][q[".id"]].isoformat()
        for host in result["hosts"]:
            host["sampled_at"] = host_times[(host["mac"].upper(), host["ip"])]
        for report in result["reports"]:
            report["sampled_at"] = queue_times[report["queue_key"]]
    return result

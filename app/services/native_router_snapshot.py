"""Decode bounded, atomic native RouterOS snapshots without router-side row loops.

The router sends data only. A partial upload never becomes a usage report.
This module has no database or network I/O.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

BASE_PARTS = frozenset({"queues", "queue_stats", "hosts", "summary"})
INVENTORY_PARTS = frozenset({"bridge_hosts", "bindings", "leases", "neighbors", "bridge_ports"})
ALLOWED_PARTS = BASE_PARTS | INVENTORY_PARTS
MAX_PART_BYTES = 60_000
MAX_ROWS = 2_000
_BATCH = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


class SnapshotBusy(ValueError):
    pass


def rows(value: Any) -> list[dict]:
    # RouterOS serializes an empty untyped array as an empty object.
    if value == {}:
        return []
    if not isinstance(value, list) or len(value) > MAX_ROWS or any(not isinstance(x, dict) for x in value):
        raise ValueError("invalid native table")
    return value


def ids(value: Any) -> set[str]:
    if value == {}:
        return set()
    if not isinstance(value, list) or len(value) > MAX_ROWS or any(not isinstance(x, str) for x in value):
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
    if integer < 0 or integer > 9_223_372_036_854_775_807 or isinstance(value, float) and value != integer:
        raise ValueError("native counter out of range")
    return integer


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
        key = name[5:] if name.startswith("plan_") else (
            "pppoe:" + name[7:-1] if name.startswith("<pppoe-") and name.endswith(">") else "")
        stat = queue_stats.get(_id(queue))
        if not key or stat is None:
            continue  # a dynamic queue may disappear between the two reads
        counters = _text(stat.get("bytes")).split("/")
        if len(counters) != 2:
            raise ValueError("missing native queue counters")
        reports.append({"queue_key": key, "upload_bytes": _number(counters[0]),
                        "download_bytes": _number(counters[1]), "target_ip": _text(queue.get("target")),
                        "max_limit": _text(queue.get("max-limit")), "disabled": _id(queue) in disabled_queues})
    authorized = ids(host_part.get("authorized"))
    bypassed = ids(host_part.get("bypassed"))
    host_rows = rows(host_part.get("rows"))
    if not (authorized | bypassed) <= {_id(x) for x in host_rows}:
        raise ValueError("host table changed during snapshot")
    hosts = []
    for host in host_rows:
        if _id(host) not in authorized | bypassed:
            continue
        hosts.append({"mac": _text(host.get("mac-address")), "ip": _text(host.get("address")),
                      "bytes_in": _number(host.get("bytes-in")), "bytes_out": _number(host.get("bytes-out")),
                      "authorized": _id(host) in authorized, "bypassed": _id(host) in bypassed,
                      "idle_time": _text(host.get("idle-time")), "uptime": _text(host.get("uptime"))})
    ppp = [{"name": _text(x.get("name")), "address": _text(x.get("address")),
            "uptime": _text(x.get("uptime")), "caller_id": _text(x.get("caller-id"))}
           for x in rows(summary.get("ppp"))]
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
        port = {"name": _text(interface.get("name")), "running": _id(interface) in running,
                "disabled": _id(interface) in disabled_interfaces,
                "last_link_up": _text(interface.get("last-link-up-time"))}
        for native, canonical in (("rx-byte", "rx_bytes"), ("tx-byte", "tx_bytes"),
                                  ("rx-packet", "rx_packets"), ("tx-packet", "tx_packets"),
                                  ("rx-error", "rx_errors"), ("tx-error", "tx_errors"), ("link-downs", "link_downs")):
            port[canonical] = _number(stat.get(native) or interface.get(native) or 0)
        ports.append(port)
    if wan_stats is None:
        raise ValueError("missing native WAN counters")
    metrics = {"iface_rx_bytes": _number(wan_stats.get("rx-byte")),
               "iface_tx_bytes": _number(wan_stats.get("tx-byte")),
               "hotspot_active": len(authorized) + len(bypassed), "pppoe_active": len(ppp),
               "queue_count": len(reports)}
    for native, canonical in (("cpu-load", "cpu_load"), ("free-memory", "free_memory"),
                              ("total-memory", "total_memory"), ("free-hdd-space", "free_hdd"),
                              ("total-hdd-space", "total_hdd")):
        metrics[canonical] = _number(resource.get(native))
    for native, canonical in (("uptime", "uptime"), ("version", "version"), ("board-name", "board")):
        metrics[canonical] = _text(resource.get(native))
    result = {"identity": identity, "v": 4, "reports": reports, "hosts": hosts, "ppp": ppp,
              "ports": ports, "router": metrics}
    mappings = {
        "bridge_hosts": {"mac-address": "mac", "on-interface": "port"},
        "leases": {"mac-address": "mac", "address": "ip", "host-name": "host", "status": "status", "comment": "comment"},
        "neighbors": {"mac-address": "mac", "identity": "identity", "board": "board", "platform": "platform",
                      "version": "version", "interface": "interface", "address": "address"},
        "bridge_ports": {"interface": "interface", "bridge": "bridge"},
    }
    for name, mapping in mappings.items():
        if name in parts:
            result[name] = [{canonical: _text(row.get(native)) for native, canonical in mapping.items()}
                            for row in rows(parts[name])]
    if "bindings" in parts:
        binding_part = parts["bindings"]
        if not isinstance(binding_part, dict):
            raise ValueError("invalid native bindings")
        disabled = ids(binding_part.get("disabled"))
        result["bindings"] = [{"mac": _text(x.get("mac-address")), "type": _text(x.get("type")),
                               "disabled": _id(x) in disabled} for x in rows(binding_part.get("rows"))]
    return result


@dataclass
class _Pending:
    started: float
    expected: frozenset[str]
    parts: dict[str, Any] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)


class NativeSnapshotAssembler:
    """One pending batch per authenticated identity, bounded by bytes and TTL."""

    def __init__(self, *, max_pending: int = 32, max_bytes: int = 8 * 1024 * 1024, ttl: float = 45):
        self.max_pending, self.max_bytes, self.ttl = max_pending, max_bytes, ttl
        self.pending: dict[tuple[str, str], _Pending] = {}
        self.completed: dict[tuple[str, str], float] = {}
        self.total_bytes = 0

    def _drop(self, key: tuple[str, str]) -> None:
        old = self.pending.pop(key, None)
        if old:
            self.total_bytes -= sum(old.sizes.values())

    def accept(self, identity: str, native: dict, *, now: float) -> dict | None:
        """None means accepted incomplete/duplicate; only a complete report is returned.

        Call only AFTER authenticating the identity. No DB connection is needed.
        """
        for key, batch in list(self.pending.items()):
            if now - batch.started >= self.ttl:
                self._drop(key)
        self.completed = {k: until for k, until in self.completed.items() if until > now}
        batch_id, part, declared = native.get("batch"), native.get("part"), native.get("parts")
        if not isinstance(batch_id, str) or not _BATCH.fullmatch(batch_id):
            raise ValueError("invalid native batch")
        if not isinstance(declared, list) or any(not isinstance(x, str) for x in declared):
            raise ValueError("invalid native manifest")
        expected = frozenset(declared)
        if len(declared) != len(expected) or not BASE_PARTS <= expected <= ALLOWED_PARTS or not isinstance(part, str) or part not in expected:
            raise ValueError("invalid native manifest")
        key = (identity, batch_id)
        if key in self.completed:
            return None
        encoded = json.dumps(native, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_PART_BYTES:
            raise ValueError("native part too large")
        # Starting a fresh batch discards an unfinished old one. Counters remain
        # cumulative, so a later complete batch catches up without partial data.
        for old_key in list(self.pending):
            if old_key[0] == identity and old_key != key:
                self._drop(old_key)
        pending = self.pending.get(key)
        if pending is None:
            if len(self.pending) >= self.max_pending:
                raise SnapshotBusy("native snapshot capacity reached")
            pending = _Pending(now, expected)
            self.pending[key] = pending
        if pending.expected != expected:
            self._drop(key)
            raise ValueError("native manifest changed")
        data = native.get("data")
        if part in pending.parts:
            if pending.parts[part] != data:
                self._drop(key)
                raise ValueError("native part changed")
            return None
        if self.total_bytes + len(encoded) > self.max_bytes:
            self._drop(key)
            raise SnapshotBusy("native snapshot byte budget reached")
        pending.parts[part] = data
        pending.sizes[part] = len(encoded)
        self.total_bytes += len(encoded)
        if pending.parts.keys() != expected:
            return None
        self._drop(key)
        result = decode_snapshot(identity, pending.parts)
        if len(self.completed) >= 4096:
            self.completed.pop(next(iter(self.completed)))
        self.completed[key] = now + 180
        return result

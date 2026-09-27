#!/usr/bin/env python3
"""Prefer live Hetzner router tunnels for legacy 10.0.X.Y management IPs.

The application database intentionally keeps the established 10.0.0.0/16
router addresses. Hetzner assigns the same host offsets in 10.251.0.0/16.
This reconciler adds a more-specific legacy /32 route only while the native
WireGuard peer has a recent handshake or a native L2TP PPP route exists.
New routes must also pass a RouterOS TCP probe. Once selected, a native route
is kept for as long as its tunnel remains alive, so a momentarily busy API
port cannot flap live sessions back and forth through AWS transit. Without
that /32, Linux naturally falls back to the existing AWS-transit /16.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import subprocess
import time
from dataclasses import dataclass


MANAGED_ROUTE_PROTOCOL = "186"


@dataclass(frozen=True)
class RouteTarget:
    device: str
    metric: int
    source: str
    native_host: str


def run(command: list[str], *, check: bool = True) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise RuntimeError(f"{' '.join(command)}: {detail}")
    return result.stdout


def mapped_address(address: str, source: ipaddress.IPv4Network, target: ipaddress.IPv4Network) -> str:
    value = ipaddress.IPv4Address(address)
    if value not in source:
        raise ValueError(f"{value} is outside {source}")
    offset = int(value) - int(source.network_address)
    return str(ipaddress.IPv4Address(int(target.network_address) + offset))


def parse_wg_peers(interface: str) -> list[dict[str, object]]:
    lines = run(["wg", "show", interface, "dump"]).splitlines()
    peers = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        peers.append(
            {
                "public_key": fields[0],
                "allowed_ips": [item for item in fields[3].split(",") if item],
                "latest_handshake": int(fields[4] or 0),
            }
        )
    return peers


def native_host_from_allowed_ips(allowed_ips: list[str], native_network: ipaddress.IPv4Network) -> str | None:
    for entry in allowed_ips:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32:
            address = network.network_address
            if address in native_network and address != native_network.network_address + 1:
                return str(address)
    return None


def active_ppp_routes(native_network: ipaddress.IPv4Network) -> dict[str, str]:
    candidates: set[str] = set()
    for line in run(["ip", "-4", "route", "show"]).splitlines():
        fields = line.split()
        if len(fields) < 3 or "dev" not in fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0].split("/", 1)[0])
        except ValueError:
            continue
        device = fields[fields.index("dev") + 1]
        if address in native_network and device.startswith("ppp"):
            candidates.add(str(address))

    selected = {}
    for address in candidates:
        fields = run(["ip", "-4", "route", "get", address]).split()
        if "dev" not in fields:
            continue
        device = fields[fields.index("dev") + 1]
        if device.startswith("ppp"):
            selected[address] = device
    return selected


def managed_routes(primary_network: ipaddress.IPv4Network) -> dict[str, str]:
    routes = {}
    output = run(["ip", "-4", "route", "show", "proto", MANAGED_ROUTE_PROTOCOL], check=False)
    for line in output.splitlines():
        fields = line.split()
        if not fields or "dev" not in fields:
            continue
        try:
            network = ipaddress.ip_network(fields[0], strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen == 32 and network.network_address in primary_network:
            routes[str(network.network_address)] = fields[fields.index("dev") + 1]
    return routes


def control_ready(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def reconcile(args: argparse.Namespace) -> dict[str, object]:
    primary_network = ipaddress.IPv4Network(args.primary_subnet)
    native_network = ipaddress.IPv4Network(args.native_subnet)
    if primary_network.prefixlen != native_network.prefixlen:
        raise ValueError("primary and native subnets must have matching prefixes")

    now = int(time.time())
    desired: dict[str, RouteTarget] = {}
    peer_updates: list[tuple[str, list[str]]] = []

    for peer in parse_wg_peers(args.wg_interface):
        allowed_ips = list(peer["allowed_ips"])
        native_host = native_host_from_allowed_ips(allowed_ips, native_network)
        if not native_host:
            continue
        primary_host = mapped_address(native_host, native_network, primary_network)
        primary_cidr = f"{primary_host}/32"
        if primary_cidr not in allowed_ips:
            peer_updates.append((str(peer["public_key"]), [*allowed_ips, primary_cidr]))
        handshake = int(peer["latest_handshake"])
        if handshake and now - handshake <= args.handshake_max_age:
            desired[primary_host] = RouteTarget(args.wg_interface, 10, "wireguard", native_host)

    for public_key, allowed_ips in peer_updates:
        if not args.dry_run:
            run(
                [
                    "wg",
                    "set",
                    args.wg_interface,
                    "peer",
                    public_key,
                    "allowed-ips",
                    ",".join(allowed_ips),
                ]
            )

    ppp_routes = active_ppp_routes(native_network)
    for native_host, device in ppp_routes.items():
        primary_host = mapped_address(native_host, native_network, primary_network)
        desired[primary_host] = RouteTarget(device, 5, "l2tp", native_host)

    existing = managed_routes(primary_network)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.probe_workers) as pool:
        readiness = dict(
            zip(
                desired,
                pool.map(
                    lambda item: control_ready(item[1].native_host, args.probe_port, args.probe_timeout),
                    desired.items(),
                ),
            )
        )
    selected = {}
    probe_kept_existing = []
    probe_rejected_new = []
    for primary_host, target in desired.items():
        if readiness[primary_host]:
            selected[primary_host] = target
            continue
        if existing.get(primary_host) == target.device:
            selected[primary_host] = target
            probe_kept_existing.append(primary_host)
            continue
        probe_rejected_new.append(primary_host)
    desired = selected

    applied = []
    for primary_host, target in sorted(desired.items()):
        command = [
            "ip",
            "route",
            "replace",
            f"{primary_host}/32",
            "dev",
            target.device,
            "proto",
            MANAGED_ROUTE_PROTOCOL,
            "metric",
            str(target.metric),
        ]
        if not args.dry_run:
            run(command)
        applied.append({"ip": primary_host, "device": target.device, "source": target.source})

    removed = []
    for primary_host, device in sorted(existing.items()):
        if primary_host in desired:
            continue
        command = ["ip", "route", "del", f"{primary_host}/32", "proto", MANAGED_ROUTE_PROTOCOL]
        if not args.dry_run:
            run(command, check=False)
        removed.append({"ip": primary_host, "device": device})

    return {
        "dry_run": args.dry_run,
        "wireguard_peer_updates": len(peer_updates),
        "wireguard_active_routes": sum(1 for route in desired.values() if route.source == "wireguard"),
        "l2tp_active_routes": sum(1 for route in desired.values() if route.source == "l2tp"),
        "probe_kept_existing": probe_kept_existing,
        "probe_rejected_new": probe_rejected_new,
        "applied": applied,
        "removed": removed,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wg-interface", default="wg2")
    parser.add_argument("--primary-subnet", default="10.0.0.0/16")
    parser.add_argument("--native-subnet", default="10.251.0.0/16")
    parser.add_argument("--handshake-max-age", type=int, default=180)
    parser.add_argument("--probe-port", type=int, default=8728)
    parser.add_argument("--probe-timeout", type=float, default=1.5)
    parser.add_argument("--probe-workers", type=int, default=32)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(reconcile(args), sort_keys=True))


if __name__ == "__main__":
    main()

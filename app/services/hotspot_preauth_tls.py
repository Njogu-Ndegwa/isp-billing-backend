"""Plan opt-in native HTTPS rejection without changing HotSpot authorization.

Unauthenticated non-portal HTTPS is rejected by a firewall rule instead of
being redirected to the HotSpot HTTPS service. Allowed destinations retain
the original HotSpot path. DNS FWD records track the answers actually given
to clients, including permitted subdomains and CDN address changes.

This module does not enroll routers or enable the policy automatically.
RouterOS 7 support must be verified before applying the returned plan.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Iterable, Mapping

_HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LABEL = re.compile(r"[A-Za-z0-9_-]{1,60}\Z")


class UnsafePreauthTlsPlan(ValueError):
    """The existing policy cannot be preserved by this opt-in plan."""


def _disabled(row: Mapping) -> bool:
    return row.get("disabled") in (True, "true", "yes")


def _label(value: str) -> str:
    if not _LABEL.fullmatch(value):
        raise UnsafePreauthTlsPlan("Unsafe managed object label")
    return value


@dataclass(frozen=True, order=True)
class PortalDomain:
    name: str
    subdomains: bool = False


@dataclass(frozen=True)
class PreauthTlsPlan:
    domains: tuple[PortalDomain, ...]
    lookup_hosts: tuple[str, ...]
    networks: tuple[str, ...]

    def dns_rows(self, *, marker: str, address_list: str, existing: Iterable[Mapping] = ()) -> list[dict[str, str]]:
        _label(marker)
        _label(address_list)
        # Never shadow a customer-owned DNS record or regular-expression rule.
        for row in existing:
            if _disabled(row):
                continue
            name = row.get("name", "").lower().rstrip(".")
            overlaps = any(
                name == domain.name
                or (domain.subdomains and name.endswith("." + domain.name))
                or (row.get("match-subdomain") in (True, "true", "yes") and domain.name.endswith("." + name))
                for domain in self.domains
            )
            if row.get("regexp") or overlaps:
                raise UnsafePreauthTlsPlan("Existing DNS policy requires explicit preservation")
        return [{"name": d.name, "type": "FWD", "match-subdomain": "yes" if d.subdomains else "no", "address-list": address_list, "comment": marker} for d in self.domains]

    def address_rows(self, *, marker: str, address_list: str) -> list[dict[str, str]]:
        _label(marker)
        _label(address_list)
        return [{"list": address_list, "address": value, "comment": marker} for value in (*self.lookup_hosts, *self.networks)]


def build_plan(domain_rules: Iterable[Mapping], ip_rules: Iterable[Mapping]) -> PreauthTlsPlan:
    """Preserve every enabled walled-garden allow before proposing optimization.

    Source-limited allows are protected for all sources here: exclusion from
    optimization is not authorization; the original HotSpot rules still decide.
    Arbitrary regex/glob policies and unbounded allows are refused.
    """
    domains: set[PortalDomain] = set()
    hosts: set[str] = set()
    networks: set[str] = set()
    def add_address(value: str) -> None:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise UnsafePreauthTlsPlan("Unsupported walled-garden address") from exc
        if network.version == 4:
            if network.prefixlen == 0:
                raise UnsafePreauthTlsPlan("Unbounded walled-garden allow")
            networks.add(str(network))
    for family, rows in (("domain", domain_rules), ("ip", ip_rules)):
        for row in rows:
            if _disabled(row) or row.get("action", "allow" if family == "domain" else "accept") not in ("allow", "accept"):
                continue
            host = str(row.get("dst-host") or "").lower().rstrip(".")
            address = str(row.get("dst-address") or "")
            if not host and not address:
                raise UnsafePreauthTlsPlan("Unbounded or unsupported walled-garden allow")
            if address:
                add_address(address)
            if host:
                wildcard = host.startswith("*.")
                name = host[2:] if wildcard else host
                if not _HOST.fullmatch(name):
                    raise UnsafePreauthTlsPlan("Unsupported walled-garden hostname pattern")
                domains.add(PortalDomain(name, wildcard))
                if not wildcard:
                    hosts.add(name)
    minimal = tuple(sorted(d for d in domains if not any(p != d and p.subdomains and (d.name == p.name or d.name.endswith("." + p.name)) for p in domains)))
    if not hosts:
        raise UnsafePreauthTlsPlan("No concrete portal hostname to prime before enabling")
    return PreauthTlsPlan(minimal, tuple(sorted(hosts)), tuple(sorted(networks)))


def guard_rules(*, marker: str, address_list: str, before_filter_id: str) -> tuple[dict[str, str], dict[str, str]]:
    _label(marker)
    _label(address_list)
    common = {"protocol": "tcp", "dst-port": "443", "dst-address-list": "!" + address_list, "hotspot": "from-client,!auth,!local-dst", "disabled": "yes", "comment": marker}
    # A reset encourages some unpaid apps to retry immediately. A drop keeps
    # native TCP backoff, reducing the repeated work measured on RB951s.
    deny = {**common, "chain": "hs-unauth", "action": "drop", "place-before": before_filter_id}
    nat = {**common, "chain": "pre-hotspot", "action": "accept"}
    return deny, nat


def rollback_rsc(*, marker: str, address_list: str) -> str:
    _label(marker)
    _label(address_list)
    return "\n".join([
        f'/ip firewall nat remove [find where comment="{marker}"]',
        f'/ip firewall filter remove [find where comment="{marker}"]',
        f'/ip dns static remove [find where comment="{marker}"]',
        # Removing an FQDN also removes its dynamic children. A single bulk
        # remove then encounters stale IDs and can leave later parents behind.
        f':foreach i in=[/ip firewall address-list find where list="{address_list}" and dynamic=no] do={{ :do {{ /ip firewall address-list remove $i }} on-error={{}} }}',
        f':foreach i in=[/ip firewall address-list find where list="{address_list}"] do={{ :do {{ /ip firewall address-list remove $i }} on-error={{}} }}',
    ])

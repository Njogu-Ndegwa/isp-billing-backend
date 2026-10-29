"""A stateful RouterOS stand-in for router-side unit tests.

Subclasses MikroTikAPI and replaces only the wire (send_command /
send_command_optimized / connect), so the real helper methods
(add_pppoe_secret, ensure_pppoe_profile, disconnect_pppoe_session, ...) run
against an in-memory config. Menus are lists of dicts keyed by API path,
e.g. ``/ip/firewall/filter``. Supports print/add/set/remove, place-before,
duplicate names, singleton menus (``/ip/proxy``), ``?name=`` queries, and an
optional ``reject`` hook to simulate a RouterOS build refusing an argument.
"""

from __future__ import annotations

import copy
import itertools

from app.services.mikrotik_api import MikroTikAPI

SINGLETONS = {"/ip/proxy"}
NAMED = {"/ip/pool", "/ppp/profile", "/ppp/secret"}


class FakeRouterOS(MikroTikAPI):
    def __init__(self, menus=None, reject=None):
        self.connected = True
        self.host = "10.0.0.9"
        self.last_connect_error = None
        self.menus = copy.deepcopy(menus or {})
        self.menus.setdefault("/ip/proxy", [{"enabled": "false", "port": "8080"}])
        self.reject = reject  # callable(command, args) -> error str | None
        self.calls: list[tuple[str, dict]] = []
        self._ids = itertools.count(1000)

    # -- wire ---------------------------------------------------------------
    def connect(self):
        self.connected = True
        return True

    def disconnect(self):
        pass

    def writes(self):
        return [c for c in self.calls if not c[0].endswith("/print")]

    def send_command_optimized(self, command, proplist=None, query=None):
        result = self.send_command(command)
        if query and query.startswith("?name=") and result.get("success"):
            name = query[len("?name="):]
            result["data"] = [r for r in result["data"] if r.get("name") == name]
        return result

    def send_command(self, command, arguments=None):
        args = dict(arguments or {})
        self.calls.append((command, args))
        menu, _, action = command.rpartition("/")
        if self.reject:
            err = self.reject(command, args)
            if err:
                return {"error": err}
        rows = self.menus.setdefault(menu, [])
        if action == "print":
            return {"success": True, "data": copy.deepcopy(rows)}
        if action == "add":
            if menu in NAMED and any(r.get("name") == args.get("name") for r in rows):
                return {"error": "failure: already have such entry"}
            before = args.pop("place-before", None)
            row = {".id": f"*{next(self._ids):X}", "disabled": "false", **{k: str(v) for k, v in args.items()}}
            if before is not None:
                idx = next((i for i, r in enumerate(rows) if r.get(".id") == before), None)
                if idx is None:
                    return {"error": "no such item (place-before)"}
                rows.insert(idx, row)
            else:
                rows.append(row)
            return {"success": True, "data": [], "ret": row[".id"]}
        if action == "set":
            if menu in SINGLETONS:
                rows[0].update({k: str(v) for k, v in args.items()})
                return {"success": True, "data": []}
            key = args.pop("numbers", None) or args.pop(".id", None)
            row = self._find(rows, key)
            if row is None:
                return {"error": "no such item"}
            row.update({k: str(v) for k, v in args.items()})
            return {"success": True, "data": []}
        if action == "remove":
            key = args.get("numbers") or args.get(".id")
            row = self._find(rows, key)
            if row is None:
                return {"error": "no such item"}
            rows.remove(row)
            return {"success": True, "data": []}
        return {"success": True, "data": []}

    @staticmethod
    def _find(rows, key):
        for r in rows:
            if r.get(".id") == key or r.get("name") == key:
                return r
        return None

    # -- helpers for tests --------------------------------------------------
    def rows(self, menu, **match):
        return [r for r in self.menus.get(menu, []) if all(r.get(k) == v for k, v in match.items())]

    def comments(self, menu, chain=None):
        return [r.get("comment") for r in self.menus.get(menu, []) if chain is None or r.get("chain") == chain]


def typical_router_menus():
    """A provisioned hotspot + PPPoE router with LB and the anti-tunnel fix."""
    return {
        "/ip/address": [
            {".id": "*1", "address": "192.168.88.1/24", "network": "192.168.88.0", "interface": "bridge"},
            {".id": "*2", "address": "192.168.89.1/24", "network": "192.168.89.0", "interface": "bridge-pppoe"},
            {".id": "*3", "address": "10.0.3.17/32", "network": "10.0.0.1", "interface": "wg-aws"},
            {".id": "*4", "address": "100.70.1.20/24", "network": "100.70.1.0", "interface": "ether1"},
        ],
        "/ip/pool": [
            {".id": "*10", "name": "hs-pool", "ranges": "192.168.88.10-192.168.88.254"},
            {".id": "*11", "name": "pppoe-pool", "ranges": "192.168.89.2-192.168.89.254"},
        ],
        "/ip/route": [
            {".id": "*20", "dst-address": "0.0.0.0/0", "gateway": "100.70.1.1", "comment": "ISP_BILLING_LB_CHECKED_WAN1"},
            {".id": "*21", "dst-address": "10.0.0.0/16", "gateway": "wg-aws"},
        ],
        "/ppp/profile": [
            {".id": "*30", "name": "default-pppoe", "local-address": "192.168.89.1", "remote-address": "pppoe-pool",
             "dns-server": "8.8.8.8"},
            {".id": "*31", "name": "pppoe_10M_10M", "local-address": "192.168.89.1", "remote-address": "pppoe-pool",
             "rate-limit": "10M/10M"},
        ],
        "/interface/pppoe-server/server": [
            {".id": "*40", "service-name": "bw", "interface": "bridge-pppoe", "disabled": "false",
             "default-profile": "default-pppoe"},
        ],
        "/ppp/secret": [
            {".id": "*50", "name": "jane", "password": "pw-jane", "profile": "pppoe_10M_10M", "service": "pppoe",
             "comment": "CID:7|Jane|2026-10-01"},
            {".id": "*51", "name": "otis", "password": "pw-otis", "profile": "pppoe_10M_10M", "service": "pppoe",
             "comment": "CID:8|Otis|2026-10-01"},
        ],
        "/ppp/active": [
            {".id": "*60", "name": "jane", "address": "192.168.89.20"},
            {".id": "*61", "name": "otis", "address": "192.168.89.21"},
        ],
        "/ip/firewall/filter": [
            {".id": "*D1", "chain": "forward", "action": "jump", "jump-target": "hs-unauth", "dynamic": "true"},
            {".id": "*70", "chain": "input", "protocol": "tcp", "dst-port": "8728", "src-address": "10.0.0.1",
             "action": "accept", "comment": "Allow API from primary AWS"},
            {".id": "*71", "chain": "input", "in-interface-list": "!LAN", "action": "drop",
             "comment": "defconf: drop all not coming from LAN"},
            {".id": "*72", "chain": "forward", "src-address": "192.168.89.0/24", "action": "accept",
             "comment": "PPPoE bypass FastTrack (src) 192.168.89.0/24"},
            {".id": "*73", "chain": "forward", "action": "fasttrack-connection",
             "connection-state": "established,related", "connection-mark": "no-mark"},
            {".id": "*74", "chain": "forward", "action": "accept", "connection-state": "established,related"},
            {".id": "*75", "chain": "output", "protocol": "tcp", "dst-port": "80,3128,8080",
             "dst-address-list": "!isp_portal_allow", "dst-address": "!192.168.88.0/24",
             "action": "reject", "reject-with": "tcp-reset", "comment": "ISP_BILLING_PROXY_RELAY_BLOCK"},
        ],
        "/ip/firewall/nat": [
            {".id": "*D2", "chain": "dstnat", "action": "jump", "jump-target": "hotspot", "hotspot": "from-client",
             "dynamic": "true"},
            {".id": "*80", "chain": "srcnat", "out-interface": "ether1", "action": "masquerade",
             "comment": "defconf: masquerade"},
            {".id": "*81", "chain": "srcnat", "src-address": "192.168.89.0/24", "out-interface": "ether1",
             "action": "masquerade", "comment": "NAT for PPPoE clients"},
            {".id": "*82", "chain": "dstnat", "dst-port": "8291", "protocol": "tcp", "action": "dst-nat",
             "to-addresses": "192.168.88.2", "comment": "reseller port forward"},
        ],
        "/ip/firewall/mangle": [
            {".id": "*90", "chain": "prerouting", "src-address-list": "!LB_PAID", "action": "accept",
             "comment": "ISP_BILLING_LB_UNPAID"},
        ],
        "/ip/firewall/address-list": [
            {".id": "*A0", "list": "isp_portal_allow", "address": "91.98.238.12", "comment": "ISP_BILLING_PORTAL_ALLOW"},
        ],
        "/ip/proxy/access": [],
        "/ip/proxy": [{"enabled": "false", "port": "8080"}],
    }

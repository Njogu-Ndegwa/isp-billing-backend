"""Static-IP customers: router control, expiry enforcement and MAC pinning.

A static-IP customer is a device (usually a customer's own Tenda/TP-Link
router) configured by hand with a fixed address on the MikroTik's LAN, e.g.
``192.168.2.24`` with gateway ``192.168.2.1``. Nothing about it is dynamic, so
the app manages four router objects per customer, all keyed by the IP:

* ``/ip hotspot ip-binding`` — ``address=<ip> type=bypassed``, NO mac-address.
  This is what grants internet: without it the device is just another
  unauthenticated hotspot host and lands on the captive portal. Suspending a
  customer disables the binding, so an expired static drops onto the payment
  page instead of keeping free internet. The binding carries no MAC on
  purpose: the bypass safety net and the expiry reaper only ever act on
  MAC bindings, so they leave these alone.
* ``/queue simple`` named ``plan_static:<ip>`` — the plan speed. The name is
  chosen so the router's existing usage-push script (which reports every
  ``plan_*`` queue, key = the rest of the name) reports it as
  ``static:<ip>`` with no script change, and so queue hygiene (which only
  judges ``plan_<12 hex>``) never mistakes it for an orphan hotspot queue.
* ``/ip firewall filter`` ``STATIC-PIN:`` — ``src-address=<ip>
  src-mac-address=!<mac> action=drop`` in forward. Stops a neighbour typing in
  a paying customer's IP. The MAC is learned the first time the device is seen
  while the customer is paid up (``Customer.static_mac``), or set by hand.
* ``/ip firewall address-list bitwave-static`` — every static IP, used by two
  shared rules that keep static traffic out of FastTrack (FastTrack skips
  simple queues, which would void the speed limit).

A customer who flips their router to DHCP gets a pool address, which has no
binding: they are a normal hotspot client and must pay at the portal.

Everything here is desired-state and idempotent: ``apply`` makes the router
match what the database says (enabled iff ACTIVE with a future expiry), adopting
hand-made objects for the same IP instead of duplicating them. The background
job ``enforce_static_ip_customers_background`` suspends expired customers and,
every ``FULL_RECONCILE_SECONDS`` per router, repairs any drift and learns MACs.
Expiry is enforced server-side with no grace, like PPPoE.

DB session discipline (AGENTS.md): payloads are read in a short session that
is closed before any RouterOS I/O; results are persisted in fresh sessions.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.services.customer_grace import has_access_time
from app.db import database as db_module
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    Plan,
    ProvisioningLog,
    Router,
)
from app.services.mikrotik_api import (
    LANE_BACKGROUND,
    LANE_DEFAULT,
    LANE_PAYMENT,
    MikroTikAPI,
    is_hotspot_parent_queue_name,
    normalize_mac_address,
    parse_speed_to_mikrotik,
)

logger = logging.getLogger(__name__)

STATIC_QUEUE_PREFIX = "plan_static:"
STATIC_KEY_PREFIX = "static:"
STATIC_COMMENT_PREFIX = "STATIC:"
STATIC_PIN_COMMENT_PREFIX = "STATIC-PIN:"
STATIC_ADDRESS_LIST = "bitwave-static"
FASTTRACK_BYPASS_COMMENTS = (
    "STATIC: keep static-IP uploads out of FastTrack so queues apply",
    "STATIC: keep static-IP downloads out of FastTrack so queues apply",
)

# Full drift repair + MAC learning per router at most this often; expired
# customers are handled on every tick regardless.
FULL_RECONCILE_SECONDS = 600
ENFORCE_INTERVAL_SECONDS = 61

_static_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="static-ip")
_background_tasks: set = set()
_last_full_reconcile: dict[int, datetime] = {}
_reported_mismatch: dict[int, str] = {}
enforce_running = False


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def normalize_static_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical IPv4 host address, or None if ``value`` is not one.

    Accepts ``a.b.c.d`` or ``a.b.c.d/32``. Network, broadcast-looking and
    non-private addresses are not rejected here (a reseller may run public
    statics); only shape is checked.
    """
    text = str(value or "").strip()
    if not text:
        return None
    ip, _, mask = text.partition("/")
    if mask and mask.strip() != "32":
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if addr.version != 4 or addr.is_unspecified or addr.is_loopback or addr.is_multicast:
        return None
    return str(addr)


_MAC_SHAPE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$")


def normalize_pin_mac(value: Optional[str]) -> Optional[str]:
    """Canonical ``AA:BB:CC:DD:EE:FF`` pin MAC, None when blank.

    Raises ``ValueError`` for anything that is not a MAC. Shared by customer
    registration/edit and the bulk static-IP import so both accept the same
    spellings.
    """
    text = (value or "").strip()
    if not text:
        return None
    if not _MAC_SHAPE.match(text):
        raise ValueError(f"'{text}' is not a valid MAC address")
    return normalize_mac_address(text).upper()


INVALID_STATIC_IP_MESSAGE = (
    "Static IP plans need a valid IPv4 address for the customer, e.g. 192.168.2.24"
)


async def static_ips_in_use(
    db: AsyncSession, router_id: Optional[int], exclude_customer_id: Optional[int] = None,
) -> Dict[str, tuple]:
    """``{ip: (customer_id, name)}`` for every static-IP-plan customer on a router.

    One query; the uniqueness rule used by registration, edit and import.
    """
    stmt = (
        select(Customer.id, Customer.name, Customer.static_ip)
        .join(Plan, Plan.id == Customer.plan_id)
        .where(
            Customer.router_id == router_id,
            Plan.connection_type == ConnectionType.STATIC_IP,
            Customer.static_ip.isnot(None),
        )
    )
    if exclude_customer_id is not None:
        stmt = stmt.where(Customer.id != exclude_customer_id)
    out: Dict[str, tuple] = {}
    for row in (await db.execute(stmt)).all():
        ip = normalize_static_ip(row.static_ip)
        if ip and ip not in out:
            out[ip] = (row.id, row.name)
    return out


def static_queue_name(ip: str) -> str:
    return f"{STATIC_QUEUE_PREFIX}{ip}"


def static_usage_key(ip: str) -> str:
    return f"{STATIC_KEY_PREFIX}{ip}"


def static_rate_limit(speed: Optional[str]) -> str:
    """Plan speed (DOWNLOAD/UPLOAD) -> simple-queue max-limit (upload/download)."""
    return parse_speed_to_mikrotik(speed or "") or "10M/10M"


def _comment(customer_id: int, name: Optional[str]) -> str:
    label = (name or "").replace('"', "").replace("\n", " ").strip()[:60] or "customer"
    return f"{STATIC_COMMENT_PREFIX} {label} (cust {customer_id})"


def _pin_comment(customer_id: int, name: Optional[str]) -> str:
    label = (name or "").replace('"', "").replace("\n", " ").strip()[:60] or "customer"
    return f"{STATIC_PIN_COMMENT_PREFIX} {label} (cust {customer_id})"


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def _target_ip(target: Any) -> Optional[str]:
    text = str(target or "").strip()
    if not text or "," in text:
        return None
    return normalize_static_ip(text)


def customer_should_have_access(customer: Customer, now: Optional[datetime] = None) -> bool:
    now = now or datetime.utcnow()
    # Effective expiry: paid expiry plus any reseller-set grace period.
    return (
        customer.status == CustomerStatus.ACTIVE
        and customer.expiry is not None
        and has_access_time(customer, now)
    )


def is_static_customer(customer: Customer) -> bool:
    plan = getattr(customer, "plan", None)
    return bool(plan is not None and plan.connection_type == ConnectionType.STATIC_IP)


# ---------------------------------------------------------------------------
# Router side (sync; runs in a worker thread)
# ---------------------------------------------------------------------------

@dataclass
class StaticItem:
    """What one customer should look like on the router."""
    customer_id: int
    name: str
    ip: str
    rate_limit: str
    enabled: bool
    mac: Optional[str] = None        # pinned MAC from the DB
    auto_pin: bool = True            # learn a MAC if none is pinned
    clear_pin: bool = False          # remove pins on the router (reset)
    old_ip: Optional[str] = None     # tear down objects left on a previous IP


@dataclass
class _RouterTables:
    bindings: list = field(default_factory=list)
    queues: list = field(default_factory=list)
    filters: list = field(default_factory=list)
    address_list: list = field(default_factory=list)
    addresses: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    arp: list = field(default_factory=list)
    lb_paid: list = field(default_factory=list)


def _rows(api: MikroTikAPI, command: str) -> list:
    result = api.send_command(command)
    if not result.get("success"):
        raise RuntimeError(f"{command}: {result.get('error') or 'failed'}")
    return result.get("data") or []


def _read_tables(api: MikroTikAPI) -> _RouterTables:
    address_lists = _rows(api, "/ip/firewall/address-list/print")
    tables = _RouterTables(
        bindings=_rows(api, "/ip/hotspot/ip-binding/print"),
        queues=_rows(api, "/queue/simple/print"),
        filters=_rows(api, "/ip/firewall/filter/print"),
        address_list=[
            row for row in address_lists
            if row.get("list") == STATIC_ADDRESS_LIST
        ],
        addresses=_rows(api, "/ip/address/print"),
        lb_paid=[row for row in address_lists if row.get("list") == "LB_PAID"],
    )
    # Observational only: a router without hotspot or ARP must still apply.
    for attr, command in (("hosts", "/ip/hotspot/host/print"), ("arp", "/ip/arp/print")):
        result = api.send_command(command)
        if result.get("success"):
            setattr(tables, attr, result.get("data") or [])
    return tables


def _ok(result: Dict[str, Any]) -> bool:
    if not result.get("success") or result.get("error"):
        raise RuntimeError(result.get("error") or "Router rejected the operation")
    return True


def _removed(result: Dict[str, Any]) -> bool:
    """Like ``_ok`` for a remove, but an item that is already gone counts as removed.

    RouterOS drops a bypassed hotspot host by itself the moment its binding is
    disabled, so removing it by the id read a moment earlier answers
    "no such item". The desired state (absent) holds, so that must not fail
    the whole apply -- it used to turn every suspend of an online static
    customer into a 503 that the enforcement job then undid.
    """
    error = str(result.get("error") or "")
    if not result.get("success") and "no such item" in error.lower():
        return False
    return _ok(result)


def _gateway_ok(tables: _RouterTables, ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    for row in tables.addresses:
        if _is_true(row.get("disabled")) or _is_true(row.get("invalid")):
            continue
        try:
            iface = ipaddress.ip_interface(str(row.get("address") or ""))
        except ValueError:
            continue
        if iface.network.prefixlen < 32 and addr in iface.network and addr != iface.ip:
            return True
    return False


def _observed_mac(tables: _RouterTables, ip: str) -> Optional[str]:
    """MAC currently using ``ip``: hotspot host first (prefer bypassed), then ARP."""
    hosts = [h for h in tables.hosts if str(h.get("address") or "") == ip and h.get("mac-address")]
    hosts.sort(key=lambda h: not _is_true(h.get("bypassed")))
    if hosts:
        return normalize_mac_address(hosts[0]["mac-address"]).upper()
    for row in tables.arp:
        if str(row.get("address") or "") == ip and row.get("mac-address") and _is_true(row.get("complete", "true")):
            return normalize_mac_address(row["mac-address"]).upper()
    return None


def _bindings_for(tables: _RouterTables, ip: str) -> list:
    return [
        b for b in tables.bindings
        if str(b.get("address") or "") == ip and not b.get("mac-address")
        and not _is_true(b.get("dynamic"))
    ]


def _queues_for(tables: _RouterTables, ip: str) -> list:
    out = []
    for q in tables.queues:
        if _is_true(q.get("dynamic")):
            continue
        if q.get("name") == static_queue_name(ip):
            out.append(q)
        elif _target_ip(q.get("target")) == ip and str(q.get("comment") or "").startswith(STATIC_COMMENT_PREFIX):
            out.append(q)
    # The canonically named one first so it is the one kept.
    out.sort(key=lambda q: q.get("name") != static_queue_name(ip))
    return out


def _pins_for(tables: _RouterTables, ip: str) -> list:
    return [
        f for f in tables.filters
        if f.get("chain") == "forward"
        and str(f.get("comment") or "").startswith(STATIC_PIN_COMMENT_PREFIX)
        and _target_ip(f.get("src-address")) == ip
    ]


def _pin_mac(rule: dict) -> Optional[str]:
    value = str(rule.get("src-mac-address") or "").strip().lstrip("!").strip()
    return normalize_mac_address(value).upper() if value else None


def _first_static_forward_rule_id(tables: _RouterTables) -> Optional[str]:
    for f in tables.filters:
        if f.get("chain") == "forward" and not _is_true(f.get("dynamic")):
            return f.get(".id")
    return None


def _active_fasttrack_id(tables: _RouterTables) -> Optional[str]:
    for f in tables.filters:
        if (
            f.get("chain") == "forward"
            and f.get("action") == "fasttrack-connection"
            and not _is_true(f.get("disabled"))
        ):
            return f.get(".id")
    return None


def _ensure_shared_rules(api: MikroTikAPI, tables: _RouterTables, changes: list) -> None:
    """Two address-list rules that keep statics out of FastTrack (once per router)."""
    fasttrack_id = _active_fasttrack_id(tables)
    if not fasttrack_id:
        return
    for comment, match in zip(FASTTRACK_BYPASS_COMMENTS, ("src-address-list", "dst-address-list")):
        wanted = {
            "chain": "forward",
            match: STATIC_ADDRESS_LIST,
            "connection-state": "established,related",
            "action": "accept",
            "comment": comment,
        }
        existing = [f for f in tables.filters if f.get("comment") == comment]
        if existing:
            rule = existing[0]
            if _is_true(rule.get("disabled")) or any(rule.get(k) != v for k, v in wanted.items()):
                _ok(api.send_command("/ip/firewall/filter/set", {".id": rule[".id"], **wanted, "disabled": "no"}))
                changes.append(f"fasttrack bypass repaired ({match})")
            order = [f.get(".id") for f in tables.filters]
            if order.index(rule[".id"]) > order.index(fasttrack_id):
                _ok(api.send_command("/ip/firewall/filter/move", {"numbers": rule[".id"], "destination": fasttrack_id}))
                changes.append(f"fasttrack bypass moved ({match})")
            for extra in existing[1:]:
                _removed(api.send_command("/ip/firewall/filter/remove", {"numbers": extra[".id"]}))
            continue
        result = api.send_command("/ip/firewall/filter/add", {**wanted, "place-before": fasttrack_id})
        if _ok(result):
            changes.append(f"fasttrack bypass rule added ({match})")


def _apply_item(api: MikroTikAPI, tables: _RouterTables, item: StaticItem) -> Dict[str, Any]:
    ip = item.ip
    changes: list[str] = []
    out: Dict[str, Any] = {"customer_id": item.customer_id, "ip": ip, "changes": changes}

    if item.old_ip and item.old_ip != ip:
        _remove_item(api, tables, item.old_ip, changes)
    if not item.enabled:
        _remove_static_lb_paid(api, tables, ip, changes)

    out["gateway_ok"] = _gateway_ok(tables, ip)
    observed = _observed_mac(tables, ip)
    out["observed_mac"] = observed

    # --- binding: the access switch ------------------------------------
    comment = _comment(item.customer_id, item.name)
    bindings = _bindings_for(tables, ip)
    for extra in bindings[1:]:
        if _removed(api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": extra[".id"]})):
            changes.append("duplicate binding removed")
    binding = bindings[0] if bindings else None
    want_disabled = "no" if item.enabled else "yes"
    if binding is None:
        if item.enabled:
            result = api.send_command("/ip/hotspot/ip-binding/add", {
                "address": ip, "type": "bypassed", "comment": comment,
            })
            if not _ok(result):
                raise RuntimeError(f"binding add failed: {result.get('error')}")
            changes.append("binding added")
    else:
        current_disabled = "yes" if _is_true(binding.get("disabled")) else "no"
        if (
            binding.get("type") != "bypassed"
            or current_disabled != want_disabled
            or binding.get("comment") != comment
        ):
            result = api.send_command("/ip/hotspot/ip-binding/set", {
                ".id": binding[".id"], "type": "bypassed",
                "disabled": want_disabled, "comment": comment,
            })
            if not _ok(result):
                raise RuntimeError(f"binding set failed: {result.get('error')}")
            if current_disabled != want_disabled:
                changes.append("access enabled" if item.enabled else "access suspended")
            else:
                changes.append("binding updated")
    out["access"] = "enabled" if item.enabled else "suspended"

    if not item.enabled:
        # Drop the bypassed host so its next packet is judged as unpaid.
        for host in tables.hosts:
            if str(host.get("address") or "") == ip and host.get(".id"):
                _removed(api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]}))

    # --- queue: the speed ----------------------------------------------
    queues = _queues_for(tables, ip)
    for extra in queues[1:]:
        if _removed(api.send_command("/queue/simple/remove", {"numbers": extra[".id"]})):
            changes.append(f"duplicate queue {extra.get('name')} removed")
    queue = queues[0] if queues else None
    wanted_queue = {
        "name": static_queue_name(ip),
        "target": f"{ip}/32",
        "max-limit": item.rate_limit,
        "comment": comment,
    }
    if queue is None:
        result = api.send_command("/queue/simple/add", wanted_queue)
        if not _ok(result):
            raise RuntimeError(f"queue add failed: {result.get('error')}")
        changes.append(f"queue added ({item.rate_limit})")
        # Re-read to place it (we need its id and position).
        tables.queues = _rows(api, "/queue/simple/print")
        queue = next((q for q in tables.queues if q.get("name") == wanted_queue["name"]), None)
    else:
        current_limit = parse_speed_to_mikrotik_limit(queue.get("max-limit"))
        if (
            queue.get("name") != wanted_queue["name"]
            or _target_ip(queue.get("target")) != ip
            or current_limit != parse_speed_to_mikrotik_limit(item.rate_limit)
            or queue.get("comment") != comment
            or _is_true(queue.get("disabled"))
        ):
            result = api.send_command("/queue/simple/set", {".id": queue[".id"], **wanted_queue, "disabled": "no"})
            if not _ok(result):
                raise RuntimeError(f"queue set failed: {result.get('error')}")
            changes.append(f"queue updated ({item.rate_limit})")
    if queue is not None:
        _place_queue_above_hotspot_parent(api, tables, queue, changes)
    out["rate_limit"] = item.rate_limit

    # --- address list + FastTrack bypass ---------------------------------
    if not any(str(r.get("address") or "") == ip for r in tables.address_list):
        if _ok(api.send_command("/ip/firewall/address-list/add", {
            "list": STATIC_ADDRESS_LIST, "address": ip, "comment": comment,
        })):
            changes.append("address-list entry added")
    _ensure_shared_rules(api, tables, changes)

    # --- MAC pin ----------------------------------------------------------
    pins = _pins_for(tables, ip)
    router_pin = _pin_mac(pins[0]) if pins else None
    pin_mac = normalize_mac_address(item.mac).upper() if item.mac else None
    if item.clear_pin:
        for rule in pins:
            _removed(api.send_command("/ip/firewall/filter/remove", {"numbers": rule[".id"]}))
        if pins:
            changes.append("MAC pin cleared")
        pins, router_pin = [], None
    elif pin_mac is None and router_pin:
        # Pinned by hand on the router before the app knew: adopt it.
        pin_mac = router_pin
        out["adopted_pin"] = router_pin
    elif pin_mac is None and item.auto_pin and item.enabled and observed:
        pin_mac = observed
        out["learned_pin"] = observed
    if pin_mac:
        keep = None
        for rule in pins:
            if keep is None and _pin_mac(rule) == pin_mac and rule.get("action") == "drop" and not _is_true(rule.get("disabled")):
                keep = rule
                continue
            _removed(api.send_command("/ip/firewall/filter/remove", {"numbers": rule[".id"]}))
            changes.append("stale MAC pin removed")
        if keep is None:
            args = {
                "chain": "forward", "src-address": ip, "src-mac-address": f"!{pin_mac}",
                "action": "drop", "comment": _pin_comment(item.customer_id, item.name),
            }
            first = _first_static_forward_rule_id(tables)
            if first:
                args["place-before"] = first
            result = api.send_command("/ip/firewall/filter/add", args)
            if not _ok(result):
                raise RuntimeError(f"MAC pin add failed: {result.get('error')}")
            changes.append(f"MAC pinned to {pin_mac}")
        else:
            order = [f.get(".id") for f in tables.filters]
            first = next((f.get(".id") for f in tables.filters if f.get("chain") == "forward"
                          and not _is_true(f.get("dynamic"))
                          and not str(f.get("comment") or "").startswith(STATIC_PIN_COMMENT_PREFIX)), None)
            if first and order.index(keep[".id"]) > order.index(first):
                _ok(api.send_command("/ip/firewall/filter/move", {"numbers": keep[".id"], "destination": first}))
                changes.append("MAC pin moved before accept rules")
    out["pinned_mac"] = pin_mac
    out["mac_mismatch"] = bool(pin_mac and observed and observed != pin_mac)
    return out


def parse_speed_to_mikrotik_limit(value: Any) -> str:
    """Compare max-limits by bps: the router prints 10M/7M as 10000000/7000000."""
    parts = []
    for part in str(value or "").split("/"):
        part = part.strip().upper()
        if not part:
            parts.append(0)
            continue
        mult = {"K": 1_000, "M": 1_000_000, "G": 1_000_000_000}.get(part[-1], 1)
        number = part[:-1] if part[-1] in "KMG" else part
        try:
            parts.append(int(float(number) * mult))
        except ValueError:
            parts.append(0)
    return "/".join(str(p) for p in parts)


def _place_queue_above_hotspot_parent(api: MikroTikAPI, tables: _RouterTables, queue: dict, changes: list) -> None:
    """Simple queues match top-down: the hotspot parent queue (target = the whole
    bridge) would otherwise swallow the static IP's traffic before its own queue."""
    order = [q.get(".id") for q in tables.queues]
    parent_ids = [q.get(".id") for q in tables.queues if is_hotspot_parent_queue_name(q.get("name"))]
    if not parent_ids or queue.get(".id") not in order:
        return
    first_parent = min(parent_ids, key=order.index)
    if order.index(queue[".id"]) > order.index(first_parent):
        if _ok(api.send_command("/queue/simple/move", {"numbers": queue[".id"], "destination": first_parent})):
            changes.append("queue moved above hotspot parent queue")
            tables.queues = _rows(api, "/queue/simple/print")


def _remove_static_lb_paid(api: MikroTikAPI, tables: _RouterTables, ip: str, changes: list) -> None:
    # Remove before disabling/removing the bypass: an unpaid host must never
    # retain a routing mark that sends its captive-portal request out a WAN.
    for row in list(tables.lb_paid):
        if row.get("address") == ip:
            if _removed(api.send_command("/ip/firewall/address-list/remove", {"numbers": row[".id"]})):
                tables.lb_paid.remove(row)
                changes.append(f"load-balancing entry for {ip} removed")


def _remove_item(api: MikroTikAPI, tables: _RouterTables, ip: str, changes: list) -> None:
    _remove_static_lb_paid(api, tables, ip, changes)
    for b in _bindings_for(tables, ip):
        if _removed(api.send_command("/ip/hotspot/ip-binding/remove", {"numbers": b[".id"]})):
            changes.append(f"binding for {ip} removed")
    for q in _queues_for(tables, ip):
        if _removed(api.send_command("/queue/simple/remove", {"numbers": q[".id"]})):
            changes.append(f"queue for {ip} removed")
    for rule in _pins_for(tables, ip):
        if _removed(api.send_command("/ip/firewall/filter/remove", {"numbers": rule[".id"]})):
            changes.append(f"MAC pin for {ip} removed")
    for row in tables.address_list:
        if str(row.get("address") or "") == ip:
            _removed(api.send_command("/ip/firewall/address-list/remove", {"numbers": row[".id"]}))
    for host in tables.hosts:
        if str(host.get("address") or "") == ip and host.get(".id"):
            _removed(api.send_command("/ip/hotspot/host/remove", {"numbers": host[".id"]}))


def _connect(router: dict, lane: str) -> MikroTikAPI:
    api = MikroTikAPI(
        router["ip"], router["username"], router["password"], router["port"],
        timeout=20, connect_timeout=5, lane=lane,
    )
    if not api.connect():
        raise ConnectionError(api.last_connect_error or "Failed to connect to router")
    return api


def apply_static_items_sync(router: dict, items: List[StaticItem], lane: str = LANE_DEFAULT) -> Dict[str, Any]:
    """Make the router match ``items``; one connection, tables read once."""
    try:
        api = _connect(router, lane)
    except Exception as exc:
        return {"error": str(exc), "connected": False, "results": []}
    results = []
    try:
        tables = _read_tables(api)
        for item in items:
            try:
                results.append({"success": True, **_apply_item(api, tables, item)})
            except Exception as exc:
                logger.error("[STATIC-IP] apply %s on %s failed: %s", item.ip, router.get("name"), exc)
                results.append({"success": False, "customer_id": item.customer_id, "ip": item.ip, "error": str(exc)})
            # Later items must see what earlier ones changed (shared rules, order).
            tables.filters = _rows(api, "/ip/firewall/filter/print")
            tables.address_list = [
                r for r in _rows(api, "/ip/firewall/address-list/print") if r.get("list") == STATIC_ADDRESS_LIST
            ]
        return {"success": True, "connected": True, "results": results}
    except Exception as exc:
        return {"error": str(exc), "connected": True, "results": results}
    finally:
        api.disconnect()


def remove_static_ip_sync(router: dict, ip: str) -> Dict[str, Any]:
    try:
        api = _connect(router, LANE_DEFAULT)
    except Exception as exc:
        return {"error": str(exc)}
    try:
        changes: list[str] = []
        _remove_item(api, _read_tables(api), ip, changes)
        return {"success": True, "changes": changes}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        api.disconnect()


def inspect_static_ip_sync(router: dict, ip: str) -> Dict[str, Any]:
    """Read-only view of everything the router has for ``ip``."""
    try:
        api = _connect(router, LANE_DEFAULT)
    except Exception as exc:
        return {"error": str(exc), "reachable": False}
    try:
        tables = _read_tables(api)
        bindings = _bindings_for(tables, ip)
        queues = _queues_for(tables, ip)
        pins = _pins_for(tables, ip)
        hosts = [h for h in tables.hosts if str(h.get("address") or "") == ip]
        queue = queues[0] if queues else None
        order = [q.get(".id") for q in tables.queues]
        parent_ids = [q.get(".id") for q in tables.queues if is_hotspot_parent_queue_name(q.get("name"))]
        shadowed = bool(
            queue and parent_ids and queue.get(".id") in order
            and order.index(queue[".id"]) > min(order.index(p) for p in parent_ids)
        )
        return {
            "success": True,
            "reachable": True,
            "gateway_ok": _gateway_ok(tables, ip),
            "binding": None if not bindings else {
                "enabled": not _is_true(bindings[0].get("disabled")),
                "type": bindings[0].get("type"),
                "comment": bindings[0].get("comment"),
            },
            "queue": None if not queue else {
                "name": queue.get("name"),
                "max_limit": queue.get("max-limit"),
                "rate": queue.get("rate"),
                "bytes": queue.get("bytes"),
                "disabled": _is_true(queue.get("disabled")),
                "shadowed": shadowed,
            },
            "pinned_mac": _pin_mac(pins[0]) if pins else None,
            "pin_hits": sum(int(p.get("packets") or 0) for p in pins),
            "observed_mac": _observed_mac(tables, ip),
            "host": None if not hosts else {
                "mac": hosts[0].get("mac-address"),
                "bypassed": _is_true(hosts[0].get("bypassed")),
                "idle_time": hosts[0].get("idle-time"),
                "uptime": hosts[0].get("uptime"),
                "bytes_in": hosts[0].get("bytes-in"),
                "bytes_out": hosts[0].get("bytes-out"),
            },
        }
    except Exception as exc:
        return {"error": str(exc), "reachable": True}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Async orchestration
# ---------------------------------------------------------------------------

def _router_dict(router: Router) -> dict:
    return {
        "id": router.id, "name": router.name, "ip": router.ip_address,
        "username": router.username, "password": router.password, "port": router.port or 8728,
    }


def _item_for(customer: Customer, now: datetime, **overrides) -> Optional[StaticItem]:
    ip = normalize_static_ip(customer.static_ip)
    if not ip or customer.plan is None:
        return None
    item = StaticItem(
        customer_id=customer.id,
        name=customer.name or "",
        ip=ip,
        rate_limit=static_rate_limit(customer.plan.speed),
        enabled=customer_should_have_access(customer, now),
        mac=customer.static_mac,
    )
    for key, value in overrides.items():
        setattr(item, key, value)
    return item


async def _run(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(_static_pool, fn, *args)


async def _load_customer(customer_id: int) -> Optional[Customer]:
    async with db_module.async_session() as db:
        customer = (
            await db.execute(
                select(Customer)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .where(Customer.id == customer_id)
            )
        ).scalar_one_or_none()
        await db.commit()
        return customer


async def _persist_apply_results(
    router_id: int,
    results: Iterable[dict],
    action: str,
    *,
    customer_rows: Optional[dict[int, Customer]] = None,
) -> None:
    """Save learned/adopted pins and write provisioning logs, each in short sessions."""
    from app.services.customer_events import record_customer_event
    from app.services.hotspot_provisioning import log_provisioning_event

    for res in results:
        cid = res.get("customer_id")
        if cid is None:
            continue
        new_pin = res.get("learned_pin") or res.get("adopted_pin")
        if new_pin:
            async with db_module.async_session() as db:
                customer = await db.get(Customer, cid)
                if customer is not None and not customer.static_mac:
                    customer.static_mac = new_pin
                await db.commit()
            await record_customer_event(
                cid, "static_mac_pinned",
                f"Static IP {res.get('ip')} pinned to device {new_pin}"
                + (" (adopted from the router)" if res.get("adopted_pin") else " (first device seen)"),
                source="system", router_id=router_id,
            )
        if res.get("mac_mismatch"):
            observed = res.get("observed_mac") or ""
            if _reported_mismatch.get(cid) != observed:
                _reported_mismatch[cid] = observed
                await record_customer_event(
                    cid, "static_mac_mismatch",
                    f"A different device ({observed}) is using static IP {res.get('ip')}, which is pinned "
                    f"to {res.get('pinned_mac')}. Its traffic is blocked. If the customer replaced their "
                    "router, reset the pin.",
                    severity="warning", source="system", router_id=router_id,
                )
        changes = res.get("changes") or []
        if changes or not res.get("success"):
            await log_provisioning_event(
                cid, router_id, None, action,
                "success" if res.get("success") else "failed",
                details="; ".join(changes)[:500] if changes else None,
                error=res.get("error"),
            )


async def provision_static_customer(
    customer_id: int,
    *,
    action: str = "static_ip_sync",
    lane: str = LANE_DEFAULT,
    clear_pin: bool = False,
    old_ip: Optional[str] = None,
    old_router: Optional[dict] = None,
    force_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Make the router match the DB for one customer. Never holds a session over I/O.

    ``force_enabled=False`` suspends regardless of the DB (manual suspend runs
    the router step first and only then flips the status).
    """
    customer = await _load_customer(customer_id)
    if customer is None:
        return {"error": "Customer not found"}
    if not is_static_customer(customer):
        return {"error": "Customer is not on a static-IP plan"}
    if customer.router is None:
        return {"error": "Customer has no router"}
    item = _item_for(customer, datetime.utcnow(), clear_pin=clear_pin)
    if item is None:
        return {"error": "Customer has no valid static IP"}
    if force_enabled is not None:
        item.enabled = force_enabled
    if clear_pin:
        item.mac = None

    if old_router and old_ip:
        # Moved to another router: clean the old one first.
        removed = await _run(remove_static_ip_sync, old_router, old_ip)
        if not removed.get("success"):
            return {"error": "Old router cleanup failed: " + str(removed.get("error"))}
    elif old_ip and old_ip != item.ip:
        item.old_ip = old_ip

    router = _router_dict(customer.router)
    outcome = await _run(apply_static_items_sync, router, [item], lane)
    results = outcome.get("results") or []
    if outcome.get("error") and not results:
        await _persist_apply_results(router["id"], [{
            "customer_id": customer_id, "success": False, "error": outcome["error"], "ip": item.ip,
        }], action)
        return {"error": outcome["error"], "connected": outcome.get("connected", False)}
    await _persist_apply_results(router["id"], results, action)
    return results[0] if results else {"error": outcome.get("error") or "No result"}


async def remove_static_customer_from_router(router: dict, ip: str) -> Dict[str, Any]:
    return await _run(remove_static_ip_sync, router, ip)


async def inspect_static_customer(customer_id: int) -> Dict[str, Any]:
    customer = await _load_customer(customer_id)
    if customer is None or customer.router is None:
        return {"error": "Customer or router not found"}
    ip = normalize_static_ip(customer.static_ip)
    if not ip:
        return {"error": "Customer has no valid static IP"}
    return await _run(inspect_static_ip_sync, _router_dict(customer.router), ip)


def schedule_static_provision(customer_id: int, action: str = "static_ip_activation") -> None:
    """Fire-and-forget provisioning after a payment has been committed.

    Payment paths call this after their own commit. A failure here is not
    lost: the enforcement job re-applies every static customer's desired state
    on its next full pass.
    """
    async def _go():
        try:
            result = await provision_static_customer(customer_id, action=action, lane=LANE_PAYMENT)
            if result.get("error"):
                logger.warning("[STATIC-IP] provisioning customer %s failed: %s", customer_id, result["error"])
        except Exception:
            logger.exception("[STATIC-IP] provisioning customer %s crashed", customer_id)

    try:
        task = asyncio.get_running_loop().create_task(_go())
    except RuntimeError:
        logger.error("[STATIC-IP] no running loop to provision customer %s", customer_id)
        return
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


# ---------------------------------------------------------------------------
# Background enforcement
# ---------------------------------------------------------------------------

async def _load_static_customers() -> list[Customer]:
    async with db_module.async_session() as db:
        rows = (
            await db.execute(
                select(Customer)
                .join(Plan, Plan.id == Customer.plan_id)
                .options(selectinload(Customer.plan), selectinload(Customer.router))
                .where(
                    Plan.connection_type == ConnectionType.STATIC_IP,
                    Customer.static_ip.isnot(None),
                    Customer.router_id.isnot(None),
                )
            )
        ).scalars().all()
        await db.commit()
        return list(rows)


async def _mark_suspended(customer_ids: list[int], router_id: int, now: datetime) -> list[int]:
    """Flip confirmed-suspended customers INACTIVE unless they renewed meanwhile."""
    from app.services.customer_events import record_customer_event

    done: list[int] = []
    renewed: list[int] = []
    async with db_module.async_session() as db:
        for cid in customer_ids:
            customer = await db.get(Customer, cid)
            if customer is None:
                continue
            if customer_should_have_access(customer, datetime.utcnow()):
                renewed.append(cid)
                continue
            if customer.status == CustomerStatus.ACTIVE:
                customer.status = CustomerStatus.INACTIVE
                db.add(ProvisioningLog(
                    customer_id=cid, router_id=router_id, action="static_ip_deactivation",
                    status="success", details="Expiry: static-IP access suspended on the router",
                ))
                done.append(cid)
        await db.commit()
    for cid in renewed:
        # A payment raced the router suspension. Repair it now, rather than
        # leaving a paid customer offline until the next full reconciliation.
        await provision_static_customer(cid, action="static_ip_renewal_repair", lane=LANE_PAYMENT)
    for cid in done:
        await record_customer_event(
            cid, "static_ip_expired",
            "Plan expired: static-IP access suspended on the router (device now sees the payment page)",
            source="system", router_id=router_id,
        )
    return done


async def enforce_static_ip_customers_background() -> dict:
    """Suspend expired statics now; repair drift and learn MACs every 10 min per router."""
    global enforce_running
    if enforce_running:
        return {"skipped": "running"}
    from app.services.mikrotik_background import _background_db_pool_is_busy, _router_recently_offline

    if _background_db_pool_is_busy("STATIC-IP"):
        return {"skipped": "db_busy"}
    enforce_running = True
    summary = {"routers": 0, "applied": 0, "suspended": 0, "failed": 0}
    try:
        now = datetime.utcnow()
        customers = await _load_static_customers()
        by_router: dict[int, list[Customer]] = {}
        routers: dict[int, Router] = {}
        for customer in customers:
            by_router.setdefault(customer.router_id, []).append(customer)
            routers[customer.router_id] = customer.router

        async def _one(router_id: int, rows: list[Customer]):
            router = routers[router_id]
            if router is None or _router_recently_offline(router, now):
                return
            expired = [
                c for c in rows
                if c.status == CustomerStatus.ACTIVE and c.expiry is not None
                and not has_access_time(c, now)
            ]
            last = _last_full_reconcile.get(router_id)
            full = last is None or (now - last).total_seconds() >= FULL_RECONCILE_SECONDS
            targets = rows if full else expired
            if not targets:
                return
            items = [item for c in targets if (item := _item_for(c, now)) is not None]
            if not items:
                return
            outcome = await _run(apply_static_items_sync, _router_dict(router), items, LANE_BACKGROUND)
            results = outcome.get("results") or []
            if outcome.get("error") and not results:
                summary["failed"] += len(items)
                logger.warning("[STATIC-IP] router %s unreachable: %s", router.name, outcome["error"])
                return
            if full and all(r.get("success") for r in results) and len(results) == len(items):
                _last_full_reconcile[router_id] = now
            summary["routers"] += 1
            summary["applied"] += sum(1 for r in results if r.get("success"))
            summary["failed"] += sum(1 for r in results if not r.get("success"))
            await _persist_apply_results(router_id, results, "static_ip_reconcile")
            expired_ids = {c.id for c in expired}
            confirmed = [
                r["customer_id"] for r in results
                if r.get("success") and r.get("customer_id") in expired_ids and r.get("access") == "suspended"
            ]
            if confirmed:
                summary["suspended"] += len(await _mark_suspended(confirmed, router_id, now))

        await asyncio.gather(
            *[_one(rid, rows) for rid, rows in by_router.items()],
            return_exceptions=True,
        )
        if summary["applied"] or summary["failed"] or summary["suspended"]:
            logger.info("[STATIC-IP] enforcement: %s", summary)
        return summary
    finally:
        enforce_running = False

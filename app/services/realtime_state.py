"""Live router and device state for the real-time push pilot.

Routers on the pilot report every few seconds. The durable facts in those
reports (usage bytes) go to the database through the normal usage path. The
rest is gauges — current speed, online right now, CPU, which queue is actually
limiting a device — and gauges are only useful while they are fresh. They live
here, in process memory:

* The app runs one worker, so there is exactly one copy.
* A restart loses nothing that matters: the next report (seconds away) refills it.
* Nothing is written per report, so reporting every few seconds costs the
  database nothing beyond the usage rows it already writes.

Rates are computed here from consecutive cumulative counters, not read from the
router, so the router does no extra work for them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Optional

from app.config import settings
from app.services.mikrotik_api import normalize_mac_address


def pilot_router_ids() -> frozenset[int]:
    ids = set()
    for part in str(settings.REALTIME_PILOT_ROUTER_IDS or "").split(","):
        part = part.strip()
        if part.isdigit():
            ids.add(int(part))
    return frozenset(ids)


def is_pilot_router(router_id: Optional[int]) -> bool:
    return router_id is not None and router_id in pilot_router_ids()


def pilot_push_interval_seconds(router_id: Optional[int] = None, via_tunnel: bool = False) -> int:
    """Cadence to hand back to a pilot router on its next report.

    Base (or the router's HTTPS override), then backed off on the router's own
    last reported CPU: a busy small board is not made busier by reporting more
    often. Overrides exist because of TLS cost, so a report that came through
    the management tunnel (no TLS on the router) is not held to them.
    """
    base = int(settings.REALTIME_PUSH_INTERVAL_SECONDS or 10)
    for part in ("" if via_tunnel else str(settings.REALTIME_PUSH_INTERVAL_OVERRIDES or "")).split(","):
        rid, _, secs = part.strip().partition(":")
        if rid.isdigit() and secs.isdigit() and router_id is not None and int(rid) == router_id:
            base = int(secs)
    state = _routers.get(router_id) if router_id is not None else None
    if state is not None and state.backoff_seconds:
        base = max(base, state.backoff_seconds)
    return max(5, min(3600, base))


# Once a router reports high CPU it stays backed off this long. The script
# samples CPU at the start of its run, sometimes in a quiet moment; without
# this the cadence flip-flopped 30 s <-> 60 s on every report.
CPU_BACKOFF_HOLD = timedelta(minutes=10)


def _cpu_backoff_seconds(cpu: Optional[int]) -> int:
    if cpu is not None and cpu >= CPU_BACKOFF_HEAVY_PERCENT:
        return 120
    return 0


CPU_BACKOFF_HEAVY_PERCENT = 80

# How long after its last v2 report a pilot router still counts as metered by
# the push. Past this (router offline, script removed) the bandwidth poller
# and cap sampler take it back, so usage is never left uncollected.
# Several report intervals (60 s, or 120 s for small boards on HTTPS), so one
# late report does not hand the router back to the poller and count it twice.
HOST_METERING_FRESH_SECONDS = 360


def host_metering_active(router_id: Optional[int], now: Optional[datetime] = None) -> bool:
    """True while a pilot router's usage is being metered from its v2 push."""
    if not is_pilot_router(router_id):
        return False
    state = _routers.get(router_id)
    if state is None or not state.has_hosts:
        return False
    now = now or datetime.utcnow()
    return (now - state.received_at).total_seconds() <= HOST_METERING_FRESH_SECONDS


def host_metered_router_ids(now: Optional[datetime] = None) -> list[int]:
    return [rid for rid in pilot_router_ids() if host_metering_active(rid, now)]


# Queue status for a live customer, from the router's own queue list.
QUEUE_OK = "ok"                 # their own queue is the one matching their IP
QUEUE_SHADOWED = "shadowed"     # another queue above theirs takes their traffic
QUEUE_NO_LIMIT = "no_limit"     # online but no enabled queue matches their IP
QUEUE_OFFLINE = "offline"       # not on the router right now


@dataclass
class HostSample:
    mac: str
    ip: str
    bytes_in: int
    bytes_out: int
    bypassed: bool = False
    authorized: bool = False
    idle_time: str = ""
    uptime: str = ""


@dataclass
class PppSample:
    name: str
    address: str
    uptime: str = ""
    caller_id: str = ""


@dataclass
class QueueSample:
    key: str            # canonical MAC (upper, colons) or pppoe:<user>
    target_ip: str
    max_limit: str
    disabled: bool
    upload_bytes: int
    download_bytes: int


@dataclass
class DeviceLive:
    mac: str                        # MAC for hotspot, "pppoe:<user>" for PPPoE
    customer_id: Optional[int]
    ip: str
    online: bool
    bytes_in: int
    bytes_out: int
    rate_up_bps: Optional[float]
    rate_down_bps: Optional[float]
    seen_at: datetime
    idle_time: str
    uptime: str
    queue_status: str
    limited_by: Optional[str]       # key of the queue that actually matches
    max_limit: Optional[str]        # max-limit of that queue
    kind: str = "hotspot"           # "hotspot" | "pppoe"


@dataclass
class RouterLive:
    router_id: int
    received_at: datetime
    interval_seconds: int
    pushes: int = 0
    cpu_load: Optional[int] = None
    free_memory: Optional[int] = None
    total_memory: Optional[int] = None
    uptime: str = ""
    version: str = ""
    board: str = ""
    wan_rx_bytes: Optional[int] = None
    wan_tx_bytes: Optional[int] = None
    wan_rx_bps: Optional[float] = None
    wan_tx_bps: Optional[float] = None
    hotspot_active: int = 0
    pppoe_active: int = 0
    queue_count: int = 0
    devices: dict[str, DeviceLive] = field(default_factory=dict)
    orphan_queues: int = 0
    shadowed: int = 0
    no_limit: int = 0
    last_repair_at: Optional[datetime] = None
    last_repair_result: Optional[dict] = None
    problem_signature: tuple = ()
    has_hosts: bool = False         # report carried a hosts[] list (v2 metering)
    backoff_seconds: int = 0        # CPU back-off in force (sticky, see CPU_BACKOFF_HOLD)
    backoff_until: Optional[datetime] = None
    # v3: ports every report; the long lists every ~5 reports, kept until the
    # next one arrives (with the time they were read).
    ports: list = field(default_factory=list)
    bridge_hosts: Optional[dict] = None       # MAC -> port name
    bridge_hosts_at: Optional[datetime] = None
    bindings: Optional[list] = None           # [{"mac", "type", "disabled"}]
    bindings_at: Optional[datetime] = None
    leases: Optional[list] = None             # [{"mac", "ip", "host", "status", "comment"}]
    neighbors: Optional[list] = None          # /ip neighbor rows (equipment detection)
    bridge_ports: Optional[list] = None       # [{"interface", "bridge"}]
    hosts_raw: list = field(default_factory=list)   # this report's hotspot hosts, as sent
    ppp_raw: list = field(default_factory=list)     # this report's /ppp active, as sent
    free_hdd: Optional[int] = None
    total_hdd: Optional[int] = None


_routers: dict[int, RouterLive] = {}

# Every router's last accepted push that carried a router-metrics block (v1
# with metrics or v2), pilot or not. Lets polling jobs stand down for routers
# that already report what they would fetch.
_last_metrics_report: dict[int, datetime] = {}
METRICS_REPORT_FRESH_SECONDS = 360


def note_metrics_report(router_id: int, now: Optional[datetime] = None) -> None:
    _last_metrics_report[router_id] = now or datetime.utcnow()


def reports_metrics(router_id: Optional[int], now: Optional[datetime] = None) -> bool:
    """True while this router pushes interface counters + session counts itself."""
    seen = _last_metrics_report.get(router_id) if router_id is not None else None
    if seen is None:
        return False
    now = now or datetime.utcnow()
    return (now - seen).total_seconds() <= METRICS_REPORT_FRESH_SECONDS


def reset_realtime_state() -> None:
    """Test hook."""
    _routers.clear()
    _last_metrics_report.clear()


def get_router_live(router_id: int) -> Optional[RouterLive]:
    return _routers.get(router_id)


def get_device_live(router_id: Optional[int], mac: Optional[str]) -> Optional[DeviceLive]:
    if router_id is None or not mac:
        return None
    state = _routers.get(router_id)
    if state is None:
        return None
    return state.devices.get(normalize_mac_address(mac).upper())


def get_pppoe_live(router_id: Optional[int], username: Optional[str]) -> Optional[DeviceLive]:
    if router_id is None or not username:
        return None
    state = _routers.get(router_id)
    return state.devices.get(f"pppoe:{username}") if state else None


def _rate(prev: Optional[int], cur: int, seconds: float) -> Optional[float]:
    if prev is None or seconds <= 0 or cur < prev:
        # First sighting, or the counter reset (host re-created, reboot):
        # no honest rate for this window.
        return None
    return (cur - prev) * 8 / seconds


def _effective_queue(queues: list[QueueSample], ip: str) -> Optional[QueueSample]:
    """The queue RouterOS applies to ``ip``: first enabled match, top-down."""
    for queue in queues:
        if not queue.disabled and queue.target_ip == ip:
            return queue
    return None


def record_push(
    router_id: int,
    *,
    now: datetime,
    interval_seconds: int,
    hosts: Iterable[HostSample],
    queues: list[QueueSample],
    live_customers: dict[str, int],
    metrics: Optional[dict] = None,
    ppp_sessions: Iterable[PppSample] = (),
    live_pppoe_customers: Optional[dict[str, int]] = None,
    has_hosts: bool = False,
    ports: Optional[list] = None,
    bridge_hosts: Optional[list] = None,
    bindings: Optional[list] = None,
    leases: Optional[list] = None,
    bridge_ports: Optional[list] = None,
    neighbors: Optional[list] = None,
    hosts_raw: Optional[list] = None,
    ppp_raw: Optional[list] = None,
) -> RouterLive:
    """Fold one report into the live state and return the router's entry.

    ``live_customers`` maps canonical hotspot MAC -> customer id for customers
    whose plan is live on this router. ``queues`` must be in router order.
    """
    prev = _routers.get(router_id)
    elapsed = (now - prev.received_at).total_seconds() if prev else 0.0
    state = RouterLive(router_id=router_id, received_at=now, interval_seconds=interval_seconds)
    state.has_hosts = has_hosts
    _fold_v3_lists(state, prev, now, ports, bridge_hosts, bindings)
    state.hosts_raw = list(hosts_raw or [])
    state.ppp_raw = list(ppp_raw or [])
    if leases is not None:
        state.leases = list(leases)
    elif prev is not None:
        state.leases = prev.leases
    if bridge_ports is not None:
        state.bridge_ports = list(bridge_ports)
    elif prev is not None:
        state.bridge_ports = prev.bridge_ports
    if neighbors is not None:
        state.neighbors = list(neighbors)
    elif prev is not None:
        state.neighbors = prev.neighbors
    state.pushes = (prev.pushes if prev else 0) + 1
    if prev:
        state.last_repair_at = prev.last_repair_at
        state.last_repair_result = prev.last_repair_result
        state.problem_signature = prev.problem_signature

    metrics = metrics or {}
    for name in ("cpu_load", "free_memory", "total_memory", "hotspot_active", "pppoe_active", "queue_count",
                 "free_hdd", "total_hdd"):
        value = metrics.get(name)
        if value is not None:
            setattr(state, name, int(value))
    for name in ("uptime", "version", "board"):
        if metrics.get(name):
            setattr(state, name, str(metrics[name])[:64])
    wanted = _cpu_backoff_seconds(state.cpu_load)
    held = prev.backoff_seconds if (prev and prev.backoff_until and prev.backoff_until > now) else 0
    if wanted and wanted >= held:
        state.backoff_seconds, state.backoff_until = wanted, now + CPU_BACKOFF_HOLD
    elif held:
        state.backoff_seconds, state.backoff_until = held, prev.backoff_until

    rx, tx = metrics.get("iface_rx_bytes"), metrics.get("iface_tx_bytes")
    if rx is not None and tx is not None:
        state.wan_rx_bytes, state.wan_tx_bytes = int(rx), int(tx)
        if prev and prev.wan_rx_bytes is not None:
            state.wan_rx_bps = _rate(prev.wan_rx_bytes, state.wan_rx_bytes, elapsed)
            state.wan_tx_bps = _rate(prev.wan_tx_bytes, state.wan_tx_bytes, elapsed)

    seen = set()
    for host in hosts:
        mac = normalize_mac_address(host.mac).upper()
        customer_id = live_customers.get(mac)
        if customer_id is None:
            continue  # unpaid devices at the portal are not ours to show
        seen.add(mac)
        before = prev.devices.get(mac) if prev else None
        continuous = before is not None and before.online
        effective = _effective_queue(queues, host.ip)
        if effective is None:
            status = QUEUE_NO_LIMIT
        elif effective.key == mac:
            status = QUEUE_OK
        else:
            status = QUEUE_SHADOWED
        state.devices[mac] = DeviceLive(
            mac=mac,
            customer_id=customer_id,
            ip=host.ip,
            online=True,
            bytes_in=host.bytes_in,
            bytes_out=host.bytes_out,
            rate_up_bps=_rate(before.bytes_in if continuous else None, host.bytes_in, elapsed),
            rate_down_bps=_rate(before.bytes_out if continuous else None, host.bytes_out, elapsed),
            seen_at=now,
            idle_time=host.idle_time,
            uptime=host.uptime,
            queue_status=status,
            limited_by=effective.key if effective else None,
            max_limit=effective.max_limit if effective else None,
        )

    for mac, customer_id in live_customers.items():
        if mac in seen:
            continue
        before = prev.devices.get(mac) if prev else None
        state.devices[mac] = DeviceLive(
            mac=mac,
            customer_id=customer_id,
            ip=before.ip if before else "",
            online=False,
            bytes_in=0,
            bytes_out=0,
            rate_up_bps=None,
            rate_down_bps=None,
            seen_at=before.seen_at if before else now,
            idle_time="",
            uptime="",
            queue_status=QUEUE_OFFLINE,
            limited_by=None,
            max_limit=None,
        )

    # PPPoE: a session is online when it is in /ppp active; its dynamic queue
    # <pppoe-USER> carries the session's counters (and its speed limit).
    sessions = {f"pppoe:{p.name}": p for p in ppp_sessions}
    queue_by_key = {q.key: q for q in queues}
    for key, customer_id in (live_pppoe_customers or {}).items():
        session = sessions.get(key)
        queue = queue_by_key.get(key)
        before = prev.devices.get(key) if prev else None
        online = session is not None
        continuous = online and before is not None and before.online
        up = queue.upload_bytes if queue else 0
        down = queue.download_bytes if queue else 0
        if not online:
            status = QUEUE_OFFLINE
        elif queue is None or queue.disabled:
            status = QUEUE_NO_LIMIT
        else:
            status = QUEUE_OK
        state.devices[key] = DeviceLive(
            mac=key,
            customer_id=customer_id,
            ip=session.address if session else (before.ip if before else ""),
            online=online,
            bytes_in=up if online else 0,
            bytes_out=down if online else 0,
            rate_up_bps=_rate(before.bytes_in if continuous else None, up, elapsed) if online else None,
            rate_down_bps=_rate(before.bytes_out if continuous else None, down, elapsed) if online else None,
            seen_at=now if online else (before.seen_at if before else now),
            idle_time="",
            uptime=session.uptime if session else "",
            queue_status=status,
            limited_by=key if (online and queue and not queue.disabled) else None,
            max_limit=queue.max_limit if (online and queue) else None,
            kind="pppoe",
        )

    state.orphan_queues = sum(
        1 for q in queues if not q.key.startswith("pppoe:") and q.key not in live_customers
    )
    state.shadowed = sum(1 for d in state.devices.values() if d.queue_status == QUEUE_SHADOWED)
    state.no_limit = sum(1 for d in state.devices.values() if d.queue_status == QUEUE_NO_LIMIT)
    _routers[router_id] = state
    return state


def _fold_v3_lists(state, prev, now, ports, bridge_hosts, bindings) -> None:
    elapsed = (now - prev.received_at).total_seconds() if prev else 0.0
    prev_ports = {p["name"]: p for p in (prev.ports if prev else [])}
    for port in ports or []:
        before = prev_ports.get(port["name"])
        state.ports.append({
            **port,
            "rx_bps": _rate(before["rx_bytes"] if before else None, port["rx_bytes"], elapsed),
            "tx_bps": _rate(before["tx_bytes"] if before else None, port["tx_bytes"], elapsed),
        })
    if bridge_hosts is not None:
        state.bridge_hosts = {
            normalize_mac_address(h["mac"]).upper(): h["port"] for h in bridge_hosts if h.get("mac")
        }
        state.bridge_hosts_at = now
    elif prev is not None:
        state.bridge_hosts, state.bridge_hosts_at = prev.bridge_hosts, prev.bridge_hosts_at
    if bindings is not None:
        state.bindings, state.bindings_at = list(bindings), now
    elif prev is not None:
        state.bindings, state.bindings_at = prev.bindings, prev.bindings_at


# How old a pushed long list may be and still replace a RouterOS read. The
# router sends them every ~5 reports (~5 min at 60 s).
PUSHED_LIST_MAX_AGE_SECONDS = 900


def pushed_bridge_host_map(router_id: Optional[int], now: Optional[datetime] = None) -> Optional[dict]:
    """MAC -> port from the router's own report, or None if absent/stale."""
    state = _routers.get(router_id) if router_id is not None else None
    if state is None or state.bridge_hosts is None or state.bridge_hosts_at is None:
        return None
    now = now or datetime.utcnow()
    if (now - state.bridge_hosts_at).total_seconds() > PUSHED_LIST_MAX_AGE_SECONDS:
        return None
    return state.bridge_hosts


def pushed_bindings(router_id: Optional[int], now: Optional[datetime] = None) -> Optional[list]:
    """The router's ip-bindings from its own report, or None if absent/stale."""
    state = _routers.get(router_id) if router_id is not None else None
    if state is None or state.bindings is None or state.bindings_at is None:
        return None
    now = now or datetime.utcnow()
    if (now - state.bindings_at).total_seconds() > PUSHED_LIST_MAX_AGE_SECONDS:
        return None
    return state.bindings


# A repair when the set of problems changes, soon; when the same problems
# persist (e.g. a queue for a device with a manual binding, which the repair
# deliberately keeps), at most this often.
REPAIR_COOLDOWN_SECONDS = 30
REPAIR_PERSISTENT_PROBLEM_SECONDS = 300


def repair_due(state: RouterLive, now: datetime) -> bool:
    signature = tuple(sorted(
        [f"orphans:{state.orphan_queues}"]
        + [f"{d.mac}:{d.queue_status}" for d in state.devices.values()
           if d.queue_status in (QUEUE_SHADOWED, QUEUE_NO_LIMIT)]
    ))
    has_problem = state.orphan_queues or state.shadowed or state.no_limit
    if not has_problem:
        state.problem_signature = ()
        return False
    since = (now - state.last_repair_at).total_seconds() if state.last_repair_at else None
    changed = signature != state.problem_signature
    state.problem_signature = signature
    if since is None:
        return True
    if changed:
        return since >= REPAIR_COOLDOWN_SECONDS
    return since >= REPAIR_PERSISTENT_PROBLEM_SECONDS


def note_repair(router_id: int, at: datetime, result: Optional[dict]) -> None:
    state = _routers.get(router_id)
    if state is not None:
        state.last_repair_at = at
        state.last_repair_result = result

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
from datetime import datetime
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


def pilot_push_interval_seconds() -> int:
    return max(5, min(3600, int(settings.REALTIME_PUSH_INTERVAL_SECONDS or 10)))


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
class QueueSample:
    key: str            # canonical MAC (upper, colons) or pppoe:<user>
    target_ip: str
    max_limit: str
    disabled: bool
    upload_bytes: int
    download_bytes: int


@dataclass
class DeviceLive:
    mac: str
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


_routers: dict[int, RouterLive] = {}


def reset_realtime_state() -> None:
    """Test hook."""
    _routers.clear()


def get_router_live(router_id: int) -> Optional[RouterLive]:
    return _routers.get(router_id)


def get_device_live(router_id: Optional[int], mac: Optional[str]) -> Optional[DeviceLive]:
    if router_id is None or not mac:
        return None
    state = _routers.get(router_id)
    if state is None:
        return None
    return state.devices.get(normalize_mac_address(mac).upper())


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
) -> RouterLive:
    """Fold one report into the live state and return the router's entry.

    ``live_customers`` maps canonical hotspot MAC -> customer id for customers
    whose plan is live on this router. ``queues`` must be in router order.
    """
    prev = _routers.get(router_id)
    elapsed = (now - prev.received_at).total_seconds() if prev else 0.0
    state = RouterLive(router_id=router_id, received_at=now, interval_seconds=interval_seconds)
    state.pushes = (prev.pushes if prev else 0) + 1
    if prev:
        state.last_repair_at = prev.last_repair_at
        state.last_repair_result = prev.last_repair_result
        state.problem_signature = prev.problem_signature

    metrics = metrics or {}
    for name in ("cpu_load", "free_memory", "total_memory", "hotspot_active", "pppoe_active", "queue_count"):
        value = metrics.get(name)
        if value is not None:
            setattr(state, name, int(value))
    for name in ("uptime", "version", "board"):
        if metrics.get(name):
            setattr(state, name, str(metrics[name])[:64])
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

    state.orphan_queues = sum(
        1 for q in queues if not q.key.startswith("pppoe:") and q.key not in live_customers
    )
    state.shadowed = sum(1 for d in state.devices.values() if d.queue_status == QUEUE_SHADOWED)
    state.no_limit = sum(1 for d in state.devices.values() if d.queue_status == QUEUE_NO_LIMIT)
    _routers[router_id] = state
    return state


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

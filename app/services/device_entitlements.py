"""Which hotspot purchase belongs to which device, for reconnects.

A hotspot purchase (one ``customers`` row) is bound to the device it was bought
on. One phone number may hold several single-device purchases at once, one per
device in the house, and all of them must work at the same time. Reconnecting
(by phone number or by code) from device X therefore:

1. restores the purchase already bound to X, if there is one;
2. else may move a purchase whose device is not in use, so a phone whose MAC
   rotated, or a customer who changed phones, still gets back online;
3. else refuses: a purchase is never taken from a device that is in use.

"In use" depends on the kind of MAC the purchase is bound to:

* Randomized (locally administered) MAC, i.e. a phone with private Wi-Fi
  addressing, the default on Android 10+ and iOS 14+. Such a phone gets a NEW
  MAC when it rotates, and its old MAC was naturally in use until a moment
  ago, so recent traffic proves nothing. Only "on the router right now"
  counts: a hotspot host/session for the old MAC with traffic in the last
  ``LIVE_ONLINE_IDLE_SECONDS``, or a fresh real-time push showing it online.
* Vendor (universally administered) MAC: a TV, decoder, laptop, console or a
  phone with private addressing off. These never change MAC, so a different MAC
  asking for the purchase is a different device. It is in use if it was seen
  within ``FIXED_DEVICE_RECENT_WINDOW`` (usage credited, provisioned, or
  reconnected), which covers a TV switched off overnight or during the working
  day. After a full day unseen, the device is treated as gone or replaced.

The MAC kind is only a heuristic for "could this be the same device?"; it never
locks out a phone whose randomized MAC rotated, which is the common recovery.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Customer,
    CustomerUsageBucket,
    ProvisioningAttempt,
    ReconnectionAttempt,
)
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

# A fixed-MAC device seen this recently still owns its purchase.
FIXED_DEVICE_RECENT_WINDOW = timedelta(hours=24)
# A hotspot host/session with traffic this recent is on the router right now.
LIVE_ONLINE_IDLE_SECONDS = 60
# A real-time push older than this no longer says anything about "now".
REALTIME_ONLINE_FRESH_SECONDS = 120

PLAN_IN_USE_ERROR = "plan_in_use_on_another_device"


def is_randomized_mac(mac: Optional[str]) -> bool:
    """True for a locally administered (private / randomized) MAC."""
    if not mac:
        return False
    try:
        first_octet = int(normalize_mac_address(mac).split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def mac_tail(mac: Optional[str]) -> str:
    """Last two octets, enough for a customer to recognise their device."""
    if not mac:
        return ""
    return ":".join(normalize_mac_address(mac).split(":")[-2:])


@dataclass
class DeviceUse:
    """Whether the device a purchase is bound to is in use."""

    customer_id: int
    mac: Optional[str]
    in_use: bool
    reason: str               # online_now | fixed_device_recent | no_device | idle
    last_seen: Optional[datetime] = None

    @property
    def randomized(self) -> bool:
        return is_randomized_mac(self.mac)


def _mac_variants(mac: str) -> list[str]:
    norm = normalize_mac_address(mac)
    return list({norm, norm.lower(), norm.replace(":", "-"), norm.lower().replace(":", "-")})


async def device_last_seen(
    db: AsyncSession,
    bound: Iterable[tuple[int, str]],
    *,
    now: datetime,
) -> dict[int, datetime]:
    """Latest evidence that each (customer_id, bound MAC) device was here.

    Evidence: usage credited to the purchase, the purchase being provisioned on
    that MAC, or a reconnect that bound it to that MAC. Read-only; the caller
    owns the transaction.
    """
    pairs = [(cid, normalize_mac_address(mac)) for cid, mac in bound if cid and mac]
    if not pairs:
        return {}
    since = now - FIXED_DEVICE_RECENT_WINDOW
    ids = [cid for cid, _ in pairs]
    seen: dict[int, datetime] = {}

    def _note(cid: int, at: Optional[datetime]) -> None:
        if at is not None and (cid not in seen or at > seen[cid]):
            seen[cid] = at

    usage_rows = await db.execute(
        select(CustomerUsageBucket.customer_id, func.max(CustomerUsageBucket.updated_at))
        .where(
            CustomerUsageBucket.customer_id.in_(ids),
            CustomerUsageBucket.bucket_start >= since - timedelta(hours=1),
        )
        .group_by(CustomerUsageBucket.customer_id)
    )
    for cid, at in usage_rows.all():
        _note(cid, at)

    for cid, mac in pairs:
        variants = _mac_variants(mac)
        prov = (
            await db.execute(
                select(
                    func.max(ProvisioningAttempt.created_at),
                    func.max(ProvisioningAttempt.router_updated_at),
                    func.max(ProvisioningAttempt.access_seen_at),
                    func.max(ProvisioningAttempt.last_online_at),
                ).where(
                    ProvisioningAttempt.customer_id == cid,
                    ProvisioningAttempt.mac_address.in_(variants),
                )
            )
        ).one()
        for at in prov:
            _note(cid, at)
        reconnect_at = (
            await db.execute(
                select(func.max(ReconnectionAttempt.created_at)).where(
                    ReconnectionAttempt.customer_id == cid,
                    ReconnectionAttempt.mac_address.in_(variants),
                    ReconnectionAttempt.success.is_(True),
                )
            )
        ).scalar()
        _note(cid, reconnect_at)
    return seen


def realtime_online(router_id: Optional[int], mac: Optional[str], now: datetime) -> bool:
    """True when a fresh real-time push shows this MAC online on the router."""
    from app.services.realtime_state import get_device_live

    live = get_device_live(router_id, mac)
    if live is None or not live.online:
        return False
    return (now - live.seen_at).total_seconds() <= REALTIME_ONLINE_FRESH_SECONDS


def probe_online_macs_sync(router_info: dict, macs: Iterable[str]) -> Optional[set[str]]:
    """Which of ``macs`` are on the router right now. None if it can't tell.

    Online = a hotspot host or active session for the MAC whose idle-time is at
    most ``LIVE_ONLINE_IDLE_SECONDS``. Filtered server-side per MAC so a busy
    router does not ship its whole host table. Read-only.
    """
    from app.services.router_diagnosis import parse_ros_duration

    wanted = {normalize_mac_address(m) for m in macs if m}
    if not wanted:
        return set()
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=10, connect_timeout=5,
    )
    if not api.connect():
        return None
    try:
        online: set[str] = set()
        for mac in wanted:
            for path in ("/ip/hotspot/host", "/ip/hotspot/active"):
                result = api.send_command_optimized(
                    f"{path}/print",
                    proplist=["mac-address", "idle-time"],
                    query=f"?mac-address={mac}",
                )
                if not result.get("success"):
                    return None
                for row in result.get("data") or []:
                    if normalize_mac_address(row.get("mac-address", "")) != mac:
                        continue
                    idle = parse_ros_duration(row.get("idle-time"))
                    # No idle-time reported: present, so assume in use.
                    if idle is None or idle <= LIVE_ONLINE_IDLE_SECONDS:
                        online.add(mac)
        return online
    finally:
        api.disconnect()


async def probe_online_macs(router_info: Optional[dict], macs: Iterable[str]) -> Optional[set[str]]:
    """Async wrapper; never raises. No DB session may be open around it."""
    import asyncio

    macs = [m for m in macs if m]
    if not router_info or not macs:
        return set() if not macs else None
    try:
        return await asyncio.to_thread(probe_online_macs_sync, router_info, macs)
    except Exception as exc:  # router I/O must never break a reconnect
        logger.warning("[ENTITLEMENT] Live presence probe failed: %s", exc)
        return None


def classify_device_use(
    *,
    customer_id: int,
    mac: Optional[str],
    last_seen: Optional[datetime],
    online_now: bool,
    now: datetime,
) -> DeviceUse:
    if not mac:
        return DeviceUse(customer_id, None, False, "no_device")
    if online_now:
        return DeviceUse(customer_id, mac, True, "online_now", last_seen)
    if (
        not is_randomized_mac(mac)
        and last_seen is not None
        and now - last_seen < FIXED_DEVICE_RECENT_WINDOW
    ):
        return DeviceUse(customer_id, mac, True, "fixed_device_recent", last_seen)
    return DeviceUse(customer_id, mac, False, "idle", last_seen)


async def assess_bound_devices(
    db: AsyncSession,
    customers: list[Customer],
    *,
    router_id: int,
    router_info: Optional[dict],
    now: Optional[datetime] = None,
) -> dict[int, DeviceUse]:
    """Decide, for each purchase, whether its bound device is in use.

    Reads the DB, then COMMITS (releasing the pooled connection) before the
    optional live router probe, per the session discipline in AGENTS.md. The
    caller's ORM instances stay usable (expire_on_commit=False) but must be
    re-locked before any write. ``router_info`` None skips the live probe
    (RADIUS routers): randomized MACs then count as idle, as before this change.
    """
    now = now or datetime.utcnow()
    bound = [
        (c.id, normalize_mac_address(c.mac_address))
        for c in customers if c.mac_address
    ]
    last_seen = await device_last_seen(db, bound, now=now)
    await db.commit()

    online: set[str] = {
        mac for _cid, mac in bound if realtime_online(router_id, mac, now)
    }
    # Only randomized MACs need the live check: a fixed-MAC device seen in the
    # last day is already in use, and one unseen for a day is not online.
    to_probe = [
        mac for cid, mac in bound
        if mac not in online
        and (is_randomized_mac(mac) or cid not in last_seen
             or now - last_seen[cid] >= FIXED_DEVICE_RECENT_WINDOW)
    ]
    if to_probe and router_info:
        probed = await probe_online_macs(router_info, to_probe)
        if probed:
            online |= probed

    result: dict[int, DeviceUse] = {}
    for c in customers:
        mac = normalize_mac_address(c.mac_address) if c.mac_address else None
        result[c.id] = classify_device_use(
            customer_id=c.id,
            mac=mac,
            last_seen=last_seen.get(c.id),
            online_now=bool(mac and mac in online),
            now=now,
        )
    return result


def pick_movable(
    customers: list[Customer],
    uses: dict[int, DeviceUse],
    *,
    requesting_mac: str,
) -> Optional[Customer]:
    """Best purchase to move to ``requesting_mac``, or None if all are in use.

    Preference: a purchase with no device yet; then one whose device MAC is the
    same kind as the requester's (randomized -> randomized is the phone whose
    MAC rotated); then the latest expiry (the input order).
    """
    req_random = is_randomized_mac(requesting_mac)
    free = [c for c in customers if not uses[c.id].in_use]
    if not free:
        return None

    def _rank(item: tuple[int, Customer]) -> tuple[int, int, int]:
        index, c = item
        use = uses[c.id]
        return (
            0 if use.mac is None else 1,
            0 if use.mac and use.randomized == req_random else 1,
            index,
        )

    return min(enumerate(free), key=_rank)[1]


def pick_blocker(
    customers: list[Customer],
    uses: dict[int, DeviceUse],
    *,
    requesting_mac: str,
) -> DeviceUse:
    """The in-use purchase to name in the refusal: the one most likely to be
    this same device (randomized -> randomized), else the latest expiry."""
    req_random = is_randomized_mac(requesting_mac)
    in_use = [uses[c.id] for c in customers if uses[c.id].in_use]
    for use in in_use:
        if use.mac and use.randomized == req_random:
            return use
    return in_use[0]


def plan_in_use_detail(use: DeviceUse) -> dict:
    """409 body the captive portal shows when every purchase is in use."""
    tail = mac_tail(use.mac)
    if use.randomized:
        message = (
            f"This plan is in use on another phone right now (MAC ending {tail}). "
            "If that was this phone, wait a minute and try again. "
            "Otherwise, buy a plan for this device."
        )
    else:
        message = (
            f"This plan is in use on another device (MAC ending {tail}). "
            "Buy a plan for this device."
        )
    return {
        "error": PLAN_IN_USE_ERROR,
        "message": message,
        "device_mac_tail": tail,
        "offer_purchase": True,
    }


def router_probe_info(router) -> Optional[dict]:
    """Connection info for the live probe; None for RADIUS routers."""
    from app.db.models import RouterAuthMethod

    if router is None:
        return None
    auth_method = getattr(router, "auth_method", None)
    if auth_method == RouterAuthMethod.RADIUS:
        return None
    if not getattr(router, "ip_address", None):
        return None
    return {
        "ip": router.ip_address,
        "username": router.username,
        "password": router.password,
        "port": router.port,
        "name": router.name,
    }

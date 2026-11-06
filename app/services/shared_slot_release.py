"""Free a shared-plan slot held by a phone that has gone away.

A phone with private Wi-Fi addressing gets a new MAC when it rotates, and takes a
new slot while the old one stays. On a plan with few devices that eventually
locks the owner out of their own plan until they remove a device by hand.

When a new device enters the plan's code and every slot is taken, one slot may
be released, only if ALL of these hold:

* its MAC is locally administered (randomized);
* it was added as an ordinary device, never a TV, console, laptop or IoT device;
* nothing has been heard of it for at least ``MIN_IDLE_DAYS`` days;
* the router confirms it is not on the Wi-Fi right now. If the router can't
  answer, nothing is released.

A plan's main device is never considered. Off unless
``SHARED_SLOT_IDLE_RELEASE_ENABLED`` is set, because it applies to every reseller
and a phone away for over a week has to enter the code again when it returns.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import (
    Customer,
    CustomerUsageBucket,
    CustomerUsagePeriod,
    DevicePairing,
    DeviceType,
    ProvisioningAttempt,
    ReconnectionAttempt,
)
from app.services.device_entitlements import _mac_variants, is_randomized_mac, router_probe_info
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

# The setting can only lengthen this.
MIN_IDLE_DAYS = 7


@dataclass
class IdleSlot:
    pairing_id: int
    customer_id: int
    mac: str
    last_seen: datetime


def release_enabled() -> bool:
    return bool(settings.SHARED_SLOT_IDLE_RELEASE_ENABLED)


def idle_after() -> timedelta:
    return timedelta(days=max(MIN_IDLE_DAYS, int(settings.SHARED_SLOT_IDLE_RELEASE_DAYS or 0)))


async def _latest_evidence(
    db: AsyncSession, rows: list[DevicePairing]
) -> dict[int, datetime]:
    """Latest sign of life per shared customer. Deliberately generous: a delivery
    or an edit also counts, so doubt always keeps the device."""
    ids = [row.customer_id for row in rows]
    seen: dict[int, datetime] = {}

    def note(customer_id: int, at: Optional[datetime]) -> None:
        if at is not None and (customer_id not in seen or at > seen[customer_id]):
            seen[customer_id] = at

    for row in rows:
        note(row.customer_id, row.created_at)
        note(row.customer_id, row.provisioned_at)

    for customer_id, at in (
        await db.execute(
            select(CustomerUsageBucket.customer_id, func.max(CustomerUsageBucket.updated_at))
            .where(CustomerUsageBucket.customer_id.in_(ids))
            .group_by(CustomerUsageBucket.customer_id)
        )
    ).all():
        note(customer_id, at)

    for customer_id, at in (
        await db.execute(
            select(CustomerUsagePeriod.customer_id, func.max(CustomerUsagePeriod.updated_at))
            .where(CustomerUsagePeriod.customer_id.in_(ids))
            .group_by(CustomerUsagePeriod.customer_id)
        )
    ).all():
        note(customer_id, at)

    for customer_id, *times in (
        await db.execute(
            select(
                ProvisioningAttempt.customer_id,
                func.max(ProvisioningAttempt.created_at),
                func.max(ProvisioningAttempt.updated_at),
                func.max(ProvisioningAttempt.router_updated_at),
                func.max(ProvisioningAttempt.access_seen_at),
                func.max(ProvisioningAttempt.last_online_at),
            )
            .where(ProvisioningAttempt.customer_id.in_(ids))
            .group_by(ProvisioningAttempt.customer_id)
        )
    ).all():
        for at in times:
            note(customer_id, at)

    for row in rows:
        at = (
            await db.execute(
                select(func.max(ReconnectionAttempt.created_at)).where(
                    ReconnectionAttempt.mac_address.in_(_mac_variants(row.device_mac)),
                    ReconnectionAttempt.router_id == row.router_id,
                    ReconnectionAttempt.success.is_(True),
                )
            )
        ).scalar()
        note(row.customer_id, at)
    return seen


async def find_idle_slots(
    db: AsyncSession, *, owner_id: int, router_id: int, now: datetime
) -> list[IdleSlot]:
    """Slots passing the MAC, device-type and last-seen rules, longest idle first."""
    rows = (
        await db.execute(
            select(DevicePairing).where(
                DevicePairing.subscription_owner_customer_id == owner_id,
                DevicePairing.router_id == router_id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).scalars().all()
    candidates = [
        row for row in rows
        if row.device_type == DeviceType.OTHER and is_randomized_mac(row.device_mac)
    ]
    if not candidates:
        return []

    from app.services.realtime_state import get_device_live

    seen = await _latest_evidence(db, candidates)
    cutoff = now - idle_after()
    idle: list[IdleSlot] = []
    for row in candidates:
        last_seen = seen.get(row.customer_id)
        live = get_device_live(router_id, row.device_mac)
        if live is not None and (last_seen is None or live.seen_at > last_seen):
            last_seen = live.seen_at
        # No evidence at all is not proof of absence.
        if last_seen is None or last_seen > cutoff:
            continue
        idle.append(
            IdleSlot(
                pairing_id=row.id,
                customer_id=row.customer_id,
                mac=normalize_mac_address(row.device_mac),
                last_seen=last_seen,
            )
        )
    return sorted(idle, key=lambda slot: slot.last_seen)


def _present_macs_sync(router_info: dict, macs: Iterable[str]) -> Optional[set[str]]:
    """MACs with any hotspot host or session, however idle. None if it can't tell."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=10, connect_timeout=5,
    )
    if not api.connect():
        return None
    try:
        present: set[str] = set()
        for mac in macs:
            for path in ("/ip/hotspot/host", "/ip/hotspot/active"):
                result = api.send_command_optimized(
                    f"{path}/print", proplist=["mac-address"], query=f"?mac-address={mac}",
                )
                if not result.get("success"):
                    return None
                if any(
                    normalize_mac_address(row.get("mac-address", "")) == mac
                    for row in result.get("data") or []
                ):
                    present.add(mac)
        return present
    finally:
        api.disconnect()


async def present_macs(router_info: Optional[dict], macs: list[str]) -> Optional[set[str]]:
    """Async wrapper; never raises. No DB transaction may be open around it."""
    if not router_info:
        return None
    try:
        return await asyncio.to_thread(_present_macs_sync, router_info, macs)
    except Exception as exc:  # router I/O must never break adding a device
        logger.warning("[SHARED-SLOT] Presence check failed: %s", exc)
        return None


async def pick_slot_to_release(
    db: AsyncSession, *, owner: Customer, router_id: int, now: Optional[datetime] = None
) -> Optional[IdleSlot]:
    """The slot that may be freed for a new device, or None.

    COMMITS before asking the router, per Database Session Discipline, so the
    caller must reload anything it needs to lock.
    """
    if not release_enabled():
        return None
    now = now or datetime.utcnow()
    idle = await find_idle_slots(db, owner_id=owner.id, router_id=router_id, now=now)
    if not idle:
        await db.commit()
        return None
    router_info = router_probe_info(owner.router)
    await db.commit()

    present = await present_macs(router_info, [slot.mac for slot in idle])
    if present is None:
        logger.info(
            "[SHARED-SLOT] Owner %s: router %s could not confirm %d idle device(s) are away; keeping them",
            owner.id, router_id, len(idle),
        )
        return None
    return next((slot for slot in idle if slot.mac not in present), None)

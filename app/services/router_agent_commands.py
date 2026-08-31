"""Durable command outbox used by the outbound RouterOS agent."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.db.database import async_session
from app.db.models import (
    AppSetting,
    Customer,
    CustomerStatus,
    CustomerUsagePeriod,
    DevicePairing,
    Plan,
    ProvisioningAttempt,
    ProvisioningOnlineState,
    ProvisioningState,
    Router,
    RouterCommand,
)
from app.services.mikrotik_api import normalize_mac_address, parse_speed_to_mikrotik
from app.services.pull_provisioning import render_hotspot_provision_rsc


logger = logging.getLogger(__name__)

AGENT_ENABLED_SETTING = "router_agent_enabled"
PPPOE_AGENT_ENABLED_SETTING = "router_agent_pppoe_commands_enabled"
COMMAND_MAX_AGE = timedelta(hours=4)
COMMAND_DELIVERY_LEASE = timedelta(seconds=90)
MAX_FAILED_ACKS = 5
MAX_ACTION_SCRIPT_BYTES = 16_000
PPPOE_AGENT_COMMANDS_SUPPORTED = False

ACTIVE_COMMAND_STATES = ("pending", "delivered")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_RATE_RE = re.compile(r"^\d+(?:\.\d+)?[KMG]?/\d+(?:\.\d+)?[KMG]?$", re.I)
_TIME_PART_RE = re.compile(r"(\d+)([wdhms])", re.I)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _ros_quote(value: Any, limit: int = 120) -> str:
    text = str(value or "")
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    text = "".join(ch for ch in text if ord(ch) >= 0x20)
    return text[:limit]


def _safe_username(value: Any, name: str = "username") -> str:
    text = str(value or "").strip()
    if not _USERNAME_RE.fullmatch(text):
        raise ValueError(f"router-agent: unsafe {name}={value!r}")
    return text


def _duration_seconds(value: Any) -> int | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    matches = list(_TIME_PART_RE.finditer(text))
    if not matches or "".join(match.group(0) for match in matches) != text:
        return None
    factors = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = sum(int(match.group(1)) * factors[match.group(2)] for match in matches)
    return total if total > 0 else None


def _plan_duration_seconds(plan: Plan | None) -> int | None:
    if plan is None or plan.duration_value is None or plan.duration_unit is None:
        return None
    unit = str(_enum_value(plan.duration_unit)).strip().lower()
    factors = {
        "minutes": 60,
        "hours": 3600,
        "days": 86400,
        "weeks": 604800,
    }
    factor = factors.get(unit)
    if factor is None:
        return None
    try:
        seconds = int(float(plan.duration_value) * factor)
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def render_pppoe_provision_action(
    *,
    username: str,
    password: str,
    bandwidth_limit: str,
    comment: str = "",
) -> str:
    user = _safe_username(username, "pppoe_username")
    rate = parse_speed_to_mikrotik(bandwidth_limit)
    if not _RATE_RE.fullmatch(rate):
        raise ValueError(f"router-agent: unsafe rate_limit={rate!r}")
    profile = _safe_username(f"pppoe_{rate.replace('/', '_')}", "profile")
    password_q = _ros_quote(password)
    comment_q = _ros_quote(comment)
    return f"""# router-agent PPPoE provision {user}
:do {{ /ip pool add name=pppoe-pool ranges=192.168.89.2-192.168.89.254 }} on-error={{}}
:if ([:len [/ppp profile find name=\"{profile}\"]] = 0) do={{
    /ppp profile add name=\"{profile}\" local-address=192.168.89.1 remote-address=pppoe-pool rate-limit=\"{rate}\"
}} else={{
    /ppp profile set [find name=\"{profile}\"] rate-limit=\"{rate}\"
}}
:if ([:len [/ppp secret find name=\"{user}\"]] = 0) do={{
    /ppp secret add name=\"{user}\" password=\"{password_q}\" service=pppoe profile=\"{profile}\" comment=\"{comment_q}\"
}} else={{
    /ppp secret set [find name=\"{user}\"] password=\"{password_q}\" service=pppoe profile=\"{profile}\" comment=\"{comment_q}\" disabled=no
}}
:do {{ /ppp active remove [find name=\"{user}\"] }} on-error={{}}
"""


def render_hotspot_remove_action(
    *, mac_address: str, username: str, lb_enabled: bool = False
) -> str:
    mac = normalize_mac_address(mac_address)
    user = _safe_username(username)
    compact = mac.replace(":", "")
    return f"""# router-agent hotspot remove {compact}
:local bwClientIp ""
:local bwHost [/ip hotspot host find mac-address=\"{mac}\"]
:if ([:len $bwHost] > 0) do={{ :set bwClientIp [/ip hotspot host get [:pick $bwHost 0] address] }}
:do {{ /ip hotspot active remove [find mac-address=\"{mac}\"] }} on-error={{}}
:do {{ /ip hotspot active remove [find user=\"{user}\"] }} on-error={{}}
:do {{ /ip hotspot ip-binding remove [find mac-address=\"{mac}\"] }} on-error={{}}
:do {{ /ip hotspot user remove [find name=\"{user}\"] }} on-error={{}}
:do {{ /ip hotspot host remove [find mac-address=\"{mac}\"] }} on-error={{}}
:do {{ /ip dhcp-server lease remove [find mac-address=\"{mac}\"] }} on-error={{}}
:do {{ /queue simple remove [find name=\"plan_{user}\"] }} on-error={{}}
:do {{ /queue simple remove [find name=\"queue_{user}\"] }} on-error={{}}
{f':do {{ /ip firewall address-list remove [find list="LB_PAID" comment="PAID:{mac}"] }} on-error={{}}' if lb_enabled else ''}
{f':if ([:len $bwClientIp] > 0) do={{ :do {{ /ip firewall address-list remove [find list="LB_PAID" address=$bwClientIp] }} on-error={{}} }}' if lb_enabled else ''}
:if ([:len [/ip hotspot ip-binding find mac-address=\"{mac}\"]] > 0) do={{ :error \"binding remains\" }}
:if ([:len [/ip hotspot active find mac-address=\"{mac}\"]] > 0) do={{ :error \"session remains\" }}
:if ([:len [/ip hotspot user find name=\"{user}\"]] > 0) do={{ :error \"user remains\" }}
:if ([:len [/ip hotspot host find mac-address=\"{mac}\"]] > 0) do={{ :error \"host remains\" }}
:if ([:len [/queue simple find name=\"plan_{user}\"]] > 0) do={{ :error \"queue remains\" }}
{f':if ([:len [/ip firewall address-list find list="LB_PAID" comment="PAID:{mac}"]] > 0) do={{ :error "LB_PAID remains" }}' if lb_enabled else ''}
"""


def render_pppoe_remove_action(*, username: str) -> str:
    user = _safe_username(username, "pppoe_username")
    return f"""# router-agent PPPoE remove {user}
:do {{ /ppp active remove [find name=\"{user}\"] }} on-error={{}}
:do {{ /ppp secret remove [find name=\"{user}\"] }} on-error={{}}
:if ([:len [/ppp active find name=\"{user}\"]] > 0) do={{ :error \"session remains\" }}
:if ([:len [/ppp secret find name=\"{user}\"]] > 0) do={{ :error \"secret remains\" }}
"""


async def _agent_is_enabled(db) -> bool:
    setting = await db.get(AppSetting, AGENT_ENABLED_SETTING)
    return bool(setting and setting.value.strip().lower() in {"1", "true", "yes", "on"})


async def _pppoe_agent_is_enabled(db) -> bool:
    setting = await db.get(AppSetting, PPPOE_AGENT_ENABLED_SETTING)
    return bool(setting and setting.value.strip().lower() in {"1", "true", "yes", "on"})


def _notify_pending(router_id: int) -> None:
    try:
        from app.api.router_agent_routes import note_router_has_pending_command

        note_router_has_pending_command(router_id)
    except Exception:
        # The durable row is authoritative; cache refresh repairs any missed hint.
        pass


async def _enqueue_command(
    *,
    router_id: int,
    customer_id: int | None,
    attempt_id: int | None,
    idempotency_key: str,
    command_type: str,
    action_script: str,
    metadata: dict[str, Any] | None = None,
    expires_at: datetime | None = None,
) -> int | None:
    if len(action_script.encode("utf-8")) > MAX_ACTION_SCRIPT_BYTES:
        raise ValueError("router-agent: action script exceeds safe delivery size")
    async with async_session() as db:
        router = await db.get(Router, router_id)
        if (
            router is None
            or not router.router_agent_enabled
            or not router.identity
            or not await _agent_is_enabled(db)
        ):
            return None

        existing = (
            await db.execute(
                select(RouterCommand).where(RouterCommand.idempotency_key == idempotency_key)
            )
        ).scalar_one_or_none()
        if existing is not None:
            command_id = existing.id
        else:
            command = RouterCommand(
                router_id=router_id,
                customer_id=customer_id,
                provisioning_attempt_id=attempt_id,
                idempotency_key=idempotency_key[:128],
                command_type=command_type,
                action_script=action_script,
                metadata_json=metadata or {},
                state="pending",
                available_at=datetime.utcnow(),
                expires_at=expires_at,
            )
            db.add(command)
            try:
                await db.commit()
                await db.refresh(command)
                command_id = command.id
            except IntegrityError:
                # Concurrent payment/retry workers may race on the same
                # idempotency key. The unique row is the winner, not an error
                # that should suppress fallback delivery.
                await db.rollback()
                winner = (
                    await db.execute(
                        select(RouterCommand).where(
                            RouterCommand.idempotency_key == idempotency_key[:128]
                        )
                    )
                ).scalar_one()
                command_id = winner.id

    _notify_pending(router_id)
    return command_id


async def queue_hotspot_provision_command(
    *,
    router_id: int | None,
    customer_id: int,
    attempt_id: int | None,
    hotspot_payload: dict[str, Any],
) -> int | None:
    if not router_id:
        return None
    now = datetime.utcnow()
    async with async_session() as db:
        customer = await db.get(Customer, customer_id)
        if (
            customer is None
            or customer.status != CustomerStatus.ACTIVE
            or customer.router_id != router_id
            or customer.expiry is None
            or customer.expiry <= now
        ):
            return None
        original_expiry = customer.expiry

    duration = _duration_seconds(hotspot_payload.get("time_limit"))
    service_start = (
        original_expiry - timedelta(seconds=duration)
        if original_expiry and duration
        else now
    )
    rate = parse_speed_to_mikrotik(hotspot_payload.get("bandwidth_limit"))
    script = render_hotspot_provision_rsc(
        username=hotspot_payload.get("username"),
        password=hotspot_payload.get("password"),
        mac_address=hotspot_payload.get("mac_address"),
        rate_limit=rate,
        time_limit=hotspot_payload.get("time_limit"),
        comment=hotspot_payload.get("comment", ""),
        expires_at=None,
        lb_enabled=bool(hotspot_payload.get("lb_enabled")),
    )
    entitlement_key = (
        f"attempt:{attempt_id}"
        if attempt_id is not None
        else f"hotspot:{router_id}:{customer_id}:{original_expiry.isoformat() if original_expiry else 'none'}"
    )
    return await _enqueue_command(
        router_id=router_id,
        customer_id=customer_id,
        attempt_id=attempt_id,
        idempotency_key=entitlement_key,
        command_type="hotspot_provision",
        action_script=script,
        metadata={
            "original_expiry": original_expiry.isoformat() if original_expiry else None,
            "service_start": service_start.isoformat(),
            "entitlement_seconds": duration,
            "mac_address": normalize_mac_address(hotspot_payload.get("mac_address")),
            "username": hotspot_payload.get("username"),
            "lb_enabled": bool(hotspot_payload.get("lb_enabled")),
        },
        expires_at=min(now + COMMAND_MAX_AGE, original_expiry),
    )


async def queue_pppoe_provision_command(
    *,
    router_id: int | None,
    customer_id: int,
    attempt_id: int | None,
    pppoe_payload: dict[str, Any],
) -> int | None:
    if not PPPOE_AGENT_COMMANDS_SUPPORTED or not router_id:
        return None
    now = datetime.utcnow()
    async with async_session() as db:
        if not await _pppoe_agent_is_enabled(db):
            return None
        customer = await db.get(Customer, customer_id)
        if (
            customer is None
            or customer.status != CustomerStatus.ACTIVE
            or customer.router_id != router_id
            or customer.expiry is None
            or customer.expiry <= now
        ):
            return None
        original_expiry = customer.expiry
        plan = await db.get(Plan, customer.plan_id) if customer.plan_id else None
    duration = _plan_duration_seconds(plan)
    service_start = (
        original_expiry - timedelta(seconds=duration)
        if original_expiry and duration
        else now
    )
    script = render_pppoe_provision_action(
        username=pppoe_payload.get("pppoe_username"),
        password=pppoe_payload.get("pppoe_password"),
        bandwidth_limit=pppoe_payload.get("bandwidth_limit"),
        comment=pppoe_payload.get("comment", ""),
    )
    entitlement_key = (
        f"attempt:{attempt_id}"
        if attempt_id is not None
        else f"pppoe:{router_id}:{customer_id}:{original_expiry.isoformat() if original_expiry else 'none'}"
    )
    return await _enqueue_command(
        router_id=router_id,
        customer_id=customer_id,
        attempt_id=attempt_id,
        idempotency_key=entitlement_key,
        command_type="pppoe_provision",
        action_script=script,
        metadata={
            "original_expiry": original_expiry.isoformat() if original_expiry else None,
            "service_start": service_start.isoformat(),
            "entitlement_seconds": duration,
            "username": pppoe_payload.get("pppoe_username"),
        },
        expires_at=min(now + COMMAND_MAX_AGE, original_expiry),
    )


async def queue_hotspot_remove_command(
    *, router_id: int, customer_id: int, mac_address: str, username: str,
    lb_enabled: bool = False,
) -> int | None:
    async with async_session() as db:
        customer = await db.get(Customer, customer_id)
        generation = customer.expiry.isoformat() if customer and customer.expiry else "none"
    return await _enqueue_command(
        router_id=router_id,
        customer_id=customer_id,
        attempt_id=None,
        idempotency_key=f"hotspot-remove:{router_id}:{customer_id}:{generation}",
        command_type="hotspot_remove",
        action_script=render_hotspot_remove_action(
            mac_address=mac_address,
            username=username,
            lb_enabled=lb_enabled,
        ),
        metadata={
            "expiry_generation": generation,
            "mac_address": normalize_mac_address(mac_address),
            "username": username,
            "lb_enabled": lb_enabled,
        },
        expires_at=datetime.utcnow() + timedelta(days=7),
    )


async def queue_pppoe_remove_command(
    *, router_id: int, customer_id: int, username: str
) -> int | None:
    if not PPPOE_AGENT_COMMANDS_SUPPORTED:
        return None
    async with async_session() as db:
        if not await _pppoe_agent_is_enabled(db):
            return None
        customer = await db.get(Customer, customer_id)
        generation = customer.expiry.isoformat() if customer and customer.expiry else "none"
    return await _enqueue_command(
        router_id=router_id,
        customer_id=customer_id,
        attempt_id=None,
        idempotency_key=f"pppoe-remove:{router_id}:{customer_id}:{generation}",
        command_type="pppoe_remove",
        action_script=render_pppoe_remove_action(username=username),
        metadata={"expiry_generation": generation, "username": username},
        expires_at=datetime.utcnow() + timedelta(days=7),
    )


async def complete_command_from_push(command_id: int | None) -> None:
    if command_id is None:
        return
    async with async_session() as db:
        command = (
            await db.execute(
                select(RouterCommand)
                .where(RouterCommand.id == command_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if command is not None and command.state in ACTIVE_COMMAND_STATES:
            command.state = "applied"
            command.acknowledged_at = datetime.utcnow()
            command.acknowledgement_source = "direct_push"
            command.last_error = None
            command.updated_at = datetime.utcnow()
            await db.commit()


async def next_command_for_router(router_id: int) -> RouterCommand | None:
    """Claim the next live command in a short transaction.

    Lifecycle is rechecked at delivery time so an old removal can never be
    handed out after the customer renewed, and an old grant is not delivered to
    a deleted/inactive customer.
    """

    now = datetime.utcnow()
    async with async_session() as db:
        # Serialize command claims per router across app workers. The RouterOS
        # script also has a local lock; this row lock closes the server-side
        # duplicate-poll gap without holding a transaction across router I/O.
        router_claim = (
            await db.execute(
                select(Router.id)
                .where(Router.id == router_id)
                .with_for_update(skip_locked=True)
            )
        ).first()
        if router_claim is None:
            return None
        commands = (
            await db.execute(
                select(RouterCommand)
                .where(
                    RouterCommand.router_id == router_id,
                    RouterCommand.state.in_(ACTIVE_COMMAND_STATES),
                    RouterCommand.available_at <= now,
                    or_(RouterCommand.expires_at.is_(None), RouterCommand.expires_at > now),
                )
                .order_by(RouterCommand.id.asc())
                .limit(5)
                .with_for_update()
            )
        ).scalars().all()

        for command in commands:
            customer = await db.get(Customer, command.customer_id) if command.customer_id else None
            is_remove = command.command_type.endswith("_remove")
            is_provision = command.command_type.endswith("_provision")
            if command.customer_id is not None and customer is None:
                command.state = "cancelled"
                queued_cleanup = bool(
                    is_provision
                    and command.first_delivered_at is not None
                    and await _queue_cleanup_after_stale_grant(
                        db,
                        command=command,
                        customer=None,
                        now=now,
                    )
                )
                command.last_error = (
                    "Customer no longer exists; precautionary cleanup queued"
                    if queued_cleanup
                    else "Customer no longer exists"
                )
                command.updated_at = now
                continue
            if customer is not None:
                customer_is_live = (
                    customer.status == CustomerStatus.ACTIVE
                    and customer.expiry is not None
                    and customer.expiry > now
                )
                generation = (command.metadata_json or {}).get("expiry_generation")
                current_generation = customer.expiry.isoformat() if customer.expiry else "none"
                if (
                    is_remove
                    and customer.router_id == command.router_id
                    and customer_is_live
                ):
                    command.state = "cancelled"
                    command.last_error = (
                        "Customer is live before removal delivery "
                        f"(command generation={generation}, current={current_generation})"
                    )
                    command.updated_at = now
                    continue
                if is_provision and (
                    not customer_is_live or customer.router_id != command.router_id
                ):
                    command.state = "cancelled"
                    queued_cleanup = bool(
                        command.first_delivered_at is not None
                        and await _queue_cleanup_after_stale_grant(
                            db,
                            command=command,
                            customer=customer,
                            now=now,
                        )
                    )
                    command.last_error = (
                        "Paid entitlement ended or moved after delivery; cleanup queued"
                        if queued_cleanup
                        else "Paid entitlement ended or moved before delivery"
                    )
                    command.updated_at = now
                    continue

            command.state = "delivered"
            command.delivery_count += 1
            command.available_at = now + COMMAND_DELIVERY_LEASE
            command.first_delivered_at = command.first_delivered_at or now
            command.last_delivered_at = now
            command.updated_at = now
            await db.commit()
            await db.refresh(command)
            return command

        if commands:
            await db.commit()
    return None


async def expire_active_commands(now: datetime | None = None) -> int:
    """Terminalize expired commands and clean up grants that may have applied."""

    now = now or datetime.utcnow()
    async with async_session() as db:
        expired_commands = (
            await db.execute(
                select(RouterCommand)
                .where(
                    RouterCommand.state.in_(ACTIVE_COMMAND_STATES),
                    RouterCommand.expires_at.isnot(None),
                    RouterCommand.expires_at <= now,
                )
                .order_by(RouterCommand.id.asc())
                .limit(100)
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
        for command in expired_commands:
            command.state = "expired"
            command.updated_at = now
            queued_cleanup = False
            delivered_provision = bool(
                command.command_type.endswith("_provision")
                and command.first_delivered_at is not None
            )
            customer_is_live_here = False
            if (
                delivered_provision
            ):
                customer = (
                    await db.get(Customer, command.customer_id)
                    if command.customer_id
                    else None
                )
                customer_is_live_here = bool(
                    customer is not None
                    and customer.status == CustomerStatus.ACTIVE
                    and customer.expiry is not None
                    and customer.expiry > now
                    and customer.router_id == command.router_id
                )
                if not customer_is_live_here:
                    queued_cleanup = await _queue_cleanup_after_stale_grant(
                        db,
                        command=command,
                        customer=customer,
                        now=now,
                    )
            if queued_cleanup:
                command.last_error = (
                    "Command expired after delivery; precautionary cleanup queued"
                )
            elif delivered_provision and customer_is_live_here:
                command.last_error = (
                    "Command expired after delivery while entitlement remains active; "
                    "no cleanup issued"
                )
            elif delivered_provision:
                command.last_error = (
                    "CRITICAL: command expired after delivery for a stale entitlement; "
                    "cleanup could not be rendered"
                )
            else:
                command.last_error = "Command expired before acknowledgement"
        if expired_commands:
            await db.commit()
        return len(expired_commands)


async def _queue_cleanup_after_stale_grant(
    db,
    *,
    command: RouterCommand,
    customer: Customer | None,
    now: datetime,
) -> bool:
    """Durably undo a grant that was applied after its entitlement ended."""

    metadata = command.metadata_json or {}
    key = f"cleanup-after-stale-grant:{command.id}"
    existing = (
        await db.execute(
            select(RouterCommand.id).where(RouterCommand.idempotency_key == key)
        )
    ).first()
    if existing:
        return True

    generation = (
        customer.expiry.isoformat()
        if customer is not None and customer.expiry is not None
        else "none"
    )
    if command.command_type == "hotspot_provision":
        mac = metadata.get("mac_address")
        username = metadata.get("username")
        if not mac or not username:
            return False
        action = render_hotspot_remove_action(
            mac_address=mac,
            username=username,
            lb_enabled=bool(metadata.get("lb_enabled")),
        )
        command_type = "hotspot_remove"
    elif command.command_type == "pppoe_provision":
        username = metadata.get("username")
        if not username:
            return False
        action = render_pppoe_remove_action(username=username)
        command_type = "pppoe_remove"
    else:
        return False

    db.add(
        RouterCommand(
            router_id=command.router_id,
            customer_id=customer.id if customer is not None else None,
            idempotency_key=key,
            command_type=command_type,
            action_script=action,
            metadata_json={
                "expiry_generation": generation,
                "cleanup_for_command_id": command.id,
                **{
                    field: metadata[field]
                    for field in ("mac_address", "username", "lb_enabled")
                    if field in metadata
                },
            },
            state="pending",
            available_at=now,
            expires_at=now + timedelta(days=7),
        )
    )
    return True


async def _queue_hotspot_repair_after_stale_remove(
    db,
    *,
    command: RouterCommand,
    customer: Customer,
    now: datetime,
) -> bool:
    """Repair a renewed entitlement removed by an already in-flight command."""

    if not customer.mac_address or not customer.plan_id or not customer.expiry:
        return False
    plan = await db.get(Plan, customer.plan_id)
    router = await db.get(Router, command.router_id)
    if plan is None or router is None or not router.router_agent_enabled:
        return False

    generation = customer.expiry.isoformat()
    key = f"repair-after-remove:{command.id}:{generation}"
    existing = (
        await db.execute(
            select(RouterCommand.id).where(RouterCommand.idempotency_key == key)
        )
    ).first()
    if existing:
        return True

    mac = normalize_mac_address(customer.mac_address)
    username = mac.replace(":", "")
    remaining_seconds = max(60, int((customer.expiry - now).total_seconds()))
    rate = parse_speed_to_mikrotik(plan.speed)
    script = render_hotspot_provision_rsc(
        username=username,
        password=username,
        mac_address=mac,
        rate_limit=rate,
        time_limit=f"{remaining_seconds}s",
        comment=f"CID:{customer.id}|stale-removal-repair",
        expires_at=None,
        lb_enabled=bool(router.lb_enabled),
    )
    db.add(
        RouterCommand(
            router_id=command.router_id,
            customer_id=customer.id,
            idempotency_key=key[:128],
            command_type="hotspot_provision",
            action_script=script,
            metadata_json={
                "original_expiry": generation,
                "service_start": now.isoformat(),
                "entitlement_seconds": remaining_seconds,
                "mac_address": mac,
                "username": username,
                "lb_enabled": bool(router.lb_enabled),
                "repair_for_command_id": command.id,
            },
            state="pending",
            available_at=now,
            expires_at=min(now + COMMAND_MAX_AGE, customer.expiry),
        )
    )
    return True


async def _align_compensated_entitlement(
    db,
    *,
    customer: Customer,
    new_expiry: datetime,
) -> None:
    """Keep sharing and usage-cycle rows aligned with paid-time restoration."""

    customer.expiry = new_expiry
    companions = (
        await db.execute(
            select(Customer).where(
                Customer.subscription_owner_id == customer.id,
                Customer.status == CustomerStatus.ACTIVE,
            )
        )
    ).scalars().all()
    for companion in companions:
        companion.expiry = new_expiry

    pairings = (
        await db.execute(
            select(DevicePairing).where(
                DevicePairing.subscription_owner_customer_id == customer.id,
                DevicePairing.is_subscription_share == True,  # noqa: E712
                DevicePairing.is_active == True,  # noqa: E712
            )
        )
    ).scalars().all()
    for pairing in pairings:
        pairing.expires_at = new_expiry

    open_periods = (
        await db.execute(
            select(CustomerUsagePeriod).where(
                CustomerUsagePeriod.customer_id == customer.id,
                CustomerUsagePeriod.closed_at.is_(None),
            )
        )
    ).scalars().all()
    for period in open_periods:
        period.period_end = new_expiry


async def acknowledge_command(
    *, router_id: int, command_id: int, applied: bool, error: str | None = None
) -> tuple[RouterCommand | None, bool]:
    """Apply an idempotent agent acknowledgement in one short transaction."""

    now = datetime.utcnow()
    async with async_session() as db:
        command = (
            await db.execute(
                select(RouterCommand)
                .where(RouterCommand.id == command_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if command is None or command.router_id != router_id:
            return None, False
        if command.state == "applied":
            return command, True

        if not applied:
            if command.state not in ACTIVE_COMMAND_STATES:
                return command, True
            command.failure_count += 1
            command.last_error = str(error or "Router reported command failure")[:500]
            command.updated_at = now
            if command.failure_count >= MAX_FAILED_ACKS:
                command.state = "failed"
            else:
                command.state = "pending"
                command.available_at = now + timedelta(seconds=min(300, 30 * command.failure_count))
            await db.commit()
            await db.refresh(command)
            return command, True

        command.state = "applied"
        command.acknowledged_at = now
        command.acknowledgement_source = "agent"
        command.last_error = None
        command.updated_at = now

        customer = await db.get(Customer, command.customer_id) if command.customer_id else None
        is_provision = command.command_type.endswith("_provision")
        is_remove = command.command_type.endswith("_remove")
        customer_is_live_here = bool(
            customer is not None
            and customer.status == CustomerStatus.ACTIVE
            and customer.expiry is not None
            and customer.expiry > now
            and customer.router_id == command.router_id
        )

        queued_followup = False
        if is_provision and not customer_is_live_here:
            queued_followup = await _queue_cleanup_after_stale_grant(
                db,
                command=command,
                customer=customer,
                now=now,
            )
            command.last_error = (
                "Grant applied after entitlement changed; cleanup queued"
                if queued_followup
                else "CRITICAL: stale grant applied but cleanup could not be rendered"
            )

        if is_remove and customer_is_live_here:
            generation = (command.metadata_json or {}).get("expiry_generation")
            current_generation = customer.expiry.isoformat()
            if command.command_type == "hotspot_remove":
                queued_followup = await _queue_hotspot_repair_after_stale_remove(
                    db,
                    command=command,
                    customer=customer,
                    now=now,
                )
            command.last_error = (
                "Removal raced live entitlement; repair queued "
                f"(command generation={generation}, current={current_generation})"
                if queued_followup
                else "CRITICAL: removal raced live entitlement but repair could not be queued"
            )

        attempt = (
            await db.get(ProvisioningAttempt, command.provisioning_attempt_id)
            if command.provisioning_attempt_id else None
        )
        if attempt is not None and (not is_provision or customer_is_live_here):
            attempt.provisioning_state = ProvisioningState.ROUTER_UPDATED
            attempt.online_state = ProvisioningOnlineState.UNKNOWN
            attempt.router_updated_at = now
            attempt.last_error = None
            attempt.updated_at = now

        if customer is not None and is_remove and not customer_is_live_here:
            if customer.expiry is None or customer.expiry <= now:
                customer.status = CustomerStatus.INACTIVE

        # Restore paid time lost while a newly-paid customer waited for the
        # router.  ``service_start`` is the start of this purchased entitlement;
        # renewals that were still covered before delivery therefore receive no
        # artificial extension.
        if customer_is_live_here and is_provision:
            metadata = command.metadata_json or {}
            service_start_raw = metadata.get("service_start")
            original_expiry_raw = metadata.get("original_expiry")
            try:
                service_start = datetime.fromisoformat(service_start_raw)
                original_expiry = datetime.fromisoformat(original_expiry_raw)
                lost_seconds = max(0, int((now - service_start).total_seconds()))
                if lost_seconds and customer.expiry and customer.expiry <= original_expiry:
                    await _align_compensated_entitlement(
                        db,
                        customer=customer,
                        new_expiry=original_expiry + timedelta(seconds=lost_seconds),
                    )
            except (TypeError, ValueError):
                pass

        await db.commit()
        await db.refresh(command)
        if queued_followup:
            _notify_pending(command.router_id)
        return command, True


async def has_active_commands(router_id: int) -> bool:
    now = datetime.utcnow()
    async with async_session() as db:
        row = (
            await db.execute(
                select(RouterCommand.id)
                .where(
                    RouterCommand.router_id == router_id,
                    RouterCommand.state.in_(ACTIVE_COMMAND_STATES),
                    or_(RouterCommand.expires_at.is_(None), RouterCommand.expires_at > now),
                )
                .limit(1)
            )
        ).first()
    return row is not None

"""Stamp recent payments with the router port the paying customer is on.

Revenue-per-port used to be inferred live (whole payment history attributed to
wherever the customer's device happened to be at scan time), which produced
misleading numbers. Instead, this job records attribution at payment time:
shortly after a payment lands, look up the customer's MAC in the router's
bridge-host table and stamp ``customer_payments.port_name`` permanently.

Customers are almost always online right after paying (hotspot users are
literally on the captive portal), so a short retry window is enough. Payments
whose customer never shows up on a port within the window stay NULL and are
reported as "unattributed".

DB session discipline (see AGENTS.md):

1. Claim candidate payments in one short session, commit, close.
2. Read bridge-host tables from routers with NO session open.
3. Stamp the matched rows in a fresh short session.

The job sheds load when the DB pool is busy and backs off routers that were
unreachable instead of retrying them every tick.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select

from app.db.database import async_session, db_pool_snapshot
from app.db.models import Customer, CustomerPayment, Router
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

# Payments older than this stop being retried and stay unattributed (NULL).
ATTRIBUTION_WINDOW = timedelta(minutes=45)
MAX_ROUTERS_PER_RUN = 5
MAX_PAYMENTS_PER_RUN = 200
ROUTER_CONCURRENCY = 2
DB_BUSY_THRESHOLD_PERCENT = 60
OFFLINE_ROUTER_BACKOFF = timedelta(minutes=10)

# In-memory backoff for unreachable routers; process-local is fine because the
# job is best-effort and the window bounds retries anyway.
_router_backoff: dict[int, datetime] = {}
_attribution_running = False


@dataclass
class PendingPayment:
    payment_id: int
    mac: str
    router_id: int


def _db_pool_is_busy() -> bool:
    snapshot = db_pool_snapshot()
    checked_out_percent = snapshot.get("checked_out_percent")
    if isinstance(checked_out_percent, (int, float)) and checked_out_percent >= DB_BUSY_THRESHOLD_PERCENT:
        logger.warning(
            "[PORT-ATTR] Skipping payment port attribution because DB pool is busy: "
            "checked_out=%s/%s (%.2f%%)",
            snapshot.get("checked_out"),
            snapshot.get("configured_max_app_connections"),
            checked_out_percent,
        )
        return True
    return False


def _normalize_mac_safe(mac_address: Any) -> str:
    if not mac_address:
        return ""
    try:
        return normalize_mac_address(str(mac_address))
    except Exception:
        return str(mac_address).upper()


async def _claim_pending_payments(now: datetime) -> tuple[dict[int, list[PendingPayment]], dict[int, dict]]:
    """One short DB session: recent NULL-port payments grouped by router."""
    window_start = now - ATTRIBUTION_WINDOW
    async with async_session() as db:
        rows = await db.execute(
            select(
                CustomerPayment.id,
                Customer.mac_address,
                Customer.router_id,
                Router.name,
                Router.ip_address,
                Router.username,
                Router.password,
                Router.port,
            )
            .join(Customer, CustomerPayment.customer_id == Customer.id)
            .join(Router, Customer.router_id == Router.id)
            .where(
                CustomerPayment.port_name.is_(None),
                CustomerPayment.created_at >= window_start,
                Customer.mac_address.isnot(None),
                Customer.router_id.isnot(None),
            )
            .order_by(CustomerPayment.created_at.desc())
            .limit(MAX_PAYMENTS_PER_RUN)
        )
        by_router: dict[int, list[PendingPayment]] = defaultdict(list)
        router_info: dict[int, dict] = {}
        for payment_id, mac_address, router_id, name, ip, username, password, api_port in rows:
            backoff_until = _router_backoff.get(router_id)
            if backoff_until and backoff_until > now:
                continue
            mac = _normalize_mac_safe(mac_address)
            if not mac:
                continue
            by_router[router_id].append(PendingPayment(payment_id, mac, router_id))
            router_info.setdefault(router_id, {
                "id": router_id,
                "name": name,
                "ip": ip,
                "username": username,
                "password": password,
                "port": api_port,
            })
        await db.commit()

    if len(by_router) > MAX_ROUTERS_PER_RUN:
        keep = set(list(by_router.keys())[:MAX_ROUTERS_PER_RUN])
        by_router = {rid: items for rid, items in by_router.items() if rid in keep}
        router_info = {rid: info for rid, info in router_info.items() if rid in keep}
    return by_router, router_info


def _fetch_mac_port_map_sync(router_info: dict) -> dict:
    """Read the bridge-host table: which physical port each MAC is behind."""
    api = MikroTikAPI(
        router_info["ip"],
        router_info["username"],
        router_info["password"],
        router_info["port"],
        timeout=10,
        connect_timeout=4,
    )
    if not api.connect():
        return {"error": api.last_connect_error or "connect_failed"}
    try:
        result = api.send_command_optimized(
            "/interface/bridge/host/print",
            proplist=["mac-address", "on-interface", "interface", "local"],
        )
        if not (isinstance(result, dict) and result.get("success")):
            return {"error": "bridge_host_read_failed"}
        mac_to_port: dict[str, str] = {}
        for row in result.get("data") or []:
            if str(row.get("local")).lower() == "true":
                continue
            mac = _normalize_mac_safe(row.get("mac-address"))
            port = row.get("on-interface") or row.get("interface") or ""
            if mac and port:
                mac_to_port[mac] = str(port)
        return {"map": mac_to_port}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        api.disconnect()


async def _resolve_router(
    router_id: int,
    info: dict,
    payments: list[PendingPayment],
    semaphore: asyncio.Semaphore,
    now: datetime,
) -> dict[int, str]:
    """Router I/O with no DB session open; returns payment_id -> port_name."""
    async with semaphore:
        result = await asyncio.to_thread(_fetch_mac_port_map_sync, info)
    if result.get("error"):
        _router_backoff[router_id] = now + OFFLINE_ROUTER_BACKOFF
        logger.info(
            "[PORT-ATTR] Router %s (%s) unreachable, backing off: %s",
            router_id, info.get("name"), result["error"],
        )
        return {}
    _router_backoff.pop(router_id, None)
    mac_to_port = result.get("map") or {}
    return {
        payment.payment_id: mac_to_port[payment.mac]
        for payment in payments
        if payment.mac in mac_to_port
    }


async def _stamp_payments(port_by_payment_id: dict[int, str], now: datetime) -> int:
    if not port_by_payment_id:
        return 0
    async with async_session() as db:
        rows = await db.execute(
            select(CustomerPayment).where(
                CustomerPayment.id.in_(port_by_payment_id.keys()),
                CustomerPayment.port_name.is_(None),
            )
        )
        stamped = 0
        for payment in rows.scalars():
            payment.port_name = port_by_payment_id[payment.id][:64]
            stamped += 1
        await db.commit()
    return stamped


async def attribute_recent_payment_ports_background() -> None:
    """APScheduler entrypoint: stamp recent payments with their current port."""
    global _attribution_running
    if _attribution_running:
        return
    if _db_pool_is_busy():
        return

    _attribution_running = True
    now = datetime.utcnow()
    try:
        by_router, router_info = await _claim_pending_payments(now)
        if not by_router:
            return

        semaphore = asyncio.Semaphore(ROUTER_CONCURRENCY)
        outcomes = await asyncio.gather(
            *[
                _resolve_router(router_id, router_info[router_id], payments, semaphore, now)
                for router_id, payments in by_router.items()
            ],
            return_exceptions=True,
        )
        port_by_payment_id: dict[int, str] = {}
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                logger.error("[PORT-ATTR] Router resolution crashed: %s", outcome)
                continue
            port_by_payment_id.update(outcome)

        if _db_pool_is_busy():
            return
        stamped = await _stamp_payments(port_by_payment_id, now)
        if stamped:
            logger.info(
                "[PORT-ATTR] Stamped %d payment(s) across %d router(s)",
                stamped, len(by_router),
            )
    except Exception as exc:
        logger.error("[PORT-ATTR] Attribution run failed: %s", exc, exc_info=True)
    finally:
        _attribution_running = False

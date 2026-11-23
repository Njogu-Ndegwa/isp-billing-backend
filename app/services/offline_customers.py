"""Which paid customers on one router are offline right now, since when, and why.

"Paid" means the customer should have internet now: status ACTIVE and the
effective expiry (expiry + grace) still ahead. An expired customer is never
"offline" here; it is expired, and is left out.

"Online" is what the router says this minute, one connection, read-only:

* PPPoE: the username is in ``/ppp active``. When it is not, the secret's own
  ``last-logged-out`` / ``last-disconnect-reason`` (RouterOS 7) say since when
  and why.
* Hotspot: the customer's MAC is in ``/ip hotspot active``, or is a hotspot
  host that is bypassed or authorized (customers let in by IP binding).
* Static IP: the router's ARP entry for the IP is live (reachable, or complete
  on RouterOS 6), the IP has a hotspot session, or its speed queue is moving
  traffic. A stale, failed or missing ARP entry means the device is not
  answering.

When the router keeps no time (hotspot, static, RouterOS 6 PPPoE), "since" comes
from the session history the push reports leave in ``customer_events``, else from
the last hour the customer used any data. Neither found: ``offline_since`` is
null and ``since_note`` says why.

Database Session Discipline: customers are read and the session released before
the router is contacted; the history is read afterwards in its own short session.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import and_, func, select
from sqlalchemy.orm import selectinload

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerEvent,
    CustomerStatus,
    CustomerUsageBucket,
)
from app.services.customer_grace import effective_expiry, has_access_time
from app.services.customer_router_logs import (
    DISCONNECT_REASONS,
    MIN_PLAUSIBLE_YEAR,
    RouterClock,
    parse_log_time,
)
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

logger = logging.getLogger(__name__)

# How far back the session history and usage are searched for "since".
HISTORY_DAYS = 60

# ARP states (RouterOS 7 "status") that mean the device answered recently.
# "permanent" is a fixed entry and says nothing either way.
ARP_LIVE = {"reachable", "delay", "probe"}
ARP_DEAD_TEXT = {
    "stale": "the router's ARP entry for this IP is stale: the device has not answered recently",
    "failed": "the router's ARP entry for this IP failed: the device does not answer",
    "incomplete": "the router's ARP entry for this IP is incomplete: the device does not answer",
}

OFFLINE_EVENTS = ("session_disconnected", "device_offline")
ONLINE_EVENTS = ("session_connected", "session_reconnected", "device_online")


def _true(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes")


def _mac(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        out = normalize_mac_address(value)
    except Exception:
        return None
    return out if len(out) == 17 else None


def _ip(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip()
    return text.split("/")[0] if text else None


def utc_text(value: Optional[datetime]) -> Optional[str]:
    return value.replace(microsecond=0).isoformat() + "Z" if value else None


def connection_type_of(customer: Customer) -> str:
    plan = getattr(customer, "plan", None)
    if plan is not None and plan.connection_type is not None:
        return plan.connection_type.value
    if customer.pppoe_username:
        return ConnectionType.PPPOE.value
    if customer.static_ip:
        return ConnectionType.STATIC_IP.value
    return ConnectionType.HOTSPOT.value


# ---------------------------------------------------------------------------
# DB (short sessions)
# ---------------------------------------------------------------------------

async def load_paid_customers(db, router_id: int, now: datetime) -> list[dict]:
    """Plain rows for every customer on the router who should have internet now."""
    rows = (await db.execute(
        select(Customer)
        .options(selectinload(Customer.plan))
        .where(
            Customer.router_id == router_id,
            Customer.status == CustomerStatus.ACTIVE,
            Customer.expiry.isnot(None),
        )
    )).scalars().all()
    out = []
    for c in rows:
        if not has_access_time(c, now):
            continue
        out.append({
            "customer_id": c.id,
            "name": c.name,
            "connection_type": connection_type_of(c),
            "pppoe_username": c.pppoe_username,
            "mac_address": _mac(c.mac_address),
            "static_ip": _ip(c.static_ip),
            "plan": c.plan.name if c.plan else None,
            "expiry": c.expiry,
            "in_grace": bool(c.expiry <= now),
            "access_ends": effective_expiry(c),
        })
    return out


async def load_history(db, customer_ids: list[int], now: datetime) -> tuple[dict, dict]:
    """Latest session event and last data use per customer (one short read)."""
    if not customer_ids:
        return {}, {}
    since = now - timedelta(days=HISTORY_DAYS)
    latest: dict[int, tuple[str, datetime]] = {}
    sub = (
        select(CustomerEvent.customer_id, func.max(CustomerEvent.occurred_at).label("at"))
        .where(
            CustomerEvent.customer_id.in_(customer_ids),
            CustomerEvent.category == "session",
            CustomerEvent.event_type.in_(OFFLINE_EVENTS + ONLINE_EVENTS),
            CustomerEvent.occurred_at >= since,
        )
        .group_by(CustomerEvent.customer_id)
        .subquery()
    )
    for cid, event_type, at in (await db.execute(
        select(CustomerEvent.customer_id, CustomerEvent.event_type, CustomerEvent.occurred_at)
        .join(sub, and_(CustomerEvent.customer_id == sub.c.customer_id,
                        CustomerEvent.occurred_at == sub.c.at))
        .where(CustomerEvent.category == "session",
               CustomerEvent.event_type.in_(OFFLINE_EVENTS + ONLINE_EVENTS))
    )).all():
        # Two events in the same instant: an offline one wins (it is the later fact).
        if cid not in latest or event_type in OFFLINE_EVENTS:
            latest[cid] = (event_type, at)
    used: dict[int, datetime] = {}
    for cid, at in (await db.execute(
        select(CustomerUsageBucket.customer_id, func.max(CustomerUsageBucket.updated_at))
        .where(
            CustomerUsageBucket.customer_id.in_(customer_ids),
            CustomerUsageBucket.bucket_start >= since,
            (CustomerUsageBucket.upload_bytes + CustomerUsageBucket.download_bytes) > 0,
        )
        .group_by(CustomerUsageBucket.customer_id)
    )).all():
        if at is not None:
            used[cid] = at
    return latest, used


# ---------------------------------------------------------------------------
# Router (sync, run in a worker thread with no DB session open)
# ---------------------------------------------------------------------------

def _read(api: MikroTikAPI, command: str, proplist: list[str]) -> list[dict]:
    result = api.send_command_optimized(command, proplist=proplist)
    if not result.get("success"):
        # A list we could not read must not turn into "everyone is offline".
        raise RuntimeError(f"{command}: {result.get('error') or 'read failed'}")
    return [r for r in result.get("data") or [] if isinstance(r, dict)]


def read_presence_sync(router_info: dict, kinds: set[str]) -> dict:
    """One connection: the router clock plus the live lists the customers need."""
    api = MikroTikAPI(
        router_info["ip"], router_info["username"],
        router_info["password"], router_info["port"],
        timeout=20, connect_timeout=5,
    )
    if not api.connect():
        return {"error": "connect_failed"}
    fetched_utc = datetime.utcnow()
    try:
        tables: dict[str, Any] = {"clock": None}
        try:
            clock = api.send_command("/system/clock/print")
            if clock.get("success") and clock.get("data"):
                tables["clock"] = clock["data"][0]
        except Exception as exc:  # times degrade to "unknown", the list still holds
            logger.debug("router clock read failed: %s", exc)
        if "pppoe" in kinds:
            tables["ppp_secrets"] = _read(api, "/ppp/secret/print", [
                "name", "disabled", "last-logged-out", "last-disconnect-reason"])
            tables["ppp_active"] = _read(api, "/ppp/active/print", ["name", "address", "uptime"])
        if kinds & {"hotspot", "static_ip"}:
            try:
                tables["hs_active"] = _read(api, "/ip/hotspot/active/print", [
                    "user", "mac-address", "address", "uptime"])
                tables["hs_hosts"] = _read(api, "/ip/hotspot/host/print", [
                    "mac-address", "address", "authorized", "bypassed", "idle-time"])
            except RuntimeError:
                if "hotspot" in kinds:
                    raise
                tables["hs_active"], tables["hs_hosts"] = [], []  # a static-only router may have no hotspot
        if "static_ip" in kinds:
            tables["arp"] = _read(api, "/ip/arp/print", [
                "address", "mac-address", "status", "complete", "disabled", "dynamic"])
            tables["queues"] = _read(api, "/queue/simple/print", ["name", "target", "rate", "disabled"])
        return {"success": True, "fetched_utc": fetched_utc, **tables}
    except Exception as exc:
        logger.warning("offline-customers router read failed: %s", exc)
        return {"error": "read_failed", "detail": str(exc)}
    finally:
        api.disconnect()


# ---------------------------------------------------------------------------
# Classification (pure)
# ---------------------------------------------------------------------------

def _rate_moving(rate: Any) -> bool:
    for part in str(rate or "").split("/"):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits and int(digits) > 0:
            return True
    return False


def _router_logout_utc(raw: str, clock: RouterClock) -> Optional[datetime]:
    text = (raw or "").strip()
    if not text or not clock.trusted:
        return None
    local = parse_log_time(text, clock)
    if local is None or local.year < MIN_PLAUSIBLE_YEAR:
        return None
    return clock.to_utc(local)


def classify(customers: list[dict], tables: dict) -> tuple[list[dict], list[dict]]:
    """Split paid customers into (online, offline) using the router's lists.

    Offline rows carry ``router_since`` (UTC, from the router), ``reason_code``
    and ``reason`` where the router gives one.
    """
    fetched = tables.get("fetched_utc") or datetime.utcnow()
    clock = RouterClock.from_clock_print(tables.get("clock"), fetched)

    secrets = {s.get("name"): s for s in tables.get("ppp_secrets") or [] if s.get("name")}
    ppp_online = {a.get("name") for a in tables.get("ppp_active") or [] if a.get("name")}
    hs_active_macs = {_mac(a.get("mac-address")) for a in tables.get("hs_active") or []}
    hs_active_ips = {_ip(a.get("address")) for a in tables.get("hs_active") or []}
    host_live_macs = {
        _mac(h.get("mac-address")) for h in tables.get("hs_hosts") or []
        if _true(h.get("bypassed")) or _true(h.get("authorized"))
    }
    arp_by_ip: dict[str, dict] = {}
    for row in tables.get("arp") or []:
        ip = _ip(row.get("address"))
        if ip and not _true(row.get("disabled")):
            # Prefer a live entry when the same IP appears twice.
            if ip not in arp_by_ip or str(row.get("status") or "").lower() in ARP_LIVE:
                arp_by_ip[ip] = row
    moving_ips = {
        _ip(q.get("target")) for q in tables.get("queues") or []
        if not _true(q.get("disabled")) and _rate_moving(q.get("rate"))
    }

    online, offline = [], []
    for c in customers:
        kind = c["connection_type"]
        row = {**c, "router_since": None, "reason_code": None, "reason": None}
        if kind == "pppoe":
            username = c.get("pppoe_username")
            secret = secrets.get(username) if username else None
            if username and username in ppp_online:
                online.append(row)
                continue
            if not username:
                row["reason_code"] = "no_pppoe_username"
                row["reason"] = "this customer has no PPPoE username"
            elif secret is None:
                row["reason_code"] = "no_pppoe_secret"
                row["reason"] = "the router has no PPPoE account for this customer, so they cannot log in"
            elif _true(secret.get("disabled")):
                row["reason_code"] = "pppoe_secret_disabled"
                row["reason"] = "the customer's PPPoE account is disabled on the router"
            else:
                code = (secret.get("last-disconnect-reason") or "").strip()
                if code:
                    row["reason_code"] = code
                    row["reason"] = DISCONNECT_REASONS.get(code, code.replace("-", " "))
                row["router_since"] = _router_logout_utc(secret.get("last-logged-out") or "", clock)
            offline.append(row)
        elif kind == "static_ip":
            ip = c.get("static_ip")
            arp = arp_by_ip.get(ip) if ip else None
            status = str((arp or {}).get("status") or "").strip().lower()
            live = bool(ip) and (
                ip in hs_active_ips
                or ip in moving_ips
                or status in ARP_LIVE
                # RouterOS 6 has no status: a complete dynamic entry is the best it offers
                or (arp is not None and not status and _true(arp.get("dynamic"))
                    and _true(arp.get("complete", "true")))
            )
            if live:
                online.append(row)
                continue
            if not ip:
                row["reason_code"] = "no_static_ip"
                row["reason"] = "this customer has no static IP set"
            elif arp is None:
                row["reason_code"] = "no_arp_entry"
                row["reason"] = "the router does not see any device on this IP"
            elif status == "permanent" or not status:
                row["reason_code"] = "no_traffic"
                row["reason"] = ("no traffic on this IP right now, and the router's ARP entry for it is "
                                 "fixed, so the router cannot tell whether the device is there or idle")
            else:
                row["reason_code"] = f"arp_{status}"
                row["reason"] = ARP_DEAD_TEXT.get(status, f"the router's ARP entry for this IP is {status}")
            offline.append(row)
        else:  # hotspot
            mac = c.get("mac_address")
            if mac and (mac in hs_active_macs or mac in host_live_macs):
                online.append(row)
                continue
            if not mac:
                row["reason_code"] = "no_mac"
                row["reason"] = "this customer has no device MAC"
            offline.append(row)
    return online, offline


def _since(row: dict, latest: dict, used: dict) -> tuple[Optional[datetime], Optional[str], str]:
    """(offline_since, since_source, since_note) for one offline customer."""
    if row.get("router_since"):
        return row["router_since"], "router", "the router's own record of the last logout"
    event = latest.get(row["customer_id"])
    if event and event[0] in OFFLINE_EVENTS:
        return event[1], "session_history", "when the router's reports stopped showing the session"
    last_use = used.get(row["customer_id"])
    if last_use:
        return last_use, "last_traffic", (
            "no exact disconnect time is recorded; this is the last time any data use "
            "was recorded, so offline since then or later")
    if event and event[0] in ONLINE_EVENTS:
        return None, None, ("the session history shows the last connect but not the drop, "
                            "and the router keeps no time for it")
    if row["connection_type"] == "pppoe":
        note = "the router has no last-logout time (RouterOS 6, or never connected since the router restarted)"
    else:
        note = "the router keeps no time for this connection type and no history was recorded"
    return None, None, f"unknown: {note}"


def build_report(router_id: int, router_name: str, online: list[dict], offline: list[dict],
                 latest: dict, used: dict, checked_at: datetime) -> dict:
    rows = []
    for row in offline:
        since, source, note = _since(row, latest, used)
        out = {
            "customer_id": row["customer_id"],
            "name": row["name"],
            "connection_type": row["connection_type"],
            "offline_since": utc_text(since),
            "since_source": source,
            "since_note": note,
            "reason_code": row["reason_code"],
            "reason": row["reason"] or (
                "the router does not record why a hotspot device left" if row["connection_type"] == "hotspot"
                else None),
            "plan": row["plan"],
            "expiry": utc_text(row["expiry"]),
            "in_grace": row["in_grace"],
        }
        if row["connection_type"] == "pppoe":
            out["pppoe_username"] = row["pppoe_username"]
        elif row["connection_type"] == "static_ip":
            out["static_ip"] = row["static_ip"]
        else:
            out["mac_address"] = row["mac_address"]
        rows.append(out)
    # Most recently gone first; unknown times last.
    known = [r for r in rows if r["offline_since"]]
    known.sort(key=lambda r: r["offline_since"], reverse=True)
    rows = known + [r for r in rows if not r["offline_since"]]

    by_type: dict[str, dict] = {}
    for kind, bucket in (("online", online), ("offline", offline)):
        for row in bucket:
            t = by_type.setdefault(row["connection_type"], {"paid": 0, "online": 0, "offline": 0})
            t["paid"] += 1
            t[kind] += 1
    return {
        "router_id": router_id,
        "router_name": router_name,
        "checked_at": utc_text(checked_at),
        "live": True,
        "counts": {
            "paid": len(online) + len(offline),
            "online": len(online),
            "offline": len(offline),
            "by_type": by_type,
        },
        "offline": rows,
        "note": ("Paid = active and not expired. Offline = paid but not connected to the router right now. "
                 "Expired customers are not counted or listed."),
    }

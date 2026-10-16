"""Read-only, cached live audit for expired customers still in hotspot sessions.

The admin dashboard starts a scan at most every 15 minutes. Router reads run
outside DB transactions and with a small concurrency limit; failed routers are
reported as unverified, never silently counted as clean.
"""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import text

from app.db.database import async_session
from app.services.mikrotik_api import LANE_BACKGROUND, MikroTikAPI

SCAN_INTERVAL = timedelta(minutes=15)
MAX_ROUTER_READS = 3
_task: asyncio.Task | None = None
_snapshot = {
    "running": False, "started_at": None, "completed_at": None,
    "candidate_routers": 0, "checked_routers": 0, "failed_router_ids": [],
    "customers": [], "error": None,
}

_CANDIDATES = text("""
    SELECT c.id, c.name, c.router_id, c.user_id,
           CAST(c.status AS TEXT) status, c.expiry,
           upper(c.mac_address) mac, r.name router_name,
           r.ip_address, r.username, r.password, coalesce(r.port, 8728) port,
           coalesce(nullif(u.business_name, ''), nullif(u.organization_name, ''), u.email) reseller_name
    FROM customers c JOIN routers r ON r.id = c.router_id
                     JOIN users u ON u.id = c.user_id
    WHERE r.last_status IS TRUE AND c.status IN ('ACTIVE', 'INACTIVE')
      AND c.mac_address IS NOT NULL
      AND c.expiry + coalesce(c.grace_period_minutes, 0) * interval '1 minute'
          < (now() AT TIME ZONE 'UTC') - interval '3 minutes'
      AND NOT EXISTS (
          SELECT 1 FROM customers other
          WHERE other.router_id = c.router_id
            AND upper(other.mac_address) = upper(c.mac_address)
            AND other.id <> c.id AND other.status IN ('ACTIVE', 'PENDING')
            AND other.expiry + coalesce(other.grace_period_minutes, 0) * interval '1 minute'
                > (now() AT TIME ZONE 'UTC')
      )
    ORDER BY r.id, c.id
""")


def _utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _scan_router(router: dict, rows: list[dict]) -> list[dict] | None:
    api = MikroTikAPI(
        router["ip_address"], router["username"], router["password"], router["port"],
        timeout=12, connect_timeout=5, lane=LANE_BACKGROUND,
    )
    if not api.connect():
        return None
    try:
        active_reply = api.send_command_optimized(
            "/ip/hotspot/active/print", proplist=["mac-address", "user", "uptime"])
        host_reply = api.send_command_optimized(
            "/ip/hotspot/host/print", proplist=["mac-address", "authorized"])
        if not active_reply.get("success") or not host_reply.get("success"):
            return None
        active = {str(a.get("mac-address", "")).upper(): a
                  for a in active_reply.get("data") or []}
        authorized = {str(h.get("mac-address", "")).upper()
                      for h in host_reply.get("data") or []
                      if str(h.get("authorized", "")).lower() == "true"}
        matched = [row for row in rows if row["mac"] in active and row["mac"] in authorized]
        if not matched:
            return []
        users_reply = api.send_command_optimized(
            "/ip/hotspot/user/print", proplist=["name"])
        users = {str(u.get("name", "")).upper()
                 for u in users_reply.get("data") or []} if users_reply.get("success") else set()
        output = []
        for row in matched:
            mac = row["mac"]
            output.append({
                "customer_id": row["id"], "customer_name": row["name"],
                "router_id": row["router_id"], "router_name": row["router_name"],
                "reseller_id": row["user_id"], "reseller_name": row["reseller_name"],
                "status": row["status"], "expiry": row["expiry"].isoformat(),
                "mac": mac, "uptime": active[mac].get("uptime"),
                "hotspot_user_present": (mac in users or mac.replace(":", "") in users)
                                        if users_reply.get("success") else None,
            })
        return output
    finally:
        api.disconnect()


async def _run_scan() -> None:
    _snapshot.update(running=True, started_at=_utc_now(), error=None,
                     candidate_routers=0, checked_routers=0,
                     failed_router_ids=[])
    try:
        from app.services.mikrotik_background import _background_db_pool_is_busy

        if _background_db_pool_is_busy("EXPIRED-ONLINE-AUDIT"):
            _snapshot["error"] = "Database busy; live scan deferred"
            return
        async with async_session() as db:
            rows = [dict(row) for row in (await db.execute(_CANDIDATES)).mappings().all()]
            await db.commit()
        by_router = defaultdict(list)
        for row in rows:
            by_router[row["router_id"]].append(row)
        _snapshot["candidate_routers"] = len(by_router)
        gate = asyncio.Semaphore(MAX_ROUTER_READS)
        found: list[dict] = []

        async def one(router_id: int, candidates: list[dict]):
            async with gate:
                try:
                    result = await asyncio.to_thread(_scan_router, candidates[0], candidates)
                except Exception:
                    result = None
                if result is None:
                    _snapshot["failed_router_ids"].append(router_id)
                else:
                    _snapshot["checked_routers"] += 1
                    found.extend(result)

        await asyncio.gather(*(one(rid, group) for rid, group in by_router.items()))
        matches = found
        if matches:
            ids = ",".join(str(int(row["customer_id"])) for row in matches)
            async with async_session() as db:
                valid_result = await db.execute(text(f"""
                    SELECT c.id FROM customers c WHERE c.id IN ({ids})
                      AND c.status IN ('ACTIVE', 'INACTIVE')
                      AND c.expiry + coalesce(c.grace_period_minutes, 0) * interval '1 minute'
                          < (now() AT TIME ZONE 'UTC') - interval '3 minutes'
                      AND NOT EXISTS (
                          SELECT 1 FROM customers other
                          WHERE other.router_id = c.router_id
                            AND upper(other.mac_address) = upper(c.mac_address)
                            AND other.id <> c.id AND other.status IN ('ACTIVE', 'PENDING')
                            AND other.expiry + coalesce(other.grace_period_minutes, 0) * interval '1 minute'
                                > (now() AT TIME ZONE 'UTC')
                      )
                """))
                valid = set(valid_result.scalars().all())
                await db.commit()
            matches = [row for row in matches if row["customer_id"] in valid]
        matches.sort(key=lambda row: (row["router_id"], row["customer_id"]))
        _snapshot["customers"] = matches
        _snapshot["completed_at"] = _utc_now()
    except Exception as exc:
        _snapshot["error"] = str(exc)[:200]
    finally:
        _snapshot["running"] = False


def get_snapshot(*, start_if_stale: bool = True) -> dict:
    global _task
    completed = _snapshot["completed_at"]
    stale = (completed is None or
             datetime.utcnow() - datetime.fromisoformat(completed.removesuffix("Z")) >= SCAN_INTERVAL)
    if _snapshot["error"] and _snapshot["started_at"]:
        last_attempt = datetime.fromisoformat(_snapshot["started_at"].removesuffix("Z"))
        if datetime.utcnow() - last_attempt < timedelta(minutes=5):
            stale = False
    if start_if_stale and stale and (_task is None or _task.done()):
        _snapshot["running"] = True
        _task = asyncio.get_running_loop().create_task(_run_scan())
    return {**_snapshot, "customers": list(_snapshot["customers"]),
            "failed_router_ids": list(_snapshot["failed_router_ids"]),
            "count": len(_snapshot["customers"])}

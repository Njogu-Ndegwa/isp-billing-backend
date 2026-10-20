"""Explicitly selected native counter streams with a router-local fallback.

Only the usage reporter timer is paused. Source, access, expiry, check-in and
watchdog settings are preserved. Enrollment is off unless IDs AND reviewed
reporter hashes are configured. This module never enrolls a fleet implicitly.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.config import settings
from app.db.database import async_session
from app.db.models import Router
from app.services.native_router_api import (
    AsyncNativeAPI, INVENTORY_TABLES, NativeApiError, NativeTables, STREAM_TABLES,
)
from app.services.native_router_counters import native_api_to_v3
from app.services.native_router_lease import lease_sources, touch_lease
from app.services.native_router_handoff import (
    GUARD_COMMENT, acquire_claim, guard_marker, release_claim, validate_handoff,
)
from app.services.usage_push_auth import derive_router_token

logger = logging.getLogger(__name__)
_tasks: dict[int, asyncio.Task] = {}
REPORTER = "bitwave-usage-push"
_stopping = False


class SlowInventoryCycle:
    """Spread a full topology refresh over five minutes, with no catch-up burst."""

    def __init__(self, started):
        self.names = (*INVENTORY_TABLES, "interfaces")
        self.index, self.next_at = 0, started + 15

    def take_due(self, now):
        if now < self.next_at:
            return None
        name = self.names[self.index]
        self.index = (self.index + 1) % len(self.names)
        self.next_at = now + 50
        return name


def enrollment(ids: str, hashes: str) -> dict[int, str]:
    if not ids.strip():
        return {}
    entries = ids.split(",")
    if any(not re.fullmatch(r"[1-9][0-9]*", entry.strip()) for entry in entries):
        raise ValueError("Invalid native stream IDs")
    selected = {int(entry.strip()) for entry in entries}
    if len(selected) != len(entries) or len(selected) > 8:
        raise ValueError("Native stream enrollment limit exceeded")
    reviewed = {}
    for entry in hashes.split(","):
        rid, separator, digest = entry.strip().partition(":")
        if (
            not separator
            or not rid.isdecimal()
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise ValueError("Invalid native reporter hash")
        if int(rid) in reviewed:
            raise ValueError("Duplicate native reporter hash")
        reviewed[int(rid)] = digest
    if reviewed.keys() != selected:
        raise ValueError("Every selected native reporter needs a reviewed hash")
    return reviewed


async def load_router(router_id: int) -> dict | None:
    # Release the transaction before opening a socket or waiting on a router.
    async with async_session() as db:
        row = (
            (
                await db.execute(
                    select(
                        Router.id,
                        Router.identity,
                        Router.ip_address,
                        Router.username,
                        Router.password,
                        Router.port,
                    ).where(Router.id == router_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        await db.commit()
    return dict(row) if row else None


class StreamSession:
    def __init__(self, info: dict, expected_hash: str, api):
        self.info, self.expected_hash, self.api = info, expected_hash, api
        self.original = None
        self.cfg = None
        self.claimed = False
        self.guard_created = False
        self.handed_off = False
        self.takeover = None
        self.last_accepted = None
        self.owner = uuid.uuid4().hex
        self.guard_comment = (
            GUARD_COMMENT + ":" + str(int(time.time())) + ":" + self.owner
        )

    async def read(self, path: str, properties: str, query=()):
        return (await self.api.rpc(path, {".proplist": properties}, **({"query": query} if query else {})))["rows"]

    async def timer(self):
        found = [
            s
            for s in await self.read(
                "/system/scheduler/print", ".id,name,disabled,interval,on-event,comment"
            )
            if s["name"] == REPORTER
        ]
        if len(found) != 1:
            raise RuntimeError("Native reporter timer is not unique")
        return found[0]

    async def preflight(self):
        identity = (await self.read("/system/identity/print", "name"))[0]["name"]
        if identity != self.info["identity"]:
            raise RuntimeError("Native router identity mismatch")
        resource = (await self.read("/system/resource/print", "board-name,version"))[0]
        version = re.match(
            r"^7\.(\d+)(?:\.(\d+))?(?:\s|$)", resource.get("version", "")
        )
        if (
            resource.get("board-name") != "RB951Ui-2HnD"
            or not version
            or tuple(int(v or 0) for v in version.groups()) < (19, 6)
        ):
            raise RuntimeError("Native stream board/version is not enrolled")
        scripts = [
            s
            for s in await self.read(
                "/system/script/print", "name,source", ("?name=" + REPORTER,)
            )
            if s["name"] == REPORTER
        ]
        if len(scripts) != 1:
            raise RuntimeError("Native reporter script is not unique")
        source = scripts[0]["source"]
        if hashlib.sha256(source.encode()).hexdigest() != self.expected_hash:
            raise RuntimeError("Native reporter source changed since review")
        match = re.search(r':local tok "([a-f0-9]{32})"', source)
        if not match or match[1] != derive_router_token(identity):
            raise RuntimeError("Native reporter authentication mismatch")
        self.original = await self.timer()
        if self.original["disabled"] != "false":
            if not settings.NATIVE_STREAM_GRACEFUL_HANDOFF:
                raise RuntimeError("Native reporter is already paused")
            cfg = lease_sources(self.info["id"], self.original["interval"])
            guards = [g for g in await self.read(
                "/system/scheduler/print", ".id,name,disabled,on-event,comment"
            ) if g.get("name") == cfg["name"]]
            leases = await self.read(
                "/ip/firewall/address-list/print", ".id,list,address,dynamic,comment",
                ("?list=" + cfg["list"],),
            )
            if len(guards) != 1:
                raise RuntimeError("Native handover guard is not unique")
            validate_handoff(guards[0], self.original, cfg, leases)
            self.takeover = guards[0]
            # The prior owner deliberately paused an originally enabled timer.
            # Its genuine-outage fallback still restores that original state.
            self.original = {**self.original, "disabled": "false"}
        self.cfg = lease_sources(self.info["id"], self.original["interval"])
        self.cfg["owner"] = self.owner
        leases = [] if self.takeover else [
            r
            for r in await self.read("/ip/firewall/address-list/print", "list")
            if r.get("list") == self.cfg["list"]
        ]
        if leases:
            raise RuntimeError("Another native owner has a live RAM lease")
        for guard in await self.read(
            "/system/scheduler/print", ".id,name,on-event,comment"
        ):
            if guard["name"] != self.cfg["name"]:
                continue
            if self.takeover:
                continue
            # Only retire an expired guard generated by this implementation.
            prior = re.search(r"interval=([0-9wdhms:.]+)", guard.get("on-event", ""))
            marker = guard_marker(guard.get("comment", ""))
            if (
                not marker
                or not prior
                or guard["on-event"]
                != lease_sources(self.info["id"], prior[1])["guard"]
            ):
                raise RuntimeError("Unexpected native fallback timer")
            if time.time() - marker["created"] < 240:
                raise RuntimeError("Another native owner is claiming this reporter")
            await self.api.rpc("/system/scheduler/remove", {".id": guard[".id"]})
        interfaces = await self.read("/interface/print", ".id,name")
        names = {r["name"] for r in interfaces}
        wan = None
        for route in await self.read(
            "/ip/route/print", "dst-address,active,immediate-gw,gateway-status,gateway"
        ):
            if route.get("dst-address") != "0.0.0.0/0" or route.get("active") != "true":
                continue
            candidates = [
                route.get("immediate-gw", "").split("%")[-1],
                route.get("gateway", "").split("%")[-1],
            ]
            match = re.search(r"via\s+(\S+)", route.get("gateway-status", ""))
            if match:
                candidates.insert(0, match[1])
            wan = next((name for name in candidates if name in names), None)
            if wan:
                break
        return wan or ("ether1" if "ether1" in names else None)

    async def claim(self):
        if self.takeover:
            await self.claim_handoff()
            return
        # The guard is created disabled; a live RAM lease exists before either
        # pausing the reporter or enabling the guard. Heartbeats do not write
        # scheduler source/deadlines to flash.
        await self.api.rpc(
            "/system/scheduler/add",
            {
                "name": self.cfg["name"],
                "disabled": "yes",
                "interval": "30s",
                "start-time": "startup",
                "on-event": self.cfg["guard"],
                "policy": "read,write,policy,test",
                "comment": self.guard_comment,
            },
        )
        self.guard_created = True
        await touch_lease(self.api, self.cfg)
        await self.api.rpc(
            "/system/scheduler/set", {".id": self.original[".id"], "disabled": "yes"}
        )
        self.claimed = True
        guard = next(
            g
            for g in await self.read("/system/scheduler/print", ".id,name")
            if g["name"] == self.cfg["name"]
        )
        await self.api.rpc(
            "/system/scheduler/set", {".id": guard[".id"], "disabled": "no"}
        )
        for _ in range(45):
            if not any(
                j.get("script") == REPORTER
                for j in await self.read("/system/script/job/print", "script")
            ):
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Native reporter did not drain")
        await asyncio.sleep(8)

    async def claim_handoff(self):
        claim = await acquire_claim(self.api, self.info["id"], self.owner)
        try:
            current = await self.timer()
            guards = [g for g in await self.read(
                "/system/scheduler/print", ".id,name,disabled,on-event,comment"
            ) if g.get("name") == self.cfg["name"]]
            leases = await self.read(
                "/ip/firewall/address-list/print", ".id,list,address,dynamic,comment",
                ("?list=" + self.cfg["list"],),
            )
            if (current.get(".id") != self.original[".id"]
                    or current.get("interval") != self.original["interval"]
                    or len(guards) != 1):
                raise RuntimeError("Native handover changed during claim")
            validate_handoff(guards[0], current, self.cfg, leases,
                             expected_comment=self.takeover["comment"])
            used = {row["address"] for row in leases}
            address = next("127.255.0." + str(i) for i in range(1, 255)
                           if "127.255.0." + str(i) not in used)
            await self.api.rpc("/ip/firewall/address-list/add", {
                "list": self.cfg["list"], "address": address,
                "timeout": str(self.cfg["seconds"]) + "s",
                "comment": "Bitwave native API RAM lease:" + self.owner,
            })
            # Seed the successor lease before changing the guard's owner or
            # retiring the predecessor lease. The reporter stays paused.
            await self.api.rpc("/system/scheduler/set", {
                ".id": guards[0][".id"], "comment": self.guard_comment,
            })
            self.guard_created = self.claimed = True
            for row in leases:
                await self.api.rpc("/ip/firewall/address-list/remove", {".id": row[".id"]})
            await self.verify_ownership()
        finally:
            await release_claim(self.api, claim)

    async def handoff(self):
        """Leave a bounded live guard for the successor during clean shutdown."""
        if not self.guard_created or not self.claimed or self.api.failure:
            return
        if self.last_accepted is None or time.monotonic() - self.last_accepted >= 120:
            raise RuntimeError("Native handover has no fresh ingestion acknowledgement")
        guard = await self.verify_ownership()
        await touch_lease(self.api, self.cfg)
        comment = GUARD_COMMENT + ":handoff:" + str(int(time.time())) + ":" + self.owner
        await self.api.rpc("/system/scheduler/set", {".id": guard[".id"], "comment": comment})
        self.guard_comment = comment
        self.handed_off = True

    async def verify_ownership(self):
        current = await self.timer()
        if current[".id"] != self.original[".id"] or current["disabled"] != "true":
            raise RuntimeError("Native report ownership changed")
        guards = await self.read(
            "/system/scheduler/print", ".id,name,disabled,comment,on-event"
        )
        guards = [g for g in guards if g["name"] == self.cfg["name"]]
        if (len(guards) != 1 or guards[0]["disabled"] != "false"
                or guards[0].get("comment") != self.guard_comment
                or guards[0].get("on-event") != self.cfg["guard"]):
            raise RuntimeError("Native fallback relinquished ownership")
        return guards[0]

    async def release(self):
        if not self.guard_created or self.handed_off:
            return
        # A broken connection leaves the RAM lease and guard to restore the
        # reporter. No blind attempt is made through an unusable socket.
        if self.api.failure:
            return
        guards = [
            g
            for g in await self.read(
                "/system/scheduler/print", ".id,name,on-event,comment"
            )
            if g["name"] == self.cfg["name"]
            and g.get("comment") == self.guard_comment
            and g.get("on-event") == self.cfg["guard"]
        ]
        if self.claimed and guards:
            current = await self.timer()
            if current[".id"] == self.original[".id"] and current["disabled"] == "true":
                await self.api.rpc(
                    "/system/scheduler/set",
                    {
                        ".id": current[".id"],
                        "disabled": self.original["disabled"],
                        "interval": self.original["interval"],
                    },
                )
        for guard in guards:
            await self.api.rpc("/system/scheduler/remove", {".id": guard[".id"]})
        for row in await self.read(
            "/ip/firewall/address-list/print", ".id,list,dynamic,comment"
        ):
            if (
                row.get("list") == self.cfg["list"]
                and row.get("dynamic") == "true"
                and row.get("comment") == "Bitwave native API RAM lease:" + self.owner
            ):
                await self.api.rpc(
                    "/ip/firewall/address-list/remove", {".id": row[".id"]}
                )


async def stream_router(router_id: int, expected_hash: str):
    from app.api.usage_push_routes import HostReportIn, UsageReportIn

    if (
        "sampled_at" not in HostReportIn.model_fields
        or "sampled_at" not in UsageReportIn.model_fields
    ):
        raise RuntimeError("Native counter observation-time contract is unavailable")
    info = await load_router(router_id)
    if not info or not re.fullmatch(
        r"10\.0\.\d{1,3}\.\d{1,3}", info["ip_address"] or ""
    ):
        raise RuntimeError("Native router has no approved management address")
    api = AsyncNativeAPI(
        info["ip_address"], info["username"], info["password"], info["port"] or 8728
    )
    session = StreamSession(info, expected_hash, api)
    handoff_on_exit = False
    try:
        await api.connect()
        wan = await session.preflight()
        if wan is None:
            raise RuntimeError("Native WAN interface is unavailable")
        await session.claim()
        tables = NativeTables(api, interval=60, wan=wan)
        await tables.bootstrap()
        started = time.monotonic()
        next_post, next_membership = 0, started + 30
        inventory = SlowInventoryCycle(started)
        last_accepted, last_touch = started, 0
        async with httpx.AsyncClient(timeout=45, follow_redirects=False) as http:
            while True:
                now = time.monotonic()
                if api.failure:
                    raise RuntimeError("Native API connection ended")
                if now - last_touch >= 45 and now - last_accepted < 120:
                    await session.verify_ownership()
                    await touch_lease(api, session.cfg)
                    last_touch = time.monotonic()
                for name in STREAM_TABLES:
                    if any(group["tag"] in api.ended for group in tables.groups[name]):
                        await tables.refresh(name)
                if now >= next_membership:
                    for name in ("hosts", "queues", "ppp"):
                        await tables.refresh(name)
                    next_membership = time.monotonic() + 30
                name = None if tables.inventory_scan is not None else inventory.take_due(time.monotonic())
                if name is not None or tables.inventory_scan is not None:
                    inventory_name = name or tables.inventory_scan["table"]
                    try:
                        if name is None:
                            await tables.advance_inventory()
                        else:
                            await tables.refresh(name)
                    except (NativeApiError, TimeoutError):
                        if inventory_name not in INVENTORY_TABLES or api.failure:
                            raise
                        # Optional topology must not take down healthy billing
                        # feeds or be retried every five seconds.
                        logger.warning("[NATIVE-STREAM] router=%s inventory=%s deferred",
                                       router_id, inventory_name)
                if now >= next_post:
                    await session.verify_ownership()
                    body = native_api_to_v3(
                        info["identity"],
                        tables.snapshot(),
                        wan,
                        queue_order=tables.orders.get("queues"),
                        observed=tables.observed,
                    )
                    # Count sessions directly: one MAC can own multiple host IP
                    # counter entries, and bypass hosts are not active logins.
                    count = await api.rpc(
                        "/ip/hotspot/active/print",
                        {"count-only": "", ".proplist": ".id"},
                    )
                    body["router"]["hotspot_active"] = int(count["done"]["ret"])
                    for item in body["hosts"] + body["reports"]:
                        age = (
                            datetime.now(timezone.utc)
                            - datetime.fromisoformat(item["sampled_at"])
                        ).total_seconds()
                        if not 0 <= age < 180:
                            raise RuntimeError(
                                "Native billing observations became stale"
                            )
                    response = await http.post(
                        "http://127.0.0.1:8000/api/router/usage-push",
                        json=body,
                        headers={
                            "Authorization": "Bearer "
                            + derive_router_token(info["identity"]),
                            "X-Bitwave-Push-Channel": "tunnel",
                        },
                    )
                    if response.status_code in (429, 503):
                        retry = response.headers.get("Retry-After", "30")
                        next_post = time.monotonic() + min(
                            90, max(5, int(retry) if retry.isdecimal() else 30)
                        )
                    else:
                        response.raise_for_status()
                        tables.inventory_accepted(body)
                        last_accepted = time.monotonic()
                        session.last_accepted = last_accepted
                        next_post = last_accepted + min(
                            120,
                            max(
                                30, int(response.json().get("next_push_seconds") or 60)
                            ),
                        )
                if time.monotonic() - last_accepted > 180:
                    raise RuntimeError("Native ingestion remained unavailable")
                await asyncio.sleep(1 if tables.inventory_scan is not None else 5)
    except asyncio.CancelledError:
        handoff_on_exit = _stopping and settings.NATIVE_STREAM_GRACEFUL_HANDOFF
        raise
    finally:
        try:
            if handoff_on_exit:
                try:
                    await asyncio.wait_for(session.handoff(), 10)
                except Exception:
                    await asyncio.wait_for(session.release(), 10)
            else:
                await asyncio.wait_for(session.release(), 10)
        finally:
            await api.close()


async def _supervise(router_id: int, expected_hash: str):
    await asyncio.sleep(15)
    while True:
        try:
            await stream_router(router_id, expected_hash)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Neither RouterOS errors nor HTTP response bodies are logged: they
            # can contain customer identifiers or echoed script credentials.
            logger.warning(
                "[NATIVE-STREAM] router %s stopped (%s); reporter fallback retained",
                router_id,
                type(exc).__name__,
            )
        await asyncio.sleep(60)


def start() -> None:
    global _stopping
    _stopping = False
    if (
        settings.SHADOW_MODE
        or not settings.RUN_SCHEDULER
        or not settings.SCHEDULER_ENABLED
    ):
        return
    selected = enrollment(
        settings.NATIVE_STREAM_ROUTER_IDS, settings.NATIVE_STREAM_REPORTER_HASHES
    )
    for router_id, digest in selected.items():
        if router_id not in _tasks:
            _tasks[router_id] = asyncio.create_task(_supervise(router_id, digest))


async def stop() -> None:
    global _stopping
    _stopping = True
    tasks = list(_tasks.values())
    _tasks.clear()
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

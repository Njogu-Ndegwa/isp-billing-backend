"""Bounded native API subscriptions; no router writes in this module."""

import asyncio
import datetime
import itertools
import re
import time

TABLES = {
    "hosts": (
        "/ip/hotspot/host/print",
        ".id,mac-address,address,authorized,bypassed,bytes-in,bytes-out,idle-time,uptime",
    ),
    "queues": ("/queue/simple/print", ".id,name,bytes,target,max-limit,disabled"),
    "ppp": ("/ppp/active/print", ".id,name,address,uptime,caller-id"),
    "resource": (
        "/system/resource/print",
        "cpu-load,free-memory,total-memory,free-hdd-space,total-hdd-space,uptime,version,board-name",
    ),
    "interfaces": (
        "/interface/print",
        ".id,name,type,running,disabled,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,link-downs,last-link-up-time",
    ),
    "bridge_hosts": (
        "/interface/bridge/host/print",
        ".id,mac-address,on-interface,local",
    ),
    "bindings": ("/ip/hotspot/ip-binding/print", ".id,mac-address,type,disabled"),
    "leases": (
        "/ip/dhcp-server/lease/print",
        ".id,mac-address,address,host-name,status,comment",
    ),
    "neighbors": (
        "/ip/neighbor/print",
        ".id,mac-address,identity,board,platform,version,interface,address",
    ),
    "bridge_ports": ("/interface/bridge/port/print", ".id,interface,bridge"),
}

INVENTORY_TABLES = ("bridge_hosts", "bindings", "leases", "neighbors", "bridge_ports")
STREAM_TABLES = tuple(name for name in TABLES if name not in INVENTORY_TABLES)


def encode_word(value):
    data = value.encode()
    n = len(data)
    if n < 0x80:
        prefix = bytes([n])
    elif n < 0x4000:
        prefix = (n | 0x8000).to_bytes(2, "big")
    elif n < 0x200000:
        prefix = (n | 0xC00000).to_bytes(3, "big")
    elif n < 0x10000000:
        prefix = (n | 0xE0000000).to_bytes(4, "big")
    else:
        prefix = b"\xf0" + n.to_bytes(4, "big")
    return prefix + data


class NativeApiError(Exception):
    pass


class AsyncNativeAPI:
    def __init__(self, host, user, password, port=8728):
        self.host, self.user, self.password, self.port = host, user, password, port
        self.pending = {}
        self.subscribers = {}
        self.ended = {}
        self.counter = itertools.count()
        self.write_lock = asyncio.Lock()
        self.reader = None
        self.writer = None
        self.task = None
        self.last_received = 0
        self.failure = None

    async def sentence(self):
        result = []
        total = 0
        while True:
            first = (await self.reader.readexactly(1))[0]
            if first < 0x80:
                n = first
            elif first < 0xC0:
                n = ((first & 0x3F) << 8) | int.from_bytes(
                    await self.reader.readexactly(1), "big"
                )
            elif first < 0xE0:
                n = ((first & 0x1F) << 16) | int.from_bytes(
                    await self.reader.readexactly(2), "big"
                )
            elif first < 0xF0:
                n = ((first & 0x0F) << 24) | int.from_bytes(
                    await self.reader.readexactly(3), "big"
                )
            elif first == 0xF0:
                n = int.from_bytes(await self.reader.readexactly(4), "big")
            else:
                raise NativeApiError("Unsupported native control word")
            if not n:
                return result
            total += n
            if n > 1_000_000 or total > 2_000_000:
                raise NativeApiError("Native sentence size exceeded")
            result.append((await self.reader.readexactly(n)).decode())

    async def send(self, words):
        async with self.write_lock:
            self.writer.write(b"".join(encode_word(w) for w in words) + b"\0")
            await asyncio.wait_for(self.writer.drain(), 10)

    async def connect(self):
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), 10
        )
        await self.send(["/login", "=name=" + self.user, "=password=" + self.password])
        reply = await asyncio.wait_for(self.sentence(), 10)
        if not reply or reply[0] != "!done":
            raise NativeApiError("Native authentication failed")
        self.last_received = time.monotonic()
        self.task = asyncio.create_task(self.pump())

    async def pump(self):
        try:
            while True:
                words = await self.sentence()
                self.last_received = time.monotonic()
                if not words:
                    continue
                tag = next((w[5:] for w in words if w.startswith(".tag=")), None)
                attrs = {
                    w.split("=", 2)[1]: w.split("=", 2)[2]
                    for w in words[1:]
                    if w.startswith("=")
                }
                if words[0] == "!fatal":
                    raise NativeApiError("Native connection rejected")
                request = self.pending.get(tag)
                if request is not None:
                    if words[0] == "!re":
                        if len(request["rows"]) >= 2000:
                            raise NativeApiError("Native row cap exceeded")
                        request["size"] = request.get("size", 0) + sum(
                            len(w) for w in words
                        )
                        if request["size"] > 2_000_000:
                            raise NativeApiError("Native request size exceeded")
                        request["rows"].append(attrs)
                    elif words[0] == "!trap":
                        request["error"] = True
                    elif words[0] == "!done":
                        if not request["future"].done():
                            if request.get("error"):
                                request["future"].set_exception(
                                    NativeApiError("Native request rejected")
                                )
                            else:
                                request["future"].set_result(
                                    {"rows": request["rows"], "done": attrs}
                                )
                    continue
                callback = self.subscribers.get(tag)
                if callback:
                    if words[0] == "!re":
                        callback(attrs)
                    elif words[0] in ("!trap", "!done"):
                        # An ID can disappear while a print interval is active.
                        # Retire that feed and let its table refresh membership;
                        # unrelated feeds and RPCs remain usable.
                        self.subscribers.pop(tag, None)
                        self.ended[tag] = words[0]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failure = type(exc).__name__
            for req in self.pending.values():
                if not req["future"].done():
                    req["future"].set_exception(
                        NativeApiError("Native connection ended")
                    )

    async def rpc(self, path, args=None, query=(), timeout=25):
        if self.failure or self.writer is None or self.writer.is_closing():
            raise NativeApiError("Native connection unavailable")
        tag = "r" + str(next(self.counter))
        future = asyncio.get_running_loop().create_future()
        self.pending[tag] = {"future": future, "rows": []}
        try:
            async with asyncio.timeout(timeout):
                await self.send(
                    [
                        path,
                        *["=" + k + "=" + str(v) for k, v in (args or {}).items()],
                        *query,
                        ".tag=" + tag,
                    ]
                )
                return await future
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # The timeout applies to the caller and the outstanding router command.
            # /cancel itself is deliberately untracked, so cancellation cannot recurse.
            try:
                await asyncio.wait_for(
                    self.send(
                        ["/cancel", "=tag=" + tag, ".tag=c" + str(next(self.counter))]
                    ),
                    2,
                )
            except (OSError, asyncio.TimeoutError):
                pass
            raise
        finally:
            self.pending.pop(tag, None)

    async def subscribe(self, path, args, callback):
        tag = "s" + str(next(self.counter))
        self.subscribers[tag] = callback
        await self.send(
            [path, *["=" + k + "=" + str(v) for k, v in args.items()], ".tag=" + tag]
        )
        return tag

    async def subscribe_initial(self, path, args, callback, members=None, timeout=25):
        """Use the interval feed's first rows as its initial counter snapshot.

        Selected IDs must all arrive before the caller can publish the cache.
        A disappearing ID, closed connection or deadline aborts the feed rather
        than allowing a partial bootstrap to become an accounting observation.
        """
        if self.failure or self.writer is None or self.writer.is_closing():
            raise NativeApiError("Native connection unavailable")
        tag = "s" + str(next(self.counter))
        remaining = {identifier.upper() for identifier in members} if members else None
        ready = asyncio.Event()

        def receive(row):
            callback(row)
            if remaining is None:
                ready.set()
            else:
                remaining.discard(row.get(".id", "").upper())
                if not remaining:
                    ready.set()

        self.subscribers[tag] = receive
        try:
            async with asyncio.timeout(timeout):
                await self.send([
                    path, *["=" + k + "=" + str(v) for k, v in args.items()],
                    ".tag=" + tag,
                ])
                while True:
                    if self.failure or tag in self.ended:
                        raise NativeApiError("Native initial stream ended")
                    if ready.is_set():
                        return tag
                    try:
                        await asyncio.wait_for(ready.wait(), 0.1)
                    except asyncio.TimeoutError:
                        pass
        except BaseException:
            try:
                await asyncio.wait_for(self.cancel(tag), 2)
            except (OSError, NativeApiError, asyncio.TimeoutError):
                pass
            finally:
                self.subscribers.pop(tag, None)
                self.ended.pop(tag, None)
            raise

    async def cancel(self, tag):
        self.subscribers.pop(tag, None)
        if self.ended.pop(tag, None) is not None:
            return
        await self.rpc("/cancel", {"tag": tag})

    async def close(self):
        self.failure = self.failure or "Closed"
        for req in self.pending.values():
            if not req["future"].done():
                req["future"].set_exception(NativeApiError("Native connection ended"))
        self.subscribers.clear()
        self.ended.clear()
        if self.task:
            self.task.cancel()
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 5)
            except (OSError, asyncio.TimeoutError):
                pass
        if self.task:
            await asyncio.gather(self.task, return_exceptions=True)


class NativeTables:
    """One current row per native ID; membership discovery retires old IDs."""

    def __init__(self, api, interval=60, chunk_size=32, wan=None):
        self.api, self.interval, self.chunk_size = api, interval, chunk_size
        self.data = {name: {} for name in TABLES}
        self.groups = {name: [] for name in TABLES}
        self.orders = {}
        self.observed = {name: {} for name in TABLES}
        self.row_sizes = {name: {} for name in TABLES}
        self.cache_size = 0
        self.host_keys = {}
        self.wan = wan
        self.inventory_pending = set()
        self.inventory_scan = None

    async def start_inventory(self, table):
        """Discover IDs cheaply; the caller advances bounded pages between posts."""
        if table not in INVENTORY_TABLES or self.inventory_scan is not None:
            raise NativeApiError("Native inventory scan is already active or invalid")
        path, _ = TABLES[table]
        reply = await self.api.rpc(path.removesuffix("print") + "find")
        raw = reply.get("done", {}).get("ret")
        if not isinstance(raw, str) or len(raw) > 24_000 or reply.get("rows"):
            raise NativeApiError("Invalid native inventory discovery")
        identifiers = raw.split(";") if raw else []
        if (len(identifiers) > 2000
                or any(not re.fullmatch(r"\*[A-Fa-f0-9]+", i) for i in identifiers)
                or len({i.upper() for i in identifiers}) != len(identifiers)):
            raise NativeApiError("Invalid native inventory IDs")
        self.inventory_scan = {
            "table": table, "ids": identifiers, "offset": 0,
            "data": {}, "sizes": {}, "started": time.monotonic(),
            "next_at": time.monotonic() + 1,
        }
        if not identifiers:
            self._publish_inventory()

    def _publish_inventory(self):
        scan = self.inventory_scan
        table, data, sizes = scan["table"], scan["data"], scan["sizes"]
        size = self.cache_size - sum(self.row_sizes[table].values()) + sum(sizes.values())
        if size > 4_000_000:
            raise NativeApiError("Native cache size exceeded")
        self.data[table], self.row_sizes[table], self.cache_size = data, sizes, size
        now = datetime.datetime.now(datetime.timezone.utc)
        self.observed[table] = {identifier: now for identifier in data}
        self.inventory_pending.add(table)
        self.inventory_scan = None

    async def advance_inventory(self):
        """At most four selected rows and one RPC; never await an entire scan."""
        scan = self.inventory_scan
        if scan is None:
            return
        now = time.monotonic()
        try:
            if now - scan["started"] > 600:
                raise NativeApiError("Native inventory scan expired")
            if now < scan["next_at"]:
                return
            table = scan["table"]
            path, props = TABLES[table]
            members = scan["ids"][scan["offset"]:scan["offset"] + 4]
            reply = await self.api.rpc(path, {".proplist": props, "from": ",".join(members)})
            wanted = {i.upper() for i in members}
            seen = set()
            for row in reply["rows"]:
                row = dict(row)
                row.pop(".section", None)
                identifier = row.get(".id", "").upper()
                if identifier not in wanted or identifier in seen:
                    raise NativeApiError("Invalid native inventory page")
                seen.add(identifier)
                row[".id"] = identifier
                size = sum(len(str(k)) + len(str(v)) for k, v in row.items())
                if size > 64_000:
                    raise NativeApiError("Native row size exceeded")
                scan["data"][identifier], scan["sizes"][identifier] = row, size
            size = (self.cache_size - sum(self.row_sizes[table].values())
                    + sum(scan["sizes"].values()))
            if size > 4_000_000:
                raise NativeApiError("Native cache size exceeded")
            scan["offset"] += len(members)
            scan["next_at"] = time.monotonic() + 1
            if scan["offset"] >= len(scan["ids"]):
                self._publish_inventory()
        except BaseException:
            # Preserve the last complete table. Dynamic rows can vanish while
            # a page is in flight; a later scheduled cycle can try again.
            self.inventory_scan = None
            raise

    def discard(self, table, identifier):
        old = self.data[table].pop(identifier, None)
        self.observed[table].pop(identifier, None)
        self.cache_size -= self.row_sizes[table].pop(identifier, 0)
        if table == "hosts" and old:
            key = (old.get("mac-address", "").upper(), old.get("address"))
            if self.host_keys.get(key) == identifier:
                self.host_keys.pop(key, None)

    def update(self, table, row):
        row = dict(row)
        row.pop(".section", None)
        identifier = row.get(".id", "singleton")
        size = sum(len(str(k)) + len(str(v)) for k, v in row.items())
        if size > 64_000:
            raise NativeApiError("Native row size exceeded")
        previous = self.data[table].get(identifier)
        if table == "hosts" and previous:
            previous_key = (
                previous.get("mac-address", "").upper(),
                previous.get("address"),
            )
            if self.host_keys.get(previous_key) == identifier:
                self.host_keys.pop(previous_key, None)
        if table == "hosts" and row.get("mac-address") and row.get("address"):
            key = (row["mac-address"].upper(), row["address"])
            old_id = self.host_keys.get(key)
            if old_id is not None and old_id != identifier:
                self.discard(table, old_id)
            self.host_keys[key] = identifier
        next_size = self.cache_size - self.row_sizes[table].get(identifier, 0) + size
        if next_size > 4_000_000:
            raise NativeApiError("Native cache size exceeded")
        self.cache_size = next_size
        self.row_sizes[table][identifier] = size
        self.data[table][identifier] = row
        self.observed[table][identifier] = datetime.datetime.now(datetime.timezone.utc)
        if len(self.data[table]) > 2000:
            raise NativeApiError("Native table size exceeded")

    async def refresh(self, table):
        path, props = TABLES[table]
        if table in INVENTORY_TABLES:
            await self.start_inventory(table)
            return
        if table == "resource":
            if self.groups[table] and self.groups[table][0]["tag"] in self.api.ended:
                await self.api.cancel(self.groups[table][0]["tag"])
                self.groups[table] = []
            if not self.groups[table]:
                tag = await self.api.subscribe_initial(
                    path,
                    {".proplist": props, "interval": str(self.interval)},
                    lambda row: self.update(table, row),
                )
                self.groups[table] = [{"tag": tag, "members": None}]
            return
        properties = (
            ".id,name"
            if table == "queues"
            else (
                ".id,authorized,bypassed"
                if table == "hosts"
                else ".id,name,type" if table == "interfaces" and self.wan else ".id"
            )
        )
        metadata = await self.api.rpc(path, {".proplist": properties})
        identifiers = [
            r[".id"]
            for r in metadata["rows"]
            if r.get(".id")
            and (
                table != "hosts"
                or r.get("authorized") == "true"
                or r.get("bypassed") == "true"
            )
            and (
                table != "queues" or r.get("name", "").startswith(("plan_", "<pppoe-"))
            )
            and (
                table != "interfaces"
                or not self.wan
                or r.get("name") == self.wan
                or r.get("type") in ("ether", "wlan", "wifi")
            )
        ]
        if len(identifiers) > 2000 or any(
            not re.fullmatch(r"\*[A-Fa-f0-9]+", i) for i in identifiers
        ):
            raise NativeApiError("Invalid native item IDs")
        self.orders[table] = identifiers
        wanted = set(identifiers)
        # Preserve unchanged chunks, preventing every join from restarting all feeds.
        unchanged = []
        remaining = list(identifiers)
        partials = []
        for group in self.groups[table]:
            members = group["members"]
            if (
                group["tag"] not in self.api.ended
                and set(members) <= wanted
                and len(members) == self.chunk_size
            ):
                unchanged.append(group)
                remaining = [i for i in remaining if i not in members]
            else:
                partials.append(group)
        if (
            len(partials) == 1
            and partials[0]["tag"] not in self.api.ended
            and set(partials[0]["members"]) == set(remaining)
        ):
            unchanged.append(partials[0])
            remaining = []
        else:
            for group in partials:
                await self.api.cancel(group["tag"])
        self.groups[table] = unchanged
        for identifier in list(self.data[table]):
            if identifier not in wanted:
                self.discard(table, identifier)
        for start in range(0, len(remaining), self.chunk_size):
            members = remaining[start : start + self.chunk_size]
            args = {".proplist": props, "from": ",".join(members)}
            args["interval"] = str(
                self.interval
                if table in ("hosts", "queues", "ppp", "interfaces")
                else 300
            )
            tag = await self.api.subscribe_initial(
                path, args, lambda row, t=table: self.update(t, row), members=members
            )
            self.groups[table].append({"tag": tag, "members": members})
            await asyncio.sleep(0.35)

    async def bootstrap(self):
        for table in STREAM_TABLES:
            await self.refresh(table)

    def snapshot(self):
        return {
            name: [dict(row) for row in table.values()]
            for name, table in self.data.items()
            if name not in INVENTORY_TABLES or name in self.inventory_pending
        }

    def inventory_accepted(self, body):
        """Do not re-advertise an old topology observation on every usage post."""
        self.inventory_pending.difference_update(set(body) & set(INVENTORY_TABLES))

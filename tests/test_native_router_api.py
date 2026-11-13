from types import SimpleNamespace
import asyncio
import unittest
from unittest.mock import patch

from app.services import native_router_api as native


class FakeWriter:
    def __init__(self):
        self.closed = False
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        pass

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_initial_subscription_waits_for_every_selected_id_then_keeps_streaming(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader, api.writer = asyncio.StreamReader(), FakeWriter()
        api.task = asyncio.create_task(api.pump())
        received = []
        call = asyncio.create_task(api.subscribe_initial(
            "/test/print", {"from": "*A,*B", "interval": "60"},
            received.append, members=["*A", "*B"], timeout=1,
        ))
        await asyncio.sleep(0)

        def feed(identifier, value):
            words = ["!re", "=.id=" + identifier, "=counter=" + value, ".tag=s0"]
            api.reader.feed_data(b"".join(native.encode_word(w) for w in words) + b"\0")

        feed("*a", "1")
        await asyncio.sleep(0.01)
        self.assertFalse(call.done())
        feed("*B", "2")
        self.assertEqual(await call, "s0")
        self.assertEqual(len(received), 2)
        self.assertEqual(len(api.writer.writes), 1)
        feed("*a", "3")
        await asyncio.sleep(0.01)
        self.assertEqual(received[-1]["counter"], "3")
        await api.close()

    async def test_initial_subscription_failure_never_returns_a_partial_snapshot(self):
        for failure in ("trap", "disconnect", "timeout", "cancel", "close"):
            with self.subTest(failure=failure):
                api = native.AsyncNativeAPI("x", "u", "secret")
                api.reader, api.writer = asyncio.StreamReader(), FakeWriter()
                api.task = asyncio.create_task(api.pump())
                # Complete cancellation locally; this checks the actual cancel RPC
                # for deadline/cancellation without waiting on a fake router.
                original_send = api.send

                async def send(words):
                    await original_send(words)
                    if words[0] == "/cancel":
                        tag = next(w for w in words if w.startswith(".tag="))
                        api.reader.feed_data(native.encode_word("!done") + native.encode_word(tag) + b"\0")

                api.send = send
                call = asyncio.create_task(api.subscribe_initial(
                    "/test/print", {"from": "*A,*B", "interval": "60"},
                    lambda row: None, members=["*A", "*B"], timeout=0.05,
                ))
                await asyncio.sleep(0.001)
                api.reader.feed_data(b"".join(native.encode_word(w) for w in
                    ["!re", "=.id=*A", ".tag=s0"]) + b"\0")
                if failure == "trap":
                    api.reader.feed_data(b"".join(native.encode_word(w) for w in
                        ["!trap", "=message=private-secret", ".tag=s0"]) + b"\0")
                elif failure == "disconnect":
                    api.reader.feed_eof()
                elif failure == "cancel":
                    call.cancel()
                elif failure == "close":
                    await api.close()
                with self.assertRaises((native.NativeApiError, asyncio.TimeoutError, asyncio.CancelledError)) as raised:
                    await call
                self.assertNotIn("private-secret", str(raised.exception))
                self.assertEqual(api.subscribers, {})
                self.assertEqual(api.pending, {})
                if failure in ("timeout", "cancel"):
                    self.assertIn(b"/cancel", api.writer.writes[-1])
                await api.close()

    async def test_rpc_deadline_includes_a_blocked_write(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.writer = FakeWriter()
        drains = 0

        async def slow_first_drain():
            nonlocal drains
            drains += 1
            if drains == 1:
                await asyncio.sleep(1)

        api.writer.drain = slow_first_drain
        started = asyncio.get_running_loop().time()
        with self.assertRaises(asyncio.TimeoutError):
            await api.rpc("/test", timeout=0.01)
        self.assertLess(asyncio.get_running_loop().time() - started, 0.5)
        self.assertEqual(api.pending, {})
        self.assertIn(b"/cancel", api.writer.writes[-1])

    async def test_fragmented_unicode_and_long_words(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader = asyncio.StreamReader()
        words = ["!re", "=name=rÃƒÂ©sumÃƒÂ©", "=long=" + "x" * 17000, ".tag=s1"]
        data = b"".join(native.encode_word(w) for w in words) + b"\0"

        async def feed():
            for start in range(0, len(data), 17):
                api.reader.feed_data(data[start : start + 17])
                await asyncio.sleep(0)

        task = asyncio.create_task(feed())
        self.assertEqual(await api.sentence(), words)
        await task

    async def test_reject_oversized_word_before_read(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader = asyncio.StreamReader()
        api.reader.feed_data(b"\xf0" + (1_000_001).to_bytes(4, "big"))
        with self.assertRaises(native.NativeApiError):
            await api.sentence()

    async def test_interleaved_stream_and_rpc(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader = asyncio.StreamReader()
        api.writer = FakeWriter()
        received = []
        api.subscribers["s0"] = received.append
        api.task = asyncio.create_task(api.pump())
        call = asyncio.create_task(api.rpc("/test"))
        await asyncio.sleep(0)
        for words in [
            ["!re", "=n=stream", ".tag=s0"],
            ["!re", "=n=rpc", ".tag=r0"],
            ["!done", ".tag=r0"],
        ]:
            api.reader.feed_data(b"".join(native.encode_word(w) for w in words) + b"\0")
        self.assertEqual((await call)["rows"], [{"n": "rpc"}])
        self.assertEqual(received, [{"n": "stream"}])
        await api.close()

    async def test_timeout_cancels_router_command(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.writer = FakeWriter()
        with self.assertRaises(asyncio.TimeoutError):
            await api.rpc("/test", timeout=0.001)
        self.assertEqual(api.pending, {})
        self.assertIn(b"/cancel", api.writer.writes[-1])
        self.assertIn(b"=tag=r0", api.writer.writes[-1])

    async def test_close_wakes_pending_call(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.writer = FakeWriter()
        call = asyncio.create_task(api.rpc("/test"))
        await asyncio.sleep(0)
        await api.close()
        with self.assertRaises(native.NativeApiError):
            await call

    async def test_pump_does_not_echo_server_error(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader = asyncio.StreamReader()
        api.writer = FakeWriter()
        api.task = asyncio.create_task(api.pump())
        call = asyncio.create_task(api.rpc("/test"))
        await asyncio.sleep(0)
        for words in [
            ["!trap", "=message=private-secret", ".tag=r0"],
            ["!done", ".tag=r0"],
        ]:
            api.reader.feed_data(b"".join(native.encode_word(w) for w in words) + b"\0")
        with self.assertRaisesRegex(native.NativeApiError, "^Native request rejected$"):
            await call
        await api.close()

    async def test_ended_stream_does_not_break_unrelated_rpc(self):
        api = native.AsyncNativeAPI("x", "u", "secret")
        api.reader = asyncio.StreamReader()
        api.writer = FakeWriter()
        api.subscribers["s0"] = lambda row: None
        api.task = asyncio.create_task(api.pump())
        call = asyncio.create_task(api.rpc("/test"))
        await asyncio.sleep(0)
        for words in [
            ["!trap", "=message=item vanished", ".tag=s0"],
            ["!done", ".tag=s0"],
            ["!done", ".tag=r0"],
        ]:
            api.reader.feed_data(b"".join(native.encode_word(w) for w in words) + b"\0")
        self.assertEqual((await call)["rows"], [])
        self.assertEqual(api.ended, {"s0": "!trap"})
        self.assertIsNone(api.failure)
        await api.cancel("s0")
        self.assertEqual(api.ended, {})
        await api.close()


class FakeAPI:
    def __init__(self):
        self.members = []
        self.cancelled = []
        self.subs = []
        self.calls = []
        self.ended = {}

    async def rpc(self, path, args):
        self.calls.append((path, dict(args)))
        if args[".proplist"] in (".id", ".id,authorized,bypassed"):
            return {
                "rows": [
                    {".id": i, "authorized": "true", "bypassed": "false"}
                    for i in self.members
                ]
            }
        return {
            "rows": [
                {".id": i, "mac-address": "AA:" + i, "address": "192.0.2.1"}
                for i in args["from"].split(",")
            ]
        }

    async def subscribe(self, path, args, callback):
        tag = "s" + str(len(self.subs))
        self.subs.append((tag, dict(args), callback))
        return tag

    async def subscribe_initial(self, path, args, callback, members=None):
        tag = await self.subscribe(path, args, callback)
        if members is None:
            callback({"cpu-load": "7"})
        for identifier in members or []:
            callback({".id": identifier, "mac-address": "AA:" + identifier, "address": "192.0.2.1"})
        return tag

    async def cancel(self, tag):
        self.cancelled.append(tag)
        self.ended.pop(tag, None)


class InventoryAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.discovery = None
        self.page = None

    async def rpc(self, path, args=None):
        args = dict(args or {})
        self.calls.append((path, args))
        if path.endswith("/find"):
            ids = self.discovery if self.discovery is not None else ";".join(r[".id"] for r in self.members)
            return {"rows": [], "done": {"ret": ids}}
        wanted = set(args["from"].split(","))
        return {"rows": self.page if self.page is not None else [r for r in self.members if r[".id"] in wanted]}


class CacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_counter_bootstrap_uses_initial_feed_without_duplicate_full_reads(self):
        api = FakeAPI()
        api.members = ["*1", "*2"]
        tables = native.NativeTables(api)
        with patch.object(native.asyncio, "sleep", return_value=None):
            await tables.refresh("hosts")
            await tables.refresh("resource")
        self.assertEqual(api.calls, [("/ip/hotspot/host/print", {".proplist": ".id,authorized,bypassed"})])
        self.assertEqual(set(tables.data["hosts"]), {"*1", "*2"})
        self.assertEqual(tables.data["resource"]["singleton"]["cpu-load"], "7")
        self.assertEqual(len(api.subs), 2)

    async def test_inventory_pages_are_paced_and_only_publish_after_completion(self):
        api = InventoryAPI()
        api.members = [{".id": "*" + format(i, "X"), "host-name": str(i)} for i in range(1, 10)]
        tables = native.NativeTables(api)
        clock = [100.0]
        with patch.object(native, "time", SimpleNamespace(monotonic=lambda: clock[0])):
            await tables.refresh("leases")
            self.assertEqual(api.calls, [("/ip/dhcp-server/lease/find", {})])
            await tables.advance_inventory()
            self.assertEqual(len(api.calls), 1)
            for index in range(3):
                clock[0] += 1
                await tables.advance_inventory()
                self.assertLessEqual(len(api.calls[-1][1]["from"].split(",")), 4)
                if index < 2:
                    self.assertNotIn("leases", tables.snapshot())
                    tables.update("hosts", {".id": "*A", "bytes-in": str(index)})
                calls = len(api.calls)
                await tables.advance_inventory()
                self.assertEqual(len(api.calls), calls)
            self.assertIsNone(tables.inventory_scan)
            self.assertEqual(tables.snapshot()["leases"], api.members)
            self.assertEqual(api.subs, [])
            body = tables.snapshot()
            tables.inventory_accepted(body)
            self.assertNotIn("leases", tables.snapshot())
            api.members = []
            await tables.refresh("leases")
            self.assertEqual(tables.snapshot()["leases"], [])
            self.assertEqual(tables.data["hosts"]["*A"]["bytes-in"], "1")

    async def test_invalid_discovery_or_page_preserves_previous_complete_inventory(self):
        api = InventoryAPI()
        tables = native.NativeTables(api)
        clock = [100.0]
        with patch.object(native, "time", SimpleNamespace(monotonic=lambda: clock[0])):
            api.members = [{".id": "*1", "host-name": "old"}]
            await tables.refresh("leases")
            clock[0] += 1
            await tables.advance_inventory()
            original_size = tables.cache_size
            for invalid in ("bad", "*1;*1", "*a;*A", ";", ";".join("*%X" % i for i in range(2001))):
                api.discovery = invalid
                with self.assertRaises(native.NativeApiError):
                    await tables.refresh("leases")
                self.assertIsNone(tables.inventory_scan)
            api.discovery = None
            api.members = [{".id": "*2"}]
            for invalid in ([{".id": "*9"}], [{".id": "*2"}, {".id": "*2"}],
                            [{".id": "*2", "comment": "x" * 64_001}]):
                await tables.refresh("leases")
                api.page = invalid
                clock[0] += 1
                with self.assertRaises(native.NativeApiError):
                    await tables.advance_inventory()
                self.assertIsNone(tables.inventory_scan)
                self.assertEqual(tables.snapshot()["leases"], [{".id": "*1", "host-name": "old"}])
                self.assertEqual(tables.cache_size, original_size)

    async def test_expired_scan_discards_partial_rows_and_preserves_old_table(self):
        api = InventoryAPI()
        api.members = [{".id": "*%X" % i} for i in range(8)]
        tables = native.NativeTables(api)
        clock = [100.0]
        with patch.object(native, "time", SimpleNamespace(monotonic=lambda: clock[0])):
            await tables.refresh("leases")
            clock[0] += 1
            await tables.advance_inventory()
            self.assertNotIn("leases", tables.snapshot())
            clock[0] += 601
            with self.assertRaises(native.NativeApiError):
                await tables.advance_inventory()
        self.assertIsNone(tables.inventory_scan)
        self.assertNotIn("leases", tables.snapshot())
        self.assertEqual(tables.cache_size, 0)

    async def test_billing_bootstrap_does_not_wait_for_optional_topology(self):
        tables = native.NativeTables(None)
        calls = []

        async def refresh(name):
            calls.append(name)

        tables.refresh = refresh
        await tables.bootstrap()
        self.assertEqual(set(calls), set(native.STREAM_TABLES))
        self.assertTrue({"hosts", "queues", "ppp", "interfaces", "resource"} <= set(calls))
        self.assertFalse(set(calls) & set(native.INVENTORY_TABLES))

    async def test_ended_native_feed_is_rebuilt_with_current_members(self):
        api = FakeAPI()
        tables = native.NativeTables(api, chunk_size=4)
        with patch.object(native.asyncio, "sleep", return_value=None):
            api.members = ["*1", "*2"]
            await tables.refresh("hosts")
            old = tables.groups["hosts"][0]["tag"]
            api.ended[old] = "!trap"
            api.members = ["*2", "*3"]
            await tables.refresh("hosts")
        self.assertIn(old, api.cancelled)
        self.assertNotEqual(tables.groups["hosts"][0]["tag"], old)
        self.assertEqual(set(tables.data["hosts"]), {"*2", "*3"})

    async def test_churn_keeps_full_groups_repackages_partial(self):
        api = FakeAPI()
        tables = native.NativeTables(api, chunk_size=4)
        with patch.object(native.asyncio, "sleep", return_value=None):
            for count in range(1, 12):
                api.members = ["*" + format(i, "X") for i in range(count)]
                await tables.refresh("hosts")
                self.assertEqual(len(tables.groups["hosts"]), (count + 3) // 4)
                self.assertEqual(set(tables.data["hosts"]), set(api.members))
            full_tag = tables.groups["hosts"][0]["tag"]
            await tables.refresh("hosts")
            self.assertEqual(tables.groups["hosts"][0]["tag"], full_tag)
            api.members = api.members[2:]
            await tables.refresh("hosts")
            self.assertEqual(set(tables.data["hosts"]), set(api.members))
            self.assertTrue(all(len(g["members"]) <= 4 for g in tables.groups["hosts"]))
            self.assertTrue(
                all("from" in args and "interval" in args for _, args, _ in api.subs)
            )

    async def test_replaced_host_id_keeps_single_counter_key(self):
        tables = native.NativeTables(FakeAPI())
        tables.update(
            "hosts",
            {
                ".id": "*1",
                "mac-address": "AA:BB",
                "address": "192.0.2.1",
                "bytes-in": "100",
            },
        )
        tables.update(
            "hosts",
            {
                ".id": "*2",
                "mac-address": "aa:bb",
                "address": "192.0.2.1",
                "bytes-in": "1",
            },
        )
        self.assertEqual(list(tables.data["hosts"]), ["*2"])
        self.assertEqual(tables.snapshot()["hosts"][0]["bytes-in"], "1")
        self.assertNotIn("*1", tables.observed["hosts"])
        self.assertIsNotNone(tables.observed["hosts"]["*2"].tzinfo)


if __name__ == "__main__":
    unittest.main()

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

    async def cancel(self, tag):
        self.cancelled.append(tag)
        self.ended.pop(tag, None)


class CacheTests(unittest.IsolatedAsyncioTestCase):
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

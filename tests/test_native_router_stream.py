from unittest.mock import AsyncMock
from types import SimpleNamespace
import asyncio

import pytest

from app.services import native_router_stream as stream
from app.services.native_router_api import NativeApiError, NativeTables
from app.services.native_router_lease import lease_sources, touch_lease
import hashlib
import time


def test_inventory_cycle_staggers_lists_and_never_catches_up_in_a_burst():
    cycle = stream.SlowInventoryCycle(100)
    assert cycle.take_due(114.9) is None
    first = cycle.take_due(115)
    assert first == "bridge_hosts"
    assert cycle.take_due(115) is None
    assert cycle.take_due(164.9) is None
    names = [first] + [cycle.take_due(t) for t in (165, 215, 265, 315, 365)]
    assert set(names) == {*stream.INVENTORY_TABLES, "interfaces"}
    assert cycle.take_due(10_000) == "bridge_hosts"
    assert cycle.take_due(10_000) is None
    assert cycle.take_due(10_049) is None
    assert cycle.take_due(10_050) == "bindings"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [NativeApiError("optional unavailable"), TimeoutError()])
@pytest.mark.parametrize("stage", ["start", "page"])
async def test_optional_inventory_failure_keeps_usage_posts_running(monkeypatch, failure, stage):
    class StopTest(Exception):
        pass

    clock, refreshes, posts = [100.0], [], []
    api = AsyncMock()
    api.failure = None
    api.ended = {}
    api.rpc.return_value = {"done": {"ret": "0"}}
    session = AsyncMock()
    session.preflight.return_value = "ether1"
    session.cfg = {}

    class Tables:
        inventory_scan = None
        groups = {name: [] for name in stream.STREAM_TABLES}
        orders, observed = {}, {}

        async def bootstrap(self):
            pass

        async def refresh(self, name):
            refreshes.append((clock[0], name))
            if name == "bridge_hosts":
                if stage == "start":
                    raise failure
                self.inventory_scan = {"table": name}

        async def advance_inventory(self):
            self.inventory_scan = None
            raise failure

        def snapshot(self):
            return {}

        def inventory_accepted(self, body):
            pass

    class Http:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            posts.append(clock[0])
            return SimpleNamespace(status_code=200, raise_for_status=lambda: None,
                                   json=lambda: {"next_push_seconds": 60})

    async def advance(seconds):
        clock[0] += seconds
        if clock[0] >= 330:
            raise StopTest()

    monkeypatch.setattr(stream, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(stream, "asyncio", SimpleNamespace(sleep=advance, wait_for=asyncio.wait_for))
    monkeypatch.setattr(stream, "load_router", AsyncMock(return_value={
        "id": 563, "identity": "Router-test", "ip_address": "10.0.0.217",
        "username": "test", "password": "test", "port": 8728,
    }))
    monkeypatch.setattr(stream, "AsyncNativeAPI", lambda *args: api)
    monkeypatch.setattr(stream, "StreamSession", lambda *args: session)
    monkeypatch.setattr(stream, "NativeTables", lambda *args, **kwargs: Tables())
    monkeypatch.setattr(stream, "native_api_to_v3", lambda *args, **kwargs: {"hosts": [], "reports": [], "router": {}})
    monkeypatch.setattr(stream, "touch_lease", AsyncMock())
    monkeypatch.setattr(stream.httpx, "AsyncClient", lambda **kwargs: Http())
    with pytest.raises(StopTest):
        await stream.stream_router(563, 64 * "a")
    assert [t for t, name in refreshes if name == "bridge_hosts"] == [115]
    assert len(posts) >= 3 and posts[-1] > 215
    assert any(name == "leases" for _, name in refreshes)
    session.release.assert_awaited_once()
    api.close.assert_awaited_once()


def test_enrollment_is_empty_by_default_and_requires_exact_hashes():
    assert stream.enrollment("", "") == {}
    assert stream.enrollment("563,597", "563:" + 64 * "a" + ",597:" + 64 * "b") == {
        563: 64 * "a",
        597: 64 * "b",
    }
    for ids, hashes in [
        ("563", ""),
        ("563,563", "563:" + 64 * "a"),
        ("563", "563:token"),
        ("563;run", "563:" + 64 * "a"),
        ("563", "597:" + 64 * "a"),
    ]:
        with pytest.raises(ValueError):
            stream.enrollment(ids, hashes)


@pytest.mark.asyncio
@pytest.mark.parametrize("scripts,error", [
    ([], "not unique"),
    ([{"name": stream.REPORTER, "source": "changed"}], "changed since review"),
    ([{"name": stream.REPORTER, "source": "x"}] * 2, "not unique"),
])
async def test_filtered_preflight_still_rejects_missing_duplicate_or_changed_reporter(scripts, error):
    api = AsyncMock()
    api.rpc.side_effect = [
        {"rows": [{"name": "Router-test"}]},
        {"rows": [{"board-name": "RB951Ui-2HnD", "version": "7.24.2"}]},
        {"rows": scripts},
    ]
    session = stream.StreamSession({"identity": "Router-test"}, "a" * 64, api)
    with pytest.raises(RuntimeError, match=error):
        await session.preflight()
    assert api.rpc.await_count == 3
    assert api.rpc.await_args.args == ("/system/script/print", {".proplist": "name,source"})
    assert api.rpc.await_args.kwargs == {"query": ("?name=" + stream.REPORTER,)}


@pytest.mark.asyncio
async def test_long_inventory_scan_does_not_delay_usage_posts_or_router_lease(monkeypatch):
    class StopTest(Exception):
        pass

    clock, posts, touches, pages = [100.0], [], [], []
    api = AsyncMock()
    api.failure, api.ended = None, {}
    api.rpc.return_value = {"done": {"ret": "0"}}
    session = AsyncMock()
    session.preflight.return_value = "ether1"
    session.cfg = {}

    class Tables:
        groups = {name: [] for name in stream.STREAM_TABLES}
        orders, observed = {}, {}
        inventory_scan = None
        remaining = 150

        async def bootstrap(self):
            pass

        async def refresh(self, name):
            if name == "bridge_hosts":
                self.inventory_scan = {"table": name}

        async def advance_inventory(self):
            pages.append(clock[0])
            self.remaining -= 1
            if self.remaining == 0:
                self.inventory_scan = None

        def snapshot(self):
            return {}

        def inventory_accepted(self, body):
            pass

    class Http:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            posts.append(clock[0])
            return SimpleNamespace(status_code=200, raise_for_status=lambda: None,
                                   json=lambda: {"next_push_seconds": 60})

    async def advance(seconds):
        clock[0] += seconds
        if clock[0] >= 330:
            raise StopTest()

    async def touch(*args):
        touches.append(clock[0])

    monkeypatch.setattr(stream, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(stream, "asyncio", SimpleNamespace(sleep=advance, wait_for=asyncio.wait_for))
    monkeypatch.setattr(stream, "load_router", AsyncMock(return_value={
        "id": 563, "identity": "Router-test", "ip_address": "10.0.0.217",
        "username": "test", "password": "test", "port": 8728,
    }))
    monkeypatch.setattr(stream, "AsyncNativeAPI", lambda *args: api)
    monkeypatch.setattr(stream, "StreamSession", lambda *args: session)
    monkeypatch.setattr(stream, "NativeTables", lambda *args, **kwargs: Tables())
    monkeypatch.setattr(stream, "native_api_to_v3", lambda *args, **kwargs: {"hosts": [], "reports": [], "router": {}})
    monkeypatch.setattr(stream, "touch_lease", touch)
    monkeypatch.setattr(stream.httpx, "AsyncClient", lambda **kwargs: Http())
    with pytest.raises(StopTest):
        await stream.stream_router(563, "a" * 64)
    assert len(pages) == 150
    assert sum(pages[0] <= t <= pages[-1] for t in posts) >= 2
    assert max(b-a for a, b in zip(posts, posts[1:])) <= 65
    assert max(b-a for a, b in zip(touches, touches[1:])) <= 50
    session.release.assert_awaited_once()
    api.close.assert_awaited_once()


def test_native_cache_bounds_rows_and_removes_old_host_key_index():
    cache = NativeTables(None)
    cache.update("hosts", {".id": "*1", "mac-address": "AA:BB", "address": "192.0.2.1"})
    cache.update("hosts", {".id": "*1", "mac-address": "CC:DD", "address": "192.0.2.2"})
    assert ("AA:BB", "192.0.2.1") not in cache.host_keys
    cache.update("hosts", {".id": "*2", "mac-address": "CC:DD", "address": "192.0.2.2"})
    assert "*1" not in cache.data["hosts"]
    cache.discard("hosts", "*2")
    assert not cache.host_keys and cache.cache_size == 0
    with pytest.raises(NativeApiError):
        cache.update("leases", {".id": "*3", "comment": "x" * 64_001})


@pytest.mark.asyncio
async def test_shutdown_before_claim_does_not_write_to_router():
    api = AsyncMock()
    api.failure = None
    session = stream.StreamSession({"id": 563}, 64 * "a", api)
    await session.release()
    api.rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_broken_connection_leaves_router_guard_to_restore_reporter():
    api = AsyncMock()
    api.failure = "OSError"
    session = stream.StreamSession({"id": 563}, 64 * "a", api)
    session.guard_created = True
    session.claimed = True
    await session.release()
    api.rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_reporter_reenabled_by_another_path_is_not_paused_again():
    api = AsyncMock()
    api.failure = None
    session = stream.StreamSession({"id": 563}, 64 * "a", api)
    session.original = {".id": "*1", "interval": "1m", "disabled": "false"}
    session.cfg = {"name": "owned-guard"}
    session.timer = AsyncMock(
        return_value={".id": "*1", "disabled": "false", "interval": "2m"}
    )
    with pytest.raises(RuntimeError):
        await session.verify_ownership()
    api.rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_is_disabled_in_shadow_and_scheduler_standby(monkeypatch):
    monkeypatch.setattr(stream.settings, "NATIVE_STREAM_ROUTER_IDS", "563")
    monkeypatch.setattr(
        stream.settings, "NATIVE_STREAM_REPORTER_HASHES", "563:" + 64 * "a"
    )
    monkeypatch.setattr(stream.settings, "SHADOW_MODE", True)
    stream.start()
    assert not stream._tasks
    monkeypatch.setattr(stream.settings, "SHADOW_MODE", False)
    monkeypatch.setattr(stream.settings, "RUN_SCHEDULER", False)
    stream.start()
    assert not stream._tasks


@pytest.mark.asyncio
async def test_another_ram_lease_owner_is_not_overwritten():
    api = AsyncMock()
    cfg = lease_sources(563, "1m")
    cfg["owner"] = "new-owner"
    api.rpc.return_value = {
        "rows": [
            {
                ".id": "*1",
                "list": cfg["list"],
                "address": "127.255.0.1",
                "dynamic": "true",
                "comment": "Bitwave native API RAM lease:other-owner",
            }
        ]
    }
    with pytest.raises(RuntimeError, match="Another native owner"):
        await touch_lease(api, cfg)
    assert api.rpc.await_count == 1


@pytest.mark.asyncio
async def test_fresh_guard_between_claim_and_first_heartbeat_cannot_be_stolen():
    api = AsyncMock()
    info = {"id": 563, "identity": "Router-Test"}
    source = ':local tok "' + stream.derive_router_token(info["identity"]) + '"'
    session = stream.StreamSession(
        info, hashlib.sha256(source.encode()).hexdigest(), api
    )
    cfg = lease_sources(563, "1m")
    original = {
        ".id": "*0",
        "name": stream.REPORTER,
        "disabled": "false",
        "interval": "1m",
    }
    other = {
        ".id": "*1",
        "name": cfg["name"],
        "on-event": cfg["guard"],
        "comment": stream.GUARD_COMMENT + ":" + str(int(time.time())) + ":" + 32 * "a",
    }

    async def read(path, properties, query=()):
        if path == "/system/script/print":
            assert query == ("?name=" + stream.REPORTER,)
        return {
            "/system/identity/print": [{"name": info["identity"]}],
            "/system/resource/print": [
                {"board-name": "RB951Ui-2HnD", "version": "7.19.6 (stable)"}
            ],
            "/system/script/print": [{"name": stream.REPORTER, "source": source}],
            "/system/scheduler/print": [original, other],
            "/ip/firewall/address-list/print": [],
        }[path]

    session.read = read
    with pytest.raises(RuntimeError, match="Another native owner"):
        await session.preflight()
    api.rpc.assert_not_awaited()


@pytest.mark.asyncio
async def test_interface_subscriptions_exclude_unneeded_customer_ppp_counters():
    api = AsyncMock()
    api.ended = {}
    metadata = [
        {".id": "*1", "name": "ether1", "type": "ether"},
        {".id": "*2", "name": "pppoe-out", "type": "pppoe-out"},
        {".id": "*3", "name": "<pppoe-customer>", "type": "pppoe-in"},
        {".id": "*4", "name": "wlan1", "type": "wlan"},
    ]

    async def rpc(path, args):
        if args[".proplist"] == ".id,name,type":
            return {"rows": metadata}
        return {"rows": [r for r in metadata if r[".id"] in args["from"].split(",")]}

    api.rpc.side_effect = rpc
    api.subscribe_initial.return_value = "stream"
    tables = NativeTables(api, wan="pppoe-out")
    await tables.refresh("interfaces")
    assert tables.orders["interfaces"] == ["*1", "*2", "*4"]
    assert api.subscribe_initial.call_args.args[1]["from"] == "*1,*2,*4"


@pytest.mark.asyncio
async def test_old_owner_cannot_resume_reporter_under_new_owner_guard():
    api = AsyncMock()
    api.failure = None
    session = stream.StreamSession({"id": 563}, 64 * "a", api)
    session.guard_created = True
    session.claimed = True
    session.original = {".id": "*0", "disabled": "false", "interval": "1m"}
    session.cfg = {"name": "guard", "guard": "expected-source", "list": "owned-lease"}
    session.timer = AsyncMock(return_value={".id": "*0", "disabled": "true"})
    session.read = AsyncMock(
        side_effect=[
            [
                {
                    ".id": "*2",
                    "name": "guard",
                    "on-event": "expected-source",
                    "comment": "another-owner",
                }
            ],
            [],
        ]
    )
    await session.release()
    api.rpc.assert_not_awaited()
    session.timer.assert_not_awaited()


@pytest.mark.asyncio
async def test_host_stats_only_stream_for_authorized_or_bypassed_entries():
    api = AsyncMock()
    api.ended = {}
    rows = [
        {".id": "*1", "authorized": "true", "bypassed": "false"},
        {".id": "*2", "authorized": "false", "bypassed": "true"},
        {".id": "*3", "authorized": "false", "bypassed": "false"},
    ]

    async def rpc(path, args):
        if args[".proplist"] == ".id,authorized,bypassed":
            return {"rows": rows}
        return {"rows": [r for r in rows if r[".id"] in args["from"].split(",")]}

    api.rpc.side_effect = rpc
    api.subscribe_initial.return_value = "feed"
    tables = NativeTables(api)
    await tables.refresh("hosts")
    assert tables.orders["hosts"] == ["*1", "*2"]
    assert api.subscribe_initial.call_args.args[1]["from"] == "*1,*2"

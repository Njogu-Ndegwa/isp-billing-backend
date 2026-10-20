from unittest.mock import AsyncMock

import pytest

from app.services import native_router_stream as stream
from app.services.native_router_api import NativeApiError, NativeTables
from app.services.native_router_lease import lease_sources, touch_lease
import hashlib
import time


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

    async def read(path, properties):
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
    api.subscribe.return_value = "stream"
    tables = NativeTables(api, wan="pppoe-out")
    await tables.refresh("interfaces")
    assert tables.orders["interfaces"] == ["*1", "*2", "*4"]
    assert api.subscribe.call_args.args[1]["from"] == "*1,*2,*4"


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
    api.subscribe.return_value = "feed"
    tables = NativeTables(api)
    await tables.refresh("hosts")
    assert tables.orders["hosts"] == ["*1", "*2"]
    assert api.subscribe.call_args.args[1]["from"] == "*1,*2"

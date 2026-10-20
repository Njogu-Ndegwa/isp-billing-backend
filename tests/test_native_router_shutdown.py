"""Request draining must leave time for native accounting ownership transfer."""
import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import urllib.error
import urllib.request

import httpx
import pytest
import yaml

from app.services import native_router_stream as stream


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError])
@pytest.mark.parametrize("recovers", [True, False])
async def test_local_ingestion_transport_failure_preserves_owner_until_recovery_or_deadline(
    monkeypatch, caplog, failure, recovers
):
    clock, attempts = [100.0], []
    api = AsyncMock()
    api.failure, api.ended = None, {}
    api.rpc.return_value = {"done": {"ret": "0"}}
    session = AsyncMock()
    session.preflight.return_value = "ether1"
    session.cfg, session.last_accepted = {}, None
    tables = SimpleNamespace(
        bootstrap=AsyncMock(), refresh=AsyncMock(), groups={k: [] for k in stream.STREAM_TABLES},
        orders={}, observed={}, inventory_scan=None, snapshot=lambda: {}, inventory_accepted=Mock(),
    )

    class Http:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, *args, **kwargs):
            attempts.append(clock[0])
            if len(attempts) == 1 or not recovers:
                raise failure("private response body must not be logged")
            return SimpleNamespace(status_code=200, raise_for_status=lambda: None,
                                   json=lambda: {"next_push_seconds": 60})

    async def advance(seconds):
        clock[0] += seconds
        if recovers and len(attempts) == 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(stream, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(stream, "asyncio", SimpleNamespace(
        sleep=advance, wait_for=asyncio.wait_for, CancelledError=asyncio.CancelledError,
    ))
    monkeypatch.setattr(stream, "load_router", AsyncMock(return_value={
        "id": 563, "identity": "Router-test", "ip_address": "10.0.0.217",
        "username": "test", "password": "test", "port": 8728,
    }))
    monkeypatch.setattr(stream, "AsyncNativeAPI", lambda *args: api)
    monkeypatch.setattr(stream, "StreamSession", lambda *args: session)
    monkeypatch.setattr(stream, "NativeTables", lambda *args, **kwargs: tables)
    monkeypatch.setattr(stream, "native_api_to_v3", lambda *args, **kwargs: {
        "hosts": [], "reports": [], "router": {},
    })
    monkeypatch.setattr(stream, "touch_lease", AsyncMock())
    monkeypatch.setattr(stream.httpx, "AsyncClient", lambda **kwargs: Http())
    monkeypatch.setattr(stream.settings, "NATIVE_STREAM_GRACEFUL_HANDOFF", True)
    monkeypatch.setattr(stream, "_stopping", True)
    expected = asyncio.CancelledError if recovers else RuntimeError
    with pytest.raises(expected):
        await stream.stream_router(563, "a" * 64)
    assert "private response body" not in caplog.text
    if recovers:
        assert attempts == [100.0, 105.0]
        assert session.last_accepted == 105.0
        tables.inventory_accepted.assert_called_once()
        session.handoff.assert_awaited_once()
        session.release.assert_not_awaited()
    else:
        assert attempts[-1] - attempts[0] > 180
        assert session.last_accepted is None
        tables.inventory_accepted.assert_not_called()
        session.handoff.assert_not_awaited()
        session.release.assert_awaited_once()
    api.close.assert_awaited_once()


def test_container_grace_covers_request_drain_and_native_cleanup():
    config = yaml.safe_load(Path("docker-compose.hetzner.yml").read_text())
    web = config["services"]["web"]
    command = web["command"]
    drain = int(command[command.index("--timeout-graceful-shutdown") + 1])
    # The collector bounds handoff and failed-handoff release at 10s each;
    # native connection close is bounded at 5s.
    native_cleanup_budget = 25
    grace = web["stop_grace_period"]
    assert grace.endswith("s")
    assert int(grace[:-1]) >= drain + native_cleanup_budget


@pytest.mark.skipif(os.name != "posix", reason="Exercises Unix container SIGTERM delivery")
@pytest.mark.parametrize("bounded_drain", [False, True])
def test_inflight_request_cannot_prevent_bounded_lifespan_handover(tmp_path, bounded_drain):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    entered, handed_off = tmp_path / "request-entered", tmp_path / "handed-off"
    script = r"""
import asyncio, pathlib, uvicorn
entered = pathlib.Path(ENTERED)
handed_off = pathlib.Path(HANDED_OFF)
async def app(scope, receive, send):
    if scope['type'] == 'lifespan':
        while True:
            event = await receive()
            if event['type'] == 'lifespan.startup':
                await send({'type':'lifespan.startup.complete'})
            elif event['type'] == 'lifespan.shutdown':
                # This represents the existing native stop() hook. The test
                # checks whether uvicorn reaches it while a request is held.
                handed_off.write_text('completed')
                await send({'type':'lifespan.shutdown.complete'})
                return
    else:
        entered.write_text('entered')
        await asyncio.sleep(30)
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'ok'})
uvicorn.run(app, host='127.0.0.1', port=PORT, log_level='critical',
            timeout_graceful_shutdown=DRAIN, access_log=False)
""".replace("ENTERED", repr(str(entered))).replace("HANDED_OFF", repr(str(handed_off)))
    script = script.replace("PORT", str(port)).replace("DRAIN", "1" if bounded_drain else "None")
    process = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    def request():
        deadline = time.monotonic() + 5
        while process.poll() is None and time.monotonic() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/hold", timeout=4).close()
                return
            except (urllib.error.URLError, TimeoutError):
                if entered.exists():
                    return
                time.sleep(.02)
    worker = threading.Thread(target=request, daemon=True)
    try:
        worker.start()
        deadline = time.monotonic() + 5
        while not entered.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert entered.exists(), "Request did not enter the child server"
        process.send_signal(signal.SIGTERM)
        if bounded_drain:
            process.wait(timeout=4)
            assert handed_off.read_text() == "completed"
        else:
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=.75)
            assert not handed_off.exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        worker.join(timeout=1)

"""Real-time push installer: shared by the manual script and new-router setup.

Dennis 2026-09-27: new routers get the push at setup (no cron). Rules from the
2026-09-26 rollout: hAP lite/mini skipped; no encrypted tunnel -> skipped (not
HTTPS); previous script backed up; WAN from the default route.
"""

import pytest

from app.config import settings
from app.services import realtime_push_installer as rpi
from tests.factories import make_reseller, make_router


class FakeRouterOS:
    """Minimal RouterOS API: answers the reads, records the writes."""

    def __init__(self, *, arch="mipsbe", board="RB951Ui-2HnD", identity="Router-0001",
                 tunnel="wg-hz", ping=True, reachable=True, existing_script=None,
                 default_gw="192.168.1.1%ether1"):
        self.arch, self.board, self.identity = arch, board, identity
        self.tunnel, self.ping, self.reachable = tunnel, ping, reachable
        self.scripts = {}
        if existing_script is not None:
            self.scripts["bitwave-usage-push"] = existing_script
        self.schedulers = {}
        self.default_gw = default_gw
        self.writes = []

    def __call__(self, *a, **k):        # used as api_factory
        return self

    def connect(self):
        return self.reachable

    def disconnect(self):
        pass

    def send_command(self, path, args=None):
        args = args or {}
        if path == "/system/identity/print":
            return {"data": [{"name": self.identity}]}
        if path == "/system/resource/print":
            return {"data": [{"architecture-name": self.arch, "board-name": self.board,
                              "version": "7.20.7", "free-hdd-space": "110000000", "cpu-load": "9"}]}
        if path == "/ip/route/print":
            rows = [{"dst-address": "0.0.0.0/0", "active": "true", "immediate-gw": self.default_gw}]
            if self.tunnel:
                rows.append({"dst-address": "10.251.0.0/16", "active": "true", "gateway": self.tunnel})
            return {"data": rows}
        if path == "/interface/wireguard/print":
            return {"data": [{"name": self.tunnel}] if self.tunnel else []}
        if path in ("/interface/l2tp-client/print", "/interface/sstp-client/print", "/log/print"):
            return {"data": []}
        if path == "/interface/print":
            return {"data": [{"name": n} for n in ("ether1", "ether2", "pppoe-out1", "wlan1")]}
        if path == "/ping":
            return {"data": [{"time": "12ms"}] if self.ping else [{"status": "timeout"}]}
        if path == "/system/script/print":
            return {"data": [{".id": f"*{n}", "name": n, "source": s} for n, s in self.scripts.items()]}
        if path == "/system/scheduler/print":
            return {"data": [{".id": f"*{n}", "name": n} for n in self.schedulers]}
        self.writes.append((path, dict(args)))
        if path == "/system/script/add":
            self.scripts[args["name"]] = args["source"]
        elif path == "/system/script/set":
            name = args[".id"].lstrip("*")
            self.scripts[name] = args["source"]
        elif path == "/system/scheduler/add":
            self.schedulers[args["name"]] = args
        return {"data": []}


ROUTER = {"id": 1, "name": "R1", "identity": "Router-0001", "ip_address": "10.0.0.9",
          "username": "u", "password": "p", "port": 8728}


def test_installs_over_the_tunnel_and_adds_the_scheduler():
    api = FakeRouterOS()
    out = rpi.install_router(ROUTER, skip_run=True, api_factory=api)
    assert out["status"] == "installed"
    assert out["url"] == settings.REALTIME_TUNNEL_PUSH_URL
    assert '\\"v\\":3' in api.scripts["bitwave-usage-push"]
    assert api.schedulers["bitwave-usage-push"]["interval"] == "60s"
    assert not any(p == "/system/script/run" for p, _ in api.writes)       # skip_run honoured


def test_hap_lite_is_skipped_and_nothing_is_written():
    api = FakeRouterOS(arch="smips", board="hAP lite")
    out = rpi.install_router(ROUTER, api_factory=api)
    assert out["status"] == "skipped_small_board" and api.writes == []


@pytest.mark.parametrize("tunnel,ping", [(None, True), ("wg-hz", False)])
def test_no_working_tunnel_means_no_https_fallback(tunnel, ping):
    api = FakeRouterOS(tunnel=tunnel, ping=ping)
    out = rpi.install_router(ROUTER, api_factory=api)
    assert out["status"] == "skipped_no_tunnel" and api.writes == []
    forced = rpi.install_router(ROUTER, api_factory=FakeRouterOS(tunnel=tunnel, ping=ping),
                                force_https=True, skip_run=True)
    assert forced["status"] == "installed" and forced["url"] == rpi.PUBLIC_URL


def test_previous_script_is_backed_up_and_wan_comes_from_the_default_route():
    api = FakeRouterOS(existing_script="old v1 push", default_gw="10.1.1.1%pppoe-out1")
    out = rpi.install_router(ROUTER, skip_run=True, api_factory=api)
    assert out["status"] == "installed" and out["wan"] == "pppoe-out1"
    assert api.scripts["bitwave-usage-push-prev"] == "old v1 push"
    assert '[find name="pppoe-out1"]' in api.scripts["bitwave-usage-push"]


def test_wrong_router_behind_the_address_is_left_alone():
    api = FakeRouterOS(identity="Router-9999")
    assert rpi.install_router(ROUTER, api_factory=api)["status"] == "identity_mismatch"
    assert api.writes == []


@pytest.mark.asyncio
async def test_setup_install_waits_for_the_tunnel_then_stops(db, monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PUSH_INSTALL_AT_SETUP", True)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity="Router-0001")
    await db.commit()
    answers = iter(["unreachable", "skipped_no_tunnel", "installed", "installed"])
    calls, sleeps = [], []

    def fake_install(info, **kw):
        calls.append((info["id"], kw))
        return {"id": info["id"], "status": next(answers)}

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    out = await rpi.install_after_provisioning(router.id, sleep=fake_sleep, install=fake_install)
    assert out["status"] == "installed"
    assert len(calls) == 3                                    # stopped once installed
    assert all(kw == {"apply": True, "skip_run": True} for _, kw in calls)
    assert sleeps[0] == rpi.SETUP_FIRST_DELAY_SECONDS


@pytest.mark.asyncio
async def test_setup_install_gives_up_quietly_on_a_hap_lite(db, monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PUSH_INSTALL_AT_SETUP", True)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    await db.commit()
    calls = []

    async def no_sleep(_):
        pass

    def fake_install(info, **kw):
        calls.append(1)
        return {"status": "skipped_small_board"}

    out = await rpi.install_after_provisioning(router.id, sleep=no_sleep, install=fake_install)
    assert out["status"] == "skipped_small_board" and calls == [1]


@pytest.mark.asyncio
async def test_setup_install_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PUSH_INSTALL_AT_SETUP", False)

    def must_not_run(*a, **k):
        raise AssertionError("installed while switched off")

    out = await rpi.install_after_provisioning(1, install=must_not_run)
    assert out["status"] == "disabled"

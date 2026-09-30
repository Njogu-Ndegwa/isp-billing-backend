"""Standard router runtime: the check-in applier + management-tunnel watchdog
installed automatically (app/services/standard_runtime_enrol.py), the
watchdog module (app/services/mgmt_watchdog_script.py), the check-in install
helpers, and CHECKIN_ROUTER_IDS="all" enrolment on the server side."""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import settings
from app.db import database
from app.db.models import Router, RouterAuthMethod, SubscriptionStatus
from app.services import checkin_applier_script as applier
from app.services import checkin_delivery
from app.services import mgmt_watchdog_script as wd
from app.services import standard_runtime_enrol as enrol
from tests.factories import make_reseller, make_router
from tests.test_router_checkin import _checkin, _parse_frame, client, pilot  # noqa: F401  (fixtures)


# --- pure rules -------------------------------------------------------------

@pytest.mark.parametrize("board,arch,small", [
    ("hAP lite", "smips", True),
    ("hAP mini", "smips", True),          # smips even without "lite" in the name
    ("hAP ac lite", "mipsbe", True),      # Dennis's rule is literal: anything "lite"
    ("RB951Ui-2HnD", "mipsbe", False),
    ("hAP ax S", "arm64", False),
    ("", "", False),
])
def test_small_board_rule(board, arch, small):
    assert enrol.is_small_board(board, arch) is small


def test_recheck_windows():
    assert enrol.recheck_after("small board hAP lite (HTTPS check-in too costly)") == timedelta(days=7)
    assert enrol.recheck_after("no watched tunnel: nothing") == timedelta(days=7)
    assert enrol.recheck_after("scheduler disabled on router, left alone") == timedelta(days=7)
    assert enrol.recheck_after("unreachable") == timedelta(minutes=30)
    assert enrol.recheck_after(None) == timedelta(minutes=30)


def test_scope(monkeypatch):
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_MIN_ROUTER_ID", 540)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXTRA_ROUTER_IDS", "10, 224")
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXCLUDE_ROUTER_IDS", "541,224")
    assert enrol.in_scope(540) and enrol.in_scope(600) and enrol.in_scope(10)
    assert not enrol.in_scope(539) and not enrol.in_scope(541) and not enrol.in_scope(224)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_MIN_ROUTER_ID", 0)
    assert enrol.in_scope(1)


def test_auto_install_is_off_by_default():
    from app.config import Settings
    assert Settings.model_fields["STANDARD_RUNTIME_AUTO_INSTALL"].default is False


# --- "all" enrolment ----------------------------------------------------------

def test_checkin_enrolment_list_all_and_exclude(monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_EXCLUDE_ROUTER_IDS", "")
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "12,47")
    assert checkin_delivery.checkin_router_enrolled(12) and not checkin_delivery.checkin_router_enrolled(13)
    assert not checkin_delivery.checkin_all_routers()
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", " ALL ")
    assert checkin_delivery.checkin_all_routers()
    assert checkin_delivery.checkin_router_enrolled(13) and checkin_delivery.checkin_router_enrolled("99")
    assert checkin_delivery.checkin_router_ids() == frozenset()
    monkeypatch.setattr(settings, "CHECKIN_EXCLUDE_ROUTER_IDS", "13")
    assert not checkin_delivery.checkin_router_enrolled(13)
    assert not checkin_delivery.checkin_router_enrolled(None)
    # the exclude list wins over an explicit list too
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "13")
    assert not checkin_delivery.checkin_router_enrolled(13)


def test_all_enrolment_reaches_the_payment_hints(monkeypatch):
    checkin_delivery.reset_state()
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", True)
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "all")
    monkeypatch.setattr(settings, "CHECKIN_EXCLUDE_ROUTER_IDS", "8")
    checkin_delivery.note_payment_initiated(7)
    checkin_delivery.note_payment_initiated(8)
    assert checkin_delivery.payment_hint_active(7) and not checkin_delivery.payment_hint_active(8)
    snap = checkin_delivery.stats_snapshot()
    assert snap["all_routers"] is True and snap["excluded_router_ids"] == [8]
    checkin_delivery.reset_state()


@pytest.mark.asyncio
async def test_all_answers_a_router_that_is_not_listed(client, pilot, monkeypatch):
    # Router-0999 is outside the list the client fixture sets: idle before...
    resp = await _checkin(client, [], identity="Router-0999")
    assert _parse_frame(resp.text)[2] == checkin_delivery.IDLE_POLL_SECONDS
    # ...and a normal (non-idle) reply with "all".
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "all")
    resp = await _checkin(client, ["AA:BB:CC:00:00:06"], identity="Router-0999")
    _, count, next_s, _ = _parse_frame(resp.text)
    assert count == 0 and next_s != checkin_delivery.IDLE_POLL_SECONDS
    # the original pilot router still gets its add line
    resp = await _checkin(client, ["AA:BB:CC:00:00:01"])
    assert _parse_frame(resp.text)[1] == 1
    # excluded -> idle again
    monkeypatch.setattr(settings, "CHECKIN_EXCLUDE_ROUTER_IDS", str(pilot["other"].id))
    resp = await _checkin(client, [], identity="Router-0999")
    assert _parse_frame(resp.text)[2] == checkin_delivery.IDLE_POLL_SECONDS


# --- a fake RouterOS ----------------------------------------------------------

OPEN_SESSIONS = {"n": 0}


def counting(session_factory):
    @asynccontextmanager
    async def factory():
        OPEN_SESSIONS["n"] += 1
        try:
            async with session_factory() as s:
                yield s
        finally:
            OPEN_SESSIONS["n"] -= 1
    return factory


class FakeRouterOS:
    """Just enough of /system/script, /system/scheduler, the tunnel menus and
    address lists to exercise the installers."""

    def __init__(self, identity, *, board="RB951Ui-2HnD", arch="mipsbe", version="6.49.19", cpu=10,
                 reachable=True, sstp=None, wg=None, peers=None, hotspot=True):
        self.identity, self.board, self.arch, self.version = identity, board, arch, version
        self.cpu, self.reachable, self.hotspot = cpu, reachable, hotspot
        self.sstp = sstp or []          # [{"name": "sstp-hetzner", "disabled": "false"}]
        self.wg = wg or []              # [{"name": "wg-hz", "disabled": "false"}]
        self.peers = peers or []        # [{"interface": "wg-hz"}]
        self.menus = {"/system/script": [], "/system/scheduler": [], "/ip/firewall/address-list": []}
        self.commands = []
        self.connects = 0
        self._id = 0

    # -- helpers
    def did(self, cmd):
        return any(c == cmd for c, _ in self.commands)

    def writes(self):
        return [c for c, _ in self.commands if not c.endswith("/print")]

    def named(self, menu, name):
        return next((x for x in self.menus[menu] if x.get("name") == name), None)

    # -- MikroTikAPI surface
    def connect(self):
        assert OPEN_SESSIONS["n"] == 0, "DB session held across RouterOS I/O"
        self.connects += 1
        return self.reachable

    def disconnect(self):
        pass

    def send_command(self, cmd, args=None):
        assert OPEN_SESSIONS["n"] == 0, "DB session held across RouterOS I/O"
        args = dict(args or {})
        self.commands.append((cmd, args))
        if cmd == "/system/identity/print":
            return {"data": [{"name": self.identity}]}
        if cmd == "/system/resource/print":
            return {"data": [{"board-name": self.board, "architecture-name": self.arch,
                              "version": self.version, "cpu-load": str(self.cpu)}]}
        if cmd == "/interface/sstp-client/print":
            return {"data": self.sstp}
        if cmd == "/interface/wireguard/print":
            return {"data": self.wg} if self.version.startswith("7") else {"error": "no such command"}
        if cmd == "/interface/wireguard/peers/print":
            return {"data": self.peers} if self.version.startswith("7") else {"error": "no such command"}
        if cmd == "/ip/hotspot/ip-binding/print":
            return {"data": []} if self.hotspot else {"error": "no such command prefix"}
        menu, _, verb = cmd.rpartition("/")
        if menu in self.menus:
            rows = self.menus[menu]
            if verb == "print":
                return {"data": [dict(r) for r in rows]}
            if verb == "add":
                self._id += 1
                rows.append({".id": f"*{self._id}", "disabled": "false", **args})
                return {"data": []}
            if verb == "set":
                row = next(r for r in rows if r[".id"] == args.pop(".id"))
                row.update(args)
                return {"data": []}
            if verb == "remove":
                self.menus[menu] = [r for r in rows if r[".id"] != args[".id"]]
                return {"data": []}
        return {"data": []}


SSTP = dict(sstp=[{"name": "sstp-hetzner", "disabled": "false"}])
WG = dict(version="7.20.6", board="hAP ax S", arch="arm64",
          wg=[{"name": "wg-hz", "disabled": "false"}, {"name": "wg-aws", "disabled": "true"}],
          peers=[{"interface": "wg-hz"}, {"interface": "wg-aws"}])


# --- watchdog module ------------------------------------------------------------

def test_render_splay_per_kind():
    assert ":delay 16s" in wd.render_watchdog_source(wd.KIND_SSTP, "10.0.100.16")   # 16 % 40
    assert ":delay 9s" in wd.render_watchdog_source(wd.KIND_WG, "10.0.0.149")       # 149 % 20
    assert ":delay 0s" in wd.render_watchdog_source(wd.KIND_WG, "not-an-ip")
    for kind in (wd.KIND_SSTP, wd.KIND_WG):
        src = wd.render_watchdog_source(kind, "10.0.0.5")
        assert "__" not in src and "/system reboot" not in src
    with pytest.raises(ValueError):
        wd.render_watchdog_source("l2tp", "10.0.0.5")


@pytest.mark.parametrize("kw,kind", [
    (SSTP, wd.KIND_SSTP),
    (dict(sstp=[{"name": "sstp-hetzner", "disabled": "true"}], **WG), wd.KIND_WG),   # disabled SSTP ignored
    (WG, wd.KIND_WG),
    (dict(version="7.20.6", wg=[{"name": "wg-aws", "disabled": "true"}],
          peers=[{"interface": "wg-aws"}]), None),                                    # only a disabled wg-aws
    (dict(version="7.20.6", wg=[{"name": "wireguard1", "disabled": "false"}],
          peers=[{"interface": "wireguard1"}]), None),                                # not ours
    (dict(version="6.49.19"), None),                                                  # ROS6 L2TP-only
])
def test_detect_kind(kw, kind):
    fake = FakeRouterOS("R", **kw)
    assert wd.detect_kind(fake, fake.version)[0] == kind


def test_watchdog_install_is_idempotent_and_swaps_kind():
    fake = FakeRouterOS("R", **SSTP)
    assert wd.install_watchdog(fake, wd.KIND_WG, "10.0.0.5").status == "installed"
    assert fake.named("/system/scheduler", wd.SCRIPT_NAME_WG)
    # the router moved to SSTP: the WG variant goes, the SSTP one comes
    assert wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5").status == "installed"
    assert not fake.named("/system/script", wd.SCRIPT_NAME_WG)
    assert not fake.named("/system/scheduler", wd.SCRIPT_NAME_WG)
    sched = fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)
    assert sched["interval"] == "1m" and sched["on-event"] == "/system script run bw-mgmt-watchdog"
    assert sched["policy"] == "read,write,test"
    # again: nothing written
    fake.commands.clear()
    assert wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5").status == "unchanged"
    assert fake.writes() == []
    # an older source is updated in place, the scheduler left alone
    fake.named("/system/script", wd.SCRIPT_NAME_SSTP)["source"] = "# v2"
    assert wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5").status == "updated"
    assert len(fake.menus["/system/scheduler"]) == 1


def test_wg_watchdog_rotates_the_listen_port_only_after_a_failed_reset():
    src = wd.render_watchdog_source(wd.KIND_WG, "10.0.0.154")
    assert "bw-mgmt-watchdog-wg v5" in src and "__" not in src
    assert f":rndnum from={wd.ROTATE_PORT_MIN} to={wd.ROTATE_PORT_MAX}" in src
    assert "/interface wireguard set $wi listen-port=$np" in src
    # rotate is armed only inside the "backoff entry already there" branch, and only with working internet
    backoff = src.index(":if ([:len $b] > 0) do={")
    arm = src.index(":if ($up) do={ :set rotate true }")
    assert backoff < arm < src.index(":if ($up = false) do={ :set hold 60 }")
    # the port moves while the peer is disabled, before it is re-enabled
    assert src.index("peers disable $p") < src.index(":if ($rotate) do={") < src.index("peers enable $p }")
    assert "listen-port" not in wd.render_watchdog_source(wd.KIND_SSTP, "10.0.0.154")
    # the rotation range stays clear of the provisioning ports and the ephemeral range
    assert 51834 < wd.ROTATE_PORT_MIN or wd.ROTATE_PORT_MAX < 51820
    assert wd.ROTATE_PORT_MAX < 49152


def test_watchdog_version_tag():
    assert wd.version_tag(wd.KIND_WG) == "wg v5"
    assert wd.is_current("wg", "installed (wg v5, updated)")
    assert not wd.is_current("wg", "installed (wg, installed)")        # recorded before versions
    assert not wd.is_current(None, "installed (wg v5, updated)")
    assert wd.is_current("sstp", f"installed ({wd.version_tag(wd.KIND_SSTP)}, unchanged)")
    assert enrol.watchdog_needed(None, None, None)
    assert enrol.watchdog_needed(datetime.utcnow(), "wg", "installed (wg, installed)")
    assert not enrol.watchdog_needed(datetime.utcnow(), "wg", "installed (wg v5, unchanged)")


def test_watchdog_paused_scheduler_is_not_re_enabled():
    fake = FakeRouterOS("R", **SSTP)
    wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5")
    fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)["disabled"] = "true"
    assert wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5").status == "scheduler_disabled"
    assert fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)["disabled"] == "true"


def test_watchdog_uninstall_clears_scripts_and_ram_state():
    fake = FakeRouterOS("R", **SSTP)
    wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.5")
    fake.menus["/ip/firewall/address-list"] += [
        {".id": "*a1", "list": "bw-wd-fail", "address": "0.0.0.1"},
        {".id": "*a2", "list": "isp_portal_allow", "address": "1.2.3.4"},
    ]
    wd.uninstall_watchdog(fake)
    assert fake.menus["/system/script"] == [] and fake.menus["/system/scheduler"] == []
    assert [e["list"] for e in fake.menus["/ip/firewall/address-list"]] == ["isp_portal_allow"]


# --- check-in install helpers -----------------------------------------------------

URL = "https://isp.bitwavetechnologies.net/api/router/checkin"


def test_checkin_install_is_idempotent_and_never_runs_the_script():
    fake = FakeRouterOS("Router-0721")
    assert applier.install_checkin_applier(fake, identity="Router-0721", endpoint_url=URL)["status"] == "installed"
    sched = fake.named("/system/scheduler", applier.SCHEDULER_NAME)
    assert sched["interval"] == "60s" and sched["on-event"] == applier.scheduler_on_event()
    fake.commands.clear()
    # the applier owns its interval: a later install must not reset it
    sched["interval"] = "1m6s"
    assert applier.install_checkin_applier(fake, identity="Router-0721", endpoint_url=URL)["status"] == "unchanged"
    assert fake.writes() == [] and sched["interval"] == "1m6s"
    assert not fake.did("/system/script/run")
    applier.uninstall_checkin_applier(fake)
    assert fake.menus["/system/script"] == [] and fake.menus["/system/scheduler"] == []


# --- the job ------------------------------------------------------------------

@pytest.fixture
def wired(session_factory, monkeypatch):
    OPEN_SESSIONS["n"] = 0
    monkeypatch.setattr(database, "async_session", counting(session_factory))
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_AUTO_INSTALL", True)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_BATCH", 5)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_MIN_ROUTER_ID", 0)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXTRA_ROUTER_IDS", "")
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXCLUDE_ROUTER_IDS", "")
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_INSTALL_CHECKIN", True)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_INSTALL_WATCHDOG", True)
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", True)
    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", False)
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "all")
    monkeypatch.setattr(settings, "CHECKIN_EXCLUDE_ROUTER_IDS", "")
    monkeypatch.setattr(enrol, "_running", False)
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    routers: dict[str, FakeRouterOS] = {}
    monkeypatch.setattr(enrol, "MikroTikAPI", lambda ip, *a, **k: routers[ip])
    return routers


async def _router(db, ip, identity, reseller=None, **kw):
    reseller = reseller or await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    return await make_router(db, reseller, ip_address=ip, identity=identity, **kw)


async def _reload(db, router_id):
    db.expire_all()
    return (await db.execute(select(Router).where(Router.id == router_id))).scalars().one()


@pytest.mark.asyncio
async def test_switched_off_does_nothing(db, wired, monkeypatch):
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_AUTO_INSTALL", False)
    await _router(db, "10.0.0.50", "Router-5000")
    wired["10.0.0.50"] = FakeRouterOS("Router-5000", **SSTP)
    assert await enrol.standard_runtime_enrol_background() == []
    assert wired["10.0.0.50"].commands == []


@pytest.mark.asyncio
async def test_sheds_load_when_the_pool_is_busy(db, wired, monkeypatch):
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: True)
    await _router(db, "10.0.0.51", "Router-5001")
    wired["10.0.0.51"] = FakeRouterOS("Router-5001", **SSTP)
    assert await enrol.standard_runtime_enrol_background() == []
    assert wired["10.0.0.51"].commands == []


@pytest.mark.asyncio
async def test_standard_sstp_router_gets_both_and_is_not_contacted_again(db, wired):
    r = await _router(db, "10.0.100.16", "Router-5002")
    fake = wired["10.0.100.16"] = FakeRouterOS("Router-5002", **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.watchdog.installed and o.watchdog.kind == wd.KIND_SSTP
    assert o.checkin.installed
    assert fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)
    assert ":delay 16s" in fake.named("/system/script", wd.SCRIPT_NAME_SSTP)["source"]
    assert fake.named("/system/scheduler", applier.SCHEDULER_NAME)
    assert not fake.did("/system/script/run")
    row = await _reload(db, r.id)
    assert row.checkin_installed_at and row.mgmt_watchdog_installed_at
    assert row.mgmt_watchdog_kind == "sstp"
    assert row.router_agent_enabled is False          # the command agent is not part of it
    fake.commands.clear()
    assert await enrol.standard_runtime_enrol_background() == []
    assert fake.commands == []


@pytest.mark.asyncio
async def test_wireguard_router_gets_the_wg_watchdog(db, wired):
    r = await _router(db, "10.0.0.149", "Router-5003")
    fake = wired["10.0.0.149"] = FakeRouterOS("Router-5003", **WG)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.watchdog.installed and o.watchdog.kind == wd.KIND_WG and o.checkin.installed
    assert fake.named("/system/scheduler", wd.SCRIPT_NAME_WG)
    assert not fake.named("/system/script", wd.SCRIPT_NAME_SSTP)
    assert (await _reload(db, r.id)).mgmt_watchdog_kind == "wg"


@pytest.mark.asyncio
async def test_outdated_watchdog_is_upgraded_in_place_once(db, wired):
    """Routers enrolled with the v4 WG watchdog get v5 from the background job."""
    old = datetime.utcnow() - timedelta(days=2)
    r = await _router(db, "10.0.0.154", "Router-0983", mgmt_watchdog_installed_at=old,
                      mgmt_watchdog_checked_at=old, mgmt_watchdog_kind="wg",
                      mgmt_watchdog_reason="installed (wg, installed)",
                      checkin_installed_at=old, checkin_checked_at=old,
                      checkin_install_reason="installed (installed)")
    fake = wired["10.0.0.154"] = FakeRouterOS("Router-0983", **WG)
    wd.install_watchdog(fake, wd.KIND_WG, "10.0.0.154")
    sched = fake.named("/system/scheduler", wd.SCRIPT_NAME_WG)
    fake.named("/system/script", wd.SCRIPT_NAME_WG)["source"] = "# bw-mgmt-watchdog-wg v4"
    fake.commands.clear()
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin is None                                   # installed check-in is not touched
    assert o.watchdog.installed and "wg v5, updated" in o.watchdog.reason
    assert "v5" in fake.named("/system/script", wd.SCRIPT_NAME_WG)["source"]
    assert fake.menus["/system/scheduler"] == [sched]           # scheduler left as it was
    row = await _reload(db, r.id)
    assert wd.is_current(row.mgmt_watchdog_kind, row.mgmt_watchdog_reason)
    fake.commands.clear()
    assert await enrol.standard_runtime_enrol_background(now=datetime.utcnow() + timedelta(days=1)) == []
    assert fake.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize("board,arch", [("hAP lite", "smips"), ("hAP mini", "smips"), ("hAP ac lite", "mipsbe")])
async def test_small_board_gets_the_watchdog_but_never_the_checkin(db, wired, board, arch):
    r = await _router(db, "10.0.100.20", "Router-5004")
    fake = wired["10.0.100.20"] = FakeRouterOS("Router-5004", board=board, arch=arch, **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.watchdog.installed
    assert not o.checkin.installed and o.checkin.reason.startswith("small board")
    assert not fake.named("/system/script", applier.SCRIPT_NAME)
    row = await _reload(db, r.id)
    assert row.checkin_installed_at is None and row.checkin_install_reason.startswith("small board")
    # a hardware decision: not looked at again for a week...
    fake.commands.clear()
    assert await enrol.standard_runtime_enrol_background() == []
    assert await enrol.standard_runtime_enrol_background(now=datetime.utcnow() + timedelta(days=6)) == []
    assert fake.commands == []
    # ...then re-checked, and still skipped
    [o] = await enrol.standard_runtime_enrol_background(now=datetime.utcnow() + timedelta(days=8))
    assert o.watchdog is None and not o.checkin.installed


@pytest.mark.asyncio
async def test_unreachable_router_is_retried_later(db, wired):
    r = await _router(db, "10.0.0.52", "Router-5005")
    fake = wired["10.0.0.52"] = FakeRouterOS("Router-5005", reachable=False, **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin.reason == "unreachable" and o.watchdog.reason == "unreachable"
    row = await _reload(db, r.id)
    assert row.checkin_installed_at is None and row.mgmt_watchdog_installed_at is None
    assert row.checkin_checked_at is not None
    # not before the transient window...
    assert await enrol.standard_runtime_enrol_background(now=datetime.utcnow() + timedelta(minutes=10)) == []
    assert fake.connects == 1
    # ...then it is back and gets both
    fake.reachable = True
    [o] = await enrol.standard_runtime_enrol_background(now=datetime.utcnow() + timedelta(minutes=31))
    assert o.checkin.installed and o.watchdog.installed


@pytest.mark.asyncio
async def test_busy_router_is_left_alone_and_retried(db, wired):
    await _router(db, "10.0.0.53", "Router-5006")
    fake = wired["10.0.0.53"] = FakeRouterOS("Router-5006", cpu=97, **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin.reason.startswith("busy") and not o.watchdog.installed
    assert fake.writes() == []


@pytest.mark.asyncio
async def test_already_installed_by_hand_is_recorded_without_writes(db, wired):
    """Pilot routers got both by hand: the installer only records them."""
    r = await _router(db, "10.0.0.54", "Router-5007")
    fake = wired["10.0.0.54"] = FakeRouterOS("Router-5007", **SSTP)
    wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.0.54")
    applier.install_checkin_applier(fake, identity="Router-5007", endpoint_url=settings.CHECKIN_ENDPOINT_URL)
    fake.commands.clear()
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin.installed and o.watchdog.installed
    assert "unchanged" in o.checkin.reason and "unchanged" in o.watchdog.reason
    assert fake.writes() == []
    assert (await _reload(db, r.id)).checkin_installed_at is not None


@pytest.mark.asyncio
async def test_router_without_a_watched_tunnel(db, wired):
    r = await _router(db, "10.0.0.55", "Router-5008")
    wired["10.0.0.55"] = FakeRouterOS("Router-5008")            # ROS6, L2TP only
    [o] = await enrol.standard_runtime_enrol_background()
    assert not o.watchdog.installed and o.watchdog.reason.startswith("no watched tunnel")
    assert o.checkin.installed
    assert enrol.recheck_after((await _reload(db, r.id)).mgmt_watchdog_reason) == timedelta(days=7)


@pytest.mark.asyncio
async def test_checkin_follows_the_server_side_enrolment(db, wired, monkeypatch):
    listed = await _router(db, "10.0.0.56", "Router-5009")
    unlisted = await _router(db, "10.0.0.57", "Router-5010")
    wired["10.0.0.56"] = FakeRouterOS("Router-5009", **SSTP)
    wired["10.0.0.57"] = FakeRouterOS("Router-5010", **SSTP)
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", str(listed.id))
    outcomes = {o.router_id: o for o in await enrol.standard_runtime_enrol_background()}
    assert outcomes[listed.id].checkin.installed
    assert outcomes[unlisted.id].checkin is None and outcomes[unlisted.id].watchdog.installed
    assert not wired["10.0.0.57"].named("/system/script", applier.SCRIPT_NAME)
    # enrolled later ("all") -> picked up on a later run, check-in only
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "all")
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.router_id == unlisted.id and o.checkin.installed and o.watchdog is None


@pytest.mark.asyncio
@pytest.mark.parametrize("flag,value", [("CHECKIN_KILL_SWITCH", True), ("CHECKIN_ENABLED", False),
                                        ("STANDARD_RUNTIME_INSTALL_CHECKIN", False)])
async def test_no_checkin_install_while_the_channel_is_off(db, wired, monkeypatch, flag, value):
    monkeypatch.setattr(settings, flag, value)
    await _router(db, "10.0.0.58", "Router-5011")
    fake = wired["10.0.0.58"] = FakeRouterOS("Router-5011", **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin is None and o.watchdog.installed
    assert not fake.named("/system/script", applier.SCRIPT_NAME)


@pytest.mark.asyncio
async def test_radius_router_gets_no_checkin(db, wired):
    await _router(db, "10.0.0.59", "Router-5012", auth_method=RouterAuthMethod.RADIUS)
    wired["10.0.0.59"] = FakeRouterOS("Router-5012", **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin is None and o.watchdog.installed


@pytest.mark.asyncio
async def test_ineligible_or_out_of_scope_routers_are_never_contacted(db, wired, monkeypatch):
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    await _router(db, "10.0.0.60", "Router-5013", reseller=suspended)
    await _router(db, "10.0.0.61", "Router-5014", last_status=False)
    excluded = await _router(db, "10.0.0.62", "Router-5015")
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXCLUDE_ROUTER_IDS", str(excluded.id))
    for ip, ident in (("10.0.0.60", "Router-5013"), ("10.0.0.61", "Router-5014"), ("10.0.0.62", "Router-5015")):
        wired[ip] = FakeRouterOS(ident, **SSTP)
    assert await enrol.standard_runtime_enrol_background() == []
    assert all(f.commands == [] for f in wired.values())


@pytest.mark.asyncio
async def test_min_router_id_limits_to_new_routers(db, wired, monkeypatch):
    old = await _router(db, "10.0.0.63", "Router-5016")
    new = await _router(db, "10.0.0.64", "Router-5017")
    wired["10.0.0.63"] = FakeRouterOS("Router-5016", **SSTP)
    wired["10.0.0.64"] = FakeRouterOS("Router-5017", **SSTP)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_MIN_ROUTER_ID", new.id)
    assert [o.router_id for o in await enrol.standard_runtime_enrol_background()] == [new.id]
    assert wired["10.0.0.63"].commands == []
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXTRA_ROUTER_IDS", str(old.id))
    assert [o.router_id for o in await enrol.standard_runtime_enrol_background()] == [old.id]


@pytest.mark.asyncio
async def test_identity_mismatch_is_not_touched(db, wired):
    await _router(db, "10.0.0.65", "Router-5018")
    fake = wired["10.0.0.65"] = FakeRouterOS("Router-9999", **SSTP)
    [o] = await enrol.standard_runtime_enrol_background()
    assert o.checkin.reason.startswith("identity mismatch")
    assert fake.writes() == []


@pytest.mark.asyncio
async def test_batch_limit_and_new_routers_first(db, wired, monkeypatch):
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_BATCH", 2)
    reseller = await make_reseller(db, subscription_status=SubscriptionStatus.ACTIVE)
    ids = []
    for i in range(3):
        r = await _router(db, f"10.0.1.{i}", f"Router-60{i}0", reseller=reseller)
        ids.append(r.id)
        wired[f"10.0.1.{i}"] = FakeRouterOS(f"Router-60{i}0", reachable=False)
    first = [o.router_id for o in await enrol.standard_runtime_enrol_background()]
    assert first == ids[:2]
    # 31 min later the never-looked-at router goes before the two retried ones
    later = datetime.utcnow() + timedelta(minutes=31)
    assert [o.router_id for o in await enrol.standard_runtime_enrol_background(now=later)][0] == ids[2]


# --- right after registration (/complete) --------------------------------------

async def _no_sleep(_seconds):
    return None


def test_flagged_device_mode_is_rechecked_weekly_not_every_30_min():
    reason = ("scheduler_failed: failure: configuration flagged, check all router configuration "
              "for unauthorized changes and update device-mode")
    assert enrol.recheck_after(reason) == timedelta(days=7)


@pytest.mark.asyncio
async def test_registration_installs_at_once_and_stops(db, wired):
    r = await _router(db, "10.0.100.80", "Router-6000")
    fake = wired["10.0.100.80"] = FakeRouterOS("Router-6000", **SSTP)
    sleeps = []

    async def rec_sleep(s):
        sleeps.append(s)

    o = await enrol.install_after_registration(r.id, sleep=rec_sleep)
    assert o.watchdog.installed and o.checkin.installed
    assert sleeps == [enrol.SETUP_FIRST_DELAY_SECONDS]        # no retries needed
    assert fake.connects == 1 and not fake.did("/system/script/run")
    row = await _reload(db, r.id)
    assert row.checkin_installed_at and row.mgmt_watchdog_installed_at
    # the background job then has nothing left to do for it
    fake.commands.clear()
    assert await enrol.standard_runtime_enrol_background() == []
    assert fake.commands == []


@pytest.mark.asyncio
async def test_registration_retries_while_the_tunnel_comes_up(db, wired):
    r = await _router(db, "10.0.100.81", "Router-6001")
    fake = wired["10.0.100.81"] = FakeRouterOS("Router-6001", reachable=False, **SSTP)
    tries = {"n": 0}
    real_install = enrol.probe_and_install_sync

    def install(c):
        tries["n"] += 1
        if tries["n"] == 3:
            fake.reachable = True              # the tunnel is up by the third try
        return real_install(c)

    o = await enrol.install_after_registration(r.id, sleep=_no_sleep, install=install)
    assert tries["n"] == 3 and o.watchdog.installed and o.checkin.installed


@pytest.mark.asyncio
async def test_registration_retries_when_no_tunnel_is_up_yet(db, wired):
    # At setup "no watched tunnel" is transient (the background job treats it as
    # permanent for a week): the SSTP client appears on the next try.
    r = await _router(db, "10.0.100.82", "Router-6002")
    fake = wired["10.0.100.82"] = FakeRouterOS("Router-6002")
    real_install = enrol.probe_and_install_sync
    tries = {"n": 0}

    def install(c):
        tries["n"] += 1
        if tries["n"] == 2:
            fake.sstp = list(SSTP["sstp"])
        return real_install(c)

    o = await enrol.install_after_registration(r.id, sleep=_no_sleep, install=install)
    assert tries["n"] == 2 and o.watchdog.installed


@pytest.mark.asyncio
async def test_registration_gives_up_after_the_short_schedule(db, wired):
    r = await _router(db, "10.0.100.83", "Router-6003")
    wired["10.0.100.83"] = FakeRouterOS("Router-6003", reachable=False, **SSTP)
    o = await enrol.install_after_registration(r.id, sleep=_no_sleep)
    assert o.checkin.reason == "unreachable"
    assert wired["10.0.100.83"].connects == 1 + len(enrol.SETUP_RETRY_DELAYS_SECONDS)
    # left to the background job: recorded as a 30-minute recheck
    assert (await _reload(db, r.id)).checkin_checked_at is not None


@pytest.mark.asyncio
async def test_registration_respects_switch_scope_and_owner(db, wired, monkeypatch):
    r = await _router(db, "10.0.100.84", "Router-6004")
    fake = wired["10.0.100.84"] = FakeRouterOS("Router-6004", **SSTP)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_AUTO_INSTALL", False)
    assert await enrol.install_after_registration(r.id, sleep=_no_sleep) is None
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_AUTO_INSTALL", True)
    monkeypatch.setattr(settings, "STANDARD_RUNTIME_EXCLUDE_ROUTER_IDS", str(r.id))
    assert await enrol.install_after_registration(r.id, sleep=_no_sleep) is None
    suspended = await make_reseller(db, subscription_status=SubscriptionStatus.SUSPENDED)
    r2 = await _router(db, "10.0.100.85", "Router-6005", reseller=suspended)
    wired["10.0.100.85"] = FakeRouterOS("Router-6005", **SSTP)
    assert await enrol.install_after_registration(r2.id, sleep=_no_sleep) is None
    assert fake.connects == 0 and wired["10.0.100.85"].connects == 0


@pytest.mark.asyncio
async def test_registration_never_raises(db, wired):
    def boom(_c):
        raise RuntimeError("router API exploded")

    r = await _router(db, "10.0.100.86", "Router-6006")
    wired["10.0.100.86"] = FakeRouterOS("Router-6006", **SSTP)
    await enrol.install_after_registration(r.id, sleep=_no_sleep, install=boom)   # no exception


def test_complete_callback_schedules_the_install():
    import inspect
    from app.api import provisioning as provisioning_api
    src = inspect.getsource(provisioning_api.complete_provision)
    assert "schedule_install_after_registration(router_obj.id)" in src

"""Post-provision setup check + the end of the provisioning script.

Pinned incident (2026-10-30): routers 673 (RB951Ui-2HnD, RouterOS 7.12.1) and
674 (hEX lite, 7.16.1) logged "Provisioning complete! Rebooting in 5
seconds..." from the WinBox-terminal import, never rebooted, and kept the
import as a stuck /system script job owned by admin; 673 sat at ~100% CPU for
35+ minutes and its reseller got the "CPU above 90%, please restart" SMS.
"""

from datetime import datetime, timedelta
from itertools import count
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import settings
from app.db.models import (
    ProvisioningToken, ProvisioningTokenStatus, ResellerInboxMessage, Router, SmsMessage,
    SmsMessageKind, SubscriptionStatus, UserRole,
)
from app.services import provision_verify as pv
from app.services import provisioning
from app.services import router_overload_alerts as oa
from tests import test_provisioning_hetzner as hz
from tests import test_provisioning_sstp as sstp
from tests.factories import make_reseller, make_router

_PK = count(91_000)
REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. The script ends cleanly: no interactive reboot, on v6 and v7
# ---------------------------------------------------------------------------


def _scripts(monkeypatch) -> dict:
    golden = hz._settings(monkeypatch, enabled=True)
    out = {name: provisioning.generate_rsc_script(tok) for name, tok in golden.tokens().items()}
    out["v7_wg_hetzner"] = provisioning.generate_rsc_script(hz._wg_token())
    sstp._settings(monkeypatch, enabled=True)
    out["v6_sstp_hetzner"] = provisioning.generate_rsc_script(sstp._sstp_token())
    return out


def _commands(script: str) -> list:
    return [l.strip() for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]


def test_script_never_reboots_and_the_import_ends_after_the_notify(monkeypatch):
    for name, script in _scripts(monkeypatch).items():
        cmds = _commands(script)
        assert not any("/system reboot" in c or c == "reboot" for c in cmds), name
        assert "Rebooting in" not in script, name
        # The /complete notify is the last real step; only a log line follows.
        notify = max(i for i, c in enumerate(cmds) if "/api/provision/" in c and "/complete" in c)
        tail = cmds[notify + 1:]
        assert all(c.startswith((":log", "}")) for c in tail), (name, tail)
        assert not any(c.startswith(":delay") for c in tail), name
        assert "No reboot needed" in cmds[-1], name


def test_script_still_parses_structurally_on_v6_and_v7(monkeypatch):
    # A stray brace or a trailing line continuation aborts the whole import.
    for name, script in _scripts(monkeypatch).items():
        assert script.count("{") == script.count("}"), name
        assert script.count("[") == script.count("]"), name
        assert not any(line.rstrip().endswith("\\") for line in script.splitlines()), name
        depth = 0
        for ch in script:
            depth += {"{": 1, "}": -1}.get(ch, 0)
            assert depth >= 0, name


def test_v6_sstp_and_v7_wg_hz_tunnels_are_unchanged(monkeypatch):
    scripts = _scripts(monkeypatch)
    v7 = scripts["v7_wg_hetzner"]
    assert "/interface wireguard add name=wg-hz" in v7
    assert "sstp-client" not in "\n".join(_commands(v7))
    v6 = scripts["v6_sstp_hetzner"]
    assert "sstp-client add name=sstp-hetzner" in v6
    assert "/interface wireguard" not in "\n".join(_commands(v6))
    for script in (v6, v7):
        # WAN, hotspot, API steps all still there and before the notify.
        notify = script.index("/complete")
        for step in ("/ip dhcp-client add interface=ether1", "/ip hotspot profile",
                     "/ip service set api", "/system identity set"):
            assert -1 < script.index(step) < notify, step


# ---------------------------------------------------------------------------
# 2. Individual checks
# ---------------------------------------------------------------------------


def test_hotspot_check():
    assert pv.check_hotspot([{"name": "hotspot1", "interface": "bridge", "disabled": "false"}])["ok"] is True
    assert pv.check_hotspot([{"name": "hs", "interface": "bridge", "disabled": "true"}])["ok"] is False
    assert pv.check_hotspot([{"name": "hs", "interface": "bridge", "invalid": "true"}])["ok"] is False
    off = pv.check_hotspot([{"name": "hs", "interface": "bridgeLocal"}])
    assert off["ok"] is False and "bridgeLocal" in off["detail"]
    assert pv.check_hotspot([])["ok"] is False


def test_wan_check_bound_dhcp_or_default_route():
    assert pv.check_wan([{"interface": "ether1", "status": "bound", "address": "192.168.1.5/24"}], [])["ok"]
    assert pv.check_wan([{"interface": "ether1", "status": "searching..."}],
                        [{"dst-address": "0.0.0.0/0", "active": "true", "gateway": "pppoe-out1"}])["ok"]
    bad = pv.check_wan([{"interface": "ether1", "status": "searching..."}],
                       [{"dst-address": "0.0.0.0/0", "active": "false"}])
    assert bad["ok"] is False and "searching" in bad["detail"]


@pytest.mark.parametrize("res,ok", [
    ({"success": True, "data": [{"status": "finished"}]}, True),
    ({"error": "failure: closing connection: <308 Permanent Redirect> 1.2.3.4:80"}, True),
    ({"error": "failure: could not resolve dns name"}, False),
    ({"error": "failure: dns server failure"}, False),
    ({"error": "failure: connection timeout"}, True),     # resolved; fetch blocked
    ({}, None),
])
def test_dns_check(res, ok):
    assert pv.check_dns(res)["ok"] is ok


def test_usage_push_not_expected_on_small_boards(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PUSH_INSTALL_AT_SETUP", True)
    assert pv.check_usage_push([], "smips")["ok"] is True
    assert pv.check_usage_push([], "mipsbe")["ok"] is False
    assert pv.check_usage_push([{"name": "bitwave-usage-push"}], "mipsbe")["ok"] is True
    assert pv.check_usage_push([{"name": "bitwave-usage-push", "disabled": "true"}], "arm")["ok"] is False


def test_stuck_jobs_ignore_logins_our_api_user_and_bitwave_scripts():
    jobs = [
        {".id": "*1", "type": "login", "owner": "admin"},                  # WinBox terminal
        {".id": "*2", "type": "command", "owner": "admin", "parent": "*1"},  # the stuck import
        {".id": "*3", "type": "api-login", "owner": "bitwave-api"},
        {".id": "*4", "type": "script", "owner": "bitwave-api", "script": "bitwave-usage-push"},
        {".id": "*5", "type": "script", "owner": "admin", "script": "bw-mgmt-watchdog"},
    ]
    assert [j[".id"] for j in pv.stuck_jobs(jobs, jobs)] == ["*2"]
    # Seen once only (finished between the two samples) -> not stuck.
    assert pv.stuck_jobs(jobs, [j for j in jobs if j[".id"] != "*2"]) == []


def test_cpu_check_needs_every_sample_pegged():
    assert pv.check_cpu([95, 100, 97, 99])["ok"] is False
    assert pv.check_cpu([95, 100, 40, 99])["ok"] is True
    assert pv.check_cpu([])["ok"] is None


# ---------------------------------------------------------------------------
# 3. check_router against a fake RouterOS
# ---------------------------------------------------------------------------


class FakeAPI:
    def __init__(self, *, up=True, identity="Router-1001", hotspot=True, wan=True, dns=True,
                 push=True, cpu=12, stuck=False, job_removal_works=True, arch="mipsbe"):
        self.up, self.identity, self.arch = up, identity, arch
        self.hotspot, self.wan, self.dns, self.push = hotspot, wan, dns, push
        self.cpu, self.stuck, self.job_removal_works = cpu, stuck, job_removal_works
        self.calls: list = []
        self.rebooted = False

    def __call__(self, *a, **k):
        return self

    def connect(self):
        return self.up

    def disconnect(self):
        pass

    def reboot_router(self):
        self.rebooted = True
        self.calls.append(("/system/reboot", {}))
        return {"success": True, "status": "sent_connection_closed"}

    def send_command(self, path, args=None):
        self.calls.append((path, args or {}))
        ok = lambda data: {"success": True, "data": data}  # noqa: E731
        if path == "/system/identity/print":
            return ok([{"name": self.identity}])
        if path == "/system/resource/print":
            return ok([{"cpu-load": str(self.cpu), "board-name": "RB951Ui-2HnD", "version": "7.12.1",
                        "architecture-name": self.arch}])
        if path == "/ip/hotspot/print":
            return ok([{"name": "hotspot1", "interface": "bridge", "disabled": "false"}] if self.hotspot else [])
        if path == "/ip/dhcp-client/print":
            return ok([{"interface": "ether1", "status": "bound" if self.wan else "searching..."}])
        if path == "/ip/route/print":
            return ok([])
        if path == "/tool/fetch":
            return ok([{"status": "finished"}]) if self.dns else {"error": "failure: could not resolve dns name"}
        if path == "/system/scheduler/print":
            return ok([{"name": "bitwave-usage-push"}] if self.push else [])
        if path == "/system/script/job/print":
            jobs = [{".id": "*1", "type": "login", "owner": "admin"}]
            if self.stuck:
                jobs.append({".id": "*9", "type": "command", "owner": "admin", "started": "oct/30 05:25"})
            return ok(jobs)
        if path == "/system/script/job/remove":
            if self.job_removal_works:
                self.stuck = False
                self.cpu = 8
            return ok([])
        raise AssertionError(f"unexpected command {path}")

    def writes(self):
        return [p for p, _ in self.calls if not p.endswith("/print") and p != "/tool/fetch"]


ROUTER = {"id": 1, "name": "Kamau Net #1", "identity": "Router-1001", "ip_address": "10.0.3.9",
          "username": "bitwave-api", "password": "x", "port": 8728}


def _check(api, **kw):
    return pv.check_router(ROUTER, api_factory=api, sleep=lambda s: None, **kw)


def test_healthy_router_passes_read_only():
    api = FakeAPI()
    res = _check(api, remediate=True, allow_reboot=True)
    assert pv.verdict(res) == pv.STATUS_PASSED
    assert api.writes() == []


def test_unreachable_router():
    res = _check(FakeAPI(up=False))
    assert pv.verdict(res) == pv.STATUS_UNREACHABLE
    assert res["checks"][pv.CHECK_TUNNEL]["ok"] is False


def test_wrong_router_at_the_address_is_a_failure():
    res = _check(FakeAPI(identity="Router-0002"))
    assert pv.verdict(res) == pv.STATUS_FAILED and res["identity_mismatch"] == "Router-0002"


def test_missing_push_is_only_a_warning(monkeypatch):
    monkeypatch.setattr(settings, "REALTIME_PUSH_INSTALL_AT_SETUP", True)
    assert pv.verdict(_check(FakeAPI(push=False))) == pv.STATUS_PASSED_WARN


def test_stuck_import_is_reported_but_untouched_when_read_only():
    api = FakeAPI(stuck=True, cpu=100)
    res = _check(api, remediate=False, allow_reboot=True)
    assert pv.faults(res["checks"]) == [pv.CHECK_JOBS, pv.CHECK_CPU]
    assert api.writes() == [] and not api.rebooted


def test_stuck_import_is_removed_and_rechecked():
    api = FakeAPI(stuck=True, cpu=100)
    res = _check(api, remediate=True, allow_reboot=True)
    assert ("/system/script/job/remove", {".id": "*9"}) in api.calls
    assert not api.rebooted
    assert pv.verdict(res) == pv.STATUS_PASSED
    assert "removed" in res["checks"][pv.CHECK_JOBS]["detail"]


def test_job_that_will_not_go_triggers_one_reboot():
    api = FakeAPI(stuck=True, cpu=100, job_removal_works=False)
    res = _check(api, remediate=True, allow_reboot=True)
    assert api.rebooted and res["rebooted"]
    api2 = FakeAPI(stuck=True, cpu=100, job_removal_works=False)
    assert not _check(api2, remediate=True, allow_reboot=False)["rebooted"]   # only once


def test_no_auto_fix_when_anything_else_is_wrong():
    api = FakeAPI(stuck=True, cpu=100, hotspot=False)
    res = _check(api, remediate=True, allow_reboot=True)
    assert api.writes() == []
    assert pv.CHECK_HOTSPOT in pv.faults(res["checks"])


# ---------------------------------------------------------------------------
# 4. End to end: stored on the token, reseller told once
# ---------------------------------------------------------------------------


@pytest.fixture
def sms_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(oa, "_spawn_sms", lambda sms_id, sender: calls.append(sms_id))
    monkeypatch.setattr(settings, "SMS_DISPATCH_ENABLED", True)
    monkeypatch.setattr(settings, "PROVISION_VERIFY_ENABLED", True)
    monkeypatch.setattr(settings, "PROVISION_VERIFY_AUTO_FIX", True)
    return calls


async def _setup(db, *, provisioned_ago=timedelta(minutes=1), check_status=None, identity="Router-1001"):
    await make_reseller(db, role=UserRole.ADMIN, email=f"admin{next(_PK)}@example.com")
    owner = await make_reseller(db, support_phone="254700000001",
                                subscription_status=SubscriptionStatus.ACTIVE)
    router = await make_router(db, owner, name="Kamau Net #1", identity=identity,
                               ip_address="10.0.3.9", status_alerts_enabled=True)
    now = datetime.utcnow()
    db.add(ProvisioningToken(
        user_id=owner.id, token=f"tok{next(_PK)}", router_name=router.name, identity=identity,
        vpn_type="wireguard", wireguard_ip="10.0.3.9", server_public_ip="91.98.238.12",
        status=ProvisioningTokenStatus.PROVISIONED, provisioned_at=now - provisioned_ago,
        router_id=router.id, setup_check_status=check_status,
    ))
    await db.commit()
    return owner, router


async def _token(db, router_id):
    tok = (await db.execute(select(ProvisioningToken).where(ProvisioningToken.router_id == router_id))).scalar_one()
    await db.refresh(tok)
    return tok


async def _inbox(db, user_id):
    return (await db.execute(select(ResellerInboxMessage)
                             .where(ResellerInboxMessage.recipient_user_id == user_id))).scalars().all()


async def _sms(db, user_id):
    return (await db.execute(select(SmsMessage).where(SmsMessage.user_id == user_id))).scalars().all()


def _scripted(*apis):
    seq = list(apis)
    seen = []

    def check(info, **kw):
        api = seq.pop(0) if len(seq) > 1 else seq[0]
        seen.append(kw)
        return pv.check_router(info, api_factory=api, sleep=lambda s: None, **kw)
    check.seen = seen
    return check


async def _nosleep(_s):
    return None


async def test_good_router_reseller_told_set_up_correctly(db, sms_calls):
    owner, router = await _setup(db)
    res = await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=_scripted(FakeAPI()))
    assert res["status"] == pv.STATUS_PASSED
    tok = await _token(db, router.id)
    assert tok.setup_check_status == pv.STATUS_PASSED and tok.setup_check_at is not None
    assert tok.setup_check_result["checks"][pv.CHECK_HOTSPOT]["ok"] is True
    assert tok.setup_check_result["notified"] is True
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1 and "set up correctly" in inbox[0].body and "Kamau Net #1" in inbox[0].body
    sms = await _sms(db, owner.id)
    assert len(sms) == 1 and sms[0].credits_charged == 0 and sms[0].category == pv.SMS_CATEGORY
    assert sms[0].kind == SmsMessageKind.ADMIN_TO_RESELLER and sms_calls == [sms[0].id]


async def test_stuck_import_router_673_is_fixed_then_reported_ok(db, sms_calls):
    owner, router = await _setup(db)
    res = await pv.verify_after_provisioning(
        router.id, sleep=_nosleep, check=_scripted(FakeAPI(stuck=True, cpu=100)))
    assert res["status"] == pv.STATUS_PASSED
    assert res["attempts"][0]["fixes"][0]["action"] == "remove_job"
    assert "set up correctly" in (await _inbox(db, owner.id))[0].body


async def test_hard_faults_reported_after_two_attempts_in_plain_language(db, sms_calls):
    owner, router = await _setup(db)
    check = _scripted(FakeAPI(wan=False, hotspot=False))
    res = await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=check)
    assert res["status"] == pv.STATUS_FAILED and len(res["attempts"]) == 2
    tok = await _token(db, router.id)
    assert tok.setup_check_status == pv.STATUS_FAILED
    inbox = await _inbox(db, owner.id)
    assert len(inbox) == 1
    assert "no internet on port 1" in inbox[0].body and "hotspot is not running" in inbox[0].body
    assert "port 1 (ether1)" in inbox[0].body
    sms = (await _sms(db, owner.id))[0]
    assert "needs attention" in sms.body and "inbox" in sms.body


async def test_router_that_never_answers_is_reported_after_the_last_attempt(db, sms_calls):
    owner, router = await _setup(db)
    res = await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=_scripted(FakeAPI(up=False)))
    assert res["status"] == pv.STATUS_UNREACHABLE
    assert len(res["attempts"]) == 1 + len(pv.RETRY_DELAYS_SECONDS)
    assert "not connected to Bitwave" in (await _inbox(db, owner.id))[0].body


async def test_reboot_happens_at_most_once_per_verification(db, sms_calls):
    owner, router = await _setup(db)
    check = _scripted(FakeAPI(stuck=True, cpu=100, job_removal_works=False))
    res = await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=check)
    assert [k["allow_reboot"] for k in check.seen] == [True] + [False] * len(pv.RETRY_DELAYS_SECONDS)
    assert res["status"] == pv.STATUS_FAILED
    assert "stuck in the WinBox terminal" in (await _inbox(db, owner.id))[0].body


async def test_reseller_is_told_only_once(db, sms_calls):
    owner, router = await _setup(db)
    await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=_scripted(FakeAPI()))
    assert await pv.finish(router.id, pv.STATUS_FAILED, {"checks": {}, "reachable": False}) is False
    assert len(await _inbox(db, owner.id)) == 1
    assert (await _token(db, router.id)).setup_check_status == pv.STATUS_PASSED


async def test_disabled_does_nothing(db, sms_calls, monkeypatch):
    monkeypatch.setattr(settings, "PROVISION_VERIFY_ENABLED", False)
    owner, router = await _setup(db)
    res = await pv.verify_after_provisioning(router.id, sleep=_nosleep, check=_scripted(FakeAPI()))
    assert res["status"] == "disabled" and await _inbox(db, owner.id) == []


async def test_catch_up_requeues_unfinished_recent_checks(db, sms_calls):
    _, pending = await _setup(db, check_status=pv.STATUS_PENDING, identity="Router-2001")
    _, done = await _setup(db, check_status=pv.STATUS_PASSED, identity="Router-2002")
    _, old = await _setup(db, provisioned_ago=timedelta(hours=5), identity="Router-2003")
    queued = []
    ids = await pv.catch_up_after_restart(sleep=_nosleep, schedule=lambda rid, first_delay: queued.append(rid))
    assert pending.id in ids and done.id not in ids and old.id not in ids
    assert queued == ids


def test_complete_callback_schedules_the_check():
    src = (REPO / "app" / "api" / "provisioning.py").read_text(encoding="utf-8")
    assert "schedule_verify_after_provisioning(router_obj.id)" in src
    main = (REPO / "main.py").read_text(encoding="utf-8")
    assert "schedule_setup_check_catch_up()" in main


def test_messages_fit_sms_limits():
    from app.services.messaging import count_segments
    _, _, ok_sms = pv.render_message("Kamau Net hotspot #12", pv.STATUS_PASSED, {})
    assert count_segments(ok_sms) <= 2
    every = {"checks": {k: {"ok": False} for k in pv.RESELLER_CHECKS}, "reachable": True}
    _, body, sms = pv.render_message("Kamau Net hotspot #12", pv.STATUS_FAILED, every)
    assert count_segments(sms) <= 2 and len(body) <= 2000


# ---------------------------------------------------------------------------
# 5. CPU alerts held back during setup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ago,status,held", [
    (timedelta(minutes=5), None, True),
    (timedelta(minutes=5), pv.STATUS_PENDING, True),
    (timedelta(minutes=5), pv.STATUS_FAILED, True),
    (timedelta(minutes=5), pv.STATUS_PASSED, False),          # check passed -> alerts back on
    (timedelta(minutes=31), pv.STATUS_PENDING, False),        # window over
])
async def test_cpu_alert_held_back_during_setup(db, sms_calls, monkeypatch, ago, status, held):
    owner, router = await _setup(db, provisioned_ago=ago, check_status=status)
    now = datetime.utcnow()
    oa._attempted[(router.id, oa.LEVEL_WARNING)] = "today"
    subject, body = oa.render_cpu_alert(router.name, oa.LEVEL_WARNING, 97)
    sent = await oa.send_overload_alert(router.id, oa.LEVEL_WARNING, subject, body, now=now, setup_grace=True)
    assert sent is (not held)
    assert (len(await _inbox(db, owner.id)) == 0) is held
    if held:
        # Nothing claimed for today, so the alert can still go after the window.
        await db.refresh(router)
        assert router.overload_warning_notified_at is None
        assert (router.id, oa.LEVEL_WARNING) not in oa._attempted
    oa._attempted.clear()


async def test_payment_overload_alert_ignores_the_setup_window(db, sms_calls):
    owner, router = await _setup(db, provisioned_ago=timedelta(minutes=5))
    subject, body = oa.render_payment_overload(router.name, 3)
    assert await oa.send_overload_alert(router.id, oa.LEVEL_CRITICAL, subject, body) is True


async def test_router_without_a_token_has_no_grace(db, sms_calls):
    await make_reseller(db, role=UserRole.ADMIN, email=f"admin{next(_PK)}@example.com")
    owner = await make_reseller(db, support_phone="254700000002")
    router = await make_router(db, owner, status_alerts_enabled=True)
    subject, body = oa.render_cpu_alert(router.name, oa.LEVEL_WARNING, 97)
    assert await oa.send_overload_alert(router.id, oa.LEVEL_WARNING, subject, body, setup_grace=True) is True

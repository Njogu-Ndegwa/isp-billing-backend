"""The SSTP watchdog re-checks the tunnel right before it restarts it.

Router 715, 2026-11-13: the watchdog logged "dead for 3 checks" at 08:46:50,
waited out its splay delay, and disabled the client at 08:47:25 although the
tunnel had reconnected at 08:46:48. The generated script must check again
after the delay and leave a tunnel that came back alone.
"""
import re

import pytest

from app.services import mgmt_watchdog_script as wd

def _health_check(indent: str, var: str) -> str:
    return (":if ([/interface sstp-client get $id running] = true) do={\n"
            f"{indent}:if ([/ping $srv count=3 interval=1s] > 0) do={{ :set {var} true }}")


def _block(src: str, start: int) -> tuple[str, int]:
    """Body of the ``{...}`` whose ``{`` is the first one at/after ``start``,
    and the index just past its closing ``}``."""
    open_at = src.index("{", start)
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at + 1:i], i + 1
    raise AssertionError("unbalanced braces")


def _sstp(mgmt_ip="10.0.7.15"):
    return wd.render_watchdog_source(wd.KIND_SSTP, mgmt_ip)


def test_braces_balance_in_both_variants():
    for kind in (wd.KIND_SSTP, wd.KIND_WG):
        src = wd.render_watchdog_source(kind, "10.0.7.15")
        assert src.count("{") == src.count("}")
        depth = 0
        for ch in src:
            depth += {"{": 1, "}": -1}.get(ch, 0)
            assert depth >= 0


def test_restart_only_happens_after_a_fresh_check_that_follows_the_splay_delay():
    src = _sstp()
    delay = src.index(":delay 15s")                     # 15 % 40
    assert src.count(":delay 15s") == 1
    recheck = src.index(":local back false", delay)
    disable = src.index("/interface sstp-client disable $id")
    assert delay < recheck < disable
    # the restart is the only disable, and it lives in the else branch of the re-check
    assert src.count("/interface sstp-client disable") == 1
    branch = src.index(":if ($back) do={", recheck)
    skipped, after = _block(src, branch)
    assert re.match(r"\s*else=\{", src[after:])
    restart, _ = _block(src, after)
    assert "/interface sstp-client disable $id" in restart
    assert "/interface sstp-client enable $id" in restart
    assert "list=bw-wd-hold" in restart
    assert "sstp-client disable" not in skipped


def test_recheck_uses_the_same_health_test_as_the_counted_check():
    src = _sstp()
    counted = _health_check("    ", "ok")
    again = _health_check("        ", "back")
    assert counted in src
    assert again in src
    assert src.index(counted) < src.index(":delay 15s") < src.index(again)


def test_tunnel_that_came_back_clears_the_counter_and_gets_no_hold():
    src = _sstp()
    skipped, _ = _block(src, src.index(":if ($back) do={"))
    assert '/ip firewall address-list remove [find where list="bw-wd-fail"]' in skipped
    assert '/ip firewall address-list remove [find where list="bw-wd-backoff"]' in skipped
    assert "restart skipped" in skipped
    assert "bw-wd-hold" not in skipped and "bw-wd-busy" not in skipped


def test_recheck_honours_the_test_hook_server_address():
    # bw-wd-test overrides $srv before any check, so the re-check pings the same
    # (deliberately dead) address and a test restart still goes through.
    src = _sstp()
    assert src.index(':set srv [/ip firewall address-list get') < src.index(":local back false")


def test_sstp_script_uses_no_v7_only_syntax():
    # Runs on RouterOS 6 and 7: slash-path menus with spaces only, no :return,
    # no v7-only commands.
    src = _sstp()
    assert "/interface/" not in src and "/ip/" not in src
    assert ":return" not in src and ":onerror" not in src and ":retry" not in src


# --- WireGuard variant ---------------------------------------------------------

def _wg(mgmt_ip="10.0.7.15"):
    return wd.render_watchdog_source(wd.KIND_WG, mgmt_ip)


def test_wg_reset_only_happens_after_a_fresh_handshake_read_that_follows_the_splay_delay():
    src = _wg()
    delay = src.index(":delay 15s")                     # 15 % 20
    assert src.count(":delay 15s") == 1
    reread = src.index(":set hs2 [/interface wireguard peers get $p last-handshake]")
    assert delay < reread
    assert src.count("/interface wireguard peers disable $p") == 1
    branch = src.index(":if ($back) do={", reread)
    skipped, after = _block(src, branch)
    assert re.match(r"\s*else=\{", src[after:])
    reset, _ = _block(src, after)
    for step in ("/ip firewall connection remove $cx", "/interface wireguard peers disable $p",
                 "/interface wireguard peers enable $p"):
        assert step in reset and step not in skipped
    assert src.index("/ip firewall connection find") > branch     # conntrack cleanup moved inside


def test_wg_reread_uses_the_same_staleness_test():
    src = _wg()
    assert ':if ([:typeof $hs] = "time") do={ :if ($hs < $staleAfter) do={ :set stale false } }' in src
    assert ':if ([:typeof $hs2] = "time") do={ :if ($hs2 < $staleAfter) do={ :set back true } }' in src
    # the test hook (staleAfter 0s) is set before either check, so a test reset still happens
    assert src.index(":set staleAfter 0s") < src.index(":set hs2")


def test_wg_peer_that_handshook_meanwhile_drops_the_hold_it_just_got():
    src = _wg()
    skipped, _ = _block(src, src.index(":if ($back) do={"))
    assert "/ip firewall address-list remove [find where list=$hl]" in skipped
    assert "/ip firewall address-list remove [find where list=$bl]" in skipped
    assert "reset skipped" in skipped
    assert "bw-wd-busy" not in skipped
    # the hold is still written BEFORE the delay (v4 guarantee kept)
    assert src.index("add list=$hl") < src.index(":delay 15s")


# --- text-only refresh for the rollout ----------------------------------------------

def _fake(**kw):
    from tests.test_standard_runtime_enrol import FakeRouterOS
    return FakeRouterOS("R", **kw)


@pytest.mark.parametrize("kind", [wd.KIND_SSTP, wd.KIND_WG])
def test_refresh_rewrites_only_the_source_of_the_installed_script(kind):
    fake = _fake()
    assert wd.install_watchdog(fake, kind, "10.0.7.15").status == "installed"
    name = wd.script_name(kind)
    script = fake.named("/system/script", name)
    script["source"] = "# bw-mgmt-watchdog old"
    sched_before = dict(fake.named("/system/scheduler", name))

    fake.commands.clear()
    assert wd.refresh_installed_source(fake, "10.0.7.15", apply=False) == {name: "would update"}
    assert fake.writes() == []

    assert wd.refresh_installed_source(fake, "10.0.7.15", apply=True) == {name: "updated"}
    assert [c for c in fake.writes()] == ["/system/script/set"]
    # an old source has no rotation, and the refresh never switches it on
    assert script["source"] == wd.render_watchdog_source(kind, "10.0.7.15", rotate=False)
    assert script["policy"] == wd.POLICY and script["comment"] == wd.COMMENT
    assert fake.named("/system/scheduler", name) == sched_before

    fake.commands.clear()
    assert wd.refresh_installed_source(fake, "10.0.7.15", apply=True) == {name: "unchanged"}
    assert fake.writes() == []


def test_refresh_keeps_the_rotation_as_installed():
    """Only the enrol job's firewall check arms the WG port rotation; the rollout
    refresh keeps an armed install armed and a disarmed one disarmed."""
    for armed in (True, False):
        fake = _fake()
        wd.install_watchdog(fake, wd.KIND_WG, "10.0.7.15", rotate=armed)
        script = fake.named("/system/script", wd.SCRIPT_NAME_WG)
        installed = script["source"]
        assert wd.refresh_installed_source(fake, "10.0.7.15", apply=True) == {wd.SCRIPT_NAME_WG: "unchanged"}
        assert script["source"] == installed
        assert (":set rotate true" in installed) is armed


def test_refresh_never_installs_and_leaves_a_paused_scheduler_paused():
    fake = _fake()
    assert wd.refresh_installed_source(fake, "10.0.7.15", apply=True) == {}
    assert fake.writes() == []

    wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.7.15")
    fake.named("/system/script", wd.SCRIPT_NAME_SSTP)["source"] = "# old"
    fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)["disabled"] = "true"
    fake.commands.clear()
    res = wd.refresh_installed_source(fake, "10.0.7.15", apply=True)
    assert res == {wd.SCRIPT_NAME_SSTP: "updated (scheduler paused)"}
    assert fake.writes() == ["/system/script/set"]
    assert fake.named("/system/scheduler", wd.SCRIPT_NAME_SSTP)["disabled"] == "true"


def test_refresh_reports_a_refused_write():
    fake = _fake()
    wd.install_watchdog(fake, wd.KIND_SSTP, "10.0.7.15")
    fake.named("/system/script", wd.SCRIPT_NAME_SSTP)["source"] = "# old"
    real = fake.send_command

    def refuse(cmd, args=None):
        if cmd == "/system/script/set":
            return {"error": "failure: not enough permissions"}
        return real(cmd, args)

    fake.send_command = refuse
    res = wd.refresh_installed_source(fake, "10.0.7.15", apply=True)
    assert res[wd.SCRIPT_NAME_SSTP].startswith("failed: failure: not enough permissions")

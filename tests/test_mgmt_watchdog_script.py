"""The SSTP watchdog re-checks the tunnel right before it restarts it.

Router 715, 2026-11-13: the watchdog logged "dead for 3 checks" at 08:46:50,
waited out its splay delay, and disabled the client at 08:47:25 although the
tunnel had reconnected at 08:46:48. The generated script must check again
after the delay and leave a tunnel that came back alone.
"""
import re

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

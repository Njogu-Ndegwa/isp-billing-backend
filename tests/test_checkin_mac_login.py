"""Check-in delivery on MAC-login routers (applier v2, U lines)."""

from datetime import datetime

import pytest

from app.config import settings
from app.services import checkin_delivery as svc
from app.services.checkin_applier_script import render_checkin_applier_source

IDENT = "Bitwave-Wangige"
MAC = "AA:BB:CC:00:00:01"
ROUTER = svc.RouterRef(id=10, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)
OTHER_ROUTER = svc.RouterRef(id=11, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)


@pytest.fixture(autouse=True)
def mac_login_router_10(monkeypatch):
    svc.reset_state()
    monkeypatch.setattr(settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", "10")
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", 0)
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 10)
    yield
    svc.reset_state()


def _entry(mac=MAC, rate="10M/10M", epoch=1790000000):
    return svc.DesiredEntry(mac=mac, rate=rate, expiry_epoch=epoch, ref=mac.replace(":", ""))


def _report(macs, version=2, q=None, c=None):
    body = f"v={version}&id={IDENT}&n={len(macs)}&macs={','.join(macs)}"
    if q is not None:
        body += f"&q={','.join(q)}"
    if c is not None:
        body += f"&c={','.join(c)}"
    return svc.parse_checkin_body(body.encode())


def _decide(router, report, desired, t=1000.0):
    return svc.decide(router=router, report=report, desired=desired, undelivered_recent=False,
                      mode="add", now=datetime.utcnow(), now_mono=t)


def _applier_accepts_u(line):
    """Python mirror of the applier's pass-1 check for a U line."""
    ll = len(line)
    if not (45 <= ll <= 80 and line[0:2] == "U," and line[19] == ","
            and line[ll - 22] == "," and line[ll - 11] == ","):
        return None
    vm, vr, ve, vt = line[2:19], line[20:ll - 22], line[ll - 21:ll - 11], line[ll - 10:]
    ok = (all(vm[i] == ":" for i in (2, 5, 8, 11, 14)) and "/" in vr and "," not in vr
          and ve.isdigit() and vt.isdigit())
    return {"mac": vm, "rate": vr, "exp": ve, "t": vt} if ok else None


def test_report_version_is_parsed_and_defaults_to_1():
    assert _report([MAC], version=2).version == 2
    assert _report([MAC], version=1).version == 1
    assert svc.parse_checkin_body(f"id={IDENT}&n=0&macs=".encode()).version == 1


@pytest.mark.parametrize("rate", ["10M/10M", "5M/2M", "10000000/10000000", "512K/1.5M"])
def test_user_line_matches_the_applier_offsets(rate):
    line = svc.format_user_line(_entry(rate=rate), 1790626309)
    parsed = _applier_accepts_u(line)
    assert parsed == {"mac": MAC, "rate": rate, "exp": "1790000000", "t": "1790626309"}


def test_unsafe_user_line_fields_are_dropped():
    assert svc.format_user_line(_entry(rate="10M/10M;/system reset"), 1790626309) is None
    assert svc.format_user_line(_entry(mac="AA:BB:CC:00:00:0"), 1790626309) is None


def test_v2_applier_on_mac_login_router_gets_u_lines_and_no_q_lines():
    desired = [_entry()]
    decision = _decide(ROUTER, _report([], q=[]), desired)
    assert [e.mac for e in decision.lines] == [MAC]
    assert decision.add_kind == "U"
    assert decision.queue_lines == []
    frame = svc.render_frame(1, decision.lines, decision.next_s, decision.queue_lines,
                             add_kind=decision.add_kind)
    header, *lines = frame.strip().split("\n")
    assert header.split(",")[2] == "1" and lines[-1] == "END"
    assert _applier_accepts_u(lines[0])["mac"] == MAC


def test_v2_applier_reporting_the_user_gets_nothing():
    decision = _decide(ROUTER, _report([MAC]), [_entry()])
    assert decision.lines == [] and decision.would_send == []


def test_v1_applier_on_mac_login_router_is_never_sent_bypass_lines():
    desired = [_entry()]
    for t in (1000.0, 2000.0, 9000.0):
        decision = _decide(ROUTER, _report([], version=1, q=[]), desired, t)
        assert decision.lines == [] and decision.queue_lines == []
    assert svc.stats_snapshot()["routers"][ROUTER.id]["push_only_suppressed_total"] >= 1


def test_bypass_routers_keep_a_lines_with_a_v2_applier():
    decision = _decide(OTHER_ROUTER, _report([]), [_entry()])
    assert [e.mac for e in decision.lines] == [MAC]
    assert decision.add_kind == "A"
    frame = svc.render_frame(1, decision.lines, decision.next_s, add_kind=decision.add_kind)
    assert f"\nA,{MAC},10M/10M,1790000000,AABBCC000001\n" in frame


def test_checkin_created_user_counts_as_a_checkin_delivery():
    report = _report([MAC], c=[MAC])
    assert MAC in report.checkin_added


# ------------------------------------------------------------ applier source

def _src():
    return render_checkin_applier_source(identity=IDENT, endpoint_url="https://x.example/api/router/checkin")


def test_applier_v2_reports_mac_login_users_with_an_anchored_match():
    src = _src()
    assert '("v=2&id="' in src
    # "|" is regex alternation in RouterOS: an unanchored "MACLOGIN|" would
    # match every user on the router.
    assert 'find where comment~"^MACLOGIN"' in src
    assert 'comment~"MACLOGIN|"' not in src


def test_applier_u_line_adds_a_user_only_when_missing_and_kicks_after():
    src = _src()
    u_block = src[src.index(':if ($kind = "U") do={'):src.index(':if ($kind = "Q") do={')]
    guard = u_block.index('[:len [/ip hotspot user find where name=$mac]] = 0')
    add = u_block.index("/ip hotspot user add name=$mac")
    assert guard < add
    assert 'password="" mac-address=$mac profile=$pn' in u_block
    assert '"MACLOGIN|MAC:" . $mac . "|T:" . $uts . "|EXP:" . $uexp . "|CHECKIN"' in u_block
    # Only a tagged bypass binding is dropped, and only after the user exists.
    assert u_block.index(":if ($uadded)") < u_block.index("/ip hotspot ip-binding remove")
    assert 'type=bypassed comment~"USER:"' in u_block
    assert u_block.index(":if ($uadded)") < u_block.index("/ip hotspot host remove")


def test_applier_validates_u_lines_before_applying_anything():
    src = _src()
    validate = src.index('([:pick $ln 0 2] = "U,")')
    frame_ok = src.index(":set frameOk true")
    first_user_write = src.index("/ip hotspot user add")
    assert validate < frame_ok < first_user_write

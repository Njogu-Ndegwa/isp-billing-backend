"""Router expiry reaper: the router removes its own expired hotspot customers,
asking the platform first and reporting after (app/services/router_expiry.py)."""
import calendar
import re
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.models import ConnectionType, CustomerStatus, ProvisioningLog
from app.services import mikrotik_background
from app.services.expiry_reaper_script import SCRIPT_NAME, render_expiry_reaper_script, script_source
from app.services.router_expiry import (
    CustomerRow,
    binding_comment,
    clock_ok,
    decide,
    expiry_minute,
    expiry_second,
    parse_request,
    render_reply,
    with_exp_tag,
)
from app.services.router_script_gate import render_gate, strip_gate
from app.services.usage_push_auth import derive_router_token
from tests.factories import make_customer, make_plan, make_reseller, make_router

MAC_A = "AA:BB:CC:00:00:01"
MAC_B = "AA:BB:CC:00:00:02"
MAC_C = "AA:BB:CC:00:00:03"
IDENT = "Router-0478"
TURL = "http://10.251.0.1:8088/api/router/expiry-check"
PURL = "https://isp.example.net/api/router/expiry-check"


# --- deadline format --------------------------------------------------------

def test_expiry_minute_rounds_up_so_the_router_never_asks_early():
    assert expiry_minute(datetime(2026, 9, 25, 18, 0, 0)) == calendar.timegm((2026, 9, 25, 18, 0, 0)) // 60
    assert expiry_minute(datetime(2026, 9, 25, 18, 0, 1)) == calendar.timegm((2026, 9, 25, 18, 1, 0)) // 60


def test_binding_comment_keeps_legacy_fields_and_adds_the_deadline():
    c = binding_comment("AABBCC000001", datetime(2026, 9, 25, 18, 0), now=datetime(2026, 9, 25, 12, 0))
    assert c.startswith("USER:AABBCC000001|EXPIRES:DB_MANAGED|EXP:")
    assert f"EXP:{expiry_second(datetime(2026, 9, 25, 18, 0))}|" in c
    assert "EXP:" not in binding_comment("X", None)


def test_with_exp_tag_adds_replaces_and_revives_a_forgotten_tag():
    assert with_exp_tag("USER:X|EXPIRES:DB_MANAGED|2026", 100) == "USER:X|EXPIRES:DB_MANAGED|2026|EXP:100"
    assert with_exp_tag("USER:X|EXP:50|2026", 100) == "USER:X|2026|EXP:100"
    assert with_exp_tag("USER:X|EXX:50", 100) == "USER:X|EXP:100"
    assert with_exp_tag("", 7) == "EXP:7"


# --- request / decision / reply ---------------------------------------------

def test_parse_request_keeps_only_valid_macs_and_minutes():
    req = parse_request(f"ident={IDENT}&now=123&due={MAC_A},junk,{MAC_A.lower()},&done={MAC_B}@120,{MAC_C}@x,bad@1,")
    assert req.identity == IDENT and req.router_now == 123
    assert req.due == [MAC_A]
    assert req.done == [(MAC_B, 120), (MAC_C, None)]
    with pytest.raises(ValueError):
        parse_request('ident=bad"id&now=1')


def test_decide_per_mac_with_phantom_rows():
    now = datetime(2026, 9, 25, 12, 0)
    rows = [
        CustomerRow(1, MAC_A, True, now - timedelta(minutes=2)),      # expired
        CustomerRow(2, MAC_B, True, now - timedelta(days=1)),         # old row ...
        CustomerRow(3, MAC_B, True, now + timedelta(hours=5)),        # ... renewed row
        CustomerRow(4, MAC_C, False, now - timedelta(days=3)),        # phantom inactive row
    ]
    remove, keep, forget = decide([MAC_A, MAC_B, MAC_C, "AA:BB:CC:00:00:09"], rows, now)
    assert remove == [MAC_A, MAC_C]
    assert keep == [(MAC_B, expiry_second(now + timedelta(hours=5)))]
    assert forget == ["AA:BB:CC:00:00:09"]


def test_reply_always_has_every_segment():
    assert render_reply(False, [], [], []) == "BW1;C=0;R=;K=;X=;"
    assert render_reply(True, [MAC_A], [(MAC_B, 9)], [MAC_C]) == f"BW1;C=1;R={MAC_A},;K={MAC_B}@9,;X={MAC_C},;"


def test_clock_is_trusted_only_within_five_minutes():
    now = datetime(2026, 9, 25, 12, 0)
    s = expiry_second(now)
    assert clock_ok(s + 300, now) and clock_ok(s - 300, now)
    assert not clock_ok(s + 301, now) and not clock_ok(None, now)
    assert clock_ok(expiry_minute(now), now)          # first installs send minutes


def test_expiry_second_rounds_up():
    assert expiry_second(datetime(2026, 9, 25, 18, 0, 0)) == calendar.timegm((2026, 9, 25, 18, 0, 0))
    assert expiry_second(datetime(2026, 9, 25, 18, 0, 0, 1)) == calendar.timegm((2026, 9, 25, 18, 0, 1))


def test_script_compares_in_seconds_and_still_reads_minute_tags():
    s = _script()
    assert ":local nows (($nowm * 60) + $se)" in s
    assert ":if ($x <= $nows) do={" in s
    assert ':if (([:typeof $x] = "num") && ($x < 1000000000)) do={ :set x ($x * 60) }' in s
    assert "$nowm >=" not in s and "$x <= $nowm" not in s


# --- the RouterOS script ----------------------------------------------------

def _script():
    return render_expiry_reaper_script(identity=IDENT, tunnel_url=TURL, public_url=PURL)


def test_script_has_no_bare_return_and_no_placeholders_left():
    s = _script()
    assert not re.search(r":return\b", s)       # rejected wholesale on RouterOS 7.19+
    assert ":toarray" not in s                  # would type-guess MACs
    assert "__" not in s
    assert derive_router_token(IDENT) in s
    assert s.index(TURL) < s.index(PURL)        # tunnel first, HTTPS fallback


def test_script_rejects_unsafe_inputs():
    with pytest.raises(ValueError):
        render_expiry_reaper_script(identity='x";/system reset;"', tunnel_url=TURL, public_url=PURL)
    with pytest.raises(ValueError):
        render_expiry_reaper_script(identity=IDENT, tunnel_url="http://x/\"", public_url=PURL)


def test_script_source_is_the_body_only():
    src = script_source(_script())
    assert src.startswith(render_gate(SCRIPT_NAME))
    assert strip_gate(src).lstrip().startswith(":global bwExpNext")
    assert "/system scheduler add" not in src
    assert src.count("{") == src.count("}")


def _unix_minute_like_the_script(date_str, time_str, gmt_offset):
    """Python mirror of the script's clock maths, line for line (integer only)."""
    if date_str[4] == "-":
        y, mo, dd = int(date_str[0:4]), int(date_str[5:7]), int(date_str[8:10])
    else:
        mo = "janfebmaraprmayjunjulaugsepoctnovdec".find(date_str[0:3]) // 3 + 1
        dd, y = int(date_str[4:6]), int(date_str[7:11])
    h, mi = int(time_str[0:2]), int(time_str[3:5])
    sign = -1 if gmt_offset.startswith("-") else 1
    g = gmt_offset.lstrip("+-")
    if ":" in g:
        gh, gm = g.split(":")[0], g.split(":")[1][:2]
        off = (int(gh) * 60 + int(gm)) * sign
    else:
        off = (int(g) // 60) * sign
    yy = y - 1 if mo <= 2 else y
    era = yy // 400
    yoe = yy - era * 400
    mp = mo - 3 if mo > 2 else mo + 9
    doy = (153 * mp + 2) // 5 + (dd - 1)
    doe = yoe * 365 + yoe // 4 - (yoe // 100 - doy)
    days = era * 146097 + doe - 719468
    return days * 1440 + h * 60 + mi - off


@pytest.mark.parametrize("utc", [
    datetime(2026, 9, 25, 18, 14), datetime(2026, 12, 31, 23, 59), datetime(2027, 1, 1, 0, 0),
    datetime(2028, 2, 29, 21, 30), datetime(2028, 3, 1, 0, 5), datetime(2026, 2, 28, 22, 0),
    datetime(2030, 7, 4, 3, 7), datetime(2025, 1, 1, 0, 0),
])
@pytest.mark.parametrize("offset_min,offset_text", [(180, "+03:00"), (180, "10800"), (0, "+00:00"), (-300, "-05:00")])
def test_clock_maths_matches_utc_for_both_date_formats(utc, offset_min, offset_text):
    local = utc + timedelta(minutes=offset_min)
    expected = calendar.timegm(utc.timetuple()) // 60
    v7 = local.strftime("%Y-%m-%d")
    v6 = local.strftime("%b/%d/%Y").lower()
    t = local.strftime("%H:%M:%S")
    assert _unix_minute_like_the_script(v7, t, offset_text) == expected
    assert _unix_minute_like_the_script(v6, t, offset_text) == expected


def test_script_uses_the_same_clock_maths_as_the_mirror():
    s = _script()
    for line in (
        ":local doy ((((153 * $mp) + 2) / 5) + ($dd - 1))",
        ":local doe ((($yoe * 365) + ($yoe / 4)) - (($yoe / 100) - $doy))",
        ":local days ((($era * 146097) + $doe) - 719468)",
        ":set nowm (((($days * 1440) + ($h * 60)) + $mi) - $offm)",
        ':local names "janfebmaraprmayjunjulaugsepoctnovdec"',
    ):
        assert line in s


# --- endpoint ---------------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    import app.api.router_expiry_routes as routes

    monkeypatch.setattr(routes, "async_session", session_factory)
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    spawned = []
    monkeypatch.setattr(routes, "_spawn", lambda coro: (spawned.append(coro), coro.close()))
    # Calls without v= look like old scripts: don't reach for a router here.
    from app.services import expiry_reaper_upgrade
    monkeypatch.setattr(expiry_reaper_upgrade.settings, "EXPIRY_REAPER_AUTO_UPGRADE", False)
    routes.reset_rate_limiter()
    application = FastAPI()
    application.include_router(routes.router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        c.spawned = spawned
        yield c


async def _post(client, body, token=None):
    return await client.post(
        "/api/router/expiry-check", content=body,
        headers={"Authorization": f"Bearer {token or derive_router_token(IDENT)}", "Content-Type": "text/plain"},
    )


async def _router_with(db, customers):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=IDENT)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    made = []
    for mac, status, expiry in customers:
        made.append(await make_customer(db, reseller, plan, router, mac_address=mac, status=status, expiry=expiry))
    return router, made


def _now_minute():
    return expiry_minute(datetime.utcnow())


@pytest.mark.asyncio
async def test_endpoint_rejects_a_wrong_token(client, db):
    await _router_with(db, [])
    r = await _post(client, f"ident={IDENT}&now=1&due=&done=", token="nope")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_endpoint_decides_remove_keep_and_forget(client, db):
    now = datetime.utcnow()
    await _router_with(db, [
        (MAC_A, CustomerStatus.ACTIVE, now - timedelta(minutes=1)),
        (MAC_B, CustomerStatus.ACTIVE, now + timedelta(hours=2)),
    ])
    r = await _post(client, f"ident={IDENT}&now={_now_minute()}&due={MAC_A},{MAC_B},{MAC_C},&done=")
    assert r.status_code == 200
    body = r.text
    assert body.startswith("BW1;C=1;")
    assert f";R={MAC_A},;" in body
    assert f";K={MAC_B}@{expiry_second(now + timedelta(hours=2))},;" in body
    assert f";X={MAC_C},;" in body


@pytest.mark.asyncio
async def test_a_wrong_router_clock_is_flagged_but_decisions_still_come_from_the_db(client, db):
    now = datetime.utcnow()
    await _router_with(db, [(MAC_A, CustomerStatus.ACTIVE, now - timedelta(minutes=1))])
    r = await _post(client, f"ident={IDENT}&now={_now_minute() + 600}&due={MAC_A},&done=")
    assert r.text.startswith("BW1;C=0;") and f";R={MAC_A},;" in r.text


@pytest.mark.asyncio
async def test_confirmed_removal_marks_inactive_and_logs_the_router_time(client, db, session_factory):
    now = datetime.utcnow()
    router, (cust,) = await _router_with(db, [(MAC_A, CustomerStatus.ACTIVE, now - timedelta(minutes=3))])
    removed_minute = _now_minute() - 2
    r = await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done={MAC_A}@{removed_minute},")
    assert r.status_code == 200 and r.text.startswith("BW1;C=1;")

    async with session_factory() as s:
        c = await s.get(type(cust), cust.id)
        assert c.status == CustomerStatus.INACTIVE
        logs = (await s.execute(select(ProvisioningLog).where(ProvisioningLog.customer_id == cust.id))).scalars().all()
    assert [(l.action, l.status) for l in logs] == [("hotspot_deactivation", "success")]
    assert "reaper" in logs[0].details
    assert abs((logs[0].log_date - datetime.utcfromtimestamp(removed_minute * 60)).total_seconds()) < 1
    assert len(client.spawned) == 1   # expiry SMS queued after commit


@pytest.mark.asyncio
async def test_removal_of_a_customer_who_renewed_is_repaired_not_recorded(client, db, session_factory):
    now = datetime.utcnow()
    router, (cust,) = await _router_with(db, [(MAC_A, CustomerStatus.ACTIVE, now + timedelta(hours=3))])
    r = await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done={MAC_A}@{_now_minute()},")
    assert r.status_code == 200
    async with session_factory() as s:
        assert (await s.get(type(cust), cust.id)).status == CustomerStatus.ACTIVE
        assert (await s.execute(select(ProvisioningLog))).scalars().all() == []
    assert len(client.spawned) == 1   # the re-provision task


@pytest.mark.asyncio
async def test_calls_faster_than_the_floor_are_refused(client, db):
    await _router_with(db, [])
    assert (await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done=")).status_code == 200
    assert (await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done=")).status_code == 429


# --- the server cleanup is the backstop on reaper routers --------------------

async def _async_zero(*_a, **_k):
    return 0


@pytest.mark.asyncio
async def test_server_cleanup_waits_for_the_reaper_then_acts(db, session_factory, monkeypatch):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _async_zero)
    seen = []

    def fake_cleanup(_router, customers):
        seen.extend(c["id"] for c in customers)
        return {"removed": [{"id": c["id"], "details": {}} for c in customers], "failed": [], "connected": True}

    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync", fake_cleanup)

    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    reaper = await make_router(db, reseller, identity="Router-9001", expiry_reaper_enabled=True)
    plain = await make_router(db, reseller, identity="Router-9002")
    fresh = await make_customer(db, reseller, plan, reaper, mac_address=MAC_A,
                                status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=1))
    stale = await make_customer(db, reseller, plan, reaper, mac_address=MAC_B,
                                status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=10))
    other = await make_customer(db, reseller, plan, plain, mac_address=MAC_C,
                                status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=1))

    await mikrotik_background.cleanup_expired_users_background()

    assert sorted(seen) == sorted([stale.id, other.id])
    assert fresh.id not in seen


# --- removal time in seconds ------------------------------------------------

def test_done_time_accepts_seconds_and_the_first_installs_minutes():
    from app.services.router_expiry import done_time_to_datetime

    t = datetime(2026, 9, 26, 7, 15, 42)
    secs = calendar.timegm(t.timetuple())
    assert done_time_to_datetime(secs) == t
    assert done_time_to_datetime(secs // 60) == datetime(2026, 9, 26, 7, 15)


def test_script_reports_removals_in_seconds():
    s = _script()
    assert ':local ss [:pick $t 6 8]' in s
    assert '($bwExpDone . $m . "@" . $nows . ",")' in s


@pytest.mark.asyncio
async def test_removal_logged_at_the_routers_second(client, db, session_factory):
    now = datetime.utcnow()
    router, (cust,) = await _router_with(db, [(MAC_A, CustomerStatus.ACTIVE, now - timedelta(minutes=2))])
    removed = now.replace(microsecond=0) - timedelta(seconds=37)
    secs = calendar.timegm(removed.timetuple())
    r = await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done={MAC_A}@{secs},")
    assert r.status_code == 200
    async with session_factory() as s:
        log = (await s.execute(select(ProvisioningLog).where(ProvisioningLog.customer_id == cust.id))).scalars().one()
    assert log.log_date == removed


def test_unconfirmed_clock_rechecks_within_five_minutes():
    s = _script()
    assert ':if (!$bwExpClockOk) do={ :set bwExpBeat ($nows - 3300) }' in s
    assert "(($nows - $bwExpBeat) >= 3600)" in s


# --- MAC-login routers (script v2, 2026-09-29) ------------------------------

def test_v2_script_reads_asks_about_redates_and_removes_mac_login_users():
    src = _script()
    # counted and scanned like bindings, named after the MAC
    assert '[/ip hotspot user find where comment~"^MACLOGIN"]' in src
    assert '/ip hotspot user find where comment~"^MACLOGIN.*EXP:"' in src
    assert '[/ip hotspot user get $u name]' in src
    # K re-dates the user's deadline, X retires it
    assert '/ip hotspot user set $ku comment=' in src
    assert '"EXX:"' in src and '/ip hotspot user set $xu comment=' in src
    # removal takes the MAC-login user (named with colons) as well as the old one
    assert '/ip hotspot user remove [find where name=$m]' in src
    assert '/ip hotspot user remove [find where name=$u]' in src
    # and it tells the server it can see them
    assert '"ident=" . $ident . "&v=2&now="' in src


def test_parse_request_reads_the_script_version():
    assert parse_request(f"ident={IDENT}&v=2&now=1&due=&done=").version == 2
    assert parse_request(f"ident={IDENT}&now=1&due=&done=").version == 1
    assert parse_request(f"ident={IDENT}&v=x&now=1&due=&done=").version == 1


@pytest.mark.asyncio
async def test_endpoint_remembers_each_routers_script_version(client, db):
    from app.services.router_expiry import reaper_version, reset_reaper_versions

    reset_reaper_versions()
    await _router_with(db, [])
    assert reaper_version(IDENT) == 0
    r = await _post(client, f"ident={IDENT}&v=2&now={_now_minute()}&due=&done=")
    assert r.status_code == 200 and reaper_version(IDENT) == 2


def test_mac_login_deadline_is_the_rounded_up_utc_second():
    from app.services.hotspot_mac_login import build_user_comment

    exp = datetime(2026, 9, 29, 7, 29, 17, 377322)
    comment = build_user_comment("aa:bb:cc:00:00:01", "x", now=1, expiry=exp)
    assert f"|EXP:{expiry_second(exp)}|" in comment
    assert expiry_second(exp) == calendar.timegm(exp.timetuple()) + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mac_login,version,waits", [
    (False, 0, True),    # bindings: every reaper version sees them
    (True, 1, False),    # MAC login + old script: it cannot see them, do not wait
    (True, 0, False),    # MAC login, script version not known yet (restart)
    (True, 2, True),     # MAC login + v2 script: leave them to the router
])
async def test_server_waits_for_the_reaper_only_when_it_can_see_the_customer(
        db, session_factory, monkeypatch, mac_login, version, waits):
    from app.services import hotspot_mac_login
    from app.services.router_expiry import note_reaper_version, reset_reaper_versions

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability", _async_zero)
    monkeypatch.setattr(hotspot_mac_login, "mac_login_enabled", lambda _rid: mac_login)
    seen = []

    def fake_cleanup(_router, customers):
        seen.extend(c["id"] for c in customers)
        return {"removed": [{"id": c["id"], "details": {}} for c in customers], "failed": [], "connected": True}

    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync", fake_cleanup)
    reset_reaper_versions()
    if version:
        note_reaper_version("Router-9101", version)

    now = datetime.utcnow()
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    reaper = await make_router(db, reseller, identity="Router-9101", expiry_reaper_enabled=True)
    fresh = await make_customer(db, reseller, plan, reaper, mac_address=MAC_A,
                                status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=1))

    await mikrotik_background.cleanup_expired_users_background()

    assert (fresh.id not in seen) is waits

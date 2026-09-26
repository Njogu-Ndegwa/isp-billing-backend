"""Router check-in delivery pilot: wire format, desired state, endpoint, applier.

What these pin, and why:

* **Only whitelisted data reaches a router.** A server bug must at worst
  produce a line the router rejects, never text that changes what a RouterOS
  command does. Every field is checked against a strict pattern.
* **Desired state = ACTIVE, unexpired hotspot customers on THIS router**, minus
  what the router already reports. Expired, inactive, other-router and PPPoE
  customers never produce a line.
* **Off means off.** Flags off, kill switch, or a router outside the allowlist
  all get an empty idle frame; shadow mode never sends lines.
* **The applier is fixed code** and never uses the constructs that broke the
  old agent on RouterOS 7.19+.
"""

import random
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.db.models import (
    ConnectionType,
    CustomerStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningState,
)
from app.services import checkin_delivery as svc
from app.services.checkin_applier_script import (
    SCHEDULER_NAME,
    SCRIPT_NAME,
    render_checkin_applier_source,
)
from app.services.usage_push_auth import (
    derive_checkin_token,
    derive_router_token,
    verify_checkin_token,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

IDENT = "Router-0721"
FUTURE = timedelta(days=3)


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def _entry(mac="AA:BB:CC:00:00:01", rate="5M/5M", epoch=1790000000, ref=None):
    return svc.DesiredEntry(mac=mac, rate=rate, expiry_epoch=epoch, ref=ref or mac.replace(":", ""))


def _parse_frame(text):
    """Python mirror of the router applier's parser (fixed offsets)."""
    lines = text.split("\n")
    assert lines[0].startswith("BWE1,")
    _, seq, count, next_s = lines[0].split(",")
    ops = []
    for ln in lines[1:]:
        if ln == "END":
            break
        ll = len(ln)
        assert ln[0:2] == "A," and ln[19] == "," and ln[ll - 24] == "," and ln[ll - 13] == ","
        ops.append({
            "mac": ln[2:19],
            "rate": ln[20:ll - 24],
            "epoch": ln[ll - 23:ll - 13],
            "ref": ln[ll - 12:],
        })
    return int(seq), int(count), int(next_s), ops


def test_frame_round_trips_through_the_applier_offsets():
    entries = [_entry(), _entry("AA:BB:CC:00:00:02", "512K/1.5M"), _entry("AA:BB:CC:00:00:03", "10000000/10000000")]
    text = svc.render_frame(1790000000, entries, 5)
    assert text.endswith("END\n")
    seq, count, next_s, ops = _parse_frame(text)
    assert (count, next_s) == (3, 5)
    assert len(ops) == 3
    assert ops[1] == {"mac": "AA:BB:CC:00:00:02", "rate": "512K/1.5M", "epoch": "1790000000", "ref": "AABBCC000002"}
    assert ops[2]["rate"] == "10000000/10000000"


@pytest.mark.parametrize("bad", [
    _entry(mac='AA:BB:CC:00:00:0"'),
    _entry(mac="aa:bb:cc:00:00:01", ref="AABBCC000001"),
    _entry(rate="5M/5M;/system reboot"),
    _entry(rate='5M"/5M'),
    _entry(rate="$x/5M"),
    _entry(rate="5M"),
    _entry(epoch=12345),
    _entry(ref="AABBCC00000"),
    _entry(ref="AABBCC00000]"),
])
def test_unsafe_fields_are_dropped_never_emitted(bad):
    assert svc.format_add_line(bad) is None
    text = svc.render_frame(1, [bad, _entry()], 5)
    # The header count reflects only what was actually emitted.
    assert text.startswith("BWE1,1,1,5\n")
    assert text.count("\nA,") == 1
    assert not re.search(r'["$;\[\]{}\\]', text)


def test_idle_frame_has_no_lines():
    text = svc.idle_frame()
    assert re.fullmatch(r"BWE1,\d+,0,600\nEND\n", text)


def test_next_s_is_clamped():
    assert svc.render_frame(1, [], 1).startswith("BWE1,1,0,5\n")
    assert svc.render_frame(1, [], 99999).startswith("BWE1,1,0,3600\n")


def test_parse_body():
    rep = svc.parse_checkin_body(b"v=1&id=Router-0721&n=3&macs=aa:bb:cc:00:00:01,AA-BB-CC-00-00-02,garbage\n")
    assert rep.identity == "Router-0721"
    assert rep.macs == {"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"}
    assert rep.invalid == 1 and rep.tokens == 3 and rep.count_matches


def test_parse_body_empty_list_and_mismatch():
    assert svc.parse_checkin_body(b"v=1&id=R1&n=0&macs=").count_matches
    assert not svc.parse_checkin_body(b"v=1&id=R1&n=5&macs=AA:BB:CC:00:00:01").count_matches
    assert not svc.parse_checkin_body(b"v=1&id=R1&macs=AA:BB:CC:00:00:01").count_matches


@pytest.mark.parametrize("raw", [
    b"v=1&n=0&macs=",
    b'v=1&id=Router"x&n=0&macs=',
    b"\xff\xfe",
    b"v=1&id=R1&n=0&macs=" + b"A" * (svc.MAX_BODY_BYTES + 1),
], ids=["no-identity", "quote-in-identity", "not-ascii", "too-large"])
def test_parse_body_rejects(raw):
    with pytest.raises(svc.BadCheckin):
        svc.parse_checkin_body(raw)


def test_compute_diff_excludes_present_and_reports_unknown():
    desired = [_entry("AA:BB:CC:00:00:01"), _entry("AA:BB:CC:00:00:02")]
    missing, unknown = svc.compute_diff(desired, {"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:09"})
    assert [e.mac for e in missing] == ["AA:BB:CC:00:00:02"]
    assert unknown == {"AA:BB:CC:00:00:09"}


def test_compute_diff_dedupes_mac_keeping_latest_expiry():
    missing, _ = svc.compute_diff(
        [_entry(epoch=1790000000), _entry(epoch=1790009999)], set()
    )
    assert len(missing) == 1 and missing[0].expiry_epoch == 1790009999


def test_idle_poll_interval_is_stable_per_router():
    # The applier rewrites its scheduler (a flash write) whenever next_s changes, so the
    # idle cadence must not change between check-ins of the same router.
    for rid in (292, 426, 448):
        first = svc.next_poll_seconds(lines_sent=0, payment_hot=False, router_id=rid)
        assert all(svc.next_poll_seconds(lines_sent=0, payment_hot=False, router_id=rid) == first
                   for _ in range(20))
        assert 54 <= first <= 66
    spread = {svc.next_poll_seconds(lines_sent=0, payment_hot=False, router_id=rid) for rid in range(1, 60)}
    assert len(spread) > 5  # still spreads the fleet across the window
    assert svc.next_poll_seconds(lines_sent=0, payment_hot=True, router_id=448) == 10
    assert svc.next_poll_seconds(lines_sent=1, payment_hot=False, router_id=448) == 5


def test_next_poll_seconds():
    assert svc.next_poll_seconds(lines_sent=2, payment_hot=True) == 5
    assert svc.next_poll_seconds(lines_sent=0, payment_hot=True) == 10
    rng = random.Random(1)
    for _ in range(50):
        assert 54 <= svc.next_poll_seconds(lines_sent=0, payment_hot=False, rng=rng) <= 66


def test_desired_entry_uses_push_rate_and_ref():
    e = svc.desired_entry("aa:bb:cc:00:00:01", "5Mbps", datetime(2026, 10, 1))
    assert e.rate == "5M/5M" and e.ref == "AABBCC000001" and e.mac == "AA:BB:CC:00:00:01"
    assert svc.desired_entry("not-a-mac", "5M/5M", datetime(2026, 10, 1)) is None


# ---------------------------------------------------------------------------
# Token namespace
# ---------------------------------------------------------------------------

def test_checkin_token_is_its_own_namespace():
    assert derive_checkin_token(IDENT) != derive_router_token(IDENT)
    assert verify_checkin_token(IDENT, derive_checkin_token(IDENT))
    assert not verify_checkin_token(IDENT, derive_router_token(IDENT))
    assert not verify_checkin_token("Router-0722", derive_checkin_token(IDENT))


# ---------------------------------------------------------------------------
# Desired state from the DB
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def pilot(db, session_factory, monkeypatch):
    monkeypatch.setattr(svc, "async_session", session_factory)
    svc.reset_state()
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, identity=IDENT)
    other = await make_router(db, reseller, identity="Router-0999")
    hotspot = await make_plan(db, reseller, speed="5M/5M")
    pppoe = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    now = datetime.utcnow()
    paid = await make_customer(db, reseller, hotspot, router, mac_address="AA:BB:CC:00:00:01",
                               status=CustomerStatus.ACTIVE, expiry=now + FUTURE)
    await make_customer(db, reseller, hotspot, router, mac_address="AA:BB:CC:00:00:02",
                        status=CustomerStatus.ACTIVE, expiry=now + FUTURE)
    await make_customer(db, reseller, hotspot, router, mac_address="AA:BB:CC:00:00:03",
                        status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=1))  # expired
    await make_customer(db, reseller, hotspot, router, mac_address="AA:BB:CC:00:00:04",
                        status=CustomerStatus.INACTIVE, expiry=now + FUTURE)  # inactive
    await make_customer(db, reseller, hotspot, router, mac_address="AA:BB:CC:00:00:05",
                        status=CustomerStatus.PENDING, expiry=now + FUTURE)  # mid-payment
    await make_customer(db, reseller, hotspot, other, mac_address="AA:BB:CC:00:00:06",
                        status=CustomerStatus.ACTIVE, expiry=now + FUTURE)  # other router
    await make_customer(db, reseller, pppoe, router, mac_address="AA:BB:CC:00:00:07",
                        status=CustomerStatus.ACTIVE, expiry=now + FUTURE, pppoe_username="p1")
    await make_customer(db, reseller, hotspot, router, mac_address="",
                        status=CustomerStatus.ACTIVE, expiry=now + FUTURE, phone="254700000001")  # no MAC
    return {"router": router, "other": other, "paid": paid, "db": db, "reseller": reseller}


@pytest.mark.asyncio
async def test_desired_state_only_active_unexpired_hotspot_on_this_router(pilot):
    entries, undelivered = await svc.load_desired_state(pilot["router"].id, datetime.utcnow())
    assert sorted(e.mac for e in entries) == ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]
    assert all(e.rate == "5M/5M" for e in entries)
    assert undelivered is False


@pytest.mark.asyncio
async def test_recent_undelivered_attempt_marks_router_hot(pilot):
    db = pilot["db"]
    db.add(ProvisioningAttempt(
        customer_id=pilot["paid"].id, router_id=pilot["router"].id,
        mac_address="AA:BB:CC:00:00:01",
        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=1,
        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
        provisioning_state=ProvisioningState.RETRY_PENDING,
        created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
    ))
    await db.commit()
    _, undelivered = await svc.load_desired_state(pilot["router"].id, datetime.utcnow())
    assert undelivered is True
    _, other = await svc.load_desired_state(pilot["other"].id, datetime.utcnow())
    assert other is False


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(pilot, monkeypatch):
    import app.api.router_checkin_routes as routes
    from app.api.router_checkin_routes import router as checkin_router

    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: False)
    routes.reset_state()
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", True)
    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", False)
    monkeypatch.setattr(settings, "CHECKIN_MODE", "add")
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", str(pilot["router"].id))
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 10)
    application = FastAPI()
    application.include_router(checkin_router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _checkin(client, macs=(), identity=IDENT, token=None, n=None):
    body = f"v=1&id={identity}&n={len(macs) if n is None else n}&macs={','.join(macs)}"
    tok = derive_checkin_token(identity) if token is None else token
    svc._last_checkin.clear()  # tests call faster than the per-router floor
    return await client.post(
        "/api/router/checkin", content=body,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "text/plain"},
    )


@pytest.mark.asyncio
async def test_add_mode_sends_only_missing_paid_macs(client):
    resp = await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:03"])
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    _, count, next_s, ops = _parse_frame(resp.text)
    assert count == 1 and [o["mac"] for o in ops] == ["AA:BB:CC:00:00:02"]
    assert ops[0]["rate"] == "5M/5M" and ops[0]["ref"] == "AABBCC000002"
    assert next_s == 5  # lines sent -> confirm quickly


@pytest.mark.asyncio
async def test_nothing_missing_means_normal_cadence(client):
    resp = await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    _, count, next_s, _ = _parse_frame(resp.text)
    assert count == 0 and 54 <= next_s <= 66


@pytest.mark.asyncio
async def test_shadow_mode_sends_nothing_but_records(client, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MODE", "shadow")
    resp = await _checkin(client, [])
    _, count, _, ops = _parse_frame(resp.text)
    assert count == 0 and ops == []
    snap = svc.stats_snapshot()
    rid = next(iter(snap["routers"]))
    assert snap["mode"] == "shadow"
    assert snap["routers"][rid]["would_send_total"] == 2
    assert snap["routers"][rid]["lines_sent_total"] == 0
    assert snap["routers"][rid]["currently_missing"] == ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]


@pytest.mark.asyncio
async def test_unknown_mode_value_falls_back_to_shadow(client, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MODE", "remove")
    resp = await _checkin(client, [])
    assert _parse_frame(resp.text)[1] == 0


@pytest.mark.asyncio
async def test_lines_are_capped(client, pilot, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 1)
    resp = await _checkin(client, [])
    assert _parse_frame(resp.text)[1] == 1
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 500)
    assert svc.max_lines_per_reply() == svc.HARD_MAX_LINES_PER_REPLY


@pytest.mark.asyncio
async def test_count_mismatch_sends_nothing(client):
    resp = await _checkin(client, ["AA:BB:CC:00:00:01"], n=7)
    assert _parse_frame(resp.text)[1] == 0


@pytest.mark.asyncio
async def test_bad_token_is_401(client):
    resp = await _checkin(client, [], token="0" * 32)
    assert resp.status_code == 401
    assert "BWE1" not in resp.text


@pytest.mark.asyncio
async def test_usage_push_token_is_not_accepted(client):
    resp = await _checkin(client, [], token=derive_router_token(IDENT))
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unknown_identity_is_401(client):
    resp = await _checkin(client, [], identity="Router-4040")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_router_outside_allowlist_gets_idle_frame(client, pilot):
    resp = await _checkin(client, [], identity="Router-0999")
    assert resp.status_code == 200
    _, count, next_s, _ = _parse_frame(resp.text)
    assert (count, next_s) == (0, svc.IDLE_POLL_SECONDS)


@pytest.mark.asyncio
@pytest.mark.parametrize("flag,value", [("CHECKIN_ENABLED", False), ("CHECKIN_KILL_SWITCH", True)])
async def test_flags_off_or_kill_switch_reply_empty(client, monkeypatch, flag, value):
    monkeypatch.setattr(settings, flag, value)
    resp = await _checkin(client, [])
    _, count, next_s, _ = _parse_frame(resp.text)
    assert (count, next_s) == (0, svc.IDLE_POLL_SECONDS)


@pytest.mark.asyncio
async def test_bad_body_is_400(client):
    resp = await client.post("/api/router/checkin", content="hello",
                             headers={"Authorization": "Bearer x"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_payment_hint_speeds_up_cadence(client, pilot):
    svc.note_payment_initiated(pilot["other"].id)  # not in the pilot: ignored
    assert svc.payment_hint_active(pilot["other"].id) is False
    svc.note_payment_initiated(pilot["router"].id)
    resp = await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    assert _parse_frame(resp.text)[2] == svc.FAST_POLL_SECONDS


@pytest.mark.asyncio
async def test_pool_pressure_sheds_unless_payment_hot(client, pilot, monkeypatch):
    import app.api.router_checkin_routes as routes

    await _checkin(client, [])  # warms the identity cache
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: True)
    resp = await _checkin(client, [])
    assert _parse_frame(resp.text)[1] == 0
    svc.note_payment_initiated(pilot["router"].id)
    resp = await _checkin(client, [])
    assert _parse_frame(resp.text)[1] == 2


@pytest.mark.asyncio
async def test_rate_limited_check_in_gets_empty_frame(client):
    body = f"v=1&id={IDENT}&n=0&macs="
    headers = {"Authorization": f"Bearer {derive_checkin_token(IDENT)}"}
    svc._last_checkin.clear()
    first = await client.post("/api/router/checkin", content=body, headers=headers)
    second = await client.post("/api/router/checkin", content=body, headers=headers)
    assert _parse_frame(first.text)[1] == 2
    assert _parse_frame(second.text)[1] == 0


@pytest.mark.asyncio
async def test_non_converging_mac_backs_off(client):
    for _ in range(svc.MAX_OFFERS_BEFORE_BACKOFF):
        resp = await _checkin(client, ["AA:BB:CC:00:00:01"])
        assert _parse_frame(resp.text)[1] == 1
    resp = await _checkin(client, ["AA:BB:CC:00:00:01"])
    assert _parse_frame(resp.text)[1] == 0  # paused, not offered forever at 5 s


@pytest.mark.asyncio
async def test_resolution_is_recorded_when_mac_appears(client):
    await _checkin(client, ["AA:BB:CC:00:00:01"])
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    rid = next(iter(svc.stats_snapshot()["routers"]))
    resolved = svc.stats_snapshot()["routers"][rid]["recent_resolutions"]
    assert resolved and resolved[-1]["mac"] == "AA:BB:CC:00:00:02"
    assert resolved[-1]["resolved"] == "present"


def test_note_payment_initiated_is_noop_when_disabled(monkeypatch):
    svc.reset_state()
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", False)
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "5")
    svc.note_payment_initiated(5)
    svc.note_payment_initiated(None)
    svc.note_payment_initiated("junk")
    assert svc._payment_hint == {}


# ---------------------------------------------------------------------------
# Router applier (static checks — the bench is where it is proven)
# ---------------------------------------------------------------------------

URL = "https://isp.bitwavetechnologies.net/api/router/checkin"


def _src(**kw):
    return render_checkin_applier_source(identity=IDENT, endpoint_url=URL, **kw)


@pytest.mark.parametrize("forbidden", [
    ":return", "/import", ":global", ":deserialize", ":serialize", ":parse", ":execute",
    ":onerror", ":timestamp", "delimiter=", "/file/read", "file read", "dst-path",
])
def test_applier_avoids_constructs_that_broke_the_old_agent(forbidden):
    assert forbidden not in _src()


def test_applier_validates_frame_before_any_change():
    src = _src()
    first_write = min(
        src.index(cmd) for cmd in (
            "/ip hotspot ip-binding add", "/queue simple add", "/queue simple remove",
            "/ip hotspot host remove", "/ip hotspot active remove", "/ip firewall address-list add",
        )
    )
    for check in ('= "BWE1,")', '($ln = "END")', "($cnt = $want)", ":set frameOk true",
                  ":if ($frameOk && ($want > 0))"):
        assert src.index(check) < first_write, check
    # Kicks happen only after a NEW binding was added.
    assert src.index(":if ($added)") < src.index("/ip hotspot host remove")


def test_applier_matches_push_formats():
    src = _src()
    assert 'comment=("USER:" . $ref . "|EXPIRES:DB_MANAGED|CHECKIN")' in src
    assert "type=bypassed" in src
    assert ':local qn ("plan_" . $ref)' in src
    assert 'comment=("MAC:" . $mac . "|Plan rate limit")' in src
    assert 'target=($ip . "/32") max-limit=$rate' in src
    assert 'comment~"USER:"' in src
    # Existing bindings (ours or a reseller's) are left alone.
    assert "[:len [/ip hotspot ip-binding find where mac-address=$mac]] = 0" in src


def test_applier_uses_checkin_token_and_parameters():
    src = _src()
    assert derive_checkin_token(IDENT) in src
    assert derive_router_token(IDENT) not in src
    assert f'"{URL}"' in src
    assert "check-certificate=no " in src
    assert "check-certificate=yes-without-crl " in _src(check_certificate="yes-without-crl")
    assert f'script="{SCRIPT_NAME}"' in src
    assert f'[find name="{SCHEDULER_NAME}"]' in src
    assert "output=user as-value" in src
    assert "__" not in src.replace("DB_MANAGED", "")


def test_applier_braces_and_quotes_balance():
    src = _src()
    assert src.count("{") == src.count("}")
    assert src.count("[") == src.count("]")
    assert src.count("(") == src.count(")")
    assert src.count('"') % 2 == 0


@pytest.mark.parametrize("kw", [
    {"identity": 'Router"; /system reboot'},
    {"endpoint_url": "https://x/$(reboot)"},
    {"check_certificate": "maybe"},
])
def test_applier_rejects_unsafe_inputs(kw):
    args = {"identity": IDENT, "endpoint_url": URL, **kw}
    with pytest.raises(ValueError):
        render_checkin_applier_source(**args)


# ---------------------------------------------------------------------------
# Database Session Discipline guard over the new code
# ---------------------------------------------------------------------------

def test_new_modules_pass_the_session_discipline_guard():
    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "scripts"))
    from check_session_discipline import run_check

    failing, _, _ = run_check(
        ["app/services/checkin_delivery.py", "app/api/router_checkin_routes.py",
         "scripts/checkin_pilot_install.py"],
        repo / "scripts" / "session_discipline_allowlist.txt",
    )
    assert failing == []

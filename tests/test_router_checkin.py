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
    """Python mirror of the router applier's parser (fixed offsets).

    ``A`` ops are {mac, rate, epoch, ref}; ``Q`` ops also carry kind="Q".
    """
    lines = text.split("\n")
    assert lines[0].startswith("BWE1,")
    _, seq, count, next_s = lines[0].split(",")
    ops = []
    for ln in lines[1:]:
        if ln == "END":
            break
        ll = len(ln)
        if ln[0:2] == "Q,":
            assert ln[19] == "," and ln[ll - 13] == ","
            ops.append({"kind": "Q", "mac": ln[2:19], "rate": ln[20:ll - 13], "ref": ln[ll - 12:]})
            continue
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
    # Endpoint tests exercise the diff; the grace window has its own tests.
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", 0)
    application = FastAPI()
    application.include_router(checkin_router)
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


async def _checkin(client, macs=(), identity=IDENT, token=None, n=None, q=None):
    body = f"v=1&id={identity}&n={len(macs) if n is None else n}&macs={','.join(macs)}"
    if q is not None:
        body += f"&q={','.join(q)}"
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


# ---------------------------------------------------------------------------
# Fix 1 (2026-09-26): grace window against the Reconnect race
# ---------------------------------------------------------------------------

OLD = "AA:BB:CC:00:00:0A"
NEW = "AA:BB:CC:00:00:0B"
ROUTER = svc.RouterRef(id=7, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)


def _report(macs, q=None):
    body = f"v=1&id={IDENT}&n={len(macs)}&macs={','.join(macs)}"
    if q is not None:
        body += f"&q={','.join(q)}"
    return svc.parse_checkin_body(body.encode())


def _decide(macs, desired, t, q=None, mode="add"):
    return svc.decide(router=ROUTER, report=_report(macs, q), desired=desired,
                      undelivered_recent=False, mode=mode, now=datetime.utcnow(), now_mono=t)


@pytest.fixture
def grace60(monkeypatch):
    svc.reset_state()
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", 60)
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 10)
    yield
    svc.reset_state()


def test_mac_missing_for_less_than_grace_is_not_sent(grace60):
    desired = [_entry(OLD)]
    first = _decide([], desired, 1000.0)
    assert first.lines == [] and [e.mac for e in first.in_grace] == [OLD]
    # A MAC in its grace window keeps the router on the fast cadence.
    assert first.next_s == svc.FAST_POLL_SECONDS
    assert _decide([], desired, 1059.0).lines == []


def test_mac_missing_for_grace_or_longer_is_sent(grace60):
    desired = [_entry(OLD)]
    _decide([], desired, 1000.0)
    sent = _decide([], desired, 1060.0)
    assert [e.mac for e in sent.lines] == [OLD] and sent.in_grace == []


def test_reconnect_old_mac_that_stops_being_desired_is_never_sent(grace60):
    # t=1000: the app removed OLD's binding, the customer row still says OLD.
    assert _decide([], [_entry(OLD)], 1000.0).lines == []
    # t=1010: the row now says NEW (present) -> OLD is no longer desired and
    # must be forgotten, not just skipped.
    _decide([NEW], [_entry(NEW)], 1010.0)
    assert (ROUTER.id, OLD) not in svc._missing_since
    # Even far past the grace window OLD is never offered.
    for t in (1070.0, 1200.0, 5000.0):
        d = _decide([NEW], [_entry(NEW)], t)
        assert OLD not in [e.mac for e in d.lines + d.would_send]
    snap = svc.stats_snapshot()["routers"][ROUTER.id]["recent_resolutions"]
    assert snap[-1] == {"mac": OLD, "missing_seconds": 10, "resolved": "not_desired"}


def test_old_mac_desired_again_restarts_the_grace_clock(grace60):
    _decide([], [_entry(OLD)], 1000.0)
    _decide([], [_entry(NEW)], 1010.0)           # reconnect: OLD dropped
    assert _decide([], [_entry(OLD)], 1065.0).lines == []   # clock restarted at 1065
    assert [e.mac for e in _decide([], [_entry(OLD)], 1125.0).lines] == [OLD]


def test_present_again_resets_the_grace_clock(grace60):
    desired = [_entry(OLD)]
    _decide([], desired, 1000.0)
    _decide([OLD], desired, 1030.0)               # back: resolved present
    assert _decide([], desired, 1050.0).lines == []
    assert _decide([], desired, 1100.0).lines == []   # only 50 s this time
    assert [e.mac for e in _decide([], desired, 1110.0).lines] == [OLD]


def test_truncated_report_does_not_start_the_grace_clock(grace60):
    bad = svc.parse_checkin_body(f"v=1&id={IDENT}&n=9&macs=".encode())
    svc.decide(router=ROUTER, report=bad, desired=[_entry(OLD)], undelivered_recent=False,
               mode="add", now=datetime.utcnow(), now_mono=1000.0)
    assert (ROUTER.id, OLD) not in svc._missing_since
    assert _decide([], [_entry(OLD)], 1060.0).lines == []   # first real observation


def test_grace_setting_is_clamped(monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", -5)
    assert svc.missing_grace_seconds() == 0
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", "junk")
    assert svc.missing_grace_seconds() == svc.DEFAULT_MISSING_GRACE_SECONDS


@pytest.mark.asyncio
async def test_endpoint_holds_first_missing_report_with_default_grace(client, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", 60)
    resp = await _checkin(client, [])
    _, count, next_s, _ = _parse_frame(resp.text)
    assert count == 0 and next_s == svc.FAST_POLL_SECONDS


# ---------------------------------------------------------------------------
# Fix 3: Q lines (speed limit for a device whose IP was unknown at bypass)
# ---------------------------------------------------------------------------

def _router_accepts(text):
    """Python mirror of the applier's pass 1 (validate everything first)."""
    if not text.startswith("BWE1,") or "\n" not in text:
        return False
    hdr, body = text.split("\n", 1)
    parts = hdr[5:].split(",")
    if len(parts) != 3 or not parts[1].isdigit():
        return False
    want = int(parts[1])
    cnt, rest = 0, body
    for _ in range(40):
        ln, _, rest = rest.partition("\n")
        if ln == "END":
            return cnt == want
        ll = len(ln)
        ok = False
        if 47 <= ll <= 80 and ln[0:2] == "A," and ln[19] == "," and ln[ll - 24] == "," and ln[ll - 13] == ",":
            vm, vr, ve = ln[2:19], ln[20:ll - 24], ln[ll - 23:ll - 13]
            ok = all(vm[i] == ":" for i in (2, 5, 8, 11, 14)) and "/" in vr and "," not in vr and ve.isdigit()
        if 36 <= ll <= 70 and ln[0:2] == "Q," and ln[19] == "," and ln[ll - 13] == ",":
            vm, vr = ln[2:19], ln[20:ll - 13]
            ok = all(vm[i] == ":" for i in (2, 5, 8, 11, 14)) and "/" in vr and "," not in vr
        if not ok:
            return False
        cnt += 1
    return False


def test_queue_line_round_trips_and_counts_in_header():
    text = svc.render_frame(1, [_entry()], 5, [_entry("AA:BB:CC:00:00:02", "512K/1.5M")])
    assert text.startswith("BWE1,1,2,5\n")
    _, count, _, ops = _parse_frame(text)
    assert count == 2
    assert ops[1] == {"kind": "Q", "mac": "AA:BB:CC:00:00:02", "rate": "512K/1.5M", "ref": "AABBCC000002"}
    assert _router_accepts(text)


@pytest.mark.parametrize("rate", ["1/1", "5M/5M", "10000000/10000000", "1234567890.123G/1234567890.123G"])
def test_router_validator_accepts_every_valid_queue_line_length(rate):
    assert _router_accepts(svc.render_frame(1, [], 5, [_entry(rate=rate)]))


@pytest.mark.parametrize("bad", [
    _entry(mac='AA:BB:CC:00:00:0"'),
    _entry(rate="5M/5M;/system reboot"),
    _entry(rate="$x/5M"),
    _entry(rate="5M"),
    _entry(ref="AABBCC00000]"),
])
def test_unsafe_queue_fields_are_dropped(bad):
    assert svc.format_queue_line(bad) is None
    text = svc.render_frame(1, [], 5, [bad, _entry()])
    assert text.startswith("BWE1,1,1,5\n") and text.count("\nQ,") == 1
    assert not re.search(r'["$;\[\]{}\\]', text)


def test_router_validator_rejects_count_or_shape_mismatch():
    good = svc.render_frame(1, [_entry()], 5, [_entry("AA:BB:CC:00:00:02")])
    assert _router_accepts(good)
    assert not _router_accepts(good.replace("BWE1,1,2,", "BWE1,1,1,"))    # count excludes Q
    assert not _router_accepts(good.replace("Q,AA:", "Q,AA-"))
    assert not _router_accepts(good.replace("\nEND\n", "\n"))            # truncated


def test_parse_body_queue_field():
    rep = svc.parse_checkin_body(
        b"v=1&id=R1&n=2&macs=AA:BB:CC:00:00:01,AA:BB:CC:00:00:02&q=aa:bb:cc:00:00:02,AA:BB:CC:00:00:09,junk")
    assert rep.reports_queues and rep.queue_missing == {"AA:BB:CC:00:00:02"}  # subset of macs only
    old = svc.parse_checkin_body(b"v=1&id=R1&n=1&macs=AA:BB:CC:00:00:01")
    assert not old.reports_queues and old.queue_missing == frozenset()
    empty = svc.parse_checkin_body(b"v=1&id=R1&n=1&macs=AA:BB:CC:00:00:01&q=")
    assert empty.reports_queues and empty.queue_missing == frozenset()


@pytest.mark.asyncio
async def test_endpoint_sends_q_line_for_present_mac_without_queue(client):
    macs = ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"]
    resp = await _checkin(client, macs, q=["AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"])
    text = resp.text
    assert _router_accepts(text)
    _, count, next_s, ops = _parse_frame(text)
    # 03 is expired (not desired): no queue for it.
    assert count == 1 and ops == [{"kind": "Q", "mac": "AA:BB:CC:00:00:02", "rate": "5M/5M", "ref": "AABBCC000002"}]
    assert next_s != svc.CONFIRM_POLL_SECONDS  # Q lines do not pin the router at 5 s


@pytest.mark.asyncio
async def test_old_applier_without_q_never_gets_q_lines(client):
    resp = await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    assert _parse_frame(resp.text)[1] == 0
    assert "\nQ," not in resp.text


@pytest.mark.asyncio
async def test_shadow_mode_sends_no_q_lines(client, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MODE", "shadow")
    resp = await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"], q=["AA:BB:CC:00:00:02"])
    assert _parse_frame(resp.text)[1] == 0
    rid = next(iter(svc.stats_snapshot()["routers"]))
    assert svc.stats_snapshot()["routers"][rid]["would_queue_total"] == 1


@pytest.mark.asyncio
async def test_add_lines_take_priority_over_q_lines_under_the_cap(client, monkeypatch):
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 1)
    resp = await _checkin(client, ["AA:BB:CC:00:00:02"], q=["AA:BB:CC:00:00:02"])
    _, count, _, ops = _parse_frame(resp.text)
    assert count == 1 and "kind" not in ops[0] and ops[0]["mac"] == "AA:BB:CC:00:00:01"


def test_q_line_backs_off_when_not_converging(grace60):
    desired = [_entry(OLD)]
    for i in range(svc.MAX_QUEUE_OFFERS_BEFORE_BACKOFF):
        assert len(_decide([OLD], desired, 1000.0 + i, q=[OLD]).queue_lines) == 1
    assert _decide([OLD], desired, 1010.0, q=[OLD]).queue_lines == []
    # The queue appeared -> offers reset; a later gap is offered again at once.
    _decide([OLD], desired, 1011.0, q=[])
    assert len(_decide([OLD], desired, 1012.0, q=[OLD]).queue_lines) == 1


# ---------------------------------------------------------------------------
# Fix 2: record check-in deliveries on provisioning_attempts
# ---------------------------------------------------------------------------

_SRC_PK = iter(range(900_000, 999_999))


async def _customer_by_mac(db, mac):
    from sqlalchemy import select as _select
    from app.db.models import Customer
    return (await db.execute(_select(Customer).where(Customer.mac_address == mac))).scalars().first()


async def _attempt(db, customer, router, state=ProvisioningState.RETRY_PENDING, age=timedelta(minutes=3),
                   attempt_count=3):
    now = datetime.utcnow()
    a = ProvisioningAttempt(
        customer_id=customer.id, router_id=router.id, mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_SRC_PK),
        entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, provisioning_state=state,
        attempt_count=attempt_count, last_error="Failed to connect",
        last_attempt_at=now - timedelta(seconds=30), created_at=now - age, updated_at=now - age,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


async def _logs(db, attempt_id):
    from sqlalchemy import select as _select
    from app.db.models import ProvisioningLog
    return (await db.execute(_select(ProvisioningLog).where(ProvisioningLog.attempt_id == attempt_id))).scalars().all()


@pytest.mark.asyncio
async def test_present_mac_marks_undelivered_attempt_delivered_like_a_push(client, pilot):
    from app.db.models import ProvisioningOnlineState
    from app.services.hotspot_provisioning import derive_delivery_status

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router)
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert a.delivered_via == "checkin"
    assert a.router_updated_at is not None and a.access_seen_at == a.router_updated_at
    assert a.online_state == ProvisioningOnlineState.UNKNOWN
    assert a.last_error is None
    assert derive_delivery_status(a.provisioning_state, a.online_state) == "access_ready"
    logs = await _logs(db, a.id)
    assert len(logs) == 1 and logs[0].action == "checkin_delivery" and logs[0].status == "success"
    assert "delivered via check-in at" in logs[0].details and "previous_state=retry_pending" in logs[0].details
    rid = router.id
    assert svc.stats_snapshot()["routers"][rid]["deliveries_recorded_total"] == 1

    # Idempotent: the next check-in finds nothing left to mark.
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    assert len(await _logs(db, a.id)) == 1


@pytest.mark.asyncio
async def test_failed_attempt_with_exhausted_retry_window_is_marked_delivered(client, pilot):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router, state=ProvisioningState.FAILED, age=timedelta(hours=6),
                       attempt_count=14)
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED and a.delivered_via == "checkin"
    assert "previous_state=failed" in (await _logs(db, a.id))[0].details


@pytest.mark.asyncio
async def test_attempts_not_proven_by_the_report_are_left_alone(client, pilot):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    expired = await _customer_by_mac(db, "AA:BB:CC:00:00:03")
    absent = await _attempt(db, paid, router)                     # 01 not in the report
    lapsed = await _attempt(db, expired, router)                  # customer expired
    await _checkin(client, ["AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"])
    for a in (absent, lapsed):
        await db.refresh(a)
        assert a.provisioning_state == ProvisioningState.RETRY_PENDING and a.delivered_via is None
    # A truncated report proves nothing either.
    await _checkin(client, ["AA:BB:CC:00:00:01"], n=5)
    await db.refresh(absent)
    assert absent.provisioning_state == ProvisioningState.RETRY_PENDING


@pytest.mark.asyncio
async def test_superseded_old_failure_is_history_not_rewritten(client, pilot):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    old = await _attempt(db, paid, router, state=ProvisioningState.FAILED, age=timedelta(hours=10))
    await _attempt(db, paid, router, state=ProvisioningState.ROUTER_UPDATED, age=timedelta(hours=5))
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    await db.refresh(old)
    assert old.provisioning_state == ProvisioningState.FAILED and old.delivered_via is None


@pytest.mark.asyncio
async def test_other_router_attempts_are_never_touched(client, pilot):
    db, other, paid = pilot["db"], pilot["other"], pilot["paid"]
    a = await _attempt(db, paid, other)
    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.RETRY_PENDING


@pytest.mark.asyncio
async def test_customer_changed_between_read_and_write_is_skipped(pilot):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router)
    state = await svc.load_checkin_state(router.id, datetime.utcnow())
    cands = svc.delivery_candidates(_report(["AA:BB:CC:00:00:01"]), state.pending)
    assert [c.attempt_id for c in cands] == [a.id]
    paid.mac_address = "AA:BB:CC:00:00:0F"   # Reconnect lands before the write
    await db.commit()
    assert await svc.record_checkin_deliveries(router.id, cands) == 0
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.RETRY_PENDING


@pytest.mark.asyncio
async def test_checkin_delivery_clears_consumers_backlog_and_alerts(client, pilot, monkeypatch):
    """Everything keyed on provisioning_state must now see 'delivered'."""
    from app.services import hotspot_provisioning
    from app.services import router_overload_alerts as oa

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    attempts = [await _attempt(db, paid, router, age=timedelta(minutes=5)) for _ in range(3)]
    now = datetime.utcnow()
    assert any(r[0] == router.id for r in await oa.find_payment_overload_candidates(now))

    await _checkin(client, ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    for a in attempts:
        await db.refresh(a)
        assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED

    # Router overload alerts: no longer "failing payments".
    assert not any(r[0] == router.id for r in await oa.find_payment_overload_candidates(now))

    # Retry job: never a full re-provision again (a verify-only refresh at most).
    groups_seen = []

    async def capture(groups):
        groups_seen.append(groups)

    monkeypatch.setattr(hotspot_provisioning, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(hotspot_provisioning, "_process_hotspot_retry_router_groups", capture)
    await hotspot_provisioning.retry_pending_hotspot_provisioning_background()
    ids = {a.id for a in attempts}
    items = [item for g in groups_seen for lst in g.values() for item in lst if item[0].id in ids]
    assert items and all(item[4] is True for item in items)   # verify_only

    # Ops health provisioning section: nothing retry_pending for this router.
    from app.services import ops_health
    section = await ops_health.build_provisioning_section(datetime.utcnow())
    assert section["counts"]["retry_pending"] == 0
    assert section["counts"]["router_updated"] >= 3


# ---------------------------------------------------------------------------
# Fix 2a: the push records itself, and a late push failure cannot regress
# ---------------------------------------------------------------------------

def _push_payload(customer):
    return {"mac_address": customer.mac_address, "username": customer.mac_address.replace(":", "")}


@pytest.mark.asyncio
async def test_push_success_records_delivered_via_push(pilot):
    from app.services import hotspot_provisioning as hsp

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router, state=ProvisioningState.IN_PROGRESS)
    await hsp._persist_provisioning_result(
        result={"provision_result": {}, "online_state": "online"}, verify_only=False,
        customer_id=paid.id, router_id=router.id, router_ip="10.0.0.2", mac_address=paid.mac_address,
        action="hotspot_payment", attempt_id=a.id, hotspot_payload=_push_payload(paid),
    )
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert a.delivered_via == "push" and a.access_seen_at == a.router_updated_at


@pytest.mark.asyncio
async def test_push_after_checkin_keeps_checkin_attribution(pilot):
    from app.services import hotspot_provisioning as hsp

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router, state=ProvisioningState.IN_PROGRESS)
    cands = svc.delivery_candidates(_report(["AA:BB:CC:00:00:01"]),
                                    (await svc.load_checkin_state(router.id, datetime.utcnow())).pending)
    assert await svc.record_checkin_deliveries(router.id, cands) == 1
    await db.refresh(a)
    seen = a.access_seen_at
    await hsp._persist_provisioning_result(
        result={"provision_result": {}, "online_state": "online"}, verify_only=False,
        customer_id=paid.id, router_id=router.id, router_ip="10.0.0.2", mac_address=paid.mac_address,
        action="hotspot_payment", attempt_id=a.id, hotspot_payload=_push_payload(paid),
    )
    await db.refresh(a)
    assert a.delivered_via == "checkin" and a.access_seen_at == seen


@pytest.mark.asyncio
async def test_late_push_failure_does_not_regress_a_checkin_delivery(pilot):
    from app.services import hotspot_provisioning as hsp

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    a = await _attempt(db, paid, router, state=ProvisioningState.IN_PROGRESS)
    cands = svc.delivery_candidates(_report(["AA:BB:CC:00:00:01"]),
                                    (await svc.load_checkin_state(router.id, datetime.utcnow())).pending)
    await svc.record_checkin_deliveries(router.id, cands)
    result = await hsp._persist_provisioning_result(
        result={"error": "Failed to connect to router"}, verify_only=False,
        customer_id=paid.id, router_id=router.id, router_ip="10.0.0.2", mac_address=paid.mac_address,
        action="hotspot_payment", attempt_id=a.id, hotspot_payload=_push_payload(paid),
    )
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED and a.delivered_via == "checkin"
    assert a.last_error is None
    assert result["delivery"]["delivery_status"] == "access_ready"
    statuses = [log.status for log in await _logs(db, a.id)]
    assert "push_failed_after_checkin_delivery" in statuses


# ---------------------------------------------------------------------------
# Fix 4: admin metrics — per-path counts and payment->access latency
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delivery_path_metrics_split_pilot_and_rest(pilot, monkeypatch):
    db, router, other, paid = pilot["db"], pilot["router"], pilot["other"], pilot["paid"]
    monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", str(router.id))
    now = datetime.utcnow()

    async def add(rid, state, via, age_s, access_after_s):
        created = now - timedelta(seconds=age_s)
        db.add(ProvisioningAttempt(
            customer_id=paid.id, router_id=rid, mac_address=paid.mac_address,
            source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_SRC_PK),
            entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, provisioning_state=state,
            delivered_via=via, created_at=created, updated_at=created,
            access_seen_at=(created + timedelta(seconds=access_after_s)) if access_after_s is not None else None,
        ))

    await add(router.id, ProvisioningState.ROUTER_UPDATED, "checkin", 600, 40)
    await add(router.id, ProvisioningState.ROUTER_UPDATED, "push", 600, 10)
    await add(router.id, ProvisioningState.RETRY_PENDING, None, 600, None)
    await add(other.id, ProvisioningState.ROUTER_UPDATED, "push", 600, 5)
    await add(other.id, ProvisioningState.ROUTER_UPDATED, None, 600, None)   # pre-2026-09-26 row
    await add(other.id, ProvisioningState.ROUTER_UPDATED, "push", 3 * 86400, 5)  # outside 24 h
    await db.commit()

    m = await svc.delivery_path_metrics(now)
    assert m["pilot_router_ids"] == [router.id]
    assert m["pilot"]["counts"] == {"push": 1, "checkin": 1, "other": 0, "undelivered": 1}
    assert m["pilot"]["payment_to_access"] == {"samples": 2, "p50_seconds": 10.0, "p95_seconds": 40.0}
    assert m["pilot"]["payment_to_access_by_path"]["checkin"]["p50_seconds"] == 40.0
    assert m["rest"]["counts"] == {"push": 1, "checkin": 0, "other": 1, "undelivered": 0}
    assert m["rest"]["payment_to_access"]["p95_seconds"] == 5.0


def test_percentile_nearest_rank():
    assert svc._percentile([], 0.5) is None
    vals = sorted(float(v) for v in range(1, 101))
    assert svc._percentile(vals, 0.5) == 50.0 and svc._percentile(vals, 0.95) == 95.0


# ---------------------------------------------------------------------------
# Applier: Q-line support (static checks)
# ---------------------------------------------------------------------------

def test_applier_reports_bindings_without_queue():
    src = _src()
    assert '[:len [/queue simple find where name=("plan_" . $rf)]] = 0' in src
    assert ':if ($qOk) do={ :set post ($post . "&q=" . $qmacs) }' in src
    assert "http-data=$post" in src
    # The report still carries n= and macs= exactly as before (old servers).
    assert '("v=1&id=" . $ident . "&n=" . $n . "&macs=" . $macs)' in src


def test_applier_validates_q_lines_before_any_change():
    src = _src()
    first_write = min(src.index(c) for c in ("/ip hotspot ip-binding add", "/queue simple add", "/queue simple remove"))
    assert src.index('([:pick $ln 0 2] = "Q,")') < first_write
    assert src.index(":if ($frameOk && ($want > 0))") < first_write


def test_applier_q_line_only_queues_checkin_bindings_that_lack_a_queue():
    src = _src()
    q_block = src[src.index(':if ($kind = "Q") do={'):]
    assert 'find where mac-address=$mac comment~"CHECKIN"' in q_block
    assert '[:len [/queue simple find where name=("plan_" . $ref)]] = 0' in q_block
    # Same queue creation as the add path, reached for Q or a new binding only.
    assert src.count("/queue simple add name=$qn") == 1
    assert ':if ($added || ($kind = "Q")) do={' in src
    # The IP is looked up before the kick removes the hotspot host entry.
    assert src.index("/ip hotspot host get $h address") < src.index("/ip hotspot host remove")
    # A Q line never adds or kicks anything.
    assert src.index(':if ($kind = "A") do={\n                        :do {\n                            /ip hotspot ip-binding add') > 0

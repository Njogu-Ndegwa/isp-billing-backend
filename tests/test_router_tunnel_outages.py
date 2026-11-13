"""A dead management tunnel is not a dead site.

2026-10-12, routers 448 and 351: from about 13:55 to 15:07 UTC no usage
report arrived and every RouterOS connection failed, so uptime and the
activity log said "Site went offline: power or the site's internet may be
down". Router 448 had been up 8.5 days; 351's expiry reaper kept calling us
over public HTTPS the whole time, and customers kept paying through both
sites. Only the tunnel was down.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.api import router_management
from app.api.customer_audit_routes import _router_status_items
from app.db.models import RouterPublicContact
from app.services.router_availability import (
    PUBLIC_CONTACT_SILENCE,
    record_router_availability,
    split_tunnel_outages,
    uptime_outages,
)
from tests.factories import make_reseller, make_router
from tests.test_router_expiry_reaper import IDENT, _now_minute, _post, _router_with, client  # noqa: F401

T = datetime(2026, 10, 12, 12, 0, 0)


def _at(minutes):
    return T + timedelta(minutes=minutes)


def _checks(silent_from, silent_to, until=180):
    """Reports every 5 min, failed connections every 2 min while silent."""
    out = []
    for m in range(0, until, 5):
        if not silent_from <= m < silent_to:
            out.append({"checked_at": _at(m), "is_online": True, "source": "usage_push"})
    for m in range(silent_from, silent_to, 2):
        out.append({"checked_at": _at(m), "is_online": False, "source": "provisioning"})
    return out


def _split(checks, contacts, now):
    return split_tunnel_outages(uptime_outages(checks, now=now), contacts, now=now)


def test_an_outage_with_no_public_call_is_still_the_site():
    out = _split(_checks(60, 135), [], now=_at(180))
    assert len(out["outages"]) == 1 and out["tunnel_outages"] == []


def test_calls_over_the_internet_make_it_a_tunnel_outage():
    contacts = [_at(m) for m in (72, 76, 80, 95, 110, 125)]
    out = _split(_checks(60, 135), contacts, now=_at(180))
    assert out["outages"] == []
    (tunnel,) = out["tunnel_outages"]
    # Failures within 8 minutes of the last report (at 55) do not count.
    assert tunnel["started_at"] == _at(64).isoformat()
    assert tunnel["ended_at"] == _at(135).isoformat()
    assert tunnel["public_contacts"] == 6


def test_a_long_quiet_stretch_inside_a_tunnel_outage_is_still_site_downtime():
    # Silent from 60; the first internet call only at 60 + 2 h: the site was
    # probably down until then, the tunnel stayed down after.
    first = 60 + 120
    contacts = [_at(first), _at(first + 10)]
    out = _split(_checks(60, first + 20, until=first + 60), contacts, now=_at(first + 60))
    (site,) = out["outages"]
    assert (site["started_at"], site["ended_at"]) == (_at(64).isoformat(), _at(first).isoformat())
    assert len(out["tunnel_outages"]) == 1


def test_a_tunnel_outage_still_going_with_no_recent_call_is_the_site_again():
    last_call = 70
    now = last_call + PUBLIC_CONTACT_SILENCE.total_seconds() / 60 + 30
    out = _split(_checks(60, int(now), until=int(now)), [_at(last_call)], now=_at(now))
    (site,) = out["outages"]
    assert site["started_at"] == _at(last_call).isoformat() and site["ended_at"] is None
    assert out["tunnel_outages"][0]["ended_at"] is None


def test_activity_log_says_tunnel_down_not_site_offline():
    contacts = [_at(m) for m in (72, 90, 110, 125)]
    items = _router_status_items(
        _checks(60, 135), 448, window_start=T, window_end=_at(180), public_contacts=contacts,
    )
    kinds = [i["event_type"] for i in sorted(items, key=lambda i: i["occurred_at"])]
    assert kinds == ["tunnel_down", "tunnel_up"]
    assert "site still online" in items[0]["message"] or "site still online" in items[1]["message"]
    assert not any("Power" in i["message"] for i in items)


def test_activity_log_when_the_site_comes_back_before_the_tunnel():
    first = 60 + 120
    contacts = [_at(first), _at(first + 10)]
    items = sorted(_router_status_items(
        _checks(60, first + 20, until=first + 60), 448,
        window_start=T, window_end=_at(first + 60), public_contacts=contacts,
    ), key=lambda i: i["occurred_at"])
    assert [i["event_type"] for i in items] == ["router_offline", "router_online", "tunnel_up"]
    assert "management tunnel is still down" in items[1]["message"]


@pytest.mark.asyncio
async def test_uptime_does_not_count_a_tunnel_outage(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    start = now - timedelta(hours=3)
    for m in range(0, 180, 5):
        at = start + timedelta(minutes=m)
        if 60 <= m < 135:
            await record_router_availability(None, router.id, False, "provisioning", checked_at=at)
        else:
            await record_router_availability(None, router.id, True, "usage_push", checked_at=at)
    for m in (70, 85, 100, 115, 130):
        db.add(RouterPublicContact(router_id=router.id, contacted_at=start + timedelta(minutes=m),
                                   source="expiry_check"))
    await db.commit()

    out = await router_management.get_router_uptime(
        router.id, hours=24, recent_checks=200, db=db,
        token={"user_id": reseller.id, "role": reseller.role.value})
    assert out["window"]["outage_count"] == 0
    assert out["window"]["uptime_percentage"] == 100.0
    assert len(out["tunnel_outages"]) == 1
    failed = [c for c in out["recent_checks"] if not c["is_online"]]
    assert failed and not any(c["counted_as_outage"] for c in failed)
    assert sum(c["in_tunnel_outage"] for c in failed) >= 10


@pytest.mark.asyncio
async def test_a_reaper_call_over_the_internet_is_recorded(client, db, session_factory):  # noqa: F811
    router, _ = await _router_with(db, [])
    assert (await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done=")).status_code == 200
    async with session_factory() as s:
        rows = (await s.execute(select(RouterPublicContact))).scalars().all()
    assert [(r.router_id, r.source) for r in rows] == [(router.id, "expiry_check")]


@pytest.mark.asyncio
async def test_a_reaper_call_through_the_tunnel_is_not(client, db, session_factory):  # noqa: F811
    from app.services.usage_push_auth import derive_router_token

    await _router_with(db, [])
    r = await client.post(
        "/api/router/expiry-check", content=f"ident={IDENT}&now={_now_minute()}&due=&done=",
        headers={"Authorization": f"Bearer {derive_router_token(IDENT)}",
                 "Content-Type": "text/plain", "X-Bitwave-Push-Channel": "tunnel"},
    )
    assert r.status_code == 200
    async with session_factory() as s:
        assert (await s.execute(select(RouterPublicContact))).scalars().all() == []


@pytest.mark.asyncio
async def test_public_calls_are_kept_at_most_every_two_minutes(client, db, session_factory):  # noqa: F811
    import app.api.router_expiry_routes as routes

    await _router_with(db, [])
    for _ in range(3):
        routes._last_call_at.clear()   # step past the 20 s call floor
        assert (await _post(client, f"ident={IDENT}&now={_now_minute()}&due=&done=")).status_code == 200
    async with session_factory() as s:
        assert len((await s.execute(select(RouterPublicContact))).scalars().all()) == 1

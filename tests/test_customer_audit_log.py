"""Customer audit log: session diffs, router log capture, the merged timeline."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import customer_audit_routes, customer_routes
from app.db.models import (
    ConnectionType, CustomerEvent, CustomerPayment, CustomerStatus,
    MpesaTransaction, MpesaTransactionStatus, PaymentMethod, PaymentStatus,
)
from app.services import customer_events, customer_router_logs
from app.services.customer_events import observe_push, parse_uptime
from app.services.customer_router_logs import (
    CustomerIndex, RouterClock, match_log_entries, parse_gmt_offset, parse_log_time,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

UTC_NOW = datetime(2026, 10, 11, 9, 0, 0)  # 12:00 EAT


def _clock(local_now=datetime(2026, 10, 11, 12, 0, 0), offset=180):
    return RouterClock(local_now=local_now, offset_minutes=offset, trusted=True)


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


# ---------------------------------------------------------------------------
# Router clock / timestamps
# ---------------------------------------------------------------------------

def test_gmt_offset_forms():
    assert parse_gmt_offset("+03:00") == 180
    assert parse_gmt_offset("-01:30") == -90
    assert parse_gmt_offset("+0100") == 60
    assert parse_gmt_offset(10800) == 180
    assert parse_gmt_offset("") is None


def test_clock_print_ros6_and_ros7():
    ros6 = RouterClock.from_clock_print(
        {"time": "12:00:00", "date": "oct/11/2026", "gmt-offset": "+03:00"}, UTC_NOW)
    ros7 = RouterClock.from_clock_print(
        {"time": "12:00:00", "date": "2026-10-11", "gmt-offset": "+03:00"}, UTC_NOW)
    for clock in (ros6, ros7):
        assert clock.local_now == datetime(2026, 10, 11, 12, 0, 0)
        assert clock.offset_minutes == 180
        assert clock.trusted


def test_unset_router_clock_is_not_trusted():
    # hAP lite with no RTC before SNTP: the clock reads 1970.
    clock = RouterClock.from_clock_print(
        {"time": "00:05:00", "date": "jan/02/1970", "gmt-offset": "+03:00"}, UTC_NOW)
    assert not clock.trusted


@pytest.mark.parametrize("raw, expected", [
    ("11:59:01", datetime(2026, 10, 11, 11, 59, 1)),           # today
    ("23:30:00", datetime(2026, 10, 10, 23, 30, 0)),           # "later than now" = yesterday
    ("oct/09 08:00:00", datetime(2026, 10, 9, 8, 0, 0)),       # ROS6 this year
    ("dec/31 23:00:00", datetime(2025, 12, 31, 23, 0, 0)),     # ROS6 last year
    ("jan/05/2025 07:00:00", datetime(2025, 1, 5, 7, 0, 0)),   # ROS6 with year
    ("10-09 08:00:00", datetime(2026, 10, 9, 8, 0, 0)),        # ROS7 this year
    ("2025-12-31 23:00:00", datetime(2025, 12, 31, 23, 0, 0)),  # ROS7 with year
    ("garbage", None),
])
def test_log_time_formats(raw, expected):
    assert parse_log_time(raw, _clock()) == expected


# ---------------------------------------------------------------------------
# Matching log lines to customers
# ---------------------------------------------------------------------------

def test_index_matches_whole_usernames_and_macs():
    index = CustomerIndex()
    index.add(1, 10, "john", [])
    index.add(2, 10, "pppoe_254712345678", ["3c:52:82:aa:bb:cc"])
    index.add(3, 10, "bob", ["11:22:33:44:55:66"])  # "bob" is too short to search for

    assert index.match("<pppoe-john>: authenticated")[0].customer_id == 1
    assert index.match("john logged in, 10.10.0.5 from 3C:52:82:00:00:01")[0].customer_id == 1
    assert index.match("user john authentication failed") is not None
    assert index.match("johnny logged in") is None
    assert index.match("john.doe logged in") is None
    assert index.match("john2 logged in") is None
    ref, how = index.match("<pppoe-3C:52:82:AA:BB:CC>: waiting for call...")
    assert (ref.customer_id, how) == (2, "mac")
    assert index.match("bob logged in") is None
    assert index.match("dhcp1 assigned 10.5.50.9 for 11:22:33:44:55:66")[0].customer_id == 3


def test_match_log_entries_converts_to_utc_and_dedups_across_midnight():
    index = CustomerIndex()
    index.add(7, 3, "alice_home", [])
    entries = [
        {"time": "11:00:00", "topics": "pppoe,ppp,info", "message": "<pppoe-alice_home>: authenticated"},
        {"time": "11:00:05", "topics": "pppoe,ppp,info,account", "message": "alice_home logged in, 10.0.0.9"},
        {"time": "11:00:06", "topics": "firewall,info", "message": "alice_home forward: in:x"},
        {"time": "11:00:07", "topics": "system,info", "message": "router rebooted"},
        {"time": "11:30:00", "topics": "pppoe,ppp,error",
         "message": "<pppoe-alice_home>: terminating... - peer is not responding"},
    ]
    rows = match_log_entries(5, entries, _clock(), index, UTC_NOW)
    assert [r["message"] for r in rows] == [
        "<pppoe-alice_home>: authenticated",
        "alice_home logged in, 10.0.0.9",
        "<pppoe-alice_home>: terminating... - peer is not responding",
    ]
    assert rows[0]["occurred_at"] == datetime(2026, 10, 11, 8, 0, 0)  # 11:00 EAT
    assert rows[2]["severity"] in ("warning", "error")
    assert all(r["customer_id"] == 7 and r["user_id"] == 3 for r in rows)

    # The next day the router prints the same line as "oct/11 11:00:00".
    next_day = _clock(local_now=datetime(2026, 10, 12, 9, 0, 0))
    again = match_log_entries(5, [dict(entries[0], time="oct/11 11:00:00")], next_day, index, UTC_NOW)
    assert again[0]["dedup_key"] == rows[0]["dedup_key"]


# ---------------------------------------------------------------------------
# Session transitions from push reports
# ---------------------------------------------------------------------------

def test_uptime_parsing():
    assert parse_uptime("1w2d03:04:05") == 7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert parse_uptime("3h12m5s") == 3 * 3600 + 12 * 60 + 5
    assert parse_uptime("00:00:40") == 40
    assert parse_uptime("") is None


def _ppp(name, uptime, address="10.0.0.5", caller="3C:52:82:AA:BB:CC"):
    return {"name": name, "uptime": uptime, "address": address, "caller_id": caller}


def test_pppoe_connect_drop_and_silent_reconnect():
    live = {"pppoe:john": 11}
    t0 = UTC_NOW
    # First report after a restart only seeds the state.
    assert observe_push(1, t0, ppp=[_ppp("john", "2h")], live_pppoe_customers=live) == []

    # Session gone from /ppp active.
    ev = observe_push(1, t0 + timedelta(seconds=10), ppp=[], live_pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_disconnected"]
    assert ev[0]["customer_id"] == 11 and ev[0]["details"]["uptime_seconds"] == 7200

    ev = observe_push(1, t0 + timedelta(seconds=20), ppp=[_ppp("john", "5s")], live_pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_connected"]

    # Online in both reports, but the uptime says it restarted in between.
    ev = observe_push(1, t0 + timedelta(seconds=80), ppp=[_ppp("john", "20s")], live_pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_reconnected"]

    # Steady session: nothing.
    ev = observe_push(1, t0 + timedelta(seconds=140), ppp=[_ppp("john", "1m20s")], live_pppoe_customers=live)
    assert ev == []
    assert customer_events.buffered_count() == 3


def test_report_without_ppp_list_concludes_nothing():
    live = {"pppoe:john": 11}
    observe_push(1, UTC_NOW, ppp=[_ppp("john", "1h")], live_pppoe_customers=live)
    assert observe_push(1, UTC_NOW + timedelta(seconds=10), ppp=None, live_pppoe_customers=live) == []
    ev = observe_push(1, UTC_NOW + timedelta(seconds=20), ppp=[_ppp("john", "1h20s")],
                      live_pppoe_customers=live)
    assert ev == []


def test_hotspot_offline_needs_two_missed_reports():
    live = {"AA:BB:CC:00:00:01": 21}
    host = {"mac": "aa:bb:cc:00:00:01", "ip": "10.5.50.3", "uptime": "10m", "bytes_in": 1, "bytes_out": 1}
    observe_push(2, UTC_NOW, hosts=[host], live_hotspot_customers=live)
    assert observe_push(2, UTC_NOW + timedelta(seconds=10), hosts=[], live_hotspot_customers=live) == []
    ev = observe_push(2, UTC_NOW + timedelta(seconds=20), hosts=[], live_hotspot_customers=live)
    assert [e["event_type"] for e in ev] == ["device_offline"]
    ev = observe_push(2, UTC_NOW + timedelta(seconds=30), hosts=[host], live_hotspot_customers=live)
    assert [e["event_type"] for e in ev] == ["device_online"]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flush_writes_queued_events_with_owner(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="john")
    live = {"pppoe:john": customer.id}
    observe_push(router.id, UTC_NOW, ppp=[_ppp("john", "1h")], live_pppoe_customers=live)
    observe_push(router.id, UTC_NOW + timedelta(seconds=10), ppp=[], live_pppoe_customers=live)

    assert await customer_events.flush_customer_events() == 1
    row = (await db.execute(select(CustomerEvent))).scalar_one()
    assert (row.customer_id, row.user_id, row.event_type) == (customer.id, reseller.id, "session_disconnected")
    assert customer_events.buffered_count() == 0


@pytest.mark.asyncio
async def test_router_log_rows_are_stored_once(db):
    index = CustomerIndex()
    index.add(5, 1, "alice_home", [])
    rows = match_log_entries(9, [{"time": "11:00:00", "topics": "pppoe,ppp,info",
                                  "message": "<pppoe-alice_home>: authenticated"}], _clock(), index, UTC_NOW)
    assert await customer_events.store_event_rows([dict(r) for r in rows]) == 1
    await customer_events.store_event_rows([dict(r) for r in rows])
    count = (await db.execute(select(func.count()).select_from(CustomerEvent))).scalar_one()
    assert count == 1


# ---------------------------------------------------------------------------
# The endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_log_merges_sources_and_is_scoped_to_owner(db):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, pppoe_username="john_doe", status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() + timedelta(days=5),
        created_at=datetime.utcnow() - timedelta(days=10))
    now = datetime.utcnow()
    db.add(CustomerPayment(
        customer_id=customer.id, reseller_id=reseller.id, amount=1500,
        payment_method=PaymentMethod.MOBILE_MONEY, days_paid_for=30,
        status=PaymentStatus.COMPLETED, plan_id=plan.id, created_at=now - timedelta(hours=3)))
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_1", phone_number="254712345678", amount=1500,
        reference="x", status=MpesaTransactionStatus.failed, customer_id=customer.id,
        result_desc="Request cancelled by user", created_at=now - timedelta(hours=4)))
    db.add(MpesaTransaction(
        checkout_request_id="ws_CO_2", phone_number="254712345678", amount=1500,
        reference="y", status=MpesaTransactionStatus.completed, customer_id=customer.id,
        created_at=now - timedelta(hours=3)))
    db.add(CustomerEvent(
        customer_id=customer.id, user_id=reseller.id, router_id=router.id,
        occurred_at=now - timedelta(hours=1), category="router_log", event_type="router_log",
        severity="error", source="router_log",
        message="<pppoe-john_doe>: terminating... - peer is not responding"))
    await db.commit()

    out = await customer_audit_routes.customer_audit_log(
        customer.id, None, None, None, 150, db, _token(reseller))
    kinds = [i["event_type"] for i in out["items"]]
    assert kinds == ["router_log", "payment_completed", "mpesa_failed", "customer_created"]
    assert "Request cancelled by user" in out["items"][2]["message"]
    assert out["customer"]["connection_type"] == "pppoe"
    assert out["has_more"] is False

    only_logs = await customer_audit_routes.customer_audit_log(
        customer.id, None, None, "router_log", 150, db, _token(reseller))
    assert [i["event_type"] for i in only_logs["items"]] == ["router_log"]

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.customer_audit_log(customer.id, None, None, None, 150, db, _token(other))
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_audit_log_pages_by_time(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan)
    base = datetime.utcnow() - timedelta(days=1)
    for n in range(5):
        db.add(CustomerEvent(customer_id=customer.id, occurred_at=base + timedelta(minutes=n),
                             category="session", event_type="session_connected",
                             source="router_push", message=f"e{n}"))
    await db.commit()

    first = await customer_audit_routes.customer_audit_log(
        customer.id, None, None, "session", 3, db, _token(reseller))
    assert [i["message"] for i in first["items"]] == ["e4", "e3", "e2"]
    assert first["has_more"] is True
    second = await customer_audit_routes.customer_audit_log(
        customer.id, datetime.fromisoformat(first["next_before"]), None, "session", 3, db, _token(reseller))
    assert [i["message"] for i in second["items"]] == ["e1", "e0"]
    assert second["has_more"] is False


@pytest.mark.asyncio
async def test_edit_records_who_changed_what_without_passwords(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="mary_k",
                                   pppoe_password="old-secret", status=CustomerStatus.INACTIVE)

    await customer_routes.edit_customer(
        customer.id,
        customer_routes.CustomerEditRequest(phone="254700000001", pppoe_password="new-secret"),
        db, _token(reseller))

    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert event.event_type == "customer_updated"
    assert event.actor_user_id == reseller.id
    assert "254712345678 -> 254700000001" in event.message
    assert "PPPoE password changed" in event.message
    assert "secret" not in event.message and "secret" not in str(event.details)


@pytest.mark.asyncio
async def test_pull_router_logs_saves_matching_lines(db, monkeypatch):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="peter_w")

    def fake_fetch(router_info):
        return {
            "success": True,
            "clock": {"time": "12:00:00", "date": "2026-10-11", "gmt-offset": "+03:00"},
            "entries": [
                {"time": "11:58:00", "topics": "pppoe,ppp,error",
                 "message": "<pppoe-peter_w>: user peter_w authentication failed"},
                {"time": "11:59:00", "topics": "pppoe,ppp,info", "message": "<pppoe-someone>: authenticated"},
            ],
        }

    async def fake_guard(router_id, func, *args, **kwargs):
        return fake_fetch(*args)

    monkeypatch.setattr("app.services.router_concurrency.run_with_guard", fake_guard)
    monkeypatch.setattr(customer_router_logs, "fetch_router_log_sync", fake_fetch)
    customer_audit_routes._last_pull.clear()

    out = await customer_audit_routes.pull_customer_router_logs(customer.id, db, _token(reseller))
    assert (out["lines_read"], out["matched"], out["stored"]) == (2, 1, 1)
    saved = (await db.execute(select(CustomerEvent))).scalar_one()
    assert saved.customer_id == customer.id and saved.severity == "error"

    with pytest.raises(HTTPException) as exc:  # cooldown
        await customer_audit_routes.pull_customer_router_logs(customer.id, db, _token(reseller))
    assert exc.value.status_code == 429

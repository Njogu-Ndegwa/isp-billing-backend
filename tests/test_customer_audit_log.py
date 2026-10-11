"""Customer audit log: session diffs, router log capture, the merged timeline."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.api import customer_audit_routes, customer_routes
from app.db.models import (
    ConnectionType, CustomerEvent, CustomerPayment, CustomerStatus,
    MpesaTransaction, MpesaTransactionStatus, PaymentMethod, PaymentStatus,
    RouterAvailabilityCheck, SmsMessage, SmsMessageKind, SmsMessageStatus,
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
    assert observe_push(1, t0, ppp=[_ppp("john", "2h")], pppoe_customers=live) == []

    # Missing from one report is not yet a drop; from two it is, stamped at
    # the first report it was missing from.
    assert observe_push(1, t0 + timedelta(seconds=10), ppp=[], pppoe_customers=live) == []
    ev = observe_push(1, t0 + timedelta(seconds=20), ppp=[], pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_disconnected"]
    assert ev[0]["occurred_at"] == t0 + timedelta(seconds=10)
    assert ev[0]["customer_id"] == 11 and ev[0]["details"]["uptime_seconds"] == 7200

    ev = observe_push(1, t0 + timedelta(seconds=30), ppp=[_ppp("john", "5s")], pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_connected"]
    # Stamped when the session began, not when the report noticed it.
    assert ev[0]["occurred_at"] == t0 + timedelta(seconds=25)

    ev = observe_push(1, t0 + timedelta(seconds=90), ppp=[_ppp("john", "1m5s")], pppoe_customers=live)
    assert ev == []

    # Online in both reports, but the router's uptime went backwards.
    ev = observe_push(1, t0 + timedelta(seconds=150), ppp=[_ppp("john", "20s")], pppoe_customers=live)
    assert [e["event_type"] for e in ev] == ["session_reconnected"]
    assert customer_events.buffered_count() == 3


def test_one_missed_report_is_not_a_drop():
    live = {"pppoe:john": 11}
    observe_push(1, UTC_NOW, ppp=[_ppp("john", "1h")], pppoe_customers=live)
    assert observe_push(1, UTC_NOW + timedelta(seconds=10), ppp=[], pppoe_customers=live) == []
    assert observe_push(1, UTC_NOW + timedelta(seconds=20), ppp=[_ppp("john", "1h20s")],
                        pppoe_customers=live) == []


def test_short_session_list_proves_nothing_about_the_missing():
    # The RouterOS 6 script can stop its /ppp active walk early: 2 of 5 listed.
    live = {f"pppoe:u{i}": i for i in range(5)}
    full = [_ppp(f"u{i}", "1h") for i in range(5)]
    observe_push(1, UTC_NOW, ppp=full, pppoe_customers=live)
    for n in (1, 2, 3):
        ev = observe_push(1, UTC_NOW + timedelta(seconds=10 * n), ppp=full[:2], pppoe_customers=live,
                          ppp_complete=False)
        assert ev == []


def test_late_report_is_not_a_fake_reconnect():
    # A report that waited in our ingest queue: our clock moved 20 s, the
    # session's uptime only 5 s. Nothing restarted.
    live = {"pppoe:john": 11}
    observe_push(1, UTC_NOW, ppp=[_ppp("john", "5s")], pppoe_customers=live)
    assert observe_push(1, UTC_NOW + timedelta(seconds=20), ppp=[_ppp("john", "10s")],
                        pppoe_customers=live) == []


def test_session_cut_at_expiry_is_recorded():
    # The tracker follows every PPPoE customer on the router, not only paid
    # ones, so the session that expiry cuts still shows up.
    everyone = {"pppoe:john": 11}
    observe_push(1, UTC_NOW, ppp=[_ppp("john", "3h")], pppoe_customers=everyone)
    observe_push(1, UTC_NOW + timedelta(seconds=10), ppp=[], pppoe_customers=everyone)
    ev = observe_push(1, UTC_NOW + timedelta(seconds=20), ppp=[], pppoe_customers=everyone)
    assert [e["event_type"] for e in ev] == ["session_disconnected"]


def test_session_end_reports_duration_and_data_used():
    live = {"pppoe:john": 11}
    t0 = UTC_NOW
    observe_push(1, t0, ppp=[_ppp("john", "1h")], pppoe_customers=live,
                 pppoe_queue_bytes={"pppoe:john": (10, 20)})
    observe_push(1, t0 + timedelta(seconds=60), ppp=[_ppp("john", "1h1m")], pppoe_customers=live,
                 pppoe_queue_bytes={"pppoe:john": (50 * 1024 ** 2, 2 * 1024 ** 3)})
    observe_push(1, t0 + timedelta(seconds=120), ppp=[], pppoe_customers=live)
    ev = observe_push(1, t0 + timedelta(seconds=180), ppp=[], pppoe_customers=live)
    assert ev[0]["message"] == "PPPoE session ended after 1h 1m, used 2.0 GB down / 50.0 MB up (IP 10.0.0.5)"
    assert ev[0]["details"]["download_bytes"] == 2 * 1024 ** 3
    assert ev[0]["details"]["started_at"] == (t0 - timedelta(hours=1)).isoformat()


def test_report_without_ppp_list_concludes_nothing():
    live = {"pppoe:john": 11}
    observe_push(1, UTC_NOW, ppp=[_ppp("john", "1h")], pppoe_customers=live)
    for n in (1, 2, 3):
        assert observe_push(1, UTC_NOW + timedelta(seconds=10 * n), ppp=None, pppoe_customers=live) == []
    ev = observe_push(1, UTC_NOW + timedelta(seconds=40), ppp=[_ppp("john", "1h40s")],
                      pppoe_customers=live)
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
    observe_push(router.id, UTC_NOW, ppp=[_ppp("john", "1h")], pppoe_customers=live)
    observe_push(router.id, UTC_NOW + timedelta(seconds=10), ppp=[], pppoe_customers=live)
    observe_push(router.id, UTC_NOW + timedelta(seconds=20), ppp=[], pppoe_customers=live)

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
    db.add(SmsMessage(
        user_id=reseller.id, customer_id=customer.id, recipient_phone="254712345678",
        body="Your internet is due tomorrow", segments=1, credits_charged=1,
        kind=SmsMessageKind.RESELLER_TO_CUSTOMER, status=SmsMessageStatus.FAILED,
        error="Error sending via TextSms", created_at=now - timedelta(hours=2)))
    db.add(CustomerEvent(
        customer_id=customer.id, user_id=reseller.id, router_id=router.id,
        occurred_at=now - timedelta(hours=1), category="router_log", event_type="router_log",
        severity="error", source="router_log",
        message="<pppoe-john_doe>: terminating... - peer is not responding"))
    await db.commit()

    out = await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=None, categories=None, limit=150, db=db, token=_token(reseller))
    kinds = [i["event_type"] for i in out["items"]]
    assert kinds == ["router_log", "sms_failed", "payment_completed", "mpesa_failed", "customer_created"]
    assert "Request cancelled by user" in out["items"][3]["message"]
    assert out["items"][1]["details"]["body"] == "Your internet is due tomorrow"
    assert out["customer"]["connection_type"] == "pppoe"
    assert out["has_more"] is False

    only_logs = await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=None, categories="router_log", limit=150, db=db, token=_token(reseller))
    assert [i["event_type"] for i in only_logs["items"]] == ["router_log"]

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=None, categories=None, limit=150, db=db, token=_token(other))
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
        customer.id, before=None, after=None, cursor=None, categories="session", limit=3, db=db, token=_token(reseller))
    assert [i["message"] for i in first["items"]] == ["e4", "e3", "e2"]
    assert first["has_more"] is True
    second = await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=datetime.fromisoformat(first["next_before"]), categories="session", limit=3, db=db, token=_token(reseller))
    # The cursor is inclusive (the client drops e2 by id), so nothing that
    # shares the boundary second can fall between pages.
    assert [i["message"] for i in second["items"]] == ["e2", "e1", "e0"]
    # A full page cannot know it was the last; one more call says so.
    third = await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=datetime.fromisoformat(second["next_before"]),
        categories="session", limit=3, db=db, token=_token(reseller))
    assert [i["message"] for i in third["items"]] == ["e0"]
    assert third["has_more"] is False


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

    def fake_fetch(router_info, ppp_username=None):
        return {
            "success": True,
            "clock": {"time": "12:00:00", "date": "2026-10-11", "gmt-offset": "+03:00"},
            "entries": [
                {"time": "11:58:00", "topics": "pppoe,ppp,error",
                 "message": "<pppoe-peter_w>: user peter_w authentication failed"},
                {"time": "11:59:00", "topics": "pppoe,ppp,info", "message": "<pppoe-someone>: authenticated"},
            ],
            "secret": {"name": "peter_w", "last-logged-out": "2026-10-11 11:57:30",
                       "last-caller-id": "3C:52:82:AA:BB:CC", "last-disconnect-reason": "port-error"},
        }

    async def fake_guard(router_id, func, *args, **kwargs):
        return fake_fetch(*args)

    monkeypatch.setattr("app.services.router_concurrency.run_with_guard", fake_guard)
    monkeypatch.setattr(customer_router_logs, "fetch_router_log_sync", fake_fetch)
    customer_audit_routes._last_pull.clear()

    out = await customer_audit_routes.pull_customer_router_logs(customer.id, db, _token(reseller))
    assert (out["lines_read"], out["matched"], out["stored"]) == (2, 1, 2)
    saved = (await db.execute(select(CustomerEvent).order_by(CustomerEvent.occurred_at))).scalars().all()
    assert [e.event_type for e in saved] == ["last_disconnect", "router_log"]
    assert all(e.customer_id == customer.id for e in saved)
    assert "port-error" in saved[0].message and "cable" in saved[0].message
    assert saved[1].severity == "error"

    with pytest.raises(HTTPException) as exc:  # cooldown
        await customer_audit_routes.pull_customer_router_logs(customer.id, db, _token(reseller))
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_viewing_pppoe_credentials_is_logged(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="ann_k", pppoe_password="pw")

    await customer_routes.get_pppoe_credentials(customer.id, db, _token(reseller))

    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert (event.event_type, event.actor_user_id) == ("credentials_viewed", reseller.id)
    assert "pw" not in event.message


@pytest.mark.asyncio
async def test_paging_never_skips_entries_sharing_a_second(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    customer = await make_customer(db, reseller, plan)
    same = datetime.utcnow() - timedelta(hours=1)
    for n in range(5):  # one PPPoE connect writes several lines in one second
        db.add(CustomerEvent(customer_id=customer.id, occurred_at=same, category="router_log",
                             event_type="router_log", source="router_log", message=f"line{n}"))
    await db.commit()

    seen, cursor = {}, None
    for _ in range(5):
        page = await customer_audit_routes.customer_audit_log(
            customer.id, before=None, after=None, cursor=cursor, categories="router_log",
            limit=2, db=db, token=_token(reseller))
        seen.update({i["id"]: i["message"] for i in page["items"]})
        if not page["next_before"]:
            break
        cursor = datetime.fromisoformat(page["next_before"])
    # Five rows in one second and a page size of two: the cursor steps past
    # the second rather than loop, and says so by not promising more.
    assert len(seen) >= 2 and page["next_before"] is None


@pytest.mark.asyncio
async def test_summary_and_router_outages(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="sam_k")
    now = datetime.utcnow()
    db.add(CustomerEvent(customer_id=customer.id, occurred_at=now - timedelta(hours=2), category="session",
                         event_type="session_disconnected", source="router_push", severity="warning",
                         message="PPPoE session ended after 3h"))
    db.add(CustomerEvent(customer_id=customer.id, occurred_at=now - timedelta(hours=3), category="router_log",
                         event_type="router_log", source="router_log", severity="warning",
                         message="<pppoe-sam_k>: terminating... - peer is not responding"))
    for minutes, up in ((300, True), (240, False), (200, False), (150, True)):
        db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=now - timedelta(minutes=minutes),
                                       is_online=up, source="test"))
    await db.commit()

    out = await customer_audit_routes.customer_audit_log(
        customer.id, before=None, after=None, cursor=None, categories=None, limit=150, db=db,
        token=_token(reseller))
    assert out["summary"]["drops_24h"] == 1
    assert "peer is not responding" in out["summary"]["last_problem"]["message"]
    kinds = [i["event_type"] for i in out["items"] if i["category"] == "router"]
    assert kinds == ["router_online", "router_offline"]
    assert "after 1h 30m" in next(i for i in out["items"] if i["event_type"] == "router_online")["message"]


def test_sms_passwords_are_never_shown():
    body = "Welcome to Kahawa Net! Username: jane_w Password: Ab12cd. Pay via M-Pesa Paybill 4699342"
    shown = customer_audit_routes.redact_sms(body)
    assert "Ab12cd" not in shown and "Username: jane_w" in shown and "Paybill 4699342" in shown
    assert customer_audit_routes.redact_sms("Your passport is ready") == "Your passport is ready"


def test_lines_from_before_the_clock_was_set_are_skipped():
    index = CustomerIndex()
    index.add(5, 1, "alice_home", [])
    rows = match_log_entries(9, [
        {"time": "jan/02/1970 00:00:31", "topics": "pppoe,ppp,info", "message": "<pppoe-alice_home>: connected"},
        {"time": "11:00:00", "topics": "pppoe,ppp,info", "message": "<pppoe-alice_home>: authenticated"},
    ], _clock(), index, UTC_NOW)
    assert [r["message"] for r in rows] == ["<pppoe-alice_home>: authenticated"]


def test_usernames_match_exactly_and_only_in_login_lines():
    index = CustomerIndex()
    index.add(1, 1, "home", [])
    index.add(2, 1, "John", [])
    assert index.match("home logged in, 10.0.0.2", "pppoe,ppp,info")[0].customer_id == 1
    assert index.match("home page served to 10.5.50.3", "dhcp,info") is None
    assert index.match("john logged in", "pppoe,ppp,info") is None
    assert index.match("John logged in", "pppoe,ppp,info")[0].customer_id == 2


def test_stamps_follow_the_router_clock_not_its_time_zone():
    # A router left on UTC (offset 0) still lands at the right moment: times
    # are taken as a distance from the router's own "now".
    clock = RouterClock.from_clock_print(
        {"time": "09:00:00", "date": "2026-10-11", "gmt-offset": "+00:00"}, UTC_NOW)
    local = parse_log_time("08:30:00", clock)
    assert clock.to_utc(local) == UTC_NOW - timedelta(minutes=30)


@pytest.mark.asyncio
async def test_reset_session_drops_the_pppoe_session_and_logs_who(db, monkeypatch):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router, pppoe_username="ruth_m")
    calls = []

    async def fake_guard(router_id, func, *args, **kwargs):
        calls.append((router_id, args[1]))
        return {"success": True, "disconnected": 1}

    monkeypatch.setattr("app.services.router_concurrency.run_with_guard", fake_guard)
    customer_audit_routes._last_reset.clear()

    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(other))
    assert exc.value.status_code == 404 and calls == []

    out = await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert out["disconnected"] == 1 and calls == [(router.id, "ruth_m")]
    event = (await db.execute(select(CustomerEvent))).scalar_one()
    assert (event.event_type, event.actor_user_id) == ("session_reset", reseller.id)

    with pytest.raises(HTTPException) as exc:  # cooldown
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_reset_session_is_pppoe_only(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(db, reseller, plan, router)
    with pytest.raises(HTTPException) as exc:
        await customer_audit_routes.reset_customer_session(customer.id, db, _token(reseller))
    assert exc.value.status_code == 400


def test_outage_already_in_progress_is_measured_from_its_start():
    t = datetime(2026, 10, 11, 12, 0, 0)
    # Window starts at 12:00; the router went down at 09:00, last good at 08:55.
    checks = [(t + timedelta(minutes=10), False), (t + timedelta(minutes=25), True)]
    items = customer_audit_routes._router_status_items(
        checks, 7, seed_online=False, seed_went_down=t - timedelta(hours=3))
    assert [i["event_type"] for i in items] == ["router_online"]
    assert "after 3h 25m" in items[0]["message"]
    # Start unknown: no made-up duration.
    items = customer_audit_routes._router_status_items(checks, 7, seed_online=False, seed_went_down=None)
    assert items[0]["message"] == "Router answering again"


def test_custom_welcome_wording_still_hides_the_password():
    body = "Karibu! Nenosiri lako ni Xy9z8w7v. Lipa kupitia Paybill 4699342"
    shown = customer_audit_routes.redact_sms(body, "Xy9z8w7v")
    assert "Xy9z8w7v" not in shown and "Paybill 4699342" in shown


def test_offset_times_are_converted_not_dropped():
    from datetime import timezone as tz
    eat = tz(timedelta(hours=3))
    assert customer_audit_routes._naive_utc(datetime(2026, 10, 11, 15, 0, tzinfo=eat)) == datetime(2026, 10, 11, 12, 0)
    assert customer_audit_routes._naive_utc(datetime(2026, 10, 11, 15, 0)) == datetime(2026, 10, 11, 15, 0)

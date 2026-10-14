"""Static-IP customers: router desired state, metering, live view, routes, expiry."""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

from app.api import customer_routes
from app.db.models import (
    ConnectionType,
    Customer,
    CustomerPayment,
    CustomerStatus,
    ProvisioningLog,
)
from app.services import mikrotik_background, realtime_state, static_ip
from app.services.static_ip import StaticItem, apply_static_items_sync
from app.services.usage_push import UsageReport, _canonical_key, ingest_usage_reports
from tests.factories import make_customer, make_plan, make_reseller, make_router


IP = "192.168.2.24"
MAC = "50:0F:F5:C1:07:50"
ROUTER = {"id": 1, "name": "R", "ip": "10.0.0.2", "username": "u", "password": "p", "port": 8728}


# ---------------------------------------------------------------------------
# A tiny in-memory RouterOS
# ---------------------------------------------------------------------------

class FakeRouterOS:
    def __init__(self):
        self.seq = 0
        self.tables = {
            "/ip/hotspot/ip-binding": [],
            "/queue/simple": [],
            "/ip/firewall/filter": [],
            "/ip/firewall/address-list": [],
            "/ip/address": [{".id": "*A1", "address": "192.168.2.1/24", "interface": "bridge"}],
            "/ip/hotspot/host": [],
            "/ip/arp": [],
        }
        self.add("/queue/simple", {"name": "hs-<hotspot1>", "target": "bridge", "dynamic": "true"})
        self.add("/ip/firewall/filter", {"chain": "forward", "action": "jump", "dynamic": "true"})
        self.add("/ip/firewall/filter", {"chain": "forward", "action": "accept", "comment": "defconf: ipsec"})
        self.add("/ip/firewall/filter", {"chain": "forward", "action": "fasttrack-connection",
                                         "connection-state": "established,related"})
        self.writes = []

    def add(self, table, row, place_before=None):
        self.seq += 1
        row = {".id": f"*{self.seq:X}", **row}
        rows = self.tables[table]
        if place_before:
            idx = next(i for i, r in enumerate(rows) if r[".id"] == place_before)
            rows.insert(idx, row)
        else:
            rows.append(row)
        return row

    def send_command(self, command, args=None):
        args = dict(args or {})
        table, _, verb = command.rpartition("/")
        rows = self.tables[table]
        if verb == "print":
            return {"success": True, "data": [dict(r) for r in rows]}
        self.writes.append((command, args))
        if verb == "add":
            before = args.pop("place-before", None)
            self.add(table, args, before)
        elif verb == "set":
            target = args.pop(".id")
            row = next(r for r in rows if r[".id"] == target)
            row.update(args)
        elif verb == "remove":
            target = args.get("numbers") or args.get(".id")
            self.tables[table] = [r for r in rows if r[".id"] != target]
        elif verb == "move":
            row = next(r for r in rows if r[".id"] == args["numbers"])
            rows.remove(row)
            idx = next(i for i, r in enumerate(rows) if r[".id"] == args["destination"])
            rows.insert(idx, row)
        return {"success": True, "data": []}

    def disconnect(self):
        pass

    def find(self, table, **match):
        return [r for r in self.tables[table] if all(r.get(k) == v for k, v in match.items())]


@pytest.fixture
def fake(monkeypatch):
    router = FakeRouterOS()
    monkeypatch.setattr(static_ip, "_connect", lambda r, lane: router)
    return router


def _item(**kw):
    base = dict(customer_id=7, name="dt9 FF1", ip=IP, rate_limit="10M/10M", enabled=True)
    base.update(kw)
    return StaticItem(**base)


# ---------------------------------------------------------------------------
# Router desired state
# ---------------------------------------------------------------------------

def test_enable_builds_binding_queue_list_and_learns_mac(fake):
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC, "bypassed": "false"})

    out = apply_static_items_sync(ROUTER, [_item()])
    res = out["results"][0]

    assert res["success"] and res["gateway_ok"] and res["access"] == "enabled"
    binding = fake.find("/ip/hotspot/ip-binding", address=IP)[0]
    assert binding["type"] == "bypassed" and "mac-address" not in binding
    queue = fake.find("/queue/simple", name="plan_static:192.168.2.24")[0]
    assert queue["target"] == f"{IP}/32" and queue["max-limit"] == "10M/10M"
    names = [q["name"] for q in fake.tables["/queue/simple"]]
    assert names.index("plan_static:192.168.2.24") < names.index("hs-<hotspot1>")
    assert fake.find("/ip/firewall/address-list", address=IP)
    # Learned on first sight and pinned above every static forward rule.
    assert res["learned_pin"] == MAC
    pin = fake.find("/ip/firewall/filter", **{"src-address": IP})[0]
    assert pin["src-mac-address"] == f"!{MAC}" and pin["action"] == "drop"
    forward = [r for r in fake.tables["/ip/firewall/filter"] if r.get("chain") == "forward"]
    assert forward.index(pin) == 1  # right after the dynamic hotspot rule
    # FastTrack bypass sits before the fasttrack rule.
    ft = next(i for i, r in enumerate(forward) if r["action"] == "fasttrack-connection")
    bypass = [i for i, r in enumerate(forward) if "FastTrack" in str(r.get("comment"))]
    assert len(bypass) == 2 and all(i < ft for i in bypass)


def test_second_apply_is_a_no_op(fake):
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC})
    apply_static_items_sync(ROUTER, [_item()])
    fake.writes.clear()

    res = apply_static_items_sync(ROUTER, [_item(mac=MAC)])["results"][0]

    assert res["changes"] == [] and fake.writes == []


def test_adopts_hand_made_objects_instead_of_duplicating(fake):
    # What was configured by hand on router 602 before the app knew.
    fake.add("/ip/hotspot/ip-binding", {"address": IP, "type": "bypassed", "comment": "STATIC: dt9 FF1 (cust 7)"})
    fake.add("/queue/simple", {"name": "dt9 FF1", "target": f"{IP}/32", "max-limit": "10000000/10000000",
                               "comment": "STATIC: cust 7"}, place_before="*1")
    fake.add("/ip/firewall/filter", {"chain": "forward", "src-address": IP, "src-mac-address": f"!{MAC}",
                                     "action": "drop", "comment": "STATIC-PIN: dt9 FF1 (cust 7)"},
             place_before="*3")

    res = apply_static_items_sync(ROUTER, [_item()])["results"][0]

    assert len(fake.find("/ip/hotspot/ip-binding", address=IP)) == 1
    queues = [q for q in fake.tables["/queue/simple"] if q["target"] == f"{IP}/32"]
    assert [q["name"] for q in queues] == ["plan_static:192.168.2.24"]
    assert res["adopted_pin"] == MAC
    assert len(fake.find("/ip/firewall/filter", **{"src-address": IP})) == 1


def test_suspend_disables_binding_and_kicks_host(fake):
    apply_static_items_sync(ROUTER, [_item()])
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC, "bypassed": "true"})

    res = apply_static_items_sync(ROUTER, [_item(enabled=False)])["results"][0]

    assert res["access"] == "suspended" and "access suspended" in res["changes"]
    assert fake.find("/ip/hotspot/ip-binding", address=IP)[0]["disabled"] == "yes"
    assert fake.find("/ip/hotspot/host", address=IP) == []


def _host_vanishes_on_remove(fake, monkeypatch):
    """RouterOS drops a bypassed host itself once its binding is disabled, so
    the remove by the id read earlier answers "no such item" (router 602,
    2026-10-13: every suspend of an online static customer returned 503)."""
    original = fake.send_command

    def send(cmd, args=None):
        if cmd == "/ip/hotspot/host/remove":
            fake.tables["/ip/hotspot/host"] = []
            return {"success": False, "error": "no such item (4)"}
        return original(cmd, args)

    monkeypatch.setattr(fake, "send_command", send)


def test_suspend_succeeds_when_router_already_dropped_the_host(fake, monkeypatch):
    apply_static_items_sync(ROUTER, [_item()])
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC, "bypassed": "true"})
    _host_vanishes_on_remove(fake, monkeypatch)

    res = apply_static_items_sync(ROUTER, [_item(enabled=False)])["results"][0]

    assert res["success"] and res["access"] == "suspended"
    assert fake.find("/ip/hotspot/ip-binding", address=IP)[0]["disabled"] == "yes"


def test_removal_succeeds_when_router_already_dropped_the_host(fake, monkeypatch):
    apply_static_items_sync(ROUTER, [_item()])
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC})
    _host_vanishes_on_remove(fake, monkeypatch)

    result = static_ip.remove_static_ip_sync(ROUTER, IP)

    assert result.get("success")
    assert fake.find("/ip/hotspot/ip-binding", address=IP) == []


def test_suspended_customer_never_gets_a_binding_created(fake):
    res = apply_static_items_sync(ROUTER, [_item(enabled=False)])["results"][0]
    assert res["success"] and fake.find("/ip/hotspot/ip-binding", address=IP) == []


def test_other_device_on_pinned_ip_is_reported_not_repinned(fake):
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": "AA:AA:AA:AA:AA:AA"})

    res = apply_static_items_sync(ROUTER, [_item(mac=MAC)])["results"][0]

    assert res["mac_mismatch"] is True and res["pinned_mac"] == MAC
    pins = fake.find("/ip/firewall/filter", **{"src-address": IP})
    assert [p["src-mac-address"] for p in pins] == [f"!{MAC}"]


def test_clear_pin_removes_rule_and_does_not_relearn_same_pass(fake):
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC})
    apply_static_items_sync(ROUTER, [_item()])

    res = apply_static_items_sync(ROUTER, [_item(clear_pin=True)])["results"][0]

    assert "MAC pin cleared" in res["changes"] and res["pinned_mac"] is None
    assert fake.find("/ip/firewall/filter", **{"src-address": IP}) == []


def test_ip_change_tears_down_old_ip(fake):
    apply_static_items_sync(ROUTER, [_item(ip="192.168.2.30")])

    apply_static_items_sync(ROUTER, [_item(old_ip="192.168.2.30")])

    assert fake.find("/ip/hotspot/ip-binding", address="192.168.2.30") == []
    assert fake.find("/queue/simple", name="plan_static:192.168.2.30") == []
    assert fake.find("/ip/hotspot/ip-binding", address=IP)


def test_missing_gateway_is_reported(fake):
    fake.tables["/ip/address"] = [{".id": "*A1", "address": "192.168.88.1/24"}]
    assert apply_static_items_sync(ROUTER, [_item()])["results"][0]["gateway_ok"] is False


def test_speed_change_updates_queue(fake):
    apply_static_items_sync(ROUTER, [_item()])
    res = apply_static_items_sync(ROUTER, [_item(rate_limit="20M/20M")])["results"][0]
    assert fake.find("/queue/simple", name="plan_static:192.168.2.24")[0]["max-limit"] == "20M/20M"
    assert any("queue updated" in c for c in res["changes"])


def test_unreachable_router_returns_error(monkeypatch):
    def _boom(router, lane):
        raise ConnectionError("timed out")
    monkeypatch.setattr(static_ip, "_connect", _boom)
    out = apply_static_items_sync(ROUTER, [_item()])
    assert out["error"] == "timed out" and out["results"] == []


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("192.168.2.24", "192.168.2.24"), (" 192.168.2.24/32 ", "192.168.2.24"),
    ("192.168.2.0/24", None), ("999.1.1.1", None), ("", None), ("0.0.0.0", None), ("fe80::1", None),
])
def test_normalize_static_ip(raw, expected):
    assert static_ip.normalize_static_ip(raw) == expected


def test_rate_limit_is_routeros_upload_download():
    # Plans read DOWNLOAD/UPLOAD; queues want upload/download.
    assert static_ip.static_rate_limit("7M/10M") == "10M/7M"
    assert static_ip.static_rate_limit("15M") == "15M/15M"


def test_usage_key_shape():
    assert _canonical_key("static:192.168.2.24") == "static:192.168.2.24"
    assert _canonical_key("static:not-an-ip") is None


def test_pppoe_usage_key_accepts_real_usernames():
    assert _canonical_key("pppoe:house 24") == "pppoe:house 24"
    assert _canonical_key("pppoe:TELV!AN") == "pppoe:TELV!AN"
    assert _canonical_key("pppoe:Mama mishel") == "pppoe:Mama mishel"
    assert _canonical_key("pppoe:") is None
    assert _canonical_key('pppoe:bad"quote') is None
    assert _canonical_key("pppoe:bad\nline") is None
    assert _canonical_key("pppoe:" + "x" * 65) is None


# ---------------------------------------------------------------------------
# DB-backed: metering, live view, routes, enforcement
# ---------------------------------------------------------------------------

async def _seed_static(db, *, status=CustomerStatus.ACTIVE, expiry_delta=timedelta(days=5), **overrides):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP, speed="10M/10M")
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, status=status,
        expiry=datetime.utcnow() + expiry_delta if expiry_delta is not None else None,
        mac_address=None, static_ip=IP, name="dt9 FF1", **overrides,
    )
    # make_customer auto-fills a MAC when given None.
    customer.mac_address = None
    await db.commit()
    return reseller, plan, router, customer


def _token(user):
    return {"user_id": user.id, "role": user.role.value}


async def test_usage_push_credits_static_queue(db, session_factory):
    _, _, router, customer = await _seed_static(db)

    result = await ingest_usage_reports(
        router.id,
        [UsageReport(queue_key="static:192.168.2.24", upload_bytes=1000, download_bytes=5000,
                     target_ip=f"{IP}/32")],
        session_factory=session_factory,
    )

    assert result.accepted == 1, result.errors
    assert result.live_static_customers == {"static:192.168.2.24": customer.id}


async def test_pppoe_static_ip_is_not_indexed_as_static(db, session_factory):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    router = await make_router(db, reseller)
    await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                        expiry=datetime.utcnow() + timedelta(days=1), pppoe_username="joe",
                        static_ip=IP)

    result = await ingest_usage_reports(
        router.id, [UsageReport(queue_key="static:192.168.2.24", upload_bytes=1, download_bytes=1)],
        session_factory=session_factory,
    )
    assert result.accepted == 0 and "unknown_queue_key:static:192.168.2.24" in result.errors


async def test_expired_static_usage_is_not_banked(db, session_factory):
    _, _, router, _ = await _seed_static(db, expiry_delta=timedelta(minutes=-5))
    result = await ingest_usage_reports(
        router.id, [UsageReport(queue_key="static:192.168.2.24", upload_bytes=1, download_bytes=1)],
        session_factory=session_factory,
    )
    assert result.accepted == 0 and result.live_static_customers == {}


def test_live_state_static_online_by_host_and_rate_from_queue():
    t0 = datetime(2026, 10, 13, 1, 0, 0)
    queue = realtime_state.QueueSample(key="static:192.168.2.24", target_ip=IP, max_limit="10M/10M",
                                       disabled=False, upload_bytes=1_000, download_bytes=10_000)
    host = realtime_state.HostSample(mac=MAC, ip=IP, bytes_in=0, bytes_out=0, bypassed=True)
    live = {"static:192.168.2.24": 9}
    realtime_state.record_push(5, now=t0, interval_seconds=60, hosts=[host], queues=[queue],
                               live_customers={}, live_static_customers=live, has_hosts=True)
    queue2 = realtime_state.QueueSample(key="static:192.168.2.24", target_ip=IP, max_limit="10M/10M",
                                        disabled=False, upload_bytes=2_000, download_bytes=110_000)
    state = realtime_state.record_push(5, now=t0 + timedelta(seconds=10), interval_seconds=60,
                                       hosts=[host], queues=[queue2], live_customers={},
                                       live_static_customers=live, has_hosts=True)

    device = realtime_state.get_static_live(5, IP)
    assert device.online and device.kind == "static" and device.customer_id == 9
    assert device.rate_down_bps == pytest.approx(100_000 * 8 / 10)
    assert device.queue_status == realtime_state.QUEUE_OK
    assert state.orphan_queues == 0

    realtime_state.record_push(5, now=t0 + timedelta(seconds=20), interval_seconds=60, hosts=[],
                               queues=[queue2], live_customers={}, live_static_customers=live,
                               has_hosts=True)
    assert realtime_state.get_static_live(5, IP).online is False


async def test_register_static_requires_valid_unique_ip_and_moves_mac(db, monkeypatch):
    reseller, plan, router, _ = await _seed_static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))

    def _req(**kw):
        base = dict(name="New", phone="0700", plan_id=plan.id, router_id=router.id)
        base.update(kw)
        return customer_routes.CustomerRegisterRequest(**base)

    with pytest.raises(HTTPException) as bad:
        await customer_routes.register_customer_api(_req(static_ip="192.168.2.300"), db, "t")
    assert bad.value.status_code == 400
    with pytest.raises(HTTPException) as dup:
        await customer_routes.register_customer_api(_req(static_ip=IP), db, "t")
    assert dup.value.status_code == 409

    out = await customer_routes.register_customer_api(
        _req(static_ip="192.168.2.25", mac_address="aa-bb-cc-dd-ee-ff"), db, "t")
    row = await db.get(Customer, out["id"])
    assert row.static_ip == "192.168.2.25" and row.mac_address is None
    assert row.static_mac == "AA:BB:CC:DD:EE:FF"


def _user_getter(user):
    async def _get(token, db):
        return user
    return _get


async def test_activate_static_records_payment_and_provisions(db, monkeypatch):
    reseller, plan, router, customer = await _seed_static(db, status=CustomerStatus.INACTIVE,
                                                          expiry_delta=None)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    calls = []

    async def _provision(cid, **kw):
        calls.append((cid, kw))
        return {"success": True, "access": "enabled", "changes": ["access enabled"], "gateway_ok": True}

    monkeypatch.setattr(customer_routes, "provision_static_customer", _provision)

    out = await customer_routes.activate_static_customer(
        customer.id, customer_routes.ActivatePPPoERequest(payment_method="cash"), db, "t")

    assert out["provision_result"] == "ok" and calls[0][0] == customer.id
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE and customer.expiry > datetime.utcnow() + timedelta(days=29)
    payments = (await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))).scalars().all()
    assert len(payments) == 1


async def test_suspend_static_keeps_status_when_router_fails(db, monkeypatch):
    reseller, _, _, customer = await _seed_static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))

    async def _fail(cid, **kw):
        assert kw["force_enabled"] is False
        return {"error": "Failed to connect to router"}

    monkeypatch.setattr(customer_routes, "provision_static_customer", _fail)
    with pytest.raises(HTTPException) as exc:
        await customer_routes.suspend_static_customer(customer.id, db, "t")
    assert exc.value.status_code == 503
    await db.refresh(customer)
    assert customer.status == CustomerStatus.ACTIVE

    async def _ok(cid, **kw):
        return {"success": True, "access": "suspended", "changes": ["access suspended"]}

    monkeypatch.setattr(customer_routes, "provision_static_customer", _ok)
    out = await customer_routes.suspend_static_customer(customer.id, db, "t")
    assert out["status"] == "inactive"


async def test_delete_static_removes_router_access_first(db, monkeypatch):
    reseller, _, router, customer = await _seed_static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    await db.commit()
    removed = []

    async def _fail(creds, ip):
        return {"error": "Failed to connect"}

    monkeypatch.setattr(customer_routes, "remove_static_customer_from_router", _fail)
    with pytest.raises(HTTPException):
        await customer_routes.delete_customer(customer.id, db, "t")
    assert await db.get(Customer, customer.id) is not None

    async def _ok(creds, ip):
        removed.append((creds["ip"], ip))
        return {"success": True, "changes": []}

    monkeypatch.setattr(customer_routes, "remove_static_customer_from_router", _ok)
    await customer_routes.delete_customer(customer.id, db, "t")
    assert removed == [(router.ip_address, IP)]


async def test_pin_endpoint_sets_and_clears(db, monkeypatch):
    reseller, _, _, customer = await _seed_static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    seen = []

    async def _provision(cid, **kw):
        seen.append(kw)
        return {"success": True}

    monkeypatch.setattr(customer_routes, "provision_static_customer", _provision)

    await customer_routes.pin_static_customer(customer.id, customer_routes.StaticPinRequest(mac=MAC.lower()), db, "t")
    await db.refresh(customer)
    assert customer.static_mac == MAC and seen[-1]["clear_pin"] is False

    await customer_routes.pin_static_customer(customer.id, customer_routes.StaticPinRequest(mac=None), db, "t")
    await db.refresh(customer)
    assert customer.static_mac is None and seen[-1]["clear_pin"] is True

    with pytest.raises(HTTPException):
        await customer_routes.pin_static_customer(customer.id, customer_routes.StaticPinRequest(mac="zz"), db, "t")


async def test_enforcement_suspends_expired_then_marks_inactive(db, session_factory, monkeypatch):
    _, _, _, expired = await _seed_static(db, expiry_delta=timedelta(minutes=-1))
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda name: False)
    monkeypatch.setattr(static_ip, "_last_full_reconcile", {})
    applied = []

    def _apply(router, items, lane):
        applied.extend(items)
        return {"success": True, "results": [
            {"success": True, "customer_id": i.customer_id, "ip": i.ip,
             "access": "enabled" if i.enabled else "suspended", "changes": []}
            for i in items
        ]}

    monkeypatch.setattr(static_ip, "apply_static_items_sync", _apply)

    summary = await static_ip.enforce_static_ip_customers_background()

    assert summary["suspended"] == 1
    assert [i.enabled for i in applied] == [False]
    await db.refresh(expired)
    assert expired.status == CustomerStatus.INACTIVE
    logs = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.customer_id == expired.id,
        ProvisioningLog.action == "static_ip_deactivation"))).scalars().all()
    assert len(logs) == 1


async def test_enforcement_keeps_active_when_router_unreachable(db, monkeypatch):
    _, _, _, expired = await _seed_static(db, expiry_delta=timedelta(minutes=-1))
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda name: False)
    monkeypatch.setattr(static_ip, "_last_full_reconcile", {})
    monkeypatch.setattr(static_ip, "apply_static_items_sync",
                        lambda router, items, lane: {"error": "timed out", "results": []})

    await static_ip.enforce_static_ip_customers_background()

    await db.refresh(expired)
    assert expired.status == CustomerStatus.ACTIVE  # retried next tick


async def test_identityless_deactivation_leaves_static_customers_alone(db):
    _, _, _, expired = await _seed_static(db, expiry_delta=timedelta(minutes=-1))
    ids = await mikrotik_background._deactivate_expired_identityless_customers(db, datetime.utcnow())
    assert expired.id not in ids
    await db.refresh(expired)
    assert expired.status == CustomerStatus.ACTIVE


async def test_learned_pin_is_saved(db, monkeypatch):
    _, _, _, customer = await _seed_static(db)
    await static_ip._persist_apply_results(1, [
        {"success": True, "customer_id": customer.id, "ip": IP, "learned_pin": MAC, "changes": ["MAC pinned"]},
    ], "static_ip_reconcile")
    await db.refresh(customer)
    assert customer.static_mac == MAC


@pytest.mark.parametrize("command", ["/ip/hotspot/ip-binding/remove", "/ip/hotspot/host/remove"])
def test_router_rejection_prevents_successful_deletion(fake, monkeypatch, command):
    apply_static_items_sync(ROUTER, [_item()])
    fake.add("/ip/hotspot/host", {"address": IP, "mac-address": MAC})
    original = fake.send_command
    monkeypatch.setattr(fake, "send_command", lambda cmd, args=None:
                        {"success": False, "error": "router rejected removal"} if cmd == command else original(cmd, args))
    result = static_ip.remove_static_ip_sync(ROUTER, IP)
    assert not result.get("success") and "rejected" in result["error"]


def test_repairs_disabled_and_misordered_firewall_rules(fake):
    apply_static_items_sync(ROUTER, [_item(mac=MAC)])
    rules = fake.tables["/ip/firewall/filter"]
    for rule in list(rules):
        if "FastTrack" in rule.get("comment", "") or rule.get("comment", "").startswith("STATIC-PIN:"):
            rules.remove(rule)
            rules.append(rule)
            if "FastTrack" in rule.get("comment", ""):
                rule["disabled"] = "true"
    result = apply_static_items_sync(ROUTER, [_item(mac=MAC)])["results"][0]
    assert result["success"]
    rules = fake.tables["/ip/firewall/filter"]
    ft = next(i for i, r in enumerate(rules) if r["action"] == "fasttrack-connection")
    for i, rule in enumerate(rules):
        if "FastTrack" in rule.get("comment", "") or rule.get("comment", "").startswith("STATIC-PIN:"):
            assert i < ft and rule.get("disabled") != "true"


async def test_resume_preserves_expiry_and_creates_no_payment(db, monkeypatch):
    reseller, _, _, customer = await _seed_static(db, status=CustomerStatus.INACTIVE)
    expiry = customer.expiry
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    async def provision(*args, **kwargs):
        return {"success": True}
    monkeypatch.setattr(customer_routes, "provision_static_customer", provision)
    result = await customer_routes.resume_static_customer(customer.id, db, "t")
    await db.refresh(customer)
    assert result["router_result"] == "ok"
    assert customer.status == CustomerStatus.ACTIVE and customer.expiry == expiry
    assert not (await db.execute(select(CustomerPayment).where(CustomerPayment.customer_id == customer.id))).scalars().all()
    customer.expiry = datetime.utcnow() - timedelta(seconds=1)
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await customer_routes.resume_static_customer(customer.id, db, "t")
    assert exc.value.status_code == 400


async def test_failed_move_keeps_old_ip_in_billing(db, monkeypatch):
    reseller, _, _, customer = await _seed_static(db)
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    async def fail(*args):
        return {"error": "router offline"}
    monkeypatch.setattr(customer_routes, "remove_static_customer_from_router", fail)
    with pytest.raises(HTTPException) as exc:
        await customer_routes.edit_customer(customer.id, customer_routes.CustomerEditRequest(static_ip="192.168.2.99"), db, "t")
    assert exc.value.status_code == 503
    await db.refresh(customer)
    assert customer.static_ip == IP


async def test_failed_pin_reset_keeps_saved_pin(db, monkeypatch):
    reseller, _, _, customer = await _seed_static(db)
    customer.static_mac = MAC
    await db.commit()
    monkeypatch.setattr(customer_routes, "get_current_user", _user_getter(reseller))
    async def fail(*args, **kwargs):
        return {"error": "router offline"}
    monkeypatch.setattr(customer_routes, "provision_static_customer", fail)
    with pytest.raises(HTTPException) as exc:
        await customer_routes.pin_static_customer(customer.id, customer_routes.StaticPinRequest(mac=None), db, "t")
    assert exc.value.status_code == 503
    await db.refresh(customer)
    assert customer.static_mac == MAC
    with pytest.raises(HTTPException) as edit_exc:
        await customer_routes.edit_customer(customer.id, customer_routes.CustomerEditRequest(static_mac=""), db, "t")
    assert edit_exc.value.status_code == 503
    await db.refresh(customer)
    assert customer.static_mac == MAC


async def test_renewal_during_expiry_is_repaired_immediately(db, monkeypatch):
    _, _, router, customer = await _seed_static(db)
    repaired = []
    async def provision(cid, **kwargs):
        repaired.append(cid)
        return {"success": True}
    monkeypatch.setattr(static_ip, "provision_static_customer", provision)
    assert await static_ip._mark_suspended([customer.id], router.id, datetime.utcnow()) == []
    assert repaired == [customer.id]

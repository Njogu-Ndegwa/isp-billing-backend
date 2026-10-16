"""Reboot recovery must include static customers without admitting unpaid IPs."""
from datetime import datetime, timedelta

import pytest

from app.db.models import ConnectionType, CustomerStatus
from app.services import mikrotik_lb, mikrotik_lb_background, mikrotik_background
from tests.factories import make_reseller, make_router, make_plan, make_customer
from tests.test_mikrotik_lb import FakeLBAPI


IP = "172.172.10.2"


class StaticLBAPI(FakeLBAPI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bindings = [{"address": IP, "type": "bypassed", "comment": "STATIC: test (cust 7)"}]
        self.read_failure = None

    def _print(self, command):
        if command == self.read_failure:
            return {"success": False, "error": "read failed"}
        if command == "/ip/hotspot/ip-binding/print":
            return {"success": True, "data": self.bindings}
        return super()._print(command)

    def send_command(self, command, arguments=None):
        if command == "/ip/firewall/address-list/set":
            self.commands.append((command, dict(arguments)))
            row = next(a for a in self.address_lists if a[".id"] == arguments[".id"])
            row.update(arguments)
            return {"success": True}
        return super().send_command(command, arguments)


def customer(**kwargs):
    return {"id": 7, "static_ip": IP, "expiry": datetime.utcnow() + timedelta(days=2), **kwargs}


def test_reboot_recovery_without_mac_or_online_host_and_idempotency():
    api = StaticLBAPI()
    paid = customer()
    result = mikrotik_lb.lb_seed_static_paid(api, [paid])
    assert result["added"] == [IP]
    entry = api.address_lists[0]
    assert 0 < int(entry["timeout"][:-1]) <= 2 * 86400
    writes = len(api.commands)
    mikrotik_lb.lb_seed_static_paid(api, [paid])
    assert len(api.commands) == writes
    api.address_lists.clear()  # Router reboot loses timeout-bearing entries.
    assert mikrotik_lb.lb_seed_static_paid(api, [paid])["added"] == [IP]


def test_near_expiry_is_not_extended_to_minimum_hotspot_timeout():
    api = StaticLBAPI()
    mikrotik_lb.lb_seed_static_paid(api, [customer(expiry=datetime.utcnow() + timedelta(seconds=10))])
    assert 0 < int(api.address_lists[0]["timeout"][:-1]) <= 10


def test_router_worker_runs_static_recovery(monkeypatch):
    api = StaticLBAPI()
    monkeypatch.setattr(api, "connect", lambda: True)
    monkeypatch.setattr(api, "disconnect", lambda: None)
    monkeypatch.setattr("app.services.mikrotik_api.MikroTikAPI", lambda *a, **k: api)
    report = mikrotik_lb_background._seed_router_lb_paid_sync(
        {"ip": "10.0.0.1", "username": "test", "password": "test", "port": 8728}, [customer()])
    assert report["success"]
    assert report["static"]["added"] == [IP]


@pytest.mark.parametrize("fault", ["missing", "disabled", "wrong_type", "foreign", "duplicate", "unauth", "expired", "invalid_ip"])
def test_static_recovery_rejects_unproven_access(fault):
    api = StaticLBAPI()
    paid = customer()
    if fault == "missing": api.bindings.clear()
    elif fault == "disabled": api.bindings[0]["disabled"] = "true"
    elif fault == "wrong_type": api.bindings[0]["type"] = "regular"
    elif fault == "foreign": api.bindings[0]["comment"] = "STATIC: test (cust 77)"
    elif fault == "duplicate": api.bindings.append(dict(api.bindings[0]))
    elif fault == "unauth": api.hotspot_hosts = [{"address": IP, "bypassed": "false"}]
    elif fault == "expired": paid["expiry"] = datetime.utcnow() - timedelta(seconds=1)
    elif fault == "invalid_ip": paid["static_ip"] = "172.172.10.0/24"
    result = mikrotik_lb.lb_seed_static_paid(api, [paid])
    assert not result["added"]
    assert not api.commands


def test_renewal_and_shortened_expiry_refresh_timeout():
    api = StaticLBAPI()
    paid = customer()
    mikrotik_lb.lb_seed_static_paid(api, [paid])
    paid["expiry"] += timedelta(days=10)
    assert mikrotik_lb.lb_seed_static_paid(api, [paid])["updated"] == [IP]
    assert int(api.address_lists[0]["timeout"][:-1]) > 11 * 86400
    paid["expiry"] = datetime.utcnow() + timedelta(hours=1)
    assert mikrotik_lb.lb_seed_static_paid(api, [paid])["updated"] == [IP]
    assert int(api.address_lists[0]["timeout"][:-1]) <= 3600


def test_cleanup_only_removes_owned_static_entries():
    api = StaticLBAPI(address_lists=[
        {".id": "*old", "list": "LB_PAID", "address": IP, "comment": "ISP_BILLING_STATIC_PAID:7", "timeout": "1h"},
        {".id": "*hot", "list": "LB_PAID", "address": "172.172.10.3", "comment": "PAID:AA", "timeout": "1h"},
    ])
    result = mikrotik_lb.lb_seed_static_paid(api, [])
    assert result["removed"] == [IP]
    assert [e[".id"] for e in api.address_lists] == ["*hot"]


@pytest.mark.parametrize("path", ["/ip/hotspot/ip-binding/print", "/ip/hotspot/host/print", "/ip/firewall/address-list/print"])
def test_failed_read_never_mutates_router(path):
    api = StaticLBAPI()
    api.read_failure = path
    assert not mikrotik_lb.lb_seed_static_paid(api, [customer()])["success"]
    assert not api.commands


@pytest.mark.asyncio
async def test_reconciler_selects_active_static_without_mac_and_respects_grace(db, monkeypatch):
    owner = await make_reseller(db)
    router = await make_router(db, owner, lb_enabled=True)
    plan = await make_plan(db, owner, connection_type=ConnectionType.STATIC_IP)
    now = datetime.utcnow()
    active = await make_customer(db, owner, plan, router, mac_address=None, static_ip=IP,
                                 status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=1))
    grace = await make_customer(db, owner, plan, router, mac_address=None, static_ip="172.172.10.3",
                                status=CustomerStatus.ACTIVE, expiry=now - timedelta(minutes=5), grace_period_minutes=60)
    await make_customer(db, owner, plan, router, mac_address=None, static_ip="172.172.10.4",
                        status=CustomerStatus.INACTIVE, expiry=now + timedelta(days=1))
    await make_customer(db, owner, plan, router, mac_address=None, static_ip="172.172.10.5",
                        status=CustomerStatus.ACTIVE, expiry=now - timedelta(days=1))
    hotspot = await make_plan(db, owner)
    hot = await make_customer(db, owner, hotspot, router, status=CustomerStatus.ACTIVE, expiry=now + timedelta(days=1))
    seen = []
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _: False)
    monkeypatch.setattr(mikrotik_background, "_router_recently_offline", lambda *_: False)
    def seed(info, customers):
        seen.extend(customers)
        return {"success": True, "added": []}
    monkeypatch.setattr(mikrotik_lb_background, "_seed_router_lb_paid_sync", seed)
    await mikrotik_lb_background.reconcile_lb_paid_background()
    assert {c["id"] for c in seen if c.get("static_ip")} == {active.id, grace.id}
    assert next(c for c in seen if c.get("id") == grace.id)["expiry"] == grace.expiry + timedelta(minutes=60)
    assert any(c.get("mac") == hot.mac_address.upper() for c in seen)

"""LB_PAID lifecycle hook tests.

CREATE: hotspot bypass provisioning adds the client to LB_PAID — but only when
the router has LB enabled, and never at the cost of provisioning itself.
EXPIRE: the expired-customer cleanup removes the LB_PAID entry alongside the
ip-binding — and never at the cost of the cleanup itself.
Uses the monkeypatch idiom from tests/test_expired_hotspot_cleanup.py.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import CustomerStatus
from app.services import hotspot_provisioning, mikrotik_background
from app.services.hotspot_provisioning import (
    _call_mikrotik_bypass_sync,
    build_hotspot_payload,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router

MAC = "AA:BB:CC:DD:EE:20"
CLIENT_IP = "192.168.88.77"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeProvisionAPI:
    """Just enough MikroTikAPI surface for _call_mikrotik_bypass_sync."""

    def __init__(self, *, fail_lb_add=False, hosts=None):
        self.commands = []
        self.fail_lb_add = fail_lb_add
        self.hosts = hosts if hosts is not None else [
            {"mac-address": MAC, "address": CLIENT_IP, "bypassed": "true"},
        ]

    def connect(self):
        return True

    def disconnect(self):
        pass

    def add_customer_bypass_mode(self, *args, **kwargs):
        return {"success": True}

    def get_hotspot_user_by_name(self, username):
        return {"success": True, "found": True, "data": {"name": username}}

    def get_ip_binding_by_mac(self, mac):
        return {"success": True, "found": True, "data": {"type": "bypassed"}}

    def get_online_state_by_mac(self, mac):
        return {"success": True, "online": True, "source": "host", "details": None}

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/ip/hotspot/host/print":
            return {"success": True, "data": list(self.hosts)}
        if command == "/ip/firewall/address-list/print":
            return {"success": True, "data": []}
        return {"success": True, "data": []}

    def send_command(self, command, arguments=None):
        self.commands.append((command, dict(arguments or {})))
        if self.fail_lb_add and command == "/ip/firewall/address-list/add":
            return {"error": "router said no"}
        return {"success": True, "data": []}


def _payload(lb_enabled, expiry=None):
    return {
        "mac_address": MAC,
        "username": MAC.replace(":", ""),
        "password": MAC.replace(":", ""),
        "time_limit": "1d",
        "bandwidth_limit": "5M/5M",
        "comment": "test",
        "router_ip": "10.0.0.99",
        "router_username": "admin",
        "router_password": "pw",
        "router_port": 8728,
        "lb_enabled": lb_enabled,
        "customer_expiry": expiry,
    }


def _lb_adds(api):
    return [args for cmd, args in api.commands
            if cmd == "/ip/firewall/address-list/add"
            and args.get("list") == "LB_PAID"]


class FakeCleanupAPI:
    """Just enough MikroTikAPI surface for _cleanup_single_router_hotspot_sync."""

    def __init__(self, *, fail_lb_remove=False):
        self.commands = []
        self.fail_lb_remove = fail_lb_remove
        self.bindings = [
            {".id": "*B1", "mac-address": MAC, "type": "bypassed",
             "comment": f"USER:{MAC.replace(':', '')}"},
        ]
        self.lb_paid = [
            {".id": "*L1", "list": "LB_PAID", "address": CLIENT_IP},
        ]

    def connect(self):
        return True

    def disconnect(self):
        pass

    def get_client_ip_by_mac(self, mac):
        return CLIENT_IP

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/ip/firewall/address-list/print":
            return {"success": True, "data": list(self.lb_paid)}
        return {"success": True, "data": []}

    def send_command(self, command, arguments=None):
        args = dict(arguments or {})
        self.commands.append((command, args))
        if command == "/ip/hotspot/ip-binding/print":
            return {"success": True, "data": list(self.bindings)}
        if command == "/ip/hotspot/ip-binding/remove":
            self.bindings = [b for b in self.bindings
                             if b.get(".id") != args.get("numbers")]
            return {"success": True, "data": []}
        if command == "/ip/firewall/address-list/remove":
            if self.fail_lb_remove:
                return {"error": "router said no"}
            self.lb_paid = [e for e in self.lb_paid
                            if e.get(".id") != args.get(".id")]
            return {"success": True, "data": []}
        if command.endswith("/print"):
            return {"success": True, "data": []}
        return {"success": True, "data": []}


# ---------------------------------------------------------------------------
# CREATE hook (provisioning)
# ---------------------------------------------------------------------------

def test_provisioning_adds_lb_paid_when_lb_enabled(monkeypatch):
    api = FakeProvisionAPI()
    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI",
                        lambda *a, **k: api)

    expiry = datetime.utcnow() + timedelta(days=2)
    result = _call_mikrotik_bypass_sync(_payload(lb_enabled=True, expiry=expiry))

    assert result["success"] is True
    adds = _lb_adds(api)
    assert len(adds) == 1
    assert adds[0]["address"] == CLIENT_IP
    assert adds[0]["timeout"].endswith("s")
    secs = int(adds[0]["timeout"][:-1])
    assert 60 <= secs <= 21_000_000
    assert result["lb_paid_result"]["ok"] is True


def test_provisioning_skips_lb_paid_when_lb_disabled(monkeypatch):
    api = FakeProvisionAPI()
    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI",
                        lambda *a, **k: api)

    result = _call_mikrotik_bypass_sync(
        _payload(lb_enabled=False, expiry=datetime.utcnow() + timedelta(days=2))
    )

    assert result["success"] is True
    assert _lb_adds(api) == []
    assert result["lb_paid_result"] is None


def test_provisioning_succeeds_even_when_lb_paid_add_fails(monkeypatch):
    api = FakeProvisionAPI(fail_lb_add=True)
    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI",
                        lambda *a, **k: api)

    result = _call_mikrotik_bypass_sync(
        _payload(lb_enabled=True, expiry=datetime.utcnow() + timedelta(days=2))
    )

    assert result["success"] is True  # provisioning must not fail over LB_PAID
    assert result["lb_paid_result"]["ok"] is False


def test_provisioning_succeeds_when_lb_paid_helper_crashes(monkeypatch):
    api = FakeProvisionAPI()
    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI",
                        lambda *a, **k: api)

    def boom(*_a, **_k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("app.services.mikrotik_lb.lb_add_paid_entry", boom)
    result = _call_mikrotik_bypass_sync(
        _payload(lb_enabled=True, expiry=datetime.utcnow() + timedelta(days=2))
    )
    assert result["success"] is True


def test_provisioning_skips_lb_paid_without_expiry(monkeypatch):
    api = FakeProvisionAPI()
    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI",
                        lambda *a, **k: api)

    result = _call_mikrotik_bypass_sync(_payload(lb_enabled=True, expiry=None))

    assert result["success"] is True
    assert _lb_adds(api) == []  # no timeout derivable -> no entry (rule 6)
    assert result["lb_paid_result"]["ok"] is False


@pytest.mark.asyncio
async def test_build_hotspot_payload_threads_lb_flag_and_expiry(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller, lb_enabled=True)
    expiry = datetime.utcnow() + timedelta(days=1)
    customer = await make_customer(
        db, reseller, plan, router, mac_address=MAC, expiry=expiry,
    )

    payload = build_hotspot_payload(customer, plan, router, comment="c")
    assert payload["lb_enabled"] is True
    assert payload["customer_expiry"] == expiry

    router.lb_enabled = False
    payload = build_hotspot_payload(customer, plan, router, comment="c")
    assert payload["lb_enabled"] is False


# ---------------------------------------------------------------------------
# EXPIRE hook (cleanup)
# ---------------------------------------------------------------------------

def _cleanup_router_info(lb_enabled):
    return {
        "id": 1, "name": "Router-1", "ip": "10.0.0.99",
        "username": "admin", "password": "pw", "port": 8728,
        "lb_enabled": lb_enabled,
    }


def _cleanup_customers():
    return [{"id": 1, "name": "Cust", "mac_address": MAC,
             "expiry": datetime.utcnow() - timedelta(hours=1), "router_id": 1}]


def test_cleanup_removes_lb_paid_entry_when_lb_enabled(monkeypatch):
    api = FakeCleanupAPI()
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)

    results = mikrotik_background._cleanup_single_router_hotspot_sync(
        _cleanup_router_info(lb_enabled=True), _cleanup_customers(),
    )

    assert [r["id"] for r in results["removed"]] == [1]
    removes = [args for cmd, args in api.commands
               if cmd == "/ip/firewall/address-list/remove"]
    assert removes == [{".id": "*L1"}]
    assert api.lb_paid == []
    assert results["removed"][0]["details"]["lb_paid"] == 1


def test_cleanup_leaves_lb_paid_alone_when_lb_disabled(monkeypatch):
    api = FakeCleanupAPI()
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)

    results = mikrotik_background._cleanup_single_router_hotspot_sync(
        _cleanup_router_info(lb_enabled=False), _cleanup_customers(),
    )

    assert [r["id"] for r in results["removed"]] == [1]
    assert not any(cmd == "/ip/firewall/address-list/remove"
                   for cmd, _ in api.commands)
    assert api.lb_paid  # untouched


def test_cleanup_survives_lb_paid_removal_failure(monkeypatch):
    api = FakeCleanupAPI(fail_lb_remove=True)
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)

    results = mikrotik_background._cleanup_single_router_hotspot_sync(
        _cleanup_router_info(lb_enabled=True), _cleanup_customers(),
    )

    # the binding removal (the thing that gates access) still succeeded
    assert [r["id"] for r in results["removed"]] == [1]
    assert results["failed"] == []


def test_cleanup_survives_lb_paid_helper_crash(monkeypatch):
    api = FakeCleanupAPI()
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)

    def boom(*_a, **_k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("app.services.mikrotik_lb.lb_remove_paid_entry", boom)
    results = mikrotik_background._cleanup_single_router_hotspot_sync(
        _cleanup_router_info(lb_enabled=True), _cleanup_customers(),
    )
    assert [r["id"] for r in results["removed"]] == [1]


# ---------------------------------------------------------------------------
# The background cleanup threads lb_enabled into router_info
# ---------------------------------------------------------------------------

async def _async_zero(*_args, **_kwargs):
    return 0


async def _async_none(*_args, **_kwargs):
    return None


@pytest.mark.asyncio
async def test_expired_cleanup_passes_lb_enabled_to_router_info(
    db, session_factory, monkeypatch,
):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy",
                        lambda _job: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers",
                        _async_zero)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials",
                        _async_zero)
    monkeypatch.setattr(mikrotik_background, "record_router_availability",
                        _async_none)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller, lb_enabled=True)
    await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.ACTIVE,
        expiry=datetime.utcnow() - timedelta(hours=2),
        mac_address="AA:BB:CC:DD:EE:21",
    )

    seen_router_infos = []

    def fake_router_cleanup(router_info, customers_data):
        seen_router_infos.append(router_info)
        return {
            "removed": [{"id": c["id"], "details": {}} for c in customers_data],
            "failed": [],
            "connected": True,
        }

    monkeypatch.setattr(mikrotik_background, "_cleanup_single_router_hotspot_sync",
                        fake_router_cleanup)

    await mikrotik_background.cleanup_expired_users_background()

    assert len(seen_router_infos) == 1
    assert seen_router_infos[0]["lb_enabled"] is True

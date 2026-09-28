"""Hotspot MAC-login pilot: router-side behaviour against a fake RouterOS."""

import itertools
import time

import pytest

from app.services import checkin_delivery, hotspot_mac_login as ml, hotspot_provisioning, mikrotik_background
from app.services.mikrotik_api import MikroTikAPI

MAC = "AA:BB:CC:DD:EE:01"
OTHER = "AA:BB:CC:DD:EE:02"


class FakeRouter:
    """Just enough RouterOS for the MAC-login code paths."""

    def __init__(self, *, fasttrack=True):
        self._ids = itertools.count(1)
        self.tables = {
            "/ip/hotspot": [self._row(name="hotspot1", interface="bridge", profile="hsprof1", disabled="false")],
            "/ip/hotspot/profile": [self._row(name="hsprof1", **{"login-by": "cookie,http-chap"})],
            "/ip/hotspot/user/profile": [self._row(name="default")],
            "/ip/hotspot/user": [],
            "/ip/hotspot/ip-binding": [],
            "/ip/hotspot/active": [],
            "/ip/hotspot/host": [],
            "/queue/simple": [],
            "/interface/list": [self._row(name="LAN")],
            "/interface/list/member": [],
            "/ip/firewall/filter": [
                self._row(chain="forward", action="accept", comment="defconf: accept in ipsec policy"),
            ],
            "/ip/firewall/connection": [],
        }
        if fasttrack:
            self.tables["/ip/firewall/filter"].append(self._row(
                chain="forward", action="fasttrack-connection", comment="defconf: fasttrack",
                **{"connection-state": "established,related"}))
            self.tables["/ip/firewall/filter"].append(self._row(
                chain="forward", action="accept", comment="defconf: accept established,related"))
        self.writes = []

    def _row(self, **fields):
        return {".id": f"*{next(self._ids)}", **fields}

    def api(self):
        api = MikroTikAPI.__new__(MikroTikAPI)
        api.connected = True
        api.send_command = self.send_command
        api.send_command_optimized = lambda path, proplist=None, query=None: self.send_command(path)
        return api

    def send_command(self, path, args=None):
        args = dict(args or {})
        base, _, verb = path.rpartition("/")
        table = self.tables.get(base)
        if table is None:
            raise AssertionError(f"unexpected command {path}")
        if verb == "print":
            return {"success": True, "data": [dict(r) for r in table]}
        self.writes.append((path, args))
        if verb == "add":
            place_before = args.pop("place-before", None)
            row = self._row(**args)
            if place_before:
                index = next(i for i, r in enumerate(table) if r[".id"] == place_before)
                table.insert(index, row)
            else:
                table.append(row)
            return {"success": True, "data": [{"ret": row[".id"]}]}
        row = self._find(table, args.get("numbers"))
        if verb == "set":
            row.update({k: v for k, v in args.items() if k != "numbers"})
        elif verb == "remove":
            table.remove(row)
        elif verb == "move":
            table.remove(row)
            index = next(i for i, r in enumerate(table) if r[".id"] == args["destination"])
            table.insert(index, row)
        elif verb == "enable":
            row["disabled"] = "false"
        else:
            raise AssertionError(f"unexpected verb {path}")
        return {"success": True}

    @staticmethod
    def _find(table, key):
        for r in table:
            if r[".id"] == key or r.get("name") == key:
                return r
        raise AssertionError(f"no row {key}")

    def user(self, name):
        return next((u for u in self.tables["/ip/hotspot/user"] if u.get("name") == name), None)

    def filter_comments(self):
        return [r.get("comment") for r in self.tables["/ip/firewall/filter"]]


def _bypass_customer(router, mac):
    compact = mac.replace(":", "")
    router.tables["/ip/hotspot/ip-binding"].append(router._row(
        **{"mac-address": mac, "type": "bypassed", "comment": f"USER:{compact}|EXPIRES:DB_MANAGED"}))
    router.tables["/queue/simple"].append(router._row(
        name=f"plan_{compact}", target="192.168.88.10/32", dynamic="false",
        comment=f"MAC:{mac}|Plan rate limit", **{"max-limit": "5000000/5000000"}))
    router.tables["/ip/hotspot/host"].append(router._row(
        **{"mac-address": mac, "address": "192.168.88.10", "bypassed": "true"}))


# ---------------------------------------------------------------- helpers

def test_router_ids_parse_and_enable(monkeypatch):
    monkeypatch.setattr(ml.settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", " 10, 47 ,x,")
    assert ml.mac_login_router_ids() == frozenset({10, 47})
    assert ml.mac_login_enabled(10) and ml.mac_login_enabled("47")
    assert not ml.mac_login_enabled(11) and not ml.mac_login_enabled(None)


def test_user_matcher_covers_both_eras_and_nothing_else():
    assert ml.hotspot_user_is_for_mac({"name": "AABBCCDDEE01"}, MAC)
    assert ml.hotspot_user_is_for_mac({"name": "aa:bb:cc:dd:ee:01"}, MAC)
    assert ml.hotspot_user_is_for_mac({"name": "x", "comment": f"MACLOGIN|MAC:{MAC}|T:1"}, MAC)
    assert not ml.hotspot_user_is_for_mac({"name": "AABBCCDDEE02"}, MAC)
    assert not ml.hotspot_user_is_for_mac({"name": "voucher123", "comment": "Payment successful"}, MAC)


# ---------------------------------------------------------------- setup

def test_setup_enables_mac_login_and_exempts_hotspot_from_fasttrack():
    router = FakeRouter()
    result = ml.ensure_router_setup(router.api())

    assert result["success"], result
    assert router.tables["/ip/hotspot/profile"][0]["login-by"] == "cookie,http-chap,mac"
    assert any(m["list"] == ml.HOTSPOT_CLIENT_IFACE_LIST and m["interface"] == "bridge"
               for m in router.tables["/interface/list/member"])
    comments = router.filter_comments()
    fasttrack_at = comments.index("defconf: fasttrack")
    assert comments.index(ml.NO_FASTTRACK_IN_COMMENT) < fasttrack_at
    assert comments.index(ml.NO_FASTTRACK_OUT_COMMENT) < fasttrack_at
    rule = next(r for r in router.tables["/ip/firewall/filter"] if r.get("comment") == ml.NO_FASTTRACK_IN_COMMENT)
    assert rule["connection-state"] == "established,related"
    assert rule["in-interface-list"] == ml.HOTSPOT_CLIENT_IFACE_LIST


def test_setup_is_idempotent_and_never_removes_its_rules():
    router = FakeRouter()
    ml.ensure_router_setup(router.api())
    router.writes.clear()

    ml.ensure_router_setup(router.api())

    assert router.writes == []


def test_setup_moves_a_rule_that_ended_up_after_fasttrack():
    router = FakeRouter()
    ml.ensure_router_setup(router.api())
    filters = router.tables["/ip/firewall/filter"]
    rule = next(r for r in filters if r.get("comment") == ml.NO_FASTTRACK_OUT_COMMENT)
    filters.remove(rule)
    filters.append(rule)
    router.writes.clear()

    ml.ensure_router_setup(router.api())

    assert [w[0] for w in router.writes] == ["/ip/firewall/filter/move"]
    comments = router.filter_comments()
    assert comments.index(ml.NO_FASTTRACK_OUT_COMMENT) < comments.index("defconf: fasttrack")


def test_setup_without_fasttrack_adds_no_rules():
    router = FakeRouter(fasttrack=False)
    result = ml.ensure_router_setup(router.api())
    assert result["fasttrack"]["fasttrack_enabled"] is False
    assert ml.NO_FASTTRACK_IN_COMMENT not in router.filter_comments()


# ---------------------------------------------------------------- provision

def test_provision_replaces_bypass_with_mac_login_user():
    router = FakeRouter()
    _bypass_customer(router, MAC)
    _bypass_customer(router, OTHER)
    router.tables["/ip/hotspot/active"].append(router._row(**{"mac-address": MAC, "user": "x"}))

    result = ml.provision_customer(router.api(), MAC, "5M/5M", note="Payment successful for Guest 1")

    assert result["success"], result
    assert hotspot_provisioning._extract_provisioning_error(result) is None
    user = router.user(MAC)
    assert user["profile"] == "plan_5M_5M"
    assert user["mac-address"] == MAC and user["password"] == ""
    assert user["comment"].startswith(f"MACLOGIN|MAC:{MAC}|T:")
    assert any(p["name"] == "plan_5M_5M" and p["rate-limit"] == "5M/5M"
               for p in router.tables["/ip/hotspot/user/profile"])
    # this MAC's bypass-era access is gone; the other customer's is untouched
    assert [b["mac-address"] for b in router.tables["/ip/hotspot/ip-binding"]] == [OTHER]
    assert [q["name"] for q in router.tables["/queue/simple"]] == ["plan_AABBCCDDEE02"]
    assert result["kick_result"] == {"sessions_removed": 1, "hosts_removed": 1}
    assert [h["mac-address"] for h in router.tables["/ip/hotspot/host"]] == [OTHER]


def test_provision_keeps_a_resellers_blocked_binding():
    router = FakeRouter()
    router.tables["/ip/hotspot/ip-binding"].append(router._row(**{"mac-address": MAC, "type": "blocked"}))
    ml.provision_customer(router.api(), MAC, "5M/5M")
    assert router.tables["/ip/hotspot/ip-binding"][0]["type"] == "blocked"


def test_provision_updates_an_existing_user_in_place():
    router = FakeRouter()
    router.tables["/ip/hotspot/user"].append(router._row(
        name=MAC, profile="plan_2M_2M", disabled="true", comment="MACLOGIN|MAC:x|T:1"))

    result = ml.provision_customer(router.api(), MAC, "10M/5M")

    assert result["success"], result
    assert len(router.tables["/ip/hotspot/user"]) == 1
    user = router.user(MAC)
    assert user["profile"] == "plan_10M_5M"
    assert user["disabled"] == "no" and user["limit-uptime"] == "0s"


def test_verify_requires_the_user_not_a_binding():
    router = FakeRouter()
    payload = {"mac_login": True, "mac_address": MAC, "username": "AABBCCDDEE01"}
    assert hotspot_provisioning._verify_hotspot_configuration(router.api(), payload).get("error")
    ml.provision_customer(router.api(), MAC, "5M/5M")
    assert hotspot_provisioning._verify_hotspot_configuration(router.api(), payload)["success"]


def test_payment_executor_uses_mac_login_on_pilot_routers(monkeypatch):
    router = FakeRouter()
    _bypass_customer(router, MAC)

    class Api:
        def __new__(cls, *args, **kwargs):
            api = router.api()
            api.connect = lambda: True
            api.disconnect = lambda: None
            return api

    monkeypatch.setattr(hotspot_provisioning, "MikroTikAPI", Api)
    monkeypatch.setattr(hotspot_provisioning, "_poll_online_state",
                        lambda api, mac: {"success": True, "online": True})
    payload = {
        "mac_address": MAC, "username": "AABBCCDDEE01", "password": "AABBCCDDEE01",
        "time_limit": "1d", "bandwidth_limit": "5M/5M", "comment": "Payment",
        "router_ip": "10.0.0.5", "router_username": "u", "router_password": "p", "router_port": 8728,
        "lb_enabled": False, "customer_expiry": None, "router_id": 10, "mac_login": True,
    }

    result = hotspot_provisioning._call_mikrotik_bypass_sync(payload)

    assert result["success"], result
    assert router.user(MAC)["profile"] == "plan_5M_5M"
    assert router.tables["/ip/hotspot/ip-binding"] == []


# ---------------------------------------------------------------- reconcile

def test_reconcile_provisions_missing_and_removes_unpaid(monkeypatch):
    router = FakeRouter()
    now = time.time()
    old = int(now - ml.ORPHAN_GRACE_SECONDS - 60)
    young = int(now - 60)
    users = router.tables["/ip/hotspot/user"]
    users.append(router._row(name=OTHER, profile="plan_5M_5M", comment=f"MACLOGIN|MAC:{OTHER}|T:{old}"))
    users.append(router._row(name="AA:BB:CC:DD:EE:03", profile="plan_5M_5M",
                             comment=f"MACLOGIN|MAC:AA:BB:CC:DD:EE:03|T:{young}"))
    users.append(router._row(name="voucher1", profile="plan_5M_5M", comment="voucher"))
    router.tables["/ip/hotspot/active"].append(router._row(**{"mac-address": OTHER, "user": OTHER}))

    summary = ml.reconcile_router(router.api(), [{"mac_address": MAC, "plan_speed": "5M/5M"}], now=now)

    assert summary["provisioned"] == 1 and summary["orphans_removed"] == 1, summary
    names = [u["name"] for u in router.tables["/ip/hotspot/user"]]
    assert MAC in names
    assert OTHER not in names                    # unpaid and old: gone
    assert "AA:BB:CC:DD:EE:03" in names          # inside the payment grace
    assert "voucher1" in names                   # not ours
    assert router.tables["/ip/hotspot/active"] == []


def test_reconcile_leaves_healthy_users_alone():
    router = FakeRouter()
    ml.ensure_router_setup(router.api())
    ml.provision_customer(router.api(), MAC, "5M/5M")
    router.writes.clear()

    summary = ml.reconcile_router(router.api(), [{"mac_address": MAC, "plan_speed": "5M/5M"}])

    assert summary["already_ok"] == 1 and summary["provisioned"] == 0
    assert router.writes == []


def test_reconcile_applies_fup_throttle_but_not_over_a_block():
    router = FakeRouter()
    ml.provision_customer(router.api(), MAC, "5M/5M")
    ml.provision_customer(router.api(), OTHER, "5M/5M")
    ml.block_customer(router.api(), OTHER)

    ml.reconcile_router(router.api(), [
        {"mac_address": MAC, "plan_speed": "1M/1M", "fup_action": "throttle"},
        {"mac_address": OTHER, "plan_speed": "5M/5M", "fup_action": "block"},
    ])

    assert router.user(MAC)["profile"] == "plan_1M_1M"
    assert router.user(OTHER)["disabled"] == "yes"


def test_reconcile_leaves_unconverted_bypass_customers_to_the_convert_script():
    router = FakeRouter()
    _bypass_customer(router, MAC)

    summary = ml.reconcile_router(router.api(), [{"mac_address": MAC, "plan_speed": "5M/5M"}])

    assert summary["on_bypass"] == 1 and summary["provisioned"] == 0
    assert router.user(MAC) is None
    assert len(router.tables["/ip/hotspot/ip-binding"]) == 1


def test_reconcile_reconverts_a_customer_whose_binding_came_back():
    router = FakeRouter()
    ml.provision_customer(router.api(), MAC, "5M/5M")
    _bypass_customer(router, MAC)  # e.g. another path re-added a binding

    summary = ml.reconcile_router(router.api(), [{"mac_address": MAC, "plan_speed": "5M/5M"}])

    assert summary["provisioned"] == 1
    assert router.tables["/ip/hotspot/ip-binding"] == []


# ---------------------------------------------------------------- wiring

def test_background_sync_routes_mac_login_routers_to_reconcile(monkeypatch):
    monkeypatch.setattr(ml.settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", "10")
    called = {}

    def fake_reconcile(router_info, customers):
        called["router"] = router_info["id"]
        return {"synced": 0, "errors": 0, "skipped": 0, "routers_connected": 1, "details": None}

    monkeypatch.setattr(mikrotik_background, "_reconcile_mac_login_router_sync", fake_reconcile)
    info = {"id": 10, "name": "r", "ip": "10.0.0.5", "username": "u", "password": "p", "port": 8728}
    mikrotik_background._sync_single_router_queues_sync(info, [{"mac_address": MAC, "plan_speed": "5M/5M"}])
    assert called == {"router": 10}


def test_checkin_never_sends_add_lines_to_mac_login_routers(monkeypatch):
    monkeypatch.setattr(ml.settings, "HOTSPOT_MAC_LOGIN_ROUTER_IDS", "10")
    assert checkin_delivery.delivery_mode(10) == checkin_delivery.DELIVERY_PUSH_ONLY
    assert checkin_delivery.delivery_mode(11) != checkin_delivery.DELIVERY_PUSH_ONLY


def test_expiry_cleanup_removes_mac_login_user_and_session():
    router = FakeRouter()
    ml.provision_customer(router.api(), MAC, "5M/5M")
    router.tables["/ip/hotspot/active"].append(router._row(**{"mac-address": MAC, "user": MAC}))
    for table in ("/ip/arp", "/ip/dhcp-server/lease"):
        router.tables[table] = []

    class Api:
        def __new__(cls, *args, **kwargs):
            api = router.api()
            api.connect = lambda: True
            api.disconnect = lambda: None
            return api

    original = mikrotik_background.MikroTikAPI
    mikrotik_background.MikroTikAPI = Api
    try:
        result = mikrotik_background._cleanup_single_router_hotspot_sync(
            {"id": 10, "name": "r", "ip": "10.0.0.5", "username": "u", "password": "p", "port": 8728},
            [{"id": 1, "name": "c", "mac_address": MAC}],
        )
    finally:
        mikrotik_background.MikroTikAPI = original

    assert [r["id"] for r in result["removed"]] == [1]
    assert router.user(MAC) is None
    assert router.tables["/ip/hotspot/active"] == []

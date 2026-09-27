"""Expiry removal speed: one table read per router, its own lane, and the
safety-net scan moved off the removal job (2026-09-25: the scan paused removals
for 5-6 min out of every ~10, and each customer cost ~10 full-table reads)."""
import asyncio
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.services import mikrotik_background

MACS = ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"]


class FakeRouter:
    """A router whose tables hold one binding/host/queue per expired MAC."""

    def __init__(self, macs, *, sticky_binding=None, bindings_fail=False,
                 shared_host_ip=None):
        self.calls = []
        self.bindings_fail = bindings_fail
        self.sticky_binding = sticky_binding  # this binding id survives removal
        self.tables = {
            "/ip/hotspot/ip-binding": [
                {".id": f"*B{i}", "mac-address": m, "type": "bypassed",
                 "comment": f"USER:{m.replace(':', '')}"} for i, m in enumerate(macs)],
            "/ip/hotspot/host": [
                {".id": f"*H{i}", "mac-address": m, "address": f"192.168.88.{10 + i}"}
                for i, m in enumerate(macs)],
            "/queue/simple": [
                {".id": f"*Q{i}", "name": f"plan_{m.replace(':', '')}", "comment": ""}
                for i, m in enumerate(macs)],
        }
        if shared_host_ip:
            for h in self.tables["/ip/hotspot/host"]:
                h["address"] = shared_host_ip

    def connect(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, command, arguments=None):
        self.calls.append((command, dict(arguments or {})))
        table, _, verb = command.rpartition("/")
        if verb == "print":
            if table == "/ip/hotspot/ip-binding" and self.bindings_fail:
                return {"error": "timeout"}
            return {"success": True, "data": list(self.tables.get(table, []))}
        if verb == "remove":
            entry_id = (arguments or {}).get("numbers")
            if entry_id == self.sticky_binding:
                # says ok the first time but the binding stays; the retry errors
                if self.removes(table).count(entry_id) > 1:
                    return {"error": "failure: item is busy"}
                return {"success": True, "data": []}
            self.tables[table] = [e for e in self.tables.get(table, []) if e[".id"] != entry_id]
            return {"success": True, "data": []}
        return {"success": True, "data": []}

    def prints(self):
        return Counter(c for c, _ in self.calls if c.endswith("/print"))

    def removes(self, table):
        return [a["numbers"] for c, a in self.calls if c == f"{table}/remove"]


def _run(monkeypatch, api, macs=MACS):
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", lambda *a, **k: api)
    router = {"id": 1, "name": "R1", "ip": "10.0.0.9", "username": "u",
              "password": "p", "port": 8728, "lb_enabled": False}
    customers = [{"id": i + 1, "name": f"C{i + 1}", "mac_address": m,
                  "expiry": datetime.utcnow() - timedelta(minutes=5), "router_id": 1}
                 for i, m in enumerate(macs)]
    return mikrotik_background._cleanup_single_router_hotspot_sync(router, customers)


def test_each_table_is_read_once_per_router_not_once_per_customer(monkeypatch):
    api = FakeRouter(MACS)
    results = _run(monkeypatch, api)

    assert sorted(r["id"] for r in results["removed"]) == [1, 2, 3]
    assert results["failed"] == []
    prints = api.prints()
    # 7 snapshot reads + 1 verification read of the bindings, for 3 customers
    assert sum(prints.values()) == 8
    assert prints["/ip/hotspot/ip-binding/print"] == 2
    assert all(n == 1 for cmd, n in prints.items() if cmd != "/ip/hotspot/ip-binding/print")
    assert sorted(api.removes("/ip/hotspot/ip-binding")) == ["*B0", "*B1", "*B2"]
    assert sorted(api.removes("/queue/simple")) == ["*Q0", "*Q1", "*Q2"]
    assert api.tables["/ip/hotspot/ip-binding"] == []


def test_binding_that_survives_removal_and_retry_keeps_customer_active(monkeypatch):
    api = FakeRouter(MACS[:2], sticky_binding="*B0")
    results = _run(monkeypatch, api, macs=MACS[:2])

    assert [r["id"] for r in results["removed"]] == [2]
    assert [f["id"] for f in results["failed"]] == [1]
    assert "may still have access" in results["failed"][0]["error"]
    # removed, still there on verification, removed once more
    assert api.removes("/ip/hotspot/ip-binding").count("*B0") == 2


def test_unreadable_bindings_fail_every_customer_on_the_router(monkeypatch):
    api = FakeRouter(MACS, bindings_fail=True)
    results = _run(monkeypatch, api)

    assert results["removed"] == []
    assert sorted(f["id"] for f in results["failed"]) == [1, 2, 3]


def test_customer_without_binding_counts_as_already_removed(monkeypatch):
    api = FakeRouter([])
    results = _run(monkeypatch, api, macs=MACS[:1])

    assert [r["id"] for r in results["removed"]] == [1]
    # nothing was bound, so there is nothing to verify
    assert api.prints()["/ip/hotspot/ip-binding/print"] == 1


def test_entry_matched_by_several_customers_is_removed_once(monkeypatch):
    api = FakeRouter(MACS[:2], shared_host_ip="192.168.88.50")
    api.tables["/ip/hotspot/active"] = [
        {".id": "*A0", "mac-address": MACS[0], "address": "192.168.88.50", "user": ""}]
    _run(monkeypatch, api, macs=MACS[:2])

    host_removes = api.removes("/ip/hotspot/host")
    assert sorted(host_removes) == ["*H0", "*H1"]
    assert len(host_removes) == len(set(host_removes))


@pytest.mark.asyncio
async def test_expiry_lane_does_not_wait_for_the_shared_fleet_slots():
    shared = mikrotik_background.router_locks._semaphore
    held = 0
    while not shared.locked():
        await shared.acquire()
        held += 1
    try:
        result = await asyncio.wait_for(
            mikrotik_background._run_expiry_router_cleanup("10.0.0.9:8728", lambda x: x + 1, 41),
            timeout=5,
        )
        assert result == 42
    finally:
        for _ in range(held):
            shared.release()


@pytest.mark.asyncio
async def test_removal_job_no_longer_runs_the_safety_net(db, session_factory, monkeypatch):
    calls = []

    async def spy(*_a, **_k):
        calls.append("called")
        return 0

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "cleanup_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", spy)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", spy)
    monkeypatch.setattr(mikrotik_background, "_last_safety_net_cleanup_at", None)
    monkeypatch.setattr(mikrotik_background, "_last_access_credential_reaper_at", None)

    await mikrotik_background.cleanup_expired_users_background()

    assert calls == []


@pytest.mark.asyncio
async def test_housekeeping_runs_both_then_waits_for_their_intervals(session_factory, monkeypatch):
    calls = []

    async def safety_net(_db):
        calls.append("safety_net")
        return 0

    async def reaper(_db):
        calls.append("reaper")
        return 0

    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)
    monkeypatch.setattr(mikrotik_background, "housekeeping_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", safety_net)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", reaper)
    monkeypatch.setattr(mikrotik_background, "_last_safety_net_cleanup_at", None)
    monkeypatch.setattr(mikrotik_background, "_last_access_credential_reaper_at", None)

    await mikrotik_background.expiry_housekeeping_background()
    await mikrotik_background.expiry_housekeeping_background()

    assert calls == ["safety_net", "reaper"]


@pytest.mark.asyncio
async def test_housekeeping_sheds_load_when_the_pool_is_busy(monkeypatch):
    calls = []

    async def spy(*_a, **_k):
        calls.append("called")
        return 0

    monkeypatch.setattr(mikrotik_background, "housekeeping_running", False)
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: True)
    monkeypatch.setattr(mikrotik_background, "_cleanup_bypassing_for_all_routers", spy)
    monkeypatch.setattr(mikrotik_background, "_reap_idle_access_credentials", spy)

    await mikrotik_background.expiry_housekeeping_background()

    assert calls == []


def test_housekeeping_has_its_own_scheduled_job():
    main_py = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
    assert "expiry_housekeeping_background," in main_py
    assert "id='expiry_housekeeping'" in main_py

"""Circuit-breaker lanes: background failures must never block paid provisioning.

Evening-peak evidence (2026-09-23): on routers with congested uplinks, background
jobs (usage-cap watcher, queue repair, port attribution) tripped the shared
breaker and 48 payment provisioning attempts were skipped in 4 h.
"""

import ast
import pathlib
import socket

import pytest

from app.services import mikrotik_api as m
from app.services.mikrotik_api import (
    LANE_BACKGROUND,
    LANE_DEFAULT,
    LANE_PAYMENT,
    MikroTikAPI,
)

HOST, PORT = "10.0.0.138", 8728
ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean_breaker():
    m._router_failures.clear()
    yield
    m._router_failures.clear()


def _trip(lane, n=m.CIRCUIT_BREAKER_THRESHOLD):
    for _ in range(n):
        m._record_failure(HOST, PORT, lane)


def test_background_failures_do_not_block_payments_or_default():
    _trip(LANE_BACKGROUND)
    assert m._is_circuit_open(HOST, PORT, LANE_BACKGROUND)
    assert not m._is_circuit_open(HOST, PORT, LANE_PAYMENT)
    assert not m._is_circuit_open(HOST, PORT, LANE_DEFAULT)


def test_payment_failures_open_every_lane():
    _trip(LANE_PAYMENT)
    assert m._is_circuit_open(HOST, PORT, LANE_PAYMENT)
    assert m._is_circuit_open(HOST, PORT, LANE_DEFAULT)
    assert m._is_circuit_open(HOST, PORT, LANE_BACKGROUND)


def test_default_failures_block_default_and_background_but_not_payments():
    _trip(LANE_DEFAULT)
    assert m._is_circuit_open(HOST, PORT, LANE_DEFAULT)
    assert m._is_circuit_open(HOST, PORT, LANE_BACKGROUND)
    assert not m._is_circuit_open(HOST, PORT, LANE_PAYMENT)


def test_background_yields_after_a_single_payment_failure(monkeypatch):
    t = [1_000_000.0]
    monkeypatch.setattr(m.time, "time", lambda: t[0])
    m._record_failure(HOST, PORT, LANE_PAYMENT)          # below threshold
    assert not m._is_circuit_open(HOST, PORT, LANE_PAYMENT)
    assert m._is_circuit_open(HOST, PORT, LANE_BACKGROUND)
    t[0] += m.PAYMENT_PRIORITY_WINDOW + 1
    assert not m._is_circuit_open(HOST, PORT, LANE_BACKGROUND)


def test_breaker_resets_after_reset_time(monkeypatch):
    t = [2_000_000.0]
    monkeypatch.setattr(m.time, "time", lambda: t[0])
    _trip(LANE_PAYMENT)
    assert m._is_circuit_open(HOST, PORT, LANE_PAYMENT)
    t[0] += m.CIRCUIT_BREAKER_RESET_TIME + 1
    assert not m._is_circuit_open(HOST, PORT, LANE_PAYMENT)


def test_success_in_any_lane_clears_all_lanes():
    _trip(LANE_PAYMENT)
    _trip(LANE_BACKGROUND)
    _trip(LANE_DEFAULT)
    m._record_success(HOST, PORT, LANE_BACKGROUND)
    assert m._router_failures == {}
    for lane in (LANE_PAYMENT, LANE_DEFAULT, LANE_BACKGROUND):
        assert not m._is_circuit_open(HOST, PORT, lane)


def test_connect_records_failure_in_its_own_lane(monkeypatch):
    class _Sock:
        def settimeout(self, _):
            pass

        def connect(self, _addr):
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(m.socket, "socket", lambda *a, **k: _Sock())
    for _ in range(m.CIRCUIT_BREAKER_THRESHOLD):
        assert MikroTikAPI(HOST, "u", "p", PORT, lane=LANE_BACKGROUND).connect() is False
    # Background tripped its own lane; a paid customer's connection still tries.
    attempted = []

    class _Sock2(_Sock):
        def connect(self, addr):
            attempted.append(addr)
            raise socket.timeout()

    monkeypatch.setattr(m.socket, "socket", lambda *a, **k: _Sock2())
    api = MikroTikAPI(HOST, "u", "p", PORT, lane=LANE_PAYMENT)
    assert api.connect() is False
    assert attempted == [(HOST, PORT)]
    assert "Circuit breaker open" not in (api.last_connect_error or "")
    # ...while another background connection is skipped without touching the network.
    attempted.clear()
    bg = MikroTikAPI(HOST, "u", "p", PORT, lane=LANE_BACKGROUND)
    assert bg.connect() is False
    assert attempted == []
    assert "Circuit breaker open" in bg.last_connect_error


def test_unknown_lane_falls_back_to_default():
    assert MikroTikAPI(HOST, "u", "p", PORT, lane="bogus").lane == LANE_DEFAULT
    assert MikroTikAPI(HOST, "u", "p", PORT).lane == LANE_DEFAULT


# --- call sites stay in the intended lane --------------------------------------

EXPECTED = {
    "app/services/hotspot_provisioning.py": {"_call_mikrotik_bypass_sync": "LANE_PAYMENT"},
    "app/services/pppoe_provisioning.py": {"_provision_pppoe_sync": "LANE_PAYMENT"},
    "app/services/usage_cap_sampler.py": {"_fetch_queue_usage_for_router_sync": "LANE_BACKGROUND"},
    "app/services/payment_port_attribution.py": {"_fetch_mac_port_map_sync": "LANE_BACKGROUND"},
    "app/services/mikrotik_lb_background.py": {"_seed_router_lb_paid_sync": "LANE_BACKGROUND"},
    "app/services/mikrotik_background.py": {
        "_sync_single_router_queues_sync": "LANE_BACKGROUND",
        "_fetch_bandwidth_data_sync_for_router": "LANE_BACKGROUND",
        "_fetch_bandwidth_data_sync": "LANE_BACKGROUND",
        "_scan_router_idle_credentials_sync": "LANE_BACKGROUND",
        "_find_router_binding_cleanup_candidates_sync": "LANE_BACKGROUND",
        "_remove_router_bindings_sync": "LANE_BACKGROUND",
        # Expiry enforcement keeps today's behaviour on purpose.
        "_cleanup_single_router_hotspot_sync": None,
        "_cleanup_single_router_pppoe_sync": None,
    },
}


def _lanes_by_function(path):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    found = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for call in ast.walk(fn):
            if isinstance(call, ast.Call) and getattr(call.func, "id", None) == "MikroTikAPI":
                lane = next((kw.value.id for kw in call.keywords
                             if kw.arg == "lane" and isinstance(kw.value, ast.Name)), None)
                found.setdefault(fn.name, lane)
    return found


@pytest.mark.parametrize("path", sorted(EXPECTED))
def test_call_sites_use_the_intended_lane(path):
    found = _lanes_by_function(path)
    for func, lane in EXPECTED[path].items():
        assert func in found, f"{path}:{func} no longer builds a MikroTikAPI"
        assert found[func] == lane, f"{path}:{func} lane={found[func]!r}, expected {lane!r}"

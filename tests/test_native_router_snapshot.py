"""Native snapshots must remain complete, bounded and data-only."""
import json

import pytest
from fastapi import HTTPException, Response

from app.services.native_router_snapshot import BASE_PARTS, NativeSnapshotAssembler, SnapshotBusy, decode_snapshot
from app.services.checkin_delivery import parse_checkin_body, BadCheckin


def parts():
    return {
        "queues": [{".id": "*a", "name": "plan_AABBCCDDEEFF", "target": ["192.0.2.1/32"], "max-limit": "1M/1M"}],
        "queue_stats": [{".id": "*A", "bytes": "12/34"}],
        "hosts": {"rows": {}, "authorized": {}, "bypassed": {}},
        "summary": {"resource": [{"cpu-load": 1, "free-memory": 10, "total-memory": 100,
                                     "free-hdd-space": 10, "total-hdd-space": 100,
                                     "version": "7.19.6", "uptime": "1h", "board-name": "RB951Ui-2HnD"}],
                    "wan": "ether1", "queue_disabled": {}, "ppp": {},
                    "interfaces": [{".id": "*1", "name": "ether1", "type": "ether"}],
                    "interface_stats": [{".id": "*1", "rx-byte": 12, "tx-byte": 34}],
                    "interface_running": ["*1"], "interface_disabled": {}}
    }


def envelope(name, data, *, batch="a", manifest=None):
    return {"batch": batch, "part": name, "parts": sorted(manifest or BASE_PARTS), "data": data}


def test_atomic_reordered_parts_and_duplicate_do_not_emit_partial_inventory():
    a = NativeSnapshotAssembler()
    p = parts()
    for name in ["summary", "queue_stats", "queues"]:
        assert a.accept("R1", envelope(name, p[name]), now=0) is None
        assert a.accept("R1", envelope(name, p[name]), now=1) is None
    report = a.accept("R1", envelope("hosts", p["hosts"]), now=2)
    assert report["reports"] == [{"queue_key": "AABBCCDDEEFF", "upload_bytes": 12,
                                  "download_bytes": 34, "target_ip": "192.0.2.1/32",
                                  "max_limit": "1M/1M", "disabled": False}]
    assert report["hosts"] == [] and "bindings" not in report
    assert report["ports"][0]["running"] is True
    assert a.total_bytes == 0 and not a.pending
    assert a.accept("R1", envelope("hosts", p["hosts"]), now=3) is None


def test_conflicting_duplicate_or_manifest_is_discarded():
    a = NativeSnapshotAssembler()
    e = envelope("queues", parts()["queues"])
    a.accept("R1", e, now=0)
    with pytest.raises(ValueError):
        a.accept("R1", {**e, "data": []}, now=1)
    assert a.total_bytes == 0
    a.accept("R1", e, now=2)
    with pytest.raises(ValueError):
        a.accept("R1", {**e, "parts": sorted(BASE_PARTS | {"bindings"})}, now=3)
    assert not a.pending


@pytest.mark.parametrize("part", [None, [], {}, 1])
def test_malformed_part_name_is_refused_without_allocating(part):
    a = NativeSnapshotAssembler()
    with pytest.raises(ValueError):
        a.accept("R", {**envelope("queues", []), "part": part}, now=0)
    assert not a.pending and a.total_bytes == 0


def test_identity_isolation_ttl_fresh_batch_and_capacity():
    a = NativeSnapshotAssembler(max_pending=1, ttl=5)
    e = envelope("queues", [])
    a.accept("R1", e, now=0)
    with pytest.raises(SnapshotBusy):
        a.accept("R2", e, now=1)
    a.accept("R1", {**e, "batch": "b"}, now=2)
    assert set(a.pending) == {("R1", "b")}
    a.accept("R2", e, now=7)
    assert set(a.pending) == {("R2", "a")}
    tiny = NativeSnapshotAssembler(max_bytes=1)
    with pytest.raises(SnapshotBusy):
        tiny.accept("R1", e, now=0)
    assert tiny.total_bytes == 0 and not tiny.pending


@pytest.mark.parametrize("bad", [-1, "nan", 1.5, True, str(2**64)])
def test_invalid_counters_reject_entire_snapshot(bad):
    p = parts()
    p["summary"]["interface_stats"][0]["rx-byte"] = bad
    with pytest.raises(ValueError):
        decode_snapshot("R", p)


def test_metadata_is_native_json_not_csv_and_queue_order_is_preserved():
    p = parts()
    p["queues"] += [{".id": "*b", "name": "<pppoe-alice>", "target": "192.0.2.2/32", "max-limit": "2M/2M"}]
    p["queue_stats"].insert(0, {".id": "*B", "bytes": "56/78"})
    text = 'office, "upstairs"\nsecond line'
    p["neighbors"] = [{"identity": text, "address": "192.0.2.3"}]
    r = decode_snapshot("R", json.loads(json.dumps(p)))
    assert [x["queue_key"] for x in r["reports"]] == ["AABBCCDDEEFF", "pppoe:alice"]
    assert r["neighbors"][0]["identity"] == text and r["neighbors"][0]["address"] == "192.0.2.3"


def test_hotspot_rows_preserve_counters_and_reject_racing_incomplete_presence():
    p = parts()
    p["hosts"] = {"rows": [{".id": "*b", "mac-address": "AA:BB:CC:DD:EE:FF",
                             "address": "192.0.2.4", "bytes-in": 56, "bytes-out": 78}],
                  "authorized": ["*B"], "bypassed": {}}
    host = decode_snapshot("R", p)["hosts"][0]
    assert host["authorized"] and host["bytes_in"] == 56 and host["bytes_out"] == 78
    p["hosts"]["authorized"].append("*C")
    with pytest.raises(ValueError, match="host table changed"):
        decode_snapshot("R", p)


def test_typed_routeros_durations_are_relative_to_epoch_but_link_dates_are_absolute():
    p = parts()
    p["summary"]["resource"][0]["uptime"] = "1970-01-02 01:02:03"
    p["summary"]["interfaces"][0]["last-link-up-time"] = "2026-10-19 10:00:00"
    p["summary"]["ppp"] = [{"name": "demo", "uptime": "1970-01-01 00:00:19"}]
    r = decode_snapshot("R", p)
    assert r["router"]["uptime"] == "90123s"
    assert r["ppp"][0]["uptime"] == "19s"
    assert r["ports"][0]["last_link_up"] == "2026-10-19 10:00:00"


def census():
    c = {name: {"count": 0, "data": ""} for name in
         ["users", "checkin_users", "bindings", "checkin_bindings", "queues", "others"]}
    for key in ["bindings", "checkin_bindings"]:
        c[key] = {"count": 1, "data": "mac-address\nAA:BB:CC:DD:EE:FF"}
    c["queues"] = {"count": 1, "data": "name\nplan_AABBCCDDEEFF_suffix"}
    return {"v": 3, "id": "Bench", "census": c}


def test_native_census_preserves_missing_exact_queue_and_delivery_contract():
    c = census()
    r = parse_checkin_body(json.dumps(c).encode())
    legacy = parse_checkin_body(b"v=3&id=Bench&n=1&macs=AA:BB:CC:DD:EE:FF&q=AA:BB:CC:DD:EE:FF&c=AA:BB:CC:DD:EE:FF&o=")
    assert r == legacy
    c["census"]["queues"]["data"] = "name\nplan_AABBCCDDEEFF"
    assert not parse_checkin_body(json.dumps(c).encode()).queue_missing


@pytest.mark.parametrize("change", ["missing", "truncated", "injection", "wrong_header"])
def test_invalid_census_never_advertises_partial_inventory(change):
    c = census()
    if change == "missing": del c["census"]["users"]
    if change == "truncated": c["census"]["bindings"]["count"] = 2
    if change == "injection": c["census"]["bindings"]["data"] += "&macs="
    if change == "wrong_header": c["census"]["bindings"]["data"] = "password\nsecret"
    with pytest.raises(BadCheckin): parse_checkin_body(json.dumps(c).encode())


@pytest.mark.asyncio
async def test_endpoint_authenticates_before_assembly_and_partial_never_touches_db(monkeypatch):
    import app.api.usage_push_routes as routes
    from app.services.usage_push_auth import derive_router_token
    routes.reset_rate_limiter()
    def forbidden(*args): raise AssertionError("partial snapshot touched DB")
    monkeypatch.setattr(routes, "async_session", forbidden)
    payload = routes.UsagePushIn(identity="Bench", v=4, native=envelope("queues", []))
    with pytest.raises(HTTPException) as exc:
        await routes.receive_usage_push(payload, Response(), authorization="Bearer wrong")
    assert exc.value.status_code == 401 and not routes._native_snapshots.pending
    result = await routes.receive_usage_push(payload, Response(), authorization="Bearer " + derive_router_token("Bench"))
    assert result["accepted_part"] and not routes._last_push_at


def test_native_is_opt_in_and_firmware_gated_and_not_run_via_api(monkeypatch):
    from app.config import settings
    from app.services.native_router_scripts import native_cpu_enabled, native_cpu_supported
    from app.services import realtime_push_installer as installer
    from tests.test_realtime_push_installer import FakeRouterOS, ROUTER
    monkeypatch.setattr(settings, "ROUTER_NATIVE_CPU_IDENTITIES", "")
    assert not native_cpu_enabled("Router-0001")
    monkeypatch.setattr(settings, "ROUTER_NATIVE_CPU_IDENTITIES", "Router-0001")
    assert not native_cpu_supported("6.49.18") and not native_cpu_supported("7.19.5")
    assert not native_cpu_supported("7.20rc1") and native_cpu_supported("7.19.6 (stable)")
    api = FakeRouterOS()
    assert installer.install_router(ROUTER, api_factory=api)["status"] == "installed"
    assert not any(p == "/system/script/run" for p, _ in api.writes)
    assert "bw-native-snapshot" in api.scripts["bitwave-usage-push"]


def test_native_installers_leave_routeros6_untouched(monkeypatch):
    from app.config import settings
    from app.services import realtime_push_installer as installer
    from app.services.checkin_applier_script import install_checkin_applier
    from tests.test_realtime_push_installer import FakeRouterOS, ROUTER

    class OldRouter(FakeRouterOS):
        def send_command(self, path, args=None):
            result = super().send_command(path, args)
            if path == "/system/resource/print":
                result["data"][0]["version"] = "6.49.18 (stable)"
            return result

    monkeypatch.setattr(settings, "ROUTER_NATIVE_CPU_IDENTITIES", "Router-0001")
    api = OldRouter(existing_script="preserve")
    assert installer.install_router(ROUTER, api_factory=api)["status"] == "skipped_unsupported_native"
    assert install_checkin_applier(api, identity="Router-0001", endpoint_url="http://example.com/checkin")["status"] == "skipped_unsupported_native"
    assert api.writes == [] and api.scripts["bitwave-usage-push"] == "preserve"

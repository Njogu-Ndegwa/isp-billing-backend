"""Per-WAN line health on load-balanced routers (app/services/lb_wan_health.py).

KWETU WIFI / ZEUS, router 671, 2026-11-19: line 2 answered ping, so
check-gateway kept it in the balancing, but 193 of 444 established TCP flows
marked for WAN2 got under 1 KB back (WAN1: 10 of 281). These tests pin the
detector math to those numbers, the hysteresis (pull after N bad checks, rest,
trial, restore after M good checks), and that only that WAN's MARK rule is
ever written — never WAN1's, never the guard.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models import CustomerEvent
from app.services import lb_wan_health as h
from app.services import mikrotik_background, mikrotik_lb
from app.services.mikrotik_background import RouterLockManager
from tests.factories import make_reseller, make_router
from tests.test_mikrotik_lb import FakeLBAPI, _applied_api

TH = h.Thresholds()
NOW = datetime(2026, 11, 19, 18, 0)


def _flows(mark, n, starved, proto="tcp", state="established"):
    """n flows on mark, `starved` of them with ~0 reply bytes."""
    return ([{"protocol": proto, "tcp-state": state, "connection-mark": mark,
              "repl-bytes": "212"} for _ in range(starved)]
            + [{"protocol": proto, "tcp-state": state, "connection-mark": mark,
                "repl-bytes": "48213"} for _ in range(n - starved)])


ZEUS = _flows("WAN1_conn", 281, 10) + _flows("WAN2_conn", 444, 193)


# --- detector math --------------------------------------------------------------------

def test_zeus_numbers_flag_wan2_and_clear_wan1():
    stats = h.wan_flow_stats(ZEUS)
    assert stats[1] == {"flows": 281, "starved": 10, "ratio": round(10 / 281, 4)}
    assert stats[2] == {"flows": 444, "starved": 193, "ratio": round(193 / 444, 4)}
    v = h.assess_wans(stats, [1, 2], TH)
    assert v[2]["verdict"] == h.VERDICT_DEGRADED
    assert v[2]["factor"] > 10
    assert v[1]["verdict"] == h.VERDICT_HEALTHY


def test_only_established_tcp_with_a_wan_mark_counts():
    conns = (_flows("WAN2_conn", 60, 60, state="syn-sent")
             + _flows("WAN2_conn", 60, 60, proto="udp", state=None)
             + _flows("", 60, 60) + _flows("WAN2_conn", 3, 1))
    assert h.wan_flow_stats(conns) == {2: {"flows": 3, "starved": 1, "ratio": 0.3333}}


def test_reply_byte_threshold_is_strict_below():
    conns = [{"tcp-state": "established", "connection-mark": "WAN1_conn",
              "repl-bytes": b} for b in ("1023", "1024", "", None)]
    assert h.wan_flow_stats(conns, 1024)[1]["starved"] == 3


def test_too_few_flows_is_unknown_not_degraded():
    stats = h.wan_flow_stats(_flows("WAN1_conn", 300, 10) + _flows("WAN2_conn", 49, 49))
    assert h.assess_wans(stats, [1, 2], TH)[2]["verdict"] == h.VERDICT_UNKNOWN


def test_absolute_floor_holds_even_when_ratio_vs_other_is_high():
    # 20% starved vs 1%: 20x, but under the 25% floor.
    stats = h.wan_flow_stats(_flows("WAN1_conn", 300, 3) + _flows("WAN2_conn", 300, 60))
    assert h.assess_wans(stats, [1, 2], TH)[2]["verdict"] == h.VERDICT_HEALTHY


def test_both_lines_equally_noisy_is_healthy():
    stats = h.wan_flow_stats(_flows("WAN1_conn", 300, 105) + _flows("WAN2_conn", 300, 120))
    v = h.assess_wans(stats, [1, 2], TH)
    assert v[1]["verdict"] == v[2]["verdict"] == h.VERDICT_HEALTHY


def test_zero_baseline_uses_floor_not_division_by_zero():
    stats = h.wan_flow_stats(_flows("WAN1_conn", 300, 0) + _flows("WAN2_conn", 300, 90))
    v = h.assess_wans(stats, [1, 2], TH)
    assert v[2]["verdict"] == h.VERDICT_DEGRADED
    assert v[2]["factor"] == pytest.approx(0.3 / TH.baseline_floor)


def test_no_baseline_line_falls_back_to_absolute_only():
    alone_bad = h.wan_flow_stats(_flows("WAN1_conn", 100, 80))
    alone_meh = h.wan_flow_stats(_flows("WAN1_conn", 100, 50))
    assert h.assess_wans(alone_bad, [1, 2], TH)[1]["verdict"] == h.VERDICT_DEGRADED
    assert h.assess_wans(alone_meh, [1, 2], TH)[1]["verdict"] == h.VERDICT_HEALTHY
    assert h.assess_wans(alone_meh, [1, 2], TH)[2]["verdict"] == h.VERDICT_UNKNOWN


def test_three_wans_compare_against_the_healthiest_other_line():
    stats = h.wan_flow_stats(_flows("WAN1_conn", 200, 4) + _flows("WAN2_conn", 200, 90)
                             + _flows("WAN3_conn", 200, 100))
    v = h.assess_wans(stats, [1, 2, 3], TH)
    assert [v[n]["verdict"] for n in (1, 2, 3)] == [
        h.VERDICT_HEALTHY, h.VERDICT_DEGRADED, h.VERDICT_DEGRADED]


def test_thresholds_come_from_settings(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "LB_HEALTH_MIN_FLOWS", 7, raising=False)
    monkeypatch.setattr(settings, "LB_HEALTH_RELATIVE_FACTOR", 9.5, raising=False)
    th = h.Thresholds.from_settings()
    assert th.min_flows == 7 and th.relative_factor == 9.5


def test_contract_record_for_zeus():
    v = h.assess_wans(h.wan_flow_stats(ZEUS), [1, 2], TH)
    rec = h.contract_record(671, "ZEUS", v, ["ether1", "ether2"])
    assert rec["detector"] == "lb_wan_reply_loss"
    assert rec["status"] == "hit" and rec["code"] == "LB_WAN2_SILENT_REPLY_LOSS"
    assert rec["evidence"]["wans"]["WAN2"]["port"] == "ether2"
    assert "ether2" in rec["reseller_message"]
    clean = h.contract_record(1, "x", h.assess_wans(
        h.wan_flow_stats(_flows("WAN1_conn", 100, 2) + _flows("WAN2_conn", 100, 3)),
        [1, 2], TH), ["ether1", "ether2"])
    assert clean["status"] == "clean" and clean["code"] is None


# --- hysteresis -----------------------------------------------------------------------

def _run(verdicts, entry=None, streak=None, mark_enabled=True, can_pull=True,
         now=NOW, th=TH):
    actions = []
    for verdict in verdicts:
        entry, streak, action = h.step_wan(entry, streak, verdict, mark_enabled=mark_enabled,
                                           can_pull=can_pull, now=now, th=th)
        actions.append(action)
    return entry, streak, actions


D, G, U = h.VERDICT_DEGRADED, h.VERDICT_HEALTHY, h.VERDICT_UNKNOWN


def test_pull_only_after_n_consecutive_degraded_checks():
    entry, _, actions = _run([D] * TH.degraded_checks)
    assert actions == [None] * (TH.degraded_checks - 1) + ["pull"]
    assert entry["state"] == h.STATE_PULLED
    assert entry["cooldown_minutes"] == TH.cooldown_minutes
    assert entry["pulls"] == 1


def test_a_healthy_check_resets_the_degraded_streak():
    _, _, actions = _run([D, D, G, D, D])
    assert "pull" not in actions


def test_unknown_neither_advances_nor_resets():
    _, _, actions = _run([D, U, U, D, U, D])
    assert actions[-1] == "pull"


def test_wan1_is_alerted_never_pulled_and_not_re_alerted_within_6h():
    entry, streak, actions = _run([D] * 3, can_pull=False)
    assert actions[-1] == "alert"
    assert entry["state"] == h.STATE_ACTIVE
    _, _, more = _run([D] * 6, entry=entry, streak=streak, can_pull=False,
                      now=NOW + timedelta(hours=1))
    assert "alert" not in more and "pull" not in more
    _, _, later = _run([D], entry=entry, streak=streak, can_pull=False,
                       now=NOW + timedelta(hours=7))
    assert later == ["alert"]


def test_rule_already_off_and_not_ours_is_left_alone():
    entry, _, actions = _run([D] * 5, mark_enabled=False)
    assert actions == [None] * 5 and entry == {"state": h.STATE_ACTIVE}


def test_pulled_waits_out_the_cooldown_then_goes_on_trial():
    pulled, _, _ = _run([D] * 3)
    _, _, early = _run([U], entry=pulled, mark_enabled=False,
                       now=NOW + timedelta(minutes=TH.cooldown_minutes - 1))
    assert early == [None]
    trial, streak, actions = _run([U], entry=pulled, mark_enabled=False,
                                  now=NOW + timedelta(minutes=TH.cooldown_minutes))
    assert actions == ["trial"] and trial["state"] == h.STATE_TRIAL
    assert streak == {"degraded": 0, "healthy": 0}


def test_trial_restores_after_m_healthy_checks():
    trial = {"state": h.STATE_TRIAL, "since": NOW.isoformat(), "cooldown_minutes": 60,
             "pulls": 2}
    entry, _, actions = _run([G] * TH.healthy_checks, entry=trial)
    assert actions[-1] == "restore" and actions[:-1] == [None] * (TH.healthy_checks - 1)
    assert entry == {"state": h.STATE_ACTIVE}  # cooldown reset


def test_failed_trial_is_pulled_again_with_doubled_capped_cooldown():
    trial = {"state": h.STATE_TRIAL, "since": NOW.isoformat(), "cooldown_minutes": 30,
             "pulls": 1}
    entry, _, actions = _run([D] * TH.degraded_checks, entry=trial)
    assert actions[-1] == "repull"
    assert entry["state"] == h.STATE_PULLED and entry["cooldown_minutes"] == 60
    assert entry["pulls"] == 2
    capped = {**trial, "cooldown_minutes": 200}
    entry, _, _ = _run([D] * TH.degraded_checks, entry=capped)
    assert entry["cooldown_minutes"] == TH.max_cooldown_minutes


def test_re_enabled_elsewhere_while_pulled_goes_on_trial():
    pulled, _, _ = _run([D] * 3)
    entry, _, actions = _run([D], entry=pulled, mark_enabled=True)
    assert actions == ["external_reenable"] and entry["state"] == h.STATE_TRIAL


# --- the router write -----------------------------------------------------------------

def _lb_api():
    api = _applied_api()
    original = api.send_command

    def send_command(command, arguments=None):
        # RouterOS takes yes/no but prints true/false.
        out = original(command, arguments)
        if command == "/ip/firewall/mangle/set":
            for r in api.mangle_rules:
                if r.get("disabled") in ("yes", "no"):
                    r["disabled"] = "true" if r["disabled"] == "yes" else "false"
        return out

    api.send_command = send_command
    api.commands = []
    return api


def _rule(api, comment):
    return next(r for r in api.mangle_rules if r.get("comment") == comment)


def test_disable_touches_only_that_wans_mark_rule():
    api = _lb_api()
    before = {r[".id"]: dict(r) for r in api.mangle_rules}
    out = h.set_mark_rule(api, 2, enable=False)
    assert out["ok"] is True
    writes = [(c, a) for c, a in api.commands if not c.endswith("/print")]
    mark2 = _rule(api, "ISP_BILLING_PCC_MARK_WAN2")
    assert writes == [("/ip/firewall/mangle/set", {".id": mark2[".id"], "disabled": "yes"})]
    for r in api.mangle_rules:
        if r[".id"] != mark2[".id"]:
            assert r == before[r[".id"]]
    assert _rule(api, mikrotik_lb.GUARD_COMMENT).get("disabled") != "true"
    # The rule order check now routes WAN2's hash bucket to the main table only.
    order = mikrotik_lb.lb_pcc_order_check(api.mangle_rules, 2)
    assert order["unreachable"] == ["WAN2"]
    assert order["share"]["WAN1"] == 0.5


def test_never_touches_wan1():
    api = _lb_api()
    assert h.set_mark_rule(api, 1, enable=False) == {"ok": False, "error": "never_touch_wan1"}
    assert api.commands == []


def test_re_enable_refuses_without_the_guard():
    api = _lb_api()
    h.set_mark_rule(api, 2, enable=False)
    _rule(api, mikrotik_lb.GUARD_COMMENT)["disabled"] = "true"
    api.commands = []
    out = h.set_mark_rule(api, 2, enable=True)
    assert out == {"ok": False, "error": "guard_not_enabled"}
    assert _rule(api, "ISP_BILLING_PCC_MARK_WAN2")["disabled"] == "true"
    assert not [c for c, _ in api.commands if c == "/ip/firewall/mangle/set"]


def test_re_enable_refuses_without_the_route_rule():
    api = _lb_api()
    h.set_mark_rule(api, 2, enable=False)
    _rule(api, "ISP_BILLING_PCC_ROUTE_WAN2")["disabled"] = "true"
    assert h.set_mark_rule(api, 2, enable=True)["error"] == "route_rule_not_enabled"


def test_re_enable_round_trip():
    api = _lb_api()
    h.set_mark_rule(api, 2, enable=False)
    assert h.set_mark_rule(api, 2, enable=True)["ok"] is True
    assert mikrotik_lb.lb_pcc_order_check(api.mangle_rules, 2)["ok"] is True


def test_verify_treats_a_pulled_wan_as_expected():
    api = _lb_api()
    h.set_mark_rule(api, 2, enable=False)
    plain = mikrotik_lb.lb_verify(api, ["ether1", "ether2"])
    assert plain["pcc_order"]["ok"] is False
    pulled = mikrotik_lb.lb_verify(api, ["ether1", "ether2"], pulled_wans=[2])
    assert pulled["pcc_order"]["ok"] is True
    assert pulled["pcc_order"]["pulled_by_health_check"] == ["WAN2"]


# --- the job --------------------------------------------------------------------------

@pytest.fixture
def job(monkeypatch):
    h.reset_state()
    monkeypatch.setattr(mikrotik_background, "router_locks", RouterLockManager(max_concurrent=3))
    alerts = []

    async def fake_deliver(items, now=None, memory=None):
        alerts.extend(items)
        return {"delivered": len(items)}

    import app.services.ops_health as ops_health
    monkeypatch.setattr(ops_health, "deliver_alerts", fake_deliver)
    api = _lb_api()
    api.connections = list(ZEUS)
    monkeypatch.setattr(h, "_read_sync", lambda info: h.read_router(api))
    writes = []

    def fake_set(info, n, enable):
        writes.append((n, enable))
        return h.set_mark_rule(api, n, enable)

    monkeypatch.setattr(h, "_set_mark_sync", fake_set)
    yield {"api": api, "alerts": alerts, "writes": writes}
    h.reset_state()


async def _bundle(db, health=None):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller, name="ZEUS")
    router.lb_enabled = True
    router.lb_config = {"wan_ports": ["ether1", "ether2"]}
    if health:
        router.lb_config["health"] = health
    await db.commit()
    return router, {
        "id": router.id, "name": "ZEUS", "user_id": reseller.id,
        "router_key": "10.0.0.2:8728", "router_info": {},
        "wan_ports": ["ether1", "ether2"], "health": health or {},
    }


async def test_job_pulls_wan2_after_n_checks_logs_alerts_and_persists(db, job):
    router, bundle = await _bundle(db)
    for i in range(TH.degraded_checks):
        out = await h.check_router(bundle, TH, now=NOW + timedelta(minutes=5 * i),
                                   mitigate=True)
    assert out["status"] == "hit"
    assert job["writes"] == [(2, False)]
    assert _rule(job["api"], "ISP_BILLING_PCC_MARK_WAN2")["disabled"] == "true"
    assert _rule(job["api"], "ISP_BILLING_PCC_MARK_WAN1").get("disabled") != "true"
    assert _rule(job["api"], mikrotik_lb.GUARD_COMMENT).get("disabled") != "true"

    await db.refresh(router)
    assert router.lb_config["health"]["wans"]["2"]["state"] == "pulled"
    assert router.lb_config["wan_ports"] == ["ether1", "ether2"]
    events = (await db.execute(select(CustomerEvent).where(
        CustomerEvent.router_id == router.id))).scalars().all()
    assert [e.event_type for e in events] == ["lb_wan_health_pull"]
    assert "ether2" in events[0].message
    assert len(job["alerts"]) == 1 and job["alerts"][0]["severity"] == "critical"
    assert "ether2" in job["alerts"][0]["message"]


async def test_job_detect_only_mode_never_writes(db, job):
    _, bundle = await _bundle(db)
    for i in range(TH.degraded_checks):
        await h.check_router(bundle, TH, now=NOW, mitigate=False)
    assert job["writes"] == []
    assert [a["severity"] for a in job["alerts"]] == ["critical"]


async def test_job_trials_and_restores_a_recovered_line(db, job):
    pulled = {"wans": {"2": {"state": "pulled", "since": NOW.isoformat(),
                             "cooldown_minutes": 30, "pulls": 1}}}
    router, bundle = await _bundle(db, pulled)
    h.set_mark_rule(job["api"], 2, enable=False)
    job["api"].connections = _flows("WAN1_conn", 300, 6)  # WAN2 rests: no flows
    await h.check_router(bundle, TH, now=NOW + timedelta(minutes=10), mitigate=True)
    assert job["writes"] == []
    await h.check_router(bundle, TH, now=NOW + timedelta(minutes=31), mitigate=True)
    assert job["writes"] == [(2, True)]
    await db.refresh(router)
    bundle["health"] = router.lb_config["health"]
    assert bundle["health"]["wans"]["2"]["state"] == "trial"

    job["api"].connections = _flows("WAN1_conn", 300, 6) + _flows("WAN2_conn", 200, 5)
    for i in range(TH.healthy_checks):
        await h.check_router(bundle, TH, now=NOW + timedelta(minutes=35 + 5 * i),
                             mitigate=True)
    await db.refresh(router)
    assert router.lb_config["health"]["wans"] == {}
    events = (await db.execute(select(CustomerEvent).where(
        CustomerEvent.router_id == router.id).order_by(CustomerEvent.id))).scalars().all()
    assert [e.event_type for e in events] == ["lb_wan_health_trial", "lb_wan_health_restore"]
    assert [a["severity"] for a in job["alerts"]] == ["watch"]  # trial itself is quiet


async def test_job_skips_a_router_rolled_back_by_hand(db, job):
    """ZEUS today: rollback_lb.py disabled every mangle rule, DB lb_enabled=true."""
    _, bundle = await _bundle(db)
    for r in job["api"].mangle_rules:
        r["disabled"] = "true"
    for _ in range(5):
        out = await h.check_router(bundle, TH, now=NOW, mitigate=True)
    assert out["status"] == "skipped"
    assert job["writes"] == [] and job["alerts"] == []


async def test_job_failed_write_keeps_state_and_retries_next_check(db, job, monkeypatch):
    router, bundle = await _bundle(db)
    calls = []

    def failing(info, n, enable):
        calls.append((n, enable))
        return {"ok": False, "error": "set_failed"}

    monkeypatch.setattr(h, "_set_mark_sync", failing)
    for i in range(TH.degraded_checks + 1):
        await h.check_router(bundle, TH, now=NOW, mitigate=True)
    assert calls == [(2, False), (2, False)]
    await db.refresh(router)
    assert "health" not in router.lb_config


# --- the dashboard "Disable load balancing" path --------------------------------------

def test_disable_keeps_checked_defaults_when_wan1_dhcp_adds_no_default_route():
    """WAN1 DHCP add-default-route=no (ZEUS): removing d1/d2 would leave the
    router with no default route at all."""
    api = _applied_api(wan1_dhcp_default=False)
    report = mikrotik_lb.lb_rollback(api)
    assert report["success"] is True
    kept = {r["comment"] for r in api.routes}
    assert {"ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED",
            "ISP_BILLING_DUAL_WAN_ETHER1_PROBE"} <= kept
    assert set(report["kept_failover_routes"]) == kept
    assert not [c for c in kept if c.startswith("ISP_BILLING_PCC_WAN")]  # to_wanX gone
    assert api.routing_tables == []
    assert not [m for m in api.mangle_rules
                if (m.get("comment") or "").startswith("ISP_BILLING")]
    assert report["warnings"]


def test_disable_full_teardown_when_wan1_has_its_own_default():
    api = _applied_api(wan1_dhcp_default=True)
    report = mikrotik_lb.lb_rollback(api)
    assert report["kept_failover_routes"] == []
    assert [r for r in api.routes if not (r.get("comment") or "").startswith("ISP_BILLING")]
    assert not [r for r in api.routes if (r.get("comment") or "").startswith("ISP_BILLING")]


def test_inactive_or_policy_table_defaults_do_not_count_as_a_way_out():
    assert not mikrotik_lb.lb_has_unmanaged_default([
        {"dst-address": "0.0.0.0/0", "active": "false"},
        {"dst-address": "0.0.0.0/0", "active": "true", "routing-table": "to_wan1"},
        {"dst-address": "0.0.0.0/0", "active": "true", "routing-mark": "to_wan1"},
        {"dst-address": "0.0.0.0/0", "active": "true",
         "comment": "ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"},
    ])
    assert mikrotik_lb.lb_has_unmanaged_default([
        {"dst-address": "0.0.0.0/0", "active": "true", "routing-table": "main"}])


async def test_disable_endpoint_reports_kept_routes_and_clears_health(db, monkeypatch):
    from app.api import load_balancing_routes as lbr

    async def no_avail(*a, **k):
        return None

    monkeypatch.setattr(lbr, "record_router_availability", no_avail)
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    router.lb_enabled = True
    router.lb_config = {"wan_ports": ["ether1", "ether2"],
                        "health": {"wans": {"2": {"state": "pulled"}}}}
    await db.commit()

    async def run(router_obj, sync_func, *args, **kwargs):
        return {"success": True, "steps": [], "warnings": ["kept"],
                "kept_failover_routes": ["ISP_BILLING_DUAL_WAN_PRIMARY_CHECKED"]}

    monkeypatch.setattr(lbr, "_run_locked_router_thread", run)
    resp = await lbr.disable_load_balancing(
        router.id, lbr.LBDisableRequest(confirm=True), db,
        {"user_id": reseller.id, "role": reseller.role.value})
    assert "backup routes were kept" in resp["message"]
    assert resp["warnings"] == ["kept"]
    await db.refresh(router)
    assert router.lb_config == {"wan_ports": ["ether1", "ether2"]}


def test_pulled_wans_from_config():
    from app.api.load_balancing_routes import _pulled_wans
    assert _pulled_wans({"health": {"wans": {"2": {"state": "pulled"},
                                             "3": {"state": "trial"}}}}) == [2]
    assert _pulled_wans(None) == []

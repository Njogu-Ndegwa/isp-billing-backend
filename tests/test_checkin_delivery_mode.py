"""Per-router delivery mode for the push-vs-check-in A/B (money path).

What these pin, and why:

* **push_only never gets A/Q lines** and never the fast cadence; the check-in
  there only records 'observed', never 'checkin'.
* **checkin_only skips the payment-time push** and the check-in sends the A
  line on the first report (no grace) for a MAC with an undelivered attempt.
* **The safety net**: if the check-in has not delivered within
  CHECKIN_ONLY_FALLBACK_SECONDS of the attempt's created_at, the push runs
  (in-process timer, and the retry job as the backstop after a restart). A
  broken check-in must never strand a paying customer.
* **Nothing flags a deferred attempt as a failure** while it waits.
* **Grace is measured from the attempt's DB created_at**, so an app restart
  (in-memory state cleared) does not reset it, while the Reconnect guard
  still holds a MAC that was on the router moments ago.
* **Default mode is unchanged** apart from that.
* **Per-mode metrics** are what the A/B is judged on.
"""

from datetime import datetime, timedelta

import pytest

from app.config import settings
from app.db.models import (
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningLog,
    ProvisioningState,
    RouterAuthMethod,
)
from app.services import checkin_delivery as svc
from app.services import hotspot_provisioning as hsp
from tests.factories import make_router

# Fixtures and helpers of the check-in suite (imported, not redefined, so the
# endpoint is exercised exactly as there).
from tests.test_router_checkin import (  # noqa: F401  (pytest fixtures)
    IDENT,
    _checkin,
    _entry,
    _parse_frame,
    _report,
    client,
    pilot,
)

M1 = "AA:BB:CC:00:00:01"
M2 = "AA:BB:CC:00:00:02"
ROUTER = svc.RouterRef(id=7, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)
_PK = iter(range(1_900_000, 1_999_999))


def _arm(monkeypatch, *, push_only="", checkin_only="", pilot_ids=None, grace=60, fallback=120):
    monkeypatch.setattr(settings, "CHECKIN_ENABLED", True)
    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", False)
    monkeypatch.setattr(settings, "CHECKIN_MODE", "add")
    if pilot_ids is not None:
        monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", pilot_ids)
    monkeypatch.setattr(settings, "CHECKIN_PUSH_ONLY_ROUTER_IDS", push_only)
    monkeypatch.setattr(settings, "CHECKIN_ONLY_ROUTER_IDS", checkin_only)
    monkeypatch.setattr(settings, "CHECKIN_MISSING_GRACE_SECONDS", grace)
    monkeypatch.setattr(settings, "CHECKIN_ONLY_FALLBACK_SECONDS", fallback)
    monkeypatch.setattr(settings, "CHECKIN_MAX_LINES_PER_REPLY", 10)


def _pending(mac=M1, age_s=0.0, state="scheduled", now=None, attempt_id=1):
    now = now or datetime.utcnow()
    return svc.PendingAttempt(attempt_id=attempt_id, customer_id=1, mac=mac, state=state,
                              created_at=now - timedelta(seconds=age_s))


def _decide(macs, desired, t, *, pending=(), now=None, q=None, c=None, undelivered_recent=False):
    return svc.decide(router=ROUTER, report=_report(macs, q=q, c=c), desired=desired,
                      undelivered_recent=undelivered_recent, mode="add",
                      now=now or datetime.utcnow(), now_mono=t, pending=pending)


@pytest.fixture(autouse=True)
def _clean_state():
    svc.reset_state()
    yield
    svc.reset_state()


# ---------------------------------------------------------------------------
# Mode resolution
# ---------------------------------------------------------------------------

def test_delivery_mode_from_env_lists(monkeypatch):
    _arm(monkeypatch, push_only="1, 2,junk", checkin_only="3,2", pilot_ids="1,2,3,4")
    assert svc.delivery_mode(1) == svc.DELIVERY_PUSH_ONLY
    assert svc.delivery_mode(3) == svc.DELIVERY_CHECKIN_ONLY
    assert svc.delivery_mode(2) == svc.DELIVERY_BOTH      # in both lists: safe default
    assert svc.delivery_mode(4) == svc.DELIVERY_BOTH
    assert svc.delivery_mode(None) == svc.DELIVERY_BOTH
    snap = svc.stats_snapshot()["delivery_modes"]
    assert snap["conflicting_router_ids"] == [2]
    assert snap["checkin_only_effective_router_ids"] == [3]


def test_empty_lists_mean_current_behaviour(monkeypatch):
    _arm(monkeypatch, pilot_ids="3")
    assert svc.delivery_mode(3) == svc.DELIVERY_BOTH
    assert not svc.checkin_only_active(3)
    assert svc.effective_checkin_only_router_ids() == frozenset()


@pytest.mark.parametrize("setting,value", [
    ("CHECKIN_ENABLED", False),
    ("CHECKIN_KILL_SWITCH", True),
    ("CHECKIN_MODE", "shadow"),
    ("CHECKIN_ROUTER_IDS", "99"),   # not in the pilot
])
def test_checkin_only_is_inert_unless_the_channel_can_deliver(monkeypatch, setting, value):
    _arm(monkeypatch, checkin_only="3", pilot_ids="3")
    assert svc.checkin_only_active(3)
    monkeypatch.setattr(settings, setting, value)
    assert svc.delivery_mode(3) == svc.DELIVERY_CHECKIN_ONLY   # still the configured arm
    assert not svc.checkin_only_active(3)                      # but the push is back


def test_fallback_seconds_is_clamped(monkeypatch):
    for raw, want in ((120, 120), (0, 30), (-5, 30), (100000, 600), ("junk", 120)):
        monkeypatch.setattr(settings, "CHECKIN_ONLY_FALLBACK_SECONDS", raw)
        assert svc.checkin_only_fallback_seconds() == want


# ---------------------------------------------------------------------------
# push_only: the check-in never delivers
# ---------------------------------------------------------------------------

def test_push_only_router_never_gets_a_or_q_lines(monkeypatch):
    _arm(monkeypatch, push_only=str(ROUTER.id), pilot_ids=str(ROUTER.id), grace=0)
    d = _decide([M2], [_entry(M1), _entry(M2)], 1000.0, q=[M2],
                pending=[_pending(M1, age_s=600, state="retry_pending")], undelivered_recent=True)
    assert d.lines == [] and d.queue_lines == []
    assert [e.mac for e in d.would_send] == [M1]              # counted, not sent
    # No fast cadence: it would only burn router CPU here.
    assert svc.NORMAL_POLL_SECONDS - 6 <= d.next_s <= svc.NORMAL_POLL_SECONDS + 6
    stats = svc.stats_snapshot()["routers"][ROUTER.id]
    assert stats["push_only_suppressed_total"] == 1 and stats["lines_sent_total"] == 0
    assert stats["delivery_mode"] == "push_only"


def test_push_only_never_credits_the_check_in(monkeypatch):
    _arm(monkeypatch, push_only=str(ROUTER.id), pilot_ids=str(ROUTER.id))
    rep = _report([M1], c=[M1])     # a CHECKIN binding left over from before
    gave_up = svc.delivery_candidates(rep, [_pending(M1, state="retry_pending")], ROUTER.id)
    assert [(p.via) for p in gave_up] == ["observed"]
    in_flight = svc.delivery_candidates(rep, [_pending(M1, state="in_progress")], ROUTER.id)
    assert in_flight == []          # the push owns it and records itself


@pytest.mark.asyncio
async def test_push_only_endpoint_replies_with_no_lines(client, pilot, monkeypatch):
    rid = pilot["router"].id
    _arm(monkeypatch, push_only=str(rid), pilot_ids=str(rid), grace=0)
    resp = await _checkin(client, [M1], q=[M1])     # M2 missing, M1 lacks a queue
    _, count, next_s, ops = _parse_frame(resp.text)
    assert count == 0 and ops == []
    assert next_s >= svc.NORMAL_POLL_SECONDS - svc.NORMAL_POLL_JITTER_SECONDS


# ---------------------------------------------------------------------------
# Grace measured from the attempt's created_at (default mode)
# ---------------------------------------------------------------------------

def test_default_mode_attempt_younger_than_grace_is_held(monkeypatch):
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    d = _decide([], [_entry(M1)], 1000.0, pending=[_pending(M1, age_s=30, now=now)], now=now)
    assert d.lines == [] and [e.mac for e in d.in_grace] == [M1]


def test_default_mode_late_poll_sends_on_first_report_when_attempt_is_old_enough(monkeypatch):
    """The router polled late: the payment is 61 s old, so the push had its
    grace. Previously the first missing report started a fresh 60 s clock."""
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    d = _decide([], [_entry(M1)], 1000.0, pending=[_pending(M1, age_s=61, now=now)], now=now)
    assert [e.mac for e in d.lines] == [M1]
    assert svc.stats_snapshot()["routers"][ROUTER.id]["sent_by_attempt_age_total"] == 1


def test_grace_from_created_at_survives_a_restart(monkeypatch):
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    created = datetime.utcnow() - timedelta(seconds=40)
    pend = [svc.PendingAttempt(attempt_id=1, customer_id=1, mac=M1, state="retry_pending", created_at=created)]
    held = _decide([], [_entry(M1)], 1000.0, pending=pend, now=created + timedelta(seconds=40))
    assert held.lines == []

    svc.reset_state()   # app restart: every in-memory clock is gone

    # 25 s later (65 s after the payment) the first report after the restart
    # sends at once; the in-memory clock alone would hold it another 60 s.
    after = _decide([], [_entry(M1)], 5.0, pending=pend, now=created + timedelta(seconds=65))
    assert [e.mac for e in after.lines] == [M1]


def test_newest_attempt_is_the_anchor(monkeypatch):
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    pend = [_pending(M1, age_s=3600, state="failed", now=now, attempt_id=1),
            _pending(M1, age_s=10, state="scheduled", now=now, attempt_id=2)]
    assert _decide([], [_entry(M1)], 1000.0, pending=pend, now=now).lines == []


def test_mac_without_attempt_keeps_the_in_memory_clock(monkeypatch):
    """Renewal/reconnect paths without an attempt row: unchanged behaviour."""
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    assert _decide([], [_entry(M1)], 1000.0).lines == []
    assert _decide([], [_entry(M1)], 1059.0).lines == []
    assert [e.mac for e in _decide([], [_entry(M1)], 1060.0).lines] == [M1]


def test_reconnect_guard_holds_a_mac_that_was_just_on_the_router(monkeypatch):
    """The Reconnect flow removes OLD's binding seconds before the customer
    row moves to NEW. Even with an old undelivered attempt on OLD, a MAC seen
    present moments ago waits the full grace (in-memory clock)."""
    _arm(monkeypatch, pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    pend = [_pending(M1, age_s=600, state="in_progress", now=now)]
    _decide([M1], [_entry(M1)], 1000.0, pending=pend, now=now)                      # present
    assert _decide([], [_entry(M1)], 1005.0, pending=pend, now=now).lines == []     # just removed
    assert _decide([], [_entry(M1)], 1059.0, pending=pend, now=now).lines == []
    assert [e.mac for e in _decide([], [_entry(M1)], 1066.0, pending=pend, now=now).lines] == [M1]


# ---------------------------------------------------------------------------
# checkin_only: no grace for a paid MAC with an attempt
# ---------------------------------------------------------------------------

def test_checkin_only_sends_immediately_for_a_fresh_payment(monkeypatch):
    _arm(monkeypatch, checkin_only=str(ROUTER.id), pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    d = _decide([], [_entry(M1)], 1000.0, pending=[_pending(M1, age_s=1, now=now)], now=now,
                undelivered_recent=True)
    assert [e.mac for e in d.lines] == [M1] and d.in_grace == []
    assert d.next_s == svc.CONFIRM_POLL_SECONDS


def test_checkin_only_mac_without_attempt_still_waits_the_grace(monkeypatch):
    _arm(monkeypatch, checkin_only=str(ROUTER.id), pilot_ids=str(ROUTER.id), grace=60)
    assert _decide([], [_entry(M1)], 1000.0).lines == []


def test_checkin_only_keeps_the_reconnect_guard(monkeypatch):
    _arm(monkeypatch, checkin_only=str(ROUTER.id), pilot_ids=str(ROUTER.id), grace=60)
    now = datetime.utcnow()
    pend = [_pending(M1, age_s=1, now=now)]
    _decide([M1], [_entry(M1)], 1000.0, pending=pend, now=now)
    assert _decide([], [_entry(M1)], 1003.0, pending=pend, now=now).lines == []


# ---------------------------------------------------------------------------
# The push side: deferral, fallback, retry job, consumers
# ---------------------------------------------------------------------------

async def _payment_attempt(db, customer, router, *, age_s=0.0, state=ProvisioningState.SCHEDULED,
                           entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, attempt_count=0):
    now = datetime.utcnow()
    a = ProvisioningAttempt(
        customer_id=customer.id, router_id=router.id, mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_PK),
        entrypoint=entrypoint, provisioning_state=state, attempt_count=attempt_count,
        created_at=now - timedelta(seconds=age_s), updated_at=now - timedelta(seconds=age_s),
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


def _payload(customer):
    return {"mac_address": customer.mac_address, "username": customer.mac_address.replace(":", ""),
            "router_ip": "10.0.0.2"}


@pytest.fixture
def router_calls(monkeypatch):
    """Record MikroTik pushes (and succeed) instead of touching a router."""
    calls = []

    async def fake_op(payload, verify_only=False):
        calls.append((payload.get("mac_address"), verify_only))
        return {"success": True, "provision_result": {}, "online_state": "offline"}

    monkeypatch.setattr(hsp, "_run_mikrotik_operation", fake_op)
    return calls


@pytest.fixture
def fallbacks(monkeypatch):
    """Capture fallback timers instead of sleeping."""
    armed = []
    monkeypatch.setattr(hsp, "_spawn_checkin_fallback", lambda *a: armed.append(a))
    return armed


async def _logs(db, attempt_id):
    from sqlalchemy import select
    return (await db.execute(
        select(ProvisioningLog).where(ProvisioningLog.attempt_id == attempt_id).order_by(ProvisioningLog.id)
    )).scalars().all()


@pytest.mark.asyncio
async def test_push_is_skipped_for_checkin_only_payment(pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)

    result = await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)

    assert router_calls == []                                    # no RouterOS login
    assert result["deferred_to_checkin"] is True
    assert result["delivery"]["delivery_status"] == "activating"
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.SCHEDULED and a.attempt_count == 0
    assert a.delivered_via is None
    assert len(fallbacks) == 1
    delay, customer_id, router_id, _, attempt_id = fallbacks[0]
    assert (customer_id, router_id, attempt_id) == (paid.id, router.id, a.id)
    assert 115 <= delay <= 120
    logs = await _logs(db, a.id)
    assert [(l.action, l.status) for l in logs] == [("checkin_only_deferred", "deferred")]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [
    "both_arm", "push_only_arm", "kill_switch", "shadow", "not_in_pilot", "radius_router",
    "manual_entrypoint", "retry_action", "past_fallback_window", "verify_only",
])
async def test_push_runs_normally_outside_checkin_only(pilot, monkeypatch, router_calls, fallbacks, case):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    kwargs = {}
    action = "hotspot_payment"
    if case == "both_arm":
        monkeypatch.setattr(settings, "CHECKIN_ONLY_ROUTER_IDS", "")
    elif case == "push_only_arm":
        _arm(monkeypatch, push_only=str(router.id), pilot_ids=str(router.id))
    elif case == "kill_switch":
        monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", True)
    elif case == "shadow":
        monkeypatch.setattr(settings, "CHECKIN_MODE", "shadow")
    elif case == "not_in_pilot":
        monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "")
    elif case == "radius_router":
        router.auth_method = RouterAuthMethod.RADIUS
        await db.commit()
    elif case == "manual_entrypoint":
        kwargs["entrypoint"] = ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION
    elif case == "retry_action":
        action = "hotspot_retry"
    elif case == "past_fallback_window":
        kwargs["age_s"] = 121
    a = await _payment_attempt(db, paid, router, **kwargs)

    result = await hsp.provision_hotspot_customer(
        paid.id, router.id, _payload(paid), action, a.id, verify_only=(case == "verify_only"))

    assert router_calls and fallbacks == []
    assert not result.get("deferred_to_checkin")
    if case != "verify_only":
        await db.refresh(a)
        assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED
        assert a.delivered_via == "push" and a.attempt_count == 1


@pytest.mark.asyncio
async def test_checkin_only_end_to_end_checkin_delivers_and_fallback_is_a_no_op(
        client, pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    # Grace 60 on purpose: checkin_only must not wait for it.
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id), grace=60)
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert router_calls == [] and len(fallbacks) == 1

    # First check-in after the payment: A line at once, confirm cadence.
    resp = await _checkin(client, [M2], c=[])
    _, count, next_s, ops = _parse_frame(resp.text)
    assert [o["mac"] for o in ops] == [M1] and next_s == svc.CONFIRM_POLL_SECONDS

    # The applier added it; the confirming report records it as the check-in's.
    await _checkin(client, [M1, M2], c=[M1])
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert a.delivered_via == "checkin" and a.attempt_count == 0 and a.access_seen_at is not None

    # The fallback timer fires: nothing to do, no push.
    delay, *args = fallbacks[0]
    assert await hsp._checkin_only_fallback_after(0, *args) is None
    assert router_calls == []
    await db.refresh(a)
    assert a.delivered_via == "checkin"

    # A late duplicate payment-time call inside the window does not push either.
    res = await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert res["success"] is True and res["skipped_push"] == "delivered_by_checkin"
    assert router_calls == []


@pytest.mark.asyncio
async def test_fallback_pushes_when_the_checkin_never_delivered(pilot, monkeypatch, router_calls, fallbacks):
    """A broken check-in (router never polls) must not strand the customer."""
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert router_calls == []

    delay, *args = fallbacks[0]
    result = await hsp._checkin_only_fallback_after(0, *args)

    assert router_calls == [(M1, False)]
    assert result["success"] is True
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED
    assert a.delivered_via == "push" and a.attempt_count == 1
    actions = [(l.action, l.status) for l in await _logs(db, a.id)]
    assert ("checkin_only_fallback", "started") in actions
    assert actions[-1] == ("checkin_only_fallback", "success")


@pytest.mark.asyncio
async def test_real_fallback_timer_fires_after_the_window(pilot, monkeypatch, router_calls):
    """The timer itself (not captured): with a tiny window the push lands."""
    import asyncio

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    monkeypatch.setattr(svc, "checkin_only_fallback_seconds", lambda: 1)
    a = await _payment_attempt(db, paid, router, age_s=0.5)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert router_calls == []
    await asyncio.gather(*list(hsp._fallback_tasks))
    assert router_calls == [(M1, False)]
    await db.refresh(a)
    assert a.delivered_via == "push"


@pytest.mark.asyncio
async def test_fallback_leaves_an_attempt_another_push_already_has(pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    a.provisioning_state = ProvisioningState.IN_PROGRESS      # the retry job got there first
    await db.commit()
    delay, *args = fallbacks[0]
    assert await hsp._checkin_only_fallback_after(0, *args) is None
    assert router_calls == []


async def _retry_job_items(monkeypatch):
    groups_seen = []

    async def capture(groups):
        groups_seen.append(groups)

    monkeypatch.setattr(hsp, "_retry_db_pool_is_busy", lambda: False)
    monkeypatch.setattr(hsp, "_process_hotspot_retry_router_groups", capture)
    await hsp.retry_pending_hotspot_provisioning_background()
    return [item for g in groups_seen for lst in g.values() for item in lst]


@pytest.mark.asyncio
async def test_retry_job_leaves_a_waiting_attempt_to_the_checkin_then_takes_over(pilot, monkeypatch):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    waiting = await _payment_attempt(db, paid, router, age_s=30)
    overdue = await _payment_attempt(db, paid, router, age_s=120 + hsp.CHECKIN_FALLBACK_RETRY_SLACK_SECONDS + 5)
    manual = await _payment_attempt(db, paid, router, age_s=30,
                                    entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION)

    items = {item[0].id: item for item in await _retry_job_items(monkeypatch)}
    assert waiting.id not in items                     # waiting for the check-in
    assert overdue.id in items and items[overdue.id][4] is False   # full push: the backstop
    assert manual.id in items                          # never deferred

    # Kill switch: the push path owns every scheduled attempt again at once.
    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", True)
    items = {item[0].id for item in await _retry_job_items(monkeypatch)}
    assert waiting.id in items


@pytest.mark.asyncio
async def test_retry_job_unchanged_for_other_routers(pilot, monkeypatch):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, pilot_ids=str(router.id))       # both arm
    a = await _payment_attempt(db, paid, router, age_s=5)
    assert a.id in {item[0].id for item in await _retry_job_items(monkeypatch)}


@pytest.mark.asyncio
async def test_waiting_attempt_is_not_flagged_as_a_failure(pilot, monkeypatch):
    from app.services import ops_health
    from app.services import router_overload_alerts as oa

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    for _ in range(4):
        await _payment_attempt(db, paid, router, age_s=60)
    now = datetime.utcnow()
    assert not any(r[0] == router.id for r in await oa.find_payment_overload_candidates(now))
    section = await ops_health.build_provisioning_section(now)
    assert section["counts"]["retry_pending"] == 0 and section["counts"]["failed"] == 0
    assert hsp.derive_delivery_status(ProvisioningState.SCHEDULED, None) == "activating"


@pytest.mark.asyncio
async def test_checkin_only_router_is_fast_while_an_attempt_is_undelivered(client, pilot, monkeypatch):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    idle = svc.NORMAL_POLL_SECONDS - svc.NORMAL_POLL_JITTER_SECONDS
    resp = await _checkin(client, [M1, M2])
    assert _parse_frame(resp.text)[2] >= idle                      # idle polling stays slow
    # A payment waiting for the check-in (renewal while still bound, so no
    # A line applies): fast until it is settled.
    await _payment_attempt(db, paid, router)
    resp = await _checkin(client, [M1, M2])
    assert _parse_frame(resp.text)[2] == svc.FAST_POLL_SECONDS
    # push_only: the same undelivered payment does not speed the router up.
    monkeypatch.setattr(settings, "CHECKIN_ONLY_ROUTER_IDS", "")
    monkeypatch.setattr(settings, "CHECKIN_PUSH_ONLY_ROUTER_IDS", str(router.id))
    resp = await _checkin(client, [M1, M2])
    assert _parse_frame(resp.text)[2] >= idle


# ---------------------------------------------------------------------------
# Metrics per mode
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delivery_path_metrics_by_mode(pilot, monkeypatch):
    db, router, paid, reseller = pilot["db"], pilot["router"], pilot["paid"], pilot["reseller"]
    r_push = await make_router(db, reseller, identity="Router-0801")
    r_both = await make_router(db, reseller, identity="Router-0802")
    outside = pilot["other"]
    _arm(monkeypatch, push_only=str(r_push.id), checkin_only=str(router.id),
         pilot_ids=f"{router.id},{r_push.id},{r_both.id}")
    now = datetime.utcnow()

    async def add(rid, state, via, access_after_s, attempt_count,
                  entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT):
        created = now - timedelta(minutes=10)
        db.add(ProvisioningAttempt(
            customer_id=paid.id, router_id=rid, mac_address=paid.mac_address,
            source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_PK),
            entrypoint=entrypoint, provisioning_state=state, delivered_via=via,
            attempt_count=attempt_count, created_at=created, updated_at=created,
            access_seen_at=(created + timedelta(seconds=access_after_s)) if access_after_s is not None else None,
        ))

    U, R = ProvisioningState.ROUTER_UPDATED, ProvisioningState.RETRY_PENDING
    # checkin_only: two check-in deliveries, one fallback push, one still waiting.
    await add(router.id, U, "checkin", 12, 0)
    await add(router.id, U, "checkin", 20, 0, ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API)
    await add(router.id, U, "push", 125, 1)
    await add(router.id, ProvisioningState.SCHEDULED, None, None, 0)
    await add(router.id, U, "push", 3, 1, ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION)  # not A/B
    # push_only: first-try push, a retried push, one undelivered.
    await add(r_push.id, U, "push", 4, 1)
    await add(r_push.id, U, "push", 90, 3)
    await add(r_push.id, R, None, None, 2)
    # both: push first try, check-in rescue after a failed push.
    await add(r_both.id, U, "push", 5, 1)
    await add(r_both.id, U, "checkin", 70, 2)
    # Outside the pilot: never in the A/B.
    await add(outside.id, U, "push", 2, 1)
    await db.commit()

    m = (await svc.delivery_path_metrics(now))["by_mode"]
    co, po, both = m["checkin_only"], m["push_only"], m["both"]
    assert co["router_ids"] == [router.id] and po["router_ids"] == [r_push.id]
    assert both["router_ids"] == [r_both.id]
    assert (co["attempts"], co["delivered"], co["undelivered"], co["first_try"]) == (4, 3, 1, 2)
    assert co["fallbacks_triggered"] == 1 and co["first_try_pct"] == 50.0
    assert co["delivered_via"] == {"push": 1, "checkin": 2, "observed": 0, "other": 0}
    assert co["payment_to_access"] == {"samples": 3, "p50_seconds": 20.0, "p95_seconds": 125.0,
                                       "max_seconds": 125.0}
    assert (po["attempts"], po["delivered"], po["undelivered"], po["first_try"]) == (3, 2, 1, 1)
    assert po["fallbacks_triggered"] is None
    assert po["payment_to_access"]["max_seconds"] == 90.0
    assert (both["attempts"], both["delivered"], both["first_try"]) == (2, 2, 1)
    assert m["checkin_only_fallback_seconds"] == 120
    assert "hotspot_payment" in m["entrypoints"] and "manual_transaction_provision" not in m["entrypoints"]


@pytest.mark.asyncio
async def test_admin_endpoint_exposes_by_mode(pilot, monkeypatch):
    import app.api.admin_metrics_routes as routes

    _arm(monkeypatch, checkin_only=str(pilot["router"].id), pilot_ids=str(pilot["router"].id))

    async def no_auth(token, db):
        return None

    monkeypatch.setattr(routes, "_require_admin", no_auth)
    snap = await routes.admin_checkin_pilot_stats(db=pilot["db"], token="t")
    assert set(snap["delivery_paths_24h"]["by_mode"]) >= {"push_only", "checkin_only", "both"}
    assert snap["delivery_modes"]["checkin_only_router_ids"] == [pilot["router"].id]

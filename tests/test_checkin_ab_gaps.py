"""Follow-up gaps in the push-vs-check-in A/B (money path).

What these pin, and why:

* **Renewal while still bound** on a checkin_only router: the applier never
  edits a binding it did not add, so the payment would sit until the 120 s
  fallback (and count as a check-in failure). It goes to the push at once,
  whether the bound state is known at payment time (latest report) or only
  from the next report, and it is counted as ``renewal_handoffs``, not as a
  fallback.
* **Every attempt-creating payment path tells the check-in** (vouchers,
  reconciliation, device pairing, not only STK): its check-ins are never shed
  for pool pressure while the payment waits.
* **Honest metrics**: new device vs already bound latency, hand-offs, and
  deliveries that happened while the push path was failing (rescues).
* **Other strand risks**: the fallback pushes the customer's CURRENT MAC (a
  Reconnect during the wait must not re-add the old one), hands back at once
  when the channel stops being able to deliver, and a timer lost to a restart
  is re-armed by the retry job.
"""

import asyncio
import inspect
from datetime import datetime, timedelta

import pytest

from app.config import settings
from app.db.models import (
    CustomerStatus,
    ProvisioningAttempt,
    ProvisioningAttemptEntrypoint,
    ProvisioningAttemptSource,
    ProvisioningState,
)
from app.services import checkin_delivery as svc
from app.services import hotspot_provisioning as hsp
from tests.factories import make_router
from tests.test_checkin_delivery_mode import (  # noqa: F401  (pytest fixtures)
    M1,
    M2,
    _arm,
    _logs,
    _payload,
    _payment_attempt,
    _retry_job_items,
    fallbacks,
    router_calls,
)
from tests.test_router_checkin import (  # noqa: F401  (pytest fixtures)
    _checkin,
    _parse_frame,
    _report,
    client,
    pilot,
)

_PK = iter(range(2_900_000, 2_999_999))


@pytest.fixture(autouse=True)
async def _clean_state():
    svc.reset_state()
    hsp._fallback_waiters.clear()
    hsp._fallback_wake_reason.clear()
    hsp._push_inflight.clear()
    yield
    for task in list(hsp._fallback_tasks):
        task.cancel()
    if hsp._fallback_tasks:
        await asyncio.gather(*list(hsp._fallback_tasks), return_exceptions=True)
    hsp._fallback_waiters.clear()
    hsp._fallback_wake_reason.clear()
    hsp._push_inflight.clear()
    svc.reset_state()


def _pend(mac=M1, state="scheduled", entrypoint="hotspot_payment", attempt_id=1, age_s=5.0):
    return svc.PendingAttempt(attempt_id=attempt_id, customer_id=1, mac=mac, state=state,
                              created_at=datetime.utcnow() - timedelta(seconds=age_s),
                              entrypoint=entrypoint)


async def _drain():
    """Let background pushes (timers woken early, direct hand-offs) finish."""
    for _ in range(50):
        pending = [t for t in hsp._fallback_tasks if not t.done()]
        if not pending:
            return
        await asyncio.wait(pending, timeout=0.2)


# ---------------------------------------------------------------------------
# Gap 1: renewal while still bound on a checkin_only router
# ---------------------------------------------------------------------------

def test_handoff_candidates_are_waiting_payments_already_bound(monkeypatch):
    _arm(monkeypatch, checkin_only="7", pilot_ids="7")
    rep = _report([M1, M2], c=[M2])        # M1 foreign/pushed, M2 a leftover CHECKIN binding
    pending = [
        _pend(M1, attempt_id=1),
        _pend(M2, attempt_id=2),
        _pend(M1, state="in_progress", attempt_id=3),             # a push already has it
        _pend(M1, entrypoint="manual_transaction_provision", attempt_id=4),  # never deferred
        _pend("AA:BB:CC:00:00:09", attempt_id=5),                 # not bound: the A line's job
    ]
    got = svc.renewal_handoff_candidates(rep, pending, 7, now_mono=100.0)
    assert [p.attempt_id for p in got] == [1, 2]
    # Asked once, not on every check-in.
    assert svc.renewal_handoff_candidates(rep, pending, 7, now_mono=110.0) == []
    assert svc.stats_snapshot()["routers"][7]["renewal_handoffs_total"] == 2


def test_binding_the_checkin_added_for_this_payment_is_not_a_handoff(monkeypatch):
    _arm(monkeypatch, checkin_only="7", pilot_ids="7", grace=60)
    now = datetime.utcnow()
    p = svc.PendingAttempt(attempt_id=1, customer_id=1, mac=M1, state="scheduled",
                           created_at=now - timedelta(seconds=2), entrypoint="hotspot_payment")
    router = svc.RouterRef(id=7, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)
    d = svc.decide(router=router, report=_report([]), desired=[_entry_for(M1)],
                   undelivered_recent=True, mode="add", now=now, now_mono=100.0, pending=[p])
    assert [e.mac for e in d.lines] == [M1]
    confirm = _report([M1], c=[M1])
    assert svc.renewal_handoff_candidates(confirm, [p], 7, now_mono=105.0) == []
    assert [c.via for c in svc.delivery_candidates(confirm, [p], 7)] == ["checkin"]


def _entry_for(mac):
    return svc.DesiredEntry(mac=mac, rate="5M/5M", expiry_epoch=1790000000, ref=mac.replace(":", ""))


@pytest.mark.parametrize("arm", ["both", "push_only", "killed"])
def test_no_handoff_outside_an_active_checkin_only_router(monkeypatch, arm):
    if arm == "both":
        _arm(monkeypatch, pilot_ids="7")
    elif arm == "push_only":
        _arm(monkeypatch, push_only="7", pilot_ids="7")
    else:
        _arm(monkeypatch, checkin_only="7", pilot_ids="7")
        monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", True)
    assert svc.renewal_handoff_candidates(_report([M1]), [_pend(M1)], 7, now_mono=1.0) == []


@pytest.mark.asyncio
async def test_bound_at_payment_pushes_at_once_instead_of_deferring(
        client, pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    await _checkin(client, [M1, M2])                 # M1 still bound when they renew
    a = await _payment_attempt(db, paid, router)

    result = await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)

    assert router_calls == [(M1, False)] and fallbacks == []    # pushed now, no 120 s wait
    assert result["success"] is True and not result.get("deferred_to_checkin")
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED and a.delivered_via == "push"
    actions = [(l.action, l.status) for l in await _logs(db, a.id)]
    assert actions[0] == (svc.ACTION_BOUND_AT_PAYMENT, "bound")
    assert (hsp.CHECKIN_HANDOFF_ACTION, "started") in actions
    assert actions[-1] == (hsp.CHECKIN_HANDOFF_ACTION, "success")
    assert ("checkin_only_deferred", "deferred") not in actions


@pytest.mark.asyncio
async def test_new_device_is_still_deferred_and_marked_not_bound(
        client, pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    await _checkin(client, [M2])                     # M1 has no binding: a new device
    a = await _payment_attempt(db, paid, router)
    result = await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert result["deferred_to_checkin"] is True and router_calls == [] and len(fallbacks) == 1
    actions = [(l.action, l.status) for l in await _logs(db, a.id)]
    assert actions == [(svc.ACTION_BOUND_AT_PAYMENT, "not_bound"), ("checkin_only_deferred", "deferred")]


@pytest.mark.asyncio
async def test_next_report_showing_the_mac_bound_hands_off_to_the_push(client, pilot, monkeypatch, router_calls):
    """Bound state unknown at payment (no report yet): deferred. The next
    report shows the MAC bound, so the waiting timer is woken and the push
    runs at once instead of at the fallback deadline."""
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id), fallback=600)
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    assert router_calls == [] and a.id in hsp._fallback_waiters

    resp = await _checkin(client, [M1, M2])
    assert _parse_frame(resp.text)[3] == []           # nothing for the applier to do
    await _drain()

    assert router_calls == [(M1, False)]
    await db.refresh(a)
    assert a.provisioning_state == ProvisioningState.ROUTER_UPDATED and a.delivered_via == "push"
    actions = [(l.action, l.status) for l in await _logs(db, a.id)]
    assert (hsp.CHECKIN_HANDOFF_ACTION, "started") in actions
    assert ("checkin_only_fallback", "started") not in actions
    # The next report changes nothing (attempt settled, hand-off remembered).
    await _checkin(client, [M1, M2])
    await _drain()
    assert router_calls == [(M1, False)]


@pytest.mark.asyncio
async def test_handoff_with_no_timer_after_a_restart_pushes_directly(
        client, pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    hsp._fallback_waiters.clear()                     # restart: the timer is gone

    await _checkin(client, [M1, M2])
    await _drain()
    assert router_calls == [(M1, False)]
    await db.refresh(a)
    assert a.delivered_via == "push"


# ---------------------------------------------------------------------------
# Gap 2: every attempt-creating path tells the check-in
# ---------------------------------------------------------------------------

async def _create_attempt(db, customer, router, entrypoint):
    attempt = await hsp.get_or_create_provisioning_attempt(
        db, customer_id=customer.id, router_id=router.id, mac_address=customer.mac_address,
        source_table=ProvisioningAttemptSource.CUSTOMER_PAYMENT, source_pk=next(_PK),
        external_reference="V-1", entrypoint=entrypoint,
    )
    await db.commit()
    return attempt


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", [
    ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API,
    ProvisioningAttemptEntrypoint.HOTSPOT_RECONCILIATION,
    ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT,
])
async def test_attempt_creation_marks_the_router_waiting(pilot, monkeypatch, entrypoint):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    assert not svc.shed_exempt(router.id)
    await _create_attempt(db, paid, router, entrypoint)
    assert svc.shed_exempt(router.id)
    # It does not touch the poll cadence (the undelivered attempt does that).
    assert not svc.payment_hint_active(router.id)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["manual", "push_only", "disabled", "not_in_pilot"])
async def test_attempt_creation_hint_scope(pilot, monkeypatch, case):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    entrypoint = ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API
    if case == "manual":
        entrypoint = ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION
    elif case == "push_only":
        _arm(monkeypatch, push_only=str(router.id), pilot_ids=str(router.id))
    elif case == "disabled":
        monkeypatch.setattr(settings, "CHECKIN_ENABLED", False)
    else:
        monkeypatch.setattr(settings, "CHECKIN_ROUTER_IDS", "")
    await _create_attempt(db, paid, router, entrypoint)
    assert not svc.shed_exempt(router.id)


@pytest.mark.asyncio
async def test_attempt_creation_survives_a_broken_hint(pilot, monkeypatch):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]

    def boom(*a, **k):
        raise RuntimeError("hint broke")

    monkeypatch.setattr(svc, "note_attempt_created", boom)
    a = await _create_attempt(db, paid, router, ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API)
    assert a.id is not None and a.provisioning_state == ProvisioningState.SCHEDULED


@pytest.mark.asyncio
async def test_waiting_router_is_not_shed_for_pool_pressure(client, pilot, monkeypatch):
    import app.api.router_checkin_routes as routes

    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    await _checkin(client, [M2])                     # router ref cached; M1 not bound
    monkeypatch.setattr(routes, "_pool_under_pressure", lambda: True)
    shed = await _checkin(client, [M2])
    assert _parse_frame(shed.text)[1] == 0 and _parse_frame(shed.text)[2] == svc.NORMAL_POLL_SECONDS

    await _create_attempt(db, paid, router, ProvisioningAttemptEntrypoint.VOUCHER_DIRECT_API)
    served = await _checkin(client, [M2])
    assert [o["mac"] for o in _parse_frame(served.text)[3]] == [M1]   # voucher delivered


def test_stk_initiation_paths_send_the_payment_hint():
    from app.api import device_pairing, payment_routes

    for fn in (payment_routes.initiate_mpesa_payment_api, payment_routes.register_hotspot_and_pay_api,
               device_pairing.pair_device_and_pay):
        assert "note_payment_initiated(" in inspect.getsource(fn), fn.__name__


# ---------------------------------------------------------------------------
# Gap 3: metrics
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_metrics_split_handoffs_devices_and_rescues(pilot, monkeypatch):
    from app.db.models import ProvisioningLog

    db, router, paid, reseller = pilot["db"], pilot["router"], pilot["paid"], pilot["reseller"]
    r_push = await make_router(db, reseller, identity="Router-0811")
    _arm(monkeypatch, push_only=str(r_push.id), checkin_only=str(router.id),
         pilot_ids=f"{router.id},{r_push.id}")
    now = datetime.utcnow()
    created = now - timedelta(minutes=10)
    U = ProvisioningState.ROUTER_UPDATED

    async def add(rid, state, via, access_after_s, attempt_count, logs=()):
        a = ProvisioningAttempt(
            customer_id=paid.id, router_id=rid, mac_address=paid.mac_address,
            source_table=ProvisioningAttemptSource.MPESA_TRANSACTION, source_pk=next(_PK),
            entrypoint=ProvisioningAttemptEntrypoint.HOTSPOT_PAYMENT, provisioning_state=state,
            delivered_via=via, attempt_count=attempt_count, created_at=created, updated_at=created,
            access_seen_at=(created + timedelta(seconds=access_after_s)) if access_after_s is not None else None,
        )
        db.add(a)
        await db.flush()
        for action, status in logs:
            db.add(ProvisioningLog(customer_id=paid.id, router_id=rid, attempt_id=a.id, mac_address=M1,
                                   action=action, status=status, log_date=created))

    bound = (svc.ACTION_BOUND_AT_PAYMENT, "bound")
    new = (svc.ACTION_BOUND_AT_PAYMENT, "not_bound")
    handoff = (svc.ACTION_RENEWAL_HANDOFF, "started")
    # checkin_only: check-in new device x2, a renewal hand-off, a real fallback,
    # and a fallback whose push failed once before the retry landed.
    await add(router.id, U, "checkin", 10, 0, [new])
    await add(router.id, U, "checkin", 30, 0, [new])
    await add(router.id, U, "push", 4, 1, [bound, handoff, (svc.ACTION_RENEWAL_HANDOFF, "success")])
    await add(router.id, U, "push", 125, 1, [new])
    await add(router.id, U, "push", 400, 2, [("checkin_only_fallback", "retry_pending")])
    # push_only: a renewal push, a new-device push, a push that failed then landed.
    await add(r_push.id, U, "push", 2, 1, [bound])
    await add(r_push.id, U, "push", 6, 1, [new])
    await add(r_push.id, U, "observed", 300, 1, [new, ("hotspot_payment", "retry_pending")])
    await db.commit()

    m = (await svc.delivery_path_metrics(now))["by_mode"]
    co, po = m["checkin_only"], m["push_only"]
    assert co["attempts"] == 5 and co["renewal_handoffs"] == 1
    assert co["fallbacks_triggered"] == 2                     # the hand-off is not a fallback
    assert co["first_try"] == 2 and co["first_try_pct"] == 50.0   # 2 of the 4 judged
    dev = co["payment_to_access_by_device"]
    assert dev["new_device"]["samples"] == 3 and dev["new_device"]["p50_seconds"] == 30.0
    assert dev["already_bound"]["samples"] == 1 and dev["already_bound"]["max_seconds"] == 4.0
    assert dev["unknown"]["samples"] == 1
    assert co["push_failed"] == 1 and co["rescues"]["total"] == 1
    assert co["rescues"]["delivered_via"]["push"] == 1

    assert po["renewal_handoffs"] is None and po["fallbacks_triggered"] is None
    assert po["payment_to_access_by_device"]["already_bound"]["samples"] == 1
    assert po["payment_to_access_by_device"]["new_device"]["samples"] == 2
    assert po["push_failed"] == 1
    assert po["rescues"] == {"total": 1, "delivered_via": {"push": 0, "checkin": 0, "observed": 1, "other": 0}}


@pytest.mark.asyncio
async def test_push_path_writes_the_bound_marker_on_every_pilot_arm(client, pilot, monkeypatch, router_calls):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, pilot_ids=str(router.id))       # both arm: push at payment time
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    # No check-in report yet: no marker (the metrics count it as unknown).
    assert svc.ACTION_BOUND_AT_PAYMENT not in [l.action for l in await _logs(db, a.id)]

    await _checkin(client, [M1, M2])
    b = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", b.id)
    # A retry of the same attempt does not write a second marker.
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_retry", b.id)
    markers = [(l.action, l.status) for l in await _logs(db, b.id) if l.action == svc.ACTION_BOUND_AT_PAYMENT]
    assert markers == [(svc.ACTION_BOUND_AT_PAYMENT, "bound")]


def test_bound_lookup_needs_a_fresh_trusted_report(monkeypatch):
    _arm(monkeypatch, pilot_ids="7")
    router = svc.RouterRef(id=7, auth_method="direct_api", lb_enabled=False, fetched_at=0.0)
    assert svc.mac_bound_on_router(7, M1) is None
    svc.decide(router=router, report=_report([M1], o=[M2]), desired=[], undelivered_recent=False,
               mode="add", now=datetime.utcnow(), now_mono=1000.0)
    assert svc.mac_bound_on_router(7, M1.lower(), now_mono=1001.0) is True
    assert svc.mac_bound_on_router(7, M2, now_mono=1001.0) is True          # o= counts as bound
    assert svc.mac_bound_on_router(7, "AA:BB:CC:00:00:09", now_mono=1001.0) is False
    assert svc.mac_bound_on_router(7, M1, now_mono=1000.0 + svc.REPORT_FRESH_SECONDS + 1) is None
    # A truncated report is not trusted: the previous one stays.
    bad = svc.parse_checkin_body(f"v=1&id=R&n=5&macs={M2}".encode())
    svc.decide(router=router, report=bad, desired=[], undelivered_recent=False, mode="add",
               now=datetime.utcnow(), now_mono=1002.0)
    assert svc.mac_bound_on_router(7, M1, now_mono=1003.0) is True


# ---------------------------------------------------------------------------
# Gap 4: other ways a paying customer could be stranded
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fallback_pushes_the_current_mac_after_a_reconnect(pilot, monkeypatch, router_calls, fallbacks):
    """Captured payload = the MAC at payment time. A Reconnect during the wait
    moves the customer to a new MAC; pushing the old one would re-add it as
    an orphan binding (the 2026-09-26 bug class)."""
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    paid.mac_address = "AA:BB:CC:00:00:0F"
    await db.commit()

    delay, *args = fallbacks[0]
    await hsp._checkin_only_fallback_after(0, *args)
    assert router_calls == [("AA:BB:CC:00:00:0F", False)]


@pytest.mark.asyncio
async def test_fallback_does_not_push_a_customer_no_longer_entitled(pilot, monkeypatch, router_calls, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    paid.status = CustomerStatus.INACTIVE
    await db.commit()
    delay, *args = fallbacks[0]
    assert await hsp._checkin_only_fallback_after(0, *args) is None
    assert router_calls == []


@pytest.mark.asyncio
async def test_waiting_timer_hands_back_when_the_channel_is_switched_off(pilot, monkeypatch, router_calls):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id), fallback=600)
    monkeypatch.setattr(hsp, "CHECKIN_HANDBACK_POLL_SECONDS", 0.05)
    a = await _payment_attempt(db, paid, router)
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    await asyncio.sleep(0.1)
    assert router_calls == []

    monkeypatch.setattr(settings, "CHECKIN_KILL_SWITCH", True)
    await _drain()
    assert router_calls == [(M1, False)]
    actions = [(l.action, l.status) for l in await _logs(db, a.id)]
    assert (hsp.CHECKIN_HANDBACK_ACTION, "started") in actions


@pytest.mark.asyncio
async def test_fallback_fires_on_time_when_the_router_never_checks_in(pilot, monkeypatch, router_calls):
    """No report ever arrives: the in-process timer alone pushes, at the
    deadline (not later: the hand-back poll does not stretch it)."""
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    monkeypatch.setattr(svc, "checkin_only_fallback_seconds", lambda: 1)
    a = await _payment_attempt(db, paid, router, age_s=0.7)
    started = asyncio.get_running_loop().time()
    await hsp.provision_hotspot_customer(paid.id, router.id, _payload(paid), "hotspot_payment", a.id)
    await _drain()
    assert router_calls == [(M1, False)]
    assert asyncio.get_running_loop().time() - started < 2.0


@pytest.mark.asyncio
async def test_retry_job_rearms_timers_lost_to_a_restart(pilot, monkeypatch, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, checkin_only=str(router.id), pilot_ids=str(router.id))
    young = await _payment_attempt(db, paid, router, age_s=30)
    due = await _payment_attempt(db, paid, router, age_s=125)       # past the window, inside the hold
    manual = await _payment_attempt(db, paid, router, age_s=30,
                                    entrypoint=ProvisioningAttemptEntrypoint.MANUAL_TRANSACTION_PROVISION)

    items = {item[0].id for item in await _retry_job_items(monkeypatch)}

    armed = {args[4]: args[0] for args in fallbacks}
    assert set(armed) == {young.id, due.id}
    assert 85 <= armed[young.id] <= 90 and armed[due.id] == 0
    assert young.id not in items and due.id not in items and manual.id in items

    # A second tick does not arm twice while the timers are alive.
    for attempt_id in armed:
        hsp._fallback_waiters[attempt_id] = asyncio.Event()
    fallbacks.clear()
    await _retry_job_items(monkeypatch)
    assert fallbacks == []


@pytest.mark.asyncio
async def test_rearm_is_a_no_op_without_checkin_only_routers(pilot, monkeypatch, fallbacks):
    db, router, paid = pilot["db"], pilot["router"], pilot["paid"]
    _arm(monkeypatch, pilot_ids=str(router.id))
    await _payment_attempt(db, paid, router, age_s=30)
    assert await hsp.rearm_checkin_only_fallbacks() == 0 and fallbacks == []


def test_handoff_action_matches_the_metric_marker():
    assert hsp.CHECKIN_HANDOFF_ACTION == svc.ACTION_RENEWAL_HANDOFF
    assert {hsp.CHECKIN_HANDOFF_ACTION, hsp.CHECKIN_HANDBACK_ACTION, hsp.CHECKIN_FALLBACK_ACTION} <= hsp._NEVER_DEFER_ACTIONS


def test_changed_modules_pass_the_session_discipline_guard():
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo / "scripts"))
    from check_session_discipline import run_check

    failing, _, _ = run_check(
        ["app/services/checkin_delivery.py", "app/api/router_checkin_routes.py",
         "app/services/hotspot_provisioning.py"],
        repo / "scripts" / "session_discipline_allowlist.txt",
    )
    assert failing == []


def test_handoff_background_task_runs_on_the_event_loop():
    """A sync BackgroundTask runs in Starlette's threadpool: no event loop,
    so the hand-off could neither wake a timer nor start a push."""
    import app.api.router_checkin_routes as routes

    assert inspect.iscoroutinefunction(routes._hand_off)

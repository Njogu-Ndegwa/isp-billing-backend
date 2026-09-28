"""Router EXP deadlines follow an expiry that moved later outside a payment
(outage compensation, admin edit, pairing): app/services/expiry_tag_sync.py.

The one property that matters most: a deadline is only ever moved LATER, so
nothing here can make a router remove a paying customer early.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db import database
from app.db.models import CustomerStatus, ProvisioningLog, RouterAuthMethod
from app.services import expiry_tag_sync as sync
from app.services.expiry_tag_sync import plan_fixes, tag_seconds
from app.services.router_expiry import expiry_second
from tests.factories import make_customer, make_plan, make_reseller, make_router

MAC = "AA:BB:CC:00:00:01"
MAC2 = "AA:BB:CC:00:00:02"
MAC3 = "AA:BB:CC:00:00:03"
EXP = datetime(2026, 9, 28, 18, 0, 0, 400000)


def binding(mac, comment, bid="*1"):
    return {".id": bid, "mac-address": mac, "type": "bypassed", "comment": comment}


# --- pure rule ---------------------------------------------------------------

def test_early_tag_is_moved_to_the_paid_expiry_in_place():
    old = expiry_second(EXP - timedelta(hours=6))
    comment = f"USER:AABBCC000001|EXPIRES:DB_MANAGED|CHECKIN|EXP:{old}|2026-09-28 10:00:00"
    [fix] = plan_fixes([binding(MAC, comment)], {MAC: (7, EXP)})
    assert fix.old_tag == old and fix.new_tag == expiry_second(EXP)
    # layout kept: only the digits change
    assert fix.new_comment == comment.replace(str(old), str(expiry_second(EXP)))
    assert fix.customer_id == 7


def test_tag_at_or_after_the_paid_expiry_is_never_lowered():
    for tag in (expiry_second(EXP), expiry_second(EXP) + 3600):
        assert plan_fixes([binding(MAC, f"USER:x|EXP:{tag}")], {MAC: (7, EXP)}) == []


def test_minute_tags_from_the_first_pilot_are_read_as_minutes():
    minute = expiry_second(EXP) // 60 - 30     # 30 min early, in minutes
    assert tag_seconds(f"EXP:{minute}") == minute * 60
    [fix] = plan_fixes([binding(MAC, f"USER:x|EXP:{minute}")], {MAC: (7, EXP)})
    assert fix.new_tag == expiry_second(EXP)
    # a minute tag that is not early is left alone
    late_minute = expiry_second(EXP) // 60 + 1
    assert plan_fixes([binding(MAC, f"USER:x|EXP:{late_minute}")], {MAC: (7, EXP)}) == []


@pytest.mark.parametrize("comment", [
    "USER:x|EXPIRES:DB_MANAGED|2026-09-28",          # no deadline: the reaper ignores it
    "USER:x|EXX:1790000000",                         # forgotten by the reaper
    "",
])
def test_bindings_the_reaper_does_not_enforce_are_left(comment):
    assert plan_fixes([binding(MAC, comment)], {MAC: (7, EXP)}) == []


def test_bindings_of_other_macs_are_left():
    assert plan_fixes([binding(MAC2, "EXP:1000000001")], {MAC: (7, EXP)}) == []


# --- fakes ------------------------------------------------------------------

OPEN_SESSIONS = {"n": 0}


def counting(session_factory):
    @asynccontextmanager
    async def factory():
        OPEN_SESSIONS["n"] += 1
        try:
            async with session_factory() as s:
                yield s
        finally:
            OPEN_SESSIONS["n"] -= 1
    return factory


class FakeRouterOS:
    def __init__(self, bindings, reachable=True):
        self.bindings = bindings
        self.reachable = reachable
        self.sets = []
        self.on_print = None      # hook: simulate a payment landing between reads

    def connect(self):
        assert OPEN_SESSIONS["n"] == 0, "DB session held across RouterOS I/O"
        return self.reachable

    def disconnect(self):
        pass

    def send_command(self, cmd, args=None):
        if cmd == "/ip/hotspot/ip-binding/print":
            if self.on_print:
                self.on_print(self)
            return {"data": [dict(b) for b in self.bindings]}
        if cmd == "/ip/hotspot/ip-binding/set":
            self.sets.append(dict(args))
            for b in self.bindings:
                if b[".id"] == args[".id"]:
                    b["comment"] = args["comment"]
            return {"data": []}
        return {"data": []}


@pytest.fixture
def wired(session_factory, monkeypatch):
    OPEN_SESSIONS["n"] = 0
    monkeypatch.setattr(database, "async_session", counting(session_factory))
    monkeypatch.setattr(sync.settings, "EXPIRY_TAG_SYNC_ENABLED", True)
    monkeypatch.setattr(sync, "_running", False)
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: False)
    routers: dict[str, FakeRouterOS] = {}
    monkeypatch.setattr(sync, "MikroTikAPI", lambda ip, *a, **k: routers[ip])
    return routers


async def _setup(db, ip="10.0.9.1", reaper=True, **router_kw):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller, ip_address=ip, expiry_reaper_enabled=reaper, **router_kw)
    return reseller, plan, router


def _future(hours):
    return (datetime.utcnow() + timedelta(hours=hours)).replace(microsecond=0)


# --- behaviour ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_compensated_customer_gets_the_new_deadline_and_an_audit_row(db, wired):
    reseller, plan, router = await _setup(db)
    new_expiry = _future(8)
    c = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=new_expiry, mac_address=MAC)
    old = expiry_second(new_expiry - timedelta(hours=6))
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, f"USER:AABBCC000001|EXP:{old}|t")])

    fixed = await sync.sync_expiry_tags([c.id], "outage compensation run 1")

    assert fixed == 1
    assert tag_seconds(fake.bindings[0]["comment"]) == expiry_second(new_expiry)
    log = (await db.execute(select(ProvisioningLog).where(
        ProvisioningLog.action == sync.LOG_ACTION))).scalars().one()
    assert log.customer_id == c.id and "outage compensation" in log.details


@pytest.mark.asyncio
async def test_the_latest_paid_row_for_a_mac_wins(db, wired):
    reseller, plan, router = await _setup(db)
    short, longer = _future(1), _future(5)
    a = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=short, mac_address=MAC)
    other = await make_reseller(db)     # (mac, reseller) is unique; phantom rows differ by owner
    await make_customer(db, other, plan, router, status=CustomerStatus.ACTIVE,
                        expiry=longer, mac_address=MAC)
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, f"EXP:{expiry_second(short)}")])

    await sync.sync_expiry_tags([a.id], "admin expiry edit")

    assert tag_seconds(fake.bindings[0]["comment"]) == expiry_second(longer)


@pytest.mark.asyncio
async def test_a_payment_landing_meanwhile_is_never_overwritten_earlier(db, wired):
    """Between our first read and our write a payment writes a LATER tag: we
    must leave it."""
    reseller, plan, router = await _setup(db)
    comp_expiry = _future(3)
    c = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=comp_expiry, mac_address=MAC)
    early = expiry_second(comp_expiry) - 3600
    paid_later = expiry_second(comp_expiry) + 86400
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, f"EXP:{early}")])
    prints = {"n": 0}

    def payment_lands(r):
        prints["n"] += 1
        if prints["n"] == 2:          # the re-read just before writing
            r.bindings[0]["comment"] = f"EXP:{paid_later}"
    fake.on_print = payment_lands

    assert await sync.sync_expiry_tags([c.id], "outage compensation run 2") == 0
    assert fake.sets == []
    assert tag_seconds(fake.bindings[0]["comment"]) == paid_later


@pytest.mark.asyncio
async def test_an_expiry_shortened_meanwhile_is_not_raised_past_the_database(db, wired):
    reseller, plan, router = await _setup(db)
    c = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=_future(6), mac_address=MAC)
    early = expiry_second(_future(1))
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, f"EXP:{early}")])

    async def expired_meanwhile(router_id, macs, now):
        return {}                     # the fresh read finds no paid row any more
    sync_fresh = sync.fresh_wanted
    try:
        sync.fresh_wanted = expired_meanwhile
        assert await sync.sync_expiry_tags([c.id], "admin expiry edit") == 0
    finally:
        sync.fresh_wanted = sync_fresh
    assert fake.sets == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["pppoe", "not_reaper", "radius", "expired"])
async def test_customers_and_routers_outside_the_reaper_are_never_touched(db, wired, case):
    kw = {"auth_method": RouterAuthMethod.RADIUS} if case == "radius" else {}
    reseller, plan, router = await _setup(db, reaper=(case != "not_reaper"), **kw)
    c = await make_customer(
        db, reseller, plan, router,
        status=CustomerStatus.INACTIVE if case == "expired" else CustomerStatus.ACTIVE,
        expiry=_future(-1) if case == "expired" else _future(4),
        mac_address=MAC, pppoe_username="pp1" if case == "pppoe" else None)
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, "EXP:1000000001")])

    assert await sync.sync_expiry_tags([c.id], "admin expiry edit") == 0
    assert fake.sets == []


@pytest.mark.asyncio
async def test_unreachable_router_is_left_for_the_reconcile(db, wired):
    reseller, plan, router = await _setup(db)
    c = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=_future(4), mac_address=MAC)
    wired["10.0.9.1"] = FakeRouterOS([binding(MAC, "EXP:1000000001")], reachable=False)
    assert await sync.sync_expiry_tags([c.id], "admin expiry edit") == 0


@pytest.mark.asyncio
async def test_reconcile_fixes_every_reaper_router_and_skips_the_rest(db, wired):
    reseller, plan, r1 = await _setup(db, ip="10.0.9.1")
    r2 = await make_router(db, reseller, ip_address="10.0.9.2", expiry_reaper_enabled=True)
    r3 = await make_router(db, reseller, ip_address="10.0.9.3", expiry_reaper_enabled=False)
    e1, e2 = _future(3), _future(9)
    await make_customer(db, reseller, plan, r1, status=CustomerStatus.ACTIVE, expiry=e1, mac_address=MAC)
    await make_customer(db, reseller, plan, r2, status=CustomerStatus.ACTIVE, expiry=e2, mac_address=MAC2)
    await make_customer(db, reseller, plan, r3, status=CustomerStatus.ACTIVE, expiry=e2, mac_address=MAC3)
    f1 = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, f"EXP:{expiry_second(e1) - 600}")])
    f2 = wired["10.0.9.2"] = FakeRouterOS([binding(MAC2, f"EXP:{expiry_second(e2)}")])   # already right
    f3 = wired["10.0.9.3"] = FakeRouterOS([binding(MAC3, "EXP:1000000001")])

    assert await sync.expiry_tag_reconcile_background() == 1
    assert tag_seconds(f1.bindings[0]["comment"]) == expiry_second(e1)
    assert f2.sets == [] and f3.sets == []


@pytest.mark.asyncio
async def test_reconcile_switched_off_or_pool_busy_does_nothing(db, wired, monkeypatch):
    reseller, plan, router = await _setup(db)
    await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                        expiry=_future(4), mac_address=MAC)
    fake = wired["10.0.9.1"] = FakeRouterOS([binding(MAC, "EXP:1000000001")])
    monkeypatch.setattr(sync.settings, "EXPIRY_TAG_SYNC_ENABLED", False)
    assert await sync.expiry_tag_reconcile_background() == 0
    monkeypatch.setattr(sync.settings, "EXPIRY_TAG_SYNC_ENABLED", True)
    from app.services import mikrotik_background
    monkeypatch.setattr(mikrotik_background, "_background_db_pool_is_busy", lambda _n: True)
    assert await sync.expiry_tag_reconcile_background() == 0
    assert fake.sets == []


@pytest.mark.asyncio
async def test_sync_never_raises(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("db down")
    monkeypatch.setattr(sync.settings, "EXPIRY_TAG_SYNC_ENABLED", True)
    monkeypatch.setattr(sync, "load_targets", boom)
    assert await sync.sync_expiry_tags([1], "x") == 0


def test_sync_is_on_by_default():
    from app.config import Settings
    assert Settings.model_fields["EXPIRY_TAG_SYNC_ENABLED"].default is True


# --- the callers ----------------------------------------------------------------

@pytest.mark.asyncio
async def test_outage_compensation_schedules_a_tag_sync_for_credited_customers(db, monkeypatch):
    from app.services import outage_compensation as oc
    calls = []
    monkeypatch.setattr(sync, "schedule_expiry_tag_sync", lambda ids, reason: calls.append((list(ids), reason)))
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    now = datetime.utcnow()
    c = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                            expiry=now + timedelta(hours=2), mac_address=MAC,
                            created_at=now - timedelta(days=3))
    await oc.apply_outage_compensation(
        db, reseller_id=reseller.id, router_ids=[router.id],
        outage_start=now - timedelta(hours=3), outage_end=now - timedelta(hours=1),
    )
    assert len(calls) == 1 and c.id in calls[0][0] and "outage compensation" in calls[0][1]


def test_admin_expiry_edit_schedules_a_tag_sync():
    import inspect
    from app.api import customer_routes
    src = inspect.getsource(customer_routes)
    assert 'schedule_expiry_tag_sync([customer.id], "admin expiry edit")' in src

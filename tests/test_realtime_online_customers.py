"""Online / Offline filter on the Customers page: which customers are online on
routers that report in real time.

The answer comes from the push state already in memory, so the page can filter
every customer a reseller has without polling each router.
"""

from datetime import datetime, timedelta

import pytest

from app.api import usage_routes
from app.db.models import ConnectionType, CustomerStatus
from app.services import realtime_state
from app.services.realtime_state import HostSample, PppSample
from tests.factories import make_customer, make_plan, make_reseller, make_router


@pytest.fixture(autouse=True)
def _clean_state():
    realtime_state.reset_realtime_state()
    yield
    realtime_state.reset_realtime_state()


def _push(router_id, *, hosts=(), live_customers=None, ppp=(), live_pppoe=None, now=None):
    realtime_state.note_realtime_report(router_id, now)
    realtime_state.record_push(
        router_id,
        now=now or datetime.utcnow(),
        interval_seconds=60,
        hosts=list(hosts),
        queues=[],
        live_customers=live_customers or {},
        ppp_sessions=list(ppp),
        live_pppoe_customers=live_pppoe or {},
    )


@pytest.mark.asyncio
async def test_online_customers_on_live_routers_scoped_to_the_caller(db, monkeypatch):
    reseller = await make_reseller(db)
    other = await make_reseller(db)
    live_router = await make_router(db, reseller)
    polled_router = await make_router(db, reseller)
    other_router = await make_router(db, other)
    hotspot = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    pppoe = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE)
    other_plan = await make_plan(db, other, connection_type=ConnectionType.HOTSPOT)
    expiry = datetime.utcnow() + timedelta(days=3)

    online_hs = await make_customer(db, reseller, hotspot, live_router, mac_address="AA:00:00:00:00:01",
                                    status=CustomerStatus.ACTIVE, expiry=expiry)
    offline_hs = await make_customer(db, reseller, hotspot, live_router, mac_address="AA:00:00:00:00:02",
                                     status=CustomerStatus.ACTIVE, expiry=expiry)
    online_ppp = await make_customer(db, reseller, pppoe, live_router, pppoe_username="techmid-1",
                                     status=CustomerStatus.ACTIVE, expiry=expiry)
    offline_ppp = await make_customer(db, reseller, pppoe, live_router, pppoe_username="techmid-2",
                                      status=CustomerStatus.ACTIVE, expiry=expiry)
    on_polled_router = await make_customer(db, reseller, hotspot, polled_router, mac_address="AA:00:00:00:00:03",
                                           status=CustomerStatus.ACTIVE, expiry=expiry)
    other_online = await make_customer(db, other, other_plan, other_router, mac_address="AA:00:00:00:00:04",
                                       status=CustomerStatus.ACTIVE, expiry=expiry)

    _push(
        live_router.id,
        hosts=[HostSample(mac="AA:00:00:00:00:01", ip="10.5.50.10", bytes_in=1, bytes_out=1)],
        live_customers={"AA:00:00:00:00:01": online_hs.id, "AA:00:00:00:00:02": offline_hs.id},
        ppp=[PppSample(name="techmid-1", address="10.10.0.2")],
        live_pppoe={"pppoe:techmid-1": online_ppp.id, "pppoe:techmid-2": offline_ppp.id},
    )
    _push(
        other_router.id,
        hosts=[HostSample(mac="AA:00:00:00:00:04", ip="10.5.50.11", bytes_in=1, bytes_out=1)],
        live_customers={"AA:00:00:00:00:04": other_online.id},
    )

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    result = await usage_routes.list_realtime_online_customers(db=db, token="t")

    assert result.router_ids == [live_router.id]
    assert result.online_customer_ids == sorted([online_hs.id, online_ppp.id])
    assert on_polled_router.id not in result.online_customer_ids
    assert other_online.id not in result.online_customer_ids


@pytest.mark.asyncio
async def test_a_router_that_stopped_reporting_is_not_covered(db, monkeypatch):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    customer = await make_customer(db, reseller, plan, router, mac_address="AA:00:00:00:00:09",
                                   status=CustomerStatus.ACTIVE,
                                   expiry=datetime.utcnow() + timedelta(days=1))
    stale = datetime.utcnow() - timedelta(minutes=10)
    _push(
        router.id,
        now=stale,
        hosts=[HostSample(mac="AA:00:00:00:00:09", ip="10.5.50.12", bytes_in=1, bytes_out=1)],
        live_customers={"AA:00:00:00:00:09": customer.id},
    )

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    result = await usage_routes.list_realtime_online_customers(db=db, token="t")

    # Ten minutes of silence: the router is handed back to the monitor
    # endpoints rather than reporting its customers from a stale push.
    assert result.router_ids == []
    assert result.online_customer_ids == []


@pytest.mark.asyncio
async def test_the_customer_list_keeps_only_who_is_online(db, monkeypatch):
    """"Show me those online now" reads the customer list with online=true: whole
    customer rows (names, plans), not bare ids the chat cannot draw."""
    from app.api import customer_routes

    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    expiry = datetime.utcnow() + timedelta(days=2)
    on = await make_customer(db, reseller, plan, router, name="Calvins", mac_address="AA:00:00:00:00:21",
                             status=CustomerStatus.ACTIVE, expiry=expiry)
    off = await make_customer(db, reseller, plan, router, name="Idle", mac_address="AA:00:00:00:00:22",
                              status=CustomerStatus.ACTIVE, expiry=expiry)
    _push(router.id, hosts=[HostSample(mac="AA:00:00:00:00:21", ip="10.5.50.21", bytes_in=1, bytes_out=1)],
          live_customers={"AA:00:00:00:00:21": on.id, "AA:00:00:00:00:22": off.id})

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(customer_routes, "get_current_user", _current_user)
    online = await customer_routes.get_customers_api(router_id=None, tier=None, online=True, db=db, token="t")
    offline = await customer_routes.get_customers_api(router_id=None, tier=None, online=False, db=db, token="t")
    assert [c["name"] for c in online] == ["Calvins"]
    assert [c["name"] for c in offline] == ["Idle"]

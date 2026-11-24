"""CR-1123-B4: the assistant's answers about who is offline and when a router went down.

2026-11-23: a router whose last contact was 08:42 was reported "down at 08:53" (when
Bitwave's checks began failing); a static-IP customer with access enabled but a stale
ARP entry was reported "not offline". The data the model reads now says both plainly.
"""
from datetime import datetime, timedelta

import pytest

from app.api import router_management
from app.db.models import ConnectionType, CustomerStatus, RouterAvailabilityCheck
from app.services import static_ip
from app.services.assistant import agent as agent_mod
from tests.factories import make_customer, make_plan, make_router
from tests.fake_routeros import FakeRouterOS
from tests.test_assistant import auth, client, owner  # noqa: F401  (fixtures)


def _at(value) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", ""))


async def _router_down_since_0842(db, reseller):
    """Reports every 5 min until "08:42", then only failed checks from "08:53" to now."""
    now = datetime.utcnow().replace(microsecond=0)
    last_contact = now - timedelta(minutes=67)       # "08:42"
    first_failure = last_contact + timedelta(minutes=11)  # "08:53"
    router = await make_router(db, reseller, name="AFODACOM 1")
    t = now - timedelta(hours=6)
    while t <= last_contact:
        db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=t, is_online=True, source="usage_push"))
        t += timedelta(minutes=5)
    db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=last_contact, is_online=True,
                                   source="usage_push"))
    t = first_failure
    while t <= now:
        db.add(RouterAvailabilityCheck(router_id=router.id, checked_at=t, is_online=False,
                                       source="reachability_probe"))
        t += timedelta(minutes=5)
    router.last_status = False
    router.last_checked_at = now - timedelta(minutes=1)
    router.last_online_at = last_contact
    await db.commit()
    return router, last_contact, first_failure


@pytest.mark.asyncio
async def test_uptime_says_down_since_the_last_contact_not_the_first_failed_check(db, owner):  # noqa: F811
    reseller, _ = owner
    router, last_contact, first_failure = await _router_down_since_0842(db, reseller)

    out = await router_management.get_router_uptime(
        router.id, hours=24, recent_checks=50, db=db,
        token={"user_id": reseller.id, "role": reseller.role.value})

    outage = out["outages"][-1]
    assert outage["ended_at"] is None
    assert _at(outage["down_since"]) == last_contact
    assert _at(outage["checks_failing_since"]) == first_failure
    assert out["down_now"] is not None
    assert _at(out["down_now"]["down_since"]) == last_contact
    assert _at(out["down_now"]["checks_failing_since"]) == first_failure


@pytest.mark.asyncio
async def test_router_list_names_the_down_time_plainly(client, db, owner):  # noqa: F811
    reseller, token = owner
    router, last_contact, _ = await _router_down_since_0842(db, reseller)

    r = await client.get("/api/routers", headers=auth(token))
    assert r.status_code == 200
    row = next(x for x in r.json() if x["id"] == router.id)
    assert row["status"] == "offline"
    assert _at(row["down_since"]) == last_contact


def _static_menus(arp_status: str) -> dict:
    ip = "172.172.10.77"
    return {
        "/ip/hotspot/ip-binding": [{".id": "*1", "address": ip, "type": "bypassed", "disabled": "false",
                                    "comment": "STATIC: Jawahir (cust 1)"}],
        "/queue/simple": [{".id": "*2", "name": f"plan_static:{ip}", "target": f"{ip}/32",
                           "max-limit": "20000000/20000000", "rate": "0/0", "bytes": "1/1",
                           "disabled": "false"}],
        "/ip/firewall/filter": [], "/ip/firewall/address-list": [],
        "/ip/address": [{".id": "*3", "address": "172.172.10.1/24", "interface": "bridge"}],
        "/ip/hotspot/host": [],
        "/ip/arp": [{".id": "*4", "address": ip, "mac-address": "1C:59:9B:36:42:97", "status": arp_status,
                     "dynamic": "true", "complete": "true"}],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("arp_status, online", [("stale", False), ("reachable", True)])
async def test_static_status_says_whether_the_device_answers_not_only_access(
        client, db, owner, monkeypatch, arp_status, online):  # noqa: F811
    reseller, token = owner
    router = await make_router(db, reseller, name="Hassan Server #1")
    plan = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP, name="Diamond 20M",
                           speed="20M/20M")
    cust = await make_customer(db, reseller, plan, router, status=CustomerStatus.ACTIVE,
                               expiry=datetime.utcnow() + timedelta(days=7), name="Jawahir",
                               static_ip="172.172.10.77")
    await db.commit()
    menus = _static_menus(arp_status)
    monkeypatch.setattr(static_ip, "MikroTikAPI", lambda *a, **k: FakeRouterOS(menus))

    r = await client.get(f"/api/customers/{cust.id}/static/status", headers=auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["actual_access"] == "enabled"      # the router lets her through...
    assert body["device_online"] is online         # ...but whether her device answers is separate
    if not online:
        assert "stale" in body["device_note"]


def test_instructions_cover_down_time_static_reads_and_consistency():
    text = agent_mod.SYSTEM_TEMPLATE
    assert "down_since" in text and "checks_failing_since" in text
    assert "device_online" in text
    assert "contradict" in text

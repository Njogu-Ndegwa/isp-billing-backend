"""Every new router gets the health monitoring the existing fleet has (Dennis, 2026-11-24).

The rule lives in AGENTS.md, "Router Health Monitoring (every router, new ones too)". These
tests fail if a router-creation path stops enrolling the router, if the push stops sending
what the graphs and WAN-drop counter need, or if a hAP lite could be given the push agent.
"""

import inspect
from datetime import datetime

from app.api import provisioning, router_management
from app.services import realtime_push_installer as rpi
from app.services import router_metric_history as mh
from app.services.usage_push_script import render_realtime_push_script
from tests.factories import make_reseller, make_router


def test_every_router_creation_path_enrols_the_router_in_health_reporting():
    for endpoint in (provisioning.complete_provision, router_management.create_router_api):
        assert "schedule_install_after_provisioning(" in inspect.getsource(endpoint), endpoint.__name__


def test_the_push_always_sends_what_the_graphs_and_wan_drops_need():
    script = render_realtime_push_script(identity="new-router", endpoint_url="http://10.251.0.1:8088/x")
    assert "/system resource" in script or "/system/resource" in script  # CPU + memory
    assert '\\"ports\\":[' in script and "link-downs" in script        # WAN drops derived from ports


def test_hap_lites_never_get_the_push_agent_by_default():
    assert "smips" in rpi.SMALL_ARCHITECTURES
    assert inspect.signature(rpi.install_router).parameters["allow_small"].default is False


async def test_a_new_router_with_no_readings_yet_is_listed_not_hidden(db):
    new = await make_router(db, await make_reseller(db), name="brand new", last_status=True)
    out = await mh.ranking(db, "24h", now=datetime(2026, 11, 24, 12, 0))
    assert [r["router_id"] for r in out["not_reporting"]] == [new.id]
    assert out["routers"] == []


async def test_a_new_hap_lite_gets_graphs_from_the_server_poll_with_no_script(db, monkeypatch):
    """No push agent for a hAP lite, yet graphs: the server health poll picks up any
    online router with no fresh push from the routers table, new ones included."""
    from app.config import settings
    from app.services import router_health_poll as poll
    from app.services.app_settings import set_setting

    assert rpi._SMALL_BOARD_RE.search("hAP lite")       # never offered the push agent

    class HapLite:
        def __init__(self, *a, **k): pass
        async def connect(self): pass
        async def close(self): pass
        async def rpc(self, path, args=None, query=(), timeout=25):
            if path == "/system/resource/print":
                return {"rows": [{"cpu-load": "9", "free-memory": "5705728",
                                  "total-memory": "33554432", "uptime": "1h",
                                  "board-name": "hAP lite", "version": "6.49.17"}]}
            if path == "/ip/route/print":
                return {"rows": [{"gateway-status": "192.168.1.1 reachable via  ether1"}]}
            return {"rows": [{"name": "ether1", "link-downs": "0"}]}

    monkeypatch.setattr(poll, "AsyncNativeAPI", HapLite)
    monkeypatch.setattr(poll, "_router_busy", lambda target: False)
    monkeypatch.setattr(poll, "SLOTS", 1)
    monkeypatch.setattr(settings, "ROUTER_HEALTH_POLL_ENABLED", True)
    poll._wan_cache.clear(); poll._failures.clear()
    await set_setting(db, poll.KEY_ROUTER_IDS, "all")   # the rollout's end state

    new = await make_router(db, await make_reseller(db), name="new hAP lite", last_status=True)
    now = datetime.utcnow()
    assert await poll.poll_router_health(now=now) == 1

    out = await mh.ranking(db, "24h", now=now)
    assert [r["router_id"] for r in out["routers"]] == [new.id]
    assert out["routers"][0]["board"] == "hAP lite" and out["not_reporting"] == []

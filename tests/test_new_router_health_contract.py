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

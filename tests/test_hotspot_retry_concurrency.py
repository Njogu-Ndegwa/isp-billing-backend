import asyncio
from types import SimpleNamespace

import pytest

from app.services import hotspot_provisioning


pytestmark = pytest.mark.asyncio


async def test_hotspot_retry_router_groups_are_concurrency_limited(monkeypatch):
    active = 0
    max_seen = 0
    calls = 0
    lock = asyncio.Lock()

    async def fake_provision_hotspot_customer(**kwargs):
        nonlocal active, max_seen, calls
        async with lock:
            active += 1
            calls += 1
            max_seen = max(max_seen, active)
        await asyncio.sleep(0.02)
        async with lock:
            active -= 1
        return {"success": True}

    monkeypatch.setattr(
        hotspot_provisioning,
        "build_hotspot_payload",
        lambda customer, plan, router, comment: {"comment": comment},
    )
    monkeypatch.setattr(
        hotspot_provisioning,
        "provision_hotspot_customer",
        fake_provision_hotspot_customer,
    )

    group_count = hotspot_provisioning.HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS + 3
    router_groups = {}
    for idx in range(group_count):
        router_groups[f"10.0.0.{idx}:8728"] = [
            (
                SimpleNamespace(id=idx),
                SimpleNamespace(id=idx, name=f"Customer {idx}"),
                SimpleNamespace(),
                SimpleNamespace(id=idx),
                False,
            )
        ]

    await hotspot_provisioning._process_hotspot_retry_router_groups(router_groups)

    assert calls == group_count
    assert max_seen == hotspot_provisioning.HOTSPOT_RETRY_MAX_CONCURRENT_ROUTER_GROUPS

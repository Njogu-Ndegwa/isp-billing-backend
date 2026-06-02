from datetime import datetime, timedelta

import pytest

from app.db.models import CustomerStatus
from app.services import mikrotik_background
from tests.factories import make_customer, make_plan, make_reseller, make_router


pytestmark = pytest.mark.asyncio


async def test_safety_net_recheck_keeps_recently_reactivated_mac(
    db,
    session_factory,
    monkeypatch,
):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=10)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=20),
        mac_address="1e-db-03-f4-11-3b",
    )

    stale_snapshot = await mikrotik_background._load_authorized_bypass_macs(db)
    assert "1E:DB:03:F4:11:3B" not in stale_snapshot

    customer.status = CustomerStatus.ACTIVE
    customer.expiry = datetime.utcnow() + timedelta(minutes=10)
    await db.commit()

    orphans = await mikrotik_background._filter_current_orphan_bypass_macs(
        {"1E:DB:03:F4:11:3B"}
    )

    assert orphans == set()


async def test_safety_net_recheck_allows_truly_expired_mac_removal(
    db,
    session_factory,
    monkeypatch,
):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)

    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller, duration_value=10)
    router = await make_router(db, reseller)
    await make_customer(
        db,
        reseller,
        plan,
        router,
        status=CustomerStatus.INACTIVE,
        expiry=datetime.utcnow() - timedelta(minutes=20),
        mac_address="1e-db-03-f4-11-3b",
    )

    orphans = await mikrotik_background._filter_current_orphan_bypass_macs(
        {"1E:DB:03:F4:11:3B"}
    )

    assert orphans == {"1E:DB:03:F4:11:3B"}


async def test_safety_net_batches_router_candidate_recheck(
    db,
    session_factory,
    monkeypatch,
):
    monkeypatch.setattr(mikrotik_background, "async_session", session_factory)

    reseller = await make_reseller(db)
    await make_router(db, reseller, ip_address="10.0.0.2", port=8728)
    await make_router(db, reseller, ip_address="10.0.0.3", port=8728)

    def fake_find_candidates(router_info, active_macs):
        if router_info["ip"] == "10.0.0.2":
            return {"AA-BB-CC-DD-EE-01"}
        if router_info["ip"] == "10.0.0.3":
            return {"AA:BB:CC:DD:EE:02"}
        return set()

    recheck_calls = []

    async def fake_filter_current(candidates):
        recheck_calls.append(set(candidates))
        return {"AA:BB:CC:DD:EE:01"}

    remove_calls = []

    def fake_remove_bindings(router_info, orphan_macs):
        remove_calls.append((router_info["ip"], set(orphan_macs)))
        return len(orphan_macs)

    monkeypatch.setattr(
        mikrotik_background,
        "_find_router_binding_cleanup_candidates_sync",
        fake_find_candidates,
    )
    monkeypatch.setattr(
        mikrotik_background,
        "_filter_current_orphan_bypass_macs",
        fake_filter_current,
    )
    monkeypatch.setattr(
        mikrotik_background,
        "_remove_router_bindings_sync",
        fake_remove_bindings,
    )

    removed = await mikrotik_background._cleanup_bypassing_for_all_routers(db)

    assert removed == 1
    assert recheck_calls == [{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}]
    assert remove_calls == [("10.0.0.2", {"AA:BB:CC:DD:EE:01"})]

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

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import event

from app.api import usage_routes
from app.db.models import ConnectionType, CustomerUsagePeriod
from tests.factories import make_admin, make_customer, make_plan, make_reseller, make_router


@pytest.mark.asyncio
async def test_bulk_usage_is_bounded_scoped_and_constant_query_count(
    db,
    engine,
    monkeypatch,
):
    reseller = await make_reseller(db)
    other_reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    other_router = await make_router(db, other_reseller)
    hotspot_plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.HOTSPOT,
        data_cap_mb=100,
    )
    pppoe_plan = await make_plan(
        db,
        reseller,
        connection_type=ConnectionType.PPPOE,
        data_cap_mb=200,
    )
    other_plan = await make_plan(db, other_reseller)
    expiry = datetime.utcnow() + timedelta(days=30)
    hotspot_customer = await make_customer(
        db,
        reseller,
        hotspot_plan,
        router,
        expiry=expiry,
    )
    pppoe_customer = await make_customer(
        db,
        reseller,
        pppoe_plan,
        router,
        pppoe_username="bulk-pppoe",
        expiry=expiry,
    )
    inaccessible_customer = await make_customer(
        db,
        other_reseller,
        other_plan,
        other_router,
        expiry=expiry,
    )
    now = datetime.utcnow()
    db.add_all(
        [
            CustomerUsagePeriod(
                customer_id=hotspot_customer.id,
                period_start=now - timedelta(days=1),
                period_end=expiry,
                upload_bytes=2 * 1024 * 1024,
                download_bytes=3 * 1024 * 1024,
                total_bytes=5 * 1024 * 1024,
            ),
            CustomerUsagePeriod(
                customer_id=pppoe_customer.id,
                period_start=now - timedelta(days=1),
                period_end=expiry,
                upload_bytes=4 * 1024 * 1024,
                download_bytes=6 * 1024 * 1024,
                total_bytes=10 * 1024 * 1024,
            ),
        ]
    )
    await db.commit()

    async def _current_user(_token, _db):
        return reseller

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    statements = []

    def _count_query(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _count_query)
    try:
        rows = await usage_routes.get_customer_usage_bulk(
            body=usage_routes.BulkUsageRequest(
                customer_ids=[
                    pppoe_customer.id,
                    hotspot_customer.id,
                    inaccessible_customer.id,
                    pppoe_customer.id,
                ]
            ),
            db=db,
            token="test",
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _count_query)

    assert [row.customer_id for row in rows] == [pppoe_customer.id, hotspot_customer.id]
    assert rows[0].connection_type == "pppoe"
    assert rows[0].period.total_mb == 10.0
    assert rows[1].connection_type == "hotspot"
    assert rows[1].period.total_mb == 5.0
    assert len(statements) == 3


@pytest.mark.asyncio
async def test_bulk_usage_admin_can_read_multiple_resellers(db, monkeypatch):
    admin = await make_admin(db)
    first_reseller = await make_reseller(db)
    second_reseller = await make_reseller(db)
    first_plan = await make_plan(db, first_reseller)
    second_plan = await make_plan(db, second_reseller)
    first = await make_customer(db, first_reseller, first_plan)
    second = await make_customer(db, second_reseller, second_plan)

    async def _current_user(_token, _db):
        return admin

    monkeypatch.setattr(usage_routes, "get_current_user", _current_user)
    rows = await usage_routes.get_customer_usage_bulk(
        body=usage_routes.BulkUsageRequest(customer_ids=[first.id, second.id]),
        db=db,
        token="test",
    )

    assert [row.customer_id for row in rows] == [first.id, second.id]


@pytest.mark.asyncio
async def test_bulk_usage_rejects_more_than_one_page(db):
    with pytest.raises(HTTPException) as exc_info:
        await usage_routes.get_customer_usage_bulk(
            body=usage_routes.BulkUsageRequest(customer_ids=list(range(1, 102))),
            db=db,
            token="test",
        )

    assert exc_info.value.status_code == 400
    assert "maximum of 100" in exc_info.value.detail

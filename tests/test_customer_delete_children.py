"""Deleting a customer must clear every row that would block it.

2026-10-10: a reseller could not delete a customer because
``customer_usage_buckets`` (added 2026-09-26) still referenced it and
``delete_customer`` did not know about the new table. The guard below fails
the build for the next table that is added the same way.
"""

import inspect
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from app.api import customer_routes
from app.db.models import Base, Customer, CustomerUsageBucket, SmsMessage, SmsMessageKind
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _blocking_customer_fks():
    """(model class name, column) for every FK to customers.id with no ON DELETE."""
    classes = {m.local_table.name: m.class_.__name__ for m in Base.registry.mappers}
    out = []
    for table in Base.metadata.sorted_tables:
        for fk in table.foreign_keys:
            if fk.column.table.name == "customers" and fk.ondelete is None:
                out.append((classes.get(table.name, table.name), fk.parent.name))
    return out


def test_delete_customer_handles_every_blocking_foreign_key():
    src = inspect.getsource(customer_routes.delete_customer)
    missing = [
        f"{model}.{column}" for model, column in _blocking_customer_fks()
        if f"{model}.{column} == customer_id" not in src
    ]
    assert not missing, (
        "delete_customer does not delete or NULL these rows, so deleting a "
        f"customer that has one fails with a foreign-key error: {missing}"
    )


@pytest.mark.asyncio
async def test_delete_customer_clears_usage_buckets_and_keeps_sms_history(db):
    reseller = await make_reseller(db)
    plan = await make_plan(db, reseller)
    router = await make_router(db, reseller)
    customer = await make_customer(
        db, reseller, plan, router, expiry=datetime.utcnow() + timedelta(days=1),
        mac_address="62:39:3A:F0:4D:5F",
    )
    db.add(CustomerUsageBucket(
        customer_id=customer.id, router_id=router.id,
        bucket_start=datetime.utcnow().replace(minute=0, second=0, microsecond=0),
        upload_bytes=10, download_bytes=20,
    ))
    sms = SmsMessage(
        user_id=reseller.id, customer_id=customer.id, recipient_phone="254712345678",
        body="hello", segments=1, credits_charged=1, kind=list(SmsMessageKind)[0],
    )
    db.add(sms)
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_check (customer_id INTEGER)"))
    await db.execute(text("CREATE TABLE IF NOT EXISTS radius_reply (customer_id INTEGER)"))
    await db.commit()

    response = await customer_routes.delete_customer(
        customer.id, db, {"user_id": reseller.id, "role": reseller.role.value})

    assert response["success"] is True
    assert (await db.execute(select(Customer).where(Customer.id == customer.id))).scalar_one_or_none() is None
    buckets = await db.execute(
        select(func.count()).select_from(CustomerUsageBucket).where(CustomerUsageBucket.customer_id == customer.id))
    assert buckets.scalar_one() == 0
    kept = (await db.execute(select(SmsMessage).where(SmsMessage.id == sms.id))).scalar_one()
    assert kept.customer_id is None

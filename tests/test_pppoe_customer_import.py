from datetime import datetime

import pytest
from sqlalchemy import func, select

from app.db.models import ConnectionType, Customer, CustomerStatus, Plan
from app.services.account_numbers import is_valid_account_number
from app.services.mikrotik_api import MikroTikAPI
from app.services.pppoe_customer_import import (
    import_pppoe_customers,
    normalize_workbook_rows,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


def _record(**overrides):
    base = {
        "Username": "alice",
        "Names": "Alice Njeri",
        "Phone": "0712345678",
        "Activity": "offline",
        "Status": "Active",
        "Expiry": "01 Jul 2026 01:54 pm",
        "Package": "mnthly 15mbps",
        "Location": "Gichira",
    }
    base.update(overrides)
    return base


def test_normalize_rows_maps_status_and_expiry_to_utc():
    rows, report = normalize_workbook_rows([_record()])

    assert report.errors == []
    assert rows[0].username == "alice"
    assert rows[0].status == CustomerStatus.ACTIVE
    assert rows[0].expiry == datetime(2026, 7, 1, 10, 54)
    assert rows[0].password is None
    assert report.statuses == {"Active": 1}
    assert report.packages == {"mnthly 15mbps": 1}


def test_normalize_rows_maps_expired_to_inactive_and_counts_missing_phone():
    rows, report = normalize_workbook_rows([
        _record(Username="bob", Status="Expired", Phone="", Expiry="")
    ])

    assert report.errors == []
    assert report.missing_phone == 1
    assert rows[0].status == CustomerStatus.INACTIVE
    assert rows[0].expiry is None


async def test_import_creates_customers_plans_and_preserves_source_state(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    rows, parse_report = normalize_workbook_rows(
        [
            _record(Username="alice", Status="Active", Package="mnthly 15mbps"),
            _record(Username="bob", Status="Expired", Package="monthly 5mbps", Phone=""),
        ]
    )
    assert parse_report.errors == []

    report = await import_pppoe_customers(
        db,
        rows,
        reseller_id=reseller.id,
        router_id=router.id,
        source_file="items_export_2026-06-03.xlsx",
        dry_run=False,
        create_missing_plans=True,
    )

    assert report.errors == []
    assert report.created == 2
    assert report.updated == 0
    assert len(report.created_plans) == 2
    assert report.missing_phone == 1

    customers = (
        await db.execute(select(Customer).order_by(Customer.pppoe_username))
    ).scalars().all()
    assert [c.pppoe_username for c in customers] == ["alice", "bob"]
    assert customers[0].status == CustomerStatus.ACTIVE
    assert customers[1].status == CustomerStatus.INACTIVE
    assert customers[0].user_id == reseller.id
    assert customers[0].router_id == router.id
    assert customers[0].pppoe_password is None
    assert is_valid_account_number(customers[0].account_number)
    assert customers[0].pending_update_data["pppoe_import"]["source_status"] == "Active"


async def test_import_dry_run_rolls_back(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    rows, _ = normalize_workbook_rows([_record()])

    report = await import_pppoe_customers(
        db,
        rows,
        reseller_id=reseller.id,
        router_id=router.id,
        source_file="items.xlsx",
        dry_run=True,
        create_missing_plans=True,
    )

    assert report.errors == []
    assert report.created == 1
    customer_count = (await db.execute(select(func.count(Customer.id)))).scalar_one()
    plan_count = (await db.execute(select(func.count(Plan.id)))).scalar_one()
    assert customer_count == 0
    assert plan_count == 0


async def test_import_updates_existing_username_idempotently(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        name="mnthly 15mbps",
        speed="15Mbps",
        connection_type=ConnectionType.PPPOE,
    )
    existing = await make_customer(
        db,
        reseller,
        plan,
        router,
        pppoe_username="alice",
        status=CustomerStatus.ACTIVE,
        account_number=None,
    )
    rows, _ = normalize_workbook_rows([
        _record(Username="alice", Status="Expired", Phone="0700000000", Expiry="")
    ])

    report = await import_pppoe_customers(
        db,
        rows,
        reseller_id=reseller.id,
        router_id=router.id,
        source_file="items.xlsx",
        dry_run=False,
    )

    assert report.errors == []
    assert report.created == 0
    assert report.updated == 1
    refreshed = (
        await db.execute(select(Customer).where(Customer.id == existing.id))
    ).scalar_one()
    assert refreshed.status == CustomerStatus.INACTIVE
    assert refreshed.phone == "0700000000"
    assert is_valid_account_number(refreshed.account_number)


async def test_import_requires_existing_plan_unless_create_missing_enabled(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    rows, _ = normalize_workbook_rows([_record()])

    report = await import_pppoe_customers(
        db,
        rows,
        reseller_id=reseller.id,
        router_id=router.id,
        source_file="items.xlsx",
        dry_run=False,
        create_missing_plans=False,
    )

    assert report.created == 0
    assert report.errors
    assert "has no matching PPPoE plan" in report.errors[0]


async def test_import_uses_explicit_package_plan_mapping(db):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(
        db,
        reseller,
        name="1 Month 50 Mbps",
        speed="50M/50M",
        connection_type=ConnectionType.PPPOE,
    )
    rows, _ = normalize_workbook_rows([
        _record(Package="mnthly 70mbps")
    ])

    report = await import_pppoe_customers(
        db,
        rows,
        reseller_id=reseller.id,
        router_id=router.id,
        source_file="items.xlsx",
        dry_run=False,
        package_plan_ids={"mnthly 70mbps": plan.id},
    )

    assert report.errors == []
    assert report.created == 1
    assert report.plan_mappings["mnthly 70mbps"] == plan.id
    customer = (
        await db.execute(select(Customer).where(Customer.pppoe_username == "alice"))
    ).scalar_one()
    assert customer.plan_id == plan.id


class _FakeMikroTik(MikroTikAPI):
    def __init__(self, responses):
        self.connected = True
        self.responses = responses
        self.calls = []

    def send_command(self, command, arguments=None):
        self.calls.append((command, arguments or {}))
        response = self.responses.pop(0)
        if callable(response):
            return response(command, arguments or {})
        return response


def test_add_pppoe_secret_without_password_preserves_existing_router_password():
    api = _FakeMikroTik(
        [
            {"success": True, "data": [{"name": "alice", ".id": "*1"}]},
            {"success": True},
        ]
    )

    result = api.add_pppoe_secret("alice", None, "pppoe_15M_15M", comment="CID:1")

    assert result == {"success": True}
    assert api.calls[0] == ("/ppp/secret/print", {})
    assert api.calls[1][0] == "/ppp/secret/set"
    assert api.calls[1][1]["numbers"] == "*1"
    assert api.calls[1][1]["profile"] == "pppoe_15M_15M"
    assert "password" not in api.calls[1][1]


def test_add_pppoe_secret_without_password_fails_when_secret_missing():
    api = _FakeMikroTik([{"success": True, "data": []}])

    result = api.add_pppoe_secret("alice", None, "pppoe_15M_15M")

    assert "does not already exist" in result["error"]

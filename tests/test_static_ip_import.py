"""Bulk static-IP customer import: parsing, preview, apply, plan resolution, safety."""

import io
import json
import zipfile
from datetime import datetime
from xml.sax.saxutils import escape

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

import app.api.static_ip_import_routes as routes
from app.db.database import get_db
from app.db.models import ConnectionType, Customer, CustomerEvent, CustomerStatus, Plan
from app.services.account_numbers import is_valid_account_number
from app.services.auth import verify_token
from app.services.static_ip_import import parse_plan_speed, speed_key
from tests.factories import make_customer, make_plan, make_reseller, make_router

URL = "/api/routers/{}/static-customers/import"


@pytest_asyncio.fixture
async def client(session_factory):
    application = FastAPI()
    application.include_router(routes.router)

    async def _override_get_db():
        async with session_factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    application.dependency_overrides[get_db] = _override_get_db
    application.dependency_overrides[verify_token] = lambda: "tok"
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


@pytest.fixture
def scheduled(monkeypatch):
    calls = []
    monkeypatch.setattr(routes, "schedule_static_provision",
                        lambda cid, action="static_ip_activation": calls.append((cid, action)))
    return calls


def _auth_as(monkeypatch, user):
    async def _fake(token, db):
        return user
    monkeypatch.setattr(routes, "get_current_user", _fake)


async def _seed(db, monkeypatch, *, plan_speed="10M/10M", plan_name="Home 10", price=1500):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP,
                           speed=plan_speed, name=plan_name, price=price)
    _auth_as(monkeypatch, reseller)
    return reseller, router, plan


def _csv(*lines):
    return ("\n".join(lines) + "\n").encode()


def _xlsx(rows, sheet_name="Customers"):
    """Minimal OpenXML workbook with inline-string (or numeric) cells."""
    def col(i):
        return chr(ord("A") + i)

    sheet_rows = []
    for r, values in enumerate(rows, start=1):
        cells = []
        for c, value in enumerate(values):
            ref = f"{col(c)}{r}"
            if isinstance(value, (int, float)):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>')
        sheet_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg = "http://schemas.openxmlformats.org/package/2006/relationships"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml",
                   f'<workbook xmlns="{main}" xmlns:r="{rel}"><sheets>'
                   f'<sheet name="{sheet_name}" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   f'<Relationships xmlns="{pkg}"><Relationship Id="rId1" '
                   f'Type="{rel}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml",
                   f'<worksheet xmlns="{main}"><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>')
    return buf.getvalue()


async def _post(client, router_id, content, filename="customers.csv", **form):
    data = {k: (json.dumps(v) if isinstance(v, dict) else str(v).lower() if isinstance(v, bool) else str(v))
            for k, v in form.items()}
    return await client.post(URL.format(router_id), files={"file": (filename, content)}, data=data)


async def _count(db, model):
    return (await db.execute(select(func.count()).select_from(model))).scalar_one()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_speed_parsing_uses_rate_limit_rules():
    assert speed_key("10M") == speed_key("10M/10M") == speed_key("10 Mbps") == speed_key("10")
    assert speed_key("Static 10M") == speed_key("10M")
    assert speed_key("10M/5M") != speed_key("10M")
    assert parse_plan_speed("Gold") is None
    assert parse_plan_speed("5GHz dish") is None


async def test_csv_preview_with_aliased_headers(db, client, monkeypatch, scheduled):
    _, router, plan = await _seed(db, monkeypatch)
    body = _csv(
        "Customer Name,IP Address,MSISDN,MAC Address,Package,Valid Until",
        "Jane,192.168.2.24,0712000111,aa-bb-cc-dd-ee-01,10M,2030-01-01 03:00",
        "Kamau,192.168.2.25,,,home 10,",
    )

    resp = await _post(client, router.id, body)

    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["success"] is True and out["dry_run"] is True and out["stage"] == "import"
    assert out["router_name"] == router.name and out["source_file"] == "customers.csv"
    assert "created_customer_ids" not in out
    assert out["summary"] == {"rows_total": 2, "to_create": 2, "skipped": 0, "errors": 0,
                              "active": 1, "inactive": 1, "plans_to_create": 0}
    jane, kamau = out["rows"]
    assert jane["row"] == 2 and kamau["row"] == 3
    assert jane["mac"] == "AA:BB:CC:DD:EE:01" and jane["phone"] == "0712000111"
    assert jane["plan_id"] == plan.id and jane["plan_name"] == "Home 10"
    assert jane["expiry"] == "2030-01-01T00:00:00"  # Nairobi -> naive UTC
    assert jane["status"] == "active" and jane["action"] == "create" and jane["reason"] is None
    assert kamau["status"] == "inactive" and kamau["expiry"] is None and kamau["plan_id"] == plan.id
    assert scheduled == []


async def test_xlsx_first_sheet_aliases_and_excel_dates(db, client, monkeypatch, scheduled):
    _, router, plan = await _seed(db, monkeypatch)
    body = _xlsx([
        ["Customer", "IP", "Phone Number", "Static MAC", "Plan Name", "Expires"],
        ["Achieng", "192.168.2.30", 254712345678, "", "Home 10", 47484.5],  # 2030-01-01 12:00 EAT
        ["Otieno", "192.168.2.31", "", "", "10M", "2020-01-01"],
    ])

    resp = await _post(client, router.id, body, filename="Export.XLSX")

    out = resp.json()
    assert resp.status_code == 200 and out["success"] is True, resp.text
    first, second = out["rows"]
    assert first["phone"] == "254712345678"
    assert first["expiry"] == "2030-01-01T09:00:00" and first["status"] == "active"
    assert second["status"] == "inactive" and second["expiry"] == "2019-12-31T21:00:00"
    assert {r["plan_id"] for r in out["rows"]} == {plan.id}


async def test_preview_writes_nothing(db, client, monkeypatch, scheduled):
    _, router, _ = await _seed(db, monkeypatch)
    customers, plans = await _count(db, Customer), await _count(db, Plan)

    resp = await _post(client, router.id, _csv("name,static_ip,plan", "A,192.168.2.40,40M"),
                       create_missing_plans=True, default_plan_price=2000)

    out = resp.json()
    assert out["success"] is True and out["summary"]["plans_to_create"] == 1
    assert out["rows"][0]["plan_id"] is None and out["rows"][0]["plan_name"] == "Static 40M"
    assert await _count(db, Customer) == customers and await _count(db, Plan) == plans


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

async def test_apply_creates_customers_active_and_inactive(db, client, monkeypatch, scheduled):
    reseller, router, plan = await _seed(db, monkeypatch)
    body = _csv(
        "name,static_ip,mac,phone,plan,expiry",
        "Jane,192.168.2.24,aabbccddee01,0712000111,10M,2030-01-01",
        "Kamau,192.168.2.25,,,10M,2020-01-01",
        "Wanjiru,192.168.2.26/32,,0700,10M,",
    )

    resp = await _post(client, router.id, body, apply=True)

    out = resp.json()
    assert resp.status_code == 200 and out["success"] is True, resp.text
    assert out["dry_run"] is False and len(out["created_customer_ids"]) == 3
    rows = {c.static_ip: c for c in (await db.execute(
        select(Customer).where(Customer.id.in_(out["created_customer_ids"])))).scalars()}
    jane, kamau, wanjiru = rows["192.168.2.24"], rows["192.168.2.25"], rows["192.168.2.26"]
    assert jane.status == CustomerStatus.ACTIVE and jane.expiry == datetime(2029, 12, 31, 21, 0)
    assert jane.static_mac == "AA:BB:CC:DD:EE:01" and jane.mac_address is None
    assert kamau.status == CustomerStatus.INACTIVE and kamau.expiry == datetime(2019, 12, 31, 21, 0)
    assert kamau.phone == ""
    assert wanjiru.status == CustomerStatus.INACTIVE and wanjiru.expiry is None
    for c in rows.values():
        assert is_valid_account_number(c.account_number)
        assert c.plan_id == plan.id and c.router_id == router.id and c.user_id == reseller.id
    assert len({c.account_number for c in rows.values()}) == 3

    # Router work only for the paid-up customer, and only after commit.
    assert scheduled == [(jane.id, "static_ip_import")]
    events = (await db.execute(select(CustomerEvent).where(
        CustomerEvent.event_type == "customer_created"))).scalars().all()
    assert {e.customer_id for e in events} == set(out["created_customer_ids"])


async def test_existing_ip_is_skipped_never_updated(db, client, monkeypatch, scheduled):
    reseller, router, plan = await _seed(db, monkeypatch)
    existing = await make_customer(db, reseller, plan, router, static_ip="192.168.2.24",
                                   name="Old Name", status=CustomerStatus.INACTIVE)

    resp = await _post(client, router.id, _csv(
        "name,static_ip,plan,expiry",
        "New Name,192.168.2.24,10M,2030-01-01",
        "Fresh,192.168.2.50,10M,",
    ), apply=True)

    out = resp.json()
    assert out["success"] is True and out["summary"]["skipped"] == 1
    skip = out["rows"][0]
    assert skip["action"] == "skip" and skip["reason"] == f"already a customer (#{existing.id})"
    assert skip["status"] is None
    assert len(out["created_customer_ids"]) == 1
    await db.refresh(existing)
    assert existing.name == "Old Name" and existing.status == CustomerStatus.INACTIVE
    assert scheduled == []


async def test_duplicates_in_file_block_the_whole_apply(db, client, monkeypatch, scheduled):
    _, router, _ = await _seed(db, monkeypatch)
    before = await _count(db, Customer)

    resp = await _post(client, router.id, _csv(
        "name,static_ip,mac,plan",
        "A,192.168.2.24,AA:BB:CC:DD:EE:01,10M",
        "B,192.168.2.24,,10M",
        "C,192.168.2.27,aa:bb:cc:dd:ee:01,10M",
        "D,192.168.2.28,,10M",
        "E,not-an-ip,zz,10M",
    ), apply=True)

    out = resp.json()
    assert resp.status_code == 200
    assert out["success"] is False and out["stage"] == "parse" and out["dry_run"] is False
    assert out["created_customer_ids"] == []
    actions = [r["action"] for r in out["rows"]]
    assert actions == ["create", "error", "error", "create", "error"]
    assert "duplicate static IP 192.168.2.24 in file (also row 2)" in out["rows"][1]["reason"]
    assert "duplicate MAC AA:BB:CC:DD:EE:01 in file (also row 2)" in out["rows"][2]["reason"]
    assert "not valid" in out["rows"][4]["reason"] and "not a valid MAC" in out["rows"][4]["reason"]
    assert out["summary"]["errors"] == 3
    assert await _count(db, Customer) == before
    assert scheduled == []


async def test_row_errors_for_missing_fields_and_bad_expiry(db, client, monkeypatch, scheduled):
    _, router, _ = await _seed(db, monkeypatch)
    resp = await _post(client, router.id, _csv(
        "name,static_ip,plan,expiry",
        ",192.168.2.24,10M,",
        "B,,10M,",
        "C,192.168.2.26,,",
        "D,192.168.2.27,10M,not a date",
    ))
    reasons = [r["reason"] for r in resp.json()["rows"]]
    assert "name is required" in reasons[0]
    assert "static_ip is required" in reasons[1]
    assert "plan is required" in reasons[2]
    assert "expiry" in reasons[3].lower()


# ---------------------------------------------------------------------------
# Plan resolution
# ---------------------------------------------------------------------------

async def test_plan_resolution_mapping_name_speed_and_create(db, client, monkeypatch, scheduled):
    reseller, router, by_speed = await _seed(db, monkeypatch, plan_speed="10M/10M", plan_name="Home 10")
    by_name = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP,
                              speed="3M/3M", name="Biashara Gold", price=3000)
    mapped = await make_plan(db, reseller, connection_type=ConnectionType.STATIC_IP,
                             speed="7M/7M", name="Seven", price=0)
    plans_before = await _count(db, Plan)

    resp = await _post(client, router.id, _csv(
        "name,static_ip,plan",
        "A,192.168.2.1,Legacy Package",
        "B,192.168.2.2,biashara gold",
        "C,192.168.2.3,10 Mbps",
        "D,192.168.2.4,20M",
        "E,192.168.2.5,20 Mbps",
        "F,192.168.2.6,15M/5M",
    ), apply=True, create_missing_plans=True, default_plan_price=2500,
        plan_mapping_json={"legacy package": mapped.id})

    out = resp.json()
    assert resp.status_code == 200 and out["success"] is True, resp.text
    ids = [r["plan_id"] for r in out["rows"]]
    assert ids[:3] == [mapped.id, by_name.id, by_speed.id]
    assert ids[3] == ids[4] and ids[3] not in (None, mapped.id, by_name.id, by_speed.id)
    assert out["plans_to_create"] == [
        {"label": "20M", "name": "Static 20M", "speed": "20M/20M", "price": 2500},
        {"label": "15M/5M", "name": "Static 15M/5M", "speed": "15M/5M", "price": 2500},
    ]
    assert out["summary"]["plans_to_create"] == 2
    assert await _count(db, Plan) == plans_before + 2
    created = await db.get(Plan, ids[3])
    assert created.connection_type == ConnectionType.STATIC_IP and created.price == 2500
    assert created.duration_value == 30 and created.user_id == reseller.id
    # Zero-price existing plan: a warning, not an error.
    assert out["warnings"] == [{"row": 2, "message": out["warnings"][0]["message"]}]
    assert "price 0" in out["warnings"][0]["message"]


async def test_unknown_plan_is_a_row_error_without_create(db, client, monkeypatch, scheduled):
    _, router, _ = await _seed(db, monkeypatch)
    resp = await _post(client, router.id, _csv("name,static_ip,plan", "A,192.168.2.1,50M"), apply=True)
    out = resp.json()
    assert out["success"] is False and out["stage"] == "import"
    assert out["rows"][0]["reason"] == "unknown plan '50M'"
    assert out["created_customer_ids"] == []


async def test_create_missing_plans_requires_a_price(db, client, monkeypatch, scheduled):
    _, router, _ = await _seed(db, monkeypatch)
    resp = await _post(client, router.id, _csv("name,static_ip,plan", "A,192.168.2.1,50M"),
                       create_missing_plans=True)
    assert resp.status_code == 400
    assert "default_plan_price" in resp.json()["detail"]


async def test_mapping_to_non_static_plan_is_rejected(db, client, monkeypatch, scheduled):
    reseller, router, _ = await _seed(db, monkeypatch)
    hotspot = await make_plan(db, reseller, connection_type=ConnectionType.HOTSPOT)
    other = await make_reseller(db)
    foreign = await make_plan(db, other, connection_type=ConnectionType.STATIC_IP)
    for plan_id in (hotspot.id, foreign.id):
        resp = await _post(client, router.id, _csv("name,static_ip,plan", "A,192.168.2.1,x"),
                           plan_mapping_json={"x": plan_id})
        assert resp.status_code == 400, resp.text
        assert str(plan_id) in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Access and upload validation
# ---------------------------------------------------------------------------

async def test_other_resellers_router_is_404(db, client, monkeypatch, scheduled):
    await _seed(db, monkeypatch)
    other = await make_reseller(db)
    foreign_router = await make_router(db, other)
    resp = await _post(client, foreign_router.id, _csv("name,static_ip,plan", "A,192.168.2.1,10M"))
    assert resp.status_code == 404


@pytest.mark.parametrize("filename,content,fragment", [
    ("customers.txt", b"name,static_ip\nA,192.168.2.1\n", ".csv or .xlsx"),
    ("customers.csv", b"", "empty"),
    ("customers.csv", b"name,phone\nA,0700\n", "static_ip"),
    ("customers.csv", b"name,static_ip,plan\n", "no customer rows"),
    ("customers.xlsx", b"not a zip", "Could not read"),
])
async def test_bad_uploads_are_400(db, client, monkeypatch, scheduled, filename, content, fragment):
    _, router, _ = await _seed(db, monkeypatch)
    resp = await _post(client, router.id, content, filename=filename)
    assert resp.status_code == 400
    assert fragment in resp.json()["detail"]


async def test_template_csv(client):
    resp = await client.get("/api/static-customers/import-template")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert 'filename="static-ip-customers-template.csv"' in resp.headers["content-disposition"]
    lines = resp.text.strip().splitlines()
    assert lines[0] == "name,static_ip,mac,phone,plan,expiry"
    assert len(lines) == 3

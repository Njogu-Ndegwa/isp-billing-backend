from __future__ import annotations

import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DurationUnit,
    Plan,
    PlanType,
    Router,
    User,
    UserRole,
)
from app.services.account_numbers import generate_account_number


_XML_NS = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pkgrel": "http://schemas.openxmlformats.org/package/2006/relationships",
}


@dataclass(frozen=True)
class PPPoEWorkbookRow:
    row_number: int
    username: str
    name: str
    phone: str
    activity: str
    source_status: str
    status: CustomerStatus
    expiry: Optional[datetime]
    package: str
    location: str
    password: Optional[str]
    raw: Dict[str, str]


@dataclass
class PPPoEImportReport:
    dry_run: bool
    total_rows: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    missing_phone: int = 0
    created_plans: List[Dict[str, Any]] = field(default_factory=list)
    plan_mappings: Dict[str, int] = field(default_factory=dict)
    statuses: Dict[str, int] = field(default_factory=dict)
    packages: Dict[str, int] = field(default_factory=dict)
    activities: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    samples: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)


def _cell_column(cell_ref: str) -> str:
    match = re.match(r"^[A-Z]+", cell_ref or "")
    return match.group(0) if match else ""


def _norm_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _shared_strings(zip_file: zipfile.ZipFile) -> List[str]:
    try:
        with zip_file.open("xl/sharedStrings.xml") as handle:
            root = ET.parse(handle).getroot()
    except KeyError:
        return []

    out: List[str] = []
    for item in root.findall("main:si", _XML_NS):
        out.append("".join(item.itertext()))
    return out


def _sheet_path(zip_file: zipfile.ZipFile, sheet_name: str) -> str:
    with zip_file.open("xl/workbook.xml") as handle:
        workbook = ET.parse(handle).getroot()
    with zip_file.open("xl/_rels/workbook.xml.rels") as handle:
        rels = ET.parse(handle).getroot()

    rel_targets = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels.findall("pkgrel:Relationship", _XML_NS)
    }

    for sheet in workbook.findall("main:sheets/main:sheet", _XML_NS):
        if sheet.attrib.get("name") != sheet_name:
            continue
        rel_id = sheet.attrib.get(f"{{{_XML_NS['rel']}}}id")
        target = rel_targets[rel_id]
        if target.startswith("/"):
            return target.lstrip("/")
        return f"xl/{target}"

    names = [
        sheet.attrib.get("name", "")
        for sheet in workbook.findall("main:sheets/main:sheet", _XML_NS)
    ]
    raise ValueError(f"Sheet '{sheet_name}' not found. Available sheets: {', '.join(names)}")


def _cell_value(cell: ET.Element, shared: List[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        inline = cell.find("main:is", _XML_NS)
        return "" if inline is None else "".join(inline.itertext())

    value_node = cell.find("main:v", _XML_NS)
    value = "" if value_node is None or value_node.text is None else value_node.text
    if cell_type == "s" and value:
        return shared[int(value)]
    return value


def read_pppoe_workbook(path: str | Path, *, sheet_name: str = "Items") -> List[Dict[str, str]]:
    """Read the exported PPPoE workbook using only Python stdlib OpenXML parsing."""
    path = Path(path)
    with zipfile.ZipFile(path) as zip_file:
        shared = _shared_strings(zip_file)
        sheet_entry = _sheet_path(zip_file, sheet_name)
        with zip_file.open(sheet_entry) as handle:
            sheet = ET.parse(handle).getroot()

    rows = sheet.findall("main:sheetData/main:row", _XML_NS)
    if not rows:
        return []

    headers: Dict[str, str] = {}
    for cell in rows[0].findall("main:c", _XML_NS):
        headers[_cell_column(cell.attrib.get("r", ""))] = _cell_value(cell, shared).strip()

    records: List[Dict[str, str]] = []
    for row in rows[1:]:
        record: Dict[str, str] = {"__row_number": row.attrib.get("r", "")}
        for cell in row.findall("main:c", _XML_NS):
            col = _cell_column(cell.attrib.get("r", ""))
            header = headers.get(col)
            if not header:
                continue
            record[header] = _cell_value(cell, shared).strip()
        if any(value for key, value in record.items() if key != "__row_number"):
            records.append(record)
    return records


def _pick(record: Dict[str, str], *names: str) -> str:
    normalized = {_norm_header(k): v for k, v in record.items()}
    for name in names:
        value = normalized.get(_norm_header(name))
        if value is not None:
            return value.strip()
    return ""


def _status_from_source(value: str) -> CustomerStatus:
    normalized = value.strip().lower()
    if normalized in {"active", "enabled", "paid"}:
        return CustomerStatus.ACTIVE
    if normalized in {"expired", "inactive", "disabled", "suspended"}:
        return CustomerStatus.INACTIVE
    if normalized in {"pending", "provisioning", "awaiting_payment"}:
        return CustomerStatus.PENDING
    raise ValueError(f"Unsupported status '{value}'")


def _parse_expiry(value: str, source_timezone: str) -> Optional[datetime]:
    value = value.strip()
    if not value:
        return None

    parsed: Optional[datetime] = None
    for fmt in (
        "%d %b %Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
    ):
        try:
            parsed = datetime.strptime(value.upper(), fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        try:
            from dateutil import parser as date_parser

            parsed = date_parser.parse(value)
        except Exception as exc:
            raise ValueError(f"Could not parse expiry '{value}': {exc}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(source_timezone))

    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _password_for_row(
    record: Dict[str, str],
    *,
    username: str,
    phone: str,
    password_column: Optional[str],
    default_password: Optional[str],
    password_from: Optional[str],
) -> Optional[str]:
    if password_column:
        value = _pick(record, password_column)
        if value:
            return value
    if default_password is not None:
        return default_password
    if password_from == "username":
        return username
    if password_from == "phone":
        return phone or None
    return None


def normalize_workbook_rows(
    records: Iterable[Dict[str, str]],
    *,
    source_timezone: str = "Africa/Nairobi",
    password_column: Optional[str] = None,
    default_password: Optional[str] = None,
    password_from: Optional[str] = None,
) -> Tuple[List[PPPoEWorkbookRow], PPPoEImportReport]:
    rows: List[PPPoEWorkbookRow] = []
    report = PPPoEImportReport(dry_run=True)
    seen_usernames: set[str] = set()

    for index, record in enumerate(records, start=2):
        row_number_raw = record.get("__row_number") or str(index)
        try:
            row_number = int(row_number_raw)
        except ValueError:
            row_number = index

        username = _pick(record, "Username", "User Name", "PPPoE Username")
        name = _pick(record, "Names", "Name", "Customer Name") or username
        phone = _pick(record, "Phone", "Phone Number", "MSISDN")
        activity = _pick(record, "Activity")
        source_status = _pick(record, "Status")
        package = _pick(record, "Package", "Plan")
        location = _pick(record, "Location", "Address")
        expiry_raw = _pick(record, "Expiry", "Expires At", "Expiration")

        report.total_rows += 1
        report.statuses[source_status or "<blank>"] = report.statuses.get(source_status or "<blank>", 0) + 1
        report.packages[package or "<blank>"] = report.packages.get(package or "<blank>", 0) + 1
        report.activities[activity or "<blank>"] = report.activities.get(activity or "<blank>", 0) + 1
        if not phone:
            report.missing_phone += 1

        if not username:
            report.errors.append(f"row {row_number}: missing Username")
            continue
        username_key = username.casefold()
        if username_key in seen_usernames:
            report.errors.append(f"row {row_number}: duplicate Username '{username}' in workbook")
            continue
        seen_usernames.add(username_key)
        if not package:
            report.errors.append(f"row {row_number}: missing Package")
            continue

        try:
            status = _status_from_source(source_status)
            expiry = _parse_expiry(expiry_raw, source_timezone) if expiry_raw else None
        except ValueError as exc:
            report.errors.append(f"row {row_number}: {exc}")
            continue

        rows.append(
            PPPoEWorkbookRow(
                row_number=row_number,
                username=username,
                name=name,
                phone=phone,
                activity=activity,
                source_status=source_status,
                status=status,
                expiry=expiry,
                package=package,
                location=location,
                password=_password_for_row(
                    record,
                    username=username,
                    phone=phone,
                    password_column=password_column,
                    default_password=default_password,
                    password_from=password_from,
                ),
                raw={k: v for k, v in record.items() if not k.startswith("__")},
            )
        )

    return rows, report


def _speed_from_package(package: str) -> str:
    match = re.search(r"(\d+(?:\.\d+)?)\s*m(?:b|p)?p?s?", package, flags=re.IGNORECASE)
    if match:
        return f"{match.group(1)}Mbps"
    match = re.search(r"(\d+(?:\.\d+)?)", package)
    if match:
        return f"{match.group(1)}Mbps"
    return "10Mbps"


def _canonical_speed(value: str) -> str:
    parsed = _speed_from_package(value)
    return parsed.replace(" ", "").lower()


async def _load_or_create_plan(
    db: AsyncSession,
    *,
    reseller_id: int,
    package: str,
    explicit_plan_id: Optional[int],
    create_missing_plans: bool,
    default_plan_price: int,
    report: PPPoEImportReport,
) -> Optional[Plan]:
    if explicit_plan_id is not None:
        plan = (
            await db.execute(
                select(Plan).where(
                    Plan.id == explicit_plan_id,
                    Plan.user_id == reseller_id,
                    Plan.connection_type == ConnectionType.PPPOE,
                )
            )
        ).scalar_one_or_none()
        if not plan:
            report.errors.append(
                f"package '{package}' is mapped to plan_id={explicit_plan_id}, "
                f"but that PPPoE plan was not found for reseller {reseller_id}"
            )
            return None
        report.plan_mappings.setdefault(package, plan.id)
        return plan

    normalized_package = package.strip().lower()

    exact = await db.execute(
        select(Plan).where(
            Plan.user_id == reseller_id,
            Plan.connection_type == ConnectionType.PPPOE,
            func.lower(Plan.name) == normalized_package,
        )
    )
    plan = exact.scalar_one_or_none()
    if plan:
        report.plan_mappings.setdefault(package, plan.id)
        return plan

    package_speed = _canonical_speed(package)
    pppoe_plans = (
        await db.execute(
            select(Plan).where(
                Plan.user_id == reseller_id,
                Plan.connection_type == ConnectionType.PPPOE,
            )
        )
    ).scalars().all()
    by_speed = [plan for plan in pppoe_plans if _canonical_speed(plan.speed or "") == package_speed]
    if len(by_speed) == 1:
        report.plan_mappings.setdefault(package, by_speed[0].id)
        return by_speed[0]
    if len(by_speed) > 1:
        report.errors.append(
            f"package '{package}' matched multiple PPPoE plans by speed '{package_speed}'"
        )
        return None

    if not create_missing_plans:
        report.errors.append(
            f"package '{package}' has no matching PPPoE plan for reseller {reseller_id}; "
            "re-run with --create-missing-plans or create/map the plan first"
        )
        return None

    plan = Plan(
        name=package,
        speed=_speed_from_package(package),
        price=default_plan_price,
        duration_value=30,
        duration_unit=DurationUnit.DAYS,
        connection_type=ConnectionType.PPPOE,
        user_id=reseller_id,
        plan_type=PlanType.REGULAR,
    )
    db.add(plan)
    await db.flush()
    report.created_plans.append(
        {"id": plan.id, "name": plan.name, "speed": plan.speed, "price": plan.price}
    )
    report.plan_mappings.setdefault(package, plan.id)
    return plan


async def _next_account_number(db: AsyncSession, reserved: set[str]) -> str:
    while True:
        account_number = await generate_account_number(db)
        if account_number not in reserved:
            reserved.add(account_number)
            return account_number


def _import_metadata(row: PPPoEWorkbookRow, source_file: str) -> Dict[str, Any]:
    return {
        "source": "pppoe_items_export",
        "source_file": source_file,
        "source_row": row.row_number,
        "source_status": row.source_status,
        "source_activity": row.activity,
        "source_package": row.package,
        "source_location": row.location,
        "imported_at": datetime.utcnow().isoformat(),
        "raw": row.raw,
    }


async def import_pppoe_customers(
    db: AsyncSession,
    rows: List[PPPoEWorkbookRow],
    *,
    reseller_id: int,
    router_id: int,
    source_file: str,
    dry_run: bool = True,
    create_missing_plans: bool = False,
    default_plan_price: int = 0,
    reassign_existing: bool = False,
    package_plan_ids: Optional[Dict[str, int]] = None,
) -> PPPoEImportReport:
    report = PPPoEImportReport(dry_run=dry_run, total_rows=len(rows))

    reseller = (
        await db.execute(select(User).where(User.id == reseller_id, User.role == UserRole.RESELLER))
    ).scalar_one_or_none()
    if not reseller:
        report.errors.append(f"reseller_id={reseller_id} was not found or is not a reseller")
        return report

    router = (
        await db.execute(select(Router).where(Router.id == router_id, Router.user_id == reseller_id))
    ).scalar_one_or_none()
    if not router:
        report.errors.append(f"router_id={router_id} was not found for reseller_id={reseller_id}")
        return report

    report.statuses = dict(Counter(row.source_status or "<blank>" for row in rows))
    report.packages = dict(Counter(row.package or "<blank>" for row in rows))
    report.activities = dict(Counter(row.activity or "<blank>" for row in rows))
    report.missing_phone = sum(1 for row in rows if not row.phone)
    if any(row.password is None for row in rows):
        report.warnings.append(
            "Workbook/import options did not provide PPPoE passwords for all rows. "
            "The import will not touch routers; existing RouterOS secrets keep their current passwords."
        )

    normalized_plan_ids = {
        key.strip().lower(): value
        for key, value in (package_plan_ids or {}).items()
    }

    plans: Dict[str, Plan] = {}
    for package in sorted({row.package for row in rows}):
        plan = await _load_or_create_plan(
            db,
            reseller_id=reseller_id,
            package=package,
            explicit_plan_id=normalized_plan_ids.get(package.strip().lower()),
            create_missing_plans=create_missing_plans,
            default_plan_price=default_plan_price,
            report=report,
        )
        if plan:
            plans[package] = plan

    if report.errors:
        await db.rollback()
        return report

    reserved_account_numbers: set[str] = set()
    for row in rows:
        plan = plans[row.package]
        matches = (
            await db.execute(select(Customer).where(Customer.pppoe_username == row.username))
        ).scalars().all()

        if len(matches) > 1:
            report.errors.append(
                f"row {row.row_number}: PPPoE username '{row.username}' already has multiple customer rows"
            )
            report.skipped += 1
            continue

        customer = matches[0] if matches else None
        if customer and (customer.user_id != reseller_id or customer.router_id != router_id):
            if not reassign_existing:
                report.errors.append(
                    f"row {row.row_number}: PPPoE username '{row.username}' already belongs to "
                    f"user_id={customer.user_id}, router_id={customer.router_id}; "
                    "use --reassign-existing only if that is intentional"
                )
                report.skipped += 1
                continue

        if customer is None:
            account_number = await _next_account_number(db, reserved_account_numbers)
            customer = Customer(
                name=row.name,
                phone=row.phone,
                mac_address=None,
                pppoe_username=row.username,
                pppoe_password=row.password,
                status=row.status,
                expiry=row.expiry,
                plan_id=plan.id,
                user_id=reseller_id,
                router_id=router_id,
                account_number=account_number,
                pending_update_data={"pppoe_import": _import_metadata(row, source_file)},
            )
            db.add(customer)
            report.created += 1
            action = "create"
        else:
            customer.name = row.name
            customer.phone = row.phone
            if row.password:
                customer.pppoe_password = row.password
            customer.status = row.status
            customer.expiry = row.expiry
            customer.plan_id = plan.id
            customer.user_id = reseller_id
            customer.router_id = router_id
            if not customer.account_number:
                customer.account_number = await _next_account_number(db, reserved_account_numbers)
            pending = dict(customer.pending_update_data or {})
            pending["pppoe_import"] = _import_metadata(row, source_file)
            customer.pending_update_data = pending
            report.updated += 1
            action = "update"

        if len(report.samples) < 10:
            report.samples.append(
                {
                    "action": action,
                    "row": row.row_number,
                    "username": row.username,
                    "name": row.name,
                    "status": row.status.value,
                    "expiry": row.expiry.isoformat() if row.expiry else None,
                    "plan_id": plan.id,
                    "package": row.package,
                }
            )

    if report.errors:
        await db.rollback()
        return report

    if dry_run:
        await db.rollback()
    else:
        await db.commit()
    return report

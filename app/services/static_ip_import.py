"""Bulk import of static-IP customers from a CSV/XLSX sheet.

One router per upload. The flow is preview-first: ``build_static_import``
reads the database (no writes) and decides an action for every row —
``create``, ``skip`` (the IP already belongs to a customer on that router; an
import never edits existing customers) or ``error``. ``apply_static_import``
then writes the plans and customers in one short transaction, and only when
no row has an error (all-or-nothing). Router work happens after the commit,
in the caller, through ``schedule_static_provision``.

The row rules are the registration rules (``app/services/static_ip.py``):
same IPv4 validation, same per-router uniqueness, same pin-MAC normalisation,
customers created with an account number and no hotspot MAC.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    DurationUnit,
    Plan,
    PlanType,
)
from app.services.mikrotik_api import _normalize_mikrotik_rate_part
from app.services.pppoe_customer_import import (
    _next_account_number,
    _norm_header,
    _parse_expiry,
)
from app.services.static_ip import (
    INVALID_STATIC_IP_MESSAGE,
    normalize_pin_mac,
    normalize_static_ip,
    parse_speed_to_mikrotik_limit,
    static_ips_in_use,
)

MAX_IMPORT_ROWS = 5000
CREATED_PLAN_DURATION_DAYS = 30

# Canonical field -> accepted header spellings (compared after _norm_header).
COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
    "name": ("name", "customer", "customer_name"),
    "static_ip": ("static_ip", "ip", "ip_address"),
    "phone": ("phone", "phone_number", "msisdn"),
    "mac": ("mac", "static_mac", "mac_address"),
    "plan": ("plan", "plan_name", "package", "speed"),
    "expiry": ("expiry", "expires", "expiry_date", "valid_until"),
}
REQUIRED_COLUMNS = ("name", "static_ip")

TEMPLATE_CSV = (
    "name,static_ip,mac,phone,plan,expiry\r\n"
    "Jane Wanjiku,192.168.2.24,AA:BB:CC:DD:EE:01,0712345678,10M,2027-12-31\r\n"
    "Kamau Shop,192.168.2.25,,0722000111,Static 20M,\r\n"
)

_EXCEL_EPOCH = datetime(1899, 12, 30)
_SPEED_TOKEN = re.compile(
    r"\d+(?:\.\d+)?\s*[KMG](?:BPS)?(?:\s*/\s*\d+(?:\.\d+)?\s*[KMG](?:BPS)?)?(?![A-Z])",
    re.IGNORECASE,
)


class ImportFileError(ValueError):
    """The upload as a whole is unusable (the API answers 400)."""


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------

def read_csv_records(data: bytes) -> List[Dict[str, str]]:
    """CSV bytes -> ``{header: text}`` records with ``__row_number`` (header = row 1)."""
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:  # pragma: no cover - cp1252 decodes almost anything
        raise ImportFileError("Could not decode the CSV file; save it as UTF-8")

    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample.splitlines()[0] if sample else ",", delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        headers = next(reader)
    except StopIteration:
        return []

    records: List[Dict[str, str]] = []
    for index, cells in enumerate(reader, start=2):
        if not any((cell or "").strip() for cell in cells):
            continue
        record: Dict[str, str] = {"__row_number": str(index)}
        for header, cell in zip(headers, cells):
            if header and header.strip():
                record.setdefault(header.strip(), (cell or "").strip())
        records.append(record)
    return records


def map_columns(headers: Iterable[str]) -> Dict[str, str]:
    """Canonical field -> the header used for it in this file. First match wins."""
    by_norm: Dict[str, str] = {}
    for header in headers:
        if header.startswith("__"):
            continue
        by_norm.setdefault(_norm_header(header), header)
    mapping: Dict[str, str] = {}
    for field_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in by_norm:
                mapping[field_name] = by_norm[alias]
                break
    missing = [name for name in REQUIRED_COLUMNS if name not in mapping]
    if missing:
        raise ImportFileError(
            "File is missing required column(s): " + ", ".join(missing)
            + ". Expected headers: name, static_ip, mac, phone, plan, expiry"
        )
    return mapping


# ---------------------------------------------------------------------------
# Value parsing
# ---------------------------------------------------------------------------

def _speed_parts(text: str) -> Optional[Tuple[str, str]]:
    value = str(text or "").strip()
    if not value:
        return None
    if "/" in value:
        down, up = value.split("/", 1)
        d = _normalize_mikrotik_rate_part(down, slash_context=True)
        u = _normalize_mikrotik_rate_part(up, slash_context=True)
        return (d, u) if d and u else None
    part = _normalize_mikrotik_rate_part(value)
    return (part, part) if part else None


def parse_plan_speed(label: Optional[str]) -> Optional[Tuple[str, str]]:
    """(download, upload) in RouterOS units, or None when no speed is readable.

    Accepts the whole label as a speed ("10M", "10M/5M", "10 Mbps", "10") or a
    speed token inside it ("Static 10M", "Home 5Mbps"). Uses the same rate
    parser as plan rate limits, minus its silent 10M fallback.
    """
    parts = _speed_parts(label or "")
    if parts:
        return parts
    match = _SPEED_TOKEN.search(str(label or ""))
    return _speed_parts(match.group(0)) if match else None


def speed_key(label: Optional[str]) -> Optional[str]:
    """Comparable bps form of a speed ("10M" == "10M/10M" == "10 Mbps")."""
    parts = parse_plan_speed(label)
    return parse_speed_to_mikrotik_limit(f"{parts[0]}/{parts[1]}") if parts else None


def _clean_phone(value: str) -> str:
    text = (value or "").strip()
    # A phone column typed as a number in Excel/LibreOffice can come back "712345678.0".
    if re.fullmatch(r"\d+\.0+", text):
        text = text.split(".", 1)[0]
    return text


def parse_import_expiry(value: str, source_timezone: str) -> Optional[datetime]:
    """Date/datetime text or an Excel serial number -> naive UTC (None if blank)."""
    text = (value or "").strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text) and 0 < float(text) < 2958466:
        local = _EXCEL_EPOCH + timedelta(days=float(text))
        local = local.replace(microsecond=0, tzinfo=ZoneInfo(source_timezone))
        return local.astimezone(timezone.utc).replace(tzinfo=None)
    return _parse_expiry(text, source_timezone)


# ---------------------------------------------------------------------------
# Building the import plan
# ---------------------------------------------------------------------------

@dataclass
class PendingPlan:
    label: str
    name: str
    speed: str
    price: int
    plan_id: Optional[int] = None  # set once created (apply)


@dataclass
class ImportRow:
    row: int
    name: str
    static_ip: str
    mac: Optional[str]
    phone: str
    plan_label: str
    expiry: Optional[datetime] = None
    status: Optional[CustomerStatus] = None
    action: str = "create"
    reasons: List[str] = field(default_factory=list)
    parse_error: bool = False
    # Plain values, not ORM objects: the report is built after a rollback
    # (preview) has expired every loaded row.
    existing_plan_id: Optional[int] = None
    existing_plan_name: Optional[str] = None
    pending_plan: Optional[PendingPlan] = None

    def fail(self, reason: str, *, parse: bool = False) -> None:
        self.action = "error"
        self.reasons.append(reason)
        self.parse_error = self.parse_error or parse

    @property
    def plan_id(self) -> Optional[int]:
        if self.existing_plan_id is not None:
            return self.existing_plan_id
        return self.pending_plan.plan_id if self.pending_plan is not None else None

    @property
    def plan_name(self) -> Optional[str]:
        if self.existing_plan_name is not None:
            return self.existing_plan_name
        return self.pending_plan.name if self.pending_plan is not None else None


@dataclass
class StaticImport:
    router_id: int
    owner_id: int
    rows: List[ImportRow] = field(default_factory=list)
    pending_plans: List[PendingPlan] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    created_customer_ids: List[int] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(row.action == "error" for row in self.rows)

    @property
    def stage(self) -> str:
        return "parse" if any(row.parse_error for row in self.rows) else "import"


def _label_key(label: Optional[str]) -> str:
    return (label or "").strip().casefold()


async def load_mapping_plans(
    db: AsyncSession, owner_id: int, mapping: Dict[str, int],
) -> Dict[str, Plan]:
    """Label key -> Plan for an explicit mapping; every id must be the owner's STATIC_IP plan."""
    if not mapping:
        return {}
    ids = {int(v) for v in mapping.values()}
    plans = {
        plan.id: plan
        for plan in (
            await db.execute(
                select(Plan).where(
                    Plan.id.in_(ids),
                    Plan.user_id == owner_id,
                    Plan.connection_type == ConnectionType.STATIC_IP,
                )
            )
        ).scalars().all()
    }
    bad = sorted(ids - set(plans))
    if bad:
        raise ImportFileError(
            "plan_mapping_json refers to plan id(s) that are not static-IP plans of this "
            "router's owner: " + ", ".join(str(i) for i in bad)
        )
    return {_label_key(label): plans[int(plan_id)] for label, plan_id in mapping.items()}


def _parse_rows(
    records: List[Dict[str, str]], columns: Dict[str, str], source_timezone: str, now: datetime,
) -> List[ImportRow]:
    rows: List[ImportRow] = []
    seen_ips: Dict[str, int] = {}

    def pick(record: Dict[str, str], name: str) -> str:
        header = columns.get(name)
        return (record.get(header) or "").strip() if header else ""

    for index, record in enumerate(records, start=2):
        try:
            row_number = int(record.get("__row_number") or index)
        except ValueError:
            row_number = index
        raw_ip = pick(record, "static_ip")
        row = ImportRow(
            row=row_number,
            name=pick(record, "name"),
            static_ip=raw_ip,
            mac=pick(record, "mac") or None,
            phone=_clean_phone(pick(record, "phone")),
            plan_label=pick(record, "plan"),
        )
        rows.append(row)

        if not row.name:
            row.fail("name is required", parse=True)

        ip = normalize_static_ip(raw_ip)
        if not raw_ip:
            row.fail("static_ip is required", parse=True)
        elif not ip:
            row.fail(f"'{raw_ip}' is not valid: {INVALID_STATIC_IP_MESSAGE}", parse=True)
        else:
            row.static_ip = ip
            if ip in seen_ips:
                row.fail(f"duplicate static IP {ip} in file (also row {seen_ips[ip]})", parse=True)
            else:
                seen_ips[ip] = row.row

        try:
            row.mac = normalize_pin_mac(row.mac)
        except ValueError as exc:
            row.fail(str(exc), parse=True)

        try:
            row.expiry = parse_import_expiry(pick(record, "expiry"), source_timezone)
        except (ValueError, OverflowError) as exc:
            row.fail(str(exc), parse=True)
        else:
            row.status = (
                CustomerStatus.ACTIVE
                if row.expiry is not None and row.expiry > now
                else CustomerStatus.INACTIVE
            )
    return rows


async def build_static_import(
    db: AsyncSession,
    records: List[Dict[str, str]],
    *,
    router_id: int,
    owner_id: int,
    mapping_plans: Optional[Dict[str, Plan]] = None,
    create_missing_plans: bool = False,
    default_plan_price: int = 0,
    source_timezone: str = "Africa/Nairobi",
    now: Optional[datetime] = None,
) -> StaticImport:
    """Decide every row's action. Reads only; never writes."""
    if not records:
        raise ImportFileError("The file has no customer rows")
    if len(records) > MAX_IMPORT_ROWS:
        raise ImportFileError(f"The file has {len(records)} rows; import at most {MAX_IMPORT_ROWS} at a time")
    try:
        ZoneInfo(source_timezone)
    except Exception as exc:
        raise ImportFileError(f"Unknown source_timezone '{source_timezone}'") from exc

    headers: Dict[str, None] = {}
    for record in records:
        headers.update(dict.fromkeys(record))
    columns = map_columns(headers)
    now = now or datetime.utcnow()
    result = StaticImport(router_id=router_id, owner_id=owner_id)
    result.rows = _parse_rows(records, columns, source_timezone, now)

    # Existing customers on this router: their rows are skipped, never updated.
    in_use = await static_ips_in_use(db, router_id)
    seen_macs: Dict[str, int] = {}
    for row in result.rows:
        taken = in_use.get(row.static_ip)
        if taken is not None and row.action != "error":
            row.action = "skip"
            row.reasons = [f"already a customer (#{taken[0]})"]
            row.status = None
            continue
        if row.mac:
            if row.mac in seen_macs:
                row.fail(f"duplicate MAC {row.mac} in file (also row {seen_macs[row.mac]})", parse=True)
            else:
                seen_macs[row.mac] = row.row

    owner_plans = (
        await db.execute(
            select(Plan).where(
                Plan.user_id == owner_id,
                Plan.connection_type == ConnectionType.STATIC_IP,
            ).order_by(Plan.id)
        )
    ).scalars().all()
    mapping_plans = mapping_plans or {}
    resolved: Dict[str, Any] = {}  # label key -> Plan | PendingPlan | error str
    pending_by_speed: Dict[str, PendingPlan] = {}
    warned_zero_price: set[int] = set()

    def resolve(label: str) -> Any:
        key = _label_key(label)
        if key in mapping_plans:
            return mapping_plans[key]
        if not key:
            return "plan is required (or map the blank plan in plan_mapping_json)"
        by_name = [p for p in owner_plans if _label_key(p.name) == key]
        if len(by_name) == 1:
            return by_name[0]
        if len(by_name) > 1:
            return f"plan '{label}' matches {len(by_name)} static plans by name; map it explicitly"
        wanted = speed_key(label)
        if wanted is not None:
            by_speed = [p for p in owner_plans if speed_key(p.speed) == wanted]
            if len(by_speed) == 1:
                return by_speed[0]
            if len(by_speed) > 1:
                return (
                    f"plan '{label}' matches {len(by_speed)} static plans by speed "
                    f"({', '.join(p.name for p in by_speed)}); map it explicitly"
                )
        if not create_missing_plans:
            return f"unknown plan '{label}'"
        if wanted is None:
            return f"unknown plan '{label}': no speed to create a plan from; map it or use a speed like 10M"
        pending = pending_by_speed.get(wanted)
        if pending is None:
            down, up = parse_plan_speed(label)
            shown = down if down == up else f"{down}/{up}"
            pending = PendingPlan(
                label=label, name=f"Static {shown}", speed=f"{down}/{up}", price=default_plan_price,
            )
            pending_by_speed[wanted] = pending
            result.pending_plans.append(pending)
        return pending

    for row in result.rows:
        if row.action == "skip":
            continue
        key = _label_key(row.plan_label)
        if key not in resolved:
            resolved[key] = resolve(row.plan_label)
        outcome = resolved[key]
        if isinstance(outcome, Plan):
            row.existing_plan_id = outcome.id
            row.existing_plan_name = outcome.name
            if (outcome.price or 0) <= 0 and outcome.id not in warned_zero_price:
                warned_zero_price.add(outcome.id)
                result.warnings.append({
                    "row": row.row,
                    "message": f"Plan '{outcome.name}' (#{outcome.id}) has price 0; "
                               "customers on it cannot pay to renew until the price is set",
                })
        elif isinstance(outcome, PendingPlan):
            row.pending_plan = outcome
        else:
            row.fail(outcome)
    return result


async def apply_static_import(db: AsyncSession, plan: StaticImport) -> List[int]:
    """Write plans + customers in one transaction and commit. Refuses if any row errored."""
    if plan.has_errors:
        raise ValueError("refusing to apply an import with row errors")
    creating = [row for row in plan.rows if row.action == "create"]
    used_pending = {id(row.pending_plan): row.pending_plan for row in creating if row.pending_plan}
    new_plans = []
    for pending in plan.pending_plans:
        if id(pending) not in used_pending:
            continue
        new_plan = Plan(
            name=pending.name,
            speed=pending.speed,
            price=pending.price,
            duration_value=CREATED_PLAN_DURATION_DAYS,
            duration_unit=DurationUnit.DAYS,
            connection_type=ConnectionType.STATIC_IP,
            user_id=plan.owner_id,
            plan_type=PlanType.REGULAR,
        )
        db.add(new_plan)
        new_plans.append((pending, new_plan))
    await db.flush()
    for pending, new_plan in new_plans:
        pending.plan_id = new_plan.id

    reserved: set[str] = set()
    customers: List[Customer] = []
    for row in creating:
        customer = Customer(
            name=row.name,
            phone=row.phone,
            mac_address=None,
            static_ip=row.static_ip,
            static_mac=row.mac,
            status=row.status,
            expiry=row.expiry,
            plan_id=row.plan_id,
            user_id=plan.owner_id,
            router_id=plan.router_id,
            account_number=await _next_account_number(db, reserved),
        )
        db.add(customer)
        customers.append(customer)
    await db.flush()
    created_ids = [c.id for c in customers]
    await db.commit()
    plan.created_customer_ids = created_ids
    return created_ids


def report_payload(
    plan: StaticImport, *, router_name: Optional[str], source_file: str, dry_run: bool,
) -> Dict[str, Any]:
    rows = plan.rows
    creating = [r for r in rows if r.action == "create"]
    payload: Dict[str, Any] = {
        "success": not plan.has_errors,
        "stage": plan.stage,
        "router_id": plan.router_id,
        "router_name": router_name,
        "source_file": source_file,
        "dry_run": dry_run,
        "summary": {
            "rows_total": len(rows),
            "to_create": len(creating),
            "skipped": sum(1 for r in rows if r.action == "skip"),
            "errors": sum(1 for r in rows if r.action == "error"),
            "active": sum(1 for r in creating if r.status == CustomerStatus.ACTIVE),
            "inactive": sum(1 for r in creating if r.status == CustomerStatus.INACTIVE),
            "plans_to_create": len(plan.pending_plans),
        },
        "plans_to_create": [
            {"label": p.label, "name": p.name, "speed": p.speed, "price": p.price}
            for p in plan.pending_plans
        ],
        "rows": [
            {
                "row": r.row,
                "name": r.name,
                "static_ip": r.static_ip,
                "mac": r.mac,
                "phone": r.phone,
                "plan_label": r.plan_label,
                "plan_id": r.plan_id,
                "plan_name": r.plan_name,
                "expiry": r.expiry.isoformat() if r.expiry else None,
                "status": r.status.value.lower() if r.status is not None and r.action != "skip" else None,
                "action": r.action,
                "reason": "; ".join(r.reasons) if r.reasons else None,
            }
            for r in rows
        ],
        "warnings": list(plan.warnings),
    }
    if not dry_run:
        payload["created_customer_ids"] = list(plan.created_customer_ids)
    return payload

"""Bulk import of static-IP customers (CSV/XLSX), preview by default.

Contract (the dashboard builds against it):
``POST /api/routers/{router_id}/static-customers/import`` and
``GET /api/static-customers/import-template``. Row rules live in
``app/services/static_ip_import.py``.

DB session discipline (AGENTS.md): the request session is committed before
the upload is read, the import is validated and written in one short
transaction, and router provisioning is scheduled only after that commit —
``schedule_static_provision`` opens its own short sessions and runs the
RouterOS work in the background.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import CustomerStatus
from app.services.auth import get_current_user, verify_token
from app.services.customer_events import actor_label, store_event_rows
from app.services.pppoe_customer_import import read_workbook_records
from app.services.router_helpers import get_router_by_id
from app.services.static_ip import schedule_static_provision
from app.services.static_ip_import import (
    TEMPLATE_CSV,
    ImportFileError,
    apply_static_import,
    build_static_import,
    load_mapping_plans,
    read_csv_records,
    report_payload,
)
from app.services.subscription import enforce_active_subscription

logger = logging.getLogger(__name__)

router = APIRouter(tags=["static-ip-import"])

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
TEMPLATE_FILENAME = "static-ip-customers-template.csv"


def _parse_plan_mapping(raw_json: Optional[str]) -> Dict[str, int]:
    if not raw_json or not raw_json.strip():
        return {}
    try:
        raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"plan_mapping_json must be valid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="plan_mapping_json must be a JSON object")
    out: Dict[str, int] = {}
    for label, plan_id in raw.items():
        if isinstance(plan_id, bool):
            plan_id = None
        try:
            out[str(label)] = int(plan_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid plan id for plan '{label}': {plan_id}",
            ) from exc
    return out


async def _read_upload(file: UploadFile) -> bytes:
    data = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=400, detail="File is larger than 10 MB")
    return bytes(data)


def _read_xlsx_bytes(data: bytes, sheet: Optional[str]):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
            temp_path = tmp.name
            tmp.write(data)
        return read_workbook_records(temp_path, sheet_name=sheet)
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning("Could not delete temporary static import workbook %s", temp_path)


@router.get("/api/static-customers/import-template")
async def static_customers_import_template():
    """Blank CSV template with the expected headers and two example rows."""
    return Response(
        content=TEMPLATE_CSV,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{TEMPLATE_FILENAME}"'},
    )


@router.post("/api/routers/{router_id}/static-customers/import")
async def import_router_static_customers(
    router_id: int,
    file: UploadFile = File(...),
    sheet: Optional[str] = Form(None),
    apply_changes: bool = Form(False, alias="apply"),
    create_missing_plans: bool = Form(False),
    default_plan_price: int = Form(0),
    plan_mapping_json: Optional[str] = Form(None),
    source_timezone: str = Form("Africa/Nairobi"),
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Preview (default) or apply a bulk import of static-IP customers onto one router."""
    try:
        user = await get_current_user(token, db)
        enforce_active_subscription(user)
        router_obj = await get_router_by_id(db, router_id, user.id, getattr(user, "role", None))
        if not router_obj:
            raise HTTPException(status_code=404, detail="Router not found")

        if create_missing_plans and default_plan_price <= 0:
            raise HTTPException(
                status_code=400,
                detail="create_missing_plans requires default_plan_price greater than 0",
            )

        filename = Path(file.filename or "").name or "upload"
        lower = filename.lower()
        if lower.endswith(".csv"):
            kind = "csv"
        elif lower.endswith(".xlsx"):
            kind = "xlsx"
        else:
            raise HTTPException(status_code=400, detail="Upload a .csv or .xlsx file")

        mapping = _parse_plan_mapping(plan_mapping_json)
        router_name = router_obj.name
        owner_id = router_obj.user_id
        # Nothing is held open while the upload is read and parsed.
        await db.commit()

        data = await _read_upload(file)
        if not data.strip():
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        try:
            if kind == "csv":
                records = read_csv_records(data)
            else:
                records = await asyncio.to_thread(_read_xlsx_bytes, data, (sheet or "").strip() or None)
        except ImportFileError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Could not read {kind.upper()} file: {type(exc).__name__}: {exc}",
            ) from exc

        try:
            mapping_plans = await load_mapping_plans(db, owner_id, mapping)
            plan = await build_static_import(
                db,
                records,
                router_id=router_id,
                owner_id=owner_id,
                mapping_plans=mapping_plans,
                create_missing_plans=create_missing_plans,
                default_plan_price=default_plan_price,
                source_timezone=source_timezone,
            )
        except ImportFileError as exc:
            await db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if not apply_changes or plan.has_errors:
            # Preview, or an apply refused because a row is wrong: write nothing.
            await db.rollback()
            return report_payload(plan, router_name=router_name, source_file=filename,
                                  dry_run=not apply_changes)

        created_ids = await apply_static_import(db, plan)
    finally:
        await file.close()

    # --- committed; everything below runs with no transaction open ---
    created_rows = [row for row in plan.rows if row.action == "create"]
    active_ids = [
        cid for cid, row in zip(created_ids, created_rows) if row.status == CustomerStatus.ACTIVE
    ]
    logger.info(
        "[STATIC-IMPORT] router %s (%s) by user %s from %s: created %d customers "
        "(%d active, %d inactive), %d skipped, %d plans created",
        router_id, router_name, user.id, filename, len(created_ids), len(active_ids),
        len(created_ids) - len(active_ids), sum(1 for r in plan.rows if r.action == "skip"),
        sum(1 for p in plan.pending_plans if p.plan_id is not None),
    )

    try:
        await store_event_rows([
            {
                "customer_id": cid,
                "user_id": owner_id,
                "router_id": router_id,
                "category": "change",
                "event_type": "customer_created",
                "severity": "info",
                "source": "admin",
                "actor_user_id": user.id,
                "actor_label": actor_label(user),
                "message": (
                    f"Customer imported from {filename} (row {row.row}) on plan "
                    f"{row.plan_name}, router {router_name}"
                ),
                "details": {"source": "static_ip_import", "source_file": filename, "source_row": row.row},
            }
            for cid, row in zip(created_ids, created_rows)
        ])
    except Exception as exc:  # best effort, like record_customer_event
        logger.warning("[AUDIT] could not record static import events: %s", exc)

    for cid in active_ids:
        schedule_static_provision(cid, action="static_ip_import")

    return report_payload(plan, router_name=router_name, source_file=filename, dry_run=False)

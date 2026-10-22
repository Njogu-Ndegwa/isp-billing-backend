"""Admin-only support desk snapshot.

Dennis's support dashboard is built on his laptop (tickets, worklog, product
backlog, response times...). To read it from anywhere, the laptop pushes the
finished JSON to the host over the root SSH key it already has, written
atomically (tmp + mv) into a directory that docker-compose.hetzner.yml
bind-mounts read-only into this container. No table, no migration, no new
secret: this endpoint just reads the file on each request and hands it back
verbatim, plus ``received_at`` (the file's mtime, i.e. when the server got it).

Status codes:
  200  the pushed JSON object + "received_at"
  404  {"detail": "No support desk snapshot yet"} - nothing pushed yet
  503  the file exists but is unreadable, too large, or not a JSON object
       (a bad push must not 500; the next good push fixes it)

The snapshot holds customer conversation summaries, so it is ADMIN-only and
sent with Cache-Control: no-store.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.database import get_db
from app.db.models import User, UserRole
from app.services.auth import get_current_user, verify_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin-support-desk"])

NOT_FOUND_DETAIL = "No support desk snapshot yet"
UNREADABLE_DETAIL = "Support desk snapshot is unreadable; push it again"


class SnapshotMissing(Exception):
    pass


class SnapshotUnreadable(Exception):
    pass


async def _require_admin(token: str, db: AsyncSession) -> User:
    user = await get_current_user(token, db)
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _reject_constant(value: str):
    # NaN / Infinity parse in Python but cannot be re-serialised as JSON.
    raise ValueError(f"non-JSON constant {value}")


def read_snapshot(path: str, max_bytes: int) -> Tuple[Dict[str, Any], str]:
    """Return (snapshot, received_at_iso). Blocking; call off the event loop."""
    try:
        with open(path, "rb") as fh:
            stat = os.fstat(fh.fileno())
            raw = fh.read(max_bytes + 1)
    except (FileNotFoundError, NotADirectoryError):
        raise SnapshotMissing()
    except OSError as exc:
        raise SnapshotUnreadable(f"cannot open: {exc.__class__.__name__}")

    if len(raw) > max_bytes:
        raise SnapshotUnreadable(f"larger than {max_bytes} bytes")
    try:
        data = json.loads(raw.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SnapshotUnreadable(f"invalid JSON: {exc.__class__.__name__}")
    if not isinstance(data, dict):
        raise SnapshotUnreadable("top level is not a JSON object")

    received_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    return data, received_at.isoformat().replace("+00:00", "Z")


@router.get("/api/admin/support-desk")
async def get_support_desk_snapshot(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_token),
):
    await _require_admin(token, db)
    # Release the pooled connection before touching the filesystem.
    await db.commit()
    try:
        data, received_at = await asyncio.to_thread(
            read_snapshot,
            settings.SUPPORT_DESK_SNAPSHOT_PATH,
            settings.SUPPORT_DESK_SNAPSHOT_MAX_BYTES,
        )
    except SnapshotMissing:
        raise HTTPException(status_code=404, detail=NOT_FOUND_DETAIL)
    except SnapshotUnreadable as exc:
        logger.warning("support desk snapshot unreadable: %s", exc)
        raise HTTPException(status_code=503, detail=UNREADABLE_DETAIL)

    data["received_at"] = received_at
    return JSONResponse(content=data, headers={"Cache-Control": "no-store"})

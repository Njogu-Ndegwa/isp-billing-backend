"""
Persist notable router log entries to the database for historical tracking.
Called by the PPPoE and Hotspot log endpoints after fetching logs from the router.
"""
import logging
import re
from datetime import datetime
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import RouterLogEntry, RouterLogSeverity

logger = logging.getLogger(__name__)

NOTABLE_PATTERNS = [
    (re.compile(r"(auth|authentication)\s*(fail|error|reject)", re.IGNORECASE), RouterLogSeverity.ERROR),
    (re.compile(r"disconnect", re.IGNORECASE), RouterLogSeverity.WARNING),
    (re.compile(r"(pool|address).*(exhaust|full|no\s+free)", re.IGNORECASE), RouterLogSeverity.ERROR),
    (re.compile(r"interface.*(down|link\s*down)", re.IGNORECASE), RouterLogSeverity.WARNING),
    (re.compile(r"(timeout|timed?\s*out)", re.IGNORECASE), RouterLogSeverity.WARNING),
    (re.compile(r"(error|fail)", re.IGNORECASE), RouterLogSeverity.ERROR),
]


def _classify_entry(entry: Dict[str, Any]) -> RouterLogSeverity | None:
    """Return severity if the entry is notable, else None."""
    message = entry.get("message", "")
    for pattern, severity in NOTABLE_PATTERNS:
        if pattern.search(message):
            return severity
    return None


def _extract_username(message: str) -> str | None:
    """Try to extract a username from a log message."""
    m = re.search(r"<([^>]+)>", message)
    if m:
        return m.group(1)
    m = re.search(r"user\s+['\"]?(\S+)", message, re.IGNORECASE)
    if m:
        return m.group(1).strip("'\"")
    return None


async def persist_notable_logs(
    db: AsyncSession,
    router_id: int,
    log_entries: List[Dict[str, Any]],
    topic_filter: str = "",
) -> int:
    """
    Scan log entries and persist notable ones to the database.
    Returns count of entries persisted.
    """
    persisted = 0
    for entry in log_entries:
        severity = _classify_entry(entry)
        if severity is None:
            continue

        message = entry.get("message", "")
        topics = entry.get("topics", topic_filter)
        username = _extract_username(message)

        log_record = RouterLogEntry(
            router_id=router_id,
            topic=topics[:50] if topics else "unknown",
            message=message[:1000],
            username=username,
            severity=severity,
            router_timestamp=entry.get("time", ""),
        )
        db.add(log_record)
        persisted += 1

    if persisted > 0:
        try:
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to persist {persisted} log entries: {e}")
            await db.rollback()
            return 0

    return persisted

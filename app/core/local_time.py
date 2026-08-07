"""Local billing-calendar helpers.

Every timestamp in this app is stored in UTC, but the people reading the
dashboards live in East Africa Time (UTC+3). A rolling "last 24 hours" window
therefore always spills into yesterday evening, which is not what a reseller
means by "today" — they mean 00:00 EAT until now. These helpers convert
between UTC and the local billing calendar so day filters start at local
midnight instead of "now minus N hours".

A fixed offset (rather than a tzdata zone) is deliberate: EAT has no DST and
the app has no per-reseller timezone yet. If that ever changes, widen
``LOCAL_UTC_OFFSET_HOURS`` handling here rather than at each call site.
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple

from app.config import settings

# Bandwidth snapshots are pruned after 30 days
# (``mikrotik_background.BANDWIDTH_HISTORY_RETENTION_DAYS``), so a calendar
# window can never usefully reach further back than 30 local days. Duplicated
# as a plain int so request paths don't import the background job module.
MAX_HISTORY_CALENDAR_DAYS = 30

CALENDAR_PRESETS = ("today", "yesterday", "this_month")


def local_offset() -> timedelta:
    return timedelta(hours=settings.LOCAL_UTC_OFFSET_HOURS)


def to_local(dt: datetime) -> datetime:
    """UTC naive datetime -> local naive datetime."""
    return dt + local_offset()


def to_utc(local_dt: datetime) -> datetime:
    """Local naive datetime -> UTC naive datetime."""
    return local_dt - local_offset()


def local_now(now_utc: Optional[datetime] = None) -> datetime:
    return to_local(now_utc or datetime.utcnow())


def local_midnight_utc(now_utc: Optional[datetime] = None, *, days_back: int = 0) -> datetime:
    """UTC instant of local midnight ``days_back`` local days ago.

    ``days_back=0`` is the midnight that started the current local day;
    ``days_back=-1`` is the midnight that ends it (exclusive upper bound).
    """
    ln = local_now(now_utc)
    midnight_local = datetime(ln.year, ln.month, ln.day) - timedelta(days=days_back)
    return to_utc(midnight_local)


def calendar_day_window(days: int, now_utc: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """UTC ``[start, end)`` covering the last ``days`` local calendar days, today included."""
    days = max(1, int(days))
    return (
        local_midnight_utc(now_utc, days_back=days - 1),
        local_midnight_utc(now_utc, days_back=-1),
    )


def parse_local_date(value: str) -> datetime:
    """Parse ``YYYY-MM-DD`` as a local calendar date (raises ``ValueError``)."""
    return datetime.strptime(value.strip(), "%Y-%m-%d")


def _span_days(start_utc: datetime, end_utc: datetime) -> int:
    return max(1, round((end_utc - start_utc).total_seconds() / 86400))


def resolve_usage_window(
    *,
    hours: Optional[int] = None,
    days: Optional[int] = None,
    preset: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    now_utc: Optional[datetime] = None,
    max_rolling_hours: int = 24 * 30,
) -> dict:
    """Resolve usage-history filter params into a UTC ``[start, end)`` window.

    Priority mirrors ``/api/dashboard/analytics``: explicit dates > preset >
    calendar days > rolling hours. Only the rolling-hours branch keeps the
    legacy "now minus N hours" behaviour, so existing callers that pass just
    ``hours`` are unaffected.

    Raises ``ValueError`` with a user-safe message on bad input.
    """
    now_utc = now_utc or datetime.utcnow()
    truncated = False

    if start_date or end_date:
        try:
            start_local = parse_local_date(start_date) if start_date else to_local(now_utc)
            end_local = parse_local_date(end_date) if end_date else to_local(now_utc)
        except ValueError:
            raise ValueError("Invalid date format. Use YYYY-MM-DD")
        start = to_utc(datetime(start_local.year, start_local.month, start_local.day))
        end = to_utc(
            datetime(end_local.year, end_local.month, end_local.day) + timedelta(days=1)
        )
        if end <= start:
            raise ValueError("end_date must not be before start_date")
        mode = "calendar"
        label = f"{start_local:%Y-%m-%d} to {end_local:%Y-%m-%d}"

    elif preset:
        preset = preset.strip().lower()
        if preset not in CALENDAR_PRESETS:
            raise ValueError(f"Invalid preset. Choose from: {', '.join(CALENDAR_PRESETS)}")
        if preset == "today":
            start, end = calendar_day_window(1, now_utc)
            label = "Today"
        elif preset == "yesterday":
            start = local_midnight_utc(now_utc, days_back=1)
            end = local_midnight_utc(now_utc, days_back=0)
            label = "Yesterday"
        else:  # this_month
            ln = local_now(now_utc)
            start = to_utc(datetime(ln.year, ln.month, 1))
            end = local_midnight_utc(now_utc, days_back=-1)
            label = "This month"
        mode = "calendar"

    elif days:
        days = max(1, min(int(days), MAX_HISTORY_CALENDAR_DAYS))
        start, end = calendar_day_window(days, now_utc)
        mode = "calendar"
        label = "Today" if days == 1 else f"Last {days} days"

    else:
        rolling_hours = max(1, min(int(hours or 24), max_rolling_hours))
        start = now_utc - timedelta(hours=rolling_hours)
        end = now_utc
        return {
            "start": start,
            "end": end,
            "mode": "rolling",
            "label": f"Last {rolling_hours}h",
            "days": None,
            "hours": rolling_hours,
            "truncated": False,
        }

    # Never ask for snapshots older than retention — the rows are pruned, so a
    # wider window silently returns a half-empty first day instead of an error.
    retention_floor = local_midnight_utc(now_utc, days_back=MAX_HISTORY_CALENDAR_DAYS - 1)
    if start < retention_floor:
        start = retention_floor
        truncated = True

    span_days = _span_days(start, end)
    return {
        "start": start,
        "end": end,
        "mode": mode,
        "label": label,
        "days": span_days,
        "hours": max(1, round((min(end, now_utc) - start).total_seconds() / 3600)),
        "truncated": truncated,
    }

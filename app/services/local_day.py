"""Dates in a query, on the account's own calendar.

The database stores naive UTC. A reseller picks "23 Nov" on their own clock,
and in Nairobi that day starts at 21:00 UTC on the 22nd: read as a UTC day,
every payment between local midnight and 03:00 lands in the day before.

So for a filter value:

* a date without a time ("2026-11-23") is that calendar day in the account's
  market time zone (EAT for Kenya, WAT for Cameroon; Kenya when unknown);
* a time written with its offset ("2026-11-23T00:30:00+03:00", or ...Z) is
  that exact moment, whoever asks;
* a time without an offset is UTC, as every time the API returns is.

Everything comes back as naive UTC, ready to compare with a DateTime column.
An end is inclusive: the last microsecond of the day, for ``column <= end``.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from app.services.markets import reseller_market
from app.services.subscription_reminders import _zone

_TICK = timedelta(microseconds=1)


def _day_start(day: date, user) -> datetime:
    """Midnight starting ``day`` on the account's clock, as naive UTC."""
    local = datetime(day.year, day.month, day.day, tzinfo=_zone(reseller_market(user).timezone))
    return local.astimezone(timezone.utc).replace(tzinfo=None)


def _day_end(day: date, user) -> datetime:
    return _day_start(day + timedelta(days=1), user) - _TICK


def _read(value: str) -> tuple[date | None, datetime | None]:
    """A calendar day, or a moment as naive UTC. ValueError when it is neither."""
    text = value.strip()
    try:
        return date.fromisoformat(text), None
    except ValueError:
        pass
    when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc).replace(tzinfo=None)
    return None, when


def day_bounds(day: str, user) -> tuple[datetime, datetime]:
    """First and last moment of the YYYY-MM-DD day on the account's clock."""
    parsed = datetime.strptime(day.strip(), "%Y-%m-%d").date()
    return _day_start(parsed, user), _day_end(parsed, user)


def range_start(value: str, user) -> datetime:
    """Where a range begins: the start of a local day, or the moment given."""
    day, when = _read(value)
    return _day_start(day, user) if day else when


def range_end(value: str, user) -> datetime:
    """Where a range ends (inclusive): the end of a local day, or the moment given."""
    day, when = _read(value)
    return _day_end(day, user) if day else when

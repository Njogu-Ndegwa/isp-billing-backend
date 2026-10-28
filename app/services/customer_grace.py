"""Per-customer grace period.

A reseller can let a customer stay connected for a while after their paid
``expiry`` without changing that expiry: the customer's access is cut at
``expiry + grace`` (the "effective expiry") instead of at ``expiry``. The paid
expiry stays the source of truth for renewals, reminders and reporting.

Grace never moves the billing date. A payment made during grace extends from
the paid expiry, not from payment time (see :func:`renewal_expiry`): expiry
Oct 1, 3-day grace, a 30-day plan paid on Oct 3 runs to Oct 31. Only a
customer whose access has fully ended restarts from payment time.

Grace is a standing setting (``Customer.grace_period_minutes``): it applies
after every expiry until the reseller changes it. Every code path that decides
whether a customer should still have access must compare ``now`` against
``effective_expiry`` rather than the raw ``expiry``.

SQL filters keep using the raw ``expiry`` as a cheap pre-filter (anyone whose
effective expiry has passed has a raw expiry that passed too) and then filter
in Python with :func:`effective_expiry_of`. That keeps the queries portable
between Postgres and the SQLite test database, and the extra rows are only the
handful of customers currently inside their grace window.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

# Upper bound a reseller may set. Long enough for "pays at month end", short
# enough that grace cannot become indefinite free service by accident.
MAX_GRACE_MINUTES = 30 * 24 * 60


def normalize_grace_minutes(value: Any) -> int:
    """Coerce a stored or submitted grace value to a valid minute count."""
    try:
        minutes = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(minutes, MAX_GRACE_MINUTES))


def grace_delta(customer: Any) -> timedelta:
    return timedelta(minutes=normalize_grace_minutes(getattr(customer, "grace_period_minutes", 0)))


def effective_expiry_of(expiry: Optional[datetime], grace_minutes: Any) -> Optional[datetime]:
    """``expiry + grace`` for raw column values (e.g. from a column select)."""
    if expiry is None:
        return None
    minutes = normalize_grace_minutes(grace_minutes)
    if not minutes:
        return expiry
    return expiry + timedelta(minutes=minutes)


def effective_expiry(customer: Any) -> Optional[datetime]:
    """When this customer's access actually ends.

    A paused customer (``paused_at`` set) gets no grace: their expiry is
    frozen at the pause moment, so access has ended until they are resumed.
    """
    if getattr(customer, "paused_at", None) is not None:
        return getattr(customer, "expiry", None)
    return effective_expiry_of(
        getattr(customer, "expiry", None),
        getattr(customer, "grace_period_minutes", 0),
    )


def access_floor(now: datetime) -> datetime:
    """SQL pre-filter bound for "may still have access" queries.

    ``Customer.expiry > access_floor(now)`` keeps every customer whose
    effective expiry can still be in the future; follow it with
    :func:`has_access_time` in Python. Pair it with a status filter so the
    extra rows are only customers actually inside a grace window.
    """
    return now - timedelta(minutes=MAX_GRACE_MINUTES)


def access_prefilter(now: datetime):
    """SQL clause: rows whose effective expiry may be after ``now``.

    For queries with no status filter, where :func:`access_floor` alone would
    pull in a month of long-expired rows. Follow with :func:`has_access_time`.
    """
    from sqlalchemy import and_, or_

    from app.db.models import Customer

    return or_(
        Customer.expiry > now,
        and_(Customer.grace_period_minutes > 0, Customer.expiry > access_floor(now)),
    )


def has_access_time(customer: Any, now: datetime) -> bool:
    """True while ``now`` is before the effective expiry."""
    eff = effective_expiry(customer)
    return eff is not None and eff > now


def is_in_grace(customer: Any, now: datetime) -> bool:
    """Paid time has ended but the grace window is still open."""
    expiry = getattr(customer, "expiry", None)
    eff = effective_expiry(customer)
    return expiry is not None and eff is not None and expiry <= now < eff


def grace_fields(customer: Any, now: datetime) -> dict:
    """API fields describing a customer's grace state."""
    eff = effective_expiry(customer)
    return {
        "grace_period_minutes": normalize_grace_minutes(
            getattr(customer, "grace_period_minutes", 0)
        ),
        "effective_expiry": eff.isoformat() if eff else None,
        "in_grace": is_in_grace(customer, now),
    }


def renewal_expiry(customer: Any, now: datetime, period: timedelta) -> datetime:
    """New paid expiry when ``period`` is bought at ``now``.

    Extends from the paid expiry while the customer still has access, paid
    time or grace, so grace never shifts the billing date. Restarts from
    ``now`` once access has ended, or when the purchase would not even reach
    ``now`` (a plan shorter than the grace already used), since a paid period
    that ends in the past is no use to anyone.
    """
    expiry = getattr(customer, "expiry", None)
    if expiry is not None and has_access_time(customer, now):
        extended = expiry + period
        if extended > now:
            return extended
    return now + period

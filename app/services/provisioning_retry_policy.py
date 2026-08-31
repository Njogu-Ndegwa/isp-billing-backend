"""Shared rapid-first retry policy for paid direct-router provisioning.

Paid access must feel immediate.  Keep the first several attempts eligible on
consecutive worker ticks so a short management-tunnel flap recovers quickly,
then retain a bounded slow tail for longer outages instead of declaring a paid
delivery permanently failed after only a few minutes.  Both hotspot and PPPoE
use the same policy.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, or_


PAID_PROVISIONING_RETRY_MAX_ATTEMPTS = 14

# Delay after N completed attempts before attempt N+1.  The first five delays
# are all below both existing worker cadences (97s hotspot / 113s PPPoE), so a
# new paid activation remains eligible on every early worker tick.  After that
# rapid lane, progressively back off and cap at 40 minutes.  This changes no
# scheduler cadence, batch size, worker concurrency, or DB-pool threshold.
PAID_PROVISIONING_RETRY_BACKOFF_SECONDS = (
    30,
    45,
    60,
    75,
    90,
    180,
    300,
    600,
    1200,
    2400,
)


def retry_delay_seconds(attempt_count: int | None) -> int:
    """Return the delay before retrying after ``attempt_count`` attempts."""
    count = max(int(attempt_count or 0), 0)
    if count == 0:
        return 0
    index = min(count - 1, len(PAID_PROVISIONING_RETRY_BACKOFF_SECONDS) - 1)
    return PAID_PROVISIONING_RETRY_BACKOFF_SECONDS[index]


def retry_due_clause(model, now: datetime, *, max_attempts: int):
    """SQL predicate selecting attempts whose bounded backoff has elapsed.

    ``last_attempt_at`` is the authoritative start of a RouterOS attempt. Null
    legacy rows are immediately eligible. The caller still scopes state, paid
    lifecycle, retry age, and batch size.
    """
    clauses = [model.attempt_count <= 0, model.last_attempt_at.is_(None)]
    for count in range(1, max_attempts):
        delay = retry_delay_seconds(count)
        clauses.append(
            and_(
                model.attempt_count == count,
                model.last_attempt_at <= now - timedelta(seconds=delay),
            )
        )
    return or_(*clauses)


def retryable_connectivity_error_clause(model):
    """Match legacy terminal failures caused by reachability, not bad config.

    Before this policy, attempt five became terminal immediately. Selecting
    only transport-shaped errors lets the new worker resume those paid attempts
    without repeatedly replaying deterministic RouterOS validation failures.
    """
    return or_(
        model.last_error.ilike("%connect%"),
        model.last_error.ilike("%timeout%"),
        model.last_error.ilike("%timed out%"),
        model.last_error.ilike("%unreachable%"),
    )

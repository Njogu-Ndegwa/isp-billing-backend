"""Shared bounded backoff policy for paid direct-router provisioning.

Five attempts on every scheduler tick exhausted in only a few minutes during a
management-tunnel flap. Keep the existing four-hour retry window, but spread a
bounded number of attempts across it. Both hotspot and PPPoE use the same policy
so a successful payment has consistent delivery behavior.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, or_


PAID_PROVISIONING_RETRY_MAX_ATTEMPTS = 14

# Delay after N completed attempts before attempt N+1. After the eighth
# attempt, cap at 30 minutes. Fourteen total attempts fit inside four hours:
# immediate, then approximately 1, 3, 6, 11, 19, 32, 53, 83, ... 233 minutes.
PAID_PROVISIONING_RETRY_BACKOFF_SECONDS = (
    60,
    120,
    180,
    300,
    480,
    780,
    1260,
    1800,
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

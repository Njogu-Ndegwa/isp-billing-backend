"""Problem routers: the few routers costing paying customers right now, and
whether the ones we fixed have stayed fixed.

Built by the ops-health snapshot job from data we already store (DB-only, one
short session, no network I/O):

* ``router_availability_checks`` -> how often the router was reachable, and how
  many times it dropped (online -> offline);
* ``provisioning_attempts``       -> paid deliveries: first-try success,
  payments that were never connected (state ``failed``), and payments still
  WAITING right now (``retry_pending`` / stuck in flight). A waiting payment only
  turns ``failed`` after hours of retries, so without the live count a router
  whose customers are paying into a dead tunnel stays invisible until then.

Each router is judged on an AFTER window against a BEFORE window. For a router
whose management tunnel was changed (``routers.management_tunnel_changed_at``
within the lookback) the split is at that moment, so a fix shows as a clean
before/after; otherwise AFTER is the last 24 h and BEFORE the six days before.

The admin can also ask for a different AFTER window ("last 1h", "last 6h", ...)
through ``build_problem_routers_window``: AFTER is then the last N hours (or
since a tunnel change inside them), BEFORE the rest of the week, and the
evidence thresholds shrink with the window so a short window can still call a
router fixed. That is how an admin checks a fix without waiting a day.

States: ``attention`` (bad now, or paid customers waiting), ``recovering`` (was bad, better but not clean
or too little activity to tell), ``fixed`` (was bad, clean since). Routers of
suspended/inactive resellers are left out: they are cut off at the platform.

The section never raises the overall health status: some router is almost
always struggling, and a permanently amber dashboard teaches people to ignore
it. The card carries its own colours.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from app.db import database
from app.db.models import ProvisioningAttempt, ProvisioningState, Router, RouterAvailabilityCheck, User

RECENT = timedelta(hours=24)
LOOKBACK = timedelta(days=7)
CACHE_TTL = timedelta(minutes=5)
# On-demand windows re-read the tables at most this often (all windows share one read).
INPUTS_TTL = timedelta(seconds=60)
MIN_WINDOW_HOURS = 1
MAX_WINDOW_HOURS = 72       # leaves at least four days of BEFORE to compare against
MAX_ATTENTION_ROWS = 12
MAX_OUTCOME_ROWS = 10       # recovering + fixed
MAX_WINDOW_ROWS = 25        # per state group, on-demand windows
# Recovering/fixed rows are only worth showing for routers we deliberately fixed,
# or that had a genuinely bad week; one bad day that healed itself is noise.
SIGNIFICANT_BEFORE_LOST = 5
# A healthy delivery lands in seconds and a single transient retry within ~2 min;
# anything still undelivered after this is a customer who paid and is waiting.
WAITING_GRACE = timedelta(minutes=5)
_WAITING_STATES = (ProvisioningState.RETRY_PENDING.value, ProvisioningState.IN_PROGRESS.value,
                   ProvisioningState.SCHEDULED.value)
ADVISORY_SOURCES = ("expired_cleanup",)  # failure-only probes; they bias reachability down

_TUNNEL_LABELS = {"sstp": "SSTP", "wireguard": "WireGuard"}
_STATE_ORDER = {"attention": 0, "recovering": 1, "fixed": 2}

# Module cache: the snapshot runs every minute, this needs refreshing every few.
_CACHE: dict = {}


def reset_cache() -> None:
    _CACHE.clear()


@dataclass(frozen=True)
class Thresholds:
    """How much activity a window needs before a rate is trusted.

    The 24 h values are the originals. Shorter windows scale them down in
    proportion (a router sees ~0.4 availability checks an hour at the median, so
    "12 checks" can never happen in one hour), with a floor so a single missed
    check or retried payment cannot condemn a router in a short window.
    """
    first_try_payments: int = 10   # judge first-try % once this many payments settled
    reach_checks: int = 12         # judge reachability once this many checks
    evidence_payments: int = 5     # enough payments to call a router fixed
    evidence_checks: int = 12      # ... or enough checks


DEFAULT_THRESHOLDS = Thresholds()


def thresholds_for(window: timedelta) -> Thresholds:
    f = min(1.0, window / RECENT)
    return Thresholds(
        first_try_payments=max(5, math.ceil(10 * f)),
        reach_checks=max(4, math.ceil(12 * f)),
        evidence_payments=max(2, math.ceil(5 * f)),
        evidence_checks=max(4, math.ceil(12 * f)),
    )


def window_label(window: timedelta) -> str:
    hours = int(window.total_seconds() // 3600)
    if hours >= 48 and hours % 24 == 0:
        return f"{hours // 24} days"
    return f"{hours}h"


@dataclass
class Window:
    start: datetime
    end: datetime
    checks: int = 0
    online: int = 0
    drops: int = 0
    payments: int = 0
    settled: int = 0
    first_try: int = 0
    lost: int = 0

    @property
    def reach_pct(self) -> Optional[int]:
        return round(100 * self.online / self.checks) if self.checks else None

    @property
    def first_try_pct(self) -> Optional[int]:
        return round(100 * self.first_try / self.settled) if self.settled else None

    def as_dict(self) -> dict:
        return {"payments": self.payments, "lost": self.lost, "first_try_pct": self.first_try_pct,
                "reach_pct": self.reach_pct, "drops": self.drops}


def is_bad(w: Window, th: Thresholds = DEFAULT_THRESHOLDS) -> bool:
    """Costing customers: lost payments, a poor first-try rate, or mostly unreachable."""
    return (
        w.lost >= 2
        or (w.settled >= th.first_try_payments and (w.first_try_pct or 0) < 80)
        or (w.checks >= th.reach_checks and (w.reach_pct or 0) < 70)
    )


def is_clean(w: Window, th: Thresholds = DEFAULT_THRESHOLDS) -> bool:
    return (
        w.lost == 0
        and (w.settled < th.evidence_payments or (w.first_try_pct or 0) >= 90)
        and (w.checks < th.evidence_checks or (w.reach_pct or 0) >= 85)
    )


def has_evidence(w: Window, th: Thresholds = DEFAULT_THRESHOLDS) -> bool:
    return w.settled >= th.evidence_payments or w.checks >= th.evidence_checks


def classify(before: Window, after: Window, th: Thresholds = DEFAULT_THRESHOLDS) -> Optional[str]:
    if is_bad(after, th):
        return "attention"
    if not is_bad(before):
        return None
    if is_clean(after, th) and has_evidence(after, th):
        return "fixed"
    return "recovering"


def criteria(window: Optional[timedelta] = None) -> list[str]:
    """The rules above in plain words, so the card can say how it judged."""
    th = thresholds_for(window) if window else DEFAULT_THRESHOLDS
    span = f"the last {window_label(window)}" if window else "the last 24h"
    fix_note = ("inside the window" if window else "in the last 7 days")
    return [
        f"Needs attention: a paid customer has waited over {int(WAITING_GRACE.total_seconds() // 60)} min "
        f"to be connected (right now), or in {span}: 2+ paid customers not connected, under 80% of "
        f"payments connected first time (once {th.first_try_payments}+ payments), or reachable under "
        f"70% of the time (once {th.reach_checks}+ checks).",
        "Not connected means retries gave up, which takes hours, so a recent undelivered payment "
        "shows as waiting instead.",
        f"Recovering: was bad earlier in the week, not bad in {span} but not clean yet, or too "
        "little activity to confirm.",
        f"Fixed: was bad earlier in the week, and clean in {span} (nothing lost, 90%+ first time, "
        f"85%+ reachable) with at least {th.evidence_payments} payments or {th.evidence_checks} "
        "checks to go on.",
        f"A router whose management tunnel was changed {fix_note} is judged from the change.",
        "Left out: routers of suspended or inactive resellers, and routers silent all week unless "
        "customers are still paying into them.",
    ]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _age_label(delta: timedelta) -> str:
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    return f"{hours // 24} days"


def waiting_reason(waiting: int, oldest: datetime, now: datetime,
                   last_online_at: Optional[datetime]) -> str:
    text = (f"{_plural(waiting, 'paid customer')} waiting to be connected"
            f" (oldest {_age_label(now - oldest)})")
    if last_online_at is None:
        return text + " · never reached"
    if now - last_online_at >= WAITING_GRACE:
        return text + f" · no contact since {last_online_at.strftime('%d %b %H:%M UTC')}"
    return text


def _since_label(fix: Optional[dict], window: Optional[timedelta] = None) -> str:
    if not fix:
        return f"in the last {window_label(window or RECENT)}"
    return f"since the move to {fix['label']} ({fix['at_short']})"


def reason_for(state: str, before: Window, after: Window, fix: Optional[dict],
               last_online_at: Optional[datetime] = None, window: Optional[timedelta] = None,
               th: Thresholds = DEFAULT_THRESHOLDS) -> str:
    """``fix`` is passed only when AFTER starts at the tunnel change."""
    since = _since_label(fix, window)
    if state == "attention":
        # Name the condition that actually tripped is_bad(), most customer-visible first.
        if after.lost >= 2:
            return f"{_plural(after.lost, 'paid customer')} not connected {since}"
        if after.settled >= th.first_try_payments and (after.first_try_pct or 0) < 80:
            return f"Only {after.first_try_pct}% of {after.payments} payments connected first time {since}"
        if after.online == 0 and last_online_at is not None:
            return f"Down: no contact since {last_online_at.strftime('%d %b %H:%M UTC')}"
        return f"Reachable {after.reach_pct}% of the time {since} ({_plural(after.drops, 'drop')})"
    was = []
    if before.lost:
        was.append(f"{before.lost} not connected")
    if before.reach_pct is not None and before.reach_pct < 85:
        was.append(f"reachable {before.reach_pct}%")
    was_text = f" (before: {', '.join(was)})" if was else ""
    if state == "fixed":
        if after.payments:
            return f"Clean {since}: {_plural(after.payments, 'payment')}, all connected{was_text}"
        return f"Clean {since}: reachable {after.reach_pct}%{was_text}"
    if not has_evidence(after, th):
        return f"Too little activity {since} to confirm the fix{was_text}"
    return (f"Better {since}: {after.lost} not connected, {after.first_try_pct}% first time"
            f"{was_text}")


def _fix_info(management_tunnel: Optional[str], changed_at: Optional[datetime], now: datetime) -> Optional[dict]:
    if not changed_at or not management_tunnel or changed_at > now or now - changed_at > LOOKBACK:
        return None
    return {
        "tunnel": management_tunnel,
        "label": _TUNNEL_LABELS.get(management_tunnel, management_tunnel),
        "at": changed_at.replace(microsecond=0).isoformat() + "Z",
        "at_short": changed_at.strftime("%d %b %H:%M UTC"),
    }


def evaluate(routers: list[dict], checks: list[tuple], attempts: list[tuple], now: datetime,
             window: Optional[timedelta] = None) -> dict:
    """Pure core. routers: dicts with id, name, reseller, tunnel, management_tunnel,
    changed_at, last_online_at. checks: (router_id, checked_at, is_online).
    attempts: (router_id, created_at, state, attempt_count, router_updated_at).

    ``window`` None is the dashboard snapshot (AFTER = since a tunnel change in the
    last 7 days, else the last 24 h). A window judges AFTER on the last N hours,
    or since a tunnel change inside them, with thresholds scaled to its length.
    """
    recent = window or RECENT
    th = thresholds_for(window) if window else DEFAULT_THRESHOLDS
    split_at: dict[int, datetime] = {}
    fixes: dict[int, Optional[dict]] = {}
    split_on_fix: dict[int, bool] = {}
    for r in routers:
        fix = _fix_info(r.get("management_tunnel"), r.get("changed_at"), now)
        fixes[r["id"]] = fix
        if window is None:
            split_on_fix[r["id"]] = bool(fix)
            split_at[r["id"]] = r["changed_at"] if fix else now - RECENT
        else:
            on_fix = bool(fix) and r["changed_at"] > now - window
            split_on_fix[r["id"]] = on_fix
            split_at[r["id"]] = r["changed_at"] if on_fix else now - window

    windows: dict[int, tuple[Window, Window]] = {
        rid: (Window(now - LOOKBACK, at), Window(at, now)) for rid, at in split_at.items()
    }
    # A custom window keeps a router the default 24 h view flags, so a fix to it
    # shows up as recovering/fixed instead of the router silently vanishing.
    day: dict[int, Window] = {rid: Window(now - RECENT, now) for rid in windows} if window else {}

    by_router: dict[int, list[tuple[datetime, bool]]] = defaultdict(list)
    for rid, checked_at, is_online in checks:
        if rid in windows:
            by_router[rid].append((checked_at, bool(is_online)))
    for rid, samples in by_router.items():
        before, after = windows[rid]
        prev: Optional[bool] = None
        for checked_at, online in sorted(samples):
            w = after if checked_at >= after.start else before
            w.checks += 1
            w.online += online
            if rid in day and checked_at >= day[rid].start:
                day[rid].checks += 1
                day[rid].online += online
            if prev is True and not online:
                w.drops += 1
            prev = online

    waiting: dict[int, int] = defaultdict(int)
    oldest_waiting: dict[int, datetime] = {}
    for rid, created_at, state, attempt_count, updated_at in attempts:
        if rid not in windows:
            continue
        before, after = windows[rid]
        w = after if created_at >= after.start else before
        w.payments += 1
        state_value = state.value if hasattr(state, "value") else str(state)
        if state_value in _WAITING_STATES:
            if now - created_at >= WAITING_GRACE:
                waiting[rid] += 1
                if rid not in oldest_waiting or created_at < oldest_waiting[rid]:
                    oldest_waiting[rid] = created_at
            continue
        targets = [w]
        if rid in day and created_at >= day[rid].start:
            targets.append(day[rid])
        for t in targets:
            t.settled += 1
            if state_value == ProvisioningState.FAILED.value:
                t.lost += 1
            elif updated_at is not None and (attempt_count or 0) <= 1:
                t.first_try += 1

    rows = []
    for r in routers:
        last_online = r.get("last_online_at")
        n_waiting = waiting.get(r["id"], 0)
        # No contact for the whole lookback: an abandoned or long-dead site, not a
        # problem anyone can act on today (the tunnels section counts those) --
        # unless customers are still paying into it.
        if not n_waiting and (last_online is None or now - last_online > LOOKBACK):
            continue
        before, after = windows[r["id"]]
        fix = fixes[r["id"]]
        if n_waiting:
            state = "attention"
            reason = waiting_reason(n_waiting, oldest_waiting[r["id"]], now, last_online)
        else:
            state = classify(before, after, th)
            if not state:
                continue
            significant = bool(fix) or before.lost >= SIGNIFICANT_BEFORE_LOST
            if window is not None and not significant:
                significant = is_bad(day[r["id"]])
            if state != "attention" and not significant:
                continue
            reason = reason_for(state, before, after, fix if split_on_fix[r["id"]] else None,
                                last_online, window, th)
        oldest = oldest_waiting.get(r["id"])
        if split_on_fix[r["id"]]:
            row_window = "since_fix"
        else:
            row_window = "last_24h" if window is None else "last_window"
        rows.append({
            "router_id": r["id"],
            "router_name": r.get("name"),
            "reseller": r.get("reseller"),
            "tunnel": r.get("tunnel"),
            "state": state,
            "reason": reason,
            "waiting": n_waiting,
            "oldest_waiting_at": oldest.replace(microsecond=0).isoformat() + "Z" if oldest else None,
            "fix": fix,
            "window": row_window,
            "after": after.as_dict(),
            "before": before.as_dict(),
            "last_online_at": (r["last_online_at"].replace(microsecond=0).isoformat() + "Z"
                               if r.get("last_online_at") else None),
        })
    def _rank(x):
        # Customers waiting now first, then lost payments, first-try failures, reachability.
        return (_STATE_ORDER[x["state"]], -x["waiting"], -x["after"]["lost"], -(100 - (x["after"]["first_try_pct"] or 100)),
                x["after"]["reach_pct"] if x["after"]["reach_pct"] is not None else 101,
                -x["before"]["lost"])
    rows.sort(key=_rank)
    counts = {s: sum(1 for x in rows if x["state"] == s) for s in _STATE_ORDER}
    max_attention = MAX_WINDOW_ROWS if window else MAX_ATTENTION_ROWS
    max_outcomes = MAX_WINDOW_ROWS if window else MAX_OUTCOME_ROWS
    attention = [x for x in rows if x["state"] == "attention"][:max_attention]
    outcomes = [x for x in rows if x["state"] != "attention"][:max_outcomes]

    def _lost(span: timedelta, recent_side: bool) -> int:
        return sum(1 for rid, created_at, state, *_ in attempts
                   if rid in windows and (created_at >= now - span) == recent_side
                   and getattr(state, "value", state) == ProvisioningState.FAILED.value)
    before_days = (LOOKBACK - RECENT).total_seconds() / 86400
    result = {
        "counts": counts,
        "paid_not_connected_24h": _lost(RECENT, True),
        "paid_not_connected_daily_avg_before": round(_lost(RECENT, False) / before_days, 1),
        # Live: paid customers not yet connected (past the grace period), and on how many routers.
        "waiting_now": sum(waiting.get(r["id"], 0) for r in routers),
        "waiting_routers": sum(1 for r in routers if waiting.get(r["id"])),
        "routers": attention + outcomes,
        "routers_total": len(rows),
    }
    if window:
        # Same headline for the chosen window: lost in it vs the average per
        # window-length over the rest of the week.
        windows_before = (LOOKBACK - recent) / recent
        result.update({
            "window_hours": int(recent.total_seconds() // 3600),
            "window_label": window_label(recent),
            "criteria": criteria(window),
            "paid_not_connected_window": _lost(recent, True),
            "paid_not_connected_avg_before": round(_lost(recent, False) / windows_before, 1),
        })
    return result


async def _load_inputs(now: datetime) -> tuple[list[dict], list, list]:
    """Routers (minus cut-off resellers), checks and attempts for the lookback.

    One short read-only session, released before returning. Shared briefly by
    all on-demand windows so flicking between them costs one read.
    """
    cached = _CACHE.get("inputs")
    if cached is not None and timedelta(0) <= now - cached[0] < INPUTS_TTL:
        return cached[1]

    from app.services.ops_health import is_owner_cut_off, tunnel_type_for_router

    since = now - LOOKBACK
    async with database.async_session() as db:
        router_rows = (await db.execute(
            select(Router.id, Router.name, Router.ip_address, Router.management_tunnel,
                   Router.management_tunnel_changed_at, Router.last_online_at,
                   User.organization_name, User.email, User.subscription_status)
            .outerjoin(User, User.id == Router.user_id)
        )).all()
        check_rows = (await db.execute(
            select(RouterAvailabilityCheck.router_id, RouterAvailabilityCheck.checked_at,
                   RouterAvailabilityCheck.is_online)
            .where(RouterAvailabilityCheck.checked_at >= since,
                   RouterAvailabilityCheck.source.notin_(ADVISORY_SOURCES))
        )).all()
        attempt_rows = (await db.execute(
            select(ProvisioningAttempt.router_id, ProvisioningAttempt.created_at,
                   ProvisioningAttempt.provisioning_state, ProvisioningAttempt.attempt_count,
                   ProvisioningAttempt.router_updated_at)
            .where(ProvisioningAttempt.created_at >= since, ProvisioningAttempt.router_id.isnot(None))
        )).all()
        await db.commit()

    routers = [
        {"id": rid, "name": name, "reseller": org or email, "management_tunnel": mt, "changed_at": changed,
         "last_online_at": last_online, "tunnel": tunnel_type_for_router(ip, mt)}
        for rid, name, ip, mt, changed, last_online, org, email, owner_status in router_rows
        if not is_owner_cut_off(owner_status)
    ]
    inputs = (routers, check_rows, attempt_rows)
    _CACHE["inputs"] = (now, inputs)
    return inputs


async def build_problem_routers_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    cached = _CACHE.get("value")
    if cached is not None and now - _CACHE["at"] < CACHE_TTL:
        return {**cached, "cached": True}

    routers, check_rows, attempt_rows = await _load_inputs(now)
    result = {"status": "unknown", "window_hours": int(RECENT.total_seconds() // 3600),
              **evaluate(routers, check_rows, attempt_rows, now)}
    _CACHE.update(at=now, value=result)
    return result


async def build_problem_routers_window(now: datetime, hours: int) -> dict:
    """Problem routers judged on the last ``hours`` hours (clamped to 1..72)."""
    hours = max(MIN_WINDOW_HOURS, min(MAX_WINDOW_HOURS, int(hours)))
    routers, check_rows, attempt_rows = await _load_inputs(now)
    return {
        "status": "unknown",
        "generated_at": now.replace(microsecond=0).isoformat() + "Z",
        **evaluate(routers, check_rows, attempt_rows, now, window=timedelta(hours=hours)),
    }

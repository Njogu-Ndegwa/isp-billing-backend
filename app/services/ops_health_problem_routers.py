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

States: ``attention`` (bad now, or paid customers waiting), ``recovering`` (was bad, better but not clean
or too little activity to tell), ``fixed`` (was bad, clean since). Routers of
suspended/inactive resellers are left out: they are cut off at the platform.

The section never raises the overall health status: some router is almost
always struggling, and a permanently amber dashboard teaches people to ignore
it. The card carries its own colours.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select

from app.db import database
from app.db.models import ProvisioningAttempt, ProvisioningState, Router, RouterAvailabilityCheck, User
from app.services.router_diagnosis import attach_diagnoses

RECENT = timedelta(hours=24)
LOOKBACK = timedelta(days=7)
CACHE_TTL = timedelta(minutes=5)
MAX_ATTENTION_ROWS = 12
MAX_OUTCOME_ROWS = 10       # recovering + fixed
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


def latest_section() -> tuple[Optional[dict], Optional[datetime]]:
    """The last section this process built (without diagnoses) and when."""
    return _CACHE.get("value"), _CACHE.get("at")


def _with_diagnoses(section: dict, now: datetime) -> dict:
    # Live "what is ailing it" from the router_diagnosis job; in-memory only, no I/O.
    # Each row gets ``diagnosis`` (dict or None); the cached section is not mutated.
    return {**section, "routers": attach_diagnoses(section.get("routers") or [], now)}


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


def is_bad(w: Window) -> bool:
    """Costing customers: lost payments, a poor first-try rate, or mostly unreachable."""
    return (
        w.lost >= 2
        or (w.settled >= 10 and (w.first_try_pct or 0) < 80)
        or (w.checks >= 12 and (w.reach_pct or 0) < 70)
    )


def is_clean(w: Window) -> bool:
    return (
        w.lost == 0
        and (w.settled < 5 or (w.first_try_pct or 0) >= 90)
        and (w.checks < 12 or (w.reach_pct or 0) >= 85)
    )


def has_evidence(w: Window) -> bool:
    return w.settled >= 5 or w.checks >= 12


def classify(before: Window, after: Window) -> Optional[str]:
    if is_bad(after):
        return "attention"
    if not is_bad(before):
        return None
    if is_clean(after) and has_evidence(after):
        return "fixed"
    return "recovering"


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


def _since_label(fix: Optional[dict]) -> str:
    if not fix:
        return "in the last 24h"
    return f"since the move to {fix['label']} ({fix['at_short']})"


def reason_for(state: str, before: Window, after: Window, fix: Optional[dict],
               last_online_at: Optional[datetime] = None) -> str:
    since = _since_label(fix)
    if state == "attention":
        # Name the condition that actually tripped is_bad(), most customer-visible first.
        if after.lost >= 2:
            return f"{_plural(after.lost, 'paid customer')} not connected {since}"
        if after.settled >= 10 and (after.first_try_pct or 0) < 80:
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
    if not has_evidence(after):
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


def evaluate(routers: list[dict], checks: list[tuple], attempts: list[tuple], now: datetime) -> dict:
    """Pure core. routers: dicts with id, name, reseller, tunnel, management_tunnel,
    changed_at, last_online_at. checks: (router_id, checked_at, is_online).
    attempts: (router_id, created_at, state, attempt_count, router_updated_at)."""
    split_at: dict[int, datetime] = {}
    fixes: dict[int, Optional[dict]] = {}
    for r in routers:
        fix = _fix_info(r.get("management_tunnel"), r.get("changed_at"), now)
        fixes[r["id"]] = fix
        split_at[r["id"]] = r["changed_at"] if fix else now - RECENT

    windows: dict[int, tuple[Window, Window]] = {
        rid: (Window(now - LOOKBACK, at), Window(at, now)) for rid, at in split_at.items()
    }

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
        w.settled += 1
        if state_value == ProvisioningState.FAILED.value:
            w.lost += 1
        elif updated_at is not None and (attempt_count or 0) <= 1:
            w.first_try += 1

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
            state = classify(before, after)
            if not state:
                continue
            if state != "attention" and not fix and before.lost < SIGNIFICANT_BEFORE_LOST:
                continue
            reason = reason_for(state, before, after, fix, last_online)
        oldest = oldest_waiting.get(r["id"])
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
            "window": "since_fix" if fix else "last_24h",
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
    attention = [x for x in rows if x["state"] == "attention"][:MAX_ATTENTION_ROWS]
    outcomes = [x for x in rows if x["state"] != "attention"][:MAX_OUTCOME_ROWS]

    def _lost(recent: bool) -> int:
        return sum(1 for rid, created_at, state, *_ in attempts
                   if rid in windows and (created_at >= now - RECENT) == recent
                   and getattr(state, "value", state) == ProvisioningState.FAILED.value)
    before_days = (LOOKBACK - RECENT).total_seconds() / 86400
    return {
        "counts": counts,
        "paid_not_connected_24h": _lost(True),
        "paid_not_connected_daily_avg_before": round(_lost(False) / before_days, 1),
        # Live: paid customers not yet connected (past the grace period), and on how many routers.
        "waiting_now": sum(waiting.get(r["id"], 0) for r in routers),
        "waiting_routers": sum(1 for r in routers if waiting.get(r["id"])),
        "routers": attention + outcomes,
        "routers_total": len(rows),
    }


async def build_problem_routers_section(now: datetime, baselines: Optional[dict] = None) -> dict:
    cached = _CACHE.get("value")
    if cached is not None and now - _CACHE["at"] < CACHE_TTL:
        return {**_with_diagnoses(cached, now), "cached": True}

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
    result = {"status": "unknown", "window_hours": int(RECENT.total_seconds() // 3600),
              **evaluate(routers, check_rows, attempt_rows, now)}
    _CACHE.update(at=now, value=result)
    return _with_diagnoses(result, now)

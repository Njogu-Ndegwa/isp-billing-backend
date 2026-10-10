"""Is this reseller's SMS actually going out, and if not, why?

Backs the gateway status card. Three sources, cheapest first:

  1. `sms_messages` history: sent/failed counts per window, the failure
     reasons grouped, and the current run of consecutive failures (DB only).
  2. The gateway account row: when its settings last changed and the result
     of the last test send (DB only).
  3. A live balance check against the gateway (network). Only for a reseller
     on their own gateway whose provider supports it, cached briefly.

A reseller on their own gateway pays their vendor directly, so portal credits
say nothing about whether they can send. Before this existed, a TextSMS key
that stopped working on 2026-10-08 failed every message for two days and the
reseller only saw "0 credits" with no reason.

Session discipline: collect() is DB + CPU only (it decrypts credentials but
never calls out). status() commits before the balance call so no pooled
connection is held across the network.
"""

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    MessagingProviderAccount,
    ResellerInboxMessage,
    SmsMessage,
    SmsMessageKind,
    SmsMessageStatus,
    User,
)
from app.services.messaging import accounts as provider_accounts
from app.services.messaging import registry
from app.services.messaging.base import BalanceResult, MessagingProvider
from app.services.messaging.failure_reasons import (
    BLOCKING,
    LOW_BALANCE,
    PER_MESSAGE,
    classify,
    describe,
)

logger = logging.getLogger(__name__)

# Router status alerts are the one admin->reseller send billed to (and sent
# on the gateway of) the reseller, so they count toward their gateway health.
_RESELLER_BILLED_CATEGORIES = ("router_status_alert",)

WINDOWS = (("24h", timedelta(hours=24)), ("7d", timedelta(days=7)),
           ("30d", timedelta(days=30)))
HISTORY = timedelta(days=30)
# Temporary failures (gateway hiccup, timeout) need a run before we call the
# gateway down; one blocking failure (bad key, no balance) is already proof.
TEMPORARY_STREAK_FAILING = 3

BALANCE_TTL_SECONDS = 60
_balance_cache: dict[tuple, tuple[float, dict]] = {}

ALERT_KEY_PREFIX = "gwfail"


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def provider_label(provider: Optional[str]) -> Optional[str]:
    """Human name of a provider ("TextSMS Kenya"), or None."""
    if not provider:
        return None
    try:
        return registry.get_spec(provider).label
    except ValueError:
        return provider


async def collect(
    db: AsyncSession, user_id: int, *, now: Optional[datetime] = None,
) -> tuple[dict, Optional[MessagingProvider], Optional[tuple]]:
    """Build the report from the DB. Returns (report, provider, balance_cache_key).

    `provider` is a ready-to-call gateway client when a live balance check is
    possible, else None. No network I/O happens here.
    """
    now = now or datetime.utcnow()
    gateway = await provider_accounts.gateway_summary(db, user_id)
    own = gateway["source"] == "reseller"
    account: Optional[MessagingProviderAccount] = (
        await db.get(MessagingProviderAccount, gateway["account_id"])
        if gateway.get("account_id") else None
    )
    label = gateway.get("provider_label") if own else None

    rows = (await db.execute(
        select(SmsMessage.created_at, SmsMessage.status, SmsMessage.error,
               SmsMessage.provider_account_id)
        .where(
            SmsMessage.user_id == user_id,
            or_(SmsMessage.kind == SmsMessageKind.RESELLER_TO_CUSTOMER,
                SmsMessage.category.in_(_RESELLER_BILLED_CATEGORIES)),
            SmsMessage.status.in_([SmsMessageStatus.SENT,
                                   SmsMessageStatus.DELIVERED,
                                   SmsMessageStatus.FAILED]),
            SmsMessage.created_at >= now - HISTORY,
        )
        .order_by(SmsMessage.created_at.desc())
    )).all()

    def _ok(status) -> bool:
        return status in (SmsMessageStatus.SENT, SmsMessageStatus.DELIVERED)

    windows: dict[str, dict] = {}
    for name, span in WINDOWS:
        cut = now - span
        sent = sum(1 for r in rows if r.created_at >= cut and _ok(r.status))
        failed = sum(1 for r in rows if r.created_at >= cut and not _ok(r.status))
        total = sent + failed
        windows[name] = {
            "sent": sent, "failed": failed, "total": total,
            "success_rate": round(sent / total, 3) if total else None,
        }

    last_sent = next((r.created_at for r in rows if _ok(r.status)), None)
    last_failed = next((r.created_at for r in rows if not _ok(r.status)), None)

    # Failure reasons over the whole window, most actionable first.
    grouped: dict[str, dict] = {}
    for r in rows:
        if _ok(r.status):
            continue
        row_own = own and account is not None and r.provider_account_id == account.id
        info = describe(r.error, own_gateway=row_own, provider_label=label)
        entry = grouped.get(info["code"])
        if entry is None:
            # rows are newest-first, so the first one seen is the latest.
            grouped[info["code"]] = {**info, "count": 1, "last_seen": _iso(r.created_at)}
        else:
            entry["count"] += 1
    severity_rank = {BLOCKING: 0, "temporary": 1, PER_MESSAGE: 2}
    reasons = sorted(grouped.values(),
                     key=lambda e: (severity_rank.get(e["severity"], 3), -e["count"]))

    health = _health(rows, account if own else None, own=own, label=label, now=now)

    report = {
        "gateway": {
            **gateway,
            "label": account.label if account else None,
            "settings_changed_at": _iso(account.updated_at) if account else None,
            "last_test_at": _iso(account.last_test_at) if account else None,
            "last_test_ok": account.last_test_ok if account else None,
            "last_test_error": account.last_test_error if account else None,
        },
        "health": health,
        "metrics": {
            "windows": windows,
            "last_sent_at": _iso(last_sent),
            "last_failed_at": _iso(last_failed),
        },
        "failure_reasons": reasons,
        "balance": {"available": False,
                    "unavailable_reason": None if own else "platform_gateway"},
        "generated_at": _iso(now),
    }

    provider = None
    cache_key = None
    if own and account is not None:
        try:
            provider = provider_accounts._build(account)
        except Exception as exc:
            logger.warning("Gateway health: account %s will not build: %s", account.id, exc)
            report["balance"] = {"available": False, "unavailable_reason": "config_error",
                                 "error": str(exc)[:255]}
        else:
            if provider.supports_balance:
                cache_key = (account.id, _iso(account.updated_at))
            else:
                report["balance"] = {"available": False, "unavailable_reason": "not_supported"}
                provider = None
    return report, provider, cache_key


def _health(rows, account: Optional[MessagingProviderAccount], *, own: bool,
            label: Optional[str], now: datetime) -> dict:
    """Current state from the newest evidence backwards."""
    # On their own gateway only that account's sends count: failures from the
    # platform gateway before they switched say nothing about it.
    if own and account is not None:
        events = [(r.created_at, r.status in (SmsMessageStatus.SENT,
                                              SmsMessageStatus.DELIVERED), r.error)
                  for r in rows if r.provider_account_id == account.id]
        if account.last_test_at and account.last_test_ok is not None:
            events.append((account.last_test_at, bool(account.last_test_ok),
                           account.last_test_error))
        events.sort(key=lambda e: e[0], reverse=True)
    else:
        events = [(r.created_at, r.status in (SmsMessageStatus.SENT,
                                              SmsMessageStatus.DELIVERED), r.error)
                  for r in rows]

    # A bad phone number is the customer's problem, not the gateway's: it
    # neither proves the gateway works nor counts against it.
    events = [e for e in events if e[1] or classify(e[2]).severity != PER_MESSAGE]

    base = {"state": "idle", "reason": None, "consecutive_failures": 0,
            "failing_since": None, "message": "No messages sent in the last 30 days."}
    if not events:
        return base

    streak = []
    for event in events:
        if event[1]:
            break
        streak.append(event)

    newest = events[0][0]
    # Settings saved after the newest evidence: the old failures may already
    # be fixed. Seconds of slack because a test send stamps both at once.
    changed_after = (
        own and account is not None and account.updated_at is not None
        and account.updated_at > newest + timedelta(seconds=5)
    )

    if streak:
        latest = describe(streak[0][2], own_gateway=own, provider_label=label)
        failing_since = streak[-1][0]
        if changed_after:
            return {**base, "state": "unverified", "reason": latest,
                    "consecutive_failures": len(streak),
                    "failing_since": _iso(failing_since),
                    "message": ("Gateway settings were changed after the last "
                                "failure. The next message will confirm whether "
                                "it is fixed — or send a test SMS now.")}
        if latest["severity"] == BLOCKING or len(streak) >= TEMPORARY_STREAK_FAILING:
            return {**base, "state": "failing", "reason": latest,
                    "consecutive_failures": len(streak),
                    "failing_since": _iso(failing_since),
                    "message": (("Your last message failed. " if len(streak) == 1
                                 else f"Your last {len(streak)} messages have failed. ")
                                + f"{latest['title']}.")}

    recent = [e for e in events if e[0] >= now - timedelta(hours=24)]
    recent_failed = [e for e in recent if not e[1]]
    if recent_failed:
        latest = describe(recent_failed[0][2], own_gateway=own, provider_label=label)
        return {**base, "state": "degraded", "reason": latest,
                "consecutive_failures": len(streak),
                "message": (f"{len(recent_failed)} of {len(recent)} messages in the "
                            "last 24 hours failed. Newer messages are going out.")}
    return {**base, "state": "ok", "message": "Messages are going out normally."}


async def _check_balance(provider: MessagingProvider, cache_key: tuple,
                         *, force: bool) -> dict:
    hit = _balance_cache.get(cache_key)
    if hit and not force and hit[0] > time.monotonic():
        return dict(hit[1])
    try:
        result: BalanceResult = await provider.get_balance()
    except Exception as exc:
        logger.warning("Balance check crashed for %s: %s", provider.name, exc)
        result = BalanceResult(ok=False, error=f"network_error: {exc}"[:255])
    out = {
        "available": True,
        "ok": result.ok,
        "balance": result.balance,
        "unit": result.unit,
        "error": result.error,
        "checked_at": _iso(datetime.utcnow()),
    }
    _balance_cache[cache_key] = (time.monotonic() + BALANCE_TTL_SECONDS, out)
    return dict(out)


def _fold_balance_into_health(report: dict) -> None:
    """A live answer from the gateway beats inferring from old sends."""
    bal = report["balance"]
    if not bal.get("available"):
        return
    label = report["gateway"].get("provider_label")
    health = report["health"]
    if not bal.get("ok"):
        reason = describe(bal.get("error"), own_gateway=True, provider_label=label)
        bal["failure"] = reason
        if reason["severity"] == BLOCKING:
            report["health"] = {**health, "state": "failing", "reason": reason,
                                "message": f"{reason['title']}. Checked just now with "
                                           f"{label or 'your gateway'}."}
        return
    if bal.get("balance") is not None and bal["balance"] <= 0:
        reason = LOW_BALANCE.as_dict(label)
        reason["raw_error"] = None
        report["health"] = {**health, "state": "failing", "reason": reason,
                            "message": f"Your {label or 'gateway'} balance is "
                                       f"{bal['balance']:g}. Top up to keep sending."}
    elif health["state"] == "failing" and health["reason"] and \
            health["reason"]["code"] == "invalid_credentials":
        # The key works now (the balance call just authenticated with it), so
        # the earlier rejections are history, not the current state.
        report["health"] = {**health, "state": "unverified",
                            "message": "The gateway accepts your login now. The "
                                       "next message will confirm sending works."}


async def status(db: AsyncSession, user_id: int, *, include_balance: bool = True,
                 force_balance: bool = False) -> dict:
    """The full report for one reseller. Commits `db` before any network call."""
    report, provider, cache_key = await collect(db, user_id)
    await db.commit()  # release the pooled connection before calling out
    if include_balance and provider is not None and cache_key is not None:
        report["balance"] = await _check_balance(provider, cache_key, force=force_balance)
        _fold_balance_into_health(report)
    return report


# ---------------------------------------------------------------------------
# Inbox alert when an own gateway starts failing
# ---------------------------------------------------------------------------

async def alert_if_failing(user_id: int) -> bool:
    """Tell a reseller, once per failure episode, that their gateway is failing.

    Called by the dispatcher after a send with failures on the reseller's own
    gateway. DB only (no balance call) and never raises. The inbox row's
    broadcast_id carries "gwfail:<account>:<first failure epoch>", which is
    stable for the length of one run of failures, so repeated sends during
    the same outage add nothing and the next outage alerts again.
    """
    from app.db.database import async_session
    from app.services.reseller_welcome import _resolve_sender_admin_id

    try:
        async with async_session() as db:
            report, _, _ = await collect(db, user_id)
            health = report["health"]
            gateway = report["gateway"]
            if gateway["source"] != "reseller" or health["state"] != "failing":
                return False
            since = health.get("failing_since")
            since_epoch = int(datetime.fromisoformat(since).timestamp()) if since else 0
            key = f"{ALERT_KEY_PREFIX}:{gateway['account_id']}:{since_epoch}"
            exists = (await db.execute(
                select(ResellerInboxMessage.id).where(
                    ResellerInboxMessage.recipient_user_id == user_id,
                    ResellerInboxMessage.broadcast_id == key,
                ).limit(1)
            )).scalar_one_or_none()
            if exists is not None:
                return False
            reseller = await db.get(User, user_id)
            admin_id = await _resolve_sender_admin_id(db, reseller) if reseller else None
            if admin_id is None:
                return False
            reason = health["reason"] or {}
            body = (
                f"{health['message']}\n\n"
                f"Why: {reason.get('explanation', '')}\n"
                f"Fix: {reason.get('action', '')}\n\n"
                "Until this is fixed your automatic reminders and receipts are "
                "not reaching customers. Open Messaging → Gateway to see details."
            )
            db.add(ResellerInboxMessage(
                recipient_user_id=user_id,
                sender_user_id=admin_id,
                subject=f"SMS not sending: {reason.get('title', 'gateway problem')}"[:200],
                body=body[:2000],
                broadcast_id=key,
            ))
            await db.commit()
            logger.info("Gateway failure alert sent to reseller %s (%s, %s)",
                        user_id, key, reason.get("code"))
            return True
    except Exception:
        logger.exception("Gateway failure alert for reseller %s crashed", user_id)
        return False

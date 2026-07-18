# 2026-07-18 — Lost Safaricom B2B result callbacks → KES 12,713 double-paid

## Symptoms

- Nightly payout run (2026-07-17 23:59 UTC): 15 of ~40 B2B transactions stuck
  `pending` forever (KES 10,438 net). Previous nights completed in ~2s each.
- Admin panel showed those resellers still owed, so admin re-paid 5 of them
  manually in the morning — and the manual sends ALSO stuck pending, prompting
  repeat clicks (reseller 266 sent 4×, reseller 188 sent 3×).
- Total duplicated: KES 12,713 across resellers 10, 66, 183, 188, 266.

## Root cause

Safaricom accepted the payment requests (ResponseCode 0 → money sent) but
**never delivered the result callbacks** for 15+3 transactions. Verified: app up
all night, zero failed callback requests in Apache/uvicorn logs, every callback
that DID arrive processed fine (one took 3 min vs the usual 2 s — their result
queue was degraded). Design flaw that turned lost callbacks into double-pays:

1. `ResellerPayout` rows are only created by the result callback, so an
   unconfirmed transaction leaves the balance "owed".
2. Nothing ever reconciled stuck pendings (no Transaction Status API for B2B;
   the 90 s reconciliation job is C2B/STK only).
3. The manual payout endpoint had no in-flight guard at all, and the scheduled
   job's 20 h dedupe window ignores pendings older than 20 h.

Same failure mode existed before (2026-06-10 manual double-pay, 2026-06-21
stuck pending) — the callback loss is a Safaricom-side hazard, not a regression.

## Recovery (done 2026-07-18)

- Matched all stuck pendings against the M-Pesa org-portal statement
  (amount + destination paybill + timestamp, drift ≤3 s).
- 14 confirmed-sent → marked completed with real receipts + payout/fee rows
  (payouts 1667–1680). Double-paid resellers now negative and auto-recouping.
- 4 absent from statement (txns 1971/1985/1989/1995) → marked failed, resellers
  still owed. All four have Safaricom-rejected destination paybills.
- Affected resellers messaged via inbox + called personally.
- Scratchpad scripts: `match_statement.py`, `reconcile_b2b_pendings.py`.

## Fix (code, this commit)

- **In-flight guard**: a PENDING or TIMEOUT B2B transaction of any age/trigger
  blocks payouts to that reseller — in `run_daily_payouts` and the manual
  endpoint (409). Uncertainty never releases money.
- **Status reconciliation**: `run_b2b_status_reconciliation` (every 10 min,
  pool-pressure-aware) queries Safaricom's Transaction Status API for stuck
  transactions; `/api/mpesa/b2b/status-result` settles them — definitive
  "Completed" → same ledger rows as the callback; definitive failure → failed;
  ambiguous → stays blocked. Correlation map is in-memory; restarts just cause
  a re-query. `process_b2b_timeout` no longer implies nightly blind retry.

## Verification

- `tests/test_b2b_status_reconciliation.py` (guard blocks pending/timeout/
  manual-triggered; settle completed/failed/ambiguous/idempotent/uncorrelated;
  job selects only stale unresolved) + existing B2B suites — all pass.

## Live-verified Safaricom Transaction Status API quirks (2026-07-18, txn 1029)

- Request field for the original transaction's id is **`OriginalConversationID`**
  — NOT `OriginatorConversationID` as the B2B payment ack names it. Wrong name
  → `400.002.02`.
- Sending `TransactionID: ""` alongside it → all-empty ack (no errorCode).
- Result code **2033** = "receipt cannot be found by the specified
  OriginatorConversationID" = the payment was never processed. Auto-failed
  when the transaction is <48h old; older ones stay blocked for manual
  statement review (stale 2033 could mean aged out of their index).

## Follow-up
- Fix invalid destination paybills (SFC_IC0003 nightly: resellers 330/333/256/
  277/307; never-sent: 320→9285575, 241→5506814, 272→3463601).
- Reconcile June stuck pendings (txns 707/710/711/1029) against an older
  statement.
- Admin UI: surface unresolved-payout state instead of just the 409 text.

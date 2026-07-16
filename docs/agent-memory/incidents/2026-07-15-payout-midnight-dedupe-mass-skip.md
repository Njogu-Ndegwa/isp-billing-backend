# 2026-07-15 Daily B2B payout run silently mass-skipped owed resellers (midnight dedupe window)

## Summary

The nightly reseller payout job (fires 23:59 UTC = 2:59 AM EAT) appeared to
"break down in the middle and stop": on the 2026-07-14 23:59 UTC run it
initiated only 3 payouts (23:59:53–58) and paid nobody after midnight, even
though ~13 resellers were legitimately owed. Admin paid them manually at
03:27 UTC. No crash occurred — the run completed normally while silently
skipping almost everyone.

## Symptoms

- `b2b_transactions`: zero `triggered_by='scheduled'` rows on 2026-07-15
  (previous nights had 19–46), followed by a burst of `manual` rows at
  03:27–03:35 UTC.
- Previous nights show the run straddling midnight: rows at 23:59:4x–5x on
  day D plus 00:00:0x–00:00:3x on day D+1.
- From the admin dashboard this read as "one payment failed and everything
  after it never sent."

## Suspected Cause

Two independent defects, both confirmed live on the 2026-07-15 23:59 run:

1. **Midnight-straddling dedupe window (root cause of the mass skip).**
   `run_daily_payouts` deduped per reseller with
   `created_at >= utcnow().replace(hour=0, ...)` — the *calendar day*,
   recomputed mid-loop. The run fires at 23:59 and crosses midnight, so the
   previous night's payouts land just AFTER midnight (same calendar day as
   the next run's pre-midnight minute). During 23:59:00–23:59:59 the check
   counted last night's post-midnight payouts as "already paid today" and
   skipped every such reseller. Whether a reseller got paid depended on
   whether the loop reached them before or after midnight — oscillating,
   looks random, worst case (07-14) skipped nearly everyone.

2. **Empty-string Safaricom identifiers vs unique index.** Safaricom
   occasionally returns `{'ConversationID': '', 'ResponseCode': '', ...}`.
   Storing `''` collides with the unique index `ix_b2b_transactions_conversation_id`
   (NULLs don't collide, empty strings do) → `UniqueViolationError` when
   recording the failed transaction (seen for reseller 340 on 07-15 run).
   Since the June 10 per-reseller-session fix (c33f3c7) this only loses that
   one reseller's failure record; before it, this class of mid-loop error
   killed the whole run ("one fails, all fail").

## Fix Applied

- `app/services/mpesa_b2b.py`:
  - Dedupe window anchored once at run start as a rolling 20-hour window
    (`dedupe_window_start = utcnow() - 20h`). Still blocks a double fire
    within one night; last night's run (~24h old) stays eligible.
  - `_provider_id_or_none()` normalizes `''`/whitespace Safaricom IDs to
    NULL before storing (initiate, result callback, timeout callback).
  - Balance of KES 1 (can never net positive after the KES 1 Kadogo fee) is
    now skipped instead of raising a spurious "failed".
- Tests: `tests/test_b2b_payout_resilience.py` (midnight-straddle regression,
  in-window dedupe, KES-1 skip), `tests/test_mpesa_b2b_account_reference.py`
  (blank provider IDs stored as NULL).

## Verification

- `pytest tests/test_b2b_payout_resilience.py tests/test_mpesa_b2b_account_reference.py` — 7 passed.
- Log/DB forensics: 07-15 23:59 run completed `initiated=37 skipped=268 failed=5`
  with failures interleaved (resilience fix works); 13 of the 37 landed after
  midnight and would have been wrongly skipped again on 07-16 without this fix.
- After deploy, watch: `docker logs isp_billing_app | grep 'payout run complete'`
  — skipped count should reflect only true dedups/zero balances, and no
  `UniqueViolationError` on `ix_b2b_transactions_conversation_id`.

## Follow-Up Work

- One legacy row with `conversation_id=''` exists in `b2b_transactions`;
  harmless once code stops inserting `''`, but a one-off
  `UPDATE b2b_transactions SET conversation_id = NULL WHERE conversation_id = ''`
  would let future empty-response failures be recorded (needs approval — prod write).
- Docker logs die with the container on deploy (old container is removed) —
  yesterday's forensics had to come from the DB. Consider shipping app logs
  somewhere durable, or at least `docker logs > file` before deploys.
- Consider firing the job at 00:05 instead of 23:59 so a run never straddles
  midnight (cosmetic once the rolling window is in).

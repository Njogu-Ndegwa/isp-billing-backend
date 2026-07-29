# 2026-06-11 — Payout destination redirected to a third-party paybill

**Discovered:** 2026-07-29, during an integrity audit requested by the principal
behind Kennice Networks (reseller user 188, `mikekariuki697@gmail.com`).
**Money lost:** none. **Money at risk:** KES 4,845 over four days.

## Symptoms

The reseller's principal suspected the person operating the network was
diverting money. The digital ledger reconciled to the shilling, so the first
pass reported "no funneling". A second pass, prompted by asking specifically
whether the *destination* had ever changed, found it had.

## Timeline (UTC)

| When | What |
|---|---|
| 26 May 17:33 | Method 91 created — bank `852648` / acct `139738` (the real account) |
| **07 Jun 21:54** | Method 109 created — paybill `5652581`, label "Mpesa till" |
| **11 Jun 17:46** | Method 91 (real account) edited → `is_active = false` |
| 11 Jun 23:59 – 15 Jun 00:52 | 6 scheduled/manual B2B payouts, KES 4,845, `party_b = 5652581` — **all rejected**, `SFC_IC0003 Receiver party is invalid` |
| 14 Jun 04:15–04:17 | Methods 119 + 120 created, back to `852648` / `139738` |
| 15 Jun 04:04 | Method 109 deactivated |
| 15 Jun 23:59 | Payouts resume to the correct account — KES 1,800, catch-up for the stuck days |

The account holder confirmed on 2026-07-29: **"The till isn't mine."**

## Cause

Two gaps, both structural:

1. **No actor recorded.** `reseller_payment_methods` has `created_at` /
   `updated_at` and nothing else. The database could not say who added `5652581`
   or who deactivated the real account. Resellers share a single login with
   whoever operates the network for them, so even an application-level actor
   would have been ambiguous — but there was not even that.
2. **No notification.** Changing a payout destination was silent. The owner
   learned nothing, and would have learned nothing if the redirect had used a
   *valid* receiver.

Only Safaricom rejecting `5652581` as an invalid B2B receiver stopped the money.
That is luck, not a control.

## Fix

`app/services/payout_destination_alerts.py` + `payout_destination_change_log`
table (startup migration `run_payout_destination_audit_migrations` in `main.py`):

- Append-only audit row for every create / update / deactivate / reactivate of a
  payment method, and every re-pointing of a router to a different method.
  Records `actor_user_id` separately from `user_id`, plus before/after
  destination snapshots as readable text.
- Inbox + SMS alert to the account owner on every one of those changes, naming
  the old and new destination. `is_active` flips are reported as their own
  action rather than a generic "updated" — deactivating the real destination is
  exactly how this redirect was staged.
- Written after the endpoint commits, in its own short session, SMS
  fire-and-forget (Database Session Discipline). Never raises: a failed alert
  must not fail the edit, and the audit row is written even when the
  notification cannot go out.

Tests: `tests/test_payout_destination_alerts.py` (11), including a replay of
this incident's exact sequence.

## Still open

- **Shared logins.** Resellers have no sub-accounts, so "who did it" is only
  answerable down to the account, not the person. Operators need their own
  logins before the audit trail can name a human. Backlogged.
- **Notifications go to the registered account holder**, which in a
  principal/operator arrangement is the operator — i.e. potentially the person
  being audited. A separate security-contact address is needed.
- **No validation on update.** `_validate_fields` runs on create but not on
  `PUT /api/payment-methods/{id}`, which is why a till number could be saved
  into the paybill field and sit there for four days.

## Lesson

"Did the money go to the right place?" and "did the *destination* ever change?"
are different questions. Reconciling totals answers the first and silently
passes the second — a redirect that fails leaves the totals perfect. Always
diff the destination over time, not just the sums.

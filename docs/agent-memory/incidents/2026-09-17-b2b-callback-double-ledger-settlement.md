# 2026-09-17 B2B Callback Double Ledger Settlement

## Summary

One successful reseller withdrawal was recorded twice in the internal payout
ledger when duplicate Safaricom result callbacks ran concurrently. Safaricom
sent the money once, but the reseller dashboard showed two payouts and a
negative balance.

## Symptoms

- SafoLink/SafariLink showed KES 5,035 collected, KES 9,986 paid, KES 84 in
  charges, and a KES -5,035 balance.
- The database contained one completed B2B transaction and one Safaricom
  receipt (`UI9SH4PCPN`), but two KES 4,993 `reseller_payouts` rows and two
  KES 42 fee rows.
- The duplicate payout rows were created 31 milliseconds apart on
  2026-09-09 at 03:46:06 UTC.
- A fleet-wide audit found no other duplicated M-Pesa payout reference.

## Suspected Cause

`process_b2b_result` checked whether the B2B transaction was pending before
settling it, but did not lock the row. Two callback requests could therefore
both read `pending` before either committed. Each request created payout and fee
rows, and the later commit merely overwrote `b2b_transactions.payout_id` and
`charge_id` with its own row IDs.

## Fix Applied

- Lock B2B transaction rows with `SELECT ... FOR UPDATE` in the normal result,
  timeout, status-reconciliation, and manual-resolution paths.
- Skip settlement defensively when a transaction already links to a payout.
- Add a partial unique index on `reseller_payouts.reference` for M-Pesa B2B
  payouts so one Safaricom receipt cannot settle the ledger twice.
- Remove the orphan duplicate payout and fee rows after verifying that the B2B
  transaction points to the retained rows.

## Verification

- Sequential duplicate callback test creates one payout and one fee.
- PostgreSQL concurrency test delivers two callbacks simultaneously and asserts
  one payout and one fee.
- Database uniqueness test rejects duplicate M-Pesa payout references.
- Production audit must show one payout row, one fee row, and a zero balance for
  the affected reseller after repair.

## Follow-Up Work

- Alert when any M-Pesa payout reference appears more than once in ledger
  reporting; the unique index should make this impossible after deployment.

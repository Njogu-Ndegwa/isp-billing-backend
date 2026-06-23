# 2026-06-23 B2B Account Reference Truncation

## Summary

Reseller bank payouts could be sent with a shortened bank account number even
when the saved payment method contained the full value. The local transaction
record still stored the full account reference, making the outbound payload
look correct unless the actual Safaricom request body was inspected.

## Symptoms

- A reseller reported that payouts were going to the wrong bank account.
- The affected reported reseller email was `akcommunications01@gmail.com`.
- Pattern: a bank account ending in `0` appeared to lose that final digit when
  sent through the M-Pesa B2B request.

## Suspected Cause

`app/services/mpesa_b2b.py` sliced `AccountReference` to 13 characters in the
Daraja B2B request payload:

```python
"AccountReference": account_reference[:13]
```

For bank-account payouts, `AccountReference` is the destination account number,
so truncating it can turn a valid account identifier into a different valid
identifier. This is especially misleading because `B2BTransaction.account_reference`
stored the unsliced original value.

No production database inspection or manual production payout operation was run
as part of this investigation.

## Fix Applied

- Changed `initiate_b2b_payment` to send `AccountReference` exactly as provided.
- Added a regression test with a 14-digit account reference ending in `0`.

## Verification

- Ran:

```powershell
.\myEnv\Scripts\python.exe -m pytest tests\test_mpesa_b2b_account_reference.py tests\test_b2b_payout_resilience.py
```

- Result: `2 passed`.

## Follow-Up Work

- Before any future payout repair/backfill, get explicit current-conversation
  approval for production data inspection and any manual DB/provider action.
- Consider adding outbound B2B request auditing that records a masked hash or
  exact admin-visible payload for payout identifiers before sending.
- Consider payment-method validation for known bank account length constraints,
  but never silently shorten identifiers.

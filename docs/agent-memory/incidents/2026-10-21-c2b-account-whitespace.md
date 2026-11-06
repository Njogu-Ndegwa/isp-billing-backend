# 2026-10-21 C2B account references containing spaces stay unmatched

## Summary

A platform-paybill payment reached Bitwave but did not appear in the reseller's
available balance. The customer had already been activated manually, which
recorded the same amount as CASH. The receipt was still in the unmatched queue.

## Symptoms

- The C2B reference contained spaces between groups of digits.
- Removing those spaces produced an existing, valid customer account number.
- The unmatched reason was `invalid_luhn`, with no assigned reseller.
- A completed CASH payment for the same customer and amount followed the receipt
  by less than ten minutes. Its original provisioning attempt identified the
  earning router. The customer already had the paid service period.

## Cause

`parse_c2b_payload()` used `strip()`, which removed whitespace only at the ends.
Both validation and confirmation then rejected the grouped reference before
looking up the customer. The account validator requires eight digits and a
valid check digit.

## Fix

- Normalize `BillRefNumber` with `"".join(value.split())` in the shared parser.
  This handles spaces, tabs and nonbreaking spaces without removing punctuation
  or changing digits. Both callback paths use the same normalized reference.
- Keep the existing check-digit, account-ownership and receipt-id checks.
- For the authorized payment only, reclassify the existing CASH payment as
  system-collected MOBILE_MONEY, attach the receipt, and use the router from the
  original provisioning attempt. Mark the C2B transaction processed and resolve
  its unmatched item in the same short transaction. Preserve the original
  spaced reference and append reconciliation notes to the financial records.
- Do not replay confirmation or call the normal attribution endpoint for an
  already-activated payment: both can add another service period and sale.

## Verification

- Four spacing regression cases failed before the parser change.
- All 43 C2B handler, HTTP route and account-number tests passed locally using
  SQLite. Tests cover leading zeros, whitespace variants, invalid references,
  wrong-reseller handling and compact-format retries of the same receipt.
- The session-discipline guard passed.
- The production correction increased the reseller's canonical available balance
  by exactly the receipt amount. Payment count and total sales stayed unchanged;
  customer status, expiry and wallet stayed unchanged. Per-router balances still
  summed to the canonical total. No provider transfer or router call was made.
- The parser change requires merge and deployment; the data repair is separate.

## Follow-up

For any further spaced-reference report, check the existing customer ledger and
activation history before attributing the receipt. A valid normalized account is
not authority for a fleet repair. Use the committed regression tests to prevent
the parsing failure from returning.

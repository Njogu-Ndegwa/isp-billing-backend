# 2026-07-22 mpesa_till Methods Broke Captive-Portal Payments For 6 Resellers

## Summary

The Buy Goods till payout feature (commit `9cc59a3`, deployed ~2026-07-21
16:00 UTC) added payment method type `mpesa_till` for the nightly B2B payout,
and existing till resellers' method rows were converted to the new type in a
one-off bulk UPDATE at 15:57–15:59 UTC. But the collection dispatcher
`initiate_customer_payment` (`app/services/payment_gateway.py`) was never
taught the new type, so every captive-portal STK push on a router assigned a
till method raised `ValueError: Unsupported payment method type` → the portal
400'd. Six resellers lost all hotspot sales for ~18 hours: zoid (320),
DIKALI (330), KIMSKEY (333), Airtapnets (272), SMART LINK (277), fastnet (256).

## Symptoms

- Reseller report: "none of my customers can pay on the captive portal."
- `POST /api/hotspot/register-and-pay` → 400, log line
  `Payment gateway failed for customer <id>` with
  `ValueError: Unsupported payment method type: ResellerPaymentMethodType.MPESA_TILL`
  (152 occurrences in 20h of logs).
- DB signature: an affected reseller's `mpesa_transactions` stop dead
  (zoid: last tx 2026-07-21 15:51 UTC, then nothing) — initiation failures on
  the new gateway path are never recorded as transaction rows, so the outage
  looks like *silence*, not a failure spike.
- Router online and healthy the whole time; portal loads fine.

## Suspected Cause

Enum-value-added-without-dispatch-branch. The payout side (`mpesa_b2b.py`) got
the new branch; the collection side dispatches on an if-chain ending in
`raise ValueError`, and nothing forced the two to stay in sync. The bulk
conversion of live rows to the new type at deploy time turned the gap into an
immediate outage for everyone converted.

## Fix Applied

- `app/services/payment_gateway.py`: `MPESA_TILL` added to the
  system-collected tuple — collects like `MPESA_PAYBILL`/`BANK_ACCOUNT`
  (platform shortcode takes the STK push; the nightly B2B BusinessBuyGoods
  payout pays the reseller's till). No schema change.
- `tests/test_payment_gateway_till_collection.py`: collection test for all
  three system-collected types, plus an exhaustiveness test that fails if any
  `ResellerPaymentMethodType` member has no branch in
  `initiate_customer_payment`.
- Commit `625f66e` pushed to main, deployed 2026-07-22 ~09:55 UTC.
- Affected resellers notified via admin inbox (sender user 1) same day.

## Verification

- `pytest tests/test_payment_gateway_till_collection.py tests/test_b2b_till_payout.py`
  plus the b2b/callback/payment suites — all green.
- Post-deploy: `Application startup complete`, no errors.
- Watched prod for new completed `mpesa_transactions` from the 6 affected
  user_ids and for recurrence of `Unsupported payment method type`.

## Follow-Up Work

- **Silent-initiation-failure bug**: on the configured-payment-method path,
  gateway initiation failures are not recorded in `mpesa_transactions` (and
  the legacy path's failure recorder itself crashes with
  `greenlet_spawn has not been called` — session reuse after rollback in
  `app/api/payment_routes.py`). Outages look like missing data instead of
  failure spikes; fix the recorder and add a failed-initiation row on the new
  path too.
- Bulk data conversions that flip live rows onto new code paths should happen
  only after the code path is proven in prod (feature-flag or convert one row
  first) — the 15:59 bulk UPDATE turned a latent gap into a 6-reseller outage.
- Consider an alert on "reseller with recent sales has zero transactions for
  N daytime hours" — silence detection would have caught this within hours.

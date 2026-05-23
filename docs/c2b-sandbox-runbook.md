# C2B Paybill — Sandbox Verification Runbook

End-to-end verification path for the C2B Paybill auto-activation feature
against Safaricom Daraja sandbox. Run this before considering the feature
shippable to production.

Prereqs:
- Daraja sandbox app with **Customer To Business (C2B)** product subscribed
- A publicly reachable URL for this API (use ngrok / Cloudflare Tunnel /
  fly.io / etc. in dev; in prod use the real domain)
- Local checkout of the `feat/c2b-paybill` branch with all 7 migrations
  applied to a fresh database
- `pytest tests/` is green (40/40)

## 1. Apply migrations

```bash
python migrations/add_customer_account_number.py
python migrations/add_customer_wallet_credit.py
python migrations/add_c2b_urls_to_payment_methods.py
python migrations/create_c2b_tables.py
```

Skip `make_customer_account_number_not_null.py` for now — the backfill
hasn't run yet.

## 2. Backfill existing customers

```bash
# Dry run to see what would happen
python scripts/backfill_account_numbers.py

# Apply
python scripts/backfill_account_numbers.py --apply

# Verify
python scripts/backfill_account_numbers.py  # should report 0 missing
```

Then flip the column NOT NULL:

```bash
python migrations/make_customer_account_number_not_null.py
```

## 3. Set environment

```bash
export MPESA_ENVIRONMENT=sandbox
export MPESA_CONSUMER_KEY=<your sandbox key>
export MPESA_CONSUMER_SECRET=<your sandbox secret>
export MPESA_SHORTCODE=600980          # sandbox shortcode from Daraja portal
export MPESA_PASSKEY=<sandbox passkey>
export MPESA_CALLBACK_URL=https://<your-tunnel>/api/mpesa/callback
```

Start the app:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Expose port 8000 publicly (the URL Safaricom will hit must be reachable
from the internet — ngrok / Cloudflare Tunnel is fine for sandbox).

## 4. Register URLs with Safaricom

Get an admin token first (use existing auth flow). Then:

```bash
curl -X POST https://<your-tunnel>/api/admin/c2b/register-platform-paybill \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "confirmation_url": "https://<your-tunnel>/api/c2b/confirmation",
    "validation_url":   "https://<your-tunnel>/api/c2b/validation",
    "response_type":    "Completed"
  }'
```

Expected response:
```json
{ "OriginatorCoversationID": "...", "ResponseCode": "0",
  "ResponseDescription": "success" }
```

Note: Validation URL is **disabled by default in production**. Safaricom
requires you to email `apisupport@safaricom.co.ke` to enable it on your
production paybill. In sandbox it's available immediately.

## 5. Seed a PPPoE customer

Through normal flow:

```bash
curl -X POST https://<your-tunnel>/api/customers/register \
  -H "Authorization: Bearer <reseller-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Sandbox Tester",
    "phone": "254712345678",
    "plan_id": <pppoe-plan-id>,
    "router_id": <test-router-id>
  }'
```

The response will include `"account_number": "XXXXXXXX"` — write this
down. That's what we'll type into the M-Pesa simulator.

## 6. Fire a C2B simulator confirmation

In the Daraja portal: APIs → C2B Simulate → Simulate Transaction:

| Field | Value |
|---|---|
| Short Code | `600980` (same as MPESA_SHORTCODE) |
| Command ID | `CustomerPayBillOnline` |
| Amount | `500` (or whatever the plan price is) |
| MSISDN | `254712345678` (any sandbox-allowed number) |
| Bill Reference Number | the account_number from step 5 |

Click **Send**. Safaricom will hit your Validation URL first (accept/reject),
then your Confirmation URL.

## 7. Verify end-to-end

In the app logs you should see:

```
[C2B] Processed: customer=N, paid=500.00, plan_price=500.00, new_wallet=0 (trans_id=...)
[C2B] Queued PPPoE provisioning for customer N on router 10.x.x.x
```

In the database:

```sql
-- The C2B transaction was archived
SELECT trans_id, status, matched_customer_id, processed_at
  FROM c2b_transactions
  ORDER BY id DESC LIMIT 1;
-- status should be 'processed'

-- The customer was activated
SELECT id, status, expiry, wallet_credit_kes
  FROM customers
  WHERE id = <test customer id>;
-- status='active', expiry ~ now+30 days

-- A CustomerPayment row was written
SELECT * FROM customer_payments
  WHERE customer_id = <test customer id>
  ORDER BY id DESC LIMIT 1;

-- ResellerFinancials updated
SELECT * FROM reseller_financials WHERE user_id = <reseller id>;
```

On the MikroTik test router, `/ppp/secret/print` should show the customer's
PPPoE secret enabled with the right profile (rate-limit matching the plan).

## 8. Verify idempotency

Re-fire the same simulator transaction (or POST the same JSON to
`/api/c2b/confirmation` manually). Expect:

- App log: `[C2B] Duplicate confirmation for trans_id=... — no-op`
- No second row in `customer_payments`
- `expiry` unchanged

## 9. Verify unmatched handling

Fire a simulator transaction with a bogus BillRefNumber (`99999999`). Expect:

- App returns HTTP 200 with `{"ResultCode": 0, "ResultDesc": "Success"}`
- `c2b_transactions` row with `status='unmatched'`
- `unmatched_c2b_payments` row with `reason='unknown_account'`
- Customer status untouched

Then attribute it manually:

```bash
curl -X POST https://<your-tunnel>/api/c2b/unmatched/<id>/attribute \
  -H "Authorization: Bearer <reseller-token>" \
  -H "Content-Type: application/json" \
  -d '{"customer_id": <test customer id>, "notes": "Wrong account typed"}'
```

Verify:
- `unmatched_c2b_payments.resolved_at` is set, `resolved_by_user_id` matches
- `c2b_transactions.status` flipped to `processed`
- Customer was activated + provisioned

## 10. Sign-off checklist

- [ ] Migrations apply cleanly in order on a fresh DB
- [ ] `python scripts/backfill_account_numbers.py --apply` completes with 0 errored
- [ ] `migrations/make_customer_account_number_not_null.py` succeeds
- [ ] `pytest tests/` → 40/40 green
- [ ] Daraja registerurl returns ResponseCode 0
- [ ] Simulator confirmation → customer auto-activated, PPPoE secret enabled
- [ ] Duplicate simulation → no-op, no second activation
- [ ] Bogus BillRefNumber → unmatched bucket, return 200, manual attribute works
- [ ] Wrong reseller's paybill (if a reseller paybill is registered) →
      unmatched with reason=wrong_reseller

## Production rollout (separate from this PR)

1. Deploy code with feature flag off (or just deploy; nothing fires until
   step 2 runs).
2. Apply migrations in order, one per deploy if you're cautious.
3. Run `scripts/backfill_account_numbers.py --apply` from a deploy shell.
4. Run `migrations/make_customer_account_number_not_null.py` once
   backfill report shows `remaining=0`.
5. Email `apisupport@safaricom.co.ke` to enable Validation URL on the
   production shortcode.
6. POST `/api/admin/c2b/register-platform-paybill` with production URLs.
7. For each reseller using their own paybill (method_type=mpesa_paybill_with_keys):
   - They must subscribe to the C2B product on their Daraja app.
   - They use POST `/api/payment-methods/{id}/register-c2b` to register.

## Known limitations (out of scope this PR)

- Hotspot C2B is not supported (PPPoE only) — captive-portal STK push
  remains the hotspot flow.
- No SMS notification to customer on successful payment.
- No customer-facing wallet management UI; balance is read-only from
  the customer detail endpoint.

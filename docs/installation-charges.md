# Installation charges: Techmid tracking-only phase

This ledger records installation debt and the owner's statements of external
receipt. It does not collect or verify money, create withdrawable platform
credit, refund money, consume wallet credit, or affect internet access. No
existing debts are imported automatically. The customer card states:
**Recorded debt does not block internet yet.**

## Access and accounting boundaries

- Backend is disabled by default (`TECHMID_INSTALLATION_CHARGES_ENABLED=false`)
  and additionally restricted to verified reseller ID 597. Frontend has its own
  disabled-by-default `NEXT_PUBLIC_TECHMID_INSTALLATION_CHARGES_ENABLED` flag;
  it is display control only, not authorization.
- Only the actual owner can write. Staff, including account admins, cannot.
  Customer-view staff can read. Standard inactive-subscription restrictions
  apply to writes. Existing impersonation middleware still applies.
- The current plan must be PPPoE or static IP to create a charge. Existing
  history remains readable and correctable when a plan is removed/changed.
- Money is KES in integer minor units; 100 minor units = KES 1. Amounts must
  be positive integers, up to 100,000,000 minor units per entry. No float input.
- Payments and waivers cannot exceed outstanding debt. A reversal links the
  original event and records a reason; it is not a refund. A charge cannot be
  reversed until its effective settlements are reversed. Reversals cannot
  themselves be reversed. Nothing can be edited or deleted through the API.

## API

All routes start `/api/customers/{customer_id}/installation-charges` and use
the existing authenticated session. No integration credentials are introduced.

- `GET ?limit=50&offset=0`: `{charges, next_offset, can_create}`. `can_create`
  describes plan eligibility, not permission or subscription status.
- `POST`: `{idempotency_key, amount_minor, description}`.
- `POST /{charge_id}/events`: `{idempotency_key, kind, amount_minor, reason,
  external_reference?}`; kind is `external_payment` or `waiver`. A waiver cannot
  carry an external receipt reference.
- `POST /{charge_id}/events/{event_id}/reversal`: `{idempotency_key, reason}`.

Mutations return the current charge with totals and ordered event history.
Clients retain the same key and payload after an uncertain network result;
retries return the existing entry. Reusing a key with different payload gives
409. Every key is scoped to its owner. Customer/charge row locks serialize
concurrent changes; unique constraints cover requests and reversal targets.

## Schema and rollout

The startup migration creates only `customer_charges` and
`customer_charge_events`, using an advisory lock against simultaneous startup.
There is no backfill or ALTER of existing customer/payment tables. A nullable
customer FK uses `ON DELETE SET NULL`; immutable customer/owner identity
snapshots retain the audit trail without blocking normal customer deletion.
Charge/event rows are deliberately not cascaded away. Currency is explicitly
stored and constrained to KES.

Review and test both repositories before publication. Deploy with both flags
off; verify both new tables and ordinary customer/payment flows. Only after
authorized canary enablement, enable the backend flag and rebuild the frontend
with its matching flag for Techmid. Validate with a clearly identified test
customer/charge and reverse the test entry; do not manufacture customer debt.
No real ledger mutation is part of automated deployment verification.

Rollback: disable flags first. The additive tables and history remain intact;
do not drop them or reverse legitimate customer entries. Existing application
versions do not read these tables. No customer balance/expiry rollback exists
because this feature does not change them.

## Verification

`tests/test_customer_charges.py` exercises real HTTP middleware and PostgreSQL:
exact amounts, permission/tenant/feature gates, plan-history access, idempotent
and concurrent writes/reversals, unchanged customer fields and financial/service
tables, customer deletion, and repeatable additive migration. Run the existing
schema, customer deletion, payment allocation, payout, pause and activation
regressions as well. Keep local test workers bounded (`-n 0` or `-n 2`).

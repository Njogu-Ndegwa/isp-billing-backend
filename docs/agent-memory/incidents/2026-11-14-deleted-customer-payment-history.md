# 2026-11-14 Customer deletion hid a completed M-Pesa payment

## Summary

A reseller's account statement showed KSh 40 in direct payments. Transactions and the router's dashboard showed KSh 30 after a customer was deleted.

## Symptoms

- A completed KSh 10 direct M-Pesa payment at 13:38 EAT was absent from Transactions after the customer was deleted at 13:49 EAT.
- The ledger still held the amount, receipt reference, settlement mode, and router at payment time.

## Cause

The deletion handler removed the provider transaction and cleared the customer link on the ledger row. Transactions excluded M-Pesa ledger rows to avoid counting provider records twice. The dashboard's customer joins and router filters also excluded the surviving payment.

## Fix

Customer deletion detaches provider records and preserves attribution. Transactions can use the original ledger row for historical M-Pesa STK payments when the provider record is missing. Dashboard totals and payment lists use the router recorded on the ledger. PostgreSQL blocks deletion and truncation on ISP payment and payout tables. A confirmation received after M-Pesa customer deletion can still be ledgered without provisioning the deleted customer.

## Verification

The regression scenario exercises actual customer deletion, retained and missing provider records, dashboard totals, reseller isolation, and duplicate callbacks. An isolated PostgreSQL startup and restart checked that the schema migration ran, payment records could be inserted and transaction statuses updated, and payment deletion was rejected.

## Follow-Up Work

Verify the affected reseller's Transactions and dashboard totals after deployment.

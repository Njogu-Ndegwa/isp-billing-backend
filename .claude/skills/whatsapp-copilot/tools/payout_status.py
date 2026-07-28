#!/usr/bin/env python3
"""Payout status for a reseller: unpaid balance (canonical semantics), the
last payouts, and any stuck B2B transactions (the blocked-payout signal).

The unpaid-balance SQL mirrors app/services/mpesa_b2b.py get_unpaid_balance /
PAYOUT_REVENUE_FILTERS (commit c905cf2 "payout balance no longer counts money
the platform never held") EXACTLY — see the inline comments on each filter.
Formula: mpesa_revenue + balance_correction - payouts - charges.

Usage:
    python payout_status.py --reseller someone@example.com
    python payout_status.py --reseller 42

Output: {"reseller":..., "unpaid_balance":..., "recent_payouts":[...],
"stuck_b2b":[...]} — a non-empty stuck_b2b with status pending/timeout means
the payout pipeline for this reseller is blocked until reconciliation clears it.
"""

import argparse
import sys

from _prodquery import (
    ProdQueryError, check_resolved, emit, fail, reseller_ident_sql, run_batch,
)


def balance_sql(rid: str) -> str:
    # Mirrors mpesa_b2b.PAYOUT_REVENUE_FILTERS + get_unpaid_balance. The
    # platform only owes a reseller money it actually collected on their
    # behalf. Postgres enum labels verified live 2026-07-25: payment_method /
    # status store UPPERCASE enum names; collection_mode stores lowercase
    # values ('direct', 'system_collected').
    return f"""
SELECT
  ROUND((rev.v + corr.v - paid.v - chg.v)::numeric, 2) AS unpaid_balance,
  ROUND(rev.v::numeric, 2)  AS mpesa_revenue,
  ROUND(corr.v::numeric, 2) AS balance_correction,
  ROUND(paid.v::numeric, 2) AS total_payouts,
  ROUND(chg.v::numeric, 2)  AS total_charges
FROM
  (SELECT COALESCE(SUM(cp.amount), 0) AS v
     FROM customer_payments cp
    WHERE cp.reseller_id = {rid}
      -- Only mobile-money flows through the platform's M-Pesa; cash and
      -- voucher payments are collected by the reseller directly.
      AND cp.payment_method = 'MOBILE_MONEY'
      -- Only money that actually arrived. NULL-safe: status has an ORM
      -- default of COMPLETED but no server default, so NULL means completed
      -- (a strict equality would short-change resellers on legacy rows).
      AND (cp.status IS NULL OR cp.status = 'COMPLETED')
      -- Compensation vouchers are zero-revenue; never payable.
      AND cp.counts_as_revenue = TRUE
      -- DIRECT = C2B paid straight into the reseller's own paybill/till; the
      -- platform never held that cash, so paying it out would pay it twice.
      -- NULL-safe: only the C2B paths stamp collection_mode — legacy and
      -- system-credential STK rows are NULL and MUST keep counting.
      AND (cp.collection_mode IS NULL OR cp.collection_mode <> 'direct')
  ) rev,
  -- Everything already paid out to the reseller (any method).
  (SELECT COALESCE(SUM(p.amount), 0) AS v
     FROM reseller_payouts p WHERE p.reseller_id = {rid}) paid,
  -- Admin-recorded deductions (bank fees, M-Pesa charges, Kadogo surcharge).
  (SELECT COALESCE(SUM(ch.amount), 0) AS v
     FROM reseller_transaction_charges ch WHERE ch.reseller_id = {rid}) chg,
  -- One-time correction for payment rows lost to cascading customer deletion;
  -- 0 when the reseller has no reseller_financials row.
  (SELECT COALESCE((SELECT rf.balance_correction FROM reseller_financials rf
                     WHERE rf.user_id = {rid}), 0) AS v) corr
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Reseller payout status (read-only)")
    ap.add_argument("--reseller", required=True, help="reseller users.id or email")
    args = ap.parse_args()

    try:
        # Reseller ident resolves INLINE so the whole tool is ONE ssh
        # connection (port-22 rate limit — see _prodquery docstring).
        rid, resolve_sql = reseller_ident_sql(args.reseller)
        batch = run_batch([
            ("reseller", resolve_sql),
            ("balance", balance_sql(rid)),
            # Payout cadence context (frequency lives on reseller_financials).
            ("schedule",
             "SELECT rf.payout_frequency, rf.payout_interval_days, rf.last_payment_date\n"
             f"FROM reseller_financials rf WHERE rf.user_id = {rid}\nLIMIT 1"),
            ("recent_payouts",
             "SELECT p.id, p.amount, p.payment_method, p.reference, p.notes,\n"
             "       p.period_start, p.period_end, p.created_at\n"
             f"FROM reseller_payouts p WHERE p.reseller_id = {rid}\n"
             "ORDER BY p.created_at DESC\nLIMIT 5"),
            # Stuck B2B transactions: pending/timeout rows block further
            # automatic payouts to this reseller until status reconciliation
            # resolves them. (b2b status enum labels are lowercase.)
            ("stuck_b2b",
             "SELECT b.id, b.amount, b.fee, b.net_amount,\n"
             "       b.status::text AS status, b.command_id, b.party_b,\n"
             "       b.account_reference, b.result_code, b.result_desc,\n"
             "       b.transaction_id, b.triggered_by, b.created_at, b.completed_at,\n"
             "       ROUND(EXTRACT(EPOCH FROM (NOW() - b.created_at)) / 3600.0, 1)\n"
             "         AS age_hours\n"
             "FROM b2b_transactions b\n"
             f"WHERE b.reseller_id = {rid} AND b.status IN ('pending', 'timeout')\n"
             "ORDER BY b.created_at DESC\nLIMIT 5"),
        ])

        owner = check_resolved(batch["reseller"], args.reseller)
        result = {"reseller": {"id": owner["id"], "email": owner["email"],
                               "organization_name": owner.get("organization_name"),
                               "subscription_status": owner.get("subscription_status")}}
        result["balance"] = batch["balance"][0] if batch["balance"] else None
        result["payout_schedule"] = batch["schedule"][0] if batch["schedule"] else None
        result["recent_payouts"] = batch["recent_payouts"]
        result["stuck_b2b"] = batch["stuck_b2b"]
        result["payout_pipeline_blocked"] = bool(result["stuck_b2b"])
    except ProdQueryError as e:
        fail(str(e))

    emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

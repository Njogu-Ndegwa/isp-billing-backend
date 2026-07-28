#!/usr/bin/env python3
"""Recent payments for a customer, phone number, or reseller.

Covers both payment ledgers:
  - customer_payments  (all methods; the revenue ledger)
  - c2b_transactions   (raw Safaricom C2B paybill confirmations, incl.
                        unmatched/rejected ones that never became a payment)

MSISDNs are masked in output (middle digits). The platform-paybill C2B rows
store the MSISDN as a plain sha256 of the 254-form number — matching by
--phone therefore also compares against that hash.

Usage:
    python recent_transactions.py --account 1234              # customers.id
    python recent_transactions.py --phone 0712345678 --days 14
    python recent_transactions.py --reseller someone@example.com --days 7

--days defaults to 7, capped at 30. Row cap 20 per ledger (override --limit, max 50).
"""

import argparse
import sys

from _prodquery import (
    ProdQueryError, check_resolved, emit, fail, lit, mask_msisdn,
    phone_match_cond, phone_sha256_254, reseller_ident_sql, run_batch,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Recent transactions (read-only)")
    ident = ap.add_mutually_exclusive_group(required=True)
    ident.add_argument("--account", type=int, help="customers.id")
    ident.add_argument("--phone", help="customer phone, any format")
    ident.add_argument("--reseller", help="reseller users.id or email")
    ap.add_argument("--days", type=int, default=7, help="lookback window (1-30, default 7)")
    ap.add_argument("--limit", type=int, default=20, help="max rows per ledger (1-50, default 20)")
    args = ap.parse_args()

    days = max(1, min(args.days, 30))
    limit = max(1, min(args.limit, 50))

    result = {"window_days": days, "customer_payments": [], "c2b_transactions": []}

    try:
        # Resolve identity to SQL conditions for each ledger. Reseller idents
        # resolve INLINE (scalar subquery) so the whole tool stays at one ssh
        # connection (port-22 rate limit).
        queries = []
        if args.account:
            cp_cond = f"cp.customer_id = {args.account}"
            c2b_cond = f"t.matched_customer_id = {args.account}"
            result["identity"] = {"customer_id": args.account}
        elif args.phone:
            cp_cond = phone_match_cond("c.phone", args.phone)
            # C2B: raw MSISDN on reseller-shortcode rows, sha256(254-form) on
            # platform-paybill rows (Safaricom hashes those).
            c2b_cond = (f"({phone_match_cond('t.msisdn', args.phone)}"
                        f" OR t.msisdn = {lit(phone_sha256_254(args.phone))})")
            result["identity"] = {"phone": mask_msisdn(args.phone)}
        else:
            id_expr, resolve_sql = reseller_ident_sql(args.reseller)
            queries.append(("reseller", resolve_sql))
            cp_cond = f"cp.reseller_id = {id_expr}"
            c2b_cond = f"t.matched_reseller_id = {id_expr}"

        queries.append(("customer_payments",
            "SELECT cp.id, cp.amount, cp.payment_method::text AS method,\n"
            "       cp.status::text AS status,\n"
            "       cp.collection_mode::text AS collection_mode,\n"
            "       cp.counts_as_revenue, cp.payment_reference,\n"
            "       cp.days_paid_for, cp.payment_date, cp.created_at,\n"
            "       cp.customer_id, COALESCE(c.name, cp.customer_name) AS customer_name,\n"
            "       c.phone AS customer_phone, cp.reseller_id, cp.port_name\n"
            "FROM customer_payments cp\n"
            "LEFT JOIN customers c ON c.id = cp.customer_id\n"
            f"WHERE cp.created_at > NOW() - INTERVAL '{days} days'\n"
            f"  AND {cp_cond}\n"
            "ORDER BY cp.created_at DESC\n"
            f"LIMIT {limit}"))

        queries.append(("c2b_transactions",
            "SELECT t.id, t.trans_id, t.trans_amount, t.msisdn,\n"
            "       t.bill_ref_number, t.business_shortcode,\n"
            "       t.status::text AS status, t.received_at, t.processed_at,\n"
            "       t.matched_customer_id, t.matched_reseller_id\n"
            "FROM c2b_transactions t\n"
            f"WHERE t.received_at > NOW() - INTERVAL '{days} days'\n"
            f"  AND {c2b_cond}\n"
            "ORDER BY t.received_at DESC\n"
            f"LIMIT {limit}"))

        batch = run_batch(queries)
        if args.reseller:
            owner = check_resolved(batch["reseller"], args.reseller)
            result["identity"] = {"reseller_id": owner["id"],
                                  "reseller_email": owner["email"]}

        rows = batch["customer_payments"]
        for r in rows:
            r["customer_phone"] = mask_msisdn(r.get("customer_phone"))
        result["customer_payments"] = rows

        rows = batch["c2b_transactions"]
        for r in rows:
            r["msisdn"] = mask_msisdn(r.get("msisdn"))
        result["c2b_transactions"] = rows
    except ProdQueryError as e:
        fail(str(e))

    result["counts"] = {"customer_payments": len(result["customer_payments"]),
                        "c2b_transactions": len(result["c2b_transactions"])}
    emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

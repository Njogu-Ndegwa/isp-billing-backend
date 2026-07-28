#!/usr/bin/env python3
"""Resolve a reseller (users) and/or customer (customers) from a phone, email,
or name fragment — the copilot's identity-resolution step ("Ebu ntumie email
I check").

Read-only; one short indexed query per section, LIMITed. See _prodquery.py for
the SSH/psql invocation and the read-only enforcement.

Usage:
    python lookup_account.py --email reseller@example.com
    python lookup_account.py --phone 0712345678
    python lookup_account.py --name "wava"          # org/business/customer name
    python lookup_account.py --phone 0712345678 --limit 3

Output: {"query":..., "users":[...], "customers":[...]} compact JSON on stdout.
Phone matching is fuzzy across formats (07XX / 2547XX / +254 7XX) via
last-9-digit comparison.
"""

import argparse
import sys

from _prodquery import (
    ProdQueryError, emit, fail, ilike_contains, phone_last9,
    phone_match_cond, run_batch,
)


def build_user_cond(args) -> str:
    conds = []
    if args.email:
        conds.append(f"u.email ILIKE {ilike_contains(args.email.strip())}")
    if args.phone:
        conds.append(phone_match_cond("u.support_phone", args.phone))
    if args.name:
        n = ilike_contains(args.name.strip())
        conds.append(f"(u.organization_name ILIKE {n} OR u.business_name ILIKE {n})")
    return " OR ".join(conds)


def build_customer_cond(args) -> str:
    conds = []
    if args.phone:
        conds.append(phone_match_cond("c.phone", args.phone))
    if args.name:
        conds.append(f"c.name ILIKE {ilike_contains(args.name.strip())}")
    if args.email and not (args.phone or args.name):
        # Customers have no email; surface the matched reseller's customers is
        # too broad — instead match email-looking strings against pppoe_username
        # as a long-shot, plus account_number if the "email" is digits.
        conds.append(f"c.pppoe_username ILIKE {ilike_contains(args.email.strip())}")
    return " OR ".join(conds)


def main() -> int:
    ap = argparse.ArgumentParser(description="Resolve reseller/customer identity (read-only)")
    ap.add_argument("--phone", help="phone in any format (07.., 2547.., +254..)")
    ap.add_argument("--email", help="email or email fragment")
    ap.add_argument("--name", help="name fragment (org, business, or customer name)")
    ap.add_argument("--limit", type=int, default=5, help="max rows per section (1-10, default 5)")
    args = ap.parse_args()

    if not (args.phone or args.email or args.name):
        ap.error("give at least one of --phone / --email / --name")
    limit = max(1, min(args.limit, 10))

    result = {
        "query": {"phone": args.phone, "email": args.email, "name": args.name},
        "users": [],
        "customers": [],
    }

    try:
        queries = []
        user_cond = build_user_cond(args)
        if user_cond:
            queries.append(("users",
                "SELECT u.id, u.role::text AS role, u.email, u.organization_name,\n"
                "       u.business_name, u.support_phone,\n"
                "       u.subscription_status::text AS subscription_status,\n"
                "       u.subscription_expires_at, u.created_at, u.last_login_at,\n"
                "       (u.mpesa_shortcode IS NOT NULL) AS has_own_shortcode,\n"
                "       (SELECT COUNT(*) FROM routers r WHERE r.user_id = u.id) AS router_count,\n"
                "       (SELECT COUNT(*) FROM customers c WHERE c.user_id = u.id) AS customer_count,\n"
                "       (SELECT COUNT(*) FROM customers c WHERE c.user_id = u.id\n"
                "          AND c.status = 'ACTIVE') AS active_customer_count\n"
                "FROM users u\n"
                f"WHERE {user_cond}\n"
                "ORDER BY u.id\n"
                f"LIMIT {limit}"))

        cust_cond = build_customer_cond(args)
        if cust_cond:
            queries.append(("customers",
                "SELECT c.id, c.name, c.phone, c.status::text AS status, c.expiry,\n"
                "       (c.expiry IS NOT NULL AND c.expiry > NOW()) AS paid_up,\n"
                "       c.account_number, c.wallet_credit_kes,\n"
                "       c.mac_address, c.pppoe_username,\n"
                "       p.name AS plan_name, p.price AS plan_price,\n"
                "       p.connection_type::text AS connection_type,\n"
                "       c.router_id, r.name AS router_name,\n"
                "       c.user_id AS reseller_id, u.email AS reseller_email,\n"
                "       u.organization_name AS reseller_org,\n"
                "       c.subscription_owner_id, c.created_at\n"
                "FROM customers c\n"
                "LEFT JOIN plans p ON p.id = c.plan_id\n"
                "LEFT JOIN routers r ON r.id = c.router_id\n"
                "LEFT JOIN users u ON u.id = c.user_id\n"
                f"WHERE {cust_cond}\n"
                "ORDER BY c.id DESC\n"
                f"LIMIT {limit}"))

        # One ssh connection for everything (port-22 rate limit).
        batch = run_batch(queries)
        result["users"] = batch.get("users", [])
        result["customers"] = batch.get("customers", [])
    except ProdQueryError as e:
        fail(str(e))

    if args.phone:
        result["query"]["phone_last9"] = phone_last9(args.phone)
    result["match_counts"] = {"users": len(result["users"]),
                              "customers": len(result["customers"])}
    emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

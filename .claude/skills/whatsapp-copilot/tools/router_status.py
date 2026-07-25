#!/usr/bin/env python3
"""Router status lookup: DB-known state of one router or a reseller's fleet.

DB-only view (last_status / last_checked_at / availability history) — it does
NOT touch the router live. A router whose WAN is down is also unreachable on
its 10.0.0.x tunnel, so "last seen" here is exactly what the app knows.

Usage:
    python router_status.py --router-id 207
    python router_status.py --reseller someone@example.com
    python router_status.py --reseller 42 --limit 5

Output: {"routers":[...], "availability": {...}} — availability history/24h
uptime is fetched only when 3 or fewer routers matched (keeps queries short).
"""

import argparse
import sys

from _prodquery import (
    ProdQueryError, check_resolved, emit, fail, reseller_ident_sql, run_batch,
)


ROUTER_SELECT = (
    "SELECT r.id, r.name, r.identity, r.ip_address AS vpn_ip, r.port,\n"
    "       r.auth_method::text AS auth_method,\n"
    "       r.last_status AS last_check_online, r.last_checked_at,\n"
    "       r.last_online_at, r.last_status_source,\n"
    "       r.availability_checks, r.availability_successes,\n"
    "       CASE WHEN r.availability_checks > 0 THEN\n"
    "         ROUND(100.0 * r.availability_successes / r.availability_checks, 1)\n"
    "       END AS lifetime_availability_pct,\n"
    "       r.pull_channel_enabled, r.emergency_active,\n"
    "       r.status_alerts_enabled, r.created_at,\n"
    "       r.user_id AS owner_id, u.email AS owner_email,\n"
    "       u.organization_name AS owner_org,\n"
    "       (SELECT COUNT(*) FROM customers c WHERE c.router_id = r.id\n"
    "          AND c.status = 'ACTIVE') AS active_customers,\n"
    "       (SELECT COUNT(*) FROM customers c WHERE c.router_id = r.id) AS total_customers\n"
    "FROM routers r\n"
    "LEFT JOIN users u ON u.id = r.user_id\n"
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Router status from the billing DB (read-only)")
    ap.add_argument("--router-id", type=int, help="numeric routers.id")
    ap.add_argument("--reseller", help="reseller users.id or email — list their routers")
    ap.add_argument("--limit", type=int, default=10, help="max routers when using --reseller (1-25)")
    args = ap.parse_args()

    if not args.router_id and not args.reseller:
        ap.error("give --router-id or --reseller")
    limit = max(1, min(args.limit, 25))

    result = {"routers": [], "availability": {}}

    def availability_queries(ids_csv):
        # 24h uptime ratio + most recent individual checks (flap visibility).
        return [
            ("last_24h",
             "SELECT router_id, COUNT(*) AS checks,\n"
             "       COUNT(*) FILTER (WHERE is_online) AS online_checks,\n"
             "       ROUND(100.0 * COUNT(*) FILTER (WHERE is_online) / COUNT(*), 1)\n"
             "         AS online_pct\n"
             "FROM router_availability_checks\n"
             f"WHERE router_id IN ({ids_csv})\n"
             "  AND checked_at > NOW() - INTERVAL '24 hours'\n"
             "GROUP BY router_id"),
            ("recent_checks",
             "SELECT router_id, checked_at, is_online, source\n"
             "FROM router_availability_checks\n"
             f"WHERE router_id IN ({ids_csv})\n"
             "ORDER BY checked_at DESC\n"
             "LIMIT 10"),
        ]

    try:
        if args.router_id:
            # Everything in ONE ssh connection (port-22 rate limit).
            batch = run_batch(
                [("routers", ROUTER_SELECT + f"WHERE r.id = {args.router_id}\nLIMIT 1")]
                + availability_queries(str(args.router_id)))
            result["routers"] = batch["routers"]
            if result["routers"]:
                result["availability"] = {"last_24h": batch["last_24h"],
                                          "recent_checks": batch["recent_checks"]}
        else:
            id_expr, resolve_sql = reseller_ident_sql(args.reseller)
            batch = run_batch([
                ("reseller", resolve_sql),
                ("routers", ROUTER_SELECT + f"WHERE r.user_id = {id_expr}\n"
                 "ORDER BY r.id\n"
                 f"LIMIT {limit}"),
            ])
            owner = check_resolved(batch["reseller"], args.reseller)
            result["reseller"] = {"id": owner["id"], "email": owner["email"],
                                  "organization_name": owner.get("organization_name"),
                                  "subscription_status": owner.get("subscription_status")}
            result["routers"] = batch["routers"]

            router_ids = [r["id"] for r in result["routers"]]
            if router_ids and len(router_ids) <= 3:
                ids_csv = ", ".join(str(i) for i in router_ids)
                avail = run_batch(availability_queries(ids_csv))
                result["availability"] = {"last_24h": avail["last_24h"],
                                          "recent_checks": avail["recent_checks"]}
            elif router_ids:
                result["availability"]["note"] = (
                    "history skipped: more than 3 routers matched; re-run with --router-id")
    except ProdQueryError as e:
        fail(str(e))

    emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

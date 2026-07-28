#!/usr/bin/env python3
"""Session / online-state signals for a customer or a router, from the DB only.

There is no live-session table in this schema — hotspot/PPPoE sessions live on
the router. What the DB does hold (and what this tool reports):
  - customers.status / expiry            -> provisioned + paid-up state
  - provisioning_attempts.online_state / last_online_at / provisioning_state
                                         -> whether the paid MAC was last seen
                                            online and whether provisioning
                                            actually reached the router
  - user_bandwidth_usage.last_updated    -> last time the snapshot job saw
                                            traffic counters for the customer
  - customer_usage_periods (open row)    -> FUP state: bytes used vs cap,
                                            throttle/block trigger + revert
Live per-session detail needs the router itself (use the
diagnose-customer-router skill for that).

Usage:
    python session_state.py --account-id 1234        # customers.id
    python session_state.py --router-id 207

Output: one compact JSON object; absent signals are null/[] — no guessing.
"""

import argparse
import sys

from _prodquery import ProdQueryError, emit, fail, run_batch


def account_state(cid: int) -> dict:
    # All statements share ONE ssh connection (port-22 rate limit).
    batch = run_batch([
        ("customer",
        "SELECT c.id, c.name, c.status::text AS status, c.expiry,\n"
        "       (c.expiry IS NOT NULL AND c.expiry > NOW()) AS paid_up,\n"
        "       CASE WHEN c.expiry IS NOT NULL THEN\n"
        "         ROUND(EXTRACT(EPOCH FROM (c.expiry - NOW())) / 3600.0, 1)\n"
        "       END AS hours_to_expiry,\n"
        "       c.mac_address, c.pppoe_username, c.static_ip,\n"
        "       c.wallet_credit_kes, c.subscription_owner_id,\n"
        "       p.name AS plan_name, p.connection_type::text AS connection_type,\n"
        "       p.speed AS plan_speed, p.data_cap_mb,\n"
        "       p.fup_action::text AS plan_fup_action,\n"
        "       c.router_id, r.name AS router_name,\n"
        "       r.last_status AS router_last_check_online,\n"
        "       r.last_checked_at AS router_last_checked_at,\n"
        "       r.last_online_at AS router_last_online_at\n"
        "FROM customers c\n"
        "LEFT JOIN plans p ON p.id = c.plan_id\n"
        "LEFT JOIN routers r ON r.id = c.router_id\n"
        f"WHERE c.id = {cid}\nLIMIT 1"),
        ("provisioning_attempts",
        "SELECT pa.provisioning_state::text AS provisioning_state,\n"
        "       pa.online_state::text AS online_state,\n"
        "       pa.entrypoint::text AS entrypoint, pa.attempt_count,\n"
        "       pa.last_error, pa.last_attempt_at, pa.router_updated_at,\n"
        "       pa.last_online_at, pa.mac_address, pa.updated_at\n"
        "FROM provisioning_attempts pa\n"
        f"WHERE pa.customer_id = {cid}\n"
        "ORDER BY pa.updated_at DESC\nLIMIT 3"),
        ("bandwidth_last_seen",
        "SELECT ubu.mac_address, ubu.queue_name, ubu.target_ip,\n"
        "       ubu.upload_bytes, ubu.download_bytes, ubu.last_updated\n"
        "FROM user_bandwidth_usage ubu\n"
        f"WHERE ubu.customer_id = {cid}\n"
        "ORDER BY ubu.last_updated DESC\nLIMIT 3"),
        ("open_usage_period",
        "SELECT cup.period_start, cup.period_end, cup.total_bytes,\n"
        "       cup.upload_bytes, cup.download_bytes, cup.cap_mb_snapshot,\n"
        "       cup.fup_action_snapshot::text AS fup_action_snapshot,\n"
        "       cup.fup_triggered_at,\n"
        "       cup.fup_action_taken::text AS fup_action_taken,\n"
        "       cup.fup_reverted_at,\n"
        "       CASE WHEN cup.cap_mb_snapshot IS NOT NULL AND cup.cap_mb_snapshot > 0\n"
        "         THEN ROUND(100.0 * cup.total_bytes / (cup.cap_mb_snapshot * 1024.0 * 1024.0), 1)\n"
        "       END AS pct_of_cap\n"
        "FROM customer_usage_periods cup\n"
        f"WHERE cup.customer_id = {cid} AND cup.closed_at IS NULL\n"
        "ORDER BY cup.period_start DESC\nLIMIT 1"),
    ])

    if not batch["customer"]:
        fail(f"no customer with id {cid}")
    out = {"customer": batch["customer"][0],
           "provisioning_attempts": batch["provisioning_attempts"],
           "bandwidth_last_seen": batch["bandwidth_last_seen"]}
    fup = batch["open_usage_period"]
    out["open_usage_period"] = fup[0] if fup else None
    fup_row = out["open_usage_period"]
    out["fup_throttled_now"] = bool(
        fup_row and fup_row.get("fup_triggered_at") and not fup_row.get("fup_reverted_at"))
    return out


def router_state(rid: int) -> dict:
    # All statements share ONE ssh connection (port-22 rate limit).
    batch = run_batch([
        ("router",
        "SELECT r.id, r.name, r.identity, r.last_status AS last_check_online,\n"
        "       r.last_checked_at, r.last_online_at\n"
        f"FROM routers r WHERE r.id = {rid}\nLIMIT 1"),
        ("customer_counts",
        "SELECT COUNT(*) AS total,\n"
        "       COUNT(*) FILTER (WHERE c.status = 'ACTIVE') AS active,\n"
        "       COUNT(*) FILTER (WHERE c.status = 'ACTIVE'\n"
        "         AND c.expiry IS NOT NULL AND c.expiry < NOW()) AS active_but_expired,\n"
        "       COUNT(*) FILTER (WHERE c.expiry > NOW()) AS paid_up,\n"
        "       COUNT(*) FILTER (WHERE c.pppoe_username IS NOT NULL) AS pppoe_credentialed\n"
        f"FROM customers c WHERE c.router_id = {rid}"),
        # Customers whose traffic counters moved in the last hour — the
        # closest DB-side signal to "online right now".
        ("seen_last_hour",
        "SELECT ubu.customer_id, c.name, ubu.mac_address, ubu.last_updated\n"
        "FROM user_bandwidth_usage ubu\n"
        "JOIN customers c ON c.id = ubu.customer_id\n"
        f"WHERE c.router_id = {rid}\n"
        "  AND ubu.last_updated > NOW() - INTERVAL '1 hour'\n"
        "ORDER BY ubu.last_updated DESC\nLIMIT 10"),
        # Provisioning that has not (yet) landed on the router —
        # paid-but-offline complaints usually show up here first.
        ("pending_provisioning",
        "SELECT pa.customer_id, pa.provisioning_state::text AS provisioning_state,\n"
        "       pa.online_state::text AS online_state, pa.attempt_count,\n"
        "       pa.last_error, pa.updated_at\n"
        "FROM provisioning_attempts pa\n"
        f"WHERE pa.router_id = {rid}\n"
        "  AND pa.provisioning_state IN ('scheduled', 'in_progress', 'retry_pending', 'failed')\n"
        "ORDER BY pa.updated_at DESC\nLIMIT 10"),
    ])

    if not batch["router"]:
        fail(f"no router with id {rid}")
    return {"router": batch["router"][0],
            "customer_counts": batch["customer_counts"][0] if batch["customer_counts"] else None,
            "seen_last_hour": batch["seen_last_hour"],
            "unsettled_provisioning": batch["pending_provisioning"]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Customer/router session-state signals (read-only)")
    ident = ap.add_mutually_exclusive_group(required=True)
    ident.add_argument("--account-id", type=int, help="customers.id")
    ident.add_argument("--router-id", type=int, help="routers.id")
    args = ap.parse_args()

    try:
        if args.account_id:
            result = account_state(args.account_id)
        else:
            result = router_state(args.router_id)
    except ProdQueryError as e:
        fail(str(e))

    emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

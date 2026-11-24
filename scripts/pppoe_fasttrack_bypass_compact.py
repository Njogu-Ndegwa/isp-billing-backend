"""Shrink the PPPoE FastTrack bypass to one rule pair per pool block on routers
that still carry one pair per CIDR block (26 rules for the usual .2-.254 pool).

`MikroTikAPI.ensure_pppoe_fasttrack_bypass` does this by itself the next time a
PPPoE customer is provisioned or a port is saved on the router. This script is
for routers where that will not happen soon, mainly hotspot routers that have a
PPPoE pool but few or no PPPoE customers: every forwarded packet still walks
the old rules (router 354, 2026-11-23: 18% of firewall CPU per packet).

Run inside the app container, only once the release with the range rules is
live. An older app would add the CIDR rules back on the next PPPoE
provisioning, so the script refuses to run against one.

    docker exec -e ROUTER_IDS=354 -i isp_billing_hetzner_app python - < scripts/pppoe_fasttrack_bypass_compact.py
    docker exec -e ROUTER_IDS=354 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/pppoe_fasttrack_bypass_compact.py
    docker exec -e ALL_ONLINE=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/pppoe_fasttrack_bypass_compact.py

Without APPLY=1 it only reports. On each router it reads the managed bypass
rules, finds the IP pool they were made for, and calls
`ensure_pppoe_fasttrack_bypass(pool_name=...)`, which adds the new rule pair
first and removes the old rules after. A router whose old rules match no pool
is reported as `no_pool` and left alone. Unreachable routers are reported and
skipped: re-run with ALL_ONLINE=1 to catch them later.

Routers are read in one short DB session that is released before any RouterOS
I/O; nothing is written to the DB.
"""

import asyncio
import json
import os

from sqlalchemy import text

from app.db.database import async_session
from app.services.mikrotik_api import PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX, MikroTikAPI

APPLY = os.environ.get("APPLY") == "1"
ALL_ONLINE = os.environ.get("ALL_ONLINE") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]


async def load():
    where = "r.last_status is true" if ALL_ONLINE else "r.id = any(:ids)"
    async with async_session() as db:
        rows = (await db.execute(text(
            "select r.id, r.name, r.ip_address, r.username, r.password, r.port "
            f"from routers r where {where} order by r.id"), {"ids": IDS})).mappings().all()
        await db.commit()
    return [dict(r) for r in rows]


def _covers(outer, inner) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def compact_router(r) -> dict:
    out = {"router_id": r["id"], "name": r["name"]}
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728,
                      timeout=30, connect_timeout=5)
    if not api.connect():
        out["status"] = "unreachable"
        out["error"] = (api.last_connect_error or "")[:120]
        return out
    try:
        rules = api.send_command_optimized(
            "/ip/firewall/filter/print",
            proplist=[".id", "chain", "action", "comment", "src-address", "dst-address", "disabled"],
        )
        if not rules.get("success"):
            out["status"] = "error"
            out["error"] = f"filter read failed: {rules.get('error')}"
            return out
        managed = []
        for rule in rules.get("data") or []:
            comment = str(rule.get("comment") or "")
            if (comment.startswith(PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX)
                    and rule.get("chain") == "forward" and rule.get("action") == "accept"):
                span = api._address_span(rule.get("src-address") or rule.get("dst-address"))
                if span:
                    managed.append((comment, span))
        out["rules_now"] = len(managed)
        if not managed:
            out["status"] = "none"
            return out

        pools = api.send_command_optimized("/ip/pool/print", proplist=["name", "ranges"])
        targets = {}
        for pool in pools.get("data") or [] if pools.get("success") else []:
            matchers = api._pool_ranges_to_matchers(pool.get("ranges", ""))
            spans = [s for s in (api._address_span(m) for m in matchers) if s]
            wanted = {f"{PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX} ({side}) {m}" for m in matchers for side in ("src", "dst")}
            old = [c for c, span in managed if c not in wanted and any(_covers(s, span) for s in spans)]
            if old:
                targets[pool.get("name")] = {"matchers": matchers, "old_rules": len(old)}
        out["pools"] = targets
        covered = sum(t["old_rules"] for t in targets.values())
        if not targets:
            # Either already one pair per block, or old rules whose pool is gone.
            all_wanted = set()
            for pool in pools.get("data") or [] if pools.get("success") else []:
                for m in api._pool_ranges_to_matchers(pool.get("ranges", "")):
                    all_wanted.update(f"{PPPOE_FASTTRACK_BYPASS_COMMENT_PREFIX} ({side}) {m}" for side in ("src", "dst"))
            out["status"] = "compact" if all(c in all_wanted for c, _ in managed) else "no_pool"
            return out
        if not APPLY:
            out["status"] = "would_compact"
            out["rules_after"] = len(managed) - covered + 2 * sum(len(t["matchers"]) for t in targets.values())
            return out

        results = {}
        for pool_name in targets:
            res = api.ensure_pppoe_fasttrack_bypass(pool_name=pool_name)
            results[pool_name] = {k: res.get(k) for k in (
                "error", "fasttrack_enabled", "rules_added", "rules_reused", "rules_removed", "rules_superseded", "warnings")}
        out["results"] = results
        if any(v.get("error") for v in results.values()):
            out["status"] = "error"
        elif not all(v.get("fasttrack_enabled") for v in results.values()):
            # No active FastTrack rule: the function manages nothing, so nothing was changed.
            out["status"] = "no_fasttrack"
        else:
            out["status"] = "compacted"
        return out
    except Exception as exc:  # report and move on to the next router
        out["status"] = "error"
        out["error"] = str(exc)[:160]
        return out
    finally:
        api.disconnect()


def main():
    if not IDS and not ALL_ONLINE:
        raise SystemExit("set ROUTER_IDS=1,2,3 or ALL_ONLINE=1")
    if not hasattr(MikroTikAPI, "_pool_ranges_to_matchers"):
        raise SystemExit("this app build still writes the bypass as CIDR blocks; deploy the range-rule release first")
    routers = asyncio.run(load())
    print(f"{len(routers)} router(s), APPLY={APPLY}")
    totals: dict[str, int] = {}
    for r in routers:
        result = compact_router(r)
        totals[result["status"]] = totals.get(result["status"], 0) + 1
        print("RESULT " + json.dumps(result))
    print("TOTALS " + json.dumps(totals))


if __name__ == "__main__":  # `python - < this file` runs it; tests import it
    main()

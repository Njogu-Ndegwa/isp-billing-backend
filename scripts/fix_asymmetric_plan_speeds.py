"""Re-apply asymmetric plan speeds after the 2026-09-29 download/upload fix.

Plan speeds are DOWNLOAD/UPLOAD, but until 2026-09-29 they reached RouterOS
unswapped, so a "5M/2M" plan got 2 Mbps download. New provisioning is correct
once the fix is deployed; this moves the customers who are ALREADY online:

* PPPoE: secret -> the plan's (corrected) ``pppoe_<rate>`` profile, session
  kicked so it reconnects at the new rate (nothing else re-applies PPPoE).
* Hotspot on a MAC-login router: user -> the corrected ``plan_<rate>``
  profile, session kicked (the reconcile would also do this within ~5 min).
* Hotspot bypass: the static ``plan_<MAC>`` queue's max-limit is corrected in
  place (no kick needed; the queue sync would get there eventually).

Customers with an open FUP period are skipped (their router state carries the
throttle, and the FUP code owns it). Symmetric plans are never touched.

Runs inside the app container. Read-only unless MODE=apply.

    ssh root@<prod> "docker exec -e MODE=dry-run -i isp_billing_hetzner_app python -" \
        < scripts/fix_asymmetric_plan_speeds.py

Optional ROUTER_IDS=10,333 limits the run to those routers.

SCOPE=all (default: asymmetric) re-checks EVERY plan, not just asymmetric
ones: it also moves PPPoE secrets left on a profile with no rate limit
(e.g. "default"; router 393 had all 7 customers there on 2026-09-29).
Disabled bypass plan_ queues are only counted, never re-enabled: the queue
sync's hygiene pass disables a customer's queue when another device took over
its IP, so re-enabling it here would throttle that other device.
"""

import asyncio
import json
import os
import re
from collections import defaultdict
from datetime import datetime

from sqlalchemy import text

from app.config import settings
from app.db.database import async_engine, async_session
from app.services import hotspot_mac_login as ml
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address, parse_speed_to_mikrotik
from app.services.pppoe_provisioning import _apply_pppoe_headroom, ensure_plan_pppoe_profile

MODE = os.environ.get("MODE", "dry-run").strip().lower()
SCOPE = os.environ.get("SCOPE", "asymmetric").strip().lower()
ONLY = {int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()}
_UNIT = {"": 1, "K": 1_000, "M": 1_000_000, "G": 1_000_000_000}


def bps(part: str):
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([KMG]?)", str(part or "").upper())
    return int(float(m.group(1)) * _UNIT[m.group(2)]) if m else None


def pair(rate: str):
    if "/" not in str(rate or ""):
        return None
    a, b = str(rate).split("/", 1)
    return bps(a), bps(b)


async def load():
    sql = """
        SELECT c.id, c.mac_address, c.pppoe_username, p.speed, p.connection_type,
               r.id AS router_id, r.name AS router_name, r.ip_address, r.username, r.password, r.port
        FROM customers c
        JOIN plans p ON p.id = c.plan_id
        JOIN routers r ON r.id = c.router_id
        WHERE c.status = 'ACTIVE' AND c.expiry > now()
          AND r.auth_method = 'DIRECT_API' AND r.last_status IS TRUE
          AND NOT EXISTS (
              SELECT 1 FROM customer_usage_periods u
              WHERE u.customer_id = c.id AND u.closed_at IS NULL
                AND u.fup_triggered_at IS NOT NULL AND u.fup_reverted_at IS NULL)
        ORDER BY r.id, c.id
    """
    async with async_session() as db:
        rows = [dict(x._mapping) for x in (await db.execute(text(sql)))]
        await db.commit()
    await async_engine.dispose()
    out = []
    for row in rows:
        rate = parse_speed_to_mikrotik(row["speed"])
        up_down = pair(rate)
        if not up_down:
            continue
        if SCOPE != "all" and up_down[0] == up_down[1]:
            continue  # symmetric: unaffected by the swap
        if ONLY and row["router_id"] not in ONLY:
            continue
        row["rate"] = rate
        out.append(row)
    return out


def fix_router(rows):
    head = rows[0]
    res = {"router": f'{head["router_id"]} {head["router_name"]}', "customers": len(rows),
           "fixed": 0, "already_ok": 0, "not_on_router": 0, "disabled_by_hygiene": 0,
           "by_kind": defaultdict(int), "errors": []}
    api = MikroTikAPI(head["ip_address"], head["username"], head["password"], head["port"] or 8728, timeout=30)
    if not api.connect():
        res["errors"].append("unreachable")
        return res
    d = lambda cmd: (api.send_command(cmd).get("data") or [])
    factor = float(getattr(settings, "PPPOE_RATE_LIMIT_HEADROOM", 1.0) or 1.0)
    mac_login = ml.mac_login_enabled(head["router_id"])
    try:
        secrets = queues = users = None
        for c in rows:
            kind = str(c["connection_type"]).upper()
            before = res["fixed"]
            try:
                if kind.endswith("PPPOE"):
                    secrets = secrets if secrets is not None else {s.get("name"): s for s in d("/ppp/secret/print")}
                    s = secrets.get(c["pppoe_username"])
                    want = f"pppoe_{c['rate'].replace('/', '_')}"
                    if not s:
                        res["not_on_router"] += 1
                    elif s.get("profile") == want:
                        res["already_ok"] += 1
                    elif MODE == "apply":
                        ensured = ensure_plan_pppoe_profile(api, c["speed"])
                        if ensured.get("error"):
                            raise RuntimeError(ensured["error"])
                        api.send_command("/ppp/secret/set", {"numbers": s[".id"], "profile": ensured["profile"]})
                        api.disconnect_pppoe_session(c["pppoe_username"])
                        res["fixed"] += 1
                    else:
                        res["fixed"] += 1  # would fix
                elif mac_login:
                    mac = ml.mac_login_username(c["mac_address"])
                    users = users if users is not None else {u.get("name", "").upper(): u for u in d("/ip/hotspot/user/print")}
                    u = users.get(mac)
                    want = ml.profile_name_for_rate(c["rate"])
                    if not u:
                        res["not_on_router"] += 1
                    elif u.get("profile") == want:
                        res["already_ok"] += 1
                    elif MODE == "apply":
                        out = ml.set_customer_rate(api, mac, c["speed"])
                        if out.get("error"):
                            raise RuntimeError(out["error"])
                        res["fixed"] += 1
                    else:
                        res["fixed"] += 1
                else:
                    mac = normalize_mac_address(c["mac_address"])
                    compact = mac.replace(":", "")
                    queues = queues if queues is not None else d("/queue/simple/print")
                    q = next((q for q in queues if q.get("dynamic") != "true" and (
                        q.get("name") in (f"plan_{compact}", f"queue_{compact}")
                        or f"MAC:{mac}" in str(q.get("comment", "")).upper())), None)
                    if not q:
                        res["not_on_router"] += 1
                    elif q.get("disabled") == "true":
                        res["disabled_by_hygiene"] += 1
                    elif pair(q.get("max-limit")) == pair(c["rate"]):
                        res["already_ok"] += 1
                    elif MODE == "apply":
                        out = api.send_command("/queue/simple/set", {"numbers": q[".id"], "max-limit": c["rate"]})
                        if out.get("error"):
                            raise RuntimeError(out["error"])
                        res["fixed"] += 1
                    else:
                        res["fixed"] += 1
                if res["fixed"] > before:
                    res["by_kind"]["pppoe" if kind.endswith("PPPOE") else ("mac_login" if mac_login else "bypass")] += 1
            except Exception as exc:  # one customer must not stop the router
                res["errors"].append(f'{c["id"]}: {exc}'[:120])
    finally:
        api.disconnect()
    return res


def main():
    rows = asyncio.run(load())
    by_router = defaultdict(list)
    for row in rows:
        by_router[row["router_id"]].append(row)
    print(f"== mode={MODE} affected customers={len(rows)} routers={len(by_router)} at {datetime.utcnow():%Y-%m-%d %H:%M} UTC")
    totals = defaultdict(int)
    for rid in sorted(by_router):
        res = fix_router(by_router[rid])
        for k in ("customers", "fixed", "already_ok", "not_on_router", "disabled_by_hygiene"):
            totals[k] += res[k]
        totals["routers_with_errors"] += bool(res["errors"])
        print("ROUTER", json.dumps(res))
    label = "fixed" if MODE == "apply" else "would fix"
    print(f"== TOTAL: {dict(totals)} ({label} = 'fixed')")


main()

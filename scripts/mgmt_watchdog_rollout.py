"""Bring the management-tunnel watchdog already on routers to the current
template (app/services/mgmt_watchdog_script.py): SSTP v4 / WireGuard v5, which
re-check the tunnel after the splay delay instead of restarting a tunnel that
has just come back (router 715, 2026-11-13).

New installs already get the current template. Routers that have the
watchdog are never revisited by standard_runtime_enrol, so they need this.

Run inside the app container. Dry run (reports only) unless APPLY=1:

    # canary
    docker exec -e ROUTER_IDS=715,A,B -i isp_billing_hetzner_app python - < scripts/mgmt_watchdog_rollout.py
    docker exec -e ROUTER_IDS=715,A,B -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/mgmt_watchdog_rollout.py
    # batches of 20 updates over the online routers, one kind at a time
    docker exec -e ALL_ONLINE=1 -e KIND=sstp -e MAX_UPDATES=20 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/mgmt_watchdog_rollout.py

Only the ``source`` of a watchdog script that is already on the router is
rewritten (``refresh_installed_source``): nothing is added or removed, no
scheduler is touched (a paused one stays paused), nothing is run, nothing
rebooted. Routers already on the current source are reported "unchanged" and
cost one read, so re-running the same command is how the next batch goes out.
SKIP_IDS=1,2 leaves routers out. Unreachable routers are reported and skipped.

Routers are read in one short DB session released before any RouterOS I/O;
nothing is written to the DB.
"""

import asyncio
import json
import os
import time

from sqlalchemy import text

from app.db.database import async_session
from app.services.mgmt_watchdog_script import SCRIPT_NAMES, refresh_installed_source
from app.services.mikrotik_api import MikroTikAPI

APPLY = os.environ.get("APPLY") == "1"
ALL_ONLINE = os.environ.get("ALL_ONLINE") == "1"
KIND = os.environ.get("KIND", "").strip().lower()          # "", "sstp" or "wg"
MAX_UPDATES = int(os.environ.get("MAX_UPDATES") or 0)     # 0 = no limit
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
SKIP = {int(x) for x in os.environ.get("SKIP_IDS", "").split(",") if x.strip().isdigit()}


async def load():
    where = "r.last_status is true" if ALL_ONLINE else "r.id = any(:ids)"
    async with async_session() as db:
        rows = (await db.execute(text(
            "select r.id, r.name, r.ip_address, r.username, r.password, r.port "
            f"from routers r where {where} order by r.id"), {"ids": IDS})).mappings().all()
        await db.commit()
    return [dict(r) for r in rows if r["id"] not in SKIP]


def refresh_router(r, apply: bool) -> dict:
    out = {"router_id": r["id"], "name": r["name"]}
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728,
                      timeout=30, connect_timeout=5)
    if not api.connect():
        out["status"] = "unreachable"
        out["error"] = (api.last_connect_error or "")[:120]
        return out
    try:
        res = (api.send_command("/system/resource/print").get("data") or [{}])[0]
        out["version"] = str(res.get("version", "")).split(" ")[0]
        scripts = refresh_installed_source(api, r["ip_address"], apply=apply)
        if KIND:
            wanted = SCRIPT_NAMES.get(KIND)
            scripts = {n: s for n, s in scripts.items() if n == wanted}
        out["scripts"] = scripts
        statuses = [s.split(" (")[0] for s in scripts.values()]
        if not scripts:
            out["status"] = "no_watchdog"
        elif any(s.startswith("failed") or s == "verify_failed" for s in statuses):
            out["status"] = "failed"
        elif "updated" in statuses:
            out["status"] = "updated"
        elif "would update" in statuses:
            out["status"] = "would_update"
        else:
            out["status"] = "unchanged"
    except Exception as exc:  # one bad router must not stop the batch
        out["status"] = "error"
        out["error"] = str(exc)[:160]
    finally:
        api.disconnect()
    return out


def main():
    if not IDS and not ALL_ONLINE:
        raise SystemExit("set ROUTER_IDS=1,2,3 or ALL_ONLINE=1")
    if KIND and KIND not in SCRIPT_NAMES:
        raise SystemExit("KIND must be sstp or wg")
    routers = asyncio.run(load())
    print(f"{len(routers)} router(s), APPLY={APPLY}, KIND={KIND or 'any'}, MAX_UPDATES={MAX_UPDATES or '-'}")
    totals: dict[str, int] = {}
    updates = 0
    for r in routers:
        if MAX_UPDATES and updates >= MAX_UPDATES:
            print(f"STOP reached MAX_UPDATES={MAX_UPDATES}; re-run for the next batch")
            break
        started = time.monotonic()
        result = refresh_router(r, APPLY)
        result["seconds"] = round(time.monotonic() - started, 1)
        if result["status"] in ("updated", "would_update"):
            updates += 1
        key = result["status"]
        if result.get("version"):
            key += f" ros{result['version'].split('.')[0]}"
        totals[key] = totals.get(key, 0) + 1
        print("RESULT " + json.dumps(result))
        if result["status"] == "failed":
            print("STOP a router failed; fix it before the next batch")
            break
    print("TOTALS " + json.dumps(totals))


if __name__ == "__main__":
    main()

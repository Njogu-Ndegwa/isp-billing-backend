"""Put the one-at-a-time gate (app/services/router_script_gate.py) on the
Bitwave scripts already installed on routers.

Run inside the app container:

    docker exec -e ROUTER_IDS=585 -i isp_billing_hetzner_app python - < scripts/router_script_gate_rollout.py
    docker exec -e ROUTER_IDS=585 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/router_script_gate_rollout.py
    docker exec -e ALL_ONLINE=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/router_script_gate_rollout.py
    docker exec -e ROUTER_IDS=585 -e ROLLBACK=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/router_script_gate_rollout.py

Without APPLY=1 it only reports. The gate is prepended to the source that is
on the router now, so per-router tokens and identities are untouched and no
script is re-rendered; a router that already has the current gate is left
alone. ROLLBACK=1 strips the gate again. Schedulers are not touched. New
installs get the gate from the renderers, so this is only for routers that
already had the scripts. Unreachable routers are reported and skipped:
re-run with ALL_ONLINE=1 to catch them later.

Routers are read in one short DB session that is released before any
RouterOS I/O; nothing is written to the DB.
"""

import asyncio
import json
import os
import time

from sqlalchemy import text

from app.db.database import async_session
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_script_gate import GATED_SCRIPTS, has_current_gate, strip_gate, with_gate

APPLY = os.environ.get("APPLY") == "1"
ROLLBACK = os.environ.get("ROLLBACK") == "1"
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


def gate_router(r) -> dict:
    out = {"router_id": r["id"], "name": r["name"], "scripts": {}}
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728,
                      timeout=30, connect_timeout=5)
    if not api.connect():
        out["status"] = "unreachable"
        out["error"] = (api.last_connect_error or "")[:120]
        return out
    try:
        for script in api.send_command("/system/script/print").get("data") or []:
            name = script.get("name")
            if name not in GATED_SCRIPTS:
                continue
            src = script.get("source") or ""
            new = strip_gate(src) if ROLLBACK else with_gate(name, src)
            if new == src:
                out["scripts"][name] = "unchanged"
                continue
            if not APPLY:
                out["scripts"][name] = "would " + ("strip" if ROLLBACK else "gate")
                continue
            res = api.send_command("/system/script/set", {".id": script[".id"], "source": new})
            if (res or {}).get("error"):
                out["scripts"][name] = f"failed: {str(res['error'])[:100]}"
                continue
            check = [s for s in api.send_command("/system/script/print").get("data") or []
                     if s.get(".id") == script[".id"]]
            live = (check[0].get("source") or "") if check else ""
            ok = (not has_current_gate(name, live)) if ROLLBACK else has_current_gate(name, live)
            out["scripts"][name] = ("stripped" if ROLLBACK else "gated") if ok else "verify_failed"
        out["status"] = "ok" if out["scripts"] else "no_bitwave_scripts"
    except Exception as exc:  # one bad router must not stop the batch
        out["status"] = "error"
        out["error"] = str(exc)[:160]
    finally:
        api.disconnect()
    return out


def main():
    if not IDS and not ALL_ONLINE:
        raise SystemExit("set ROUTER_IDS=1,2,3 or ALL_ONLINE=1")
    routers = asyncio.run(load())
    print(f"{len(routers)} router(s), APPLY={APPLY}, ROLLBACK={ROLLBACK}")
    totals: dict[str, int] = {}
    for r in routers:
        started = time.monotonic()
        result = gate_router(r)
        result["seconds"] = round(time.monotonic() - started, 1)
        totals[result["status"]] = totals.get(result["status"], 0) + 1
        print("RESULT " + json.dumps(result))
    print("TOTALS " + json.dumps(totals))


main()

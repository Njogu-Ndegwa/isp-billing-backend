"""Install / update / roll back the real-time usage push (v3) on routers.

Run inside the app container (it uses the app's DB models and RouterOS client):

    docker exec -e ROUTER_IDS=10,487 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py
    docker exec -e ROUTER_IDS=10,487 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py
    docker exec -e ROUTER_IDS=10 -e ROLLBACK=1 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py

Without APPLY=1 / ROLLBACK=1 it only reports what it would do. One JSON line
per router is printed (prefix "RESULT "). Safe to re-run: a router already on
v3 is updated in place and its original backup is kept.

The logic lives in app/services/realtime_push_installer.py (shared with the
install that runs when a new router finishes setup). Flags:

    SKIP_RUN=1     don't run the first report over the API (the scheduler's first tick does)
    ALLOW_SMALL=1  also hAP lite/mini (Dennis 2026-09-26: they stay on polling - don't)
    FORCE_HTTPS=1  install even without a working encrypted tunnel (heavy on small boards)

Installing the v3 script is what puts a router on real-time push: the server
enrols any router sending v3 reports and hands it back to the poller ~15 min
after they stop. DB is read in one short session and released before any
RouterOS I/O.
"""

import asyncio
import json
import os

from sqlalchemy import text

from app.db.database import async_session
from app.services.realtime_push_installer import install_router

APPLY = os.environ.get("APPLY") == "1"
ROLLBACK = os.environ.get("ROLLBACK") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]


async def load_routers():
    async with async_session() as db:
        rows = (await db.execute(
            text("select id, name, identity, ip_address, username, password, port from routers "
                 "where id = any(:ids) order by id"),
            {"ids": IDS},
        )).mappings().all()
        await db.commit()
    return [dict(r) for r in rows]


def _line(r: dict) -> str:
    bits = [f"{r['id']} {r.get('name')}: {r['status']}"]
    if r.get("board"):
        bits.append(f"{r['board']} ({r.get('arch')}) ROS {r.get('ros')}")
    if r.get("tunnel_kind"):
        bits.append(f"tunnel={r.get('tunnel') or '-'} ({r['tunnel_kind']}) ping={'ok' if r.get('tunnel_ping') else 'fail'}")
    if r.get("wan"):
        bits.append(f"wan={r['wan']} had={r.get('had_script')}")
    if r.get("first_run_seconds") is not None:
        bits.append(f"first report {r['first_run_seconds']}s")
    if r.get("error"):
        bits.append(f"error={r['error']}")
    return " | ".join(bits)


if __name__ == "__main__":
    if not IDS:
        raise SystemExit("set ROUTER_IDS=1,2,3")
    for router in asyncio.run(load_routers()):
        result = install_router(
            router,
            apply=APPLY,
            rollback=ROLLBACK,
            skip_run=os.environ.get("SKIP_RUN") == "1",
            allow_small=os.environ.get("ALLOW_SMALL") == "1",
            force_https=os.environ.get("FORCE_HTTPS") == "1",
            measure_cpu=not APPLY and not ROLLBACK,
        )
        print(_line(result), flush=True)
        for line in result.get("log") or []:
            print(f"   log: {line}")
        print("RESULT " + json.dumps(result), flush=True)

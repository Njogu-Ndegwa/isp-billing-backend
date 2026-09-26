"""Install / remove the check-in delivery applier on ONE router (pilot).

Run inside the app container (it uses the app's DB models and RouterOS client):

    # dry run (default): read-only — checks identity, shows what would change
    docker exec -e ROUTER_ID=383 -i isp_billing_hetzner_app python - < scripts/checkin_pilot_install.py
    # install / update the applier script + its scheduler
    docker exec -e ROUTER_ID=383 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/checkin_pilot_install.py
    # remove them again (scheduler first, then script)
    docker exec -e ROUTER_ID=383 -e APPLY=1 -e UNINSTALL=1 -i isp_billing_hetzner_app python - < scripts/checkin_pilot_install.py

Optional: CHECK_CERT=yes-without-crl (default "no" for the pilot; RouterOS < 7.19
has no CA store, so only turn it on where the bench showed it works).

What it does NOT do:
* It never runs the script over the API (``/system/script/run`` jobs can die
  with the API session). The scheduler runs it; the first check-in happens
  within one interval (60 s) of install.
* It never touches bindings or queues. Uninstalling leaves every binding the
  applier created in place — they are in the API push's own format, so the
  normal expiry cleanup removes them like any other.
* It does not enable the server side. The router only receives work when
  CHECKIN_ENABLED=true and its id is in CHECKIN_ROUTER_IDS; otherwise every
  reply is an empty idle frame (next check-in in 10 min).

DB is read in one short session and released before any RouterOS I/O.
"""

import asyncio
import os

from sqlalchemy import text

from app.db.database import async_session
from app.services.checkin_applier_script import (
    INITIAL_INTERVAL_SECONDS,
    POLICY,
    SCHEDULER_COMMENT,
    SCHEDULER_NAME,
    SCRIPT_NAME,
    render_checkin_applier_source,
    scheduler_on_event,
)
from app.services.mikrotik_api import MikroTikAPI

PUBLIC_URL = "https://isp.bitwavetechnologies.net/api/router/checkin"
APPLY = os.environ.get("APPLY") == "1"
UNINSTALL = os.environ.get("UNINSTALL") == "1"
CHECK_CERT = os.environ.get("CHECK_CERT", "no").strip() or "no"
_rid = os.environ.get("ROUTER_ID", "").strip()
ROUTER_ID = int(_rid) if _rid.isdigit() else None


async def load_router(router_id: int):
    async with async_session() as db:
        row = (await db.execute(
            text("select id, name, identity, ip_address, username, password, port "
                 "from routers where id = :id"),
            {"id": router_id},
        )).mappings().first()
        await db.commit()
    return dict(row) if row else None


def _find(api, path, name):
    rows = api.send_command(f"{path}/print").get("data", []) or []
    return [r for r in rows if r.get("name") == name]


def run(r):
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=60)
    if not api.connect():
        print(f"{r['id']} {r['name']}: UNREACHABLE — nothing done")
        return
    try:
        c = lambda p, a=None: api.send_command(p, a or {})  # noqa: E731
        ident = c("/system/identity/print")["data"][0]["name"]
        if ident != r["identity"]:
            print(f"{r['id']} {r['name']}: identity mismatch router={ident} db={r['identity']} — skipped")
            return
        res = (c("/system/resource/print").get("data") or [{}])[0]
        scripts = _find(api, "/system/script", SCRIPT_NAME)
        scheds = _find(api, "/system/scheduler", SCHEDULER_NAME)
        print(f"{r['id']} {r['name']} ({ident}) RouterOS {res.get('version')} on {res.get('board-name')}")
        print(f"   existing: script={'yes' if scripts else 'no'} scheduler={'yes' if scheds else 'no'}"
              + (f" interval={scheds[0].get('interval')} disabled={scheds[0].get('disabled')}" if scheds else ""))

        if UNINSTALL:
            print("   plan: remove scheduler, then script")
            if not APPLY:
                print("   dry run — set APPLY=1 to remove")
                return
            for s in scheds:
                print("   scheduler remove:", c("/system/scheduler/remove", {".id": s[".id"]}).get("error") or "ok")
            for s in scripts:
                print("   script remove:", c("/system/script/remove", {".id": s[".id"]}).get("error") or "ok")
            return

        source = render_checkin_applier_source(
            identity=ident, endpoint_url=PUBLIC_URL, check_certificate=CHECK_CERT,
        )
        print(f"   plan: {'update' if scripts else 'add'} script '{SCRIPT_NAME}' ({len(source)} bytes, "
              f"check-certificate={CHECK_CERT}), {'update' if scheds else 'add'} scheduler "
              f"'{SCHEDULER_NAME}' every {INITIAL_INTERVAL_SECONDS}s -> {PUBLIC_URL}")
        if not APPLY:
            print("   dry run — set APPLY=1 to install")
            return

        out = (c("/system/script/set", {".id": scripts[0][".id"], "source": source, "policy": POLICY})
               if scripts else
               c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": source}))
        if out.get("error"):
            print(f"   script: {out['error']}")
            return
        out = (c("/system/scheduler/set", {".id": scheds[0][".id"], "disabled": "no",
                                           "on-event": scheduler_on_event(), "policy": POLICY,
                                           "comment": SCHEDULER_COMMENT})
               if scheds else
               c("/system/scheduler/add", {"name": SCHEDULER_NAME,
                                           "interval": f"{INITIAL_INTERVAL_SECONDS}s",
                                           "start-time": "startup",
                                           "on-event": scheduler_on_event(), "policy": POLICY,
                                           "comment": SCHEDULER_COMMENT}))
        if out.get("error"):
            print(f"   scheduler: {out['error']}")
            return
        print("   installed; first check-in within one interval. Watch: /log print where message~\"checkin\"")
    finally:
        api.disconnect()


if __name__ == "__main__":
    if ROUTER_ID is None:
        raise SystemExit("set ROUTER_ID=<id> (one router per run)")
    row = asyncio.run(load_router(ROUTER_ID))
    if row is None:
        raise SystemExit(f"router {ROUTER_ID} not found")
    run(row)

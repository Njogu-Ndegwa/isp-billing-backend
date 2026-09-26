"""Install / remove the router expiry reaper on pilot routers.

Run inside the app container (uses the app's DB models and RouterOS client):

    docker exec -e ROUTER_IDS=478,464 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py
    docker exec -e ROUTER_IDS=478,464 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py
    docker exec -e ROUTER_IDS=478 -e UNINSTALL=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py

Without APPLY=1 it only reports what it would change. With APPLY=1, per router:

1. NTP client on, if it is off (the reaper will not act on a clock the server
   has not confirmed, and a no-RTC board needs NTP to get one after a reboot).
2. EXP:<minute> added to the ip-binding comment of every customer who is
   ACTIVE with a future expiry (new payments get it from provisioning).
3. The reaper script + 1-minute scheduler, then one run.
4. routers.expiry_reaper_enabled = true (the server cleanup then waits 3 min
   past expiry on this router before acting as backstop).

UNINSTALL=1 removes the scheduler, the script and its globals, and clears the
flag. EXP tags are left in place: without the reaper nothing reads them.

DB is read in one short session and released before any RouterOS I/O; the flag
is written afterwards in its own short session.
"""

import asyncio
import os
import time
from datetime import datetime

from sqlalchemy import text

from app.config import settings
from app.db.database import async_session
from app.services.expiry_reaper_script import (
    COMMENT, POLICY, SCHEDULER_NAME, SCRIPT_NAME, render_expiry_reaper_script, script_source,
)
from app.services.mikrotik_api import MikroTikAPI
from app.services.router_expiry import expiry_second, normalize_mac, with_exp_tag

APPLY = os.environ.get("APPLY") == "1"
UNINSTALL = os.environ.get("UNINSTALL") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
NTP_SERVER = "162.159.200.1"
TUNNEL_SERVER_IP = "10.251.0.1"


async def load():
    async with async_session() as db:
        routers = (await db.execute(text(
            "select id, name, identity, ip_address, username, password, port "
            "from routers where id = any(:ids)"), {"ids": IDS})).mappings().all()
        rows = (await db.execute(text(
            "select router_id, upper(mac_address) as mac, max(expiry) as expiry from customers "
            "where router_id = any(:ids) and status = 'ACTIVE' and expiry > now() at time zone 'utc' "
            "and mac_address is not null group by router_id, upper(mac_address)"), {"ids": IDS})).mappings().all()
        await db.commit()
    paid: dict[int, dict[str, datetime]] = {}
    for r in rows:
        mac = normalize_mac(r["mac"])
        if mac:
            paid.setdefault(r["router_id"], {})[mac] = r["expiry"]
    return [dict(r) for r in routers], paid


async def set_flag(router_id: int, enabled: bool):
    async with async_session() as db:
        await db.execute(text(
            "update routers set expiry_reaper_enabled = :on, "
            "expiry_reaper_installed_at = case when :on then now() at time zone 'utc' else expiry_reaper_installed_at end "
            "where id = :id"), {"on": enabled, "id": router_id})
        await db.commit()


def first(api, path):
    data = api.send_command(path).get("data") or []
    return data[0] if data else {}


def ensure_ntp(api, version: str) -> str:
    ntp = first(api, "/system/ntp/client/print")
    if ntp.get("enabled") == "true":
        return "ntp already on"
    if not APPLY:
        return "would enable ntp"
    args = {"enabled": "yes"}
    if version.startswith("6."):
        if ntp.get("primary-ntp") in (None, "", "0.0.0.0"):
            args["primary-ntp"] = NTP_SERVER
    elif not ntp.get("servers"):
        args["servers"] = NTP_SERVER
    res = api.send_command("/system/ntp/client/set", args)
    return f"ntp enabled {res.get('error') or ''}".strip()


def tag_bindings(api, paid: dict[str, datetime]) -> str:
    changed = skipped = 0
    for b in api.send_command("/ip/hotspot/ip-binding/print").get("data") or []:
        mac = normalize_mac(b.get("mac-address", ""))
        if not mac or mac not in paid:
            skipped += 1
            continue
        comment = b.get("comment", "")
        new = with_exp_tag(comment, expiry_second(paid[mac]))
        if new == comment:
            continue
        changed += 1
        if APPLY:
            api.send_command("/ip/hotspot/ip-binding/set", {".id": b[".id"], "comment": new})
    return f"{'tagged' if APPLY else 'would tag'} {changed} binding(s), {skipped} not paid-up/untagged"


def remove_reaper(api):
    for path, name in (("/system/scheduler", SCHEDULER_NAME), ("/system/script", SCRIPT_NAME)):
        for item in api.send_command(f"{path}/print").get("data") or []:
            if item.get("name") == name:
                api.send_command(f"{path}/remove", {".id": item[".id"]})
    for env in api.send_command("/system/script/environment/print").get("data") or []:
        if str(env.get("name", "")).startswith("bwExp"):
            api.send_command("/system/script/environment/remove", {".id": env[".id"]})


def install(r, paid):
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=60)
    if not api.connect():
        print(f"{r['id']} {r['name']}: UNREACHABLE, nothing done")
        return False
    try:
        ident = first(api, "/system/identity/print").get("name")
        if ident != r["identity"]:
            print(f"{r['id']} {r['name']}: identity mismatch router={ident} db={r['identity']}, skipped")
            return False
        res = first(api, "/system/resource/print")
        version, board, cpu = res.get("version", ""), res.get("board-name"), res.get("cpu-load")
        print(f"{r['id']} {r['name']}: {board} {version} cpu {cpu}%")
        pings = api.send_command("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"}).get("data") or []
        tunnel_ok = any(p.get("time") for p in pings)
        print(f"   reaches {TUNNEL_SERVER_IP}: {'yes, calls go over the tunnel' if tunnel_ok else 'NO, calls fall back to public HTTPS (costly on a hAP lite)'}")
        if UNINSTALL:
            if APPLY:
                remove_reaper(api)
            print("   " + ("removed" if APPLY else "would remove") + " reaper script, scheduler and globals")
            return True
        print("   " + ensure_ntp(api, version))
        print("   " + tag_bindings(api, paid))
        if not APPLY:
            return False
        rendered = render_expiry_reaper_script(
            identity=ident,
            tunnel_url=settings.EXPIRY_REAPER_TUNNEL_URL,
            public_url=settings.EXPIRY_REAPER_PUBLIC_URL,
        )
        source = script_source(rendered)
        remove_reaper(api)
        added = api.send_command("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": source})
        if added.get("error"):
            print(f"   script add FAILED: {added['error']}")
            return False
        added = api.send_command("/system/scheduler/add", {
            "name": SCHEDULER_NAME, "interval": "1m", "start-time": "startup",
            "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY, "comment": COMMENT,
        })
        if added.get("error"):
            print(f"   scheduler add FAILED: {added['error']}")
            return False
        sid = [s for s in api.send_command("/system/script/print").get("data") or []
               if s.get("name") == SCRIPT_NAME][0][".id"]
        t0 = time.time()
        run = api.send_command("/system/script/run", {".id": sid})
        took = time.time() - t0
        env = {e.get("name"): e.get("value") for e in api.send_command("/system/script/environment/print").get("data") or []
               if str(e.get("name", "")).startswith("bwExp")}
        print(f"   installed; first run {took:.1f}s {run.get('error') or ''}")
        print(f"   state: {env}")
        return True
    finally:
        api.disconnect()


async def main():
    if not IDS:
        raise SystemExit("set ROUTER_IDS=1,2,3")
    routers, paid = await load()
    print(f"{'APPLY' if APPLY else 'DRY RUN'}{' UNINSTALL' if UNINSTALL else ''}: {[r['id'] for r in routers]}")
    for r in routers:
        ok = await asyncio.to_thread(install, r, paid.get(r["id"], {}))
        if ok and APPLY:
            await set_flag(r["id"], not UNINSTALL)
            print(f"   routers.expiry_reaper_enabled = {not UNINSTALL}")


if __name__ == "__main__":
    asyncio.run(main())

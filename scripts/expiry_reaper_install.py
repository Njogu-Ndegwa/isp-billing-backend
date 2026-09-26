"""Install / remove the router expiry reaper on pilot routers.

Run inside the app container (uses the app's DB models and RouterOS client):

    docker exec -e ROUTER_IDS=478,464 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py
    docker exec -e ROUTER_IDS=478,464 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py
    docker exec -e ROUTER_IDS=478 -e UNINSTALL=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/expiry_reaper_install.py

Without APPLY=1 it only reports what it would change. Skips RADIUS routers,
suspended/inactive owners, unreachable routers, RouterOS < 6.43, and small
boards with no route to the tunnel address (ALLOW_HTTPS=1 overrides). With
APPLY=1, per router:

1. NTP client on, if it is off (the reaper will not act on a clock the server
   has not confirmed, and a no-RTC board needs NTP to get one after a reboot).
2. EXP:<minute> added to the ip-binding comment of every customer who is
   ACTIVE with a future expiry (new payments get it from provisioning).
3. The reaper script + 1-minute scheduler (first run by the scheduler; the
   whole batch is verified after one shared wait).
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
# Small boards without a route to the tunnel address would call us over public
# HTTPS (5-7 s of full CPU per call on a hAP lite): skipped unless allowed.
ALLOW_HTTPS = os.environ.get("ALLOW_HTTPS") == "1"
ALLOW_BUSY = os.environ.get("ALLOW_BUSY") == "1"
WEAK_BOARDS = ("hAP lite", "hAP mini", "hAP ac lite", "cAP lite", "RB9", "RB750", "RB941", "RB931", "hEX lite", "mAP")
UNINSTALL = os.environ.get("UNINSTALL") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
NTP_SERVER = "162.159.200.1"
TUNNEL_SERVER_IP = "10.251.0.1"


async def load():
    async with async_session() as db:
        routers = (await db.execute(text(
            "select r.id, r.name, r.identity, r.ip_address, r.username, r.password, r.port, "
            "r.auth_method::text as auth_method, u.subscription_status::text as owner_status "
            "from routers r left join users u on u.id = r.user_id where r.id = any(:ids)"), {"ids": IDS})).mappings().all()
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


def _version_ok(version: str) -> bool:
    try:
        major, minor = (int(x) for x in version.split(" ")[0].split(".")[:2])
    except ValueError:
        return False
    return major >= 7 or (major == 6 and minor >= 43)   # fetch output=user as-value


def install(r, paid) -> str:
    """Returns "installed", "removed", "dry-run" or "skipped: <why>"."""
    if (r.get("auth_method") or "").upper() == "RADIUS":
        return "skipped: RADIUS router"
    if (r.get("owner_status") or "").lower() in ("suspended", "inactive"):
        return f"skipped: owner {r['owner_status']}"
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=60)
    if not api.connect():
        return "skipped: unreachable"
    try:
        ident = first(api, "/system/identity/print").get("name")
        if ident != r["identity"]:
            return f"skipped: identity mismatch router={ident} db={r['identity']}"
        res = first(api, "/system/resource/print")
        version, board, cpu = res.get("version", ""), res.get("board-name") or "", res.get("cpu-load")
        print(f"{r['id']} {r['name']}: {board} {version} cpu {cpu}%")
        pings = api.send_command("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"}).get("data") or []
        tunnel_ok = any(p.get("time") for p in pings)
        print(f"   reaches {TUNNEL_SERVER_IP}: {'yes' if tunnel_ok else 'NO (would use public HTTPS)'}")
        if UNINSTALL:
            if APPLY:
                remove_reaper(api)
            return "removed" if APPLY else "dry-run"
        if not _version_ok(version):
            return f"skipped: RouterOS {version} too old"
        # hAP lite (RB941, 32 MB, smips) is excluded (2026-09-26): 371 and 483
        # were pinned at 100% CPU with 5-7 MB free under the stack of Bitwave
        # schedulers; the server cleanup keeps enforcing expiry on them.
        model = (first(api, "/system/routerboard/print").get("model") or "")
        if any(k in f"{board} {model}".lower() for k in ("hap lite", "rb941", "hap mini", "rb931")):
            return f"skipped: small board {board or model} (hAP lite class excluded)"
        try:
            busy = int(cpu) >= 90
        except (TypeError, ValueError):
            busy = False
        if busy and not ALLOW_BUSY:
            return f"skipped: CPU at {cpu}% (set ALLOW_BUSY=1 to install anyway)"
        if not tunnel_ok and not ALLOW_HTTPS and any(w.lower() in board.lower() for w in WEAK_BOARDS):
            return f"skipped: {board} has no tunnel route (set ALLOW_HTTPS=1 to install anyway)"
        if api.send_command("/ip/hotspot/ip-binding/print").get("error"):
            return "skipped: no hotspot ip-binding table"
        print("   " + ensure_ntp(api, version))
        print("   " + tag_bindings(api, paid))
        if not APPLY:
            return "dry-run"
        rendered = render_expiry_reaper_script(
            identity=ident,
            tunnel_url=settings.EXPIRY_REAPER_TUNNEL_URL,
            public_url=settings.EXPIRY_REAPER_PUBLIC_URL,
        )
        remove_reaper(api)
        added = api.send_command("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": script_source(rendered)})
        if added.get("error"):
            return f"skipped: script add failed: {added['error']}"
        added = api.send_command("/system/scheduler/add", {
            "name": SCHEDULER_NAME, "interval": "1m", "start-time": "startup",
            "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY, "comment": COMMENT,
        })
        if added.get("error"):
            return f"skipped: scheduler add failed: {added['error']}"
        return "installed"
    finally:
        api.disconnect()


def verify(r) -> str:
    """State after the scheduler's first run. No manual run at install: a manual
    run plus the first scheduled run seconds later trips the endpoint's
    per-router rate limit (5-min back-off)."""
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=30)
    if not api.connect():
        return "unreachable at verify"
    try:
        env = {e.get("name"): e.get("value") for e in api.send_command("/system/script/environment/print").get("data") or []
               if str(e.get("name", "")).startswith("bwExp")}
    finally:
        api.disconnect()
    if env.get("bwExpClockOk") == "true" and env.get("bwExpRetryAt") in ("0", None):
        return "OK (clock confirmed)"
    return f"CHECK: clock_ok={env.get('bwExpClockOk')} retry_at={env.get('bwExpRetryAt')} beat={env.get('bwExpBeat')}"


async def main():
    if not IDS:
        raise SystemExit("set ROUTER_IDS=1,2,3")
    routers, paid = await load()
    print(f"{'APPLY' if APPLY else 'DRY RUN'}{' UNINSTALL' if UNINSTALL else ''}: {[r['id'] for r in routers]}")
    outcome = {}
    for r in routers:
        try:
            outcome[r["id"]] = await asyncio.to_thread(install, r, paid.get(r["id"], {}))
        except Exception as exc:
            outcome[r["id"]] = f"skipped: error {exc}"
        if outcome[r["id"]].startswith("skipped"):
            print(f"{r['id']} {r['name']}: {outcome[r['id']]}")
        if APPLY and outcome[r["id"]] in ("installed", "removed"):
            await set_flag(r["id"], not UNINSTALL)
    done = [r for r in routers if outcome.get(r["id"]) == "installed"]
    if done:
        print(f"waiting 75 s for the first scheduled run on {len(done)} router(s)...")
        time.sleep(75)
        for r in done:
            outcome[r["id"]] = "installed, " + await asyncio.to_thread(verify, r)
    print("SUMMARY")
    for r in routers:
        print(f"  {r['id']:>4} {r['name'][:28]:28} {outcome.get(r['id'])}")


if __name__ == "__main__":
    asyncio.run(main())

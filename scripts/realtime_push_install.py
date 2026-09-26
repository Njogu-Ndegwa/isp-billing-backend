"""Install / update the v2 real-time usage push on pilot routers.

Run inside the app container (it uses the app's DB models and RouterOS client):

    docker exec -e ROUTER_IDS=10,487 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py
    docker exec -e ROUTER_IDS=10,487 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py

Without APPLY=1 it only reports what it would do.

Transport per router: if the router's route to the server's tunnel address
(10.251.0.1) goes through an ENCRYPTED tunnel — WireGuard, L2TP with IPsec, or
SSTP — the report is posted as plain HTTP inside that tunnel
(settings.REALTIME_TUNNEL_PUSH_URL, port 8088). No TLS on the router: on a hAP lite an
HTTPS report cost ~5-7 s at 100% CPU, a tunnel HTTP request ~1-2 s. Otherwise
it falls back to the public HTTPS endpoint. While the tunnel is down no live
data arrives; usage is cumulative, so the next report catches up.

DB is read in one short session and released before any RouterOS I/O.
"""

import asyncio
import os
import time

from sqlalchemy import text

from app.config import settings
from app.db.database import async_session
from app.services.mikrotik_api import MikroTikAPI
from app.services.usage_push_script import SCHEDULER_NAME, SCRIPT_NAME, render_realtime_push_script

PUBLIC_URL = "https://isp.bitwavetechnologies.net/api/router/usage-push"
TUNNEL_SERVER_IP = "10.251.0.1"
POLICY = "read,write,test,policy"
COMMENT = "Bitwave usage reporting v2 (real-time)"
APPLY = os.environ.get("APPLY") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]


async def load_routers():
    async with async_session() as db:
        rows = (await db.execute(
            text("select id, name, identity, ip_address, username, password, port from routers where id = any(:ids)"),
            {"ids": IDS},
        )).mappings().all()
        await db.commit()
    return [dict(r) for r in rows]


def tunnel_interface(api):
    """Name + kind of the interface this router uses to reach TUNNEL_SERVER_IP, if encrypted."""
    routes = api.send_command("/ip/route/print").get("data", [])
    candidates = [
        r for r in routes
        if r.get("active") == "true" and r.get("dst-address", "") in (f"{TUNNEL_SERVER_IP}/32", "10.251.0.0/16")
    ]
    candidates.sort(key=lambda r: -int(r.get("dst-address", "0/0").split("/")[1]))
    if not candidates:
        return None, "no route"
    iface = (candidates[0].get("gateway") or "").split("%")[-1]
    if any(w.get("name") == iface for w in api.send_command("/interface/wireguard/print").get("data", []) or []):
        return iface, "wireguard"
    for l2tp in api.send_command("/interface/l2tp-client/print").get("data", []) or []:
        if l2tp.get("name") == iface:
            return (iface, "l2tp+ipsec") if l2tp.get("use-ipsec") == "true" else (None, "l2tp WITHOUT ipsec")
    if any(s.get("name") == iface for s in api.send_command("/interface/sstp-client/print").get("data", []) or []):
        return iface, "sstp"
    return None, f"unknown interface {iface}"


def install(r):
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=60)
    if not api.connect():
        print(f"{r['id']} {r['name']}: UNREACHABLE — not installed")
        return
    try:
        c = lambda p, a=None: api.send_command(p, a or {})
        ident = c("/system/identity/print")["data"][0]["name"]
        if ident != r["identity"]:
            print(f"{r['id']} {r['name']}: identity mismatch router={ident} db={r['identity']} — skipped")
            return
        iface, kind = tunnel_interface(api)
        ping_ok = bool([p for p in c("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"}).get("data", []) if p.get("time")])
        url = settings.REALTIME_TUNNEL_PUSH_URL if (iface and ping_ok) else PUBLIC_URL
        print(f"{r['id']} {r['name']}: tunnel={iface or '-'} ({kind}), ping={'ok' if ping_ok else 'fail'} -> {url}")
        if not APPLY:
            return
        rendered = render_realtime_push_script(identity=ident, endpoint_url=url, interval_seconds=10)
        source = rendered[rendered.index("source={\n") + len("source={\n"): rendered.index("\n}\n\n/system scheduler add")]
        scripts = [s for s in c("/system/script/print").get("data", []) if s.get("name") == SCRIPT_NAME]
        res = (c("/system/script/set", {".id": scripts[0][".id"], "source": source}) if scripts
               else c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": source}))
        if res.get("error"):
            print(f"   script: {res['error']}")
            return
        scheds = [s for s in c("/system/scheduler/print").get("data", []) if s.get("name") == SCHEDULER_NAME]
        res = (c("/system/scheduler/set", {".id": scheds[0][".id"], "disabled": "no", "comment": COMMENT}) if scheds
               else c("/system/scheduler/add", {"name": SCHEDULER_NAME, "interval": "30s", "start-time": "startup",
                                                "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY,
                                                "comment": COMMENT}))
        if res.get("error"):
            print(f"   scheduler: {res['error']}")
            return
        sid = [s for s in c("/system/script/print").get("data", []) if s.get("name") == SCRIPT_NAME][0][".id"]
        t0 = time.time()
        run = c("/system/script/run", {".id": sid})
        print(f"   installed; one report took {time.time() - t0:.1f}s {run.get('error') or ''}")
    finally:
        api.disconnect()


if __name__ == "__main__":
    if not IDS:
        raise SystemExit("set ROUTER_IDS=1,2,3")
    for router in asyncio.run(load_routers()):
        install(router)

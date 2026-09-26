"""Install / update / roll back the real-time usage push (v3) on routers.

Run inside the app container (it uses the app's DB models and RouterOS client):

    docker exec -e ROUTER_IDS=10,487 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py
    docker exec -e ROUTER_IDS=10,487 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py
    docker exec -e ROUTER_IDS=10 -e ROLLBACK=1 -i isp_billing_hetzner_app python - < scripts/realtime_push_install.py

Without APPLY=1 / ROLLBACK=1 it only reports what it would do. One JSON line
per router is printed after the human-readable lines (prefix "RESULT ").

Installing the v3 script is what puts a router on real-time push: the server
enrols any router sending v3 reports (realtime_state.note_realtime_report) and
hands it back to the poller ~15 min after they stop. So a rollback is just
restoring the router's previous script, which install keeps on the router as
``bitwave-usage-push-prev``.

Transport per router: if the router's route to the server's tunnel address
(10.251.0.1) goes through an ENCRYPTED tunnel — WireGuard, L2TP with IPsec, or
SSTP — the report is posted as plain HTTP inside that tunnel
(settings.REALTIME_TUNNEL_PUSH_URL, port 8088). No TLS on the router: on a hAP
lite an HTTPS report cost ~5-7 s at 100% CPU, a tunnel HTTP request ~1-2 s.
Otherwise it falls back to the public HTTPS endpoint — except on the smallest
boards (smips: hAP lite/mini), which are skipped unless FORCE_HTTPS=1.

WAN: the interface of the active default route (ether1 is only the fallback),
so routers with a renamed or PPPoE/LTE uplink still report bandwidth.

DB is read in one short session and released before any RouterOS I/O.
"""

import asyncio
import json
import os
import re
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
BACKUP_NAME = f"{SCRIPT_NAME}-prev"
SMALL_ARCHITECTURES = {"smips"}          # hAP lite / hAP mini: 650 MHz single core
APPLY = os.environ.get("APPLY") == "1"
ROLLBACK = os.environ.get("ROLLBACK") == "1"
FORCE_HTTPS = os.environ.get("FORCE_HTTPS") == "1"
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


def _data(res):
    return (res or {}).get("data") or []


def tunnel_interface(api):
    """Name + kind of the interface this router uses to reach TUNNEL_SERVER_IP, if encrypted."""
    routes = _data(api.send_command("/ip/route/print"))
    candidates = [
        r for r in routes
        if r.get("active") == "true" and r.get("dst-address", "") in (f"{TUNNEL_SERVER_IP}/32", "10.251.0.0/16")
    ]
    candidates.sort(key=lambda r: -int(r.get("dst-address", "0/0").split("/")[1]))
    if not candidates:
        return None, "no route"
    iface = (candidates[0].get("gateway") or "").split("%")[-1]
    if any(w.get("name") == iface for w in _data(api.send_command("/interface/wireguard/print"))):
        return iface, "wireguard"
    for l2tp in _data(api.send_command("/interface/l2tp-client/print")):
        if l2tp.get("name") == iface:
            return (iface, "l2tp+ipsec") if l2tp.get("use-ipsec") == "true" else (None, "l2tp WITHOUT ipsec")
    if any(s.get("name") == iface for s in _data(api.send_command("/interface/sstp-client/print"))):
        return iface, "sstp"
    return None, f"unknown interface {iface}"


def wan_interface(api, interface_names):
    """Interface of the active default route; ether1 (or the first ether) if unclear."""
    for route in _data(api.send_command("/ip/route/print")):
        if route.get("dst-address") != "0.0.0.0/0" or route.get("active") != "true":
            continue
        # ROS 7: immediate-gw "192.168.1.1%ether1"; ROS 6: gateway-status
        # "192.168.1.1 reachable via  ether1" or "pppoe-out1 reachable".
        candidates = [(route.get("immediate-gw") or "").split("%")[-1]]
        status = route.get("gateway-status") or ""
        m = re.search(r"via\s+(\S+)", status)
        if m:
            candidates.append(m.group(1))
        candidates.append(status.split(" ")[0])
        candidates.append((route.get("gateway") or "").split("%")[-1])
        for name in candidates:
            if name in interface_names:
                return name
    if "ether1" in interface_names:
        return "ether1"
    ethers = sorted(n for n in interface_names if n.startswith("ether"))
    return ethers[0] if ethers else "ether1"


def cpu_samples(api, n=3):
    out = []
    for _ in range(n):
        res = _data(api.send_command("/system/resource/print"))
        if res:
            try:
                out.append(int(res[0].get("cpu-load") or 0))
            except ValueError:
                pass
        time.sleep(1)
    return out


def recent_push_log(api):
    lines = [
        f"{row.get('time', '')} {row.get('message', '')}"
        for row in _data(api.send_command("/log/print"))
        if "usage-push" in (row.get("message") or "")
    ]
    return lines[-4:]


def find_one(api, path, name):
    rows = [r for r in _data(api.send_command(f"{path}/print")) if r.get("name") == name]
    return rows[0] if rows else None


def rollback(api, r, result, current):
    c = lambda p, a=None: api.send_command(p, a or {})
    backup = find_one(api, "/system/script", BACKUP_NAME)
    sched = find_one(api, "/system/scheduler", SCHEDULER_NAME)
    if backup and backup.get("source"):
        if current:
            c("/system/script/set", {".id": current[".id"], "source": backup["source"]})
        else:
            c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": backup["source"]})
        if sched:
            c("/system/scheduler/set", {".id": sched[".id"], "interval": "2m", "comment": "Bitwave usage reporting"})
        print(f"{r['id']} {r['name']}: rolled back to the previous script")
        return {**result, "status": "rolled_back_to_prev"}
    if sched:
        c("/system/scheduler/remove", {".id": sched[".id"]})
    if current:
        c("/system/script/remove", {".id": current[".id"]})
    print(f"{r['id']} {r['name']}: no previous script — push removed")
    return {**result, "status": "removed"}


def install(r):
    result = {"id": r["id"], "name": r["name"],
              "action": "rollback" if ROLLBACK else ("install" if APPLY else "dry-run")}
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728, timeout=60)
    if not api.connect():
        print(f"{r['id']} {r['name']}: UNREACHABLE — nothing done")
        return {**result, "status": "unreachable"}
    try:
        c = lambda p, a=None: api.send_command(p, a or {})
        ident = _data(c("/system/identity/print"))[0]["name"]
        if ident != r["identity"]:
            print(f"{r['id']} {r['name']}: identity mismatch router={ident} db={r['identity']} — skipped")
            return {**result, "status": "identity_mismatch"}
        res = _data(c("/system/resource/print"))[0]
        arch = res.get("architecture-name", "")
        result.update(board=res.get("board-name"), arch=arch, ros=res.get("version"),
                      free_hdd=int(res.get("free-hdd-space") or 0))
        current = find_one(api, "/system/script", SCRIPT_NAME)
        current_src = (current or {}).get("source") or ""
        result["had_script"] = "v3" if '\\"v\\":3' in current_src else ("v1/v2" if current else "none")

        if ROLLBACK:
            return rollback(api, r, result, current)

        iface, kind = tunnel_interface(api)
        ping_ok = bool([p for p in _data(c("/ping", {"address": TUNNEL_SERVER_IP, "count": "2"})) if p.get("time")])
        via_tunnel = bool(iface and ping_ok)
        url = settings.REALTIME_TUNNEL_PUSH_URL if via_tunnel else PUBLIC_URL
        names = {i.get("name") for i in _data(c("/interface/print"))}
        wan = wan_interface(api, names)
        small = arch in SMALL_ARCHITECTURES
        lists_every = 10 if small else 5
        result.update(tunnel=iface or None, tunnel_kind=kind, via_tunnel=via_tunnel, wan=wan,
                      lists_every=lists_every)
        print(f"{r['id']} {r['name']}: {res.get('board-name')} ({arch}) ROS {res.get('version')} "
              f"tunnel={iface or '-'} ({kind}) ping={'ok' if ping_ok else 'fail'} wan={wan} "
              f"lists_every={lists_every} had={result['had_script']} -> {url}")
        if small and not via_tunnel and not FORCE_HTTPS:
            print("   SKIPPED: smallest board with no working encrypted tunnel (HTTPS too heavy)")
            return {**result, "status": "skipped_small_https"}
        result["cpu_before"] = cpu_samples(api)
        if not APPLY:
            return {**result, "status": "would_install"}

        rendered = render_realtime_push_script(identity=ident, endpoint_url=url, interval_seconds=60,
                                               wan_interface=wan, lists_every=lists_every)
        source = rendered[rendered.index("source={\n") + len("source={\n"): rendered.index("\n}\n\n/system scheduler add")]
        if current and result["had_script"] != "v3":
            backup = find_one(api, "/system/script", BACKUP_NAME)
            res_b = (c("/system/script/set", {".id": backup[".id"], "source": current_src}) if backup
                     else c("/system/script/add", {"name": BACKUP_NAME, "policy": POLICY, "source": current_src}))
            if res_b.get("error"):
                print(f"   backup of the previous script failed: {res_b['error']} — not installed")
                return {**result, "status": "backup_failed"}
        res_s = (c("/system/script/set", {".id": current[".id"], "source": source}) if current
                 else c("/system/script/add", {"name": SCRIPT_NAME, "policy": POLICY, "source": source}))
        if res_s.get("error"):
            print(f"   script: {res_s['error']}")
            return {**result, "status": "script_failed", "error": str(res_s["error"])[:200]}
        sched = find_one(api, "/system/scheduler", SCHEDULER_NAME)
        res_c = (c("/system/scheduler/set", {".id": sched[".id"], "disabled": "no", "interval": "60s",
                                             "comment": COMMENT})
                 if sched else
                 c("/system/scheduler/add", {"name": SCHEDULER_NAME, "interval": "60s", "start-time": "startup",
                                             "on-event": f"/system script run {SCRIPT_NAME}", "policy": POLICY,
                                             "comment": COMMENT}))
        if res_c.get("error"):
            print(f"   scheduler: {res_c['error']}")
            return {**result, "status": "scheduler_failed", "error": str(res_c["error"])[:200]}
        sid = find_one(api, "/system/script", SCRIPT_NAME)[".id"]
        t0 = time.time()
        run = c("/system/script/run", {".id": sid})
        result["first_run_seconds"] = round(time.time() - t0, 1)
        result["log"] = recent_push_log(api)
        bad = [line for line in result["log"][-1:] if "deferred" in line or "skipped" in line]
        print(f"   installed; one report took {result['first_run_seconds']}s {run.get('error') or ''}")
        for line in result["log"]:
            print(f"   log: {line}")
        return {**result, "status": "installed_check_log" if bad else "installed"}
    except Exception as exc:
        print(f"{r['id']} {r['name']}: ERROR {exc}")
        return {**result, "status": "error", "error": str(exc)[:200]}
    finally:
        api.disconnect()


if __name__ == "__main__":
    if not IDS:
        raise SystemExit("set ROUTER_IDS=1,2,3")
    for router in asyncio.run(load_routers()):
        print("RESULT " + json.dumps(install(router)), flush=True)

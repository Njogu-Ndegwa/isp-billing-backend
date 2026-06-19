#!/usr/bin/env python3
"""
Read-only captive-portal / hotspot diagnostic for an already-provisioned router.

Runs INSIDE the isp_billing_app container on the production server, reusing the
app's own RouterOS API client. It NEVER writes to the router. It reads the
router's credentials in one short DB section, releases the session, then does
all RouterOS I/O (see AGENTS.md "Database Session Discipline").

Usage (from your workstation):
    ssh -o BatchMode=yes dennis@54.91.202.229 \
        "docker exec -e ROUTER_ID=<id> -i isp_billing_app python -" < diagnose_router.py

Env:
    ROUTER_ID    (required) numeric routers.id of the router to diagnose

File-completeness is checked against a built-in expected set (EXPECTED_HTML_FILES). A live
baseline-router file diff is not implemented yet.

Output: one JSON object with `report` (raw facts) and `findings` (auto-flagged
issues with severity + a SUGGESTED fix). Suggested fixes are NEVER applied here.
"""
import os, json, asyncio

# Full hotspot html file set a healthy router carries (from known-good RB951 id 207).
EXPECTED_HTML_FILES = {
    "login.html","redirect.html","alogin.html","rlogin.html","logout.html","status.html",
    "error.html","errors.txt","radvert.html","api.json","md5.js","favicon.ico","css/style.css",
    "img/user.svg","img/password.svg","xml/WISPAccessGatewayParam.xsd","xml/alogin.html",
    "xml/error.html","xml/flogout.html","xml/login.html","xml/logout.html","xml/rlogin.html",
}
STANDARD_TOP_DIRS = {"hotspot", "flash", "pub", "skins"}  # anything else may be leftover


def subnet24(ip):
    return ".".join((ip or "").split("/")[0].split(".")[:3])


async def load_creds(rid):
    from app.db.database import async_session, async_engine
    from app.db.models import Router
    async with async_session() as db:
        r = await db.get(Router, int(rid))
        info = None if not r else {
            "id": r.id, "name": r.name, "identity": r.identity,
            "ip": r.ip_address, "user": r.username, "pw": r.password, "port": r.port or 8728,
        }
        await db.commit()
    await async_engine.dispose()
    return info


def diagnose(info, baseline_files):
    from app.services.mikrotik_api import MikroTikAPI
    api = MikroTikAPI(info["ip"], info["user"], info["pw"], info["port"], timeout=20, connect_timeout=8)
    if not api.connect():
        return {"_connect_error": api.last_connect_error}, [
            {"code": "UNREACHABLE", "severity": "blocker",
             "detail": api.last_connect_error,
             "suggested_fix": "Router not reachable over the WireGuard tunnel. Check it is online "
                              "(WAN up). WAN-down => mgmt tunnel down; access locally via Winbox."}]

    def sc(cmd, opt=None):
        r = api.send_command_optimized(cmd, proplist=opt) if opt else api.send_command(cmd)
        return r.get("data", []) if r.get("success") else {"error": r.get("error")}

    rep, find = {}, []
    try:
        rep["resource"] = sc("/system/resource/print", ["version","board-name","architecture-name","uptime"])
        ver = (rep["resource"][0].get("version","") if rep["resource"] else "")
        board = (rep["resource"][0].get("board-name","") if rep["resource"] else "")

        servers = sc("/ip/hotspot/print", ["name","interface","profile","address-pool","disabled","invalid"])
        rep["hotspot_servers"] = servers
        active = next((s for s in servers if isinstance(s, dict) and s.get("disabled") != "true"), None) \
                 if isinstance(servers, list) else None
        if not active:
            find.append({"code": "NO_HOTSPOT_SERVER", "severity": "blocker",
                         "detail": "No enabled hotspot server found.",
                         "suggested_fix": "Re-run provisioning / check the hotspot package is installed."})
        if isinstance(active, dict) and active.get("invalid") == "true":
            find.append({"code": "HOTSPOT_INVALID", "severity": "blocker",
                         "detail": f"Hotspot server {active.get('name')} is invalid.",
                         "suggested_fix": "Check interface/profile/address-pool exist."})

        profs = sc("/ip/hotspot/profile/print", ["name","html-directory","hotspot-address","login-by"])
        rep["profiles"] = profs
        prof = None
        if isinstance(active, dict) and isinstance(profs, list):
            prof = next((p for p in profs if p.get("name") == active.get("profile")), None)
        html_dir = prof.get("html-directory") if prof else None
        hs_addr = prof.get("hotspot-address") if prof else None
        rep["active_profile"] = (prof.get("name") if prof else None)
        rep["active_html_directory"] = html_dir

        # ---- files under the active html-directory ----
        allfiles = sc("/file/print", ["name","type","size"])
        if isinstance(allfiles, list):
            top_dirs = sorted({f["name"] for f in allfiles
                               if f.get("type") == "directory" and "/" not in f.get("name","").rstrip("/")})
            rep["top_dirs"] = top_dirs
            leftover = [d for d in top_dirs if d not in STANDARD_TOP_DIRS]
            # 'billing' or other non-standard dirs => likely previous-provider leftover
            if any(d not in STANDARD_TOP_DIRS for d in top_dirs) or any("billing" in d for d in top_dirs):
                find.append({"code": "POSSIBLE_LEFTOVER_CONFIG", "severity": "info",
                             "detail": f"Non-standard top dirs: {leftover}. Possible previous-provider config.",
                             "suggested_fix": "Do NOT serve hotspot files from these. Verify clean factory base."})

            if html_dir:
                pre = html_dir + "/"
                present = {f["name"][len(pre):]: f.get("size") for f in allfiles
                           if f.get("name","").startswith(pre) and f.get("type") != "directory"}
                rep["html_dir_file_count"] = len(present)
                rep["html_dir_files"] = dict(sorted(present.items()))
                empty = sorted([n for n, s in present.items() if str(s) in ("0", "")])
                rep["html_dir_empty_files"] = empty
                missing = sorted(EXPECTED_HTML_FILES - set(present.keys()))
                rep["html_dir_missing_vs_baseline"] = missing
                essential = {"login.html","redirect.html","errors.txt","alogin.html","error.html"}
                missing_essential = sorted(essential - set(present.keys()))
                if len(present) <= 2 or missing_essential:
                    find.append({"code": "INCOMPLETE_HTML_DIR", "severity": "blocker",
                                 "detail": f"html-directory '{html_dir}' has {len(present)} file(s); "
                                           f"missing essential: {missing_essential or 'none'}. "
                                           f"Provisioning didn't populate the default hotspot files "
                                           f"(reset-html-directory step skipped/failed) — seen on RouterOS 7.18 and 7.23+.",
                                 "suggested_fix": "Copy a known-good router's hotspot files into this dir via "
                                                  "/file/add (per-file text; skip binaries; ~4KB API read cap). "
                                                  "Keep the correct login.html."})
                elif empty:
                    find.append({"code": "EMPTY_HTML_FILES", "severity": "warning",
                                 "detail": f"Empty (0-byte) files in html-directory: {empty}.",
                                 "suggested_fix": "Re-copy these from a known-good router (text files only)."})

        # ---- login.html target (small file -> readable) ----
        if html_dir:
            lc = sc("/file/print", None) if False else api.send_command_optimized(
                "/file/print", proplist=["name","contents"], query=f"?name={html_dir}/login.html")
            rows = lc.get("data", []) if lc.get("success") else []
            content = rows[0].get("contents","") if rows else ""
            rep["login_html_is_vercel_portal"] = "isp-frontend-two.vercel.app" in content
            rep["login_html_len"] = len(content)
            if content and "isp-frontend-two.vercel.app" not in content:
                find.append({"code": "WRONG_LOGIN_PAGE", "severity": "warning",
                             "detail": "login.html does not point to the Bitwave Vercel portal.",
                             "suggested_fix": "Re-fetch the correct login page from /api/provision/<token>/login-page."})

        # ---- DHCP / subnet alignment ----
        pools = sc("/ip/pool/print", ["name","ranges"])
        dhcp_srv = sc("/ip/dhcp-server/print", ["name","interface","address-pool","disabled"])
        dhcp_net = sc("/ip/dhcp-server/network/print", ["address","gateway","dns-server"])
        rep["pools"] = pools; rep["dhcp_server"] = dhcp_srv; rep["dhcp_network"] = dhcp_net
        pool_map = {p["name"]: p.get("ranges","") for p in pools} if isinstance(pools, list) else {}
        if isinstance(dhcp_srv, list) and dhcp_srv and hs_addr:
            srv_pool = dhcp_srv[0].get("address-pool")
            srv_range = pool_map.get(srv_pool, "")
            srv_subnet = subnet24(srv_range.split("-")[0]) if srv_range else ""
            hs_subnet = subnet24(hs_addr)
            net_subnets = {subnet24(n.get("address","")) for n in dhcp_net} if isinstance(dhcp_net, list) else set()
            rep["dhcp_subnet_check"] = {"server_pool": srv_pool, "server_subnet": srv_subnet,
                                        "hotspot_subnet": hs_subnet, "dhcp_network_subnets": sorted(net_subnets)}
            if srv_subnet and hs_subnet and srv_subnet != hs_subnet:
                find.append({"code": "DHCP_SUBNET_MISMATCH", "severity": "blocker",
                             "detail": f"DHCP server hands out {srv_subnet}.x (pool '{srv_pool}') but the hotspot "
                                       f"is on {hs_subnet}.1. Clients land on the wrong subnet / no gateway.",
                             "suggested_fix": f"/ip pool set [find name={srv_pool}] "
                                              f"ranges={hs_subnet}.10-{hs_subnet}.254  (then remove stray addresses)."})
            elif srv_subnet and srv_subnet not in net_subnets:
                find.append({"code": "DHCP_NO_MATCHING_NETWORK", "severity": "blocker",
                             "detail": f"DHCP pool subnet {srv_subnet}.x has no matching /ip dhcp-server/network "
                                       f"(networks: {sorted(net_subnets)}); clients get no gateway/DNS.",
                             "suggested_fix": "Align the pool to a subnet that has a dhcp-network entry."})

        # ---- bridge addresses (flag non-88.x leftovers) ----
        addrs = sc("/ip/address/print", ["address","interface","dynamic"])
        rep["bridge_addresses"] = [a.get("address") for a in addrs
                                   if isinstance(a, dict) and a.get("interface") == "bridge"] if isinstance(addrs, list) else addrs
        if isinstance(addrs, list):
            stray = [a.get("address") for a in addrs if a.get("interface") == "bridge"
                     and a.get("dynamic") != "true" and subnet24(a.get("address","")) not in ("192.168.88",)]
            if stray:
                find.append({"code": "STRAY_LAN_ADDRESS", "severity": "warning",
                             "detail": f"Non-standard static bridge address(es): {stray} (expected 192.168.88.1/24).",
                             "suggested_fix": "Remove the stray address(es) once DHCP is aligned to 192.168.88.x."})

        # ---- NAT redirect + walled garden presence ----
        nat = sc("/ip/firewall/nat/print")
        if isinstance(nat, list):
            has_redirect = any(n.get("chain","").startswith(("hotspot","hs-")) for n in nat)
            rep["hotspot_nat_present"] = has_redirect
            if not has_redirect:
                find.append({"code": "NO_HOTSPOT_NAT", "severity": "blocker",
                             "detail": "No hotspot NAT redirect chain present.",
                             "suggested_fix": "Hotspot not fully set up; re-run provisioning."})
        wg = sc("/ip/hotspot/walled-garden/print", ["dst-host","action","disabled"])
        if isinstance(wg, list):
            hosts = {w.get("dst-host","") for w in wg}
            rep["walled_garden_hosts"] = sorted(h for h in hosts if h)
            if not any("vercel" in h for h in hosts):
                find.append({"code": "WALLED_GARDEN_MISSING_PORTAL", "severity": "warning",
                             "detail": "Walled-garden has no *.vercel.app entry; clients can't reach the portal.",
                             "suggested_fix": "Add walled-garden allow for isp-frontend-two.vercel.app + *.vercel.app."})

        # ---- live client / link state ----
        ifaces = sc("/interface/print", ["name","type","running","disabled"])
        hosts_t = sc("/ip/hotspot/host/print", ["mac-address","authorized"])
        active_t = sc("/ip/hotspot/active/print", ["user"])
        rep["hotspot_hosts"] = len(hosts_t) if isinstance(hosts_t, list) else hosts_t
        rep["hotspot_active"] = len(active_t) if isinstance(active_t, list) else active_t
        if isinstance(ifaces, list):
            lan_up = [i["name"] for i in ifaces if i.get("type") in ("ether","wlan")
                      and i.get("name") != "ether1" and i.get("running") == "true"]
            wlan = [i for i in ifaces if i.get("type") == "wlan"]
            rep["lan_interfaces_up"] = lan_up
            rep["wlan_running"] = (wlan[0].get("running") if wlan else "n/a")
            if not lan_up and (not isinstance(hosts_t, list) or len(hosts_t) == 0):
                find.append({"code": "NO_CLIENTS_REACHING_HOTSPOT", "severity": "warning",
                             "detail": "No LAN port up, no hotspot hosts. Either the AP is disconnected/off, "
                                       "or (on hEX with no radio) the external AP isn't connected.",
                             "suggested_fix": "Confirm the AP is powered + cabled into a bridged ether port, "
                                              "or that built-in wlan1 is running if customers use it."})
        return rep, find
    finally:
        api.disconnect()


async def main():
    rid = os.environ.get("ROUTER_ID")
    if not rid:
        print(json.dumps({"error": "set ROUTER_ID env var"})); return
    info = await load_creds(rid)
    if not info:
        print(json.dumps({"error": f"router id {rid} not found in DB"})); return
    baseline_files = None  # reserved for future live-baseline diff
    rep, find = diagnose(info, baseline_files)
    out = {"router": {k: info[k] for k in ("id","name","identity","ip")},
           "findings": find, "report": rep}
    print(json.dumps(out, indent=1, default=str))

asyncio.run(main())

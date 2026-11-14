"""Upgrade the check-in applier already on routers to v3 (router actions) and
install ``bitwave-heal-tunnel`` next to it, or roll that back.

v3 (app/services/checkin_applier_script.py, ``actions=True``) lets the server
hand a router a fixed action on its next check-in: restart, repair the
management tunnel, add/remove access-credential users
(app/services/router_checkin_actions.py). It is what lets a router whose
tunnel is dead still be restarted or get its credentials.

HOW ROUTERS GET IT. The applier is fixed code that never fetches or imports
anything (no /import, :parse or :execute), so the check-in channel itself can
NOT carry a new script. The only way onto a router is the RouterOS API over
the management tunnel, i.e. this script. A router whose tunnel is down today
cannot be upgraded until the tunnel comes back (or someone pastes it in on
site). New installs keep getting v2 until CHECKIN_APPLIER_ACTIONS is turned on
after the canary.

Run inside the app container. Dry run (reports only) unless APPLY=1:

    # canary: one WireGuard RouterOS 7 router, one SSTP/RouterOS 6 router
    docker exec -e ROUTER_IDS=118,A -i isp_billing_hetzner_app python - < scripts/checkin_actions_rollout.py
    docker exec -e ROUTER_IDS=118,A -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/checkin_actions_rollout.py
    # watch them for a day (CPU, "checkin:" log lines, check-ins still answered), then
    # batches of 20 over online routers that have the applier
    docker exec -e ALL_CHECKIN=1 -e MAX_UPDATES=20 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/checkin_actions_rollout.py
    # undo on some routers (back to v2, heal script removed)
    docker exec -e ROUTER_IDS=118 -e ROLLBACK=1 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/checkin_actions_rollout.py

Only routers that ALREADY run ``bitwave-checkin`` are touched. The new source
keeps what the router's current one uses (identity, endpoint, certificate
check, tunnel transport); the identity in it must match the router's live
identity or the router is skipped. A paused (disabled) check-in scheduler is
left paused. Nothing is run, nothing rebooted. Routers already current are
reported "unchanged" and cost a few reads, so re-running the same command is
how the next batch goes out. SKIP_IDS=1,2 leaves routers out. A failure stops
the batch.

Routers are read in one short DB session released before any RouterOS I/O;
nothing is written to the DB.
"""

import asyncio
import json
import os
import re
import time

from sqlalchemy import text

from app.db.database import async_session
from app.services import checkin_applier_script as applier
from app.services.checkin_tunnel_transport import BEGIN as TUNNEL_BEGIN
from app.services.mgmt_watchdog_script import detect_kind
from app.services.mikrotik_api import MikroTikAPI

APPLY = os.environ.get("APPLY") == "1"
ROLLBACK = os.environ.get("ROLLBACK") == "1"
ALL_CHECKIN = os.environ.get("ALL_CHECKIN") == "1"
MAX_UPDATES = int(os.environ.get("MAX_UPDATES") or 0)     # 0 = no limit
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
SKIP = {int(x) for x in os.environ.get("SKIP_IDS", "").split(",") if x.strip().isdigit()}


async def load():
    where = ("r.last_status is true and r.checkin_installed_at is not null"
             if ALL_CHECKIN else "r.id = any(:ids)")
    async with async_session() as db:
        rows = (await db.execute(text(
            "select r.id, r.name, r.ip_address, r.username, r.password, r.port "
            f"from routers r where {where} order by r.id"), {"ids": IDS})).mappings().all()
        await db.commit()
    return [dict(r) for r in rows if r["id"] not in SKIP]


def current_params(source: str) -> dict:
    """What the router's current applier uses, read from its own source."""
    def one(pattern):
        m = re.search(pattern, source)
        return m.group(1) if m else None

    params = {
        "identity": one(r':local ident "([A-Za-z0-9._-]{1,64})"'),
        "endpoint_url": one(r':local url "(https?://[A-Za-z0-9._:/-]{3,200})"'),
        "check_certificate": one(r"check-certificate=(no|yes-without-crl|yes) ") or "no",
        "tunnel_endpoint_url": None,
    }
    if TUNNEL_BEGIN in source:
        params["tunnel_endpoint_url"] = one(re.escape(TUNNEL_BEGIN) + r" (\S+)")
    return params


def _first(api, path):
    return ((api.send_command(path) or {}).get("data") or [{}])[0]


def upgrade_router(r, apply: bool, rollback: bool) -> dict:
    out = {"router_id": r["id"], "name": r["name"]}
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728,
                      timeout=30, connect_timeout=5)
    if not api.connect():
        out["status"] = "unreachable"
        out["error"] = (api.last_connect_error or "")[:120]
        return out
    try:
        res = _first(api, "/system/resource/print")
        version = str(res.get("version", "")).split(" ")[0]
        out["version"] = version
        live_identity = str(_first(api, "/system/identity/print").get("name", "")).strip()
        scripts = applier._named(api, "/system/script", applier.SCRIPT_NAME)
        if not scripts:
            out["status"] = "no_checkin"
            return out
        params = current_params(scripts[0].get("source") or "")
        if not params["identity"] or not params["endpoint_url"]:
            out["status"] = "failed"
            out["error"] = "could not read identity/endpoint from the current applier"
            return out
        if params["identity"] != live_identity:
            out["status"] = "skipped"
            out["error"] = f"applier identity {params['identity']!r} != router identity {live_identity!r}"
            return out
        want_actions = not rollback
        wanted = applier.render_checkin_applier_source(actions=want_actions, **params)
        wanted_policy = applier.POLICY_ACTIONS if want_actions else applier.POLICY
        kind, kind_reason = detect_kind(api, version)
        heal_rows = applier._named(api, "/system/script", applier.HEAL_SCRIPT_NAME)
        heal_ok = (not want_actions and not heal_rows) or (
            want_actions and (kind is None or (
                heal_rows and heal_rows[0].get("source") == applier.render_heal_tunnel_source(kind))))
        current = (scripts[0].get("source") == wanted
                   and applier.same_policy(scripts[0].get("policy"), wanted_policy))
        out["tunnel_kind"] = kind or f"none ({kind_reason})"
        if current and heal_ok:
            out["status"] = "unchanged"
            return out
        if not apply:
            out["status"] = "would_rollback" if rollback else "would_update"
            return out
        result = applier.install_checkin_applier(api, actions=want_actions, **params)
        out["applier"] = result.get("status")
        if result.get("status") == "scheduler_disabled":
            out["status"] = "scheduler_paused"
            return out
        if result.get("status") not in ("installed", "updated", "unchanged"):
            out["status"] = "failed"
            out["error"] = result.get("error")
            return out
        if want_actions and kind:
            heal = applier.install_heal_tunnel(api, kind)
            out["heal"] = heal.get("status")
            if heal.get("status") == "script_failed":
                out["status"] = "failed"
                out["error"] = heal.get("error")
                return out
        elif not want_actions:
            applier.uninstall_heal_tunnel(api)
            out["heal"] = "removed"
        live = applier._named(api, "/system/script", applier.SCRIPT_NAME)
        out["status"] = ("rolled_back" if rollback else "updated") if (
            live and live[0].get("source") == wanted) else "verify_failed"
    except Exception as exc:  # one bad router must not stop the batch
        out["status"] = "error"
        out["error"] = str(exc)[:160]
    finally:
        api.disconnect()
    return out


def main():
    if not IDS and not ALL_CHECKIN:
        raise SystemExit("set ROUTER_IDS=1,2,3 or ALL_CHECKIN=1")
    routers = asyncio.run(load())
    print(f"{len(routers)} router(s), APPLY={APPLY}, ROLLBACK={ROLLBACK}, MAX_UPDATES={MAX_UPDATES or '-'}")
    totals: dict[str, int] = {}
    updates = 0
    for r in routers:
        if MAX_UPDATES and updates >= MAX_UPDATES:
            print(f"STOP reached MAX_UPDATES={MAX_UPDATES}; re-run for the next batch")
            break
        started = time.monotonic()
        result = upgrade_router(r, APPLY, ROLLBACK)
        result["seconds"] = round(time.monotonic() - started, 1)
        if result["status"] in ("updated", "would_update", "rolled_back", "would_rollback"):
            updates += 1
        key = result["status"]
        if result.get("version"):
            key += f" ros{result['version'].split('.')[0]}"
        totals[key] = totals.get(key, 0) + 1
        print("RESULT " + json.dumps(result))
        if result["status"] in ("failed", "verify_failed", "error"):
            print("STOP a router failed; fix it before the next batch")
            break
    print("TOTALS " + json.dumps(totals))


if __name__ == "__main__":
    main()

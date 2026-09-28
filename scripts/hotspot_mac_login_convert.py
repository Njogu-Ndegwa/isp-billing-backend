"""Convert one router's paid hotspot customers to MAC login, or back.

Runs inside the app container (it reuses the app's DB models and RouterOS
client). Read-only unless MODE=apply or MODE=revert.

    ssh root@<prod> "docker exec -e ROUTER_ID=10 -e MODE=dry-run \
        -i isp_billing_hetzner_app python -" < scripts/hotspot_mac_login_convert.py

MODE=dry-run  (default) show the router's current state and what apply would do
MODE=apply    enable login-by=mac + the FastTrack exemption, make every paid
              customer a MAC-login user (removing its bypass binding and static
              plan_ queue), then drop already-FastTracked connections once.
              Requires ROUTER_ID in HOTSPOT_MAC_LOGIN_ROUTER_IDS of the running
              app: otherwise the check-in would re-add bypass bindings.
ONLY_MACS     optional comma list: apply/revert/dry-run only these MACs (a canary
              device first, then everyone). The revert's "remove every
              MAC-login user" sweep only runs without ONLY_MACS.
MODE=revert   put every paid customer back on a bypass binding + plan_ queue,
              delete every MAC-login user and take "mac" out of login-by. A full
              revert requires ROUTER_ID to be REMOVED from
              HOTSPOT_MAC_LOGIN_ROUTER_IDS first (else new payments keep making
              MAC-login users that can no longer log in). A canary revert
              (ONLY_MACS) is allowed while listed: the reconcile leaves a
              customer that is back on bypass alone. The FastTrack exemption
              stays (it only helps the static queues).

Each device drops for a few seconds while it is switched over.
"""

import asyncio
import json
import os
from collections import Counter
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.database import async_engine, async_session
from app.db.models import ConnectionType, Customer, CustomerStatus, Plan, Router
from app.services import hotspot_mac_login as ml
from app.services.mikrotik_api import MikroTikAPI, normalize_mac_address

ROUTER_ID = int(os.environ["ROUTER_ID"])
MODE = os.environ.get("MODE", "dry-run").strip().lower()
ONLY_MACS = {
    normalize_mac_address(m) for m in os.environ.get("ONLY_MACS", "").split(",") if m.strip()
}


def out(title, data=None):
    print(f"== {title}" + ("" if data is None else f": {json.dumps(data, default=str)}"), flush=True)


async def load():
    now = datetime.utcnow()
    async with async_session() as db:
        router = await db.get(Router, ROUTER_ID)
        if router is None:
            raise SystemExit(f"router {ROUTER_ID} not found")
        info = {
            "id": router.id, "name": router.name, "ip": router.ip_address,
            "username": router.username, "password": router.password, "port": router.port,
        }
        rows = (await db.execute(
            select(Customer)
            .join(Plan, Customer.plan_id == Plan.id)
            .where(
                Customer.router_id == ROUTER_ID,
                Customer.status == CustomerStatus.ACTIVE,
                Customer.mac_address.isnot(None),
                Customer.expiry > now,
                Plan.connection_type == ConnectionType.HOTSPOT,
            )
            .options(selectinload(Customer.plan))
        )).scalars().all()
        customers = [{
            "id": c.id, "name": c.name, "mac_address": normalize_mac_address(c.mac_address),
            "plan_speed": c.plan.speed, "expiry": c.expiry,
        } for c in rows]
        await db.commit()
    await async_engine.dispose()
    return info, customers


def data(res):
    return (res.get("data") or []) if res.get("success") else []


def snapshot(api):
    users = data(api.send_command("/ip/hotspot/user/print"))
    binds = data(api.send_command("/ip/hotspot/ip-binding/print"))
    queues = data(api.send_command_optimized(
        "/queue/simple/print", proplist=["name", "target", "max-limit", "dynamic", "disabled", "rate"]))
    active = data(api.send_command("/ip/hotspot/active/print"))
    profiles = data(api.send_command("/ip/hotspot/profile/print"))
    return {
        "hotspot_profiles_login_by": {p.get("name"): p.get("login-by") for p in profiles},
        "mac_login_users": sum(1 for u in users if ml.is_mac_login_user(u)),
        "bypassed_bindings": sum(1 for b in binds if b.get("type") == "bypassed"),
        "static_plan_queues": sum(1 for q in queues if str(q.get("name", "")).startswith("plan_")
                                  and q.get("dynamic") != "true"),
        "disabled_static_plan_queues": sum(1 for q in queues if str(q.get("name", "")).startswith("plan_")
                                           and q.get("disabled") == "true"),
        "dynamic_hotspot_queues": sum(1 for q in queues if str(q.get("name", "")).startswith("<hotspot-")),
        "active_sessions_by_login": dict(Counter(a.get("login-by") for a in active)),
    }


def main():
    info, customers = asyncio.run(load())
    if ONLY_MACS:
        customers = [c for c in customers if c["mac_address"] in ONLY_MACS]
        out("ONLY_MACS", sorted(ONLY_MACS))
    out("router", {k: info[k] for k in ("id", "name", "ip")})
    out("mode", MODE)
    out("paid hotspot customers", len(customers))
    listed = ml.mac_login_enabled(ROUTER_ID)
    out("in HOTSPOT_MAC_LOGIN_ROUTER_IDS of this app", listed)

    if MODE == "apply" and not listed:
        raise SystemExit("refusing: add the router to HOTSPOT_MAC_LOGIN_ROUTER_IDS and deploy first")
    if MODE == "revert" and listed and not ONLY_MACS:
        raise SystemExit("refusing: remove the router from HOTSPOT_MAC_LOGIN_ROUTER_IDS and deploy first")
    if MODE not in ("dry-run", "apply", "revert"):
        raise SystemExit(f"unknown MODE {MODE}")

    api = MikroTikAPI(info["ip"], info["username"], info["password"], info["port"] or 8728, timeout=30)
    if not api.connect():
        raise SystemExit(f"connect failed: {api.last_connect_error}")
    try:
        out("before", snapshot(api))
        if MODE == "dry-run":
            for c in customers:
                user = api.get_hotspot_user_by_name(ml.mac_login_username(c["mac_address"]))
                out("customer", {"id": c["id"], "mac": c["mac_address"], "plan": c["plan_speed"],
                                 "mac_login_user_exists": bool(user.get("found"))})
            return

        if MODE == "apply":
            out("setup", ml.ensure_router_setup(api))
            cache = {}
            failures = 0
            for c in customers:
                res = ml.provision_customer(api, c["mac_address"], c["plan_speed"], note="converted",
                                            expiry=c["expiry"], profile_cache=cache)
                if res.get("error"):
                    failures += 1
                out("customer", {"id": c["id"], "mac": c["mac_address"],
                                 "result": res.get("error") or "ok",
                                 "legacy_removed": res.get("legacy_removed"),
                                 "kick": res.get("kick_result")})
            out("fasttrack flush", ml.flush_fasttracked_connections(api))
            out("failures", failures)

        if MODE == "revert":
            for c in customers:
                removed = ml.remove_customer(api, c["mac_address"])
                compact = c["mac_address"].replace(":", "")
                res = api.add_customer_bypass_mode(
                    c["mac_address"], compact, compact, "1d", c["plan_speed"],
                    "Reverted from MAC login", info["ip"], info["username"], info["password"],
                    expiry=c["expiry"],
                )
                out("customer", {"id": c["id"], "mac": c["mac_address"],
                                 "users_removed": removed.get("users_removed"),
                                 "result": res.get("error") or "ok"})
            if ONLY_MACS:
                out("after", snapshot(api))
                return
            # Nothing tagged may survive a full revert: with no reconcile
            # running, a leftover MAC-login user is free internet.
            leftovers = 0
            for u in data(api.send_command("/ip/hotspot/user/print")):
                if ml.is_mac_login_user(u):
                    api.send_command("/ip/hotspot/user/remove", {"numbers": u.get(".id")})
                    leftovers += 1
            out("leftover MAC-login users removed", leftovers)
            for p in data(api.send_command("/ip/hotspot/profile/print")):
                login_by = [x for x in str(p.get("login-by", "")).split(",") if x]
                if "mac" in login_by:
                    api.send_command("/ip/hotspot/profile/set", {
                        "numbers": p.get(".id"),
                        "login-by": ",".join(x for x in login_by if x != "mac"),
                    })
        out("after", snapshot(api))
    finally:
        api.disconnect()


main()

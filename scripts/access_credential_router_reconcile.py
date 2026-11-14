"""Find access credentials whose router does not match the DB, and (APPLY=1)
mark them pending so the normal retry delivers them.

Before 2026-11-14 a create or revoke made while the router was unreachable
changed only the DB (router 118: credentials 330/331 never reached the router;
322/314/303 were revoked but their hotspot users stayed). Those rows carry no
``router_sync`` flag, so nothing would ever repair them. This finds them:

* ACTIVE credential with no hotspot user of that name on the router -> ``add``
* REVOKED credential whose hotspot user (comment ``ACCESS_CRED|cred:<id>|``)
  is still on the router -> ``remove``

and with APPLY=1 sets ``router_sync`` on exactly those rows (only where it is
still NULL). The router itself is NOT written here: the 3-minute retry job
(``access_credential_sync``) or the check-in queue does that, with its usual
checks. Read-only on the router.

    docker exec -e ROUTER_IDS=118 -i isp_billing_hetzner_app python - < scripts/access_credential_router_reconcile.py
    docker exec -e ROUTER_IDS=118 -e APPLY=1 -i isp_billing_hetzner_app python - < scripts/access_credential_router_reconcile.py

RADIUS routers are skipped (their credentials live in our DB). Rows are read in
one short session released before any RouterOS I/O; each router's flags are
written in their own short session.
"""

import asyncio
import json
import os
import re
from datetime import datetime

from sqlalchemy import text

from app.db.database import async_session
from app.services.mikrotik_api import MikroTikAPI

APPLY = os.environ.get("APPLY") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
_TAG = re.compile(r"ACCESS_CRED\|cred:(\d+)\|")


async def load():
    async with async_session() as db:
        routers = (await db.execute(text(
            "select id, name, ip_address, username, password, port, auth_method::text as auth "
            "from routers where id = any(:ids) order by id"), {"ids": IDS})).mappings().all()
        creds = (await db.execute(text(
            "select id, router_id, username, status::text as status, router_sync "
            "from access_credentials where router_id = any(:ids)"), {"ids": IDS})).mappings().all()
        await db.commit()
    return [dict(r) for r in routers], [dict(c) for c in creds]


def router_users(r) -> dict | None:
    api = MikroTikAPI(r["ip_address"], r["username"], r["password"], r["port"] or 8728,
                      timeout=30, connect_timeout=5)
    if not api.connect():
        return None
    try:
        res = api.send_command("/ip/hotspot/user/print")
        binds = api.send_command("/ip/hotspot/ip-binding/print")
        if res.get("error") or binds.get("error"):
            return None
        users = {str(u.get("name", "")).lower(): str(u.get("comment") or "") for u in res.get("data") or []}
        macs = {}
        for b in binds.get("data") or []:
            m = _TAG.search(str(b.get("comment") or ""))
            if m and b.get("mac-address"):
                macs[int(m.group(1))] = str(b["mac-address"]).upper()
        return {"users": users, "macs": macs}
    finally:
        api.disconnect()


async def mark(changes: list[tuple[int, str]], macs: dict) -> int:
    now = datetime.utcnow()
    n = 0
    async with async_session() as db:
        for cred_id, kind in changes:
            res = await db.execute(text(
                "update access_credentials set router_sync = :k, router_sync_since = :now, "
                "router_sync_mac = :mac, "
                "router_sync_error = 'found by access_credential_router_reconcile' "
                "where id = :id and router_sync is null"),
                {"k": kind, "now": now, "id": cred_id, "mac": macs.get(cred_id) if kind == "remove" else None})
            n += res.rowcount or 0
        await db.commit()
    return n


def main():
    if not IDS:
        raise SystemExit("set ROUTER_IDS=118[,..]")
    routers, creds = asyncio.run(load())
    for r in routers:
        out = {"router_id": r["id"], "name": r["name"], "apply": APPLY}
        if (r["auth"] or "").lower() == "radius":
            out["status"] = "skipped_radius"
            print("RESULT " + json.dumps(out))
            continue
        seen = router_users(r)
        if seen is None:
            out["status"] = "unreachable"
            print("RESULT " + json.dumps(out))
            continue
        users, macs = seen["users"], seen["macs"]
        on_router_ids = set(macs) | {int(m.group(1)) for c in users.values() for m in [_TAG.search(c)] if m}
        changes = []
        for c in creds:
            if c["router_id"] != r["id"] or c["router_sync"]:
                continue
            if c["status"] == "active" and c["username"].lower() not in users:
                changes.append((c["id"], "add"))
            elif c["status"] == "revoked" and c["id"] in on_router_ids:
                changes.append((c["id"], "remove"))
        out["missing_on_router"] = [i for i, k in changes if k == "add"]
        out["revoked_but_still_on_router"] = [i for i, k in changes if k == "remove"]
        if APPLY and changes:
            out["marked"] = asyncio.run(mark(changes, macs))
        out["status"] = "ok"
        print("RESULT " + json.dumps(out))


if __name__ == "__main__":
    main()

"""Read-only fleet detector: hotspot routers missing the anti-bypass rule (HTTP Injector).

Follows the incident-to-detector contract. Piped into the prod app container:

    ssh -o BatchMode=yes root@91.98.238.12 \
      "docker exec -i -e ROUTER_ID=all -e WORKERS=3 isp_billing_hetzner_app python -u -" \
      < scripts/detect_anti_bypass_missing.py

ROUTER_ID = <id> | <id,id> | all (all = routers.last_status = true). WORKERS default 3, max 6.
Prints one JSON line per router, then {"summary": ...}. Never writes to a router or the DB.
The same check backs GET /api/admin/anti-bypass/scan; the fix is POST /api/admin/anti-bypass/apply.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from sqlalchemy import select  # noqa: E402

from app.db.database import async_session  # noqa: E402
from app.db.models import Router  # noqa: E402
from app.services import anti_bypass_fleet  # noqa: E402


async def _load(target: str) -> list[dict]:
    query = select(Router).order_by(Router.id)
    if target.strip().lower() == "all":
        query = query.where(Router.last_status.is_(True))
    else:
        ids = [int(x) for x in target.split(",") if x.strip()]
        query = query.where(Router.id.in_(ids))
    async with async_session() as db:   # one short session, closed before any router I/O
        infos = [anti_bypass_fleet.router_info(r) for r in (await db.execute(query)).scalars().all()]
        await db.commit()
    return infos


async def main() -> int:
    target = os.environ.get("ROUTER_ID", "").strip()
    if not target:
        print(json.dumps({"error": "set ROUTER_ID=<id> | <id,id> | all"}))
        return 2
    infos = await _load(target)
    results = await anti_bypass_fleet.scan(infos, anti_bypass_fleet.clamp_concurrency(os.environ.get("WORKERS", 3)))
    lines = [anti_bypass_fleet.detector_line(r) for r in results]
    for line in lines:
        print(json.dumps(line), flush=True)
    if len(lines) > 1:
        counts: dict[str, int] = {}
        for line in lines:
            counts[line["status"]] = counts.get(line["status"], 0) + 1
        print(json.dumps({"summary": {"detector": anti_bypass_fleet.DETECTOR_ID, **counts,
                                      "hit_ids": [l["router_id"] for l in lines if l["status"] == "hit"]}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

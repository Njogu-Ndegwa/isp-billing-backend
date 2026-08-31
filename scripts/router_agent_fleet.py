"""Operator CLI for staged router-agent rollout and rollback.

Examples (dry-run is the default):
  python scripts/router_agent_fleet.py status --limit 5
  python scripts/router_agent_fleet.py install --router-id 10 --apply
  python scripts/router_agent_fleet.py global-off --apply
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.router_agent_fleet import (  # noqa: E402
    load_router_agent_candidates,
    run_router_agent_fleet_change,
    set_router_agent_global_enabled,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stage or roll back the router command agent")
    parser.add_argument(
        "mode",
        choices=[
            "status",
            "install",
            "upgrade",
            "uninstall",
            "global-on",
            "global-off",
        ],
    )
    parser.add_argument("--router-id", action="append", type=int, default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--endpoint-base-url")
    parser.add_argument("--management-probe-ip", default="10.0.0.1")
    parser.add_argument("--apply", action="store_true", help="Required for any write")
    return parser


async def _main() -> int:
    args = _parser().parse_args()
    if args.mode == "status":
        rows = await load_router_agent_candidates(router_ids=args.router_id, limit=args.limit)
        print(json.dumps([row.__dict__ for row in rows], indent=2, default=str))
        return 0
    if not args.apply:
        print(json.dumps({"applied": False, "reason": "pass --apply to perform writes"}))
        return 2
    if args.mode in {"global-on", "global-off"}:
        enabled = args.mode == "global-on"
        await set_router_agent_global_enabled(enabled)
        print(json.dumps({"applied": True, "global_enabled": enabled}))
        return 0
    rows = await run_router_agent_fleet_change(
        mode=args.mode,
        router_ids=args.router_id,
        limit=args.limit,
        endpoint_base_url=args.endpoint_base_url,
        management_probe_ip=args.management_probe_ip,
    )
    print(json.dumps(rows, indent=2, default=str))
    return 0 if all(row.get("ok") for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

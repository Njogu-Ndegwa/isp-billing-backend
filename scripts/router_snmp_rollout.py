"""Operator CLI: enrol routers into SNMP CPU monitoring, 10 at a time.

Dry-run is the default; nothing is written without --apply. Run inside the
Hetzner app container (never on the AWS standby):

  python scripts/router_snmp_rollout.py --router-id 371 --router-id 316
  python scripts/router_snmp_rollout.py --router-id 371 --apply
  python scripts/router_snmp_rollout.py --router-id 371 --rollback --apply

The community comes from ROUTER_SNMP_COMMUNITY. Rollback restores exactly the
settings saved in --state (default /tmp/router_snmp_rollout_state.json), so keep
that file until the batch is confirmed.
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

from app.config import settings  # noqa: E402
from app.services import router_snmp_rollout  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Enrol routers into SNMP CPU monitoring")
    p.add_argument("--router-id", action="append", type=int, default=[], required=True)
    p.add_argument("--apply", action="store_true", help="Required for any router write")
    p.add_argument("--rollback", action="store_true")
    p.add_argument("--state", default="/tmp/router_snmp_rollout_state.json")
    return p


async def _main() -> int:
    args = _parser().parse_args()
    report = await router_snmp_rollout.run(
        args.router_id, (settings.ROUTER_SNMP_COMMUNITY or "").strip(),
        apply=args.apply, rollback=args.rollback, state_path=Path(args.state))
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

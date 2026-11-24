"""Check the admin "Router CPU by model" chart against the per-router history.

Read-only. Both tables are folded from the same router health samples by
separate code: ``router_cpu_buckets`` (the chart, router_cpu_history.py) and
``router_metric_buckets`` step 300 (the per-router graphs,
router_metric_history.py). For every closed 5-minute bucket and router model
in the window it recomputes the chart's router count and mean CPU from the
per-router rows and reports where they disagree.

Written after 24 Nov 2026, when restarts counted every router twice in the
bucket they fell in (210 routers shown, 105 real) and nobody noticed for hours.

    docker exec -e HOURS=6 -i isp_billing_hetzner_app python - < scripts/router_cpu_history_crosscheck.py

Env: HOURS (default 6). Prints one JSON line per disagreeing (bucket, model)
and a final {"summary": ...} line; exits 1 when anything disagrees.

Tolerances: a router whose board name changed inside the window is filed
under its current model here and its old one in the chart, so a count may be
off by one; ``MAX_ROUTER_DIFF`` and ``MAX_AVG_DIFF`` absorb that.
"""

import asyncio
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import text

from app.db.database import async_session
from app.services import router_cpu_history as h

MAX_ROUTER_DIFF = 1
MAX_AVG_DIFF = 0.5


async def main() -> int:
    hours = int(os.environ.get("HOURS", "6"))
    now = datetime.utcnow()
    since = h.bucket_start(now - timedelta(hours=hours))
    # Newest closed bucket: the open one and the one inside its flush grace are not written yet.
    until = h.bucket_start(now - h.CLOSE_GRACE) - timedelta(seconds=h.BUCKET_SECONDS)
    async with async_session() as db:
        model = {rid: h.model_key(b, v)[0] for rid, b, v in (await db.execute(text(
            "select router_id, board_name, routeros_version from router_health"))).all()}
        per_router = (await db.execute(text(
            "select bucket_start, router_id, cpu_sum, cpu_samples from router_metric_buckets "
            "where step_seconds = 300 and cpu_samples > 0 and bucket_start >= :s and bucket_start < :u"),
            {"s": since, "u": until})).all()
        chart_rows = (await db.execute(text(
            "select bucket_start, board_name, sum(routers), sum(cpu_mean_sum) from router_cpu_buckets "
            "where bucket_start >= :s and bucket_start < :u group by 1, 2"),
            {"s": since, "u": until})).all()
        first_chart = (await db.execute(text("select min(bucket_start) from router_cpu_buckets"))).scalar()
        await db.commit()

    independent = defaultdict(list)
    for start, rid, s, n in per_router:
        independent[(start, model.get(rid, h.UNKNOWN_BOARD))].append(s / n)
    chart = {(start, board): (routers, mean_sum) for start, board, routers, mean_sum in chart_rows}

    compared = bad = 0
    worst_avg = 0.0
    for key in sorted(set(independent) | set(chart)):
        if first_chart is None or key[0] <= first_chart:
            continue                                   # before the chart existed, or its partial first bucket
        means = independent.get(key, [])
        routers, mean_sum = chart.get(key, (0, 0.0))
        ind_avg = sum(means) / len(means) if means else None
        chart_avg = mean_sum / routers if routers else None
        compared += 1
        avg_diff = abs(chart_avg - ind_avg) if ind_avg is not None and chart_avg is not None else None
        if avg_diff is not None:
            worst_avg = max(worst_avg, avg_diff)
        if abs(routers - len(means)) > MAX_ROUTER_DIFF or avg_diff is None or avg_diff > MAX_AVG_DIFF:
            bad += 1
            print(json.dumps({
                "bucket": key[0].isoformat() + "Z", "model": key[1],
                "routers_chart": routers, "routers_per_router_history": len(means),
                "avg_chart": None if chart_avg is None else round(chart_avg, 1),
                "avg_per_router_history": None if ind_avg is None else round(ind_avg, 1),
            }))
    print(json.dumps({"summary": {"hours": hours, "compared": compared, "disagree": bad,
                                  "worst_avg_diff": round(worst_avg, 2)}}))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

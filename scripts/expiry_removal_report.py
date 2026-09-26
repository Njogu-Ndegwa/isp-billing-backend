"""How fast expired hotspot customers are removed, router-side reaper vs server job.

Read-only. Run inside the app container:

    docker exec -e ROUTER_IDS=10,224 -e HOURS=24 -i isp_billing_hetzner_app python - < scripts/expiry_removal_report.py

ROUTER_IDS is optional (default: every router with the reaper enabled). For each
router and each method it prints the number of removals and how long after
expiry they happened: median, p90, p95, max, and the share done within 30 s,
1, 2, 5 and 10 minutes. Add BEFORE=1 to also show the same routers over the
same length of time before the reaper was installed.

Removal time = provisioning_logs.log_date - customers.expiry for successful
hotspot_deactivation rows. For the reaper, log_date is the moment the router
says it removed the binding (its own clock, which the server has confirmed);
for the server job it is when the job recorded the removal.
"""

import asyncio
import os

from sqlalchemy import text

from app.db.database import async_session

HOURS = int(os.environ.get("HOURS", "24"))
BEFORE = os.environ.get("BEFORE") == "1"
IDS = [int(x) for x in os.environ.get("ROUTER_IDS", "").split(",") if x.strip().isdigit()]
REAPER_DETAILS = "Router expiry reaper%"

_SQL = """
select c.router_id, r.name,
       case when pl.details like :reaper then 'router reaper' else 'server job' end as method,
       extract(epoch from pl.log_date - c.expiry) as secs
from provisioning_logs pl
join customers c on c.id = pl.customer_id
join routers r on r.id = c.router_id
where pl.action = 'hotspot_deactivation' and pl.status = 'success'
  and pl.log_date >= c.expiry
  and c.router_id = any(:ids)
  and pl.log_date >= :start and pl.log_date < :end
"""


def pct(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def fmt(s):
    return f"{s:.0f}s" if s < 120 else f"{s / 60:.1f}m" if s < 7200 else f"{s / 3600:.1f}h"


def show(rows, title):
    print(f"\n{title}")
    groups = {}
    for rid, name, method, secs in rows:
        groups.setdefault((rid, name, method), []).append(float(secs))
    if not groups:
        print("  no removals")
        return
    print(f"  {'router':28} {'method':14} {'n':>4} {'median':>7} {'p90':>7} {'p95':>7} {'max':>7}  "
          f"{'<=30s':>6} {'<=1m':>6} {'<=2m':>6} {'<=5m':>6} {'<=10m':>6}")
    for (rid, name, method), v in sorted(groups.items()):
        within = lambda t: f"{100 * sum(x <= t for x in v) / len(v):5.0f}%"
        print(f"  {str(rid) + ' ' + name[:22]:28} {method:14} {len(v):>4} {fmt(pct(v, .5)):>7} {fmt(pct(v, .9)):>7} "
              f"{fmt(pct(v, .95)):>7} {fmt(max(v)):>7}  {within(30)} {within(60)} {within(120)} {within(300)} {within(600)}")


async def main():
    async with async_session() as db:
        ids = IDS
        if not ids:
            ids = [r for (r,) in (await db.execute(text(
                "select id from routers where expiry_reaper_enabled"))).all()]
        installed = dict((await db.execute(text(
            "select id, expiry_reaper_installed_at from routers where id = any(:ids)"), {"ids": ids})).all())
        now = (await db.execute(text("select now() at time zone 'utc'"))).scalar()
        from datetime import timedelta
        start = now - timedelta(hours=HOURS)
        after = (await db.execute(text(_SQL), {"reaper": REAPER_DETAILS, "ids": ids, "start": start, "end": now})).all()
        before = []
        if BEFORE:
            for rid in ids:
                t0 = installed.get(rid)
                if t0 is None:
                    continue
                before += (await db.execute(text(_SQL), {
                    "reaper": REAPER_DETAILS, "ids": [rid],
                    "start": t0 - timedelta(hours=HOURS), "end": t0,
                })).all()
        await db.commit()
    print(f"routers {ids}; installed at: " + ", ".join(f"{k}={v:%Y-%m-%d %H:%M}" for k, v in installed.items() if v))
    show(after, f"last {HOURS} h")
    if BEFORE:
        show(before, f"{HOURS} h before the reaper was installed")


if __name__ == "__main__":
    asyncio.run(main())

# Caddy on the Hetzner box

`Caddyfile` here is the intended content of `/etc/caddy/Caddyfile` on
91.98.238.12. Until 2026-10-03 the file lived only on the box; the first commit
that added it is a verbatim snapshot (sha256 `0ee099e4…`), so `git log -p` on
this file shows every intended change as a diff.

Nothing deploys this file. A Caddy change on production needs Dennis's explicit
approval, and a human (or an agent he has approved for that change) applies it
by hand with the steps below.

## Applying the zero-downtime upstream change

Background: [docs/zero-downtime-deploys.md](../../docs/zero-downtime-deploys.md).

**Order matters.** Caddy health-checks `GET /health/ready`. If Caddy is
switched before the app serves that endpoint, every probe 404s, both slots are
marked down, and all API traffic waits 30 s and then fails. Merge and deploy the
PR first, then:

```bash
# 0. The endpoint exists on the live app (expect {"status":"ready"})
curl -fsS http://127.0.0.1:8000/health/ready

# 1. Nobody changed Caddy since the snapshot (expect 0ee099e4...)
sha256sum /etc/caddy/Caddyfile

# 2. Back up, stage, validate
cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%F)
cp <this repo>/ops/caddy/Caddyfile /etc/caddy/Caddyfile.new
caddy adapt --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null && echo parses
# Not `caddy validate` as root: it provisions the config and can create
# /var/lib/caddy/upstream-health.log owned by root, which the caddy user then
# cannot open on reload.

# 3. Swap in and reload. A reload is all-or-nothing: if the new config fails
#    to load, Caddy keeps serving the old one and the command exits non-zero.
#    In-flight requests are not dropped.
mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
systemctl reload caddy || cp -a /etc/caddy/Caddyfile.bak-$(date +%F) /etc/caddy/Caddyfile
#   (on failure the old file goes back, so a later Caddy restart can't pick up the bad one)

# 4. Verify
curl -s http://127.0.0.1:2019/reverse_proxy/upstreams    # lists 127.0.0.1:8001
curl -sI https://isp.bitwavetechnologies.net/health | grep -i x-served-by   # hetzner-api
tail -5 /var/lib/caddy/upstream-health.log                # :8001 refused is expected
journalctl -u caddy --since "-2 min" -o cat | grep -c '"level":"error"'     # ~0
```

If step 1 shows a different hash, someone edited Caddy on the box. Merge their
change into this file first and don't overwrite it.

**Rollback:** `cp -a /etc/caddy/Caddyfile.bak-<date> /etc/caddy/Caddyfile &&
systemctl reload caddy`. The deploy workflow notices the missing :8001 upstream
and goes back to the old stop/start swap on its own. Nothing else needs undoing.

## After applying

- The next deploy log says `Starting isp_billing_hetzner_app_bridge` instead of
  `WARNING: Caddy has no 127.0.0.1:8001 upstream`.
- Check the deploy window:
  `journalctl -u caddy --since <deploy start> --until <deploy end> -o cat | grep -c '"level":"error"'`
  should be 0. Before this change it was 34–118 per deploy.
- Upstream up/down transitions are in `/var/lib/caddy/upstream-health.log`
  (5 MiB × 2, rotated by Caddy), not in the journal.

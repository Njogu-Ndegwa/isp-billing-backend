# H0 Baseline & Inventory — 2026-08-06

Migration: AWS → Hetzner `91.98.238.12` (plan: `~/.claude/plans/moonlit-weaving-valley.md`).

## Fleet reality (live-verified)

| Metric | Value |
|---|---|
| wg0 (prod 54.91.202.229) registered peers | 515 |
| wg0 handshake < 5 min | ~40 (active fleet) |
| wg1 (35.170.199.141) registered peers | 236 |
| wg1 handshake < 5 min | ~39 (backup coverage ≈ full active fleet) |
| chap-secrets entries (L2TP backups) | 77 |
| live ppp sessions on insurance box | 12 |
| wg1 peers with preshared keys | 0 → single endpoint-change repoint valid fleet-wide |
| billing DB size | 431 MB |
| wg1 MTU on AWS | 8921 (jumbo artifact — use 1420 on Hetzner) |

## Pull service

- Exactly **one** router polls it: `Router-0577` (~every 30 s).
- Container `pull-svc` = `python:3-alpine`, app bind-mounted from `/home/dennis/pullsvc` (ro), data at `/home/dennis/pullpoc` → `/data`.
- `PULL_ALLOWED_IPS=54.91.202.229`. Router-side fetch URL bakes `35.170.199.141:8443` → must repoint Router-0577's scheduler at H4.

## Factory ports on Hetzner (FLAG for Dennis — not changed)

- `8080` deploy-dispatcher: receives **TAPD webhooks** (TAPD_WEBHOOK_SECRET in env) → must stay world-open (Tencent IP ranges impractical to pin). Currently absorbing internet scanner spam, auth-rejects 401. Consider moving behind a hostname+Cloudflare later.
- `8090` factory-app-device-portal: world-open; purpose = factory device portal. Candidate for admin-IP restriction — Dennis to decide.

## Prod Apache (captured in `sites-enabled/`)

- `.net` :443 vhost uses **Cloudflare Origin cert** (`/etc/ssl/cloudflare/bitwavetechnologies-net.pem`) + :80 vhost; `.com` is :80-only (Cloudflare terminates TLS).
- Proxy: `ProxyPreserveHost On`, `X-Forwarded-Proto https`, `X-Real-IP`, HSTS/XFO/XCTO headers → replicate in Caddy site block.
- Other vhosts on prod box (NOT part of this migration, but note for final AWS retirement): `korraai.bitwavetechnologies.com` (LE cert), `isp-frontend.bitwavetechnologies.com`.

## Hetzner box (see `hetzner-baseline.txt`)

- deploy-db publishes **no host port** → billing PG can take 127.0.0.1:5434.
- Caddy = systemd, `/etc/caddy/Caddyfile` (owned by portal-origin effort; API site block must be added there, coordinated).
- wg-egress FORWARD/NAT iptables baseline recorded — DO NOT TOUCH.
- Disk 28G free; no swap (H1 adds 4G swapfile).

## Prod port exposure note (existing, unchanged)

Prod publishes 8000/5434 on 0.0.0.0 (guarded by DOCKER-USER rules per ddos-attack-response skill). Hetzner billing stack will bind loopback-only instead.

# Hetzner Cloud Firewall — ruleset for `egress-nbg1` (91.98.238.12)

**Status: APPLIED 2026-10-02 21:47 UTC** — firewall `firewall-1` (project "Default", id 11724241)
is attached to server `egress-nbg1`. The table below is the live ruleset.

We deliberately do NOT use ufw/host-iptables for this: published Docker ports bypass ufw,
and the wg-egress FORWARD/NAT rules must not be disturbed. The Cloud Firewall filters
upstream of the host and cannot interact with either.

## Inbound rules (default deny)

| Port/Proto | Source | Why |
|---|---|---|
| tcp/22 | any | SSH (key-only + fail2ban). CI/CD deploys use SSH/SCP on this port. |
| icmp | any | reachability checks |
| tcp/80-443 | Cloudflare ranges only: 15 IPv4 + 7 IPv6 (22 total) from https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 | API + frontends, all orange-clouded |
| tcp/4443 | any | SSTP router management tunnels (accel-pppd) |
| tcp/8443 | any | pull-svc (token-auth; routers on dynamic IPs) |
| tcp/8080 | any | factory dispatcher, receives TAPD webhooks |
| tcp/8090 | any | factory device portal |
| udp/51821-51823 | any | 51821 wg1 insurance, 51822 wg-egress, 51823 wg2 primary router WireGuard |
| udp/500, udp/4500, udp/1701 | any | L2TP/IPsec (ROS6 routers, dynamic IPs) |
| udp/35570 | 54.91.202.229/32 | wg-aws-transit (AWS standby ↔ Hetzner) |
| tcp/8729-8730 | 54.91.202.229/32 | wg managers |

Closed to the internet (no rule, so default deny):

- tcp/8081, tcp/8082: the pre-DNS frontend test endpoints. Closed as of this apply.
- 5434, 8000, 1812/1813, 3001, 2019: these bind loopback anyway; the firewall is defense in depth.

The previous version of this table was wrong in two places: it listed udp/51820 (wg2 actually
listens on 51823) and it left out tcp/4443 (SSTP). Both are fixed above.

### 80-443 is one rule, not two

Web traffic goes through a single rule for the port range 80-443 instead of separate tcp/80 and
tcp/443 rules, so each Cloudflare range is listed once rather than twice. The range also admits
tcp/81-442 from Cloudflare addresses. Cloudflare only proxies 80 and 443 inside that range, so
this is fine as long as nothing on the host is published on 81-442. If a service is ever
published on a port in that range, split this rule first.

When Cloudflare changes its published ranges, update this rule in the Hetzner console (or API)
to match both lists.

## ICMP
Allowed from anywhere (see table).

## Outbound
No restrictions.

## Verified after apply (2026-10-02)

- All router tunnels stayed up.
- Direct-IP `91.98.238.12:80` and `:443` time out.
- API through Cloudflare returns 200.
- CI/CD deploys are unaffected: they use SSH/SCP on 22, and their health checks hit
  `127.0.0.1` on the box.

## Related edge protections (live the same evening)

- Cloudflare, both zones (bitwavetechnologies.com and .net): a Configuration Rule that never
  challenges machine clients (payment callbacks, router check-in/provisioning), and a rate
  limit on `/api/public/`, `/api/hotspot/` and `/api/radius/hotspot/` (block above 600 requests
  per 10 s per IP + colo, 10 s mitigation).
- uvicorn concurrency limits (`--limit-concurrency 100 --backlog 128 --timeout-keep-alive 5`)
  on the `web` service in `docker-compose.hetzner.yml`, PR #177.

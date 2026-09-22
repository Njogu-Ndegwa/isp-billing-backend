# Hetzner Cloud Firewall — ruleset for `egress-nbg1` (91.98.238.12)

**Status: NOT APPLIED — needs Dennis (Hetzner console → Firewalls, or an API token).**
We deliberately do NOT use ufw/host-iptables for this: published Docker ports bypass ufw,
and the wg-egress FORWARD/NAT rules must not be disturbed. The Cloud Firewall filters
upstream of the host and cannot interact with either.

## Inbound rules (default deny)

| Port/Proto | Source | Why |
|---|---|---|
| tcp/22 | Dennis's admin IPs (or 0.0.0.0/0 initially — key-only + fail2ban active) | SSH |
| tcp/80, tcp/443 | Cloudflare IP ranges (https://www.cloudflare.com/ips/) | API + frontends, all orange-clouded |
| udp/51820 | 0.0.0.0/0 | future primary WG (routers dial from dynamic IPs) |
| udp/51821 | 0.0.0.0/0 | insurance WG |
| udp/51822 | 0.0.0.0/0 | existing wg-egress (keep!) |
| udp/500, udp/4500, udp/1701 | 0.0.0.0/0 | L2TP/IPsec (ROS6 routers, dynamic IPs) |
| tcp/8729 | 54.91.202.229/32 | prod app → insurance wg-manager |
| tcp/8443 | 0.0.0.0/0 | pull-svc (token-auth; routers on dynamic IPs) |
| tcp/8080 | 0.0.0.0/0 | **factory dispatcher — receives TAPD webhooks; must stay open (Dennis: consider Cloudflare-fronting later)** |
| tcp/8090 | Dennis's admin IPs (recommended) or 0.0.0.0/0 | factory device portal — currently world-open; Dennis decides |
| tcp/8081, tcp/8082 | Dennis's admin IPs (recommended) | pre-DNS frontend test endpoints |

Everything else (5434, 8000, 1812/1813, 3001, 2019) — blocked (they bind loopback anyway; defense in depth).

## ICMP
Allow (Hetzner default) — useful for reachability checks.

## Outbound
No restrictions.

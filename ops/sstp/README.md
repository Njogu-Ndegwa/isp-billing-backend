# SSTP management tunnel for RouterOS 6 routers

RouterOS 6 has no WireGuard, and L2TP/IPsec breaks in two common cases:
several routers behind one public (CGNAT) IP take turns being reachable,
and a NAT or PPPoE reset can strand the IPsec session until someone reboots
the router. SSTP is PPP over TLS over TCP, one connection per router, so it
has neither problem.

The pilot was proven on 2026-09-24 on Router-0961 (router 383, hAP lite,
ROS 6.49.20), including a real M-Pesa payment delivered over the tunnel.
Three routers behind a single public IP (Dansted, 102.210.24.46) have also
run on it at the same time. By 2026-09-25, 14 routers had been moved over
by hand.

## What runs where

Everything is on the Hetzner production host, 91.98.238.12:

| Piece | Location |
|---|---|
| accel-ppp binary, built from commit `c9d938173838d6955c824d141f24672d7037eb4e` | `/usr/local/sbin/accel-pppd` |
| systemd unit, enabled at boot (`router-mgmt-sstp.service` here) | `/etc/systemd/system/router-mgmt-sstp.service` |
| config (`accel-ppp.conf` here) | `/etc/accel-ppp-router-mgmt/accel-ppp.conf` |
| logins, one line per router | `/etc/accel-ppp-router-mgmt/chap-secrets` (0600) |
| CA and server cert (`create-cert.sh` here) | `/etc/accel-ppp-router-mgmt/ca.crt`, `server.crt`, plus keys |
| logs | `/var/log/accel-ppp-router-mgmt/accel-ppp.log` (also `auth-fail.log`, `core.log`) |
| CLI | `telnet 127.0.0.1 2001` (for example `show sessions`) |

Facts behind the config:

- TCP **4443**, because Caddy owns 443. TLS 1.2.
- Modules are sstp, chap-secrets and mschap and nothing else.
- `gw-ip-address=10.251.0.1`. Each router logs in as `sstp-<identity>` and
  is given `10.251.X.Y`, where `10.0.X.Y` is its `routers.ip_address`. This is
  the same plane as the Hetzner insurance L2TP and WireGuard (wg2).
- `[client-ip-range] 0.0.0.0/0` is required. Without it accel-ppp rejects
  every connection.
- The server side of each session is an ordinary `pppN` interface, so
  `isp-native-router-route-sync` routes `10.0.X.Y` over it within about 30 s.
  The app keeps using `routers.ip_address` and needs no special case.

## Rules

- **Never load accel-ppp's `l2tp` or `pptp` module in this config.** xl2tpd
  owns UDP 1701, and taking that port would cut every L2TP router.
- **Don't restart `router-mgmt-sstp` casually.** A restart drops every SSTP
  router at once. Adding or changing a login needs no restart because
  chap-secrets is read on each login.
- On a router that uses SSTP, the Hetzner insurance L2TP (`l2tp-aws2`, or
  `l2tp-hz` on a few older routers) must stay **disabled**. It claims the same
  `10.251.X.Y`.
- The router must own `10.0.X.Y` on a loopback bridge (`lo-mgmt`), because
  otherwise that address only exists on the L2TP interface.
- The AWS primary L2TP (`l2tp-aws`) stays configured as a fallback. It can
  hold the same `10.0.X.Y` as `lo-mgmt` without trouble; this was tested.
- Only `ca.crt` is public. Never commit or copy `ca.key`, `server.key`,
  chap-secrets, or any `*.password` file. `create-cert.sh` refuses to replace
  an existing CA, because a new CA would break every router that trusts the
  current one.

## Moving an existing router

Use the Claude Code skill **`migrate-router-to-sstp`** (runbook plus scripts).
It covers ROS version checks, staging, the switch with automatic revert,
pinning the loopback, verification, setting `routers.management_tunnel='sstp'`,
and rollback.

## New routers (provisioning)

When `SSTP_PROVISIONING_ENABLED=true`, a new RouterOS 6 token (`vpn_type=l2tp`)
does the following:

1. Registers `sstp-<identity>` with a random 24-character password and
   `10.251.X.Y` through the insurance manager's `POST /add-sstp-peer`. That
   endpoint writes the chap-secrets file named by `SSTP_CHAP_SECRETS`,
   atomically, with a backup, at mode 0600. No Hetzner insurance L2TP login is
   created for these tokens.
2. Produces a `.rsc` that keeps the `l2tp-aws` block and replaces the
   `l2tp-aws2` block with an SSTP block. That block fetches and trusts the CA
   from `GET /api/provision/router-mgmt-ca.crt` (served from
   `ROUTER_MGMT_CA_PEM`), turns on NTP, adds or updates `sstp-hetzner`, and
   pins `10.0.X.Y/32` on `lo-mgmt`.
3. On `/complete`, sets `routers.management_tunnel='sstp'`.

With the flag off, token creation and the script are unchanged.

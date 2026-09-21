# H2 — Insurance role replicated on Hetzner (2026-08-06)

All components live on `91.98.238.12`, fully **dormant** — no router points here yet.
Prod (54.91.202.229) untouched. Source box (35.170.199.141) only read from.

## What runs now on Hetzner

| Component | State | Verification done |
|---|---|---|
| `wg1` (10.250.0.1/16, udp 51821) | up, `wg-quick@wg1` enabled | pubkey == `INSURANCE_SERVER_WG_PUBLIC_KEY` (`5J3k7H/…efGw=`); 236 peers loaded; MTU **1420** (AWS had jumbo 8921 — deliberate change); SNAT rule for 10.250.0.2→ppp+ replicated via PostUp |
| xl2tpd | active, enabled | same conf (ip range 10.250.0.100–10.250.199.255, local 10.250.0.1); `/etc/ppp/chap-secrets` 77 entries |
| strongSwan (IKEv1 PSK for ROS6 l2tp) | active via `strongswan-starter` | Ubuntu 26.04 gotcha: strongSwan 6 disables the stroke plugin — created `/etc/strongswan.d/charon/stroke.conf` (`load = yes`); default `strongswan.service` (swanctl flavor) disabled to avoid dual charon; `l2tp-vpn` conn loaded, listeners on 500/4500 |
| `insurance_wg_manager` | up, restart unless-stopped | image `isp-insurance-wg-manager:latest` (docker save/load from 35.170); host net + NET_ADMIN + /etc/ppp bind; **container command must be `uvicorn main:app --host 0.0.0.0 --port 8729`** (image default Cmd is --uds — the TCP bind was a run-time override on the old box too); authenticated `/peers` returns 236 |
| INPUT guard | `billing-input-guard.service` (systemd oneshot, enabled) | 8729 accepts only 54.91.202.229/32 + loopback, drops rest. Additive INPUT rules only — FORWARD/NAT for wg-egress untouched |
| `pull-svc` | up, `0.0.0.0:8443->8000` | app+queue copied to /home/deploy/pullsvc + /home/deploy/pullpoc; same PULL_* env (writes still allowed only from 54.91.202.229) |

## Notes / gotchas recorded

- 142 of the 236 wg1 peers have **no allowed-ips** (stale registrations that never completed). They were preserved as handshake-only peers. Fleet hygiene cleanup is backlog, not blocking.
- Peer persistence: `SaveConfig = true` on wg1 (same as source box) — runtime-added peers survive clean shutdown/reboot.
- Secrets (wg private key, WG_MANAGER_SECRET, chap-secrets, IPsec PSK, PULL_TOKEN) were piped server→server and never written to the operator machine or logs.
- Fork source captured into `wg-manager-insurance/` in this repo (it previously existed ONLY as a container on the box slated for retirement). It adds `/test-router` and runs TCP via CLI override.

## What H3 needs (the pivot — requires Dennis's explicit go)

1. Freeze all insurance applies/batches (operator discipline — no admin UI batch runs).
2. Final delta sync: re-run the wg1 peer clone + chap-secrets copy (routers provisioned since 2026-08-06 would otherwise be missing).
3. On prod `.env`: `INSURANCE_SERVER_PUBLIC_IP=91.98.238.12`, `INSURANCE_WG_MANAGER_URL=http://91.98.238.12:8729`, add `PULL_SERVICE_URL=http://91.98.238.12:8443` (needs compose passthrough from H6 first — or defer pull-svc pivot until H6 code lands).
4. Restart **only** the `web` container.
5. Verify: insurance status read for an already-backed-up router; new registrations land on Hetzner.

Rollback: revert the 3 env lines, restart web.

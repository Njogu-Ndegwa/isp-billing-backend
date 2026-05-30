# Server Migration Runbook

Prepared: 2026-05-27

## Goal

Move the ISP billing platform from the current AWS server with a changing public IP to the new AWS server with a static Elastic IP, without losing management connectivity between the platform and MikroTik routers.

The most important rule is:

> Do not break the existing router-to-server tunnel while building the new path.

This runbook is based on the current repo design:

- Existing WireGuard/L2TP management network: `10.0.0.0/16`
- Existing server VPN IP: `10.0.0.1`
- WireGuard router IP range: `10.0.0.2` to `10.0.99.255`
- L2TP router IP range: `10.0.100.0` to `10.0.199.255`
- Router API access is currently restricted to `10.0.0.1/32`
- FreeRADIUS currently trusts `10.0.0.0/16`
- `docker-compose.yml` currently hard-codes `SERVER_PUBLIC_IP=54.91.202.229`

AWS reference:

- Elastic IP addresses are static public IPv4 addresses for EC2/VPC use: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html
- Elastic IPs can be associated with EC2 instances and related AWS resources: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-eips.html

## Existing Project Docs

Useful files already in this repo:

- `WIREGUARD_SETUP.md`
- `WIREGUARD_QUICK_START.md`
- `MIKROTIK_VPN_README.md`
- `SETUP_SUMMARY_WIREGUARD.md`
- `ROUTER_SETUP_GUIDE.md`
- `CAPTIVE_PORTAL_SETUP.md`
- `RADIUS_SETUP.md`
- `docker-compose.yml`
- `app/services/provisioning.py`
- `radius/clients.conf`

## Key Principle

Use the new server first as an insurance/control path, then migrate production traffic after it has proven router reachability.

Do not replace the old tunnel endpoint first. Build the second path next to it.

Do not add a second WireGuard peer on the same `wg-aws` interface with the same broad `10.0.0.0/16` allowed-address. That can cause route ambiguity and break the active path.

## Recommended Target Design

Keep the existing production management network unchanged during preparation:

```text
Old production VPN: 10.0.0.0/16
Old server VPN IP:  10.0.0.1
```

Add a separate insurance network on the new server:

```text
New insurance VPN: 10.250.0.0/16
New server VPN IP: 10.250.0.1
```

Map router IPs predictably:

```text
Old router IP     Insurance router IP
10.0.0.5       -> 10.250.0.5
10.0.0.33      -> 10.250.0.33
10.0.100.12    -> 10.250.100.12
```

This gives every router two management paths:

```text
Current app/server -> 10.0.x.y router IP
New server         -> 10.250.x.y router IP
```

## Phase 1: Prepare New AWS Server

1. Confirm the new server uses an Elastic IP.

   It must not be an auto-assigned public IPv4 address.

2. Configure AWS Security Group inbound rules.

   Minimum:

   ```text
   TCP 22        SSH, restricted to your admin IP
   TCP 80/443    API/domain traffic
   UDP 51820     future primary WireGuard
   UDP 51821     secondary insurance WireGuard
   UDP 500       L2TP/IPsec if supporting RouterOS v6
   UDP 4500      L2TP/IPsec NAT-T
   UDP 1701      L2TP
   ```

   Keep RADIUS public ports closed unless absolutely required. RADIUS should stay over VPN.

3. Install base packages.

   ```bash
   sudo apt update
   sudo apt install -y docker.io docker-compose-plugin wireguard wireguard-tools iproute2 iptables
   ```

4. Install L2TP/IPsec packages if RouterOS v6 routers are still used.

   The exact package set depends on how the current server is configured. Preserve the same implementation as the current production server.

5. Copy required secrets and config from old server.

   Some values are referenced in `docker-compose.yml`, but do not assume the
   compose file is a complete backup. It mostly wires environment variables into
   containers. The real values usually live in `.env`, host files, Docker
   volumes, or the database.

   Copy and store securely:

   ```text
   .env                         actual runtime env values
   SECRET_KEY                  usually inside .env or exported shell env
   MPESA_* credentials          usually inside .env or exported shell env
   L2TP_IPSEC_PSK               may be in .env; compose has a default only
   /etc/wireguard               host VPN keys/config; not fully backed by compose
   /etc/ppp/chap-secrets        host L2TP users; mounted into wg-manager
   Apache2 config               required if Apache routes public traffic
   SSL certificates             required if TLS terminates on Apache
   database backup              Postgres data is in a Docker volume, not in compose
   ```

   In the current `docker-compose.yml`, note these migration-sensitive entries:

   ```text
   SERVER_PUBLIC_IP=54.91.202.229
   WG_MANAGER_SECRET=${WG_MANAGER_SECRET:-change-me-wg-secret}
   L2TP_IPSEC_PSK=${L2TP_IPSEC_PSK:-BitwaveL2TP2026!Secure}
   MPESA_CALLBACK_URL=${MPESA_CALLBACK_URL}
   postgres_data:/var/lib/postgresql/data
   /etc/ppp:/etc/ppp
   wg_sock:/var/run/wg-manager
   ```

   `postgres_data` and `wg_sock` are Docker volumes. Their contents are not
   inside the compose file. `/etc/ppp` is a host directory mount and must be
   copied from the server if L2TP routers are used.

   If Apache2 is the reverse proxy on the current server, back up at least:

   ```text
   /etc/apache2/sites-available/
   /etc/apache2/sites-enabled/
   /etc/apache2/apache2.conf
   /etc/apache2/ports.conf
   /etc/apache2/conf-available/
   /etc/apache2/conf-enabled/
   /etc/letsencrypt/
   ```

   Also record enabled Apache modules:

   ```bash
   apache2ctl -M
   ```

   Common modules needed for this kind of setup are:

   ```text
   proxy
   proxy_http
   proxy_wstunnel
   ssl
   rewrite
   headers
   remoteip
   ```

   On the new server, enable equivalent modules before switching DNS:

   ```bash
   sudo a2enmod proxy proxy_http proxy_wstunnel ssl rewrite headers remoteip
   sudo apache2ctl configtest
   sudo systemctl reload apache2
   ```

6. Clone or deploy the repo on the new server.

7. Do not start the new app as production yet.

   Two active apps can double-run expiry cleanup, payment reconciliation, background provisioning, and router cleanup jobs.

8. Recreate Apache2 routing on the new server.

   Install Apache if needed:

   ```bash
   sudo apt update
   sudo apt install -y apache2
   sudo a2enmod proxy proxy_http proxy_wstunnel ssl rewrite headers remoteip
   ```

   Restore or recreate the virtual hosts from the old server. Confirm they
   proxy to the same backend ports used by Docker, usually:

   ```text
   app/API: http://127.0.0.1:8000
   HTTP:    port 80
   HTTPS:   port 443
   ```

   Before DNS cutover, test the new Apache config with a local host override or
   direct request using the domain as the Host header:

   ```bash
   sudo apache2ctl configtest
   curl -I -H "Host: isp.bitwavetechnologies.net" http://127.0.0.1/
   ```

   Only after this works should DNS be pointed to the new Elastic IP.

## Phase 2: Configure Insurance WireGuard On New Server

Use a second WireGuard interface, for example `wg1`.

Example server config:

```ini
[Interface]
Address = 10.250.0.1/16
ListenPort = 51821
PrivateKey = <NEW_INSURANCE_SERVER_PRIVATE_KEY>
```

Enable it:

```bash
sudo systemctl enable wg-quick@wg1
sudo systemctl start wg-quick@wg1
sudo wg show wg1
```

For each WireGuard router, add a new independent tunnel:

```routeros
/interface wireguard add name=wg-aws2 listen-port=51821
/ip address add address=10.250.X.Y/16 interface=wg-aws2
/interface wireguard peers add interface=wg-aws2 public-key="<NEW_SERVER_WG1_PUBLIC_KEY>" endpoint-address=<NEW_ELASTIC_IP> endpoint-port=51821 allowed-address=10.250.0.0/16 persistent-keepalive=25
```

Then update router API access without removing the old access:

```routeros
/ip service set api address=10.0.0.1/32,10.250.0.1/32 port=8728 disabled=no
/ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.250.0.1 action=accept comment="Allow API from new AWS insurance VPN" place-before=0
```

Add the new Elastic IP to hotspot walled garden:

```routeros
/ip hotspot walled-garden ip add dst-address=<NEW_ELASTIC_IP>/32 action=accept comment="New AWS backend API"
```

On the new server, register the router peer:

```bash
sudo wg set wg1 peer <ROUTER_WG_AWS2_PUBLIC_KEY> allowed-ips 10.250.X.Y/32 persistent-keepalive 25
```

Test from new server:

```bash
ping -c 3 10.250.X.Y
nc -vz 10.250.X.Y 8728
```

Test from old/current server too:

```bash
ping -c 3 10.0.X.Y
nc -vz 10.0.X.Y 8728
```

Only continue if both paths work.

## Phase 3: Configure Insurance Path For L2TP Routers

For RouterOS v6/L2TP routers, add a second L2TP client such as `l2tp-aws2`.

Do not disable or edit the current `l2tp-aws` yet.

Router side:

```routeros
/interface l2tp-client add name=l2tp-aws2 connect-to=<NEW_ELASTIC_IP> user="<NEW_L2TP_USER>" password="<NEW_L2TP_PASSWORD>" disabled=no allow=mschap2,mschap1 add-default-route=no comment="Insurance management VPN to new AWS"
/interface l2tp-client set [find where name=l2tp-aws2] use-ipsec=yes ipsec-secret=<L2TP_IPSEC_PSK>
```

On the new server, add a fixed L2TP user/IP mapping:

```text
<NEW_L2TP_USER>    l2tp-server    "<NEW_L2TP_PASSWORD>"    10.250.100.X
```

Then append API access:

```routeros
/ip service set api address=10.0.0.1/32,10.250.0.1/32 port=8728 disabled=no
/ip firewall filter add chain=input protocol=tcp dst-port=8728 src-address=10.250.0.1 action=accept comment="Allow API from new AWS insurance VPN" place-before=0
```

Test both paths before moving to the next router.

## Phase 4: Rollout Order

Use batches.

1. Pilot one low-risk WireGuard router.
2. Pilot one low-risk L2TP router.
3. Wait and monitor for at least 30-60 minutes.
4. Expand to 5 routers.
5. Expand to 20 routers.
6. Complete all routers.

For every router, record:

```text
Router ID
Router name
Current DB IP
Insurance IP
VPN type
Old path test result
New path test result
API test result
Walled garden updated
Rollback notes
```

## Phase 5: Keep New Server Ready

Before production cutover, the new server should already have:

- Latest application image/code
- `.env` configured
- Database backup restore tested
- WireGuard installed
- Insurance VPN working
- L2TP/IPsec working if required
- FreeRADIUS container tested
- SSL certificates ready
- Apache virtual hosts and proxy rules tested
- API domain ready
- M-Pesa callback paths verified
- Walled garden updated on routers
- Monitoring for router reachability

Keep production background jobs disabled on the new app until cutover.

## Emergency Procedure If Old Server Fails

If the old server dies before planned migration:

1. Start the new server primary VPN as a mirror of the old server.

   Use:

   ```text
   VPN IP: 10.0.0.1
   Existing WireGuard server private key
   Existing WireGuard peer list
   Existing L2TP users and fixed IPs
   Existing L2TP/IPsec PSK
   ```

2. Use the insurance tunnel to reach each router.

3. Update the existing primary endpoint on every router to the new Elastic IP.

   WireGuard:

   ```routeros
   /interface wireguard peers set [find where interface=wg-aws] endpoint-address=<NEW_ELASTIC_IP>
   ```

   L2TP:

   ```routeros
   /interface l2tp-client set [find where name=l2tp-aws] connect-to=<NEW_ELASTIC_IP>
   ```

4. Restore the latest database backup on the new server.

5. Start app, FreeRADIUS, and wg-manager.

6. Point DNS and payment callbacks to the new server.

7. Validate:

   ```text
   Router health endpoint
   Router API login
   Hotspot registration
   Voucher activation
   M-Pesa callback
   RADIUS auth/accounting
   Expired-user cleanup
   Dashboard analytics
   ```

This keeps router DB IPs as `10.0.x.y`, so the app does not need emergency database changes.

## Planned Production Cutover

### 48 Hours Before

1. Lower DNS TTL.
2. Verify SSL on new server.
3. Verify M-Pesa callback domain.
4. Verify C2B/B2B callback domains if used.
5. Confirm every router has working insurance tunnel.
6. Confirm every router has new Elastic IP in walled garden.
7. Take a fresh DB backup and test restore on new server.

### During Cutover

1. Stop old app background workers and web container.
2. Keep old VPN running temporarily if possible.
3. Take final database dump.
4. Restore final dump to new server.
5. Start primary VPN mirror on new server with `10.0.0.1`.
6. Start new app, FreeRADIUS, and wg-manager.
7. Update router primary endpoints to new Elastic IP in batches.
8. Test one real router end-to-end.
9. Update DNS to new server.
10. Update provider callback URLs if they are IP-based or point to old host.

### After Cutover

Monitor for at least 24 hours:

```text
WireGuard latest handshakes
L2TP sessions
MikroTik API connection failures
FreeRADIUS auth failures
FreeRADIUS accounting
Payment callback success
Provisioning retries
Expired-user cleanup
Router availability checks
Docker logs
Disk usage
CPU and memory
```

Keep old server available for 24-72 hours as rollback, but do not run the old app background jobs.

## Rollback Plan

If the new server fails during planned cutover:

1. Stop new app background workers.
2. Repoint DNS back to old server.
3. Change router primary endpoints back to old server public IP if they were changed.
4. Start old app.
5. Verify old server still reaches routers on `10.0.x.y`.
6. Investigate failure on new server using logs and one pilot router only.

## Codebase Follow-Up

The current app stores one management IP per router in `Router.ip_address`.

Long-term, add true failover fields:

```text
primary_mgmt_ip
secondary_mgmt_ip
active_mgmt_path
last_primary_ok_at
last_secondary_ok_at
```

Then shared MikroTik connection logic can try:

1. primary IP
2. secondary IP
3. mark selected path status
4. expose active path in admin UI

Until that exists, the insurance tunnel gives manual emergency access, but automatic application failover is not complete.

## Admin-Triggered Backup Tunnel Endpoint

The scalable approach is now:

```text
Old/current app continues normal operations over 10.0.0.0/16.
Superadmin clicks "Create Backup Tunnel" for one router.
Old/current app connects to the router over the existing tunnel.
Old/current app creates or repairs wg-aws2 on the router.
Old/current app calls wg-manager on the new server to register the router peer.
New server verifies ping and TCP 8728 over 10.250.X.Y.
```

New app settings required on the old/current app server:

```env
INSURANCE_WG_MANAGER_URL=http://35.170.199.141:8729
INSURANCE_WG_MANAGER_SECRET=<same value as GitHub secret NEW_SERVER_WG_MANAGER_SECRET>
INSURANCE_SERVER_PUBLIC_IP=35.170.199.141
INSURANCE_SERVER_WG_PUBLIC_KEY=5J3k7H/s3aDQU7vIOUMEa/2YinVidQ2vfqjSkegefGw=
INSURANCE_SERVER_VPN_IP=10.250.0.1
INSURANCE_WG_PORT=51821
INSURANCE_ROUTER_INTERFACE=wg-aws2
INSURANCE_WG_SUBNET=10.250.0.0/16
```

GitHub Actions deployment split:

```text
.github/workflows/deploy.yml
  Production deploy only.
  Guarded to refs/heads/main.
  Uses existing SERVER_* secrets.

.github/workflows/deploy-insurance-wg-manager.yml
  New server wg-manager deploy only.
  Guarded to refs/heads/migration-new-server.
  Uses NEW_SERVER_* secrets.
```

Required GitHub secrets for the new-server wg-manager workflow:

```text
NEW_SERVER_HOST=35.170.199.141
NEW_SERVER_USER=<ssh user, e.g. dennis>
NEW_SERVER_PASSWORD=<ssh password>
NEW_SERVER_WG_MANAGER_SECRET=<strong shared secret>
```

Required AWS inbound rule on the new server:

```text
TCP 8729 from 54.91.202.229/32 only
```

Endpoint shape:

```text
POST /api/admin/routers/{router_id}/insurance-wireguard
```

Dry run body:

```json
{ "apply": false }
```

Apply body:

```json
{ "apply": true }
```

Force key rotation only when intentionally replacing an existing backup tunnel:

```json
{ "apply": true, "force_rotate": true }
```

## Do Not Do These

- Do not edit the existing router peer before testing the second path.
- Do not remove `10.0.0.1/32` API access from routers.
- Do not run old and new app background jobs at the same time.
- Do not change DNS before database restore and router reachability are proven.
- Do not reuse broad `10.0.0.0/16` allowed-address on a second peer on the same WireGuard interface.
- Do not rely on a public auto-assigned EC2 IP as the final server endpoint.

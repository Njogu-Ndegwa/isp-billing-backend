# Server Access (SSH) And Deploy Runbook

How agents and operators connect to our servers non-interactively, how to deploy,
and how to grant the same capability on any new server.

Never commit SSH private keys, passwords, or router credentials to this repo.
Public keys are safe to share; private keys live only on the operator's machine.

## Current Production Server

- Connect: `ssh -o BatchMode=yes root@91.98.238.12` (Hetzner CX, Nuremberg,
  hostname `egress-nbg1` — the name is historical: this box started life as the
  router-110 Starlink egress relay and became the primary on 2026-09-22. It IS
  the right server.)
- Auth: SSH key pair on the operator machine at `~/.ssh/id_ed25519`. No password
  needed; agents and scripts must use `ssh -o BatchMode=yes ...` so a broken key
  setup fails fast instead of hanging on a password prompt. Password auth is
  disabled on this box and must stay disabled.
- The box has 3.7 GiB RAM (about 2.1 GiB free under normal load) — roughly four
  times the old AWS box. Diagnostic commands are fine; check `free -h` before
  anything heavy (an image build takes ~2 GiB while it runs).
- What runs there (docker): `isp_billing_hetzner_app` (FastAPI, port 8000,
  loopback-only; Caddy fronts 80/443), `isp_billing_hetzner_db` (Postgres 15),
  `isp_billing_hetzner_radius`, `isp-admin` (admin frontend),
  `insurance_wg_manager_hz` (wg2 tunnel manager, `10.251.0.0/16`, UDP 51823,
  manager API :8730), `pull-svc`.
- App code lives in a git clone at `/opt/isp-billing-shadow/repo` tracking
  `origin/main`. The directory name says "shadow" for historical reasons; the
  stack there is live (`.env.hetzner` has `SHADOW_MODE=false`,
  `RUN_SCHEDULER=true`).
- Router control path: the DB still stores routers as `10.0.X.Y`. The host
  routes each one natively through its wg2 peer (`10.251.X.Y`) when the
  `isp-native-router-routes.timer` (30 s, `ops/native-router-route-sync.py`)
  has verified TCP 8728 through it, and otherwise falls back to
  `wg-aws-transit` via the AWS box (~298 ms vs ~134 ms native). So scripts keep
  using the stored `10.0.X.Y` address; they never need to know which path is in
  use.
- Public health check: `curl -sI https://isp.bitwavetechnologies.net/health`
  must show `x-served-by: hetzner-api` and `X-ISP-Runtime-Mode: active`.

## Deploy Runbook (backend)

CI does this on every push to `main` (`.github/workflows/deploy.yml`, step
"Deploy to Hetzner"). The manual equivalent, for when CI is red or a hotfix
needs to go out by hand:

```bash
ssh -o BatchMode=yes root@91.98.238.12
cd /opt/isp-billing-shadow/repo
grep -E '^SHADOW_MODE=' .env.hetzner      # must be false — never deploy onto a shadow stack
git fetch origin main && git reset --hard origin/main   # deploys exactly what is on origin/main
docker compose --env-file .env.hetzner -f docker-compose.hetzner.yml build web
docker compose --env-file .env.hetzner -f docker-compose.hetzner.yml up -d --no-deps web
```

The image is built ON the host (`isp-billing-hetzner:candidate`), not pulled
from Docker Hub. Never run `docker compose down` here — it takes the database
and RADIUS down with the app; `up -d --no-deps web` recreates only the app.

Post-deploy checks:

```bash
docker ps --filter name=isp_billing_hetzner_app     # Up (healthy), RestartCount 0
docker exec isp_billing_hetzner_app python -c "import urllib.request;print(urllib.request.urlopen('http://localhost:8000/health',timeout=5).read()[:200])"
docker logs --since 5m isp_billing_hetzner_app 2>&1 | grep -E "Application startup complete|ERROR|Traceback"
curl -sI https://isp.bitwavetechnologies.net/health | grep -Ei 'x-served-by|x-isp-runtime-mode'
```

The customer portal (`isp-landing-page` repo) deploys separately: push to
`master` on GitHub and Vercel builds it automatically.

## AWS Fenced Standby (old production, 54.91.202.229)

- Connect: `ssh -o BatchMode=yes dennis@54.91.202.229` (AWS EC2, hostname
  `ip-172-31-23-68`, 1 GB RAM + 2 GB swap). Same operator key as above.
- Since 2026-09-22 this box is a FENCED standby. `isp_billing_postgres`,
  `isp_billing_radius` and `isp_wg_manager` keep running because its WireGuard
  (`10.0.0.0/16`) and L2TP/IPsec tunnels still carry transit for routers that
  have no native Hetzner path yet.
- **`isp_billing_app` there MUST STAY STOPPED.** On 2026-09-22 15:55 UTC the old
  CI step restarted it; its scheduler ran against the stale AWS database and the
  safety-net deleted 1,062 paid-client router bindings in 90 minutes. Never
  `docker compose up` on that box, never point CI at it, never start the app
  "just to check something" — its database is no longer the source of truth.
- App code there: `~/apps/isp-billing`. Left in place for rollback only.
- The other AWS box, the old Elastic-IP insurance server `35.170.199.141`, is
  retired. The insurance plane is Hetzner wg2 (`10.251.0.0/16`).

## Granting The Same Capability On A New Server

One-time setup per new server (this is how the Hetzner box `91.98.238.12` was onboarded):

1. On the operator machine, reuse the existing key pair (preferred — one key,
   many servers) or create one: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`.
   On Windows the key is at `C:\Users\<user>\.ssh\id_ed25519`.
2. Print the PUBLIC key (safe to copy anywhere):
   - Windows: `type %USERPROFILE%\.ssh\id_ed25519.pub`
   - Linux/macOS: `cat ~/.ssh/id_ed25519.pub`
3. Log in to the new server once the manual way (password, EC2 key, or console)
   and append the public key:

   ```bash
   mkdir -p ~/.ssh && chmod 700 ~/.ssh
   echo '<paste the ssh-ed25519 AAAA... line here>' >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   ```

4. Verify non-interactive access from the operator machine:

   ```bash
   ssh -o BatchMode=yes <user>@<new-server-ip> "echo KEY-LOGIN-OK"
   ```

   If this prints `KEY-LOGIN-OK` without asking anything, agents can use the
   server. If it says `Permission denied`, the key was not installed correctly
   (wrong user's home dir and file permissions are the usual culprits).
5. Optionally add an alias in `~/.ssh/config` on the operator machine:

   ```
   Host isp-prod
       HostName 91.98.238.12
       User root
   ```

   Then `ssh isp-prod` works everywhere a hostname does.
6. Recommended hardening once key login is verified: disable SSH password
   authentication on the server (`PasswordAuthentication no` in
   `/etc/ssh/sshd_config`, then `sudo systemctl restart sshd`) and restrict
   port 22 at the cloud firewall to known IPs. Both current boxes are key-only
   (AWS since 2026-07-21, Hetzner from its 2026-07-16 rebuild).

## Ground Rules For Agents On Servers

- Read-only diagnostics freely; anything that changes state (restarts, config
  edits, deletes) needs explicit operator approval in the conversation.
- Direct `psql` into the production database is restricted; prefer logs and the
  admin API endpoints.
- Check `free -h` before heavy work. The Hetzner box has headroom the old one
  never had, but the deploy build still takes ~2 GiB while it runs — do not
  stack a build on top of another memory-heavy one-off. On the AWS standby
  (1 GB) the old rule stands: nothing memory-hungry at all.

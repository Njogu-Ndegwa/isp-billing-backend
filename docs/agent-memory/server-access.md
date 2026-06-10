# Server Access (SSH) And Deploy Runbook

How agents and operators connect to our servers non-interactively, how to deploy,
and how to grant the same capability on any new server.

Never commit SSH private keys, passwords, or router credentials to this repo.
Public keys are safe to share; private keys live only on the operator's machine.

## Current Production Server

- Connect: `ssh dennis@54.91.202.229` (AWS, hostname `ip-172-31-23-68`).
- Auth: SSH key pair on the operator machine at `~/.ssh/id_ed25519`
  (public key comment `claude-code-dennis`, installed 2026-06-10). No password
  needed; agents and scripts must use `ssh -o BatchMode=yes ...` so a broken key
  setup fails fast instead of hanging on a password prompt.
- The box has 1 GB RAM + 2 GB swap and runs production — diagnostic commands
  (`free -h`, `docker logs`, `grep`) are fine; avoid anything memory-hungry.
- What runs there (docker): `isp_billing_app` (FastAPI, port 8000),
  `isp_billing_postgres`, `isp_billing_radius`, `isp_wg_manager`.
- App code lives in a git clone at `~/apps/isp-billing` tracking `origin/main`.

## Deploy Runbook (backend)

```bash
ssh dennis@54.91.202.229
cd ~/apps/isp-billing
git pull                      # main only — deploys exactly what is on origin/main
docker compose build web      # fast: pip layer cached unless requirements.txt changed
docker compose up -d web      # ~5-10s downtime while the container restarts
```

Post-deploy checks:

```bash
docker ps --filter name=isp_billing_app          # Up, RestartCount 0
docker logs --since 5m isp_billing_app 2>&1 | grep -E "Application startup complete|ERROR|Traceback"
curl -s "http://localhost:8000/api/admin/db-pool"   # needs auth token; or watch logs
```

The customer portal (`isp-landing-page` repo) deploys separately: push to
`master` on GitHub and Vercel builds it automatically.

## Granting The Same Capability On A New Server

One-time setup per new server (e.g. the AWS migration server `35.170.199.141`):

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
       HostName 54.91.202.229
       User dennis
   ```

   Then `ssh isp-prod` works everywhere a hostname does.
6. Recommended hardening once key login is verified: disable SSH password
   authentication on the server (`PasswordAuthentication no` in
   `/etc/ssh/sshd_config`, then `sudo systemctl restart sshd`) and restrict
   port 22 in the AWS security group to known IPs. As of 2026-06-10 the
   production server still accepts a weak password — this hardening is pending.

## Ground Rules For Agents On Servers

- Read-only diagnostics freely; anything that changes state (restarts, config
  edits, deletes) needs explicit operator approval in the conversation.
- Direct `psql` into the production database is restricted; prefer logs and the
  admin API endpoints.
- Mind the 1 GB RAM: no builds or memory-heavy one-liners beyond the documented
  deploy flow (its docker build is cheap only because layers are cached).

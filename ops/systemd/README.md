# L2TP service recovery

`xl2tpd-recovery.conf` is a systemd drop-in for the primary AWS server's
Debian/Ubuntu SysV-generated `xl2tpd.service`. It makes systemd track the real
daemon PID, stop its PPP child processes as one unit, and retry a failed start.

`xl2tpd-native-recovery.conf` is the smaller drop-in for Hetzner's native
systemd unit. That unit already tracks the process and its PPP children
correctly; it only needs `Restart=on-failure` instead of `Restart=on-abort`.

`isp-native-router-routes.service` and `.timer` run
`ops/native-router-route-sync.py` on the active Hetzner host. The reconciler
keeps the application's established `10.0.X.Y` router addresses unchanged but
adds a more-specific route through the matching `10.251.X.Y` Hetzner peer. A
new route requires both a recent tunnel signal and reachable TCP 8728. Once a
native route is selected, a transient API probe miss does not remove it while
the tunnel remains alive. Every run also re-asserts two `10.0.0.0/16`
fallbacks for routers that have no native `/32`: the AWS-transit route over
`wg-aws-transit` (metric 400) and a blackhole (metric 427). Traffic uses
transit while that interface is up and is dropped only if transit is gone, so
a router that has not moved to Hetzner yet stays reachable through AWS.

The script is stateless. The only state it owns is the `/32` routes it tags
with `proto 186` and the extra `10.0.X.Y/32` it appends to a wg2 peer's
allowed-ips. `--dry-run` prints the plan as JSON without changing anything.

Install it on the VPN host without interrupting the running daemon:

```bash
sudo install -d -m 0755 /etc/systemd/system/xl2tpd.service.d
sudo install -m 0644 ops/systemd/xl2tpd-recovery.conf \
  /etc/systemd/system/xl2tpd.service.d/recovery.conf
sudo systemctl daemon-reload
sudo systemctl show xl2tpd \
  -p PIDFile -p GuessMainPID -p RemainAfterExit -p KillMode \
  -p Restart -p RestartUSec -p StartLimitIntervalUSec
```

`daemon-reload` does not restart `xl2tpd`; the current L2TP sessions remain in
place. Do not deliberately restart the production service merely to test this
drop-in. Verify the next maintenance-triggered restart through the admin
management-tunnel panel and the system journal.

On Hetzner, install the native-unit drop-in at the same destination instead:

```bash
sudo install -d -m 0755 /etc/systemd/system/xl2tpd.service.d
sudo install -m 0644 ops/systemd/xl2tpd-native-recovery.conf \
  /etc/systemd/system/xl2tpd.service.d/recovery.conf
sudo systemctl daemon-reload
sudo systemctl show xl2tpd -p Restart -p RestartUSec -p StartLimitIntervalUSec
```

Install the native router-route reconciler without restarting the application
or either tunnel service:

```bash
sudo install -m 0755 ops/native-router-route-sync.py \
  /usr/local/sbin/isp-native-router-route-sync
sudo install -m 0644 ops/systemd/isp-native-router-routes.service \
  /etc/systemd/system/isp-native-router-routes.service
sudo install -m 0644 ops/systemd/isp-native-router-routes.timer \
  /etc/systemd/system/isp-native-router-routes.timer
sudo systemctl daemon-reload
sudo systemctl enable --now isp-native-router-routes.timer
```

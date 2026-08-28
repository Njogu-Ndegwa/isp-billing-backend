# L2TP service recovery

`xl2tpd-recovery.conf` is a systemd drop-in for the primary AWS server's
Debian/Ubuntu SysV-generated `xl2tpd.service`. It makes systemd track the real
daemon PID, stop its PPP child processes as one unit, and retry a failed start.

`xl2tpd-native-recovery.conf` is the smaller drop-in for Hetzner's native
systemd unit. That unit already tracks the process and its PPP children
correctly; it only needs `Restart=on-failure` instead of `Restart=on-abort`.

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

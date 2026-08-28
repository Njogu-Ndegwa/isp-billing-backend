# L2TP service recovery

`xl2tpd-recovery.conf` is a systemd drop-in for Debian/Ubuntu's generated
`xl2tpd.service`. It makes systemd track the real daemon PID, stop its PPP child
processes as one unit, and retry a failed start.

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

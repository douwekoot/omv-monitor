# Monitoring

Docker Compose project in `/opt/omv-monitor`, history kept 7 days.

## Components

- Prometheus, on loopback 127.0.0.1:9090.
- node-exporter, on loopback 127.0.0.1:9100, also reads the textfile directory.
- blackbox exporter, on loopback 127.0.0.1:9115: ping 192.168.1.1, ping 1.1.1.1, DNS lookup.
- Textfile timer: `omv-wg-metrics.sh` writes WireGuard peer and host posture metrics (forwarding, NAT, INPUT policy, SSH password auth) for node-exporter.
- Web app: https://192.168.1.10:8443, read-only except the confirmed actions on the [network actions](network-actions) page.

## Safety

Nothing in the stack can change routing, firewall or WireGuard.

- `omv-host-metrics.timer` (every 5 min) runs `omv-host-metrics.sh`: SMART disk health, container status and TLS certificate expiry for the dashboard and advisories. Install like `omv-alerts` (copy the unit files to `/etc/systemd/system/`, then enable the timer).
- Restore drill: `tools/restore_drill.py` restores the newest backup archives into a scratch dir and checks the app starts from them.

## Email alerts

See [alerts](alerts). Backups: see [backups](backups).

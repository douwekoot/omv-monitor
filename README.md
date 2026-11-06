# omv-monitor

A self-hosted monitor and wiki for a single OpenMediaVault (Debian) home server that also acts as a WireGuard gateway. One admin, LAN/VPN only, no external services.

It shows host health, traffic, WireGuard peers, services, connectivity checks and backups; raises findings and advisories from the host's security posture; mails alerts; and offers a few confirmed, audited actions (restart an allowlisted service, edit a WireGuard peer with automatic revert, start a device backup).

## Architecture

`monitor/compose.yaml` runs four host-network containers:

- **Prometheus** on loopback, 7-day retention
- **node-exporter**, also reading a textfile directory written by host timers
- **blackbox-exporter** for ping and DNS checks
- **web**: Flask app (`monitor/app/`) served by gunicorn over TLS on port 8443, read-only root filesystem, non-root user

Data flow: host scripts and exporters → Prometheus → `app/prom.py` → `app/data.py` (PromQL shaped into rows) → `app/web.py` → Jinja templates. Charts are server-rendered SVG; `static/chart.js` only adds hover readouts.

Host-side pieces live in `monitor/host/` (systemd units and scripts, installed under `/opt/omv-monitor` and `/etc/systemd/system/`):

- `omv-wg-metrics` / `omv-host-metrics`: WireGuard, posture, SMART, container and certificate metrics for node-exporter
- `omv-alerts`: mails new findings, keeps alert history
- `omv-backup`: backs up config, wiki, settings and Prometheus data to the NAS
- `omv-device-backup`: restic backups of other machines over SSH (`tools/device-backup-setup.sh` prepares a device)
- `omv-netctl`: the only root helper the web app can call; every action needs a confirm step and is audited
- `omv-restrict-8443`: limits the web port to trusted sources

## Setup

1. Copy `monitor/` to `/opt/omv-monitor` on the server.
2. Create `monitor/.env` from `.env.example` and set at least `APP_ADMIN_PASSWORD` and `APP_SECRET_KEY`.
3. Put a TLS certificate in `certs/tls.crt` and `certs/tls.key`.
4. Edit `config/monitor.toml` (alert thresholds, retention, and the `[[services]]` to watch; `restart = true` adds a restart button), `config/backups.toml` (backup targets) and `config/devices.toml` (WireGuard IP → device name). The files are validated at startup; a bad key fails loudly. Change the example addresses (`192.168.1.x`, `10.8.0.x`) throughout to your own network.
5. Mail alerts read SMTP settings from `secrets/smtp.env` (`OMV_SMTP_HOST`, `OMV_SMTP_USER`, `OMV_SMTP_PASSWORD`). Set the recipient with `OMV_ALERT_TO` in `/etc/omv-monitor/alerts.env`.
6. `docker compose up -d --build`, then install and enable the units from `monitor/host/`.

## Security model

- TLS only, single admin password plus TOTP, CSRF on every form, login rate limiting
- Strict CSP (`default-src 'self'`), no external assets; fonts are self-hosted
- The app cannot change routing, firewall or WireGuard except through `omv-netctl`'s allowlisted actions; WireGuard edits revert after 60 s unless kept
- Unknown values show as "n/a" rather than being guessed
- Device backups: `tools/device-backup-setup.sh` gives the `omvbackup` account passwordless root on the device (the runner needs `sudo sh -c`, `restic` and `shutdown`). Anyone holding the server's backup key for that device is effectively root on it; `authorized_keys` only accepts the key from the server's addresses.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -r monitor/requirements.txt
.venv/bin/pytest
.venv/bin/python tools/preview_sandbox.py   # local preview with fake data
```

Tests use a fake Prometheus client (`tests/conftest.py`); no server is needed.

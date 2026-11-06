# Alerts

`omv-alerts.timer` runs `host/omv-alerts.py` every 60 s. It mails new findings over SMTP (the recipient defaults to the address in the script; override it with `OMV_ALERT_TO` in `/etc/omv-monitor/alerts.env`, not in `smtp.env`) and records every raised and cleared finding or advisory in `data/alert-history.jsonl`, which the Alerts page shows. History is kept for `alert_history_days` from `config/monitor.toml`.

Findings that mail: the web app or Prometheus unreachable, a WireGuard peer with a stale handshake, a failing disk, an expiring certificate, a failing connectivity check, an overdue backup. A finding is mailed once; it is mailed again only after it has cleared and returned. If sending fails, the next run retries. Sends are audited as `alert-email`.

## Thresholds

Defaults are in `config/monitor.toml` (`disk_pct`, `handshake_stale_s`, `backup_age_h`). Change them in Settings; the values are stored as overrides in the settings JSON, and **Reset** returns to the defaults. A bad value in the TOML file stops the app at startup and names the file and key.

## SMTP setup

On the host, as root:

1. Create `/opt/omv-monitor/secrets/smtp.env`, mode 600, owned by root (`secrets/` is never mounted into the web container):
   ```
   OMV_SMTP_HOST=<smtp server, SSL on port 465>
   OMV_SMTP_USER=<login, also used as sender>
   OMV_SMTP_PASSWORD=<app password>
   ```
   Use an app-specific password, never the account password. If a password was ever pasted anywhere, revoke it and create a new one.
2. Install and enable: copy `omv-alerts.service` and `omv-alerts.timer` from `/opt/omv-monitor/host/` to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now omv-alerts.timer`.
3. Check: `systemctl start omv-alerts.service && journalctl -u omv-alerts -n 20`.

If the file is missing or incomplete the service fails and logs that it cannot read the SMTP settings.

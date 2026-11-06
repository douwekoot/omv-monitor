# Network actions

The dashboard can change a few things on omv-monitor from the **Network** page. Every change goes through a small root helper (`omv-netctl`) on the host; the web app itself stays unprivileged.

## What you can do

- **Restart a service.** Only these units are allowed: wg-quick@wgnet1 (WireGuard), omv-monitor (this page) and every `[[services]]` entry in `config/monitor.toml` with `restart = true`. The helper re-reads that file on each request; anything else is refused.
- **Edit a WireGuard peer.** Rename it (the name is only a label in the dashboard), enable or disable it, or change its `allowed_ips`. Disabling removes the peer from the live interface and keeps its settings, so enabling brings it back.
- **Restore a snapshot.** Before every WireGuard change the helper saves the current configuration. You can restore one from the Network page.

- **Run a backup now.** On a backup target page, **Run now** starts that target's backup through the same helper. See [backups](backups).

Adding and removing peers is **not available yet**.

## The confirm step

Every action first shows a confirm page that says what will change. Nothing happens until you press the button on that page. If the change affects the connection you are using, the page warns you.

## Auto-revert (60 seconds)

WireGuard changes take effect at once and are undone by the helper after 60 seconds unless you press **Keep** on the Network page. **Undo** reverts immediately. Only one change can be pending at a time. If the helper restarts with a change pending, it reverts it on start. Renames and service restarts are not reverted (a restart cannot be undone).

If a change cuts your connection, wait 60 seconds: the revert does not need your connection.

## Snapshots

Snapshots are `wg showconf` files in `/var/lib/omv-netctl/snapshots/` (mode 0600, the latest few are kept). Each starts with a comment line holding its id, time and summary.

## Audit log

Every action, including refused and failed ones, is recorded in `data/audit.jsonl` (in the monitor's data directory, `/opt/omv-monitor/data/`), with time, action, arguments, result and client address. The Network page shows the recent entries.

## One-time helper install

On the host, as root:

1. Copy the files:
   `cp /opt/omv-monitor/host/omv-netctl.service /etc/systemd/system/` (the script is run from `/opt/omv-monitor/host/omv-netctl.py`, so copy the repository's `monitor/host/` there).
2. Set the environment with `systemctl edit omv-netctl`:
   ```
   [Service]
   # The web container runs as uid/gid 10001 (app).
   Environment=OMV_NETCTL_GID=10001
   Environment=OMV_NETCTL_ENDPOINT=<public host:port of wgnet1, used for client configs>
   ```
   `OMV_NETCTL_GID` becomes the group owner of the socket, so the web app can reach it. `OMV_NETCTL_ENDPOINT` is only needed for peer add, which is not available yet.
3. Enable it: `systemctl daemon-reload && systemctl enable --now omv-netctl`.
4. Check: `systemctl status omv-netctl` and `ls -l /run/omv-netctl/netctl.sock`. The web container mounts `/run/omv-netctl` and finds the socket through `APP_NETCTL_SOCKET` (set in `compose.yaml`).

Without the helper the Network page still shows service state, but changes are unavailable.

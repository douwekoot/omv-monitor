# Backups

Two kinds of backup exist.

- **omv-backup** (`host/omv-backup.sh`, timer): config, wiki, settings and Prometheus archives on the NAS, downloadable from the dashboard.
- **Device backups** (`host/omv-device-backup.py`): restic repositories for three targets, all stored on a separate NAS disk (`destination_root` in `config/backups.toml`, one repo per target below it).

| Target | What | How |
|---|---|---|
| omv | the server itself | restic runs on the server |
| pc | desktop PC (Fedora) | server wakes it with Wake-on-LAN if needed, restic runs on the PC over SSH, the PC is shut down again only if the server woke it |
| laptop | laptop (Fedora) | restic over SSH on the LAN or the WireGuard IP; skipped when unreachable |

## Content categories

- omv: `omv-config` (/etc/openmediavault plus a confdb dump), `host-config` (/etc), `compose` (stacks in /opt, .env files included), `monitor-data` (config, wiki, data, Prometheus data), `nas-data` (NAS data disks; the backup disk itself is excluded).
- pc and laptop: `home`, `system-settings` (/etc), `gnome-settings` (dconf dump), `packages` (rpm, dnf repos, flatpak lists), `users` (passwd and group, no password hashes).

## Schedule, retention, include and exclude

Defaults come from `config/backups.toml`. Changes made under **Backup settings** on a target page (and the destination root in Settings) are saved as overrides in `data/backup-overrides.json`; the TOML file is not rewritten. A target runs when `interval_h` has passed since its last run: `omv-device-backup.timer` checks every 15 minutes. **Run now** on the target page (confirm and audit step, through `omv-netctl`) starts one immediately. Every page shows one state per target: ok, overdue, failed, n/a (no metrics) or disabled. A backup older than `backup_age_h` (Settings) raises an advisory; it becomes a finding when the last run failed or the backup is more than twice that old. Disabled targets raise nothing.

## Restore

List snapshots on the host, as root. For omv use the repo path directly; for pc and laptop the repo is on the NAS disk, so the same command works on the server:

```
restic -r <destination_root>/<name> --password-file /opt/omv-monitor/secrets/restic-<name>.pass snapshots
```

- **omv (single file or folder):** `restic ... restore latest --target /root/restore --include /etc/openmediavault`, then copy back what you need. OMV settings: `confdb-dump.txt` inside the snapshot is the database dump. Stacks: restore `/opt/<stack>` and run `docker compose up -d --build` there.
- **omv (whole server):** reinstall OMV, install restic, restore `latest` to a scratch dir, copy `/etc/openmediavault`, `/opt` and the data back, reboot, check the dashboard. Prometheus data is copied live, so the newest WAL may be lost.
- **pc / laptop:** on the server run `restic ... restore latest --target /srv/restore-<name>`, then copy files to the device, or run restic on the device with `-r sftp:<user>@<NAS>:<repo>`. Settings: `dconf load / < dconf-<user>.ini` as that user. Packages: reinstall from `rpm.txt` and `flatpak.txt`.
- **Never restore over a running system without a scratch copy first.**

## Download a folder from the app

The **Download** section on a target page lists the snapshots of that repo. Pick a snapshot, enter one folder (an absolute path inside the snapshot, for example `/home/user/Documents`) and press **Prepare download**; a confirm step follows, and the request is audited.

`omv-netctl` starts `omv-device-export@<name>.service`, which runs `restic dump --archive tar` on the server into `<destination_root>/.exports/`. The archive is readable only by the web container's user. While it runs the page shows **preparing**; reload to see the download link, or **failed** with restic's message. Downloads are audited too. `omv-device-backup.timer` deletes an archive about an hour after it is ready (a stuck `.part` after 6 hours).

- The export needs as much free space on the NAS disk as the folder. It refuses to run when `destination_root` is not on its own disk.
- `compose.yaml` mounts `<destination_root>/.exports` at `/app/exports` read-only. If `destination_root` changes, change that mount too.
- Whole snapshots are not offered: use the restore commands above for those.

## Restore drill

Proves a repository can be restored. The script is not deployed to the host: run it from a repo checkout (it needs access to the repositories, so as root on the host or with the NAS disk reachable), per target:

```
python3 tools/restore_drill.py --target omv
python3 tools/restore_drill.py --target pc
python3 tools/restore_drill.py --target laptop
```

It restores the newest snapshot into a scratch dir under `destination_root`, counts the files, and removes it. For the omv-backup archives: `python3 tools/restore_drill.py <dir with archives>`. Do this after setting up a target, and again after any change to its categories.

## Manual setup checklist

Status (2026-10-31): omv and pc are set up and backed up; the laptop target is disabled until step 5 and 6 are done on it. On a Fedora device, steps 2, 5, 6 (device side), 7 and 8 are done by `sudo bash tools/device-backup-setup.sh pc|laptop`; it prints the root key to add on the server. The backup user on server and devices is `omvbackup`.

1. **Separate NAS disk.** Mount it (OMV file system, or `/etc/fstab` with a UUID) and set `destination_root` to its mount path. The runner refuses a path on the system disk.
2. **Install restic** on the server and on the Fedora devices: `dnf install restic` (Debian: `apt install restic`).
3. **Passwords.** For each target create `/opt/omv-monitor/secrets/restic-<name>.pass` (random, long), `chmod 600`, root-owned. Keep a copy in your password manager: without it the repo is unreadable.
4. **Repos.** The runner runs `restic init` itself if the repo is missing. To do it by hand: `restic -r <destination_root>/<name> --password-file secrets/restic-<name>.pass init`.
5. **SSH keys, server to devices.** As root on the server make a key (`ssh-keygen -t ed25519`) and `ssh-copy-id <user>@<device>` for pc and laptop. The runner uses BatchMode, so it must work without a prompt. The device user needs passwordless sudo for `restic` (and `shutdown` on the pc): add a sudoers.d file for it.
6. **SSH keys, devices to NAS.** The device runs restic with `sftp:<user>@<NAS>:<repo>` as root (via sudo). Put root's public key from each device in the NAS user's `authorized_keys`, and accept the host key once by hand. That NAS user must be the same account as the `sftp:<user>@` in the target's repo setting, and must be allowed to write to `destination_root`.
7. **Wake-on-LAN on the PC.** Enable it in BIOS/UEFI (wake on PCIe/LAN, deep sleep off). Then in Fedora: `nmcli connection modify <connection> 802-3-ethernet.wake-on-lan magic` (or `ethtool -s <nic> wol g`), and check with `ethtool <nic>` (Wake-on: g). Put the NIC's real MAC in `mac` for the pc target.
8. **Passwordless shutdown on the PC** for the backup user: sudoers rule for `/usr/sbin/shutdown`. Needed only because `shutdown_after_wol = true`.
9. **Laptop over WireGuard.** The laptop's WireGuard IP (see `config/devices.toml`) is the second entry in `hosts`, so it is reached away from home. Check that its peer is enabled.
10. **Timer.** Copy `omv-device-backup.service`, `omv-device-backup@.service` and `omv-device-backup.timer` from `/opt/omv-monitor/host/` to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now omv-device-backup.timer`. Run one target by hand first: `systemctl start omv-device-backup@omv.service` and read `journalctl -u 'omv-device-backup@omv'`.
11. **Prometheus retention.** Set `PROM_RETENTION` in `/opt/omv-monitor/.env` (default `7d`) and `docker compose up -d`. Keep it in line with `prometheus` in `config/monitor.toml`.
12. **Email.** Set up [alerts](alerts) so an overdue backup reaches you.

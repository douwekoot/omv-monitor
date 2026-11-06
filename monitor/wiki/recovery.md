# Recovery

Use this if the network or VPN is unreachable, for example after a firewall change.

## Steps

1. Go to the physical console (keyboard and screen) of omv-monitor, and log in locally.
2. Check the link: `ip addr show enp2s0` and `ip route`. The router is 192.168.1.1.
3. Check WireGuard: `wg show wgnet1`. Restart with `systemctl restart wg-quick@wgnet1`.
4. If a firewall change locked you out, restore the ACCEPT policies: `iptables -P INPUT ACCEPT`.
5. Check forwarding: `sysctl net.ipv4.ip_forward` should be 1.
6. Restart the monitoring stack: `cd /opt/omv-monitor && docker compose up -d`.

## Restoring from backups

See [backups](backups) for restoring the server or a device from its restic repository.

## After a network action from the dashboard

See [network actions](network-actions) for how these work.

**A restart failed.** The audit log (`/opt/omv-monitor/data/audit.jsonl`) holds the error. On the host run `systemctl status <unit>` and `journalctl -u <unit> -n 50`, fix the cause, then `systemctl restart <unit>`. A failed restart of `omv-monitor` takes this page down: use the console and `cd /opt/omv-monitor && docker compose up -d`.

**A WireGuard change locked you out.** Do nothing for 60 seconds: the helper reverts the change by itself. If it did not, restore a snapshot from the console:

1. List them: `ls -t /var/lib/omv-netctl/snapshots/` (the first line of each file says what it was taken before).
2. Apply one: `wg syncconf wgnet1 /var/lib/omv-netctl/snapshots/<id>.conf`. The files are `wg showconf` output, so syncconf accepts them directly.
3. Make it permanent: `wg-quick save wgnet1`.

Or use the Network page (Restore) once you can reach it again.

**The helper is down.** The Network page shows changes as unavailable. On the host run `systemctl status omv-netctl` and `journalctl -u omv-netctl -n 50`, then `systemctl restart omv-netctl`. The socket is `/run/omv-netctl/netctl.sock`; if it is missing, the helper is not running. A pending change is reverted when the helper starts.

## Lost the authenticator app (TOTP)

Sign-in needs the password plus a 6-digit code. If the phone is gone, use one of the 10 one-time recovery codes shown at setup. If those are gone too, reset on the host: delete the state file with `rm /opt/omv-monitor/data/totp.json`. The next password login shows the setup page again with a new secret and new recovery codes. The file is also backed up under `secrets/totp` on the NAS.

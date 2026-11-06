#!/bin/bash
# One-time setup on a Fedora device so omv-monitor can back it up with restic.
#   sudo bash tools/device-backup-setup.sh pc|laptop
# Afterwards the server needs this device's root key (printed at the end) in
# /var/lib/omvbackup/.ssh/authorized_keys; see wiki: backups.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
case "${1:-}" in
  pc) KEY='ssh-ed25519 REPLACE_WITH_SERVER_BACKUP_KEY omv-backup-pc' ;;
  laptop) KEY='ssh-ed25519 REPLACE_WITH_SERVER_BACKUP_KEY omv-backup-laptop' ;;
  *) echo "usage: $0 pc|laptop"; exit 1 ;;
esac

dnf install -y -q restic ethtool

# Backup user: no password, key-only login from the server's LAN and WireGuard address.
id omvbackup >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "OMV backup" omvbackup
passwd -l omvbackup >/dev/null
install -d -m 700 -o omvbackup -g omvbackup /home/omvbackup/.ssh
echo "from=\"192.168.1.10,10.8.0.254\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding $KEY" > /home/omvbackup/.ssh/authorized_keys
chown omvbackup:omvbackup /home/omvbackup/.ssh/authorized_keys
chmod 600 /home/omvbackup/.ssh/authorized_keys
restorecon -R /home/omvbackup/.ssh 2>/dev/null || true

# The runner uses `sudo -n sh -c`, `sudo -n restic` and `sudo -n shutdown`: root without a prompt.
# WARNING: this makes omvbackup root on this device. Narrowing the rule does not help much: `sudo restic restore`
# alone can overwrite any file. Treat the server's backup key (secrets/ssh-<target>) like this device's root
# password; authorized_keys above only accepts it from the server's addresses.
echo 'omvbackup ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/omvbackup
chmod 440 /etc/sudoers.d/omvbackup
visudo -cf /etc/sudoers.d/omvbackup

# Root on the device pushes to the NAS over sftp as omvbackup@server.
install -d -m 700 /root/.ssh
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -C "root@$(hostname) restic" -f /root/.ssh/id_ed25519
touch /root/.ssh/known_hosts
grep -q '^192.168.1.10 ' /root/.ssh/known_hosts || cat >> /root/.ssh/known_hosts <<'EOF'
EOF

if [ "$1" = pc ]; then  # Wake-on-LAN (magic packet) on the wired connection; BIOS must allow it too
  nmcli connection modify Ethernet 802-3-ethernet.wake-on-lan magic
  ethtool -s enp42s0 wol g || true
fi
systemctl enable --now sshd
echo "Done. Add this key on the server (wiki: backups, step 6):"
cat /root/.ssh/id_ed25519.pub

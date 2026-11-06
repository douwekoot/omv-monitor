#!/bin/sh
# Writes WireGuard and host-posture metrics for node_exporter's textfile collector.
set -eu
IF=wgnet1; DIR=/var/lib/node_exporter/textfile; TMP="$DIR/.omv.$$"
APP=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$DIR"
{
  wg show "$IF" dump | tail -n +2 | awk -F'\t' -v i="$IF" '{
    # Base64url form of the key prefix: a "/" would break the detail-page URL.
    k = substr($1,1,8); gsub(/\//, "_", k); gsub(/\+/, "-", k)
    l = sprintf("interface=\"%s\",peer=\"%s\",allowed_ips=\"%s\"", i, k, $4)
    print "omv_wg_latest_handshake_timestamp_seconds{" l "} " $5
    print "omv_wg_received_bytes_total{" l "} " $6
    print "omv_wg_sent_bytes_total{" l "} " $7 }'
  echo "omv_ip_forward $(cat /proc/sys/net/ipv4/ip_forward)"
  echo "omv_nat_masquerade $(iptables -t nat -S POSTROUTING | grep -c -- '-o enp2s0 -j MASQUERADE' || true)"
  # 1 = no default deny: policy ACCEPT and no catch-all REJECT/DROP rule (OMV's firewall uses the latter).
  echo "omv_input_policy_accept $(iptables -S INPUT | awk '/^-P INPUT ACCEPT/{p=1} /^-A INPUT -j (REJECT|DROP)/{d=1} END{print (p && !d) ? 1 : 0}')"
  echo "# TYPE omv_service_active gauge"
  # [[services]] in config/monitor.toml, through the app's validated loader (names are [a-z0-9@._-] only).
  # An unusable file yields no service metrics, which the dashboard shows as n/a.
  for s in $(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from app import config
print(" ".join(s["unit"] for s in config.load_monitor(sys.argv[1] + "/config/monitor.toml")["services"]))' "$APP"); do
    # A service may be a systemd unit or a Docker container of that name.
    if systemctl is-active --quiet "$s" || [ "$(docker inspect -f '{{.State.Running}}' "$s" 2>/dev/null)" = true ]; then v=1; else v=0; fi
    echo "omv_service_active{service=\"$s\"} $v"
  done
  echo "omv_ssh_password_auth $(sshd -T | grep -c '^passwordauthentication yes' || true)"
} > "$TMP"
mv "$TMP" "$DIR/omv.prom"

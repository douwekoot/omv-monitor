#!/bin/sh
# Limit TCP 8443 (the monitor) to ALLOWED sources. Usage: omv-restrict-8443 apply|revert
# Rules sit at INPUT position 3, after loopback and ESTABLISHED, ahead of OMV's subnet accepts.
# OMV regenerates INPUT on every firewall deploy; the unit re-runs this afterwards.
set -eu
ALLOWED="192.168.1.20 10.8.0.0/24"  # PC on the LAN, whole VPN subnet

revert() {
  for ip in $ALLOWED; do
    while iptables -D INPUT -s "$ip" -p tcp --dport 8443 -j ACCEPT 2>/dev/null; do :; done
  done
  while iptables -D INPUT -p tcp --dport 8443 -j REJECT 2>/dev/null; do :; done
}

case "${1:-}" in
  apply)
    revert
    # REJECT first, then accepts in front of it: a failure part-way leaves 8443 closed, never open.
    iptables -I INPUT 3 -p tcp --dport 8443 -j REJECT
    for ip in $ALLOWED; do iptables -I INPUT 3 -s "$ip" -p tcp --dport 8443 -j ACCEPT; done
    ;;
  revert) revert ;;
  *) echo "usage: $0 apply|revert" >&2; exit 2 ;;
esac

#!/bin/sh
# Writes SMART health, container status and TLS cert expiry, pending apt upgrades and reboot-required for node_exporter's textfile collector.
# A missing tool or failing command omits its metric; nothing is guessed.
set -eu
DIR=${OMV_TEXTFILE_DIR:-/var/lib/node_exporter/textfile}; CERT=${OMV_CERT:-/opt/omv-monitor/certs/tls.crt}
REBOOT=${OMV_REBOOT_FLAG:-/var/run/reboot-required}
TMP="$DIR/.omv-host.$$"
mkdir -p "$DIR"
trap 'rm -f "$TMP"' EXIT
{
  if command -v smartctl >/dev/null 2>&1 && devs=$(smartctl --scan 2>/dev/null); then
    echo "$devs" | awk '{print $1}' | while read -r dev; do
      # -n standby: never wake a sleeping disk; its output has no verdict, so it is omitted.
      out=$(smartctl -H -n standby "$dev" 2>/dev/null || true)
      name=${dev##*/}
      case "$out" in
        *FAILED*) echo "omv_smart_healthy{device=\"$name\"} 0" ;;
        *PASSED*|*"health status: OK"*|*"Status: OK"*) echo "omv_smart_healthy{device=\"$name\"} 1" ;;
      esac
    done
  fi
  if command -v docker >/dev/null 2>&1 && names=$(docker ps -a --format '{{.Names}} {{.State}}' 2>/dev/null); then
    echo "$names" | while read -r n s; do
      [ -n "$n" ] || continue
      if [ "$s" = running ]; then v=1; else v=0; fi
      echo "omv_container_running{name=\"$n\"} $v"
    done
  fi
  if command -v openssl >/dev/null 2>&1 && [ -r "$CERT" ] && end=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null) \
     && ts=$(date -d "${end#notAfter=}" +%s 2>/dev/null); then
    echo "omv_cert_expiry_timestamp_seconds $ts"
  fi
  # Pending upgrades from a simulated upgrade (needs no root); the summary line wins over counting "Inst" lines.
  if command -v apt-get >/dev/null 2>&1 && sim=$(LC_ALL=C apt-get -s upgrade 2>/dev/null); then
    echo "$sim" | awk '/^Inst /{n++} /^[0-9]+ upgraded,/{n=$1; s=1} END{print "omv_apt_upgrades_pending " n+0}'
  fi
  if [ -e "$REBOOT" ]; then echo "omv_reboot_required 1"; else echo "omv_reboot_required 0"; fi
} > "$TMP"
mv "$TMP" "$DIR/omv-host.prom"

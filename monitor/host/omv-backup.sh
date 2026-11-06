#!/bin/sh
# Backs up the monitor's state to the NAS, one folder per kind of data.
#   files/<kind>/    config, wiki, settings, prometheus: the web app offers these for download
#   secrets/<kind>/  env, certs, totp: root only, never mounted into a container
set -eu
SRC=${OMV_MONITOR_DIR:-/opt/omv-monitor}
DEST=${OMV_BACKUP_DIR:-/srv/dev-disk-by-uuid-CHANGE-ME/internal/backups/omv-monitor}
KEEP_DAYS=${OMV_BACKUP_KEEP_DAYS:-14}
PROM=${OMV_PROM_DIR:-$(docker volume inspect -f '{{.Mountpoint}}' omv-monitor_prom-data)}
STAMP=$(date +%Y-%m-%d_%H%M)

# pack <files|secrets> <kind> <dir> <path...>: tar paths relative to dir, publish atomically.
pack() {
  out="$DEST/$1/$2"; kind=$2; dir=$3; shift 3
  mkdir -p "$out"
  tmp="$out/.$kind-$STAMP.tmp"; rc=0
  tar -C "$dir" ${EXCL:+"$EXCL"} -czf "$tmp" "$@" || rc=$?
  # GNU tar exits 1 when a file changed while read: expected for Prometheus' live TSDB.
  if [ "$rc" -gt 1 ] || { [ "$rc" -eq 1 ] && [ "$kind" != prometheus ]; }; then rm -f "$tmp"; return 1; fi
  mv "$tmp" "$out/$kind-$STAMP.tar.gz"
}

mkdir -p "$DEST/files" "$DEST/secrets"
chown root:root "$DEST/secrets" 2>/dev/null || true
chmod 755 "$DEST" "$DEST/files"
chmod 700 "$DEST/secrets"

umask 022
pack files config "$SRC" config
pack files wiki "$SRC" wiki
EXCL=--exclude='data/totp*.json' pack files settings "$SRC" data
pack files prometheus "$PROM" .

umask 077
pack secrets env "$SRC" .env
pack secrets certs "$SRC" certs
[ ! -e "$SRC/data/totp.json" ] || pack secrets totp "$SRC" data/totp.json

find "$DEST/files" "$DEST/secrets" -name '*.tar.gz' -mtime +"$KEEP_DAYS" -delete

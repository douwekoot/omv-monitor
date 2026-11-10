#!/bin/bash
# Runs on omv-monitor, fed by tools/deploy.sh. Applies the staged monitor/ tree to the live stack.
#   deploy-remote.sh plan       list what would change, change nothing
#   deploy-remote.sh apply      snapshot, copy, install changed systemd units, rebuild, verify
#   deploy-remote.sh rollback   restore the newest snapshot and rebuild
# Paths and commands can be overridden for tests (OMV_DIR, OMV_STAGE, OMV_UNIT_DIR, OMV_SNAP_DIR, OMV_SKIP_SERVICES).
set -euo pipefail
DIR=${OMV_DIR:-/opt/omv-monitor}
STAGE=${OMV_STAGE:-/var/tmp/omv-deploy.stage}
UNITS=${OMV_UNIT_DIR:-/etc/systemd/system}
SNAPS=${OMV_SNAP_DIR:-/var/tmp}
KEEP=5
URL=https://192.168.1.10:8443/login
# Server-only state: never in git, never overwritten or snapshotted here.
LOCAL_ONLY='^(\.env|certs|data|secrets)(/|$)'

changes() {
  # Paths (relative to DIR) that the stage adds or changes. Files removed from git are left on the server.
  (cd "$STAGE" && find . -type f -printf '%P\n') | sort | while read -r f; do
    cmp -s "$STAGE/$f" "$DIR/$f" || echo "$f"
  done | grep -Ev "$LOCAL_ONLY" || true
}

services() {
  [ -n "${OMV_SKIP_SERVICES:-}" ] && { echo "(skipped: $*)"; return 0; }
  "$@"
}

rebuild() {
  local changed=$1
  services systemctl daemon-reload
  services docker compose -f "$DIR/compose.yaml" --project-directory "$DIR" up -d --build
  if grep -qE '^(prometheus|blackbox)/' <<<"$changed"; then
    services docker compose -f "$DIR/compose.yaml" --project-directory "$DIR" restart prometheus blackbox
  fi
}

verify() {
  [ -n "${OMV_SKIP_SERVICES:-}" ] && return 0
  for _ in $(seq 15); do
    [ "$(curl -sk -m 3 -o /dev/null -w '%{http_code}' "$URL")" = 200 ] && { echo "OK: dashboard answers 200"; return 0; }
    sleep 2
  done
  echo "FAILED: dashboard does not answer. Undo with: tools/deploy.sh --rollback" >&2
  return 1
}

case "${1:-}" in
plan)
  c=$(changes)
  if [ -z "$c" ]; then echo "Server is up to date."; else echo "Would update:"; sed 's/^/  /' <<<"$c"; fi
  ;;
apply)
  c=$(changes)
  if [ -z "$c" ]; then echo "Server is up to date; nothing to do."; rm -rf "$STAGE"; exit 0; fi
  echo "Updating:"; sed 's/^/  /' <<<"$c"
  snap="$SNAPS/omv-monitor-pre-deploy-$(date +%Y-%m-%d_%H%M%S).tar.gz"
  # umask only for the snapshot: the cp below must keep files readable by the non-root web container
  (umask 077; tar -C "$DIR" --exclude=./.env --exclude=./certs --exclude=./data --exclude=./secrets -czf "$snap" .)
  chmod 600 "$snap"
  echo "Snapshot: $snap"
  ls -1t "$SNAPS"/omv-monitor-pre-deploy-*.tar.gz | tail -n +$((KEEP + 1)) | xargs -r rm -f
  rm -rf "$STAGE/.env" "$STAGE/certs" "$STAGE/data" "$STAGE/secrets"
  cp -r --no-preserve=ownership "$STAGE/." "$DIR/"
  rm -rf "$STAGE"
  for u in "$DIR"/host/*.service "$DIR"/host/*.timer; do
    [ -e "$u" ] || continue
    t="$UNITS/$(basename "$u")"
    [ -e "$t" ] || continue  # only units that were installed before; new ones are enabled by hand
    cmp -s "$u" "$t" || { install -m 600 "$u" "$t"; echo "Unit updated: $(basename "$u")"; }
  done
  rebuild "$c"
  verify
  ;;
rollback)
  snap=$(ls -1t "$SNAPS"/omv-monitor-pre-deploy-*.tar.gz 2>/dev/null | head -1)
  [ -n "$snap" ] || { echo "No snapshot found in $SNAPS." >&2; exit 1; }
  echo "Restoring $snap"
  tar -C "$DIR" -xzf "$snap"
  for u in "$DIR"/host/*.service "$DIR"/host/*.timer; do
    t="$UNITS/$(basename "$u")"
    if [ -e "$t" ] && ! cmp -s "$u" "$t"; then install -m 600 "$u" "$t"; echo "Unit restored: $(basename "$u")"; fi
  done
  rebuild "prometheus/ blackbox/"
  verify
  # The restored snapshot stays, so a second rollback restores the same state rather than an older one.
  ;;
*)
  echo "usage: deploy-remote.sh plan|apply|rollback" >&2; exit 2
  ;;
esac

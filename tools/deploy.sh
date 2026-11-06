#!/bin/bash
# Deploy the committed monitor/ tree to omv-monitor without going through Claude.
#   tools/deploy.sh             deploy HEAD
#   tools/deploy.sh <ref>       deploy a branch, tag or commit
#   tools/deploy.sh --dry-run   show which files would change, change nothing
#   tools/deploy.sh --rollback  restore the server to the snapshot taken before the last deploy
# Only committed files are sent; uncommitted work in your checkout never reaches the server.
# .env, certs/ and data/ on the server are never touched.
set -euo pipefail
HOST=${OMV_HOST:-root@192.168.1.10}
STAGE=/var/tmp/omv-deploy.stage
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
REMOTE="$ROOT/tools/deploy-remote.sh"

mode=apply
case "${1:-}" in
  -n|--dry-run) mode=plan; shift ;;
  --rollback) mode=rollback; shift ;;
  -h|--help) sed -n '2,8s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac
ref=${1:-HEAD}

if [ "$mode" = rollback ]; then
  read -r -p "Restore $HOST to the snapshot from before the last deploy? [y/N] " ok
  [ "$ok" = y ] || [ "$ok" = Y ] || exit 1
  ssh "$HOST" 'bash -s -- rollback' < "$REMOTE"
  exit
fi

commit=$(git -C "$ROOT" rev-parse --short --verify "$ref^{commit}")
echo "Deploying $commit: $(git -C "$ROOT" log -1 --format=%s "$commit")"
if [ -n "$(git -C "$ROOT" status --porcelain -- monitor)" ]; then
  echo "Note: uncommitted changes in monitor/ are not deployed:"
  git -C "$ROOT" status --short -- monitor | sed 's/^/  /'
fi

git -C "$ROOT" archive "$commit" monitor | ssh "$HOST" "rm -rf $STAGE && mkdir -p $STAGE && tar -C $STAGE --strip-components=1 -xf -"
ssh "$HOST" "bash -s -- plan" < "$REMOTE"
[ "$mode" = plan ] && { ssh "$HOST" "rm -rf $STAGE"; exit 0; }

read -r -p "Deploy this to $HOST? [y/N] " ok
if [ "$ok" != y ] && [ "$ok" != Y ]; then ssh "$HOST" "rm -rf $STAGE"; echo "Cancelled."; exit 1; fi
ssh "$HOST" "bash -s -- apply" < "$REMOTE"

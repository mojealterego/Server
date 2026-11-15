#!/usr/bin/env bash
# Restore only to a brand-new path; never overwrite existing contents.
set -Eeuo pipefail
umask 077
if (( $# != 2 ));then echo 'Usage: restore.sh crypt-remote:prefix/SNAPSHOT_ID NEW_DESTINATION' >&2;exit 2;fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE="$1"
[[ "$REMOTE" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_./-]+$ && "$REMOTE" != *'..'* ]] || {
  echo 'Invalid remote snapshot path' >&2;exit 2;
}
remote_name="${REMOTE%%:*}"
snapshot_id="${REMOTE##*/}"
[[ "$snapshot_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{5,79}$ ]] || { echo 'Invalid snapshot identifier' >&2;exit 2; }
DEST="$2"
[[ ! -e "$DEST" && ! -L "$DEST" ]] || { echo 'Destination already exists; refuse overwrite' >&2;exit 2; }
parent="$(dirname -- "$DEST")"
[[ -d "$parent" && ! -L "$parent" ]] || { echo 'Destination parent missing/unsafe' >&2;exit 2; }
DEST="$parent/$(basename -- "$DEST")"
command -v rclone >/dev/null || { echo 'rclone missing' >&2;exit 1; }
command -v python3 >/dev/null || { echo 'python3 missing' >&2;exit 1; }
[[ "$(rclone config show "$remote_name" | grep -E '^type = ' | head -1)" == 'type = crypt' ]] || {
  echo 'Restore remote must be rclone crypt' >&2;exit 1;
}
state="${OMEGA_STATE_DIR:-$HOME/.omega-x}"
key="${OMEGA_MANIFEST_KEY_FILE:-$state/manifest-hmac.key}"
[[ -f "$key" && ! -L "$key" ]] || { echo 'Private HMAC key missing; restore cannot authenticate' >&2;exit 1; }
stage="$(mktemp -d "$parent/.omega-restore.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
rclone copy "$REMOTE" "$stage" --transfers 2 --checkers 4 --retries 3 --low-level-retries 5
python3 "$ROOT/tools/snapshot_manifest.py" verify "$stage" "$key" --id "$snapshot_id"
# Fail closed against TOCTOU race; mv -T destination must not preexist.
[[ ! -e "$DEST" && ! -L "$DEST" ]] || { echo 'Destination appeared while restoring' >&2;exit 2; }
# Linux renameat2(NOREPLACE) for guaranteed no-overwrite is used through helper.
python3 "$ROOT/tools/atomic_publish.py" "$stage" "$DEST"
trap - EXIT
echo "[OMEGA] Authenticated snapshot restored to $DEST"

#!/usr/bin/env bash
# Immutable encrypted independent snapshots + local HMAC authenticator.
set -Eeuo pipefail
umask 077
if (( $# < 3 )); then
  echo 'Usage: backup.sh SOURCE crypt1:path crypt2:path [...]' >&2; exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$(realpath -- "$1")"; shift
[[ -d "$SOURCE" ]] || { echo 'Source missing' >&2; exit 2; }
[[ ! -L "$SOURCE" ]] || { echo 'Source symlink refused' >&2; exit 2; }
if [[ -n "$(find "$SOURCE" \( -type l -o -type p -o -type s -o -type b -o -type c \) -print -quit)" ]]; then
  echo 'Source contains symlink or nonregular file; refusing backup' >&2; exit 2
fi
command -v python3 >/dev/null || { echo 'Python 3 missing' >&2; exit 1; }
command -v rclone >/dev/null || { echo 'rclone missing' >&2; exit 1; }
command -v flock >/dev/null || { echo 'flock missing' >&2; exit 1; }
state="${OMEGA_STATE_DIR:-$HOME/.omega-x}"
mkdir -p "$state" && chmod 700 "$state"
exec 9>"$state/compute-io.lock"
flock -n 9 || { echo 'Compute/backup lock held' >&2; exit 75; }
key="${OMEGA_MANIFEST_KEY_FILE:-$state/manifest-hmac.key}"
python3 "$ROOT/tools/snapshot_manifest.py" keygen "$key" >/dev/null
names=' '
remotes=("$@")
for remote in "${remotes[@]}"; do
  [[ "$remote" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_./-]+$ && "$remote" != *'..'* ]] || {
    echo "Invalid target: $remote" >&2;exit 2;
  }
  name="${remote%%:*}"
  [[ "$names" != *" $name "* ]] || { echo 'Duplicate remote alias' >&2;exit 2; }
  names+="$name "
  rclone listremotes | grep -Fxq -- "$name:" || { echo "Remote missing: $name" >&2;exit 1; }
  [[ "$(rclone config show "$name" | grep -E '^type = ' | head -1)" == 'type = crypt' ]] || {
    echo "Remote must use crypt: $name" >&2;exit 1;
  }
done
stamp="${OMEGA_SNAPSHOT_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(python3 -c 'import secrets;print(secrets.token_hex(6))')}"
[[ "$stamp" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{5,79}$ ]] || { echo 'Bad snapshot id' >&2;exit 2; }
work="$(mktemp -d "$state/snapshot.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
python3 "$ROOT/tools/snapshot_manifest.py" create "$SOURCE" "$work/SHA256SUMS"
python3 "$ROOT/tools/snapshot_manifest.py" seal "$work" "$stamp" "$key"
failed=0
for remote in "${remotes[@]}";do
  target="${remote%/}/$stamp"
  echo "[OMEGA] Copy $SOURCE -> $target"
  if ! rclone copy "$SOURCE" "$target" --immutable --transfers 2 --checkers 4 \
       --retries 3 --low-level-retries 5 --stats 30s;then
    echo "[FAIL] remote copy $target" >&2;failed=1;continue
  fi
  if ! rclone check "$SOURCE" "$target" --download --one-way;then
    echo "[FAIL] remote byte verification $target" >&2;failed=1;continue
  fi
  if ! python3 "$ROOT/tools/snapshot_manifest.py" verify-files "$SOURCE" "$work/SHA256SUMS";then
    echo "[FAIL] source modified during transfer; snapshot NOT committed" >&2;failed=1;break
  fi
  if ! rclone copyto "$work/SHA256SUMS" "$target/SHA256SUMS" --immutable;then
    echo "[FAIL] manifest upload $target" >&2;failed=1;continue
  fi
  # Final commit marker is uploaded last. Restore refuses snapshots lacking it.
  if ! rclone copyto "$work/COMPLETE.json" "$target/COMPLETE.json" --immutable;then
    echo "[FAIL] commit marker upload $target" >&2;failed=1;continue
  fi
  echo "[OK] encrypted remote verified and HMAC receipt uploaded: $target"
done
if (( failed ));then
  echo '[OMEGA] Partial replication. Do not claim complete multi-cloud backup.' >&2
  exit 1
fi
echo "[OMEGA] ${#remotes[@]} remote snapshots committed; ID=$stamp"

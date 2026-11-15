#!/usr/bin/env bash
# OMEGA-X: convenience UNION view of *existing* encrypted remotes.
# This is NOT independent proof of replicated backups; use backup.sh.
set -euo pipefail
if (( $# < 3 )); then
  echo 'Usage: make_union.sh omega-mirror crypt1:path crypt2:path [cryptN:path...]' >&2
  exit 2
fi
NAME="$1"; shift
[[ "$NAME" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]] || { echo 'Invalid union name' >&2; exit 2; }
command -v rclone >/dev/null || { echo 'rclone is required' >&2; exit 1; }
if rclone listremotes | grep -Fxq -- "$NAME:"; then
  echo 'Existing remote will not be overwritten' >&2; exit 1
fi
UPSTREAMS=''
for remote in "$@"; do
  [[ "$remote" =~ ^[A-Za-z][A-Za-z0-9_-]*:[A-Za-z0-9_./-]+$ ]] && [[ "$remote" != *'..'* ]] || {
    echo "Invalid upstream: $remote" >&2; exit 2;
  }
  rclone listremotes | grep -Fxq -- "${remote%%:*}:" || {
    echo "Remote not configured: ${remote%%:*}" >&2; exit 1;
  }
  # Fail closed if caller passed unencrypted remote: check via backend type.
  [[ "$(rclone config show "${remote%%:*}" | grep -E '^type = ' | head -1)" == 'type = crypt' ]] || {
    echo "Expected rclone crypt remote: $remote" >&2; exit 1;
  }
  UPSTREAMS+="${UPSTREAMS:+ }$remote"
done
rclone config create "$NAME" union \
  upstreams "$UPSTREAMS" action_policy all create_policy all search_policy ff
printf 'Created union %s: (mirror writes, not independent backup proof)\n' "$NAME"
